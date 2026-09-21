"""
max_bot.py — клиент и мини-фреймворк для MAX Bot API (https://platform-api2.max.ru).

Зависимость: requests  (pip install requests)

Что внутри
──────────
1. MaxClient    — все методы API: бот, чаты, участники, админы, закрепы, сообщения,
                  загрузка файлов, callback-ответы, комментарии каналов, подписки (webhook),
                  long polling. Лимиты (30 rps, 2 сообщения/сек в один чат) и повторы
                  запросов (429 / 5xx / attachment.not.ready) обрабатываются автоматически.
2. Keyboard, Button, Attachment — конструкторы клавиатур и вложений.
3. Bot          — диспетчер: команды, сообщения, callback-кнопки, любые события (Update),
                  middleware, состояния (FSM-lite), обработчик ошибок.
                  Запуск: long polling (для разработки) или webhook (для production).
4. Утилиты      — проверка номера телефона (hash), diplink, разбиение длинного текста,
                  упоминание пользователя.

Документация: https://dev.max.ru/docs-api
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import mimetypes
import os
import re
import ssl
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, BinaryIO, Callable, Dict, Iterable, Iterator, List, Optional, Sequence, Union
from urllib.parse import urlparse

import requests

log = logging.getLogger("max_bot")

API_URL = "https://platform-api2.max.ru"
MAX_TEXT_LEN = 4000

#: Все типы событий из объекта Update
UPDATE_TYPES = (
    "bot_added", "bot_started", "bot_stopped", "bot_removed",
    "chat_title_changed",
    "dialog_cleared", "dialog_muted", "dialog_unmuted", "dialog_removed",
    "message_callback", "message_created", "message_edited", "message_removed",
    "comment_created", "comment_edited", "comment_removed",
    "user_added", "user_removed",
)

#: Права администратора (POST /chats/{chatId}/members/admins)
ADMIN_PERMISSIONS = (
    "read_all_messages", "add_remove_members", "add_admins", "change_chat_info",
    "pin_message", "write", "edit", "delete", "edit_link", "can_call", "view_stats",
)

SENDER_ACTIONS = ("typing_on", "sending_photo", "sending_video", "sending_audio", "sending_file")


# ══════════════════════════════════════════════════════════════════════════════
#  Сертификаты Минцифры (без них Python не доверяет platform-api2.max.ru)
# ══════════════════════════════════════════════════════════════════════════════
ROOT_CA_URL = "https://gu-st.ru/content/lending/russian_trusted_root_ca_pem.crt"
SUB_CA_URL = "https://gu-st.ru/content/lending/russian_trusted_sub_ca_pem.crt"
ROOT_CA_SHA1 = "8FF915CCAB7BC16F8C5C8099D53E0E115B3AEC2F"   # отпечаток Russian Trusted Root CA
DEFAULT_CA_BUNDLE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "max_ca_bundle.pem")

_SSL_HELP = (
    "Python не доверяет сертификату сервера MAX (нужен корневой сертификат Минцифры). Как исправить:\n"
    "  1) python max_bot.py install-certs      — создаст файл max_ca_bundle.pem рядом со скриптом "
    "(подхватится автоматически), либо\n"
    "  2) pip install truststore и переменная MAX_USE_SYSTEM_CERTS=1 — использовать хранилище Windows/macOS "
    "(если сертификат Минцифры уже установлен в систему), либо\n"
    "  3) MaxClient(..., ca_bundle='путь/к/bundle.pem') или переменная окружения MAX_CA_BUNDLE."
)


def build_ca_bundle(dest: Optional[str] = None) -> str:
    """
    Скачивает корневой и выпускающий сертификаты Минцифры и собирает bundle = certifi + Минцифры.
    Подлинность корневого сертификата проверяется по отпечатку SHA-1.
    Возвращает путь к созданному файлу.
    """
    import certifi
    dest = dest or DEFAULT_CA_BUNDLE

    def fetch(url: str) -> str:
        try:
            r = requests.get(url, timeout=30)
        except requests.exceptions.SSLError:
            # сам сайт с сертификатами может быть подписан тем же центром; подлинность проверим отпечатком
            r = requests.get(url, timeout=30, verify=False)
        r.raise_for_status()
        return r.text.strip() + "\n"

    root = fetch(ROOT_CA_URL)
    sub = fetch(SUB_CA_URL)
    try:
        thumb = hashlib.sha1(ssl.PEM_cert_to_DER_cert(root)).hexdigest().upper()
    except Exception as exc:  # noqa: BLE001
        raise RuntimeError(f"Скачанный корневой сертификат повреждён: {exc}") from exc
    if thumb != ROOT_CA_SHA1:
        raise RuntimeError(f"Отпечаток корневого сертификата не совпал ({thumb}) — файл не сохранён")
    with open(certifi.where(), encoding="utf-8") as f:
        base = f.read().rstrip() + "\n"
    with open(dest, "w", encoding="utf-8") as f:
        f.write(base + "\n# Russian Trusted Root CA\n" + root + "\n# Russian Trusted Sub CA\n" + sub)
    return dest


# ══════════════════════════════════════════════════════════════════════════════
#  Ошибки
# ══════════════════════════════════════════════════════════════════════════════
class MaxAPIError(Exception):
    """Ошибка API MAX (HTTP >= 400, success=false или сетевая ошибка)."""

    def __init__(self, message: str, status: Optional[int] = None,
                 code: Optional[str] = None, payload: Any = None):
        super().__init__(message)
        self.message = message
        self.status = status
        self.code = code
        self.payload = payload

    def __str__(self) -> str:
        parts = []
        if self.status:
            parts.append(f"HTTP {self.status}")
        if self.code:
            parts.append(str(self.code))
        parts.append(self.message)
        return " | ".join(parts)

    @property
    def attachment_not_ready(self) -> bool:
        blob = f"{self.code or ''} {self.message or ''}".lower()
        return "attachment.not.ready" in blob or "file.not.processed" in blob


# ══════════════════════════════════════════════════════════════════════════════
#  Ограничитель частоты
# ══════════════════════════════════════════════════════════════════════════════
class _Throttle:
    """Не чаще одного события в `interval` секунд на ключ (потокобезопасно)."""

    def __init__(self, interval: float):
        self.interval = interval
        self._next: Dict[Any, float] = {}
        self._lock = threading.Lock()

    def wait(self, key: Any = "*") -> None:
        if self.interval <= 0:
            return
        with self._lock:
            now = time.monotonic()
            slot = max(self._next.get(key, 0.0), now)
            self._next[key] = slot + self.interval
            if len(self._next) > 10_000:  # чистим старые ключи
                self._next = {k: v for k, v in self._next.items() if v > now}
        delay = slot - now
        if delay > 0:
            time.sleep(delay)


def _clean_params(params: Optional[dict]) -> Optional[dict]:
    if not params:
        return None
    out = {}
    for k, v in params.items():
        if v is None:
            continue
        if isinstance(v, bool):
            v = "true" if v else "false"
        elif isinstance(v, (list, tuple, set)):
            v = ",".join(str(x) for x in v)
        out[k] = v
    return out


def _strip_none(d: dict) -> dict:
    return {k: v for k, v in d.items() if v is not None}


# ══════════════════════════════════════════════════════════════════════════════
#  Кнопки и клавиатура
# ══════════════════════════════════════════════════════════════════════════════
class Button:
    """Конструкторы кнопок inline-клавиатуры. Каждый метод возвращает dict."""

    @staticmethod
    def callback(text: str, payload: str, intent: Optional[str] = None) -> dict:
        """Нажатие → событие message_callback. intent: 'default' | 'positive' | 'negative'."""
        return _strip_none({"type": "callback", "text": text, "payload": payload, "intent": intent})

    @staticmethod
    def link(text: str, url: str) -> dict:
        """Открывает ссылку (до 2048 символов)."""
        if len(url) > 2048:
            raise ValueError("URL кнопки-ссылки не может быть длиннее 2048 символов")
        return {"type": "link", "text": text, "url": url}

    @staticmethod
    def message(text: str) -> dict:
        """Отправляет боту заранее заданный текст."""
        return {"type": "message", "text": text}

    @staticmethod
    def request_contact(text: str = "Поделиться контактом") -> dict:
        """Запрашивает контакт (номер телефона) пользователя."""
        return {"type": "request_contact", "text": text}

    @staticmethod
    def request_geo(text: str = "Отправить геолокацию", quick: Optional[bool] = None) -> dict:
        """Запрашивает геолокацию пользователя."""
        return _strip_none({"type": "request_geo_location", "text": text, "quick": quick})

    @staticmethod
    def open_app(text: str, web_app: Optional[str] = None, contact_id: Optional[int] = None,
                 payload: Optional[str] = None) -> dict:
        """Открывает мини-приложение внутри бота (web_app — username бота с мини-приложением)."""
        return _strip_none({"type": "open_app", "text": text, "web_app": web_app,
                            "contact_id": contact_id, "payload": payload})

    @staticmethod
    def clipboard(text: str, payload: str) -> dict:
        """Копирует payload в буфер обмена (промокод, трек-номер и т.п.)."""
        return {"type": "clipboard", "text": text, "payload": payload}


_RESTRICTED_TYPES = {"link", "open_app", "request_geo_location", "request_contact"}


class Keyboard:
    """
    Inline-клавиатура. Лимиты API: до 210 кнопок, до 30 рядов, до 7 кнопок в ряду
    (до 3, если в ряду есть link / open_app / request_geo_location / request_contact).

        kb = (Keyboard()
              .row(Button.callback("Да", "yes", intent="positive"),
                   Button.callback("Нет", "no", intent="negative"))
              .row(Button.link("Сайт", "https://example.com")))
        bot.client.send_message("Выберите:", chat_id=123, keyboard=kb)
    """
    MAX_ROWS = 30
    MAX_BUTTONS = 210
    ROW_LIMIT = 7
    ROW_LIMIT_RESTRICTED = 3

    def __init__(self, rows: Optional[List[List[dict]]] = None):
        self.rows: List[List[dict]] = []
        for r in rows or []:
            self.row(*r)

    def row(self, *buttons: dict) -> "Keyboard":
        if not buttons:
            return self
        limit = self.ROW_LIMIT
        if any(b.get("type") in _RESTRICTED_TYPES for b in buttons):
            limit = self.ROW_LIMIT_RESTRICTED
        if len(buttons) > limit:
            raise ValueError(f"В ряду может быть не более {limit} кнопок (получено {len(buttons)})")
        if len(self.rows) >= self.MAX_ROWS:
            raise ValueError(f"В клавиатуре не может быть больше {self.MAX_ROWS} рядов")
        self.rows.append(list(buttons))
        return self

    def add(self, *buttons: dict, per_row: int = 2) -> "Keyboard":
        """Добавляет кнопки, автоматически разбивая на ряды по `per_row`."""
        for i in range(0, len(buttons), per_row):
            self.row(*buttons[i:i + per_row])
        return self

    def to_attachment(self) -> dict:
        total = sum(len(r) for r in self.rows)
        if total > self.MAX_BUTTONS:
            raise ValueError(f"В клавиатуре не может быть больше {self.MAX_BUTTONS} кнопок")
        return {"type": "inline_keyboard", "payload": {"buttons": self.rows}}

    def __bool__(self) -> bool:
        return bool(self.rows)


# ══════════════════════════════════════════════════════════════════════════════
#  Вложения
# ══════════════════════════════════════════════════════════════════════════════
class Attachment:
    """Конструкторы вложений для send_message / edit_message."""

    @staticmethod
    def image(token: Optional[str] = None, url: Optional[str] = None) -> dict:
        """Изображение: по token (после upload) или по прямому url."""
        if bool(token) == bool(url):
            raise ValueError("Укажите ровно одно: token или url")
        return {"type": "image", "payload": {"token": token} if token else {"url": url}}

    @staticmethod
    def video(token: str) -> dict:
        return {"type": "video", "payload": {"token": token}}

    @staticmethod
    def audio(token: str) -> dict:
        return {"type": "audio", "payload": {"token": token}}

    @staticmethod
    def file(token: str) -> dict:
        return {"type": "file", "payload": {"token": token}}

    @staticmethod
    def sticker(code: str) -> dict:
        return {"type": "sticker", "payload": {"code": code}}

    @staticmethod
    def location(latitude: float, longitude: float) -> dict:
        return {"type": "location", "latitude": latitude, "longitude": longitude}

    @staticmethod
    def contact(name: Optional[str] = None, contact_id: Optional[int] = None,
                vcf_info: Optional[str] = None, vcf_phone: Optional[str] = None) -> dict:
        return {"type": "contact", "payload": _strip_none({
            "name": name, "contact_id": contact_id, "vcf_info": vcf_info, "vcf_phone": vcf_phone})}

    @staticmethod
    def share(url: Optional[str] = None, token: Optional[str] = None) -> dict:
        """Медиа с превью по внешнему URL."""
        if bool(token) == bool(url):
            raise ValueError("Укажите ровно одно: token или url")
        return {"type": "share", "payload": {"token": token} if token else {"url": url}}


# ══════════════════════════════════════════════════════════════════════════════
#  Утилиты
# ══════════════════════════════════════════════════════════════════════════════
def mention(name: str, user_id: int, fmt: str = "markdown") -> str:
    """Упоминание пользователя. name — полное имя из профиля MAX (с фамилией, если есть)."""
    if fmt == "html":
        return f'<a href="max://user/{user_id}">{name}</a>'
    return f"[{name}](max://user/{user_id})"


def deeplink(bot_username: str, payload: Optional[str] = None) -> str:
    """https://max.ru/<bot>?start=<payload>. Payload — до 128 символов."""
    if payload is None:
        return f"https://max.ru/{bot_username}"
    if len(payload) > 128:
        raise ValueError("payload диплинка не может быть длиннее 128 символов")
    return f"https://max.ru/{bot_username}?start={payload}"


def split_text(text: str, limit: int = MAX_TEXT_LEN) -> List[str]:
    """Режет длинный текст на части <= limit, стараясь резать по переносам строк/пробелам."""
    if len(text) <= limit:
        return [text]
    parts: List[str] = []
    rest = text
    while len(rest) > limit:
        cut = rest.rfind("\n", 0, limit)
        if cut < limit // 2:
            cut = rest.rfind(" ", 0, limit)
        if cut < limit // 2:
            cut = limit
        parts.append(rest[:cut].rstrip())
        rest = rest[cut:].lstrip("\n ")
    if rest:
        parts.append(rest)
    return parts


def verify_contact_hash(bot_token: str, vcf_info: str, hash_value: str) -> bool:
    """
    Проверяет, что контакт из кнопки request_contact принадлежит самому пользователю:
    hash == HMAC-SHA256(key=токен бота, msg=vcf_info). Сравнение — в hex.
    """
    if not (vcf_info and hash_value):
        return False
    vcf = vcf_info.replace("\\r\\n", "\r\n")  # если пришли экранированные переводы строк
    digest = hmac.new(bot_token.encode(), vcf.encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(digest, hash_value.strip().lower())


def parse_vcf(vcf_info: str) -> Dict[str, str]:
    """Достаёт имя и телефон из vcf_info."""
    out: Dict[str, str] = {}
    m = re.search(r"^TEL[^:\r\n]*:(\+?\d[\d\s\-()]*)", vcf_info or "", re.M)
    if m:
        out["phone"] = re.sub(r"[^\d+]", "", m.group(1))
    m = re.search(r"^FN:(.+)$", vcf_info or "", re.M)
    if m:
        out["name"] = m.group(1).strip()
    return out


# ══════════════════════════════════════════════════════════════════════════════
#  MaxClient — обёртка над HTTP API
# ══════════════════════════════════════════════════════════════════════════════
class MaxClient:
    """
    Синхронный клиент MAX Bot API.

        client = MaxClient(os.environ["MAX_BOT_TOKEN"])
        print(client.get_me())
        client.send_message("Привет!", user_id=123456)
    """

    def __init__(self, token: str, *, base_url: str = API_URL, timeout: float = 30.0,
                 max_retries: int = 3, rps: float = 25.0, chat_interval: float = 0.5,
                 session: Optional[requests.Session] = None, ca_bundle: Optional[str] = None):
        """
        ca_bundle — путь к PEM с доверенными сертификатами (нужен сертификат Минцифры).
        Если не указан: переменная MAX_CA_BUNDLE → файл max_ca_bundle.pem рядом с max_bot.py
        или в текущей папке → системные сертификаты, если MAX_USE_SYSTEM_CERTS=1 (нужен truststore).
        """
        if not token:
            raise ValueError("Не задан токен бота")
        self.token = token.strip()
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.max_retries = max_retries
        self.session = session or requests.Session()
        self._verify: Optional[str] = None
        bundle = ca_bundle or os.environ.get("MAX_CA_BUNDLE")
        if not bundle:
            for cand in (DEFAULT_CA_BUNDLE, os.path.join(os.getcwd(), "max_ca_bundle.pem")):
                if os.path.isfile(cand):
                    bundle = cand
                    break
        if bundle:
            if not os.path.isfile(bundle):
                raise FileNotFoundError(f"Файл сертификатов не найден: {bundle}")
            self.session.verify = bundle
            self._verify = bundle   # передаём явно в каждый запрос: иначе REQUESTS_CA_BUNDLE из окружения перебьёт
            log.info("Использую сертификаты из %s", bundle)
        elif os.environ.get("MAX_USE_SYSTEM_CERTS") == "1":
            try:
                import truststore
                truststore.inject_into_ssl()
                log.info("Использую системное хранилище сертификатов (truststore)")
            except ImportError:
                log.warning("MAX_USE_SYSTEM_CERTS=1, но пакет truststore не установлен: pip install truststore")
        self._global = _Throttle(1.0 / rps if rps else 0)      # лимит платформы: 30 rps
        self._per_chat = _Throttle(chat_interval)               # лимит: 2 сообщения/сек в чат

    # ── низкоуровневый запрос ────────────────────────────────────────────────
    def _request(self, method: str, path: str, *, params: Optional[dict] = None,
                 body: Optional[dict] = None, timeout: Optional[float] = None,
                 chat_key: Any = None, safe: Optional[bool] = None) -> dict:
        """
        safe=True — запрос можно безопасно повторять при сетевых ошибках/5xx
        (по умолчанию: всё, кроме POST). 429 повторяется всегда.
        """
        idempotent = (method != "POST") if safe is None else safe
        url = self.base_url + path
        params = _clean_params(params)
        headers = {"Authorization": self.token}
        attempt = 0
        while True:
            self._global.wait()
            if chat_key is not None:
                self._per_chat.wait(chat_key)
            try:
                resp = self.session.request(method, url, params=params, json=body,
                                            headers=headers, timeout=timeout or self.timeout,
                                            verify=self._verify if self._verify else None)
            except requests.exceptions.SSLError as exc:
                # повторы бессмысленны: сертификат сам не «починится»
                raise MaxAPIError(f"Ошибка проверки SSL-сертификата: {exc}\n{_SSL_HELP}", code="ssl_error") from exc
            except (requests.ConnectionError, requests.Timeout) as exc:
                if idempotent and attempt < self.max_retries:
                    self._backoff(attempt, None)
                    attempt += 1
                    continue
                raise MaxAPIError(f"Сетевая ошибка: {exc}") from exc

            retryable = resp.status_code == 429 or (resp.status_code >= 500 and idempotent)
            if retryable and attempt < self.max_retries:
                self._backoff(attempt, resp.headers.get("Retry-After"))
                attempt += 1
                continue

            try:
                data = resp.json() if resp.content else {}
            except ValueError:
                data = {"raw": resp.text}
            if resp.status_code >= 400:
                d = data if isinstance(data, dict) else {}
                raise MaxAPIError(
                    d.get("message") or d.get("error") or d.get("error_description") or resp.reason or "API error",
                    status=resp.status_code, code=d.get("code") or d.get("error"), payload=data)
            return data

    @staticmethod
    def _backoff(attempt: int, retry_after: Optional[str]) -> None:
        delay = min(2 ** attempt, 30)
        if retry_after:
            try:
                delay = max(delay, float(retry_after))
            except ValueError:
                pass
        log.warning("Повтор запроса через %.1f c (попытка %d)", delay, attempt + 1)
        time.sleep(delay)

    @staticmethod
    def _ok(data: dict) -> dict:
        """Для методов, возвращающих {"success": bool, "message": str}."""
        if isinstance(data, dict) and data.get("success") is False:
            raise MaxAPIError(data.get("message") or "Операция не выполнена", payload=data)
        return data

    def _with_attachment_retry(self, fn: Callable[[], dict], attempts: int = 6) -> dict:
        """Файл после загрузки обрабатывается не мгновенно → attachment.not.ready. Ждём и повторяем."""
        for i in range(attempts):
            try:
                return fn()
            except MaxAPIError as exc:
                if not exc.attachment_not_ready or i == attempts - 1:
                    raise
                delay = 1.0 + i
                log.info("Вложение ещё обрабатывается, повтор через %.1f c", delay)
                time.sleep(delay)
        raise RuntimeError("unreachable")

    # ── бот ──────────────────────────────────────────────────────────────────
    def get_me(self) -> dict:
        """GET /me — информация о боте."""
        return self._request("GET", "/me")

    def set_commands(self, commands: Sequence[Union[dict, tuple]]) -> dict:
        """
        PATCH /me/commands — подсказки при вводе «/». До 32 команд.
        Элемент: {"name": "start", "description": "..."} или ("start", "...").
        Пустой список удаляет все команды.
        """
        if len(commands) > 32:
            raise ValueError("Не более 32 команд")
        items = []
        for c in commands:
            name, desc = (c["name"], c.get("description", "")) if isinstance(c, dict) else c
            items.append({"name": name.lstrip("/"), "description": desc})
        return self._request("PATCH", "/me/commands", body={"commands": items})

    def delete_commands(self) -> dict:
        return self.set_commands([])

    # ── обновления ───────────────────────────────────────────────────────────
    def get_updates(self, *, marker: Optional[int] = None, timeout: int = 30, limit: int = 100,
                    types: Optional[Iterable[str]] = None) -> dict:
        """
        GET /updates — long polling. Без marker вернётся только последнее обновление.
        Ответ: {"updates": [...], "marker": int|None}
        """
        params = {"marker": marker, "timeout": timeout, "limit": limit,
                  "types": list(types) if types else None}
        return self._request("GET", "/updates", params=params, timeout=timeout + 15)

    # ── подписки (webhook) ───────────────────────────────────────────────────
    def get_subscriptions(self) -> List[dict]:
        """GET /subscriptions"""
        return self._request("GET", "/subscriptions").get("subscriptions", [])

    def subscribe(self, url: str, update_types: Optional[Iterable[str]] = None,
                  secret: Optional[str] = None) -> dict:
        """
        POST /subscriptions. url — только HTTPS, порт 443, валидный сертификат (или Минцифры).
        secret (5–256 симв. [A-Za-z0-9_-]) придёт в заголовке X-Max-Bot-Api-Secret.
        """
        if not url.startswith("https://"):
            raise ValueError("Webhook URL должен начинаться с https://")
        if secret is not None and not re.fullmatch(r"[A-Za-z0-9_-]{5,256}", secret):
            raise ValueError("secret: 5–256 символов, только A-Z a-z 0-9 _ -")
        body = _strip_none({"url": url, "update_types": list(update_types) if update_types else None,
                            "secret": secret})
        return self._ok(self._request("POST", "/subscriptions", body=body, safe=True))

    def unsubscribe(self, url: str) -> dict:
        """DELETE /subscriptions?url=..."""
        return self._ok(self._request("DELETE", "/subscriptions", params={"url": url}))

    # ── загрузка файлов ──────────────────────────────────────────────────────
    def upload(self, source: Union[str, os.PathLike, bytes, BinaryIO], kind: str,
               filename: Optional[str] = None, timeout: float = 600.0) -> str:
        """
        Загружает файл и возвращает token для вложения.
        kind: 'image' | 'video' | 'audio' | 'file'.
        source: путь, bytes или файловый объект.
        """
        if kind not in ("image", "video", "audio", "file"):
            raise ValueError("kind: image | video | audio | file")
        init = self._request("POST", "/uploads", params={"type": kind}, safe=True)
        upload_url = init.get("url")
        if not upload_url:
            raise MaxAPIError("POST /uploads не вернул url", payload=init)

        close_after = False
        if isinstance(source, (str, os.PathLike)):
            filename = filename or os.path.basename(source)
            fh: Any = open(source, "rb")
            close_after = True
        elif isinstance(source, (bytes, bytearray)):
            fh = bytes(source)
            filename = filename or "file"
        else:
            fh = source
            filename = filename or os.path.basename(getattr(source, "name", "") or "file")
        mime = mimetypes.guess_type(filename)[0] or "application/octet-stream"
        try:
            # Токен бота на сторонний хост загрузки НЕ отправляем — в url уже есть всё нужное.
            resp = requests.post(upload_url, files={"data": (filename, fh, mime)}, timeout=timeout,
                                 verify=self._verify if self._verify else True)
        except requests.RequestException as exc:
            raise MaxAPIError(f"Ошибка загрузки файла: {exc}") from exc
        finally:
            if close_after:
                fh.close()
        if resp.status_code >= 400:
            raise MaxAPIError(f"Загрузка файла: HTTP {resp.status_code}: {resp.text[:200]}",
                              status=resp.status_code)
        try:
            up = resp.json()
        except ValueError:
            up = {}
        return self._extract_upload_token(kind, init, up)

    @staticmethod
    def _extract_upload_token(kind: str, init: dict, up: Any) -> str:
        from_upload = None
        if isinstance(up, dict):
            from_upload = up.get("token")
            photos = up.get("photos")
            if not from_upload and isinstance(photos, dict) and photos:
                first = next(iter(photos.values()))
                if isinstance(first, dict):
                    from_upload = first.get("token")
        from_init = init.get("token")
        # для video/audio токен приходит на первом шаге, для image/file — после загрузки
        token = (from_init or from_upload) if kind in ("video", "audio") else (from_upload or from_init)
        if not token:
            raise MaxAPIError("Не удалось получить token загруженного файла", payload={"init": init, "upload": up})
        return token

    def send_file(self, path: Union[str, os.PathLike], *, chat_id: Optional[int] = None,
                  user_id: Optional[int] = None, kind: Optional[str] = None, text: Optional[str] = None,
                  keyboard: Optional[Keyboard] = None, **kw) -> dict:
        """Загрузить файл с диска и отправить (тип определяется по расширению, если kind не указан)."""
        kind = kind or self.guess_kind(str(path))
        token = self.upload(path, kind)
        make = {"image": lambda t: Attachment.image(token=t), "video": Attachment.video,
                "audio": Attachment.audio, "file": Attachment.file}[kind]
        att = make(token)
        return self.send_message(text, chat_id=chat_id, user_id=user_id, attachments=[att],
                                 keyboard=keyboard, **kw)

    def send_images(self, paths: Sequence[Union[str, os.PathLike]], *, chat_id: Optional[int] = None,
                    user_id: Optional[int] = None, text: Optional[str] = None,
                    keyboard: Optional[Keyboard] = None, **kw) -> dict:
        """До 12 изображений в одном сообщении."""
        if not 1 <= len(paths) <= 12:
            raise ValueError("Можно отправить от 1 до 12 изображений")
        atts = [Attachment.image(token=self.upload(p, "image")) for p in paths]
        return self.send_message(text, chat_id=chat_id, user_id=user_id, attachments=atts,
                                 keyboard=keyboard, **kw)

    @staticmethod
    def guess_kind(path: str) -> str:
        mime = (mimetypes.guess_type(path)[0] or "").split("/")[0]
        return mime if mime in ("image", "video", "audio") else "file"

    # ── сообщения ────────────────────────────────────────────────────────────
    def send_message(self, text: Optional[str] = None, *, chat_id: Optional[int] = None,
                     user_id: Optional[int] = None, attachments: Optional[List[dict]] = None,
                     keyboard: Optional[Keyboard] = None, format: Optional[str] = None,
                     notify: Optional[bool] = None, reply_to: Optional[str] = None,
                     forward: Optional[str] = None, disable_link_preview: Optional[bool] = None) -> dict:
        """
        POST /messages — отправка в диалог (user_id), группу или канал (chat_id).
        format: 'markdown' | 'html'.  reply_to / forward — mid сообщения.
        Лимит текста — 4000 символов (для длинных: send_long_message).
        """
        if (chat_id is None) == (user_id is None):
            raise ValueError("Укажите ровно одно: chat_id или user_id")
        body = self._message_body(text, attachments, keyboard, format, notify, reply_to, forward)
        params = {"chat_id": chat_id, "user_id": user_id, "disable_link_preview": disable_link_preview}
        key = chat_id if chat_id is not None else f"u{user_id}"
        data = self._with_attachment_retry(
            lambda: self._request("POST", "/messages", params=params, body=body, chat_key=key))
        return data.get("message", data)

    def send_long_message(self, text: str, **kwargs) -> List[dict]:
        """Разбивает текст на части по 4000 символов. Вложения/клавиатура уйдут с последней частью."""
        parts = split_text(text)
        results = []
        for i, part in enumerate(parts):
            kw = dict(kwargs)
            if i < len(parts) - 1:
                kw.pop("attachments", None)
                kw.pop("keyboard", None)
            results.append(self.send_message(part, **kw))
        return results

    @staticmethod
    def _message_body(text, attachments, keyboard, format, notify, reply_to=None, forward=None) -> dict:
        if text is not None and len(text) > MAX_TEXT_LEN:
            raise ValueError(f"Текст длиннее {MAX_TEXT_LEN} символов — используйте send_long_message")
        atts = list(attachments) if attachments is not None else None
        if keyboard:
            atts = (atts or []) + [keyboard.to_attachment()]
        link = None
        if reply_to:
            link = {"type": "reply", "mid": reply_to}
        elif forward:
            link = {"type": "forward", "mid": forward}
        return _strip_none({"text": text, "attachments": atts, "link": link,
                            "notify": notify, "format": format})

    def edit_message(self, message_id: str, text: Optional[str] = None, *,
                     attachments: Optional[List[dict]] = None, keyboard: Optional[Keyboard] = None,
                     format: Optional[str] = None, notify: Optional[bool] = None,
                     chat_id: Optional[int] = None) -> dict:
        """
        PUT /messages — редактирование сообщения бота.
        attachments=None — вложения не менять; attachments=[] — удалить все вложения (в т.ч. клавиатуру).
        chat_id нужен только для соблюдения лимита 2 запроса/сек.
        """
        body = self._message_body(text, attachments, keyboard, format, notify)
        return self._ok(self._with_attachment_retry(
            lambda: self._request("PUT", "/messages", params={"message_id": message_id}, body=body,
                                  chat_key=chat_id)))

    def delete_message(self, message_id: str, *, chat_id: Optional[int] = None) -> dict:
        """DELETE /messages — в диалоге только свои сообщения; в чатах/каналах — любые (нужны права)."""
        return self._ok(self._request("DELETE", "/messages", params={"message_id": message_id},
                                      chat_key=chat_id))

    def get_messages(self, *, chat_id: Optional[int] = None, message_ids: Optional[Iterable[str]] = None,
                     from_time: Optional[int] = None, to_time: Optional[int] = None,
                     count: Optional[int] = None) -> List[dict]:
        """GET /messages — по chat_id (бот — админ) или по списку message_ids. Время — Unix ms."""
        if chat_id is None and not message_ids:
            raise ValueError("Нужен chat_id или message_ids")
        params = {"chat_id": chat_id, "message_ids": list(message_ids) if message_ids else None,
                  "from": from_time, "to": to_time, "count": count}
        return self._request("GET", "/messages", params=params).get("messages", [])

    def get_message(self, message_id: str) -> dict:
        """GET /messages/{messageId}"""
        return self._request("GET", f"/messages/{message_id}")

    def get_video(self, video_token: str) -> dict:
        """GET /videos/{videoToken} — информация о видео во вложении."""
        return self._request("GET", f"/videos/{video_token}")

    def answer_callback(self, callback_id: str, *, notification: Optional[str] = None,
                        text: Optional[str] = None, attachments: Optional[List[dict]] = None,
                        keyboard: Optional[Keyboard] = None, format: Optional[str] = None,
                        disable_link_preview: Optional[bool] = None) -> dict:
        """
        POST /answers — ответ на нажатие кнопки: одноразовое уведомление (notification)
        и/или изменение сообщения с кнопкой (text / attachments / keyboard).
        """
        body: Dict[str, Any] = {}
        if notification:
            body["notification"] = notification
        if text is not None or attachments is not None or keyboard:
            body["message"] = self._message_body(text, attachments, keyboard, format, None)
        return self._ok(self._with_attachment_retry(
            lambda: self._request("POST", "/answers", params={"callback_id": callback_id,
                                                              "disable_link_preview": disable_link_preview},
                                  body=body, safe=True)))

    # ── чаты ─────────────────────────────────────────────────────────────────
    def get_chat(self, chat_id: int) -> dict:
        """GET /chats/{chatId}"""
        return self._request("GET", f"/chats/{chat_id}")

    def edit_chat(self, chat_id: int, *, title: Optional[str] = None, description: Optional[str] = None,
                  icon_url: Optional[str] = None, icon_token: Optional[str] = None,
                  pin: Optional[str] = None, notify: Optional[bool] = None) -> dict:
        """PATCH /chats/{chatId} — название (1–200), описание (до 16000), иконка, закреп. Бот — админ."""
        icon = None
        if icon_url:
            icon = {"url": icon_url}
        elif icon_token:
            icon = {"token": icon_token}
        body = _strip_none({"title": title, "description": description, "icon": icon,
                            "pin": pin, "notify": notify})
        return self._request("PATCH", f"/chats/{chat_id}", body=body)

    def send_action(self, chat_id: int, action: str = "typing_on") -> dict:
        """POST /chats/{chatId}/actions — typing_on | sending_photo | sending_video | sending_audio | sending_file."""
        if action not in SENDER_ACTIONS:
            raise ValueError(f"action: одно из {SENDER_ACTIONS}")
        return self._ok(self._request("POST", f"/chats/{chat_id}/actions", body={"action": action}, safe=True))

    def get_pinned(self, chat_id: int) -> Optional[dict]:
        """GET /chats/{chatId}/pin"""
        return self._request("GET", f"/chats/{chat_id}/pin").get("message")

    def pin_message(self, chat_id: int, message_id: str, notify: Optional[bool] = None) -> dict:
        """PUT /chats/{chatId}/pin — message_id = Message.body.mid."""
        return self._ok(self._request("PUT", f"/chats/{chat_id}/pin",
                                      body=_strip_none({"message_id": message_id, "notify": notify})))

    def unpin_message(self, chat_id: int) -> dict:
        """DELETE /chats/{chatId}/pin"""
        return self._ok(self._request("DELETE", f"/chats/{chat_id}/pin"))

    def get_my_membership(self, chat_id: int) -> dict:
        """GET /chats/{chatId}/members/me — членство и права самого бота."""
        return self._request("GET", f"/chats/{chat_id}/members/me")

    def leave_chat(self, chat_id: int) -> dict:
        """DELETE /chats/{chatId}/members/me — бот покидает чат/канал."""
        return self._ok(self._request("DELETE", f"/chats/{chat_id}/members/me"))

    # ── участники и администраторы ───────────────────────────────────────────
    def get_members(self, chat_id: int, *, user_ids: Optional[Iterable[int]] = None,
                    marker: Optional[int] = None, count: Optional[int] = None) -> dict:
        """GET /chats/{chatId}/members → {"members": [...], "marker": ...}. Бот — админ."""
        params = {"user_ids": list(user_ids) if user_ids else None, "marker": marker, "count": count}
        return self._request("GET", f"/chats/{chat_id}/members", params=params)

    def iter_members(self, chat_id: int, page_size: int = 100) -> Iterator[dict]:
        """Итератор по всем участникам (сам листает marker)."""
        marker = None
        while True:
            page = self.get_members(chat_id, marker=marker, count=page_size)
            for m in page.get("members", []):
                yield m
            marker = page.get("marker")
            if not marker:
                return

    def add_members(self, chat_id: int, user_ids: Sequence[int]) -> dict:
        """
        POST /chats/{chatId}/members. ВНИМАНИЕ: по документации метод ограничен с 09.09.2026
        и будет удалён с 30.09.2026 — не рассчитывайте на него.
        """
        return self._ok(self._request("POST", f"/chats/{chat_id}/members", body={"user_ids": list(user_ids)}))

    def remove_member(self, chat_id: int, user_id: int, block: Optional[bool] = None) -> dict:
        """DELETE /chats/{chatId}/members?user_id=&block= (право add_remove_members)."""
        return self._ok(self._request("DELETE", f"/chats/{chat_id}/members",
                                      params={"user_id": user_id, "block": block}))

    def get_admins(self, chat_id: int) -> dict:
        """GET /chats/{chatId}/members/admins"""
        return self._request("GET", f"/chats/{chat_id}/members/admins")

    def set_admins(self, chat_id: int, admins: Sequence[dict]) -> dict:
        """
        POST /chats/{chatId}/members/admins. Повторный вызов полностью заменяет права.
        admins: [{"user_id": 1, "permissions": ["read_all_messages", "write"], "alias": "модератор"}]
        """
        for a in admins:
            bad = [p for p in a.get("permissions", []) if p not in ADMIN_PERMISSIONS]
            if bad:
                raise ValueError(f"Неизвестные права: {bad}")
        return self._ok(self._request("POST", f"/chats/{chat_id}/members/admins",
                                      body={"admins": list(admins)}, safe=True))

    def remove_admin(self, chat_id: int, user_id: int) -> dict:
        """DELETE /chats/{chatId}/members/admins/{userId}"""
        return self._ok(self._request("DELETE", f"/chats/{chat_id}/members/admins/{user_id}"))

    # ── комментарии в каналах ────────────────────────────────────────────────
    # Нужны: включённые комментарии в канале, бот — админ (read_all_messages + write/edit/delete).
    def get_comments(self, message_id: str, *, comment_ids: Optional[Iterable[str]] = None,
                     before: Optional[int] = None, after: Optional[int] = None,
                     count: Optional[int] = None) -> List[dict]:
        """GET /messages/{messageId}/comments (время — Unix ms, count 1–100)."""
        params = {"comment_ids": list(comment_ids) if comment_ids else None,
                  "before": before, "after": after, "count": count}
        return self._request("GET", f"/messages/{message_id}/comments", params=params).get("messages", [])

    def get_comment(self, message_id: str, comment_id: str) -> dict:
        """GET /messages/{messageId}/comments/{commentId}"""
        return self._request("GET", f"/messages/{message_id}/comments/{comment_id}")

    def send_comment(self, message_id: str, text: str, *, format: Optional[str] = None,
                     reply_to: Optional[str] = None) -> dict:
        """POST /messages/{messageId}/comments (без вложений; ссылки и упоминания не поддерживаются)."""
        if len(text) > MAX_TEXT_LEN:
            raise ValueError(f"Комментарий длиннее {MAX_TEXT_LEN} символов")
        body = _strip_none({"text": text, "format": format,
                            "link": {"type": "reply", "mid": reply_to} if reply_to else None})
        data = self._request("POST", f"/messages/{message_id}/comments", body=body)
        return data.get("message", data)

    def edit_comment(self, message_id: str, comment_id: str, text: str, *,
                     format: Optional[str] = None) -> dict:
        """PUT /messages/{messageId}/comments?comment_id= (бот может править только свои комментарии)."""
        body = _strip_none({"text": text, "format": format})
        return self._ok(self._request("PUT", f"/messages/{message_id}/comments",
                                      params={"comment_id": comment_id}, body=body))

    def delete_comment(self, message_id: str, comment_id: str) -> dict:
        """DELETE /messages/{messageId}/comments?comment_id= — необратимо."""
        return self._ok(self._request("DELETE", f"/messages/{message_id}/comments",
                                      params={"comment_id": comment_id}))


# ══════════════════════════════════════════════════════════════════════════════
#  Состояния (FSM-lite)
# ══════════════════════════════════════════════════════════════════════════════
class MemoryStorage:
    """Хранилище состояний в памяти. Для продакшена подставьте свой класс с теми же методами (Redis и т.п.)."""

    def __init__(self):
        self._data: Dict[Any, Dict[str, Any]] = {}
        self._lock = threading.Lock()

    def get(self, key: Any) -> Dict[str, Any]:
        with self._lock:
            return dict(self._data.get(key, {}))

    def set(self, key: Any, state: Optional[str], data: Optional[dict] = None) -> None:
        with self._lock:
            cur = self._data.setdefault(key, {})
            cur["state"] = state
            if data:
                cur.setdefault("data", {}).update(data)

    def update_data(self, key: Any, **data) -> None:
        with self._lock:
            self._data.setdefault(key, {}).setdefault("data", {}).update(data)

    def clear(self, key: Any) -> None:
        with self._lock:
            self._data.pop(key, None)


# ══════════════════════════════════════════════════════════════════════════════
#  Context — то, что получает обработчик
# ══════════════════════════════════════════════════════════════════════════════
_COMMAND_RE = re.compile(r"^/([A-Za-z0-9_]+)(?:@\w+)?(?:\s+(.*))?$", re.S)


class Context:
    """Обёртка над Update с удобными свойствами и методами ответа."""

    def __init__(self, bot: "Bot", update: dict):
        self.bot = bot
        self.update = update
        self.type: str = update.get("update_type", "")
        self.message: Optional[dict] = update.get("message")
        self.callback: Optional[dict] = update.get("callback")
        self.match: Optional[re.Match] = None
        self.command: Optional[str] = None
        self.args: str = ""

    # ── данные события ───────────────────────────────────────────────────────
    @property
    def client(self) -> MaxClient:
        return self.bot.client

    @property
    def chat_id(self) -> Optional[int]:
        cid = self.update.get("chat_id")
        if cid is None and self.message:
            cid = (self.message.get("recipient") or {}).get("chat_id")
        return cid

    @property
    def chat_type(self) -> Optional[str]:
        """'dialog' | 'chat' | 'channel' (если известно)."""
        if self.message:
            return (self.message.get("recipient") or {}).get("chat_type")
        return None

    @property
    def user(self) -> Optional[dict]:
        return (self.update.get("user")
                or (self.callback or {}).get("user")
                or (self.message or {}).get("sender"))

    @property
    def user_id(self) -> Optional[int]:
        u = self.user
        return u.get("user_id") if u else None

    @property
    def user_name(self) -> str:
        u = self.user or {}
        return u.get("name") or u.get("first_name") or u.get("username") or "друг"

    @property
    def body(self) -> dict:
        return (self.message or {}).get("body") or {}

    @property
    def text(self) -> str:
        return self.body.get("text") or ""

    @property
    def message_id(self) -> Optional[str]:
        """mid сообщения (для callback — сообщения с кнопкой)."""
        return self.body.get("mid")

    @property
    def attachments(self) -> List[dict]:
        return self.body.get("attachments") or []

    def attachment(self, kind: str) -> Optional[dict]:
        return next((a for a in self.attachments if a.get("type") == kind), None)

    @property
    def payload(self) -> Optional[str]:
        """Для message_callback — payload кнопки; для bot_started — payload диплинка."""
        if self.callback is not None:
            return self.callback.get("payload")
        return self.update.get("payload")

    @property
    def callback_id(self) -> Optional[str]:
        return (self.callback or {}).get("callback_id")

    @property
    def contact(self) -> Optional[dict]:
        """Вложение-контакт (payload: vcf_info, hash, ...)."""
        att = self.attachment("contact")
        return att.get("payload") if att else None

    def contact_verified(self) -> bool:
        """True, если контакт прислан кнопкой request_contact и принадлежит самому пользователю."""
        c = self.contact or {}
        return verify_contact_hash(self.client.token, c.get("vcf_info", ""), c.get("hash", ""))

    @property
    def location(self) -> Optional[dict]:
        """{'latitude': .., 'longitude': ..} если сообщение содержит геолокацию."""
        att = self.attachment("location")
        if not att:
            return None
        src = att.get("payload") or att
        return {"latitude": src.get("latitude"), "longitude": src.get("longitude")}

    # ── состояние пользователя ───────────────────────────────────────────────
    @property
    def _state_key(self):
        return (self.chat_id, self.user_id)

    @property
    def state(self) -> Optional[str]:
        return self.bot.storage.get(self._state_key).get("state")

    @property
    def data(self) -> dict:
        return self.bot.storage.get(self._state_key).get("data", {})

    def set_state(self, state: Optional[str], **data) -> None:
        self.bot.storage.set(self._state_key, state, data or None)

    def update_data(self, **data) -> None:
        self.bot.storage.update_data(self._state_key, **data)

    def clear_state(self) -> None:
        self.bot.storage.clear(self._state_key)

    # ── ответы ───────────────────────────────────────────────────────────────
    def _target(self) -> dict:
        if self.chat_id is not None:
            return {"chat_id": self.chat_id}
        if self.user_id is not None:
            return {"user_id": self.user_id}
        raise MaxAPIError("Не удалось определить получателя из события")

    def reply(self, text: Optional[str] = None, **kw) -> dict:
        """Отправить сообщение в тот же чат (kw — параметры MaxClient.send_message)."""
        kw.setdefault("format", self.bot.default_format)
        return self.client.send_message(text, **self._target(), **kw)

    def reply_quote(self, text: str, **kw) -> dict:
        """Ответить цитатой на исходное сообщение."""
        return self.reply(text, reply_to=self.message_id, **kw)

    def answer(self, notification: Optional[str] = None, *, text: Optional[str] = None,
               keyboard: Optional[Keyboard] = None, attachments: Optional[List[dict]] = None,
               format: Optional[str] = None) -> dict:
        """Ответ на нажатие кнопки: всплывающее уведомление и/или замена сообщения с кнопкой."""
        if not self.callback_id:
            raise MaxAPIError("answer() доступен только в обработчике message_callback")
        return self.client.answer_callback(self.callback_id, notification=notification, text=text,
                                           keyboard=keyboard, attachments=attachments,
                                           format=format or self.bot.default_format)

    def edit(self, text: Optional[str] = None, **kw) -> dict:
        """Отредактировать сообщение бота, к которому относится событие (например, с кнопками)."""
        if not self.message_id:
            raise MaxAPIError("Нет message_id для редактирования")
        kw.setdefault("format", self.bot.default_format)
        return self.client.edit_message(self.message_id, text, chat_id=self.chat_id, **kw)

    def delete(self) -> dict:
        if not self.message_id:
            raise MaxAPIError("Нет message_id для удаления")
        return self.client.delete_message(self.message_id, chat_id=self.chat_id)

    def typing(self) -> None:
        """Показать «печатает…» (по документации — для групповых чатов)."""
        if self.chat_id is not None:
            try:
                self.client.send_action(self.chat_id, "typing_on")
            except MaxAPIError as exc:
                log.debug("typing_on не удалось: %s", exc)


# ══════════════════════════════════════════════════════════════════════════════
#  Bot — диспетчер
# ══════════════════════════════════════════════════════════════════════════════
class _Handler:
    __slots__ = ("types", "func", "predicate", "name")

    def __init__(self, types, func, predicate, name):
        self.types, self.func, self.predicate, self.name = types, func, predicate, name


class Bot:
    """
    Диспетчер событий.

        bot = Bot(os.environ["MAX_BOT_TOKEN"])

        @bot.command("start", description="Начать")
        def start(ctx):
            ctx.reply("Привет, " + ctx.user_name)

        @bot.callback(prefix="buy:")
        def buy(ctx):
            ctx.answer("Куплено: " + ctx.payload.split(":", 1)[1])

        bot.run_polling()

    Правило: побеждает ПЕРВЫЙ подходящий обработчик в порядке регистрации.
    Поэтому специфичные обработчики (команды, состояния) регистрируйте раньше общих.
    """

    def __init__(self, token: str, *, default_format: Optional[str] = None, workers: int = 4,
                 storage: Optional[MemoryStorage] = None, client: Optional[MaxClient] = None):
        self.client = client or MaxClient(token)
        self.default_format = default_format          # 'markdown' | 'html' | None
        self.storage = storage or MemoryStorage()
        self.me: Optional[dict] = None
        self.known_chats: Dict[int, dict] = {}        # chat_id -> {'type','last_seen'}
        self._handlers: List[_Handler] = []
        self._middlewares: List[Callable] = []
        self._fallback: Optional[Callable] = None
        self._error_handler: Optional[Callable] = None
        self._commands: List[dict] = []
        self._pools = [ThreadPoolExecutor(max_workers=1, thread_name_prefix=f"max-worker-{i}")
                       for i in range(max(1, workers))]
        self._stop = threading.Event()
        self._server: Optional[ThreadingHTTPServer] = None

    # ── регистрация обработчиков ─────────────────────────────────────────────
    def _add(self, types: Iterable[str], predicate: Optional[Callable[[Context], bool]] = None):
        types = tuple(types)

        def deco(func):
            self._handlers.append(_Handler(types, func, predicate, getattr(func, "__name__", "handler")))
            return func
        return deco

    def on(self, *update_types: str, filter: Optional[Callable[[Context], bool]] = None):
        """Любые события Update: @bot.on('bot_added', 'user_added')."""
        for t in update_types:
            if t not in UPDATE_TYPES:
                raise ValueError(f"Неизвестный тип события: {t}")
        return self._add(update_types, filter)

    def command(self, *names: str, description: Optional[str] = None,
                filter: Optional[Callable[[Context], bool]] = None):
        """
        Команды вида /start, /help arg1 arg2. В ctx.command — имя, в ctx.args — остаток строки.
        description — попадёт в подсказки при вводе «/» (см. Bot.sync_commands).
        """
        names_l = [n.lstrip("/").lower() for n in names]
        if description and names_l:
            self._commands.append({"name": names_l[0], "description": description})

        def predicate(ctx: Context) -> bool:
            m = _COMMAND_RE.match(ctx.text.strip())
            if not m or m.group(1).lower() not in names_l:
                return False
            ctx.command, ctx.args = m.group(1).lower(), (m.group(2) or "").strip()
            return filter(ctx) if filter else True
        return self._add(("message_created",), predicate)

    def message(self, *, filter: Optional[Callable[[Context], bool]] = None, state: Optional[str] = None,
                regex: Optional[str] = None, content_type: Optional[str] = None,
                chat_type: Optional[str] = None, commands: bool = False):
        """
        Новое сообщение. Фильтры (все необязательные, комбинируются по И):
          state=…         — состояние пользователя (ctx.set_state)
          regex=…         — re.search по тексту (результат — ctx.match)
          content_type=…  — есть вложение этого типа: image | video | audio | file | contact | location | sticker | share
          chat_type=…     — 'dialog' | 'chat' | 'channel'
          commands=True   — не пропускать сообщения, начинающиеся с «/» (по умолчанию пропускаются)
        """
        rx = re.compile(regex) if regex else None

        def predicate(ctx: Context) -> bool:
            if not commands and _COMMAND_RE.match(ctx.text.strip()):
                return False
            if state is not None and ctx.state != state:
                return False
            if chat_type is not None and ctx.chat_type != chat_type:
                return False
            if content_type is not None and not ctx.attachment(content_type):
                return False
            if rx is not None:
                ctx.match = rx.search(ctx.text)
                if not ctx.match:
                    return False
            return filter(ctx) if filter else True
        return self._add(("message_created",), predicate)

    def callback(self, data: Optional[str] = None, *, prefix: Optional[str] = None,
                 regex: Optional[str] = None, filter: Optional[Callable[[Context], bool]] = None):
        """Нажатие callback-кнопки: точное payload, префикс или regex (ctx.match)."""
        rx = re.compile(regex) if regex else None

        def predicate(ctx: Context) -> bool:
            p = ctx.payload or ""
            if data is not None and p != data:
                return False
            if prefix is not None and not p.startswith(prefix):
                return False
            if rx is not None:
                ctx.match = rx.search(p)
                if not ctx.match:
                    return False
            return filter(ctx) if filter else True
        return self._add(("message_callback",), predicate)

    def bot_started(self):
        """Пользователь нажал «Начать» или перешёл по диплинку (ctx.payload — параметр start=)."""
        return self._add(("bot_started",))

    def fallback(self, func):
        """Вызывается, если ни один обработчик не подошёл."""
        self._fallback = func
        return func

    def error(self, func):
        """Обработчик ошибок: func(ctx, exc)."""
        self._error_handler = func
        return func

    def middleware(self, func):
        """func(ctx, call_next) — оборачивает обработку каждого события. Вызовите call_next()."""
        self._middlewares.append(func)
        return func

    # ── обработка ────────────────────────────────────────────────────────────
    def process_update(self, update: dict) -> None:
        """Синхронно обработать один Update (можно вызывать из Flask/FastAPI-вебхука)."""
        ctx = Context(self, update)
        try:
            self._track(ctx)

            def endpoint():
                for h in self._handlers:
                    if ctx.type in h.types and (h.predicate is None or h.predicate(ctx)):
                        log.debug("Update %s → %s", ctx.type, h.name)
                        return h.func(ctx)
                if self._fallback:
                    return self._fallback(ctx)
                log.debug("Нет обработчика для %s", ctx.type)

            call = endpoint
            for mw in reversed(self._middlewares):
                call = (lambda mw=mw, nxt=call: (lambda: mw(ctx, nxt)))()
            call()
        except Exception as exc:  # noqa: BLE001
            if self._error_handler:
                try:
                    self._error_handler(ctx, exc)
                    return
                except Exception:  # noqa: BLE001
                    log.exception("Ошибка в обработчике ошибок")
            log.exception("Ошибка при обработке %s", update.get("update_type"))

    def dispatch_async(self, update: dict) -> None:
        """Отдать Update в пул. Сообщения одного чата обрабатываются строго по очереди."""
        ctx = Context(self, update)
        key = ctx.chat_id if ctx.chat_id is not None else (ctx.user_id or 0)
        self._pools[hash(key) % len(self._pools)].submit(self.process_update, update)

    def _track(self, ctx: Context) -> None:
        if ctx.chat_id is not None:
            info = self.known_chats.setdefault(ctx.chat_id, {})
            info["last_seen"] = time.time()
            if ctx.chat_type:
                info["type"] = ctx.chat_type
            if ctx.type in ("bot_removed",):
                self.known_chats.pop(ctx.chat_id, None)

    def _update_types(self) -> Optional[List[str]]:
        """Типы событий, на которые есть обработчики (None — получать всё)."""
        types = set()
        for h in self._handlers:
            types.update(h.types)
        if self._fallback or not types:
            return None
        return sorted(types)

    # ── рассылка ─────────────────────────────────────────────────────────────
    def broadcast(self, user_ids: Iterable[int], text: str, **kw) -> Dict[int, str]:
        """Отправить текст списку пользователей. Возвращает {user_id: ошибка} для неудачных."""
        failed: Dict[int, str] = {}
        for uid in user_ids:
            try:
                self.client.send_message(text, user_id=uid, **kw)
            except MaxAPIError as exc:
                failed[uid] = str(exc)
        return failed

    # ── старт ────────────────────────────────────────────────────────────────
    def sync_commands(self) -> None:
        """Отправить в MAX команды, зарегистрированные через @bot.command(..., description=...)."""
        if self._commands:
            self.client.set_commands(self._commands)
            log.info("Команды обновлены: %s", ", ".join("/" + c["name"] for c in self._commands))

    def _startup(self, sync_commands: bool) -> None:
        self.me = self.client.get_me()
        log.info("Бот: %s (@%s), id=%s", self.me.get("name"), self.me.get("username"), self.me.get("user_id"))
        if sync_commands:
            try:
                self.sync_commands()
            except MaxAPIError as exc:
                log.warning("Не удалось обновить команды: %s", exc)

    def run_polling(self, *, timeout: int = 30, limit: int = 100, types: Optional[Iterable[str]] = None,
                    drop_webhook: bool = False, sync_commands: bool = True) -> None:
        """
        Long polling (GET /updates). Только для разработки и тестов: у метода есть ограничения
        по скорости и сроку хранения событий. Одновременно с webhook-подпиской не работает.
        """
        self._startup(sync_commands)
        subs = self.client.get_subscriptions()
        if subs:
            if drop_webhook:
                for s in subs:
                    self.client.unsubscribe(s["url"])
                    log.info("Webhook-подписка удалена: %s", s["url"])
            else:
                log.warning("Активна webhook-подписка (%s): long polling не получит события. "
                            "Запустите с drop_webhook=True.", ", ".join(s["url"] for s in subs))
        want = list(types) if types else self._update_types()
        marker: Optional[int] = None
        backoff = 1.0
        log.info("Long polling запущен (types=%s). Ctrl+C — остановка.", want or "все")
        try:
            while not self._stop.is_set():
                try:
                    data = self.client.get_updates(marker=marker, timeout=timeout, limit=limit, types=want)
                except MaxAPIError as exc:
                    if exc.status in (401, 403):
                        raise
                    log.error("Ошибка получения обновлений: %s (повтор через %.0f c)", exc, backoff)
                    self._stop.wait(backoff)
                    backoff = min(backoff * 2, 30)
                    continue
                backoff = 1.0
                for upd in data.get("updates", []):
                    self.dispatch_async(upd)
                if data.get("marker") is not None:
                    marker = data["marker"]
        except KeyboardInterrupt:
            log.info("Остановка по Ctrl+C")
        finally:
            self.shutdown()

    def run_webhook(self, *, url: str, host: str = "0.0.0.0", port: int = 8080, path: Optional[str] = None,
                    secret: Optional[str] = None, update_types: Optional[Iterable[str]] = None,
                    register: bool = True, sync_commands: bool = True) -> None:
        """
        Webhook — режим для production.

        MAX шлёт события только на HTTPS:443 с валидным сертификатом (самоподписанные не принимаются).
        Поэтому TLS терминируйте на nginx/Caddy и проксируйте на этот сервер (host:port), например:
            https://bot.example.com/max-webhook  →  http://127.0.0.1:8080/max-webhook
        Ответ 200 отдаётся сразу (лимит MAX — 30 с), обработка идёт в фоне.
        """
        self._startup(sync_commands)
        path = path or urlparse(url).path or "/"
        if register:
            for s in self.client.get_subscriptions():
                if s.get("url") != url:
                    log.info("Удаляю старую подписку: %s", s.get("url"))
                    self.client.unsubscribe(s["url"])
            self.client.subscribe(url, list(update_types) if update_types else self._update_types(), secret)
            log.info("Webhook зарегистрирован: %s", url)

        bot = self

        class Handler(BaseHTTPRequestHandler):
            def _reply(self, code: int, body: bytes = b"ok"):
                self.send_response(code)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):  # health-check
                self._reply(200 if self.path.split("?")[0] in ("/health", "/healthz") else 404)

            def do_POST(self):
                if self.path.split("?")[0] != path:
                    return self._reply(404, b"not found")
                if secret:
                    got = self.headers.get("X-Max-Bot-Api-Secret", "")
                    if not hmac.compare_digest(got, secret):
                        log.warning("Webhook: неверный secret от %s", self.client_address[0])
                        return self._reply(403, b"forbidden")
                try:
                    length = int(self.headers.get("Content-Length", 0))
                    if length <= 0 or length > 5_000_000:
                        return self._reply(400, b"bad length")
                    update = json.loads(self.rfile.read(length))
                except (ValueError, json.JSONDecodeError):
                    return self._reply(400, b"bad json")
                self._reply(200)
                bot.dispatch_async(update)

            def log_message(self, fmt, *args):
                log.debug("webhook http: " + fmt, *args)

        self._server = ThreadingHTTPServer((host, port), Handler)
        log.info("Webhook-сервер слушает %s:%d%s. Ctrl+C — остановка.", host, port, path)
        try:
            self._server.serve_forever()
        except KeyboardInterrupt:
            log.info("Остановка по Ctrl+C")
        finally:
            self.shutdown()

    def stop(self) -> None:
        """Остановить polling/webhook из другого потока."""
        self._stop.set()
        if self._server:
            threading.Thread(target=self._server.shutdown, daemon=True).start()

    def shutdown(self) -> None:
        self._stop.set()
        if self._server:
            self._server.server_close()
        for p in self._pools:
            p.shutdown(wait=True)
        log.info("Бот остановлен")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "install-certs":
        try:
            path = build_ca_bundle(sys.argv[2] if len(sys.argv) > 2 else None)
        except Exception as exc:  # noqa: BLE001
            raise SystemExit(f"Не удалось создать bundle: {exc}")
        print(f"Готово: {path}\nБиблиотека подхватит его автоматически "
              f"(или задайте MAX_CA_BUNDLE={path}).")
    else:
        print("Использование:\n  python max_bot.py install-certs [путь_к_bundle.pem]")