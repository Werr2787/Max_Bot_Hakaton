"""
example_bot.py — демонстрация всех возможностей библиотеки max_bot.py.

Запуск (разработка, long polling):
    export MAX_BOT_TOKEN="ваш_токен"
    python example_bot.py

Запуск (production, webhook за nginx/Caddy с HTTPS):
    export MAX_BOT_TOKEN="..."
    export MODE=webhook
    export WEBHOOK_URL="https://bot.example.com/max-webhook"
    export WEBHOOK_SECRET="любая_строка_из_A-Za-z0-9_-"     # 5–256 символов
    export PORT=8080
    python example_bot.py

Необязательные переменные:
    ADMIN_IDS="123,456"          — user_id администраторов бота (для /broadcast, /stats)
    STOP_WORDS="слово1,слово2"   — модерация комментариев в канале (нужен webhook/polling + права админа)
    LOG_LEVEL=DEBUG
"""
import logging
import os
import time
from Tikitak import TOKEN

from max_bot import (
    Attachment, Bot, Button, Context, Keyboard, MaxAPIError,
    deeplink, mention, parse_vcf, split_text,
)
MAX_BOT_TOKEN="f9LHodD0cOLXq3Ycv5c5b82ODmn0Wag_swstsBwgP0s0yYbBcUDl0CH4O0t4g1bdMnpmMwj9zJpMA_5hJPaT"
logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"),
                    format="%(asctime)s %(levelname)-7s %(name)s: %(message)s")
log = logging.getLogger("example_bot")

if not TOKEN:
    raise SystemExit("Задайте переменную окружения MAX_BOT_TOKEN")

ADMIN_IDS = {int(x) for x in os.getenv("ADMIN_IDS", "").split(",") if x.strip().isdigit()}
STOP_WORDS = [w.strip().lower() for w in os.getenv("STOP_WORDS", "").split(",") if w.strip()]

bot = Bot(TOKEN, default_format="markdown", workers=4)


# ══════════════════════════════════════════════════════════════════════════════
#  Middleware: логирование и замер времени
# ══════════════════════════════════════════════════════════════════════════════
@bot.middleware
def timing(ctx: Context, call_next):
    t0 = time.perf_counter()
    try:
        return call_next()
    finally:
        log.info("%-17s user=%s chat=%s %.0f мс", ctx.type, ctx.user_id, ctx.chat_id,
                 (time.perf_counter() - t0) * 1000)


@bot.error
def on_error(ctx: Context, exc: Exception):
    log.exception("Ошибка в обработчике", exc_info=exc)
    if ctx.type == "message_created":
        try:
            ctx.reply("😕 Что-то пошло не так. Попробуйте ещё раз позже.")
        except MaxAPIError:
            pass


def is_admin(ctx: Context) -> bool:
    return ctx.user_id in ADMIN_IDS


# ══════════════════════════════════════════════════════════════════════════════
#  Главное меню
# ══════════════════════════════════════════════════════════════════════════════
def main_menu() -> Keyboard:
    return (Keyboard()
            .row(Button.callback("🛒 Каталог", "menu:catalog"), Button.callback("🔢 Счётчик", "counter:0"))
            .row(Button.callback("📝 Анкета", "menu:form"), Button.callback("❓ Помощь", "menu:help"))
            .row(Button.link("🌐 Документация", "https://dev.max.ru/docs")))


@bot.bot_started()
def on_start(ctx: Context):
    """Пользователь нажал «Начать» или пришёл по диплинку https://max.ru/<бот>?start=<payload>."""
    extra = f"\n\nВы пришли по ссылке с параметром: `{ctx.payload}`" if ctx.payload else ""
    ctx.reply(f"👋 Привет, **{ctx.user_name}**! Я демо-бот на Python.{extra}\n\nВыберите действие:",
              keyboard=main_menu())


@bot.command("start", description="Главное меню")
def cmd_start(ctx: Context):
    ctx.reply(f"Привет, **{ctx.user_name}**! Выберите действие:", keyboard=main_menu())


@bot.command("help", "menu", description="Список возможностей")
def cmd_help(ctx: Context):
    ctx.reply(
        "**Что я умею**\n"
        "/start — главное меню\n"
        "/form — анкета (пошаговый диалог + проверка телефона)\n"
        "/location — запросить геолокацию\n"
        "/format — примеры форматирования\n"
        "/photo `<url>` — отправить картинку по ссылке\n"
        "/file — отправить файл (этот скрипт)\n"
        "/link — диплинк на этого бота\n"
        "/quote — ответ цитатой\n"
        "/buttons — все типы кнопок\n"
        "/long — очень длинное сообщение\n"
        "/cancel — отменить текущий диалог\n\n"
        "**В группах:** /title, /pin, /unpin, /members, /admins, /leave\n"
        "**Админу бота:** /stats, /broadcast"
    )


# ══════════════════════════════════════════════════════════════════════════════
#  Callback-кнопки: меню, счётчик (редактирование сообщения), подтверждение
# ══════════════════════════════════════════════════════════════════════════════
@bot.callback(prefix="counter:")
def on_counter(ctx: Context):
    n = int(ctx.payload.split(":", 1)[1]) + 1
    kb = (Keyboard()
          .row(Button.callback(f"➕ Нажато: {n}", f"counter:{n}"))
          .row(Button.callback("🔄 Сбросить", "counter:-1", intent="negative"),
               Button.callback("⬅️ Меню", "menu:home")))
    # notification — всплывающее уведомление; text/keyboard — заменяют исходное сообщение
    ctx.answer(notification=f"Счёт: {n}", text=f"Вы нажали кнопку **{n}** раз(а)", keyboard=kb)


@bot.callback("menu:home")
def on_home(ctx: Context):
    ctx.answer(text="Главное меню:", keyboard=main_menu())


@bot.callback("menu:help")
def on_menu_help(ctx: Context):
    ctx.answer("Открываю справку")
    cmd_help(ctx)


@bot.callback("menu:form")
def on_menu_form(ctx: Context):
    ctx.answer()
    start_form(ctx)


PRODUCTS = {"tea": ("🍵 Чай", 250), "coffee": ("☕ Кофе", 350), "cake": ("🍰 Торт", 500)}


@bot.callback("menu:catalog")
def on_catalog(ctx: Context):
    kb = Keyboard()
    for key, (title, price) in PRODUCTS.items():
        kb.row(Button.callback(f"{title} — {price} ₽", f"buy:{key}"))
    kb.row(Button.callback("⬅️ Меню", "menu:home"))
    ctx.answer(text="**Каталог**\nВыберите товар:", keyboard=kb)


@bot.callback(regex=r"^buy:(\w+)$")
def on_buy(ctx: Context):
    key = ctx.match.group(1)
    title, price = PRODUCTS.get(key, ("?", 0))
    kb = Keyboard().row(
        Button.callback("✅ Подтвердить", f"confirm:{key}", intent="positive"),
        Button.callback("✖️ Отмена", "menu:catalog", intent="negative"),
    ).row(Button.clipboard("📋 Скопировать промокод", "MAX2026"))
    ctx.answer(text=f"Вы выбрали **{title}** за {price} ₽.\nПодтвердить заказ?", keyboard=kb)


@bot.callback(prefix="confirm:")
def on_confirm(ctx: Context):
    title, price = PRODUCTS[ctx.payload.split(":", 1)[1]]
    # attachments=[] — убрать клавиатуру
    ctx.answer(notification="Заказ принят ✅", text=f"✅ Заказ оформлен: {title}, {price} ₽. Спасибо!",
               attachments=[])


# ══════════════════════════════════════════════════════════════════════════════
#  Диалог с состояниями: /form → имя → телефон (request_contact) → подтверждение
# ══════════════════════════════════════════════════════════════════════════════
def start_form(ctx: Context):
    ctx.set_state("form:name")
    ctx.reply("Как вас зовут? (напишите имя, или /cancel для отмены)")


@bot.command("form")
def cmd_form(ctx: Context):
    start_form(ctx)


@bot.command("cancel")
def cmd_cancel(ctx: Context):
    ctx.clear_state()
    ctx.reply("Диалог отменён. /start — меню.")


@bot.message(state="form:name")
def form_name(ctx: Context):
    name = ctx.text.strip()
    if not 2 <= len(name) <= 60:
        return ctx.reply("Имя должно быть от 2 до 60 символов. Попробуйте ещё раз.")
    ctx.set_state("form:phone", name=name)
    kb = Keyboard().row(Button.request_contact("📱 Поделиться номером"))
    ctx.reply(f"Приятно познакомиться, **{name}**! Нажмите кнопку, чтобы поделиться номером телефона.",
              keyboard=kb)


@bot.message(state="form:phone", content_type="contact")
def form_phone(ctx: Context):
    contact = ctx.contact or {}
    phone = parse_vcf(contact.get("vcf_info", "")).get("phone", "не удалось определить")
    # hash есть только если контакт отправлен именно кнопкой request_contact
    verified = ctx.contact_verified()
    name = ctx.data.get("name", "—")
    ctx.clear_state()
    ctx.reply(f"**Анкета получена**\nИмя: {name}\nТелефон: {phone}\n"
              f"Подтверждён MAX: {'да ✅' if verified else 'нет ⚠️ (контакт отправлен не кнопкой)'}")


@bot.message(state="form:phone")
def form_phone_wrong(ctx: Context):
    ctx.reply("Нажмите кнопку «Поделиться номером» под предыдущим сообщением или /cancel.")


# ══════════════════════════════════════════════════════════════════════════════
#  Геолокация, кнопки всех типов, форматирование
# ══════════════════════════════════════════════════════════════════════════════
@bot.command("location")
def cmd_location(ctx: Context):
    ctx.reply("Отправьте свою геолокацию:", keyboard=Keyboard().row(Button.request_geo("📍 Где я")))


@bot.message(content_type="location")
def on_location(ctx: Context):
    loc = ctx.location or {}
    ctx.reply(f"📍 Получено: {loc.get('latitude')}, {loc.get('longitude')}")
    # и отправим точку обратно как вложение
    ctx.reply("Ваша точка на карте:",
              attachments=[Attachment.location(loc["latitude"], loc["longitude"])])


@bot.command("buttons")
def cmd_buttons(ctx: Context):
    kb = (Keyboard()
          .row(Button.callback("Callback", "demo:cb"), Button.message("Отправить текст"))
          .row(Button.link("Ссылка", "https://dev.max.ru"))
          .row(Button.request_contact(), Button.request_geo())
          .row(Button.clipboard("Копировать", "Текст в буфере")))
    ctx.reply("Все основные типы кнопок:", keyboard=kb)


@bot.callback("demo:cb")
def demo_cb(ctx: Context):
    ctx.answer("Callback получен!")


@bot.command("format")
def cmd_format(ctx: Context):
    ctx.reply("# Markdown\n**жирный**, *курсив*, ~~зачёркнутый~~, ++подчёркнутый++, ^^выделенный^^, `код`\n"
              "[ссылка](https://dev.max.ru)\n> цитата\n"
              f"Упоминание: {mention(ctx.user_name, ctx.user_id)}")
    ctx.reply("<h2>HTML</h2><b>жирный</b>, <i>курсив</i>, <u>подчёркнутый</u>, <s>зачёркнутый</s>, "
              "<code>код</code>, <mark>выделенный</mark><br>"
              "<a href=\"https://dev.max.ru\">ссылка</a><blockquote>цитата</blockquote>",
              format="html")


@bot.command("quote")
def cmd_quote(ctx: Context):
    ctx.reply_quote("Это ответ с цитированием вашего сообщения.")


@bot.command("long")
def cmd_long(ctx: Context):
    text = "\n".join(f"Строка {i}: " + "lorem ipsum " * 8 for i in range(1, 200))
    for part in split_text(text):
        ctx.reply(part, format=None)


@bot.command("link")
def cmd_link(ctx: Context):
    username = (bot.me or {}).get("username", "")
    ctx.reply(f"Диплинк с параметром:\n{deeplink(username, f'ref_{ctx.user_id}')}", format=None)


# ══════════════════════════════════════════════════════════════════════════════
#  Медиа: фото по ссылке, файл, приём вложений
# ══════════════════════════════════════════════════════════════════════════════
@bot.command("photo")
def cmd_photo(ctx: Context):
    if not ctx.args.startswith("http"):
        return ctx.reply("Использование: /photo https://example.com/picture.jpg")
    ctx.reply("Вот ваша картинка:", attachments=[Attachment.image(url=ctx.args)])


@bot.command("file")
def cmd_file(ctx: Context):
    if ctx.chat_type == "chat":
        ctx.client.send_action(ctx.chat_id, "sending_file")
    ctx.client.send_file(__file__, chat_id=ctx.chat_id, text="Исходник этого бота 📎")


@bot.message(content_type="image")
def on_image(ctx: Context):
    n = sum(1 for a in ctx.attachments if a.get("type") == "image")
    ctx.reply_quote(f"Получил изображений: {n} 🖼")


@bot.message(content_type="file")
def on_file(ctx: Context):
    f = ctx.attachment("file") or {}
    p = f.get("payload", {})
    ctx.reply_quote(f"Получил файл: {f.get('filename') or p.get('filename') or 'без имени'} "
                    f"({f.get('size', '?')} байт)", format=None)


@bot.message(content_type="contact")
def on_contact(ctx: Context):
    ctx.reply(f"Контакт получен. Подтверждён MAX: {'да' if ctx.contact_verified() else 'нет'}")


# ══════════════════════════════════════════════════════════════════════════════
#  Группы и каналы: события, управление чатом
# ══════════════════════════════════════════════════════════════════════════════
@bot.on("bot_added")
def on_bot_added(ctx: Context):
    where = "канал" if ctx.update.get("is_channel") else "чат"
    log.info("Бота добавили в %s %s", where, ctx.chat_id)
    ctx.reply(f"Всем привет! Я бот. Чтобы я видел все сообщения, сделайте меня администратором. /help")


@bot.on("user_added")
def on_user_added(ctx: Context):
    u = ctx.update.get("user") or {}
    ctx.reply(f"Добро пожаловать, {mention(u.get('name', 'друг'), u.get('user_id'))}! 👋")


@bot.on("user_removed")
def on_user_removed(ctx: Context):
    log.info("Пользователь покинул чат %s: %s", ctx.chat_id, ctx.update.get("user"))


@bot.on("bot_stopped", "dialog_removed")
def on_stopped(ctx: Context):
    log.info("Пользователь %s остановил бота / удалил диалог", ctx.user_id)
    ctx.clear_state()


@bot.on("chat_title_changed")
def on_title_changed(ctx: Context):
    ctx.reply(f"Название чата изменено: **{ctx.update.get('title')}**")


def _group_only(ctx: Context) -> bool:
    if ctx.chat_type not in ("chat", "channel"):
        ctx.reply("Эта команда работает только в групповых чатах и каналах.")
        return False
    return True


@bot.command("title")
def cmd_title(ctx: Context):
    if not _group_only(ctx):
        return
    if not ctx.args:
        return ctx.reply("Использование: /title Новое название")
    ctx.client.edit_chat(ctx.chat_id, title=ctx.args[:200])


@bot.command("pin")
def cmd_pin(ctx: Context):
    if not _group_only(ctx):
        return
    if not ctx.args:
        return ctx.reply("Использование: /pin текст для закрепления")
    sent = ctx.reply(ctx.args)
    ctx.client.pin_message(ctx.chat_id, sent["body"]["mid"], notify=True)


@bot.command("unpin")
def cmd_unpin(ctx: Context):
    if _group_only(ctx):
        ctx.client.unpin_message(ctx.chat_id)
        ctx.reply("Сообщение откреплено")


@bot.command("members")
def cmd_members(ctx: Context):
    if not _group_only(ctx):
        return
    members = list(ctx.client.iter_members(ctx.chat_id))
    names = ", ".join(m.get("name", str(m.get("user_id"))) for m in members[:50])
    ctx.reply(f"Участников: **{len(members)}**\n{names}{' …' if len(members) > 50 else ''}", format="markdown")


@bot.command("admins")
def cmd_admins(ctx: Context):
    if not _group_only(ctx):
        return
    admins = ctx.client.get_admins(ctx.chat_id).get("members", [])
    lines = [f"• {a.get('name', a.get('user_id'))}: {', '.join(a.get('permissions') or []) or 'владелец'}"
             for a in admins]
    ctx.reply("**Администраторы**\n" + "\n".join(lines))


@bot.command("leave", filter=is_admin)
def cmd_leave(ctx: Context):
    if _group_only(ctx):
        ctx.reply("Ухожу 👋")
        ctx.client.leave_chat(ctx.chat_id)


# ══════════════════════════════════════════════════════════════════════════════
#  Модерация комментариев в канале (нужны включённые комментарии и права админа)
# ══════════════════════════════════════════════════════════════════════════════
@bot.on("comment_created")
def on_comment(ctx: Context):
    log.debug("comment_created: %s", ctx.update)   # структуру Update смотрите здесь при первом запуске
    if not STOP_WORDS:
        return
    text = (ctx.text or "").lower()
    if not any(w in text for w in STOP_WORDS):
        return
    msg = ctx.message or {}
    post_id = (msg.get("recipient") or {}).get("post_id")
    comment_id = (msg.get("body") or {}).get("mid")
    if post_id and comment_id:
        ctx.client.delete_comment(post_id, comment_id)
        ctx.client.send_comment(post_id, "Комментарий удалён за нарушение правил канала")


# ══════════════════════════════════════════════════════════════════════════════
#  Админские команды
# ══════════════════════════════════════════════════════════════════════════════
@bot.command("stats", filter=is_admin)
def cmd_stats(ctx: Context):
    by_type = {}
    for info in bot.known_chats.values():
        by_type[info.get("type", "?")] = by_type.get(info.get("type", "?"), 0) + 1
    ctx.reply(f"Известных чатов: {len(bot.known_chats)}\nПо типам: {by_type}", format=None)


@bot.command("broadcast", filter=is_admin)
def cmd_broadcast(ctx: Context):
    if not ctx.args:
        return ctx.reply("Использование: /broadcast текст")
    dialogs = [cid for cid, i in bot.known_chats.items() if i.get("type") == "dialog"]
    failed = 0
    for cid in dialogs:
        try:
            ctx.client.send_message(ctx.args, chat_id=cid)
        except MaxAPIError:
            failed += 1
    ctx.reply(f"Рассылка завершена: {len(dialogs) - failed} ок, {failed} ошибок", format=None)


# ══════════════════════════════════════════════════════════════════════════════
#  Всё остальное
# ══════════════════════════════════════════════════════════════════════════════
@bot.message(chat_type="dialog")
def echo(ctx: Context):
    """Обычный текст в личке: эхо с цитатой + «печатает…»."""
    if ctx.text:
        ctx.reply_quote(f"Вы написали: {ctx.text}", format=None)


@bot.fallback
def unknown(ctx: Context):
    if ctx.type == "message_created" and ctx.chat_type == "dialog":
        ctx.reply("Не понял. Попробуйте /help")


# ══════════════════════════════════════════════════════════════════════════════
#  Запуск
# ══════════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    if os.getenv("MODE", "polling") == "webhook":
        bot.run_webhook(
            url=os.environ["WEBHOOK_URL"],
            secret=os.getenv("WEBHOOK_SECRET"),
            port=int(os.getenv("PORT", "8080")),
        )
    else:
        # drop_webhook=True — снять webhook-подписку, иначе long polling не получит события
        bot.run_polling(drop_webhook=True)
