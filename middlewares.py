from functools import wraps
from telegram import Update
from telegram.constants import ParseMode
from telegram.ext import ContextTypes

import config


def _admin_ids() -> list[int]:
    """Normalizza ADMIN_IDS a lista, che sia int o list."""
    ids = config.ADMIN_IDS
    if isinstance(ids, int):
        return [ids]
    return list(ids)


def is_admin(tg_id: int) -> bool:
    return tg_id in _admin_ids()


def admin_only(func):
    @wraps(func)
    async def wrapper(update: Update, ctx: ContextTypes.DEFAULT_TYPE, *args, **kwargs):
        uid = update.effective_user.id if update.effective_user else None
        if not uid or uid not in _admin_ids():
            if update.callback_query:
                await update.callback_query.answer("⛔ Solo admin.", show_alert=True)
            elif update.effective_message:
                await update.effective_message.reply_text(
                    "⛔ Comando riservato all'amministratore.",
                    parse_mode=ParseMode.HTML,
                )
            return
        return await func(update, ctx, *args, **kwargs)
    return wrapper
