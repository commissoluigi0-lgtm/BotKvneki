from __future__ import annotations

import logging
import html
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.constants import ParseMode
from telegram.ext import ContextTypes

import config
import db
from api_client import APIError

log = logging.getLogger(__name__)


def esc(v) -> str:
    return html.escape(str(v if v is not None else ""))


def money(cents) -> str:
    try:
        return f"${int(cents) / 100:.2f}"
    except (TypeError, ValueError):
        return "—"


async def _is_admin(update: Update) -> bool:
    user = update.effective_user
    if not user or user.id not in config.ADMIN_IDS:
        log.warning("SIEM SECURITY ALERT | Tentativo di accesso admin non autorizzato da parte dell'utente %s", user.id if user else "Sconosciuto")
        if update.callback_query:
            await update.callback_query.answer("⛔ Accesso negato: comando riservato agli amministratori.", show_alert=True)
        elif update.effective_message:
            await update.effective_message.reply_text("⛔ Accesso negato.")
        return False
    return True


# ==================== PANNELLO ADMIN PRINCIPALE ====================

async def cmd_admin(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not await _is_admin(update):
        return
    
    msg = update.message or (update.callback_query.message if update.callback_query else None)
    if not msg:
        return

    text = (
        "👑 <b>Pannello di Amministrazione Sicuro</b>\n\n"
        "Seleziona un'opzione dal menu sottostante per gestire il bot, gli utenti e le finanze."
    )
    keyboard = [
        [InlineKeyboardButton("📊 Statistiche Bot", callback_data="admin_stats"),
         InlineKeyboardButton("💎 Saldo Pre77", callback_data="admin_pre77bal")],
        [InlineKeyboardButton("👥 Gestione Utenti", callback_data="admin_users"),
         InlineKeyboardButton("📦 Ordini & Transazioni", callback_data="admin_orders")],
        [InlineKeyboardButton("🧹 Pulisci Cache", callback_data="admin_clearcache"),
         InlineKeyboardButton("🔙 Menu Utente", callback_data="menu")]
    ]
    
    if update.callback_query:
        await update.callback_query.answer()
        await update.callback_query.edit_message_text(text, parse_mode=ParseMode.HTML, reply_markup=InlineKeyboardMarkup(keyboard))
    else:
        await msg.reply_text(text, parse_mode=ParseMode.HTML, reply_markup=InlineKeyboardMarkup(keyboard))


async def cb_admin(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not await _is_admin(update):
        return
    await cmd_admin(update, ctx)


# ==================== STATISTICHE & SALDO PRE77 ====================

async def cb_admin_stats(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not await _is_admin(update):
        return
    q = update.callback_query
    await q.answer()

    conn = db._connect()
    try:
        users_count = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        orders_count = conn.execute("SELECT COUNT(*) FROM orders").fetchone()[0]
        total_topup = conn.execute("SELECT SUM(amount_cents) FROM transactions WHERE type = 'TOPUP'").fetchone()[0] or 0
    finally:
        conn.close()

    text = (
        "📊 <b>Statistiche Generali Bot</b>\n\n"
        f"👥 Utenti Registrati: <b>{users_count}</b>\n"
        f"📦 Ordini Effettuati: <b>{orders_count}</b>\n"
        f"💵 Totale Ricariche: <b>{money(total_topup)}</b>"
    )
    keyboard = [[InlineKeyboardButton("🔙 Indietro", callback_data="admin")]]
    await q.edit_message_text(text, parse_mode=ParseMode.HTML, reply_markup=InlineKeyboardMarkup(keyboard))


async def cb_admin_pre77bal(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not await _is_admin(update):
        return
    q = update.callback_query
    await q.answer()

    api = ctx.bot_data.get("api")
    if not api:
        await q.edit_message_text("❌ API Client non inizializzato.", reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙 Indietro", callback_data="admin")]]))
        return

    try:
        me_data = await api.get_me()
        user_info = me_data.get("user", me_data)
        balance_cents = user_info.get("balanceCents", 0)
        login = user_info.get("login", "N/D")
        is_trusted = user_info.get("isTrustedSeller", False)

        text = (
            "💎 <b>Stato Account Pre77 (API)</b>\n\n"
            f"👤 Login: <code>{esc(login)}</code>\n"
            f"💰 Saldo Pre77: <b>{money(balance_cents)}</b>\n"
            f"⭐ Trusted Seller: <b>{'Sì' if is_trusted else 'No'}</b>"
        )
    except APIError as e:
        text = f"❌ Errore recupero saldo Pre77: {esc(e.message)}"

    keyboard = [[InlineKeyboardButton("🔙 Indietro", callback_data="admin")]]
    await q.edit_message_text(text, parse_mode=ParseMode.HTML, reply_markup=InlineKeyboardMarkup(keyboard))


async def cmd_pre77balance(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not await _is_admin(update):
        return
    api = ctx.bot_data.get("api")
    try:
        me_data = await api.get_me()
        user_info = me_data.get("user", me_data)
        balance_cents = user_info.get("balanceCents", 0)
        await update.message.reply_text(f"💎 Saldo Pre77 attuale: <b>{money(balance_cents)}</b>", parse_mode=ParseMode.HTML)
    except APIError as e:
        await update.message.reply_text(f"❌ Errore: {esc(e.message)}")


# ==================== GESTIONE UTENTI & BILANCIO ====================

async def cb_admin_users(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not await _is_admin(update):
        return
    q = update.callback_query
    await q.answer()

    conn = db._connect()
    try:
        users = conn.execute("SELECT tg_id, username, first_name, balance_cents, is_banned FROM users LIMIT 15").fetchall()
    finally:
        conn.close()

    text = "👥 <b>Ultimi Utenti Registrati</b>\n\n"
    for u in users:
        status = "🔴 BANNATO" if u["is_banned"] else "🟢 Attivo"
        text += f"• <code>{u['tg_id']}</code> (@{esc(u['username'] or 'N/D')}) — Saldo: <b>{money(u['balance_cents'])}</b> [{status}]\n"

    keyboard = [
        [InlineKeyboardButton("🔙 Indietro", callback_data="admin")]
    ]
    await q.edit_message_text(text, parse_mode=ParseMode.HTML, reply_markup=InlineKeyboardMarkup(keyboard))


async def cmd_addbalance(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not await _is_admin(update):
        return
    args = ctx.args
    if len(args) < 2 or not args[0].isdigit():
        await update.message.reply_text("ℹ️ Uso corretto: <code>/addbalance TG_ID IMPORTO</code>\n<i>Esempio:</i> <code>/addbalance 123456789 20</code>", parse_mode=ParseMode.HTML)
        return

    tg_id = int(args[0])
    try:
        amount = float(args[1].replace(",", "."))
        cents = int(amount * 100)
    except ValueError:
        await update.message.reply_text("❌ Importo non valido.")
        return

    db.credit(tg_id, cents, "ADMIN_CREDIT", note=f"Aggiunto da admin {update.effective_user.id}")
    log.info("SIEM AUDIT | Admin %s ha aggiunto %s a utente %s", update.effective_user.id, money(cents), tg_id)
    await update.message.reply_text(f"✅ Accredito di <b>{money(cents)}</b> effettuato con successo all'utente <code>{tg_id}</code>.", parse_mode=ParseMode.HTML)


async def cmd_subbalance(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not await _is_admin(update):
        return
    args = ctx.args
    if len(args) < 2 or not args[0].isdigit():
        await update.message.reply_text("ℹ️ Uso corretto: <code>/subbalance TG_ID IMPORTO</code>", parse_mode=ParseMode.HTML)
        return

    tg_id = int(args[0])
    try:
        amount = float(args[1].replace(",", "."))
        cents = int(amount * 100)
    except ValueError:
        await update.message.reply_text("❌ Importo non valido.")
        return

    if not db.try_debit(tg_id, cents, "ADMIN_DEBIT", note=f"Rimosso da admin {update.effective_user.id}"):
        await update.message.reply_text("❌ Impossibile sottrarre il saldo (saldo utente insufficiente).")
        return

    log.info("SIEM AUDIT | Admin %s ha sottratto %s all'utente %s", update.effective_user.id, money(cents), tg_id)
    await update.message.reply_text(f"✅ Sottrazione di <b>{money(cents)}</b> effettuata all'utente <code>{tg_id}</code>.", parse_mode=ParseMode.HTML)


async def cmd_ban(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not await _is_admin(update):
        return
    args = ctx.args
    if not args or not args[0].isdigit():
        await update.message.reply_text("ℹ️ Uso corretto: <code>/ban TG_ID</code>", parse_mode=ParseMode.HTML)
        return

    tg_id = int(args[0])
    db.set_ban(tg_id, True)
    log.warning("SIEM SECURITY | Utente %s bannato dall'admin %s", tg_id, update.effective_user.id)
    await update.message.reply_text(f"🔴 Utente <code>{tg_id}</code> bannato con successo.", parse_mode=ParseMode.HTML)


async def cmd_unban(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not await _is_admin(update):
        return
    args = ctx.args
    if not args or not args[0].isdigit():
        await update.message.reply_text("ℹ️ Uso corretto: <code>/unban TG_ID</code>", parse_mode=ParseMode.HTML)
        return

    tg_id = int(args[0])
    db.set_ban(tg_id, False)
    log.info("SIEM SECURITY | Utente %s sbannato dall'admin %s", tg_id, update.effective_user.id)
    await update.message.reply_text(f"🟢 Utente <code>{tg_id}</code> sbannato con successo.", parse_mode=ParseMode.HTML)


# ==================== UTILITY & CONFIGURAZIONE CHIAVE ====================

async def cmd_setkey(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not await _is_admin(update):
        return
    args = ctx.args
    if not args:
        await update.message.reply_text("ℹ️ Uso corretto: <code>/setkey PRE77_API_KEY</code>", parse_mode=ParseMode.HTML)
        return

    new_key = args[0].strip()
    api = ctx.bot_data.get("api")
    if api:
        api.update_api_key(new_key)
        await update.message.reply_text("🔑 <b>Chiave API Pre77 aggiornata dinamicamente con successo!</b>", parse_mode=ParseMode.HTML)
    else:
        await update.message.reply_text("❌ API Client non trovato in memoria.")


async def cmd_clearcache(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not await _is_admin(update):
        return
    cache = ctx.bot_data.setdefault("cc_cache", {})
    cache.clear()
    
    msg = update.message or (update.callback_query.message if update.callback_query else None)
    txt = "🧹 <b>Cache del catalogo pulita con successo.</b>"
    
    if update.callback_query:
        await update.callback_query.answer(txt, show_alert=True)
    elif msg:
        await msg.reply_text(txt, parse_mode=ParseMode.HTML)


async def cb_admin_orders(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not await _is_admin(update):
        return
    q = update.callback_query
    await q.answer()
    
    conn = db._connect()
    try:
        orders = conn.execute("SELECT id, tg_id, product_title, client_paid_cents, status, created_at FROM orders ORDER BY id DESC LIMIT 10").fetchall()
    finally:
        conn.close()

    text = "📦 <b>Ultimi 10 Ordini Globali</b>\n\n"
    for o in orders:
        text += f"• #{o['id']} | User <code>{o['tg_id']}</code> | <b>{esc(o['product_title'])}</b> — {money(o['client_paid_cents'])} [{o['status']}]\n"

    keyboard = [[InlineKeyboardButton("🔙 Indietro", callback_data="admin")]]
    await q.edit_message_text(text, parse_mode=ParseMode.HTML, reply_markup=InlineKeyboardMarkup(keyboard))


# Stubs aggiuntivi per compatibilità con i comandi richiamati da bot.py
async def cmd_id(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    u = update.effective_user
    chat = update.effective_chat
    await update.message.reply_text(
        f"ℹ️ <b>Info Sessione</b>\n\n"
        f"👤 User ID: <code>{u.id if u else 'N/D'}</code>\n"
        f"💬 Chat ID: <code>{chat.id if chat else 'N/D'}</code>",
        parse_mode=ParseMode.HTML
    )

async def cmd_userinfo(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not await _is_admin(update):
        return
    await update.message.reply_text("ℹ️ Funzionalità userinfo attiva.")

async def cmd_deposits(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not await _is_admin(update):
        return
    await update.message.reply_text("ℹ️ Gestione depositi attiva.")

async def cmd_admin_users(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not await _is_admin(update):
        return

async def cmd_db_wipe(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not await _is_admin(update):
        return

async def cmd_statusbot(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not await _is_admin(update):
        return
    await update.message.reply_text("🟢 Bot Online e Operativo in modalità Webhook.")

async def cmd_stats(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not await _is_admin(update):
        return

async def cmd_pending(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not await _is_admin(update):
        return

async def cmd_deliver(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not await _is_admin(update):
        return

async def cmd_refund(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not await _is_admin(update):
        return

async def on_delivery_text(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    pass

async def cb_admin_stats(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    pass

async def cb_admin_pre77bal(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    pass

async def cb_admin_orders(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    pass

async def cb_admin_pending(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    pass

async def cb_admin_deposits(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    pass
