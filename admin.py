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


async def send_security_alert(bot, title: str, details: str, level: str = "WARN"):
    """Invia un alert di sicurezza SIEM o notifica di gestione in tempo reale agli ADMIN_IDS."""
    icons = {
        "INFO": "ℹ️",
        "WARN": "⚠️",
        "CRITICAL": "🚨",
        "SUCCESS": "✅"
    }
    icon = icons.get(level.upper(), "⚠️")
    
    msg = (
        f"🛡 <b>SIEM AUDIT & NOTICES | {level.upper()}</b> {icon}\n\n"
        f"📌 <b>{title}</b>\n"
        f"<code>{esc(details)}</code>\n\n"
        f"⏱ <i>Stato: Monitoraggio Attivo</i>"
    )
    
    for admin_id in getattr(config, "ADMIN_IDS", []):
        try:
            await bot.send_message(
                chat_id=admin_id,
                text=msg,
                parse_mode=ParseMode.HTML
            )
        except Exception as e:
            log.error("Impossibile inviare alert all'admin %s: %s", admin_id, e)


async def _is_admin(update: Update, ctx: ContextTypes.DEFAULT_TYPE = None) -> bool:
    user = update.effective_user
    if not user or user.id not in config.ADMIN_IDS:
        warn_msg = f"Tentativo di accesso admin non autorizzato da parte dell'utente {user.id if user else 'Sconosciuto'}"
        log.warning("SIEM SECURITY ALERT | %s", warn_msg)
        
        if ctx and ctx.bot:
            await send_security_alert(ctx.bot, "Accesso Admin Non Autorizzato", warn_msg, level="CRITICAL")
            
        if update.callback_query:
            await update.callback_query.answer("⛔ Accesso negato: comando riservato agli amministratori.", show_alert=True)
        elif update.effective_message:
            await update.effective_message.reply_text("⛔ Accesso negato.")
        return False
    return True


# ==================== PANNELLO ADMIN PRINCIPALE ====================

async def cmd_admin(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not await _is_admin(update, ctx):
        return
    
    msg = update.message or (update.callback_query.message if update.callback_query else None)
    if not msg:
        return

    text = (
        "👑 <b>Pannello di Amministrazione Sicuro</b>\n\n"
        "Seleziona un'opzione dal menu sottostante per gestire il bot, lo shop e le finanze."
    )
    keyboard = [
        [InlineKeyboardButton("📊 Statistiche Bot", callback_data="admin_stats"),
         InlineKeyboardButton("💎 Saldo API", callback_data="admin_pre77bal")],
        [InlineKeyboardButton("📦 Gestione Stock / Restock", callback_data="admin_mystock"),
         InlineKeyboardButton("👥 Gestione Utenti", callback_data="admin_users")],
        [InlineKeyboardButton("📦 Ordini Globali", callback_data="admin_orders"),
         InlineKeyboardButton("🧹 Pulisci Cache", callback_data="admin_clearcache")],
        [InlineKeyboardButton("🔙 Menu Utente", callback_data="menu")]
    ]
    
    if update.callback_query:
        await update.callback_query.answer()
        await update.callback_query.edit_message_text(text, parse_mode=ParseMode.HTML, reply_markup=InlineKeyboardMarkup(keyboard))
    else:
        await msg.reply_text(text, parse_mode=ParseMode.HTML, reply_markup=InlineKeyboardMarkup(keyboard))


async def cb_admin(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not await _is_admin(update, ctx):
        return
    await cmd_admin(update, ctx)


# ==================== GESTIONE SHOP & RESTOCK RAPIDO ====================

async def cmd_mystock(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not await _is_admin(update, ctx):
        return
    api = ctx.bot_data.get("api")
    if not api:
        await update.message.reply_text("❌ API Client non inizializzato.")
        return

    try:
        shop_data = await api.get_shop()
        shop = shop_data.get("shop", {})
        products = shop_data.get("products", [])
    except APIError as e:
        await update.message.reply_text(f"❌ Errore recupero shop: {esc(e.message)}")
        return

    if not products:
        await update.message.reply_text("📦 Nessun prodotto presente nel tuo shop.")
        return

    text = f"🏪 <b>Inventario Shop: {esc(shop.get('name', 'Mio Negozio'))}</b>\n\n"
    keyboard = []

    for p in products:
        p_id = p.get("id")
        title = p.get("title", "Senza nome")
        price = p.get("priceCents", 0) / 100
        stock = p.get("stock", 0)
        
        text += f"• <b>{esc(title)}</b> (ID: <code>{p_id}</code>)\n  Prezzo: ${price:.2f} | Stock: <b>{stock}</b>\n\n"
        keyboard.append([InlineKeyboardButton(f"🔄 Restock: {title[:20]}", callback_data=f"admin_restock:{p_id}")])

    keyboard.append([InlineKeyboardButton("🔙 Indietro", callback_data="admin")])
    
    if update.callback_query:
        await update.callback_query.answer()
        await update.callback_query.edit_message_text(text, parse_mode=ParseMode.HTML, reply_markup=InlineKeyboardMarkup(keyboard))
    else:
        await update.message.reply_text(text, parse_mode=ParseMode.HTML, reply_markup=InlineKeyboardMarkup(keyboard))


async def cb_admin_mystock(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    await cmd_mystock(update, ctx)


async def cb_admin_restock_prompt(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not await _is_admin(update, ctx):
        return
    q = update.callback_query
    await q.answer()
    
    product_id = q.data.split(":")[1]
    ctx.user_data["awaiting"] = f"restock_lines:{product_id}"
    
    await q.edit_message_text(
        f"📦 <b>Restock Prodotto</b>\n\n"
        f"ID Prodotto: <code>{product_id}</code>\n\n"
        f"Invia in un messaggio le nuove linee di consegna (una per riga):\n"
        f"<i>Esempio:</i>\n<code>linea1:pass1\nlinea2:pass2</code>",
        parse_mode=ParseMode.HTML,
        reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙 Annulla", callback_data="admin")]])
    )


async def on_admin_restock_text(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    """Gestisce l'invio del testo di restock da parte dell'admin."""
    awaiting = ctx.user_data.get("awaiting", "")
    if not awaiting.startswith("restock_lines:"):
        return
    if not await _is_admin(update, ctx):
        return

    product_id = awaiting.split(":")[1]
    ctx.user_data.pop("awaiting", None)
    
    lines_text = update.message.text.strip()
    api = ctx.bot_data.get("api")
    
    try:
        res = await api.restock_product(product_id, lines_text)
        new_stock = res.get("stock", 0)
        added = res.get("added", 0)
        
        await update.message.reply_text(
            f"✅ <b>Restock Effettuato con Successo!</b>\n\n"
            f"Linee aggiunte: <b>{added}</b>\n"
            f"Stock totale aggiornato: <b>{new_stock}</b>",
            parse_mode=ParseMode.HTML
        )
        
        await send_security_alert(
            ctx.bot,
            "Restock Prodotti Eseguito",
            f"Prodotto ID: {product_id}\nLinee aggiunte: {added} | Nuovo stock: {new_stock}",
            level="SUCCESS"
        )
    except APIError as e:
        await update.message.reply_text(f"❌ Errore durante il restock: {esc(e.message)}", parse_mode=ParseMode.HTML)


# ==================== STATISTICHE & SALDO ====================

async def cb_admin_stats(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not await _is_admin(update, ctx):
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
    if not await _is_admin(update, ctx):
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
            "💎 <b>Stato Account API</b>\n\n"
            f"👤 Login: <code>{esc(login)}</code>\n"
            f"💰 Saldo: <b>{money(balance_cents)}</b>\n"
            f"⭐ Trusted Seller: <b>{'Sì' if is_trusted else 'No'}</b>"
        )
    except APIError as e:
        text = f"❌ Errore recupero saldo: {esc(e.message)}"

    keyboard = [[InlineKeyboardButton("🔙 Indietro", callback_data="admin")]]
    await q.edit_message_text(text, parse_mode=ParseMode.HTML, reply_markup=InlineKeyboardMarkup(keyboard))


async def cmd_pre77balance(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not await _is_admin(update, ctx):
        return
    api = ctx.bot_data.get("api")
    try:
        me_data = await api.get_me()
        user_info = me_data.get("user", me_data)
        balance_cents = user_info.get("balanceCents", 0)
        await update.message.reply_text(f"💎 Saldo attuale: <b>{money(balance_cents)}</b>", parse_mode=ParseMode.HTML)
    except APIError as e:
        await update.message.reply_text(f"❌ Errore: {esc(e.message)}")


# ==================== GESTIONE UTENTI ====================

async def cb_admin_users(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not await _is_admin(update, ctx):
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

    keyboard = [[InlineKeyboardButton("🔙 Indietro", callback_data="admin")]]
    await q.edit_message_text(text, parse_mode=ParseMode.HTML, reply_markup=InlineKeyboardMarkup(keyboard))


async def cmd_addbalance(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not await _is_admin(update, ctx):
        return
    args = ctx.args
    if len(args) < 2 or not args[0].isdigit():
        await update.message.reply_text("ℹ️ Uso: <code>/addbalance TG_ID IMPORTO</code>", parse_mode=ParseMode.HTML)
        return

    tg_id = int(args[0])
    try:
        amount = float(args[1].replace(",", "."))
        cents = int(amount * 100)
    except ValueError:
        await update.message.reply_text("❌ Importo non valido.")
        return

    db.credit(tg_id, cents, "ADMIN_CREDIT", note=f"Aggiunto da admin {update.effective_user.id}")
    await update.message.reply_text(f"✅ Accredito di <b>{money(cents)}</b> effettuato all'utente <code>{tg_id}</code>.", parse_mode=ParseMode.HTML)


async def cmd_subbalance(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not await _is_admin(update, ctx):
        return
    args = ctx.args
    if len(args) < 2 or not args[0].isdigit():
        await update.message.reply_text("ℹ️ Uso: <code>/subbalance TG_ID IMPORTO</code>", parse_mode=ParseMode.HTML)
        return

    tg_id = int(args[0])
    try:
        amount = float(args[1].replace(",", "."))
        cents = int(amount * 100)
    except ValueError:
        await update.message.reply_text("❌ Importo non valido.")
        return

    if not db.try_debit(tg_id, cents, "ADMIN_DEBIT", note=f"Rimosso da admin {update.effective_user.id}"):
        await update.message.reply_text("❌ Saldo utente insufficiente.")
        return

    await update.message.reply_text(f"✅ Sottrazione di <b>{money(cents)}</b> effettuata all'utente <code>{tg_id}</code>.", parse_mode=ParseMode.HTML)


async def cmd_ban(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not await _is_admin(update, ctx):
        return
    args = ctx.args
    if not args or not args[0].isdigit():
        await update.message.reply_text("ℹ️ Uso: <code>/ban TG_ID</code>", parse_mode=ParseMode.HTML)
        return
    tg_id = int(args[0])
    db.set_ban(tg_id, True)
    await update.message.reply_text(f"🔴 Utente <code>{tg_id}</code> bannato.", parse_mode=ParseMode.HTML)


async def cmd_unban(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not await _is_admin(update, ctx):
        return
    args = ctx.args
    if not args or not args[0].isdigit():
        await update.message.reply_text("ℹ️ Uso: <code>/unban TG_ID</code>", parse_mode=ParseMode.HTML)
        return
    tg_id = int(args[0])
    db.set_ban(tg_id, False)
    await update.message.reply_text(f"🟢 Utente <code>{tg_id}</code> sbannato.", parse_mode=ParseMode.HTML)


async def cmd_setkey(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not await _is_admin(update, ctx):
        return
    args = ctx.args
    if not args:
        await update.message.reply_text("ℹ️ Uso: <code>/setkey API_KEY</code>", parse_mode=ParseMode.HTML)
        return
    new_key = args[0].strip()
    api = ctx.bot_data.get("api")
    if api:
        api.update_api_key(new_key)
        await update.message.reply_text("🔑 <b>Chiave API aggiornata!</b>", parse_mode=ParseMode.HTML)


async def cmd_clearcache(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not await _is_admin(update, ctx):
        return
    cache = ctx.bot_data.setdefault("cc_cache", {})
    cache.clear()
    txt = "🧹 <b>Cache pulita.</b>"
    if update.callback_query:
        await update.callback_query.answer(txt, show_alert=True)
    elif update.message:
        await update.message.reply_text(txt, parse_mode=ParseMode.HTML)


async def cb_admin_orders(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not await _is_admin(update, ctx):
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


cmd_admin_users = cb_admin_users

async def cb_admin_pending(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not await _is_admin(update, ctx):
        return
    await update.callback_query.answer()
    await update.callback_query.edit_message_text("📦 Nessun ordine in attesa.", reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙 Indietro", callback_data="admin")]]))

async def cb_admin_deposits(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not await _is_admin(update, ctx):
        return
    await update.callback_query.answer()
    await update.callback_query.edit_message_text("💳 Storico depositi.", reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙 Indietro", callback_data="admin")]]))

async def cmd_id(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    u = update.effective_user
    chat = update.effective_chat
    await update.message.reply_text(f"👤 User ID: <code>{u.id if u else 'N/D'}</code>\n💬 Chat ID: <code>{chat.id if chat else 'N/D'}</code>", parse_mode=ParseMode.HTML)

async def cmd_userinfo(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not await _is_admin(update, ctx):
        return
    await update.message.reply_text("ℹ️ Uso: <code>/userinfo TG_ID</code>", parse_mode=ParseMode.HTML)

async def cmd_deposits(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not await _is_admin(update, ctx):
        return
    await update.message.reply_text("ℹ️ Gestione depositi.")

async def cmd_db_wipe(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not await _is_admin(update, ctx):
        return
    await update.message.reply_text("⚠️ Comando protetto.")

async def cmd_statusbot(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not await _is_admin(update, ctx):
        return
    await update.message.reply_text("🟢 Bot Online in modalità Webhook.")

async def cmd_stats(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not await _is_admin(update, ctx):
        return
    await cb_admin_stats(update, ctx)

async def cmd_pending(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    pass

async def cmd_deliver(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    pass

async def cmd_refund(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    pass

async def on_delivery_text(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    pass
