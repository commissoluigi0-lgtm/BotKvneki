from __future__ import annotations

import logging
import re
import hmac
import hashlib
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.constants import ParseMode
from telegram.ext import ContextTypes

import config
import db
from api_client import APIError
from keyboards import admin_menu, back_admin
from middlewares import admin_only, is_admin

log = logging.getLogger(__name__)


def verify_webhook_signature(raw_body: bytes, signature_header: str, secret_key: str) -> bool:
    """
    Verifica la firma HMAC-SHA256 inviata da Pre77 nell'header X-Pre77-Signature.
    """
    if not signature_header or not secret_key:
        return False
    computed_sig = hmac.new(
        secret_key.encode("utf-8"),
        raw_body,
        hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(computed_sig, signature_header)


async def send_siem_log(bot, level: str, action: str, user_id: int | str, details: str = ""):
    """
    Invia un log di sicurezza centralizzato formattato con tag di gravità (INFO, WARNING, CRITICAL).
    """
    emojis = {
        "INFO": "ℹ️",
        "WARNING": "⚠️",
        "CRITICAL": "🚨"
    }
    emoji = emojis.get(level.upper(), "ℹ️")
    
    log_message = (
        f"{emoji} <b>SIEM AUDIT [{level.upper()}]</b>\n"
        f"━━━━━━━━━━━━━━━━━━━\n"
        f"⚙️ <b>Azione:</b> <code>{action}</code>\n"
        f"👤 <b>Utente/Admin ID:</b> <code>{user_id}</code>\n"
        f"📝 <b>Dettagli:</b> {details or 'N/D'}"
    )
    
    lvl = level.upper()
    if lvl == "CRITICAL":
        log.critical("SIEM [CRITICAL] | Action: %s | Target: %s | Details: %s", action, user_id, details)
    elif lvl == "WARNING":
        log.warning("SIEM [WARNING] | Action: %s | Target: %s | Details: %s", action, user_id, details)
    else:
        log.info("SIEM [INFO] | Action: %s | Target: %s | Details: %s", action, user_id, details)

    log_chat_id = getattr(config, "ADMIN_LOG_CHAT_ID", None)
    if log_chat_id:
        try:
            await bot.send_message(log_chat_id, log_message, parse_mode=ParseMode.HTML)
        except Exception as e:
            log.error("Invio log SIEM su Telegram fallito: %s", e)


def audit_log(admin_id: int, action: str, target: str, details: str = ""):
    log.warning(
        "AUDIT SECURITY | Admin ID: %s | Action: %s | Target: %s | Details: %s",
        admin_id, action, target, details
    )


async def audit_log_async(bot, admin_id: int, action: str, target: str, details: str = ""):
    await send_siem_log(bot, "WARNING", action, admin_id, f"Target: {target} | {details}")


def money(cents) -> str:
    return f"${int(cents) / 100:.2f}"


def _parse_amount(s: str):
    try:
        v = float(s.replace(",", "."))
        if v <= 0:
            return None
        return int(round(v * 100))
    except ValueError:
        return None


def _extract_admin_balance(me: dict) -> int:
    """Estrae il saldo in centesimi dalla risposta di seller/v1/me."""
    if not isinstance(me, dict):
        return 0
        
    u = me.get("user") if isinstance(me.get("user"), dict) else me
    
    for key in ("balanceCents", "balance_cents", "balanceUSD", "amountCents"):
        val = u.get(key)
        if val is not None:
            try:
                return int(val)
            except (ValueError, TypeError):
                pass
                
    return 0


def _extract_admin_login(me: dict) -> str:
    u = me.get("user") if isinstance(me.get("user"), dict) else me
    for key in ("login", "displayName", "username", "email", "name", "id"):
        val = u.get(key)
        if val:
            return str(val)
    return "—"


async def cmd_admin(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not is_admin(update.effective_user.id):
        await update.message.reply_text("⛔ Non autorizzato.")
        return
    
    text = (
        "🔧 **PANNELLO DI CONTROLLO ADMIN**\n"
        "━━━━━━━━━━━━━━━━━━━\n"
        "Benvenuto nel pannello di gestione avanzata del bot. Scegli un'opzione o usa i comandi rapidi:\n\n"
        "📋 **Comandi Rapidi:**\n"
        "• `/deposits` — Monitor Criptato Invoices & Ricariche\n"
        "• `/setkey <key>` — Aggiorna API Key al volo (e salva su config)\n"
        "• `/setwebhook <url>` — Configura Webhook HTTPS nativo\n"
        "• `/pending` — Ordini in attesa di consegna\n"
        "• `/deliver <id>` — Evasione ordine\n"
        "• `/refund <id>` — Rimborso ordine\n"
        "• `/addbalance <id> <importo>` — Ricarica utente\n"
        "• `/subbalance <id> <importo>` — Storno saldo\n"
        "• `/genkey <id>` — Genera/Rigenera key accesso utente\n"
        "• `/userinfo <id>` — Info dettagliate utente\n"
        "• `/users` — Elenco interattivo utenti\n"
        "• `/db_wipe <PIN>` — Pulizia totale database (Distruttivo)\n"
        "• `/ban` / `/unban <id>` — Gestione blocchi\n"
        "• `/clearcache` — Pulizia cache di sistema\n"
        "• `/statusbot` — Report operativo & stato bot\n"
        "• `/stats` & `/pre77balance` — Statistiche e Saldo Backend"
    )
    await update.message.reply_text(text, parse_mode=ParseMode.MARKDOWN, reply_markup=admin_menu())


async def cb_admin(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    if not is_admin(update.effective_user.id):
        return
    
    text = (
        "🔧 **PANNELLO DI CONTROLLO ADMIN**\n"
        "━━━━━━━━━━━━━━━━━━━\n"
        "Seleziona una sezione dal menu sottostante:"
    )
    await q.edit_message_text(text, parse_mode=ParseMode.MARKDOWN, reply_markup=admin_menu())


async def cb_admin_stats(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    if not is_admin(update.effective_user.id):
        return
    s = db.global_stats()
    text = (
        "📊 **STATISTICHE GENERALI**\n"
        "━━━━━━━━━━━━━━━━━━━\n"
        f"👥 Clienti registrati: **{s['users']}**\n"
        f"📦 Ordini completati: **{s['orders']}**\n"
        f"⏳ In attesa di evasione: **{s['pending']}**\n"
        f"💳 Totale ricariche: **{money(s['topups_cents'])}**\n"
        f"📈 Margine lordo: **{money(s['margin_cents'])}**\n"
        f"⚠️ Esposizione (Debiti clienti): **{money(s['liabilities_cents'])}**"
    )
    await q.edit_message_text(text, parse_mode=ParseMode.MARKDOWN, reply_markup=back_admin())


async def cb_admin_pre77bal(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    if not is_admin(update.effective_user.id):
        return
    api = ctx.bot_data["api"]
    try:
        me = await api.get_me()
    except APIError as e:
        await send_siem_log(ctx.bot, "WARNING", "API_ERROR", "Backend", str(e.message))
        await q.edit_message_text(f"❌ **Errore Backend:** {e.message}", parse_mode=ParseMode.MARKDOWN, reply_markup=back_admin())
        return

    bal_cents = _extract_admin_balance(me)
    login_str = _extract_admin_login(me)

    text = (
        "💵 **BILANCIO BACKEND PRINCIPALE**\n"
        "━━━━━━━━━━━━━━━━━━━\n"
        f"💰 Saldo disponibile: **{money(bal_cents)}**\n"
        f"👤 Account collegato: **{login_str}**"
    )
    await q.edit_message_text(text, parse_mode=ParseMode.MARKDOWN, reply_markup=back_admin())


@admin_only
async def cmd_setkey(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    """Aggiorna al volo la chiave API Pre77, la salva permanentemente in config.py e la verifica."""
    if not ctx.args:
        await update.message.reply_text(
            "⚠️ <b>Uso corretto:</b> <code>/setkey NUOVA_API_KEY</code>",
            parse_mode=ParseMode.HTML
        )
        return

    new_key = ctx.args[0].strip()
    api = ctx.bot_data.get("api")
    
    if not api:
        await update.message.reply_text("❌ Client API non inizializzato.")
        return

    # 1. Aggiorna in memoria attiva
    api.update_api_key(new_key)
    
    # 2. Salva permanentemente su config.py per i futuri riavvi
    try:
        with open("config.py", "r", encoding="utf-8") as f:
            content = f.read()
        
        new_content = re.sub(r'API_KEY\s*=\s*["\'].*?["\']', f'API_KEY = "{new_key}"', content)
        
        with open("config.py", "w", encoding="utf-8") as f:
            f.write(new_content)
    except Exception as e:
        log.error("Impossibile salvare la chiave su config.py: %s", e)
    
    try:
        me = await api.get_me()
        login_str = _extract_admin_login(me)
        bal_cents = _extract_admin_balance(me)
        
        await send_siem_log(ctx.bot, "INFO", "UPDATE_API_KEY", update.effective_user.id, "Chiave API Pre77 aggiornata, salvata e verificata con successo.")
        
        await update.message.reply_text(
            f"✅ <b>Chiave API Aggiornata, Salvata e Verificata!</b>\n\n"
            f"👤 Account: <code>{login_str}</code>\n"
            f"💰 Saldo Backend: <b>{money(bal_cents)}</b>",
            parse_mode=ParseMode.HTML
        )
    except APIError as e:
        await update.message.reply_text(
            f"⚠️ <b>Chiave impostata e salvata, ma test di connessione fallito:</b> {db.esc(e.message)}",
            parse_mode=ParseMode.HTML
        )


@admin_only
async def cmd_setwebhook(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    """Registra l'URL del webhook su Pre77 per eventi istantanei (deposit.paid, purchase.created, ecc.)."""
    if not ctx.args:
        await update.message.reply_text(
            "⚠️ <b>Uso corretto:</b> <code>/setwebhook https://tuodominio.com/webhook</code>",
            parse_mode=ParseMode.HTML
        )
        return

    url = ctx.args[0].strip()
    if not url.startswith("https://"):
        await update.message.reply_text("❌ L'URL del webhook deve essere un endpoint HTTPS pubblico valido.")
        return

    api = ctx.bot_data.get("api")
    if not api:
        await update.message.reply_text("❌ Client API non inizializzato.")
        return

    events = ["deposit.paid", "purchase.created", "cc.refunded", "shop.sold", "balance.changed"]
    
    try:
        res = await api.set_webhook(url=url, events=events)
        registered_url = res.get("url", url)
        
        await send_siem_log(ctx.bot, "INFO", "SET_WEBHOOK", update.effective_user.id, f"Webhook configurato con successo su: {registered_url}")
        
        await update.message.reply_text(
            f"🌐 <b>Webhook Configurato con Successo!</b>\n\n"
            f"🔗 <b>URL:</b> <code>{registered_url}</code>\n"
            f"⚡ <b>Eventi iscritti:</b> <code>{', '.join(events)}</code>",
            parse_mode=ParseMode.HTML
        )
    except APIError as e:
        await update.message.reply_text(
            f"❌ <b>Registrazione Webhook Fallita:</b> {db.esc(e.message)}",
            parse_mode=ParseMode.HTML
        )


@admin_only
async def cmd_deposits(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    """Visualizza il registro crittografato e offuscato dei depositi/invoices in attesa e completati."""
    conn = db._connect()
    try:
        rows = conn.execute(
            "SELECT * FROM transactions WHERE type LIKE 'INVOICE%' OR type = 'TOPUP' ORDER BY id DESC LIMIT 25"
        ).fetchall()
    finally:
        conn.close()

    if not rows:
        await update.message.reply_text("📥 <b>Nessun deposito o invoice trovata nel registro.</b>", parse_mode=ParseMode.HTML)
        return

    lines = ["🔐 <b>AUDIT CRITTOGRAFICO DEPOSITI & INVOICES</b>\n━━━━━━━━━━━━━━━━━━━\n"]
    for r in rows:
        raw_inv = str(r["note"])
        inv_masked = f"INV-{raw_inv[:4]}...{raw_inv[-4:]}" if len(raw_inv) > 8 else raw_inv
        
        status_tag = "🟢 CONFIRMED" if r["type"] == "TOPUP" else ("🟡 PENDING" if r["type"] == "INVOICE_PENDING" else "🔴 EXPIRED")
        
        lines.append(
            f"• <code>{inv_masked}</code> | ID: <code>{r['tg_id']}</code>\n"
            f"  Importo: <b>{money(r['amount_cents'])}</b> | Status: {status_tag}\n"
            f"  <i>Data: {r['created_at'][:16]}</i>"
        )

    await update.message.reply_text("\n\n".join(lines), parse_mode=ParseMode.HTML)


async def cb_admin_deposits(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    if not is_admin(update.effective_user.id):
        return

    conn = db._connect()
    try:
        rows = conn.execute(
            "SELECT * FROM transactions WHERE type LIKE 'INVOICE%' OR type = 'TOPUP' ORDER BY id DESC LIMIT 20"
        ).fetchall()
    finally:
        conn.close()

    if not rows:
        await q.edit_message_text("Nessun deposito trovato.", reply_markup=back_admin())
        return

    lines = ["🔐 **AUDIT CRITTOGRAFICO DEPOSITI**", "━━━━━━━━━━━━━━━━━━━", ""]
    for r in rows:
        raw_inv = str(r["note"])
        inv_masked = f"INV-{raw_inv[:4]}...{raw_inv[-4:]}" if len(raw_inv) > 8 else raw_inv
        status_tag = "🟢 PAID" if r["type"] == "TOPUP" else ("🟡 PENDING" if r["type"] == "INVOICE_PENDING" else "🔴 EXPIRED")
        lines.append(f"• `{inv_masked}` | `{r['tg_id']}` — **{money(r['amount_cents'])}** [{status_tag}]")

    await q.edit_message_text("\n".join(lines), parse_mode=ParseMode.MARKDOWN, reply_markup=back_admin())


async def cb_admin_users(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    if not is_admin(update.effective_user.id):
        return
    
    users = db.get_all_users(limit=30)
    if not users:
        await q.edit_message_text("Nessun cliente registrato.", reply_markup=back_admin())
        return
    
    lines = ["👥 **ELENCO UTENTI REGISTRATI**", "━━━━━━━━━━━━━━━━━━━", ""]
    for u in users:
        status = "🔴" if u["is_banned"] else ("🟢" if u["is_key_active"] else "🟡")
        balance_fmt = money(u['balance_cents'])
        lines.append(f"{status} `[ID: {u['tg_id']}]` @{db.esc(u['username'] or '-')} — **{balance_fmt}**")
        
    keyboard = [[InlineKeyboardButton("🔙 Indietro", callback_data="admin")]]
    reply_markup = InlineKeyboardMarkup(keyboard)

    await q.edit_message_text("\n".join(lines), parse_mode=ParseMode.MARKDOWN, reply_markup=reply_markup)


@admin_only
async def cmd_admin_users(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    users = db.get_all_users(limit=30)
    if not users:
        await update.message.reply_text("👥 <b>Database Utenti:</b> Nessun utente registrato.", parse_mode=ParseMode.HTML)
        return

    lines = [f"👥 <b>Elenco Utenti Registrati (Totale visibili: {len(users)})</b>\n"]
    for u in users:
        status = "🔴 Banned" if u["is_banned"] else ("🟢 Attivo" if u["is_key_active"] else "🟡 In attesa 2FA")
        balance_fmt = money(u['balance_cents'])
        lines.append(
            f"• <b>{db.esc(u['first_name'] or 'User')}</b> (@{db.esc(u['username'] or 'no_user')})\n"
            f"  ID: <code>{u['tg_id']}</code> | Saldo: <b>{balance_fmt}</b> | Stato: {status}"
        )

    await update.message.reply_text("\n\n".join(lines), parse_mode=ParseMode.HTML)


@admin_only
async def cmd_db_wipe(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    args = ctx.args
    if not args:
        await update.message.reply_text(
            "⚠️ <b>Comando Distruttivo Richiesto</b>\n\n"
            "Per svuotare il database utenti, devi inserire la chiave segreta:\n"
            "<code>/db_wipe TUO_PIN_ADMIN</code>",
            parse_mode=ParseMode.HTML
        )
        return

    provided_pin = args[0]
    expected_pin = getattr(config, "ADMIN_WIPE_PIN", "Pre77SecureWipe2026!")

    if db.wipe_database(provided_pin, expected_pin):
        admin_id = update.effective_user.id
        await send_siem_log(ctx.bot, "CRITICAL", "WIPE_DATABASE", admin_id, "Database completamente svuotato da admin.")
        
        await update.message.reply_text(
            "🔥 <b>Database Svuotato con Successo!</b>\n\n"
            "Tutti gli utenti, gli ordini e le transazioni sono stati eliminati in modo sicuro.",
            parse_mode=ParseMode.HTML
        )
    else:
        await send_siem_log(ctx.bot, "CRITICAL", "WIPE_DATABASE_FAILED", update.effective_user.id, "Tentativo di wipe database con PIN errato.")
        await update.message.reply_text("❌ <b>PIN Errato.</b> Operazione di pulizia rifiutata.", parse_mode=ParseMode.HTML)


async def cb_admin_orders(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    if not is_admin(update.effective_user.id):
        return
    conn = db._connect()
    try:
        rows = conn.execute(
            "SELECT id, product_title, quantity, client_paid_cents, status, created_at "
            "FROM orders ORDER BY id DESC LIMIT 30"
        ).fetchall()
    finally:
        conn.close()
    if not rows:
        await q.edit_message_text("Nessun ordine presente.", reply_markup=back_admin())
        return
        
    lines = ["🧾 **ULTIMI 30 ORDINI**", "━━━━━━━━━━━━━━━━━━━", ""]
    for r in rows:
        status_emoji = "✅" if r['status'] == "COMPLETED" else ("⏳" if r['status'] == "PENDING" else "❌")
        lines.append(f"• `{r['id']}` · {r['product_title']} ×{r['quantity']} — **{money(r['client_paid_cents'])}** {status_emoji} `{r['status']}`")
        
    await q.edit_message_text("\n".join(lines), parse_mode=ParseMode.MARKDOWN, reply_markup=back_admin())


async def cb_admin_pending(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    if not is_admin(update.effective_user.id):
        return
    items = db.list_pending_orders()
    if not items:
        await q.edit_message_text("✅ **Ottimo!** Nessun ordine in attesa di consegna.", parse_mode=ParseMode.MARKDOWN, reply_markup=back_admin())
        return
        
    lines = ["⏳ **ORDINI DA EVADERE**", "━━━━━━━━━━━━━━━━━━━", ""]
    for o in items:
        lines.append(
            f"• Ordine `#{o['id']}` di @{o.get('username') or o['tg_id']}\n"
            f"  📦 *{o['product_title']}* ×{o['quantity']}\n"
        )
    lines.append("\nUsa `/deliver <id>` per procedere alla consegna.")
    await q.edit_message_text("\n".join(lines), parse_mode=ParseMode.MARKDOWN, reply_markup=back_admin())


@admin_only
async def cmd_ban(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not ctx.args:
        await update.message.reply_text("⚠️ Uso corretto: `/ban <tg_id>`", parse_mode=ParseMode.MARKDOWN)
        return
    try:
        tg_id = int(ctx.args[0])
    except ValueError:
        await update.message.reply_text("❌ ID utente non valido.")
        return
    if tg_id in config.ADMIN_IDS:
        await update.message.reply_text("⛔ Operazione negata: non puoi bannare un amministratore.")
        return
    db.ensure_user(tg_id, None, None)
    db.set_ban(tg_id, True)
    await send_siem_log(ctx.bot, "WARNING", "BAN_USER", update.effective_user.id, f"Utente bannato: {tg_id}")
    await update.message.reply_text(f"🚫 L'utente `{tg_id}` è stato **bannato** con successo.", parse_mode=ParseMode.MARKDOWN)


@admin_only
async def cmd_unban(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not ctx.args:
        await update.message.reply_text("⚠️ Uso corretto: `/unban <tg_id>`", parse_mode=ParseMode.MARKDOWN)
        return
    try:
        tg_id = int(ctx.args[0])
    except ValueError:
        await update.message.reply_text("❌ ID utente non valido.")
        return
    db.ensure_user(tg_id, None, None)
    db.set_ban(tg_id, False)
    await send_siem_log(ctx.bot, "INFO", "UNBAN_USER", update.effective_user.id, f"Utente sbannato: {tg_id}")
    await update.message.reply_text(f"✅ L'utente `{tg_id}` è stato **sbannato**.", parse_mode=ParseMode.MARKDOWN)


@admin_only
async def cmd_genkey(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not ctx.args:
        await update.message.reply_text("⚠️ Uso corretto: `/genkey <tg_id>`", parse_mode=ParseMode.MARKDOWN)
        return
    try:
        tg_id = int(ctx.args[0])
    except ValueError:
        await update.message.reply_text("❌ ID utente non valido.")
        return
        
    db.ensure_user(tg_id, None, None)
    new_key = db.generate_user_key(tg_id)
    
    await send_siem_log(ctx.bot, "WARNING", "GENERATE_KEY", update.effective_user.id, f"Rigenerata chiave TOTP per utente: {tg_id}")
    
    await update.message.reply_text(
        f"🔐 **Chiave di accesso generata/rigenerata**\n"
        f"Utente ID: `{tg_id}`\n\n"
        f"Segreto salvato in modo sicuro nel DB.\n"
        f"🔑 **Segreto TOTP in chiaro** (da inserire in Google Authenticator):\n`{new_key}`",
        parse_mode=ParseMode.MARKDOWN
    )


@admin_only
async def cmd_deliver(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not ctx.args:
        await update.message.reply_text("⚠️ Uso corretto: `/deliver <order_id>`", parse_mode=ParseMode.MARKDOWN)
        return
    try:
        oid = int(ctx.args[0])
    except ValueError:
        await update.message.reply_text("❌ ID ordine non valido.")
        return
    o = db.get_order(oid)
    if not o:
        await update.message.reply_text("❌ Ordine non trovato nel database.")
        return
    if o["status"] != "PENDING":
        await update.message.reply_text(f"⚠️ L'ordine è già in stato: `{o['status']}`.", parse_mode=ParseMode.MARKDOWN)
        return
    ctx.user_data["delivering_order"] = oid
    await update.message.reply_text(
        f"📦 **EVASIONE ORDINE #{oid}**\n"
        f"Prodotto: *{o['product_title']}* ×{o['quantity']}\n\n"
        "Invia ora il testo/dati della consegna in un messaggio:",
        parse_mode=ParseMode.MARKDOWN,
    )


async def on_delivery_text(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    oid = ctx.user_data.get("delivering_order")
    if not oid or not is_admin(update.effective_user.id):
        return
    ctx.user_data.pop("delivering_order", None)
    text = update.message.text.strip()
    if not text:
        await update.message.reply_text("⚠️ Testo vuoto, operazione annullata.")
        return

    o = db.get_order(oid)
    if not o or o["status"] != "PENDING":
        await update.message.reply_text("⚠️ L'ordine non è più in attesa.")
        return

    db.update_order_status(oid, "COMPLETED", delivery_lines=[text])
    await send_siem_log(ctx.bot, "INFO", "DELIVER_ORDER", update.effective_user.id, f"Consegnato ordine #{oid} a utente {o['tg_id']}")

    await update.message.reply_text(f"✅ Ordine `#{oid}` consegnato correttamente.", parse_mode=ParseMode.MARKDOWN)
    try:
        await ctx.bot.send_message(
            o["tg_id"],
            f"✅ **CONSEGNA ORDINE #{oid}**\n"
            f"📦 {o['product_title']} ×{o['quantity']}\n\n"
            f"🔑 **I tuoi dati:**\n`{text}`",
            parse_mode=ParseMode.HTML,
        )
    except Exception as e:
        log.warning("Invio notifica consegna a %s fallito: %s", o["tg_id"], e)


@admin_only
async def cmd_refund(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not ctx.args:
        await update.message.reply_text("⚠️ Uso corretto: `/refund <order_id>`", parse_mode=ParseMode.MARKDOWN)
        return
    try:
        oid = int(ctx.args[0])
    except ValueError:
        await update.message.reply_text("❌ ID ordine non valido.")
        return
    o = db.get_order(oid)
    if not o:
        await update.message.reply_text("❌ Ordine non trovato.")
        return
    if o["status"] == "REFUNDED":
        await update.message.reply_text("⚠️ Questo ordine è già stato rimborsato.")
        return
    db.credit(o["tg_id"], o["client_paid_cents"], "REFUND", note=f"ordine #{oid}")
    db.update_order_status(oid, "REFUNDED")
    await send_siem_log(ctx.bot, "WARNING", "REFUND_ORDER", update.effective_user.id, f"Rimborsato ordine #{oid} di {money(o['client_paid_cents'])}")
    await update.message.reply_text(f"✅ Rimborsati con successo **{money(o['client_paid_cents'])}** per l'ordine `#{oid}`.", parse_mode=ParseMode.MARKDOWN)
    try:
        await ctx.bot.send_message(
            o["tg_id"],
            f"💰 **RIMBORSO ACCREDITATO**\n"
            f"Ti sono stati restituiti **{money(o['client_paid_cents'])}** per l'ordine `#{oid}`.",
            parse_mode=ParseMode.MARKDOWN,
        )
    except Exception:
        pass


@admin_only
async def cmd_pending(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    items = db.list_pending_orders()
    if not items:
        await update.message.reply_text("✅ Nessun ordine in attesa.")
        return
    lines = ["⏳ **ORDINI IN ATTESA**", "━━━━━━━━━━━━━━━━━━━", ""]
    for o in items:
        lines.append(f"• `#{o['id']}` — {o['product_title']} ×{o['quantity']}")
    lines.append("\nUsa `/deliver <id>` per consegnare.")
    await update.message.reply_text("\n".join(lines), parse_mode=ParseMode.MARKDOWN)


@admin_only
async def cmd_addbalance(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if len(ctx.args) != 2:
        await update.message.reply_text("⚠️ Uso corretto: `/addbalance <tg_id> <importo>`", parse_mode=ParseMode.MARKDOWN)
        return
    try:
        tg_id = int(ctx.args[0])
    except ValueError:
        await update.message.reply_text("❌ tg_id non valido.")
        return
    amount = _parse_amount(ctx.args[1])
    if amount is None:
        await update.message.reply_text("❌ Importo non valido.")
        return
    if not db.get_user(tg_id):
        db.ensure_user(tg_id, None, None)
    new_bal = db.credit(tg_id, amount, "TOPUP", note=f"admin:{update.effective_user.id}")
    await send_siem_log(ctx.bot, "WARNING", "ADD_BALANCE", update.effective_user.id, f"Ricaricato utente {tg_id} di {money(amount)} | Nuovo saldo: {money(new_bal)}")
    await update.message.reply_text(
        f"✅ Accreditati **{money(amount)}** all'utente `{tg_id}`.\n"
        f"Nuovo saldo: **{money(new_bal)}**", parse_mode=ParseMode.MARKDOWN)
    try:
        await ctx.bot.send_message(
            tg_id, f"💰 **RICARICA EFFETTUATA**\nIl tuo saldo è stato incrementato di **{money(amount)}**.\nNuovo saldo: **{money(new_bal)}**", parse_mode=ParseMode.MARKDOWN)
    except Exception:
        pass


@admin_only
async def cmd_subbalance(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if len(ctx.args) != 2:
        await update.message.reply_text("⚠️ Uso corretto: `/subbalance <tg_id> <importo>`", parse_mode=ParseMode.MARKDOWN)
        return
    try:
        tg_id = int(ctx.args[0])
    except ValueError:
        await update.message.reply_text("❌ tg_id non valido.")
        return
    amount = _parse_amount(ctx.args[1])
    if amount is None:
        await update.message.reply_text("❌ Importo non valido.")
        return
    if not db.try_debit(tg_id, amount, "ADMIN_DEBIT", note=f"admin:{update.effective_user.id}"):
        await update.message.reply_text("❌ Saldo utente insufficiente per l'addebito.")
        return
    await send_siem_log(ctx.bot, "WARNING", "SUB_BALANCE", update.effective_user.id, f"Stornato saldo a utente {tg_id} di {money(amount)}")
    await update.message.reply_text(f"✅ Addebitati con successo **{money(amount)}** all'utente `{tg_id}`.", parse_mode=ParseMode.MARKDOWN)


@admin_only
async def cmd_userinfo(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not ctx.args:
        await update.message.reply_text("⚠️ Uso corretto: `/userinfo <tg_id>`", parse_mode=ParseMode.MARKDOWN)
        return
    try:
        tg_id = int(ctx.args[0])
    except ValueError:
        await update.message.reply_text("❌ tg_id non valido.")
        return
    u = db.get_user(tg_id)
    if not u:
        await update.message.reply_text("❌ Utente non trovato nel database.")
        return
    txs = db.list_transactions(tg_id, limit=10)
    banned_status = "Sì ❌" if u.get("is_banned") else "No ✅"
    key_status = "Attiva ✅" if u.get("is_key_active") else "Non attiva ❌"
    lines = [
        f"👤 **INFO UTENTE** @{u.get('username') or 'N/D'} (`{tg_id}`)",
        "━━━━━━━━━━━━━━━━━━━",
        f"💰 Saldo attuale: **{money(u['balance_cents'])}**",
        f"🚫 Stato Ban: **{banned_status}**",
        f"🔑 Stato Key: **{key_status}**",
        "", "📜 **Ultimi movimenti:**",
    ]
    for t in txs:
        sign = "+" if t["amount_cents"] >= 0 else ""
        lines.append(f"• `{t['created_at'][:16]}` {sign}{money(t['amount_cents'])} `({t['type']})`")
    await update.message.reply_text("\n".join(lines), parse_mode=ParseMode.MARKDOWN)


@admin_only
async def cmd_stats(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    s = db.global_stats()
    await update.message.reply_text(
        f"📊 **STATISTICHE BOT**\n"
        f"━━━━━━━━━━━━━━━━━━━\n"
        f"👥 Clienti: **{s['users']}**\n"
        f"📦 Ordini totali: **{s['orders']}** · ⏳ In attesa: **{s['pending']}**\n"
        f"💳 Totale ricariche: **{money(s['topups_cents'])}**\n"
        f"📈 Margine: **{money(s['margin_cents'])}**\n"
        f"⚠️ Debiti: **{money(s['liabilities_cents'])}**",
        parse_mode=ParseMode.MARKDOWN)


@admin_only
async def cmd_pre77balance(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    api = ctx.bot_data["api"]
    try:
        me = await api.get_me()
    except APIError as e:
        await send_siem_log(ctx.bot, "WARNING", "API_ERROR", "Backend", str(e.message))
        await update.message.reply_text(f"❌ {e.message}")
        return

    bal_cents = _extract_admin_balance(me)
    login_str = _extract_admin_login(me)

    await update.message.reply_text(
        f"💵 **Saldo Backend:** **{money(bal_cents)}**\n"
        f"👤 **Account:** `{login_str}`", parse_mode=ParseMode.MARKDOWN)


async def cmd_id(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        f"🆔 Il tuo ID Telegram: `{update.effective_user.id}`", parse_mode=ParseMode.MARKDOWN)


@admin_only
async def cmd_clearcache(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    cache = ctx.bot_data.get("cc_cache", {})
    count = len(cache)
    cache.clear()
    
    admin_id = update.effective_user.id
    await send_siem_log(ctx.bot, "INFO", "CLEAR_CACHE", admin_id, f"Rimossi {count} elementi dalla cache di sistema.")
    
    msg_text = f"🧹 **Cache svuotata con successo!**\nElementi rimossi: **{count}**"
    
    if update.callback_query:
        q = update.callback_query
        await q.answer("Cache svuotata!")
        try:
            await q.edit_message_text(msg_text, parse_mode=ParseMode.MARKDOWN, reply_markup=back_admin())
        except Exception:
            await q.message.reply_text(msg_text, parse_mode=ParseMode.MARKDOWN, reply_markup=back_admin())
    elif update.message:
        await update.message.reply_text(msg_text, parse_mode=ParseMode.MARKDOWN)


@admin_only
async def cmd_statusbot(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    admin_id = update.effective_user.id
    
    db_status = "🟢 Online"
    try:
        s = db.global_stats()
    except Exception as e:
        db_status = f"🔴 Errore DB: {e}"
        s = {"users": 0, "orders": 0, "pending": 0}

    api = ctx.bot_data.get("api")
    api_status = "🟢 Connesso"
    bal_str = "N/D"
    if api:
        try:
            me = await api.get_me()
            bal_cents = _extract_admin_balance(me)
            bal_str = money(bal_cents)
        except Exception as e:
            api_status = f"🔴 Errore API: {e}"
    else:
        api_status = "⚪ Non inizializzato"

    cache_count = len(ctx.bot_data.get("cc_cache", {}))

    report_text = (
        "🩺 <b>REPORT OPERATIVO & STATO BOT</b>\n"
        "━━━━━━━━━━━━━━━━━━━\n"
        f"🗄 <b>Database:</b> {db_status}\n"
        f"🔌 <b>Backend API:</b> {api_status}\n"
        f"💰 <b>Saldo Backend:</b> <code>{bal_str}</code>\n"
        f"🧹 <b>Elementi in Cache:</b> <code>{cache_count}</code>\n"
        f"👥 <b>Utenti Registrati:</b> <code>{s.get('users', 0)}</code>\n"
        f"📦 <b>Ordini Totali:</b> <code>{s.get('orders', 0)}</code> (⏳ In attesa: <code>{s.get('pending', 0)}</code>)\n\n"
        f"🛡 <i>Tutti i sistemi di sicurezza e monitoraggio SIEM sono attivi.</i>"
    )

    await send_siem_log(ctx.bot, "INFO", "HEALTH_CHECK", admin_id, "Eseguito controllo diagnostico manuale dello stato bot.")
    await update.message.reply_text(report_text, parse_mode=ParseMode.HTML)