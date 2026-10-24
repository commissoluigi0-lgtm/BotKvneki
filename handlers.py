from __future__ import annotations

import hmac
import hashlib
import html
import logging
import re
import time
from functools import wraps

from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.constants import ParseMode
from telegram.ext import ContextTypes

import config
import db
import admin
from api_client import APIError
from keyboards import client_menu, cc_catalog_kb, cc_orders_kb, cc_order_kb, back_menu

log = logging.getLogger(__name__)

PAGE_SIZE = 10
_rate_limit_cache = {}
_card_cache = {}


def sanitize_input(text: str, mode: str = "general") -> str:
    if not text:
        return ""
    text = text.strip()
    if mode == "totp":
        return re.sub(r"[^0-9]", "", text)[:6]
    elif mode == "search":
        return re.sub(r"[^a-zA-Z0-9\s]", "", text)[:50]
    return re.sub(r"[<>\";'\\/]", "", text)[:100]


def rate_limit(seconds: float = 2.0):
    def decorator(func):
        @wraps(func)
        async def wrapper(update: Update, ctx: ContextTypes.DEFAULT_TYPE, *args, **kwargs):
            user = update.effective_user
            if not user or user.id in config.ADMIN_IDS:
                return await func(update, ctx, *args, **kwargs)
            now = time.time()
            if now - _rate_limit_cache.get(user.id, 0.0) < seconds:
                if update.callback_query:
                    try:
                        await update.callback_query.answer("⚠️ Attendi qualche secondo!", show_alert=True)
                    except Exception:
                        pass
                return
            _rate_limit_cache[user.id] = now
            return await func(update, ctx, *args, **kwargs)
        return wrapper
    return decorator


def client_price(raw_price: float | int) -> float:
    if not raw_price:
        return 7.0
    val = float(raw_price)
    markup = getattr(config, "MARKUP_PERCENT", 20.0)
    return val * (1.0 + (markup / 100.0))


def esc(v) -> str:
    return html.escape(str(v if v is not None else ""))


def money(val) -> str:
    try:
        return f"${float(val):.2f}"
    except (TypeError, ValueError):
        return "$7.00"


async def _check_access(update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> bool:
    user = update.effective_user
    chat_id = update.effective_chat.id if update.effective_chat else 0
    if not user:
        return True
    if not db.check_chat_binding(user.id, chat_id):
        txt = "❌ <b>Sessione non autorizzata.</b>"
        if update.callback_query:
            try:
                await update.callback_query.answer(txt, show_alert=True)
            except Exception:
                pass
        return True
    if db.check_and_expire_session(user.id):
        txt = "🔒 <b>Sessione Scaduta per Inattività.</b> Re-inserisci 2FA."
        ctx.user_data["awaiting"] = "login_key"
        if update.callback_query and update.callback_query.message:
            try:
                await update.callback_query.message.reply_text(txt, parse_mode=ParseMode.HTML)
            except Exception:
                pass
        return True
    if db.is_banned(user.id):
        return True
    if user.id in config.ADMIN_IDS:
        db.update_last_activity(user.id)
        return False
    db.ensure_user(user.id, user.username, user.first_name)
    db.update_last_activity(user.id)
    return False


async def cmd_start(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    u = update.effective_user
    db.ensure_user(u.id, u.username, u.first_name)
    if await _check_access(update, ctx):
        return
    ctx.user_data.clear()
    await update.message.reply_text("👋 <b>Benvenuto nel Network!</b>\n\nCatalogo attivo e sincronizzato.", parse_mode=ParseMode.HTML, reply_markup=client_menu())


async def cmd_help(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if await _check_access(update, ctx):
        return
    await update.message.reply_text("🛠 <b>Guida e Supporto</b>\nUsa i pulsanti nel menu principale per navigare.", parse_mode=ParseMode.HTML, reply_markup=back_menu())


async def cb_help(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if await _check_access(update, ctx):
        return
    q = update.callback_query
    await q.answer()
    await q.edit_message_text("🛠 <b>Guida e Supporto</b>", parse_mode=ParseMode.HTML, reply_markup=back_menu())


async def cb_menu(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if await _check_access(update, ctx):
        return
    q = update.callback_query
    await q.answer()
    await q.edit_message_text("🏠 <b>Menu Principale</b>", parse_mode=ParseMode.HTML, reply_markup=client_menu())


async def _load_catalog(ctx, page: int, q: str = "", edit_msg=None, chat_id=None):
    api = ctx.bot_data["api"]
    try:
        data = await api.cc_search(page=page, page_size=PAGE_SIZE, q=q, sort="price_asc")
    except APIError as e:
        txt = f"⚠️ {esc(e.message)}"
        if edit_msg:
            await edit_msg.edit_text(txt, reply_markup=back_menu())
        return

    rows = data.get("rows", []) or data.get("items", [])
    total = data.get("total", 0)
    cur_page = data.get("page", page)
    page_count = data.get("pageCount", 1)

    for item in rows:
        card_id = str(item.get("id") or "")
        if card_id:
            _card_cache[card_id] = item

    header = f"🛍 <b>CC Shop Catalog</b>\nPagina {cur_page}/{page_count} · {total} disponibili"
    kb = cc_catalog_kb(rows, cur_page, cur_page > 1, cur_page < page_count, client_price) if rows else back_menu()

    if edit_msg:
        await edit_msg.edit_text(header, parse_mode=ParseMode.HTML, reply_markup=kb)


@rate_limit(seconds=2.0)
async def cb_cc(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if await _check_access(update, ctx):
        return
    q = update.callback_query
    await q.answer()
    page = int(q.data.split(":")[1]) if ":" in q.data and q.data.split(":")[1].isdigit() else 1
    await _load_catalog(ctx, page, edit_msg=q.message)


async def cb_cc_search(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if await _check_access(update, ctx):
        return
    q = update.callback_query
    await q.answer()
    ctx.user_data["awaiting"] = "cc_search_query"
    await q.edit_message_text("🔍 <b>Inserisci il BIN o il brand da cercare:</b>", parse_mode=ParseMode.HTML, reply_markup=back_menu())


async def cb_cc_product(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if await _check_access(update, ctx):
        return
    q = update.callback_query
    await q.answer()
    
    parts = q.data.split(":")
    cid = parts[1] if len(parts) > 1 else ""
    
    c = _card_cache.get(str(cid))
    if not c:
        api = ctx.bot_data["api"]
        try:
            data = await api.cc_search(page=1, page_size=50)
            rows = data.get("rows", []) or data.get("items", [])
            for item in rows:
                c_id = str(item.get("id") or "")
                if c_id:
                    _card_cache[c_id] = item
            c = _card_cache.get(str(cid))
        except APIError:
            c = None

    if not c:
        c = {"id": cid, "bin": "463339", "priceUsd": 7, "vendor": "VISA", "countryCode": "FR", "baseName": "Base Standard", "type": "CREDIT", "level": "CLASSIC"}

    bin_val = c.get("bin") or "463339"
    vendor = c.get("vendor") or "VISA"
    country = c.get("countryCode") or "FR"
    level = c.get("level") or "CLASSIC"
    card_type = c.get("type") or "CREDIT"
    base_name = c.get("baseName") or "Base Standard"
    raw_price = c.get("priceUsd") or c.get("price") or 7

    try:
        price_val = float(raw_price)
    except (TypeError, ValueError):
        price_val = 7.0

    sell_price = client_price(price_val)

    keyboard = [
        [InlineKeyboardButton("🛒 Aggiungi al Carrello", callback_data=f"cc_cart_add:{cid}")],
        [InlineKeyboardButton("🔙 Torna allo Shop", callback_data="cc_shop:1")]
    ]
    
    text = (
        f"💳 <b>Dettagli Prodotto</b>\n\n"
        f"<b>BIN:</b> <code>{esc(bin_val)}</code>\n"
        f"<b>Circuito:</b> {esc(vendor)} ({esc(country)})\n"
        f"<b>Livello / Tipo:</b> {esc(level)} - {esc(card_type)}\n"
        f"<b>Base:</b> {esc(base_name)}\n"
        f"<b>Seller:</b> <code>Kvneki</code>\n"
        f"<b>Prezzo Finale:</b> <b>{money(sell_price)}</b>"
    )
    await q.edit_message_text(text, parse_mode=ParseMode.HTML, reply_markup=InlineKeyboardMarkup(keyboard))


async def cb_cc_add_cart(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if await _check_access(update, ctx):
        return
    q = update.callback_query
    card_id = q.data.split(":")[1]
    try:
        await ctx.bot_data["api"].cc_add_cart(card_id)
        await q.answer("✅ Aggiunto al carrello!", show_alert=True)
    except APIError as e:
        await q.answer(f"❌ Errore: {e.message}", show_alert=True)


async def cb_cc_remove_cart(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if await _check_access(update, ctx):
        return
    q = update.callback_query
    card_id = q.data.split(":")[1]
    try:
        await ctx.bot_data["api"].cc_remove_cart(card_id)
        await q.answer("🗑 Rimosso dal carrello!", show_alert=True)
        await cb_cc_view_cart(update, ctx)
    except APIError as e:
        await q.answer(f"❌ Errore: {e.message}", show_alert=True)


async def cb_cc_view_cart(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if await _check_access(update, ctx):
        return
    q = update.callback_query
    try:
        cart = await ctx.bot_data["api"].cc_get_cart()
        items = cart.get("items", [])
        total_usd = cart.get("totalUsd", cart.get("total", 0))
        
        if not items:
            await q.edit_message_text("🛒 <b>Il tuo carrello è vuoto.</b>", parse_mode=ParseMode.HTML, reply_markup=back_menu())
            return
            
        text = f"🛒 <b>Carrello ({len(items)})</b>\n\n"
        keyboard = []
        for item in items:
            c_id = item.get("cardId") or item.get("id", "")
            bin_val = item.get("bin", "463339")
            p_val = client_price(item.get("priceUsd", 7))
            text += f"• BIN: <code>{bin_val}</code> — <b>{money(p_val)}</b> (Seller: Kvneki)\n"
            keyboard.append([InlineKeyboardButton(f"🗑 Rimuovi {bin_val}", callback_data=f"cc_cart_del:{c_id}")])
            
        text += f"\n💰 <b>Totale:</b> {money(client_price(total_usd))}"
        keyboard.append([InlineKeyboardButton("💳 Procedi al Checkout", callback_data="cc_checkout_exec")])
        keyboard.append([InlineKeyboardButton("🔙 Torna allo Shop", callback_data="cc_shop:1")])
        
        await q.edit_message_text(text, parse_mode=ParseMode.HTML, reply_markup=InlineKeyboardMarkup(keyboard))
    except APIError as e:
        await q.edit_message_text(f"❌ Errore carrello: {esc(e.message)}", reply_markup=back_menu())


async def cb_cc_checkout_exec(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if await _check_access(update, ctx):
        return
    q = update.callback_query
    await q.answer("⏳ Elaborazione checkout...")
    try:
        result = await ctx.bot_data["api"].cc_checkout()
        purchases = result.get('purchases', [])
        
        for p in purchases:
            db.create_order(
                tg_id=update.effective_user.id,
                product_id=p.get("cardId", "N/D"),
                title=f"CC {p.get('cardId')}",
                qty=1,
                client_paid_cents=int(client_price(p.get("priceCents", 700))),
                pre77_cost_cents=p.get("priceCents", 700),
                pre77_purchase_id=p.get("id"),
                delivery_lines=[],
                status="COMPLETED"
            )
            
        text = f"🎉 <b>Checkout completato!</b>\nAcquisti confermati: {len(purchases)}"
        keyboard = [[InlineKeyboardButton("📦 I Miei Ordini", callback_data="myorders")]]
        await q.edit_message_text(text, parse_mode=ParseMode.HTML, reply_markup=InlineKeyboardMarkup(keyboard))
    except APIError as e:
        await q.edit_message_text(f"❌ Errore checkout: {esc(e.message)}", parse_mode=ParseMode.HTML, reply_markup=back_menu())


async def cb_cc_orders(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if await _check_access(update, ctx):
        return
    q = update.callback_query
    await q.answer()
    
    orders = db.list_orders(update.effective_user.id, limit=10)
    
    if not orders:
        await q.edit_message_text("📦 <b>Nessun ordine effettuato.</b>", parse_mode=ParseMode.HTML, reply_markup=back_menu())
        return
        
    kb = cc_orders_kb(orders)
    await q.edit_message_text("📦 <b>I tuoi ultimi 10 ordini:</b>", parse_mode=ParseMode.HTML, reply_markup=kb)


async def cb_cc_reveal(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if await _check_access(update, ctx):
        return
    q = update.callback_query
    await q.answer("🔓 Dati rivelati")


async def cb_mysaldo(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if await _check_access(update, ctx):
        return
    q = update.callback_query
    u = update.effective_user
    bal = db.get_balance(u.id)
    await q.edit_message_text(f"💰 <b>Saldo Disponibile: {money(bal / 100)}</b>", parse_mode=ParseMode.HTML, reply_markup=back_menu())


async def cb_support(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if await _check_access(update, ctx):
        return
    q = update.callback_query
    await q.edit_message_text("🛠 Supporto disponibile su @ombraax", parse_mode=ParseMode.HTML, reply_markup=back_menu())


async def cmd_bin_lookup(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if await _check_access(update, ctx):
        return
    await update.message.reply_text("🔍 Inserisci un BIN da cercare.", reply_markup=back_menu())


async def on_text(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if await _check_access(update, ctx):
        return
    await update.message.reply_text("💡 Usa il menu principale per navigare.", reply_markup=client_menu())


async def error_handler(update: object, context: ContextTypes.DEFAULT_TYPE) -> None:
    log.error(f"Eccezione non gestita: {context.error}", exc_info=context.error)


async def handle_pre77_webhook(data: dict, ctx):
    log.info(f"Webhook Pre77 ricevuto: {data}")


def verify_pre77_signature(body: bytes, sig: str, secret: str) -> bool:
    """Verifica l'autenticità del webhook tramite HMAC SHA-256."""
    if not secret or not sig:
        return False
    expected_sig = hmac.new(secret.encode('utf-8'), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected_sig, sig)


# ==================== FUNZIONI ADMIN (INTEGRATE) ====================

async def _is_admin(update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> bool:
    user = update.effective_user
    return user and user.id in config.ADMIN_IDS

async def cmd_mystock(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not await _is_admin(update, ctx):
        return
    text = (
        "📦 <b>Gestione Stock CC Shop</b>\n\n"
        "Lo stock delle carte di credito è sincronizzato automaticamente con l'inventario globale di Pre77. "
        "Non è necessario (né possibile) effettuare il restock manuale delle linee per questa tipologia di servizio."
    )
    keyboard = [[InlineKeyboardButton("🔙 Indietro", callback_data="admin")]]
    
    if update.callback_query:
        await update.callback_query.answer()
        await update.callback_query.edit_message_text(text, parse_mode=ParseMode.HTML, reply_markup=InlineKeyboardMarkup(keyboard))
    else:
        await update.message.reply_text(text, parse_mode=ParseMode.HTML, reply_markup=InlineKeyboardMarkup(keyboard))

async def cb_admin_mystock(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    await cmd_mystock(update, ctx)

async def cb_admin_pre77bal(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not await _is_admin(update, ctx):
        return
    q = update.callback_query
    await q.answer("⏳ Controllo parametri...", show_alert=False)

    api = ctx.bot_data.get("api")
    if not api:
        await q.edit_message_text("❌ API Client non inizializzato.", reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙 Indietro", callback_data="admin")]]))
        return

    try:
        meta_data = await api.get_me()
        bases_count = len(meta_data.get("bases", []))
        sellers_count = len(meta_data.get("sellers", []))
        text = (
            "💎 <b>Stato API Pre77 (CC Shop)</b>\n\n"
            f"✅ Connessione: <b>Attiva</b>\n"
            f"🗃 Basi CC disponibili: <b>{bases_count}</b>\n"
            f"👤 Venditori tracciati: <b>{sellers_count}</b>\n\n"
            "<i>Nota: I fondi vengono scalati automaticamente dall'account Pre77 ad ogni acquisto effettuato dagli utenti.</i>"
        )
    except APIError as e:
        text = f"❌ <b>Errore di Connessione API:</b>\n<code>{esc(e.message)}</code>"

    keyboard = [[InlineKeyboardButton("🔙 Indietro", callback_data="admin")]]
    await q.edit_message_text(text, parse_mode=ParseMode.HTML, reply_markup=InlineKeyboardMarkup(keyboard))

async def cmd_pre77balance(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not await _is_admin(update, ctx):
        return
    api = ctx.bot_data.get("api")
    try:
        await api.get_me()
        await update.message.reply_text("💎 <b>Connessione all'API CC Shop di Pre77: ATTIVA</b>", parse_mode=ParseMode.HTML)
    except APIError as e:
        await update.message.reply_text(f"❌ Errore: {esc(e.message)}")
