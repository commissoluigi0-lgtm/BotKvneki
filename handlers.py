from __future__ import annotations

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
        return 0.0
    cents = float(raw_price)
    markup = getattr(config, "MARKUP_PERCENT", 20.0)
    return cents * (1.0 + (markup / 100.0))


def esc(v) -> str:
    return html.escape(str(v if v is not None else ""))


def money(cents) -> str:
    try:
        return f"${int(cents) / 100:.2f}"
    except (TypeError, ValueError):
        return "—"


async def _check_access(update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> bool:
    user = update.effective_user
    chat_id = update.effective_chat.id if update.effective_chat else 0
    if not user:
        return True
    if not db.check_chat_binding(user.id, chat_id):
        txt = "❌ <b>Sessione non autorizzata.</b>"
        if update.callback_query:
            await update.callback_query.answer(txt, show_alert=True)
        return True
    if db.check_and_expire_session(user.id):
        txt = "🔒 <b>Sessione Scaduta per Inattività.</b> Re-inserisci 2FA."
        ctx.user_data["awaiting"] = "login_key"
        if update.callback_query:
            await update.callback_query.message.reply_text(txt, parse_mode=ParseMode.HTML)
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

    rows = data.get("rows", [])
    total = data.get("total", 0)
    cur_page = data.get("page", page)
    page_count = data.get("pageCount", 1)

    # SALVA LE CARTE NELLA MEMORIA DI CACHE DEL BOT PER UN RECUPERO ISTANTANEO
    cache = ctx.bot_data.setdefault("cc_cache", {})
    for item in rows:
        card_id = str(item.get("id") or item.get("cardId"))
        if card_id:
            cache[card_id] = item

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
    page = int(q.data.split(":")[1]) if ":" in q.data else 1
    await _load_catalog(ctx, page, edit_msg=q.message)


async def cb_cc_product(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if await _check_access(update, ctx):
        return
    q = update.callback_query
    await q.answer()
    cid = q.data.split(":", 1)[1]
    
    # 1. TENTA PRIMA IL RECUPERO DALLA CACHE ISTANTANEA
    cache = ctx.bot_data.get("cc_cache", {})
    c = cache.get(str(cid))

    # 2. SE NON IN CACHE, ESEGUE UNA RICERCA DEDICATA SU PRE77 USANDO L'ID O IL BIN
    if not c:
        api = ctx.bot_data["api"]
        try:
            data = await api.cc_search(page=1, page_size=100, q=str(cid))
            rows = data.get("rows", [])
            c = next((item for item in rows if str(item.get("id") or item.get("cardId")) == str(cid)), None)
        except APIError:
            c = None

    if not c:
        c = {"id": cid, "bin": "N/D", "priceCents": 0}

    bin_val = c.get("bin") or "N/D"
    vendor = c.get("vendor", "Standard")
    country = c.get("country", "US")
    base_type = c.get("base") or c.get("type") or "HQ Base"
    raw_cents = c.get("priceCents") or c.get("price_cents") or 0
    
    sell_cents = client_price(raw_cents)

    keyboard = [
        [InlineKeyboardButton("🛒 Aggiungi al Carrello", callback_data=f"cc_cart_add:{cid}")],
        [InlineKeyboardButton("🔙 Torna allo Shop", callback_data="cc_shop:1")]
    ]
    
    text = (
        f"💳 <b>Dettagli Prodotto</b>\n\n"
        f"<b>BIN:</b> <code>{esc(bin_val)}</code>\n"
        f"<b>Circuito:</b> {esc(vendor)} ({esc(country)})\n"
        f"<b>Tipo / Base:</b> {esc(base_type)}\n"
        f"<b>Seller:</b> <code>Kvneki</code>\n"
        f"<b>Prezzo Finale:</b> <b>{money(sell_cents)}</b>"
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


async def cb_cc_view_cart(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if await _check_access(update, ctx):
        return
    q = update.callback_query
    try:
        cart = await ctx.bot_data["api"].cc_get_cart()
        items = cart.get("items", [])
        total_cents = cart.get("totalCents", 0)
        
        if not items:
            await q.edit_message_text("🛒 <b>Il tuo carrello è vuoto.</b>", parse_mode=ParseMode.HTML, reply_markup=back_menu())
            return
            
        text = f"🛒 <b>Carrello ({len(items)})</b>\n\n"
        keyboard = []
        for item in items:
            c_id = item.get("cardId") or item.get("id", "")
            bin_val = item.get("bin", "N/D")
            price = money(client_price(item.get("priceCents", 0)))
            text += f"• BIN: <code>{bin_val}</code> — <b>{price}</b>\n"
            keyboard.append([InlineKeyboardButton(f"🗑 Rimuovi {bin_val}", callback_data=f"cc_cart_del:{c_id}")])
            
        text += f"\n💰 <b>Totale:</b> {money(client_price(total_cents))}"
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
        text = f"🎉 <b>Checkout completato!</b>\nAcquisti: {len(result.get('purchases', []))}"
        keyboard = [[InlineKeyboardButton("📦 I Miei Ordini", callback_data="myorders")]]
        await q.edit_message_text(text, parse_mode=ParseMode.HTML, reply_markup=InlineKeyboardMarkup(keyboard))
    except APIError as e:
        await q.edit_message_text(f"❌ Errore checkout: {esc(e.message)}", parse_mode=ParseMode.HTML, reply_markup=back_menu())


async def cb_mysaldo(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if await _check_access(update, ctx):
        return
    q = update.callback_query
    u = update.effective_user
    bal = db.get_balance(u.id)
    await q.edit_message_text(f"💰 <b>Saldo Disponibile: {money(bal)}</b>", parse_mode=ParseMode.HTML, reply_markup=back_menu())


async def cb_support(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if await _check_access(update, ctx):
        return
    await update.callback_query.edit_message_text("🛠 Supporto disponibile su @ombraax", parse_mode=ParseMode.HTML, reply_markup=back_menu())
