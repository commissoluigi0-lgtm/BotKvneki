from __future__ import annotations

import html
import json
import logging
import math
import random
import re
import time
import os
import glob
import hmac
import hashlib
import asyncio
from functools import wraps

from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.constants import ParseMode
from telegram.ext import ContextTypes

import config
import db
from api_client import APIError
from keyboards import (
    client_menu, cc_catalog_kb, cc_product_kb, cc_buy_confirm_kb,
    cc_filters_kb, cc_filter_vendor_kb, cc_filter_country_kb, cc_filter_type_kb,
    cc_orders_kb, cc_order_kb, back_menu,
)

log = logging.getLogger(__name__)

PAGE_SIZE = 10

_user_ratelimit = {}
_rate_limit_cache = {}
_user_search_history = {}


def sanitize_input(text: str, mode: str = "general") -> str:
    if not text:
        return ""
    text = text.strip()
    if mode == "totp":
        return re.sub(r"[^0-9]", "", text)[:6]
    elif mode == "search":
        return re.sub(r"[^a-zA-Z0-9\s]", "", text)[:50]
    elif mode == "price":
        return re.sub(r"[^0-9.\-]", "", text)[:20]
    return re.sub(r"[<>\";'\\/]", "", text)[:100]


def rate_limit(seconds: float = 2.0):
    def decorator(func):
        @wraps(func)
        async def wrapper(update: Update, ctx: ContextTypes.DEFAULT_TYPE, *args, **kwargs):
            user = update.effective_user
            if not user or user.id in config.ADMIN_IDS:
                return await func(update, ctx, *args, **kwargs)
                
            now = time.time()
            last_time = _rate_limit_cache.get(user.id, 0.0)
            
            if now - last_time < seconds:
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


async def _check_scraping(update: Update, ctx: ContextTypes.DEFAULT_TYPE, user_id: int):
    if user_id in config.ADMIN_IDS:
        return
    now = time.time()
    history = _user_search_history.setdefault(user_id, [])
    history[:] = [t for t in history if now - t < 60]
    history.append(now)
    
    if len(history) > 50:
        log.warning("SIEM SECURITY ALERT | Possibile Scraping rilevato da utente %d (%d richieste/min)", user_id, len(history))
        history.clear()


def client_price(raw_price: float | int) -> float:
    if not raw_price:
        return 0.0
    base = float(raw_price)
    cents = base * 100 if base < 1000 and isinstance(raw_price, float) else base
    markup = getattr(config, "MARKUP_PERCENT", 0.0)
    return cents * (1.0 + (markup / 100.0))


def esc(v) -> str:
    return html.escape(str(v if v is not None else ""))


def money(cents) -> str:
    try:
        return f"${int(cents) / 100:.2f}"
    except (TypeError, ValueError):
        return "—"


def _extract_cents(item: dict) -> int:
    for key in ("priceUsd", "priceCents", "price", "costCents", "cost", "amountCents", "amount"):
        val = item.get(key)
        if val is not None:
            try:
                if key == "priceUsd" or isinstance(val, float) or "." in str(val):
                    return int(round(float(val) * 100))
                return int(val)
            except (ValueError, TypeError):
                pass
    return 0


def _default_filters() -> dict:
    return {"refund_allowed": None, "price_min": None, "price_max": None, "vendor": "Tutti", "country": "Tutti", "type": "Tutti"}


def _filters(ctx) -> dict:
    return ctx.user_data.setdefault("cc_filters", _default_filters())


def _price_label(f: dict) -> str:
    lo, hi = f.get("price_min"), f.get("price_max")
    if lo is None and hi is None:
        return "—"
    return f"{lo or 0:.0f}–{hi or '∞'} $"


# ==================== CONTROLLO ACCESSO ====================

async def _check_access(update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> bool:
    user = update.effective_user
    chat_id = update.effective_chat.id if update.effective_chat else 0
    if not user:
        return True

    if not db.check_chat_binding(user.id, chat_id):
        txt = "❌ <b>Sessione non autorizzata.</b> Chiave vincolata a un altro dispositivo."
        if update.callback_query:
            await update.callback_query.answer(txt, show_alert=True)
        elif update.effective_message:
            await update.effective_message.reply_text(txt, parse_mode=ParseMode.HTML)
        return True

    if db.check_and_expire_session(user.id):
        txt = "🔒 <b>Sessione Scaduta per Inattività (> 15 min).</b> Inserisci nuovamente il codice Google Authenticator."
        ctx.user_data["awaiting"] = "login_key"
        if update.callback_query:
            await update.callback_query.message.reply_text(txt, parse_mode=ParseMode.HTML)
        elif update.effective_message:
            await update.effective_message.reply_text(txt, parse_mode=ParseMode.HTML)
        return True

    if db.is_banned(user.id):
        return True
        
    if user.id in config.ADMIN_IDS:
        db.update_last_activity(user.id)
        return False

    db.ensure_user(user.id, user.username, user.first_name)

    if not db.is_key_activated(user.id):
        conn = db._connect()
        try:
            row = conn.execute("SELECT access_key_hash FROM users WHERE tg_id = ?", (user.id,)).fetchone()
            stored_key = row["access_key_hash"] if row else None
            has_valid_totp = bool(stored_key and len(stored_key) != 64)
        finally:
            conn.close()

        display_key_msg = ""
        if not has_valid_totp:
            raw_secret = db.generate_user_key(user.id)
            display_key_msg = f"\n\n🔑 <i>Segreto TOTP:</i>\n<code>{raw_secret}</code>\n<i>Inseriscilo in Google Authenticator.</i>"

        text = f"🔐 <b>Autenticazione 2FA Richiesta</b>\n\nInserisci il codice a 6 cifre.{display_key_msg}"
        ctx.user_data["awaiting"] = "login_key"
        
        if update.callback_query:
            await update.callback_query.message.reply_text(text, parse_mode=ParseMode.HTML)
        elif update.effective_message:
            await update.effective_message.reply_text(text, parse_mode=ParseMode.HTML)
        return True

    db.update_last_activity(user.id)
    return False


# ==================== COMANDI BASE ====================

async def cmd_start(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    u = update.effective_user
    db.ensure_user(u.id, u.username, u.first_name)
    if await _check_access(update, ctx):
        return
    ctx.user_data.clear()
    await update.message.reply_text(
        "👋 <b>Benvenuto nel Network!</b>\n\nCatalogo attivo e sincronizzato.",
        parse_mode=ParseMode.HTML, reply_markup=client_menu(),
    )


async def cmd_help(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if await _check_access(update, ctx):
        return
    await _send_help(update.effective_message, ctx)


async def cb_menu(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if await _check_access(update, ctx):
        return
    q = update.callback_query
    await q.answer()
    await q.edit_message_text("🏠 <b>Menu Principale</b>", parse_mode=ParseMode.HTML, reply_markup=client_menu())


async def cb_help(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if await _check_access(update, ctx):
        return
    q = update.callback_query
    await q.answer()
    await _send_help(q.message, ctx, edit=True)


async def _send_help(msg, ctx, edit=False):
    text = "❓ <b>Guida Rapida</b>\n\n1️⃣ Ricarica il sub-balance tramite Invoice crypto.\n2️⃣ Scegli e acquista istantaneamente."
    if edit:
        await msg.edit_text(text, parse_mode=ParseMode.HTML, reply_markup=back_menu())
    else:
        await msg.reply_text(text, parse_mode=ParseMode.HTML, reply_markup=back_menu())


# ==================== CATALOGO ====================

async def _load_catalog(ctx, page: int, q: str = "", edit_msg=None, chat_id=None, user_id=None):
    if user_id:
        await _check_scraping(None, ctx, user_id)

    api = ctx.bot_data["api"]
    f = _filters(ctx)
    vendor_param = f.get("vendor") if f.get("vendor") != "Tutti" else ""
    country_param = f.get("country") if f.get("country") != "Tutti" else ""
    query_str = " ".join([t for t in [q, vendor_param, country_param] if t]).strip()

    try:
        data = await api.cc_search(
            page=page, page_size=PAGE_SIZE, q=query_str,
            bins=query_str if query_str.isdigit() else "",
            sort="price_asc", price_min=f.get("price_min"),
            price_max=f.get("price_max"), refund_allowed=f.get("refund_allowed"),
        )
    except APIError as e:
        txt = f"⚠️ {esc(e.message)}"
        if edit_msg:
            await edit_msg.edit_text(txt, reply_markup=back_menu())
        else:
            await ctx.bot.send_message(chat_id, txt, reply_markup=back_menu())
        return

    rows = data.get("rows") or []
    total = data.get("total", 0)
    cur_page = data.get("page", page)
    page_count = data.get("pageCount", 0) or 1

    header = f"🛍 <b>CC Shop</b>\nPagina {cur_page}/{page_count} · {total} disponibili"
    kb = cc_catalog_kb(rows, cur_page, cur_page > 1, cur_page < page_count, client_price) if rows else back_menu()

    if edit_msg:
        await edit_msg.edit_text(header, parse_mode=ParseMode.HTML, reply_markup=kb)
    else:
        await ctx.bot.send_message(chat_id, header, parse_mode=ParseMode.HTML, reply_markup=kb)


@rate_limit(seconds=2.0)
async def cb_cc(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if await _check_access(update, ctx):
        return
    q = update.callback_query
    await q.answer()
    page = int(q.data.split(":")[1]) if ":" in q.data else 1
    await _load_catalog(ctx, page, edit_msg=q.message, user_id=update.effective_user.id)


@rate_limit(seconds=3.0)
async def cb_cc_search(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if await _check_access(update, ctx):
        return
    q = update.callback_query
    await q.answer()
    ctx.user_data["awaiting"] = "ccsearch"
    await q.edit_message_text("🔍 <b>Ricerca CC</b>\n\nDigita il BIN (6-8 cifre) o il brand da cercare:", parse_mode=ParseMode.HTML, reply_markup=back_menu())


async def on_text(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if await _check_access(update, ctx):
        return
    awaiting = ctx.user_data.get("awaiting")
    if not awaiting:
        return
    text = update.message.text.strip()
    user_id = update.effective_user.id
    chat_id = update.effective_chat.id

    if awaiting == "login_key":
        ctx.user_data.pop("awaiting", None)
        clean_code = sanitize_input(text, mode="totp")
        if len(clean_code) != 6:
            await update.message.reply_text("❌ Codice non valido (6 cifre richieste).", parse_mode=ParseMode.HTML)
            ctx.user_data["awaiting"] = "login_key"
            return
        
        if db.verify_user_key(user_id, clean_code, chat_id):
            db.clear_failed_logins(user_id)
            await update.message.reply_text("✅ Accesso autorizzato!", parse_mode=ParseMode.HTML, reply_markup=client_menu())
        else:
            if db.record_failed_login(user_id):
                await update.message.reply_text("🚫 Troppi tentativi errati. Blocco temporaneo di 5 minuti.", parse_mode=ParseMode.HTML)
            else:
                await update.message.reply_text("❌ Codice errato. Riprova.", parse_mode=ParseMode.HTML)
                ctx.user_data["awaiting"] = "login_key"
        return

    if awaiting == "ccsearch":
        ctx.user_data.pop("awaiting", None)
        await _load_catalog(ctx, 1, q=sanitize_input(text, mode="search"), chat_id=chat_id, user_id=user_id)

    elif awaiting == "topup_amount":
        ctx.user_data.pop("awaiting", None)
        try:
            usd = float(text.replace(",", "."))
            cents = int(usd * 100)
            if cents < 100:
                raise ValueError()
        except ValueError:
            await update.message.reply_text("❌ Importo non valido. Minimo $1.00. Riprova con /topup.", parse_mode=ParseMode.HTML)
            return

        api = ctx.bot_data["api"]
        asset = ctx.user_data.get("topup_asset", "USDT")
        try:
            invoice = await api.create_deposit_invoice(amount_cents=cents, currency=asset)
        except APIError as e:
            await update.message.reply_text(f"❌ Errore invoice: {esc(e.message)}", parse_mode=ParseMode.HTML)
            return

        inv_id = invoice.get("id") or invoice.get("invoiceId")
        pay_address = invoice.get("addressText") or invoice.get("address", "N/D")

        conn = db._connect()
        try:
            conn.execute(
                "INSERT INTO transactions (tg_id, amount_cents, type, note) VALUES (?, ?, 'INVOICE_PENDING', ?)",
                (user_id, cents, str(inv_id))
            )
            conn.commit()
        finally:
            conn.close()

        await update.message.reply_text(
            f"📥 <b>Invoice di Ricarica Generata</b>\n\n"
            f"💎 Asset: <b>{esc(asset)}</b>\n"
            f"💰 Importo: <b>${usd:.2f}</b>\n"
            f"🔗 Indirizzo:\n<code>{esc(pay_address)}</code>\n\n"
            f"<i>Il sistema monitora il pagamento in automatico. Il saldo verrà accreditato non appena confermato.</i>",
            parse_mode=ParseMode.HTML, reply_markup=back_menu()
        )


# ==================== FILTRI & PRODOTTO ====================

async def _show_filters(chat_id, ctx, edit_msg=None):
    f = _filters(ctx)
    f_display = dict(f)
    f_display["price_label"] = _price_label(f)
    text = "🎛 <b>Filtri Avanzati</b>"
    if edit_msg:
        await edit_msg.edit_text(text, parse_mode=ParseMode.HTML, reply_markup=cc_filters_kb(f_display))
    else:
        await ctx.bot.send_message(chat_id, text, parse_mode=ParseMode.HTML, reply_markup=cc_filters_kb(f_display))


async def cb_cc_filter(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if await _check_access(update, ctx):
        return
    q = update.callback_query
    await q.answer()
    await _show_filters(q.message.chat_id, ctx, edit_msg=q.message)


async def cb_ccfilt(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if await _check_access(update, ctx):
        return
    q = update.callback_query
    await q.answer()
    parts = q.data.split(":")
    action = parts[1] if len(parts) > 1 else ""
    f = _filters(ctx)

    if action == "menu_vendor":
        await q.edit_message_text("💳 Seleziona Vendor:", parse_mode=ParseMode.MARKDOWN, reply_markup=cc_filter_vendor_kb())
        return
    elif action == "set_vendor" and len(parts) > 2:
        f["vendor"] = parts[2]
        await _show_filters(q.message.chat_id, ctx, edit_msg=q.message)
        return
    elif action == "reset":
        ctx.user_data["cc_filters"] = _default_filters()
        await _show_filters(q.message.chat_id, ctx, edit_msg=q.message)


async def _find_card(ctx, card_id: str):
    cache = ctx.bot_data.setdefault("cc_cache", {})
    if card_id in cache:
        return cache[card_id]
    api = ctx.bot_data["api"]
    try:
        data = await api.cc_search(page=1, page_size=100)
    except APIError:
        return None
    for c in data.get("rows", []):
        cache[str(c.get("id"))] = c
    return cache.get(card_id)


async def cb_cc_product(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if await _check_access(update, ctx):
        return
    q = update.callback_query
    await q.answer()
    cid = q.data.split(":", 1)[1]
    c = await _find_card(ctx, cid)
    if not c:
        await q.edit_message_text("Carta non disponibile.", reply_markup=back_menu())
        return

    sell = client_price(_extract_cents(c))
    
    # Pulsanti estesi con l'aggiunta al carrello
    keyboard = [
        [InlineKeyboardButton("⚡️ Hold & Acquista Subito", callback_data=f"cc_hold:{cid}")],
        [InlineKeyboardButton("🛒 Aggiungi al Carrello", callback_data=f"cc_cart_add:{cid}")],
        [InlineKeyboardButton("🔙 Torna allo Shop", callback_data="cc_shop")]
    ]
    
    text = (
        f"💳 <b>Dettagli Carta</b>\n\n"
        f"BIN: <code>{esc(c.get('bin'))}</code>\n"
        f"Vendor: {esc(c.get('vendor') or c.get('brand') or '—')}\n"
        f"Paese: {esc(c.get('country') or '—')}\n"
        f"Prezzo: <b>{money(sell)}</b>"
    )
    await q.edit_message_text(text, parse_mode=ParseMode.HTML, reply_markup=InlineKeyboardMarkup(keyboard))


# ==================== CARRELLO & CHECKOUT MULTIPLO ====================

async def cb_cc_add_cart(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if await _check_access(update, ctx):
        return
    q = update.callback_query
    await q.answer()
    
    card_id = q.data.split(":")[1]
    api = ctx.bot_data["api"]
    try:
        await api.cc_add_cart(card_id)
        await q.answer("✅ Carta aggiunta al carrello!", show_alert=False)
        await cb_cc_view_cart(update, ctx)
    except APIError as e:
        await q.answer(f"❌ Errore: {e.message}", show_alert=True)


async def cb_cc_view_cart(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if await _check_access(update, ctx):
        return
    q = update.callback_query
    if q.message:
        await q.answer()
    
    api = ctx.bot_data["api"]
    try:
        cart = await api.cc_get_cart()
        items = cart.get("items", [])
        total_cents = cart.get("totalCents", 0)
        
        if not items:
            text = "🛒 <b>Il tuo carrello CC è vuoto.</b>"
            keyboard = [[InlineKeyboardButton("🔙 Torna allo Shop", callback_data="cc_shop")]]
            if q.message:
                await q.edit_message_text(text, parse_mode=ParseMode.HTML, reply_markup=InlineKeyboardMarkup(keyboard))
            return
            
        text = f"🛒 <b>Carrello CC (Elementi: {len(items)})</b>\n\n"
        keyboard = []
        
        for item in items:
            c_id = item.get("cardId") or item.get("id", "")
            bin_val = item.get("bin", "N/D")
            price = item.get("priceCents", 0) / 100
            text += f"• BIN: <code>{bin_val}</code> — <b>${price:.2f}</b>\n"
            keyboard.append([InlineKeyboardButton(f"🗑 Rimuovi BIN {bin_val}", callback_data=f"cc_cart_del:{c_id}")])
            
        total_usd = total_cents / 100
        text += f"\n💰 <b>Totale Carrello:</b> ${total_usd:.2f}"
        
        keyboard.append([InlineKeyboardButton("💳 Procedi al Checkout", callback_data="cc_checkout_exec")])
        keyboard.append([InlineKeyboardButton("🔙 Torna allo Shop", callback_data="cc_shop")])
        
        if q.message:
            await q.edit_message_text(text, parse_mode=ParseMode.HTML, reply_markup=InlineKeyboardMarkup(keyboard))
    except APIError as e:
        if q.message:
            await q.edit_message_text(f"❌ Errore caricamento carrello: {esc(e.message)}", reply_markup=back_menu())


async def cb_cc_remove_cart(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if await _check_access(update, ctx):
        return
    q = update.callback_query
    await q.answer()
    
    card_id = q.data.split(":")[1]
    api = ctx.bot_data["api"]
    try:
        await api.cc_remove_cart(card_id)
        await cb_cc_view_cart(update, ctx)
    except APIError as e:
        await q.answer(f"❌ Errore rimozione: {e.message}", show_alert=True)


async def cb_cc_checkout_exec(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if await _check_access(update, ctx):
        return
    q = update.callback_query
    await q.answer("⏳ Elaborazione checkout sicuro in corso...")
    
    api = ctx.bot_data["api"]
    try:
        result = await api.cc_checkout()
        purchases = result.get("purchases", [])
        new_balance = result.get("balanceCents", 0) / 100
        
        text = f"🎉 <b>Checkout completato con successo!</b>\n\n"
        text += f"💳 Carte acquistate: {len(purchases)}\n"
        text += f"💰 Nuovo Saldo: <b>${new_balance:.2f}</b>\n\n"
        text += "Puoi visualizzare e esportare i dati completi dalla sezione I Miei Ordini."
        
        keyboard = [[InlineKeyboardButton("📦 I Miei Ordini", callback_data="myorders")],
                    [InlineKeyboardButton("📁 Esporta in .TXT", callback_data="cc_export_txt")],
                    [InlineKeyboardButton("🏠 Menu Principale", callback_data="menu")]]
                    
        await q.edit_message_text(text, parse_mode=ParseMode.HTML, reply_markup=InlineKeyboardMarkup(keyboard))
    except APIError as e:
        await q.edit_message_text(f"❌ <b>Errore durante il checkout:</b>\n{esc(e.message)}", parse_mode=ParseMode.HTML, reply_markup=back_menu())


# ==================== SISTEMA DI HOLD & CHECKER ====================

async def cb_cc_hold_and_buy(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if await _check_access(update, ctx):
        return
    q = update.callback_query
    await q.answer()
    cid = q.data.split(":", 1)[1]
    u = update.effective_user
    api = ctx.bot_data["api"]

    c = await _find_card(ctx, cid)
    if not c:
        await q.edit_message_text("Carta non disponibile.", reply_markup=back_menu())
        return

    try:
        hold_res = await api.cc_hold([cid])
        if not hold_res.get("ok", True) and not hold_res.get("held"):
            await q.edit_message_text("⚠️ Impossibile bloccare la carta: potrebbe essere già in hold o venduta.", reply_markup=back_menu())
            return
    except APIError as e:
        await q.edit_message_text(f"❌ Errore durante l'hold: {esc(e.message)}", reply_markup=back_menu())
        return

    total = client_price(_extract_cents(c))
    bal = db.get_balance(u.id)

    if bal < total:
        await q.edit_message_text(f"💸 Saldo insufficiente. Hai {money(bal)}, servono {money(total)}.", parse_mode=ParseMode.HTML, reply_markup=back_menu())
        return

    keyboard = [
        [InlineKeyboardButton("✅ Conferma Acquisto (Hold attivo)", callback_data=f"cc_buyok:{cid}")],
        [InlineKeyboardButton("🔙 Annulla", callback_data="cc_shop")]
    ]
    await q.edit_message_text(
        f"🔒 <b>Carta bloccata per 30 secondi!</b>\n\n"
        f"BIN: <code>{esc(c.get('bin'))}</code>\n"
        f"Totale: <b>{money(total)}</b>\n\n"
        f"<i>Procedi con la conferma prima che scada l'hold.</i>",
        parse_mode=ParseMode.HTML,
        reply_markup=InlineKeyboardMarkup(keyboard)
    )


async def cb_cc_buy_confirm(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if await _check_access(update, ctx):
        return
    q = update.callback_query
    await q.answer()
    cid = q.data.split(":", 1)[1]
    u = update.effective_user
    api = ctx.bot_data["api"]

    c = await _find_card(ctx, cid)
    if not c:
        await q.edit_message_text("Carta non disponibile.", reply_markup=back_menu())
        return

    total = client_price(_extract_cents(c))
    if not db.try_debit(u.id, total, "PURCHASE", note=f"cc {cid}"):
        await q.edit_message_text("💸 Saldo insufficiente.", reply_markup=back_menu())
        return

    try:
        res = await api.cc_buy([cid], format_type="txt")
    except APIError as e:
        db.credit(u.id, total, "REFUND", note="rimborso cc fallito")
        await q.edit_message_text(f"❌ Acquisto fallito: {esc(e.message)}. Saldi riaccreditati.", parse_mode=ParseMode.HTML, reply_markup=back_menu())
        return

    pur = (res.get("purchases") or [{}])[0]
    oid = db.create_order(
        tg_id=u.id, product_id=cid, title=f"CC {c.get('bin')}", qty=1,
        client_paid_cents=total, pre77_cost_cents=_extract_cents(c),
        pre77_purchase_id=pur.get("id"), delivery_lines=[], status="COMPLETED",
    )

    await q.edit_message_text(f"✅ <b>Acquisto completato</b> — ordine #{oid}\nUsa 'I miei acquisti' per rivelare i dati.", parse_mode=ParseMode.HTML, reply_markup=cc_order_kb(oid, "COMPLETED"))


async def cb_cc_start_checker(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if await _check_access(update, ctx):
        return
    q = update.callback_query
    await q.answer()
    
    parts = q.data.split(":")
    oid = int(parts[1]) if len(parts) > 1 else 0
    o = db.get_order(oid)
    
    if not o or o["tg_id"] != update.effective_user.id:
        await q.edit_message_text("Ordine non trovato.", reply_markup=back_menu())
        return

    api = ctx.bot_data["api"]
    try:
        check_res = await api.cc_check(o["pre77_purchase_id"])
        check_id = check_res.get("checkId")
    except APIError as e:
        await q.edit_message_text(f"❌ Errore avvio checker: {esc(e.message)}", reply_markup=cc_order_kb(oid, o["status"]))
        return

    await q.edit_message_text("🔄 <b>Checker avviato...</b> Attendere il responso.", parse_mode=ParseMode.HTML)

    status = "PENDING"
    result = "In elaborazione"
    
    for _ in range(5):
        await asyncio.sleep(3)
        try:
            poll_res = await api.cc_get_check(o["pre77_purchase_id"], check_id)
            status = poll_res.get("status", "PENDING")
            result = poll_res.get("result", status)
            if status != "PENDING":
                break
        except Exception:
            pass

    status_icon = "🟢" if status in ("LIVE", "valid") else "🔴"
    await q.edit_message_text(
        f"📊 <b>Risultato Checker #{oid}</b>\n\n"
        f"Stato: {status_icon} <b>{esc(status)}</b>\n"
        f"Dettaglio: <code>{esc(result)}</code>",
        parse_mode=ParseMode.HTML,
        reply_markup=cc_order_kb(oid, o["status"])
    )


# ==================== SUB-BALANCE & TOPUP DINAMICO ====================

async def cb_topup(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if await _check_access(update, ctx):
        return
    q = update.callback_query
    await q.answer()
    
    api = ctx.bot_data["api"]
    try:
        assets_data = await api.get_deposit_assets()
        items = assets_data.get("items", [])
    except Exception:
        items = [{"id": "USDT", "label": "Tether USDT", "network": "TRC20"}]

    keyboard = []
    for item in items:
        coin_id = item.get("id")
        label = item.get("label", coin_id)
        net = item.get("network", "")
        btn_text = f"💎 {label} ({net})" if net else f"💎 {label}"
        keyboard.append([InlineKeyboardButton(btn_text, callback_data=f"topup_asset:{coin_id}")])
    
    keyboard.append([InlineKeyboardButton("🔙 Indietro", callback_data="mysaldo")])
    
    await q.edit_message_text(
        "💳 <b>Ricarica Sub-Balance</b>\n\nSeleziona la criptovaluta con cui desideri effettuare il deposito:",
        parse_mode=ParseMode.HTML,
        reply_markup=InlineKeyboardMarkup(keyboard)
    )


async def cb_topup_asset(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if await _check_access(update, ctx):
        return
    q = update.callback_query
    await q.answer()
    
    asset = q.data.split(":")[1]
    ctx.user_data["topup_asset"] = asset
    ctx.user_data["awaiting"] = "topup_amount"
    
    await q.edit_message_text(
        f"💳 Hai scelto <b>{asset}</b>.\n\nInserisci l'importo in dollari ($) che desideri ricaricare:\n<i>Esempio:</i> <code>15</code>",
        parse_mode=ParseMode.HTML,
        reply_markup=back_menu()
    )


async def check_invoice_status_job(ctx: ContextTypes.DEFAULT_TYPE):
    api = ctx.bot_data.get("api")
    if not api:
        return

    conn = db._connect()
    try:
        rows = conn.execute("SELECT * FROM transactions WHERE type = 'INVOICE_PENDING'").fetchall()
        for r in rows:
            tg_id = r["tg_id"]
            cents = r["amount_cents"]
            inv_id = r["note"]

            try:
                status_data = await api.get_deposit_status(inv_id)
                status = str(status_data.get("status", "")).upper()

                if status in ("PAID", "COMPLETED", "SUCCESS"):
                    db.credit(tg_id, cents, "TOPUP", note=f"invoice {inv_id}")
                    conn.execute("UPDATE transactions SET type = 'TOPUP' WHERE id = ?", (r["id"],))
                    conn.commit()

                    try:
                        await ctx.bot.send_message(
                            tg_id,
                            f"✅ <b>Ricarica Accreditata!</b>\nIl tuo sub-balance è stato incrementato di <b>{money(cents)}</b>.",
                            parse_mode=ParseMode.HTML
                        )
                    except Exception:
                        pass
                elif status in ("EXPIRED", "CANCELLED", "FAILED"):
                    conn.execute("UPDATE transactions SET type = 'INVOICE_EXPIRED' WHERE id = ?", (r["id"],))
                    conn.commit()
            except Exception as e:
                log.debug("Polling invoice %s fallito: %s", inv_id, e)
    finally:
        conn.close()


async def cb_mysaldo(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if await _check_access(update, ctx):
        return
    q = update.callback_query
    await q.answer()
    u = update.effective_user
    db.ensure_user(u.id, u.username, u.first_name)
    
    bal = db.get_balance(u.id)
    txs = db.list_transactions(u.id, limit=5)
    
    lines = [f"💰 <b>Sub-Balance: {money(bal)}</b>", ""]
    if txs:
        lines.append("<b>Ultimi movimenti:</b>")
        for t in txs:
            sign = "+" if t["amount_cents"] >= 0 else ""
            lines.append(f"• {t['created_at'][:16]} {sign}{money(t['amount_cents'])} ({t['type']})")
            
    keyboard = [
        [InlineKeyboardButton("➕ Ricarica Sub-Balance", callback_data="topup")],
        [InlineKeyboardButton("🛒 Visualizza Carrello CC", callback_data="cc_view_cart")],
        [InlineKeyboardButton("🚪 Disconnetti", callback_data="auth_logout")],
        [InlineKeyboardButton("🔙 Indietro", callback_data="menu")]
    ]
    await q.edit_message_text("\n".join(lines), parse_mode=ParseMode.HTML, reply_markup=InlineKeyboardMarkup(keyboard))


# ==================== ORDINI, REVEAL & EXPORT TXT ====================

async def cb_cc_orders(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if await _check_access(update, ctx):
        return
    q = update.callback_query
    await q.answer()
    items = db.list_orders(update.effective_user.id)
    if not items:
        await q.edit_message_text("📦 Nessun acquisto.", reply_markup=back_menu())
        return
    
    keyboard = cc_orders_kb(items)
    # Aggiungiamo il tasto per l'export completo in .txt
    keyboard.inline_keyboard.append([InlineKeyboardButton("📁 Esporta tutto in .TXT", callback_data="cc_export_txt")])
    
    await q.edit_message_text(f"📦 <b>I tuoi acquisti</b>", parse_mode=ParseMode.HTML, reply_markup=keyboard)


async def cb_cc_order(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if await _check_access(update, ctx):
        return
    q = update.callback_query
    await q.answer()
    oid = int(q.data.split(":")[1])
    o = db.get_order(oid)
    if not o or o["tg_id"] != update.effective_user.id:
        await q.edit_message_text("Ordine non trovato.", reply_markup=back_menu())
        return

    lines = [f"🧾 <b>Ordine #{o['id']}</b>", f"<b>{esc(o['product_title'])}</b>", f"Stato: <b>{o['status']}</b>"]
    if o["delivery_lines"]:
        lines.append("\n📬 <b>Dati:</b>")
        for dl in o["delivery_lines"]:
            lines.append(f"<code>{esc(dl)}</code>")
    await q.edit_message_text("\n".join(lines), parse_mode=ParseMode.HTML, reply_markup=cc_order_kb(oid, o["status"]))


async def cb_cc_reveal(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if await _check_access(update, ctx):
        return
    q = update.callback_query
    await q.answer()
    oid = int(q.data.split(":")[1])
    o = db.get_order(oid)
    if not o or o["tg_id"] != update.effective_user.id:
        await q.edit_message_text("Ordine non trovato.", reply_markup=back_menu())
        return

    if o["delivery_lines"]:
        text = "\n".join(f"<code>{esc(dl)}</code>" for dl in o["delivery_lines"])
        await q.edit_message_text(f"💳 <b>Dati carta:</b>\n\n{text}", parse_mode=ParseMode.HTML, reply_markup=cc_order_kb(oid, o["status"]))
        return

    try:
        card = await ctx.bot_data["api"].cc_full_info(o["pre77_purchase_id"])
    except APIError as e:
        await q.edit_message_text(f"⚠️ Errore reveal: {esc(e.message)}", reply_markup=cc_order_kb(oid, o["status"]))
        return

    line = f"{card.get('number')}|{card.get('exp')}|{card.get('cvv')}"
    db.update_order_status(oid, o["status"], delivery_lines=[line])
    await q.edit_message_text(f"💳 <b>Dati carta:</b>\n\n<code>{esc(line)}</code>", parse_mode=ParseMode.HTML, reply_markup=cc_order_kb(oid, o["status"]))


async def cb_cc_export_txt(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if await _check_access(update, ctx):
        return
    q = update.callback_query
    await q.answer()
    
    api = ctx.bot_data["api"]
    try:
        res = await api.cc_export_purchases()
        dump_text = res.get("dump") if isinstance(res, dict) else str(res)
        
        if not dump_text or dump_text.strip() == "":
            await q.edit_message_text("📂 Nessuna carta acquistata da esportare.", reply_markup=back_menu())
            return
            
        file_bytes = dump_text.encode("utf-8")
        await ctx.bot.send_document(
            chat_id=q.message.chat_id,
            document=file_bytes,
            filename="cc_export_purchased.txt",
            caption="📂 <b>Export completo delle tue CC acquistate</b>",
            parse_mode=ParseMode.HTML
        )
        await q.message.delete()
    except APIError as e:
        await q.edit_message_text(f"❌ Errore durante l'export: {esc(e.message)}", reply_markup=back_menu())


async def cb_cc_refund(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if await _check_access(update, ctx):
        return
    q = update.callback_query
    await q.answer()
    oid = int(q.data.split(":")[1])
    o = db.get_order(oid)
    if not o or o["tg_id"] != update.effective_user.id or o["status"] == "REFUNDED":
        await q.edit_message_text("Operazione non consentita.", reply_markup=back_menu())
        return

    try:
        await ctx.bot_data["api"].cc_refund(o["pre77_purchase_id"], reason="user request")
    except APIError as e:
        await q.edit_message_text(f"❌ Rimborso fallito: {esc(e.message)}", reply_markup=cc_order_kb(oid, o["status"]))
        return

    db.credit(update.effective_user.id, o["client_paid_cents"], "REFUND", note=f"ordine #{oid}")
    db.update_order_status(oid, "REFUNDED")
    await q.edit_message_text("✅ Rimborso accreditato sul sub-balance.", parse_mode=ParseMode.HTML, reply_markup=back_menu())


# ==================== WEBHOOK VERIFICATION & PUSH HANDLER ====================

def verify_pre77_signature(request_body: bytes, signature_header: str, secret_key: str) -> bool:
    if not signature_header or not secret_key:
        return False
    computed = hmac.new(
        secret_key.encode("utf-8"),
        request_body,
        hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(computed, signature_header)


async def handle_pre77_webhook(event_data: dict, ctx: ContextTypes.DEFAULT_TYPE):
    event_type = event_data.get("event") or event_data.get("type")
    data = event_data.get("data", {})
    
    log.info("Ricevuto evento Webhook Pre77: %s", event_type)

    if event_type == "deposit.paid":
        tg_id = data.get("tgId") or data.get("userId")
        amount_cents = data.get("amountCents", 0)
        inv_id = data.get("id")
        
        if tg_id and amount_cents > 0:
            db.credit(tg_id, amount_cents, "TOPUP", note=f"webhook {inv_id}")
            try:
                await ctx.bot.send_message(
                    chat_id=tg_id,
                    text=f"⚡️ <b>Deposito Confermato!</b>\n"
                         f"Il tuo saldo è stato incrementato di <b>{money(amount_cents)}</b>.",
                    parse_mode=ParseMode.HTML
                )
            except Exception as e:
                log.error("Errore invio notifica deposito a %s: %s", tg_id, e)

    elif event_type == "shop.sold":
        title = data.get("productTitle", "Prodotto")
        price = data.get("totalCents", 0)
        for admin_id in config.ADMIN_IDS:
            try:
                await ctx.bot.send_message(
                    chat_id=admin_id,
                    text=f"🎉 <b>Nuova Vendita Negozio!</b>\n\n"
                         f"Articolo: <b>{esc(title)}</b>\n"
                         f"Incasso: <b>{money(price)}</b>",
                    parse_mode=ParseMode.HTML
                )
            except Exception:
                pass


# ==================== UTILITY & JOBS ====================

async def job_clear_cache(ctx: ContextTypes.DEFAULT_TYPE):
    cache = ctx.bot_data.setdefault("cc_cache", {})
    cache.clear()


async def job_daily_backup(ctx: ContextTypes.DEFAULT_TYPE):
    try:
        backup_path = db.backup_database()
        if not backup_path:
            return
        for admin_id in config.ADMIN_IDS:
            try:
                with open(backup_path, "rb") as f:
                    await ctx.bot.send_document(chat_id=admin_id, document=f, caption="💾 Backup Database")
            except Exception:
                pass
        
        if os.path.exists("backups"):
            now = time.time()
            for fp in glob.glob(os.path.join("backups", "bot_backup_*.db")):
                if now - os.path.getmtime(fp) > 259200:
                    try:
                        os.remove(fp)
                    except Exception:
                        pass
    except Exception:
        pass


async def cb_support(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if await _check_access(update, ctx):
        return
    q = update.callback_query
    await q.answer()
    await q.edit_message_text(f"🛠 Supporto ufficiale: <b>{getattr(config, 'SUPPORT_USERNAME', '@support')}</b>", parse_mode=ParseMode.HTML, reply_markup=back_menu())


async def cb_logout(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    if q.from_user:
        db.logout_user(q.from_user.id)
    ctx.user_data.clear()
    await q.edit_message_text("🚪 Disconnessione effettuata in sicurezza. Invia /start per rientrare.", parse_mode=ParseMode.HTML)


async def error_handler(update: object, ctx: ContextTypes.DEFAULT_TYPE):
    log.error("Exception: %s", ctx.error)


async def cmd_bin_lookup(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if await _check_access(update, ctx):
        return
    args = ctx.args
    if not args or not args[0].isdigit():
        await update.message.reply_text("🔍 Uso corretto: <code>/bin 414720</code>", parse_mode=ParseMode.HTML)
        return
    
    bin_code = args[0]
    api = ctx.bot_data["api"]
    try:
        res = await api.cc_bin_lookup(bin_code)
        available = res.get("available", 0)
        min_p = res.get("minPriceCents", 0) / 100
        max_p = res.get("maxPriceCents", 0) / 100
        
        text = (
            f"🔍 <b>Analisi BIN: {bin_code}</b>\n\n"
            f"Disponibili: <b>{available}</b>\n"
            f"Range Prezzo: <b>${min_p:.2f} - ${max_p:.2f}</b>"
        )
        await update.message.reply_text(text, parse_mode=ParseMode.HTML)
    except APIError as e:
        await update.message.reply_text(f"❌ Errore lookup BIN: {esc(e.message)}", parse_mode=ParseMode.HTML)
