from __future__ import annotations

import html
import logging
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
import admin
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
        await admin.send_security_alert(
            ctx.bot,
            "Possibile Scraping Rilevato",
            f"User ID: {user_id}\nRichieste eccessive nel minuto: {len(history)}",
            level="WARN"
        )
        history.clear()


def client_price(raw_price: float | int) -> float:
    if not raw_price:
        return 0.0
    # I prezzi dalle API Pre77 sono già in centesimi (es. 1200 = $12.00)
    cents = float(raw_price)
    markup = getattr(config, "MARKUP_PERCENT", 0.0)
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


async def _load_catalog(ctx, page: int, q: str = "", edit_msg=None, chat_id=None, user_id=None):
    if user_id:
        await _check_scraping(None, ctx, user_id)

    api = ctx.bot_data["api"]
    try:
        data = await api.cc_search(page=page, page_size=PAGE_SIZE, q=q, sort="price_asc")
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

    header = f"🛍 <b>Secure Store Catalog</b>\nPagina {cur_page}/{page_count} · {total} disponibili"
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
    await q.edit_message_text("🔍 <b>Ricerca Prodotti</b>\n\nDigita il BIN (6-8 cifre) o il brand da cercare:", parse_mode=ParseMode.HTML, reply_markup=back_menu())


async def on_text(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if await _check_access(update, ctx):
        return
    awaiting = ctx.user_data.get("awaiting")
    if not awaiting:
        return
    
    if awaiting.startswith("restock_lines:"):
        await admin.on_admin_restock_text(update, ctx)
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
                await admin.send_security_alert(
                    ctx.bot,
                    "Tentativi 2FA Eccessivi (Brute-Force)",
                    f"User ID: {user_id} | Chat ID: {chat_id}\nL'utente è stato temporaneamente bloccato.",
                    level="CRITICAL"
                )
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
            await update.message.reply_text("❌ Importo non valido. Minimo $1.00.", parse_mode=ParseMode.HTML)
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
            conn.execute("INSERT INTO transactions (tg_id, amount_cents, type, note) VALUES (?, ?, 'INVOICE_PENDING', ?)", (user_id, cents, str(inv_id)))
            conn.commit()
        finally:
            conn.close()

        await update.message.reply_text(
            f"📥 <b>Invoice di Ricarica Generata</b>\n\n"
            f"💎 Asset: <b>{esc(asset)}</b>\n💰 Importo: <b>${usd:.2f}</b>\n"
            f"🔗 Indirizzo:\n<code>{esc(pay_address)}</code>",
            parse_mode=ParseMode.HTML, reply_markup=back_menu()
        )


async def cb_cc_product(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if await _check_access(update, ctx):
        return
    q = update.callback_query
    await q.answer()
    cid = q.data.split(":", 1)[1]
    
    api = ctx.bot_data["api"]
    c = None
    try:
        data = await api.cc_search(page=1, page_size=100)
        c = next((item for item in data.get("rows", []) if str(item.get("id")) == cid), None)
    except APIError:
        c = None

    if not c:
        c = {"id": cid, "bin": "N/D", "priceCents": 0}

    sell = client_price(c.get("priceCents", 0))
    keyboard = [
        [InlineKeyboardButton("⚡️ Hold & Acquista Subito", callback_data=f"cc_hold:{cid}")],
        [InlineKeyboardButton("🛒 Aggiungi al Carrello", callback_data=f"cc_cart_add:{cid}")],
        [InlineKeyboardButton("🔙 Torna allo Shop", callback_data="cc_shop")]
    ]
    
    text = f"💳 <b>Dettagli Prodotto</b>\n\nBIN: <code>{esc(c.get('bin'))}</code>\nPrezzo: <b>{money(sell)}</b>"
    await q.edit_message_text(text, parse_mode=ParseMode.HTML, reply_markup=InlineKeyboardMarkup(keyboard))


async def cb_cc_add_cart(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if await _check_access(update, ctx):
        return
    q = update.callback_query
    card_id = q.data.split(":")[1]
    try:
        await ctx.bot_data["api"].cc_add_cart(card_id)
        await q.answer("✅ Aggiunto al carrello!", show_alert=False)
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
        total_cents = cart.get("totalCents", 0)
        
        if not items:
            text = "🛒 <b>Il tuo carrello è vuoto.</b>"
            keyboard = [[InlineKeyboardButton("🔙 Torna allo Shop", callback_data="cc_shop")]]
            await q.edit_message_text(text, parse_mode=ParseMode.HTML, reply_markup=InlineKeyboardMarkup(keyboard))
            return
            
        text = f"🛒 <b>Carrello ({len(items)})</b>\n\n"
        keyboard = []
        for item in items:
            c_id = item.get("cardId") or item.get("id", "")
            bin_val = item.get("bin", "N/D")
            price = item.get("priceCents", 0) / 100
            text += f"• BIN: <code>{bin_val}</code> — <b>${price:.2f}</b>\n"
            keyboard.append([InlineKeyboardButton(f"🗑 Rimuovi {bin_val}", callback_data=f"cc_cart_del:{c_id}")])
            
        text += f"\n💰 <b>Totale:</b> ${total_cents/100:.2f}"
        keyboard.append([InlineKeyboardButton("💳 Procedi al Checkout", callback_data="cc_checkout_exec")])
        keyboard.append([InlineKeyboardButton("🔙 Torna allo Shop", callback_data="cc_shop")])
        
        await q.edit_message_text(text, parse_mode=ParseMode.HTML, reply_markup=InlineKeyboardMarkup(keyboard))
    except APIError as e:
        await q.edit_message_text(f"❌ Errore carrello: {esc(e.message)}", reply_markup=back_menu())


async def cb_cc_remove_cart(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if await _check_access(update, ctx):
        return
    q = update.callback_query
    try:
        await ctx.bot_data["api"].cc_remove_cart(q.data.split(":")[1])
        await cb_cc_view_cart(update, ctx)
    except APIError as e:
        await q.answer(f"❌ Errore: {e.message}", show_alert=True)


async def cb_cc_checkout_exec(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if await _check_access(update, ctx):
        return
    q = update.callback_query
    await q.answer("⏳ Elaborazione checkout...")
    try:
        result = await ctx.bot_data["api"].cc_checkout()
        text = f"🎉 <b>Checkout completato!</b>\nAcquisti: {len(result.get('purchases', []))}"
        keyboard = [[InlineKeyboardButton("📦 I Miei Ordini", callback_data="myorders")],
                    [InlineKeyboardButton("📁 Esporta .TXT", callback_data="cc_export_txt")],
                    [InlineKeyboardButton("🏠 Menu", callback_data="menu")]]
        await q.edit_message_text(text, parse_mode=ParseMode.HTML, reply_markup=InlineKeyboardMarkup(keyboard))
    except APIError as e:
        await q.edit_message_text(f"❌ Errore checkout: {esc(e.message)}", parse_mode=ParseMode.HTML, reply_markup=back_menu())


async def cb_cc_hold_and_buy(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if await _check_access(update, ctx):
        return
    q = update.callback_query
    cid = q.data.split(":", 1)[1]
    try:
        await ctx.bot_data["api"].cc_hold([cid])
    except APIError as e:
        await q.edit_message_text(f"❌ Errore hold: {esc(e.message)}", reply_markup=back_menu())
        return

    keyboard = [
        [InlineKeyboardButton("✅ Conferma Acquisto", callback_data=f"cc_buyok:{cid}")],
        [InlineKeyboardButton("🔙 Annulla", callback_data="cc_shop")]
    ]
    await q.edit_message_text("🔒 <b>Articolo bloccato per 30s!</b> Conferma l'acquisto.", parse_mode=ParseMode.HTML, reply_markup=InlineKeyboardMarkup(keyboard))


async def cb_cc_buy_confirm(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if await _check_access(update, ctx):
        return
    q = update.callback_query
    cid = q.data.split(":", 1)[1]
    u = update.effective_user
    
    try:
        res = await ctx.bot_data["api"].cc_buy([cid], format_type="txt")
    except APIError as e:
        await q.edit_message_text(f"❌ Acquisto fallito: {esc(e.message)}", parse_mode=ParseMode.HTML, reply_markup=back_menu())
        return

    pur = (res.get("purchases") or [{}])[0]
    oid = db.create_order(tg_id=u.id, product_id=cid, title="Articolo", qty=1, client_paid_cents=pur.get("priceCents", 0), pre77_cost_cents=0, pre77_purchase_id=pur.get("id"), delivery_lines=[], status="COMPLETED")
    await q.edit_message_text(f"✅ <b>Acquisto completato</b> — ordine #{oid}", parse_mode=ParseMode.HTML, reply_markup=cc_order_kb(oid, "COMPLETED"))


async def cb_cc_orders(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if await _check_access(update, ctx):
        return
    q = update.callback_query
    items = db.list_orders(update.effective_user.id)
    if not items:
        await q.edit_message_text("📦 Nessun acquisto.", reply_markup=back_menu())
        return
    keyboard = cc_orders_kb(items)
    keyboard.inline_keyboard.append([InlineKeyboardButton("📁 Esporta in .TXT", callback_data="cc_export_txt")])
    await q.edit_message_text("📦 <b>I tuoi acquisti</b>", parse_mode=ParseMode.HTML, reply_markup=keyboard)


async def cb_cc_order(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if await _check_access(update, ctx):
        return
    q = update.callback_query
    oid = int(q.data.split(":")[1])
    o = db.get_order(oid)
    if not o or o["tg_id"] != update.effective_user.id:
        await q.edit_message_text("Ordine non trovato.", reply_markup=back_menu())
        return
    await q.edit_message_text(f"🧾 <b>Ordine #{o['id']}</b>\nStato: <b>{o['status']}</b>", parse_mode=ParseMode.HTML, reply_markup=cc_order_kb(oid, o["status"]))


async def cb_cc_reveal(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if await _check_access(update, ctx):
        return
    q = update.callback_query
    oid = int(q.data.split(":")[1])
    o = db.get_order(oid)
    if not o or o["tg_id"] != update.effective_user.id:
        await q.edit_message_text("Ordine non trovato.", reply_markup=back_menu())
        return
    if o["delivery_lines"]:
        text = "\n".join(f"<code>{esc(dl)}</code>" for dl in o["delivery_lines"])
        await q.edit_message_text(f"💳 <b>Dati:</b>\n\n{text}", parse_mode=ParseMode.HTML, reply_markup=cc_order_kb(oid, o["status"]))
        return
    try:
        card = await ctx.bot_data["api"].cc_full_info(o["pre77_purchase_id"])
    except APIError as e:
        await q.edit_message_text(f"⚠️ Errore reveal: {esc(e.message)}", reply_markup=cc_order_kb(oid, o["status"]))
        return
    line = f"{card.get('number')}|{card.get('exp')}|{card.get('cvv')}"
    db.update_order_status(oid, o["status"], delivery_lines=[line])
    await q.edit_message_text(f"💳 <b>Dati:</b>\n\n<code>{esc(line)}</code>", parse_mode=ParseMode.HTML, reply_markup=cc_order_kb(oid, o["status"]))


async def cb_cc_export_txt(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if await _check_access(update, ctx):
        return
    q = update.callback_query
    try:
        res = await ctx.bot_data["api"].cc_export_purchases()
        dump_text = res.get("dump", "")
        if not dump_text.strip():
            await q.edit_message_text("📂 Nessun articolo da esportare.", reply_markup=back_menu())
            return
        await ctx.bot.send_document(chat_id=q.message.chat_id, document=dump_text.encode("utf-8"), filename="export.txt", caption="📂 <b>Export completo</b>", parse_mode=ParseMode.HTML)
        await q.message.delete()
    except APIError as e:
        await q.edit_message_text(f"❌ Errore export: {esc(e.message)}", reply_markup=back_menu())


async def cb_topup(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if await _check_access(update, ctx):
        return
    q = update.callback_query
    try:
        assets_data = await ctx.bot_data["api"].get_deposit_assets()
        items = assets_data.get("items", [{"id": "USDT", "label": "Tether USDT", "network": "TRC20"}])
    except Exception:
        items = [{"id": "USDT", "label": "Tether USDT", "network": "TRC20"}]

    keyboard = [[InlineKeyboardButton(f"💎 {i.get('label')} ({i.get('network', '')})", callback_data=f"topup_asset:{i.get('id')}")] for i in items]
    keyboard.append([InlineKeyboardButton("🔙 Indietro", callback_data="mysaldo")])
    await q.edit_message_text("💳 <b>Seleziona criptovaluta per la ricarica:</b>", parse_mode=ParseMode.HTML, reply_markup=InlineKeyboardMarkup(keyboard))


async def cb_topup_asset(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if await _check_access(update, ctx):
        return
    q = update.callback_query
    asset = q.data.split(":")[1]
    ctx.user_data["topup_asset"] = asset
    ctx.user_data["awaiting"] = "topup_amount"
    await q.edit_message_text(f"💳 Hai scelto <b>{asset}</b>.\n\nInserisci l'importo in dollari ($):\n<i>Esempio:</i> <code>15</code>", parse_mode=ParseMode.HTML, reply_markup=back_menu())


async def check_invoice_status_job(ctx: ContextTypes.DEFAULT_TYPE):
    api = ctx.bot_data.get("api")
    if not api:
        return
    conn = db._connect()
    try:
        rows = conn.execute("SELECT * FROM transactions WHERE type = 'INVOICE_PENDING'").fetchall()
        for r in rows:
            try:
                status_data = await api.get_deposit_status(r["note"])
                if str(status_data.get("status", "")).upper() in ("PAID", "COMPLETED", "SUCCESS"):
                    db.credit(r["tg_id"], r["amount_cents"], "TOPUP", note=f"invoice {r['note']}")
                    conn.execute("UPDATE transactions SET type = 'TOPUP' WHERE id = ?", (r["id"],))
                    conn.commit()
                    await ctx.bot.send_message(r["tg_id"], f"✅ <b>Ricarica Accreditata!</b> +{money(r['amount_cents'])}", parse_mode=ParseMode.HTML)
            except Exception:
                pass
    finally:
        conn.close()


async def cb_mysaldo(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if await _check_access(update, ctx):
        return
    q = update.callback_query
    u = update.effective_user
    bal = db.get_balance(u.id)
    keyboard = [
        [InlineKeyboardButton("➕ Ricarica", callback_data="topup")],
        [InlineKeyboardButton("🛒 Carrello", callback_data="cc_view_cart")],
        [InlineKeyboardButton("🚪 Disconnetti", callback_data="auth_logout")],
        [InlineKeyboardButton("🔙 Indietro", callback_data="menu")]
    ]
    await q.edit_message_text(f"💰 <b>Sub-Balance: {money(bal)}</b>", parse_mode=ParseMode.HTML, reply_markup=InlineKeyboardMarkup(keyboard))


def verify_pre77_signature(request_body: bytes, signature_header: str, secret_key: str) -> bool:
    if not signature_header or not secret_key:
        return False
    computed = hmac.new(secret_key.encode("utf-8"), request_body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(computed, signature_header)


async def handle_pre77_webhook(event_data: dict, ctx: ContextTypes.DEFAULT_TYPE):
    event_type = event_data.get("event") or event_data.get("type")
    data = event_data.get("data", {})
    
    if event_type == "deposit.paid":
        tg_id = data.get("tgId") or data.get("userId")
        amount_cents = data.get("amountCents", 0)
        if tg_id and amount_cents > 0:
            db.credit(tg_id, amount_cents, "TOPUP", note="webhook deposit")
            try:
                await ctx.bot.send_message(tg_id, f"⚡️ <b>Deposito Confermato!</b> +{money(amount_cents)}", parse_mode=ParseMode.HTML)
            except Exception:
                pass
    elif event_type == "shop.sold":
        buyer = data.get("buyerLogin", "Sconosciuto")
        total_cents = data.get("totalCents", 0)
        p_title = data.get("productTitle", "Articolo")
        
        await admin.send_security_alert(
            ctx.bot,
            "Nuova Vendita nel tuo Shop!",
            f"Acquirente: @{esc(buyer)}\nProdotto: {esc(p_title)}\nTotale: {money(total_cents)}",
            level="SUCCESS"
        )


async def job_clear_cache(ctx: ContextTypes.DEFAULT_TYPE):
    ctx.bot_data.setdefault("cc_cache", {}).clear()


async def job_daily_backup(ctx: ContextTypes.DEFAULT_TYPE):
    try:
        backup_path = db.backup_database()
        if backup_path:
            for admin_id in config.ADMIN_IDS:
                with open(backup_path, "rb") as f:
                    await ctx.bot.send_document(chat_id=admin_id, document=f, caption="💾 Backup Database")
    except Exception:
        pass


async def cb_support(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if await _check_access(update, ctx):
        return
    await update.callback_query.edit_message_text(f"🛠 Supporto: <b>{getattr(config, 'SUPPORT_USERNAME', '@support')}</b>", parse_mode=ParseMode.HTML, reply_markup=back_menu())


async def cb_logout(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    if q.from_user:
        db.logout_user(q.from_user.id)
    ctx.user_data.clear()
    await q.edit_message_text("🚪 Disconnessione effettuata. Invia /start per rientrare.", parse_mode=ParseMode.HTML)


async def error_handler(update: object, ctx: ContextTypes.DEFAULT_TYPE):
    log.error("Exception: %s", ctx.error)


async def cmd_bin_lookup(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if await _check_access(update, ctx):
        return
    args = ctx.args
    if not args or not args[0].isdigit():
        await update.message.reply_text("🔍 Uso: <code>/bin 414720</code>", parse_mode=ParseMode.HTML)
        return
    try:
        res = await ctx.bot_data["api"].cc_bin_lookup(args[0])
        await update.message.reply_text(f"🔍 <b>BIN {args[0]}</b>\nDisponibili: {res.get('available', 0)}", parse_mode=ParseMode.HTML)
    except APIError as e:
        await update.message.reply_text(f"❌ Errore: {esc(e.message)}", parse_mode=ParseMode.HTML)
