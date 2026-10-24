from __future__ import annotations

import logging
import time
import os
import asyncio
from aiohttp import web
from telegram import Update
from telegram.ext import (
    Application, CallbackQueryHandler, CommandHandler, MessageHandler, filters,
)
import config
import db
from api_client import ShopAPI
import handlers
import admin

logging.basicConfig(
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    level=logging.INFO,
)
logging.getLogger("httpx").setLevel(logging.WARNING)
log = logging.getLogger(__name__)

# --- PROTEZIONE RATE LIMITING IP (ANTI-DDOS AIOHTTP) ---
_ip_request_cache = {}

@web.middleware
async def ip_rate_limit_middleware(request: web.Request, handler):
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        client_ip = forwarded.split(",")[0].strip()
    else:
        peername = request.transport.get_extra_info("peername")
        client_ip = peername[0] if peername else "127.0.0.1"

    if client_ip in ("127.0.0.1", "::1"):
        return await handler(request)

    now = time.time()
    history = _ip_request_cache.setdefault(client_ip, [])
    history[:] = [t for t in history if now - t < 10.0]
    
    if len(history) >= 40:
        log.warning("SIEM SECURITY ALERT | Rate limit IP superato da: %s", client_ip)
        return web.json_response({"error": "Too many requests. Slow down."}, status=429, headers={"Retry-After": "10"})
        
    history.append(now)
    return await handler(request)

# --- ENDPOINT WEBHOOK PRE77 (PAGAMENTI) ---
async def pre77_webhook_endpoint(request: web.Request) -> web.Response:
    app: Application = request.app["ptb_app"]
    try:
        body_bytes = await request.read()
        sig_header = request.headers.get("X-Pre77-Signature", "")
        
        secret = getattr(config, "PRE77_WEBHOOK_SECRET", "")
        if secret and not handlers.verify_pre77_signature(body_bytes, sig_header, secret):
            log.warning("SIEM SECURITY | Signature Webhook Pre77 non valida.")
            await admin.send_security_alert(
                app.bot,
                "Tentativo Spoofing Webhook",
                f"Firma non valida ricevuta.\nHeader: {sig_header[:15]}...",
                level="CRITICAL"
            )
            return web.json_response({"error": "Invalid signature"}, status=401)

        data = await request.json()
        class DummyContext:
            bot = app.bot
            bot_data = app.bot_data
        
        await handlers.handle_pre77_webhook(data, DummyContext())
        return web.json_response({"ok": True})
    except Exception as e:
        log.error("Errore elaborazione webhook Pre77: %s", e)
        return web.json_response({"error": str(e)}, status=400)


def setup_handlers(app: Application):
    app.add_handler(CommandHandler("start", handlers.cmd_start))
    app.add_handler(CommandHandler("help", handlers.cmd_help))
    app.add_handler(CommandHandler("id", admin.cmd_id))
    app.add_handler(CommandHandler("bin", handlers.cmd_bin_lookup))

    app.add_handler(CommandHandler("admin", admin.cmd_admin))
    app.add_handler(CommandHandler("mystock", admin.cmd_mystock))
    app.add_handler(CommandHandler("addbalance", admin.cmd_addbalance))
    app.add_handler(CommandHandler("subbalance", admin.cmd_subbalance))
    app.add_handler(CommandHandler("userinfo", admin.cmd_userinfo))
    app.add_handler(CommandHandler("deposits", admin.cmd_deposits))
    app.add_handler(CommandHandler("setkey", admin.cmd_setkey))
    app.add_handler(CommandHandler("users", admin.cb_admin_users))
    app.add_handler(CommandHandler("db_wipe", admin.cmd_db_wipe))
    app.add_handler(CommandHandler("statusbot", admin.cmd_statusbot))
    app.add_handler(CommandHandler("ban", admin.cmd_ban))
    app.add_handler(CommandHandler("unban", admin.cmd_unban))
    app.add_handler(CommandHandler("stats", admin.cmd_stats))
    app.add_handler(CommandHandler("pre77balance", admin.cmd_pre77balance))
    app.add_handler(CommandHandler("pending", admin.cmd_pending))
    app.add_handler(CommandHandler("deliver", admin.cmd_deliver))
    app.add_handler(CommandHandler("refund", admin.cmd_refund))
    app.add_handler(CommandHandler("clearcache", admin.cmd_clearcache))
    
    # --- COMANDO BROADCAST ---
    app.add_handler(CommandHandler("broadcast", admin.cmd_broadcast))

    app.add_handler(CallbackQueryHandler(handlers.cb_menu, pattern=r"^menu$"))
    app.add_handler(CallbackQueryHandler(handlers.cb_help, pattern=r"^help$"))
    
    # CALLBACK CATALOGO E PRODOTTO CC SHOP
    app.add_handler(CallbackQueryHandler(handlers.cb_cc, pattern=r"^cc_shop"))
    app.add_handler(CallbackQueryHandler(handlers.cb_cc, pattern=r"^cc_page:\d+$"))
    app.add_handler(CallbackQueryHandler(handlers.cb_cc_search, pattern=r"^cc_search$"))
    
    # ROTTA DEDICATA PER IL DETTAGLIO SCHEDA CARTA (Supporta sia cc_prod: che cc_card:)
    app.add_handler(CallbackQueryHandler(handlers.cb_cc_product, pattern=r"^(cc_prod:|cc_card:)"))
    
    app.add_handler(CallbackQueryHandler(handlers.cb_cc_hold_and_buy, pattern=r"^cc_hold:"))
    app.add_handler(CallbackQueryHandler(handlers.cb_cc_buy_confirm, pattern=r"^cc_buyok:"))
    
    app.add_handler(CallbackQueryHandler(handlers.cb_cc_add_cart, pattern=r"^cc_cart_add:"))
    app.add_handler(CallbackQueryHandler(handlers.cb_cc_view_cart, pattern=r"^cc_view_cart$"))
    app.add_handler(CallbackQueryHandler(handlers.cb_cc_remove_cart, pattern=r"^cc_cart_del:"))
    app.add_handler(CallbackQueryHandler(handlers.cb_cc_checkout_exec, pattern=r"^cc_checkout_exec$"))
    app.add_handler(CallbackQueryHandler(handlers.cb_cc_export_txt, pattern=r"^cc_export_txt$"))
    
    app.add_handler(CallbackQueryHandler(handlers.cb_cc_orders, pattern=r"^myorders$"))
    app.add_handler(CallbackQueryHandler(handlers.cb_cc_order, pattern=r"^cc_order:"))
    app.add_handler(CallbackQueryHandler(handlers.cb_cc_reveal, pattern=r"^cc_reveal:"))
    
    app.add_handler(CallbackQueryHandler(handlers.cb_mysaldo, pattern=r"^mysaldo$"))
    app.add_handler(CallbackQueryHandler(handlers.cb_topup, pattern=r"^topup$"))
    app.add_handler(CallbackQueryHandler(handlers.cb_topup_asset, pattern=r"^topup_asset:"))
    app.add_handler(CallbackQueryHandler(handlers.cb_support, pattern=r"^support$"))
    app.add_handler(CallbackQueryHandler(handlers.cb_logout, pattern=r"^auth_logout$"))

    app.add_handler(CallbackQueryHandler(admin.cb_admin, pattern=r"^admin$"))
    app.add_handler(CallbackQueryHandler(admin.cb_admin_mystock, pattern=r"^admin_mystock$"))
    app.add_handler(CallbackQueryHandler(admin.cb_admin_restock_prompt, pattern=r"^admin_restock:"))
    app.add_handler(CallbackQueryHandler(admin.cb_admin_stats, pattern=r"^admin_stats$"))
    app.add_handler(CallbackQueryHandler(admin.cb_admin_pre77bal, pattern=r"^admin_pre77bal$"))
    app.add
