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

# --- ENDPOINT WEBHOOK TELEGRAM (DIRETTO E SINCRONIZZATO) ---
async def telegram_webhook_endpoint(request: web.Request) -> web.Response:
    app: Application = request.app["ptb_app"]
    try:
        data = await request.json()
        update = Update.de_json(data, app.bot)
        # Esegue l'update immediatamente in background task per non bloccare la risposta HTTP
        asyncio.create_task(app.process_update(update))
        return web.Response(text="OK", status=200)
    except Exception as e:
        log.error("Errore elaborazione update Telegram: %s", e)
        return web.Response(text="Error", status=500)

# --- ENDPOINT WEBHOOK PRE77 ---
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

    app.add_handler(CallbackQueryHandler(handlers.cb_menu, pattern=r"^menu$"))
    app.add_handler(CallbackQueryHandler(handlers.cb_help, pattern=r"^help$"))
    app.add_handler(CallbackQueryHandler(handlers.cb_cc, pattern=r"^cc_shop$"))
    app.add_handler(CallbackQueryHandler(handlers.cb_cc, pattern=r"^cc_page:\d+$"))
    app.add_handler(CallbackQueryHandler(handlers.cb_cc_search, pattern=r"^cc_search$"))
    app.add_handler(CallbackQueryHandler(handlers.cb_cc_product, pattern=r"^cc_card:"))
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
    app.add_handler(CallbackQueryHandler(admin.cb_admin_users, pattern=r"^admin_users$"))
    app.add_handler(CallbackQueryHandler(admin.cb_admin_orders, pattern=r"^admin_orders$"))
    app.add_handler(CallbackQueryHandler(admin.cb_admin_pending, pattern=r"^admin_pending$"))
    app.add_handler(CallbackQueryHandler(admin.cb_admin_deposits, pattern=r"^admin_deposits$"))
    app.add_handler(CallbackQueryHandler(admin.cmd_clearcache, pattern=r"^admin_clearcache$"))

    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handlers.on_text))
    app.add_error_handler(handlers.error_handler)


async def main():
    db.init_db()
    api = ShopAPI()

    app = Application.builder().token(config.TELEGRAM_BOT_TOKEN).build()
    app.bot_data["api"] = api

    setup_handlers(app)

    await app.initialize()
    await app.start()

    if app.job_queue:
        app.job_queue.run_repeating(handlers.job_clear_cache, interval=7200, first=60)
        app.job_queue.run_repeating(handlers.job_daily_backup, interval=86400, first=300)
        app.job_queue.run_repeating(handlers.check_invoice_status_job, interval=60, first=15)

    RENDER_URL = os.environ.get("RENDER_EXTERNAL_URL") or "https://botkvneki.onrender.com"
    tg_webhook_url = f"{RENDER_URL}/telegram_webhook"
    pre77_webhook_url = f"{RENDER_URL}/webhook/pre77"

    await app.bot.set_webhook(url=tg_webhook_url, drop_pending_updates=True)
    log.info("Webhook Telegram registrato: %s", tg_webhook_url)

    try:
        await api.set_webhook(pre77_webhook_url)
        log.info("Webhook Pre77 registrato: %s", pre77_webhook_url)
    except Exception as e:
        log.error("Impossibile registrare Webhook Pre77: %s", e)

    web_app = web.Application(middlewares=[ip_rate_limit_middleware])
    web_app["ptb_app"] = app
    web_app.router.add_post("/telegram_webhook", telegram_webhook_endpoint)
    web_app.router.add_post("/webhook/pre77", pre77_webhook_endpoint)

    PORT = int(os.environ.get("PORT", 10000))
    runner = web.AppRunner(web_app)
    await runner.setup()
    site = web.TCPSite(runner, "0.0.0.0", PORT)
    
    log.info("Server Aiohttp unificato in ascolto sulla porta %s", PORT)
    await site.start()

    await asyncio.Event().wait()


if __name__ == "__main__":
    asyncio.run(main())
