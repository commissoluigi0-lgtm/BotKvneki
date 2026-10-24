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

_ip_request_cache = {}

@web.middleware
async def ip_rate_limit_middleware(request: web.Request, handler):
    forwarded = request.headers.get("X-Forwarded-For")
    client_ip = forwarded.split(",")[0].strip() if forwarded else (request.transport.get_extra_info("peername")[0] if request.transport.get_extra_info("peername") else "127.0.0.1")

    if client_ip in ("127.0.0.1", "::1"):
        return await handler(request)

    now = time.time()
    history = _ip_request_cache.setdefault(client_ip, [])
    history[:] = [t for t in history if now - t < 10.0]
    
    if len(history) >= 40:
        return web.json_response({"error": "Too many requests."}, status=429)
        
    history.append(now)
    return await handler(request)

async def pre77_webhook_endpoint(request: web.Request) -> web.Response:
    app: Application = request.app["ptb_app"]
    try:
        body_bytes = await request.read()
        sig_header = request.headers.get("X-Pre77-Signature", "")
        secret = getattr(config, "PRE77_WEBHOOK_SECRET", "")
        if secret and not handlers.verify_pre77_signature(body_bytes, sig_header, secret):
            return web.json_response({"error": "Invalid signature"}, status=401)

        data = await request.json()
        class DummyContext:
            bot = app.bot
            bot_data = app.bot_data
        
        await handlers.handle_pre77_webhook(data, DummyContext())
        return web.json_response({"ok": True})
    except Exception as e:
        return web.json_response({"error": str(e)}, status=400)


def setup_handlers(app: Application):
    # COMANDI DI TESTO
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
    app.add_handler(CommandHandler("broadcast", admin.cmd_broadcast))

    # GESTIONE CALLBACK UNIFICATA E LINEARE
    app.add_handler(CallbackQueryHandler(handlers.cb_menu, pattern="^menu$"))
    app.add_handler(CallbackQueryHandler(handlers.cb_help, pattern="^help$"))
    
    # ROTTE CC SHOP (Pattern chiari e senza conflitti)
    app.add_handler(CallbackQueryHandler(handlers.cb_cc, pattern="^cc_shop"))
    app.add_handler(CallbackQueryHandler(handlers.cb_cc_search, pattern="^cc_search$"))
    app.add_handler(CallbackQueryHandler(handlers.cb_cc_product, pattern="^cc_prod:"))
    
    app.add_handler(CallbackQueryHandler(handlers.cb_cc_add_cart, pattern="^cc_cart_add:"))
    app.add_handler(CallbackQueryHandler(handlers.cb_cc_view_cart, pattern="^cc_view_cart$"))
    app.add_handler(CallbackQueryHandler(handlers.cb_cc_remove_cart, pattern="^cc_cart_del:"))
    app.add_handler(CallbackQueryHandler(handlers.cb_cc_checkout_exec, pattern="^cc_checkout_exec$"))
    
    app.add_handler(CallbackQueryHandler(handlers.cb_cc_orders, pattern="^myorders$"))
    app.add_handler(CallbackQueryHandler(handlers.cb_cc_order, pattern="^cc_order:"))
    app.add_handler(CallbackQueryHandler(handlers.cb_cc_reveal, pattern="^cc_reveal:"))
    
    app.add_handler(CallbackQueryHandler(handlers.cb_mysaldo, pattern="^mysaldo$"))
    app.add_handler(CallbackQueryHandler(handlers.cb_support, pattern="^support$"))

    # ADMIN CALLBACKS
    app.add_handler(CallbackQueryHandler(admin.cb_admin, pattern="^admin$"))
    app.add_handler(CallbackQueryHandler(admin.cb_admin_mystock, pattern="^admin_mystock$"))
    app.add_handler(CallbackQueryHandler(admin.cb_admin_restock_prompt, pattern="^admin_restock:"))
    app.add_handler(CallbackQueryHandler(admin.cb_admin_stats, pattern="^admin_stats$"))
    app.add_handler(CallbackQueryHandler(admin.cb_admin_pre77bal, pattern="^admin_pre77bal$"))
    app.add_handler(CallbackQueryHandler(admin.cb_admin_users, pattern="^admin_users$"))
    app.add_handler(CallbackQueryHandler(admin.cb_admin_orders, pattern="^admin_orders$"))
    app.add_handler(CallbackQueryHandler(admin.cb_admin_pending, pattern="^admin_pending$"))
    app.add_handler(CallbackQueryHandler(admin.cb_admin_deposits, pattern="^admin_deposits$"))
    app.add_handler(CallbackQueryHandler(admin.cmd_clearcache, pattern="^admin_clearcache$"))

    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handlers.on_text))
    app.add_error_handler(handlers.error_handler)


async def main():
    db.init_db()
    api = ShopAPI()

    app = Application.builder().token(config.TELEGRAM_BOT_TOKEN).build()
    app.bot_data["api"] = api

    setup_handlers(app)

    await app.bot.delete_webhook(drop_pending_updates=True)

    if app.job_queue:
        app.job_queue.run_repeating(handlers.job_clear_cache, interval=7200, first=60)
        app.job_queue.run_repeating(handlers.job_daily_backup, interval=86400, first=300)
        app.job_queue.run_repeating(handlers.check_invoice_status_job, interval=60, first=15)

    web_app = web.Application(middlewares=[ip_rate_limit_middleware])
    web_app["ptb_app"] = app
    web_app.router.add_post("/webhook/pre77", pre77_webhook_endpoint)

    PORT = int(os.environ.get("PORT", 10000))
    runner = web.AppRunner(web_app)
    await runner.setup()
    site = web.TCPSite(runner, "0.0.0.0", PORT)
    
    await site.start()

    await app.initialize()
    await app.start()
    await app.updater.start_polling(drop_pending_updates=True)

    await asyncio.Event().wait()


if __name__ == "__main__":
    asyncio.run(main())
