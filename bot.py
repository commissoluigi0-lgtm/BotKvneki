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

def setup_handlers(app: Application):
    # COMANDI DI TESTO UTENTE
    app.add_handler(CommandHandler("start", handlers.cmd_start))
    app.add_handler(CommandHandler("help", handlers.cmd_help))
    app.add_handler(CommandHandler("bin", handlers.cmd_bin_lookup))

    # COMANDI ADMIN
    app.add_handler(CommandHandler("admin", admin.cmd_admin))
    app.add_handler(CommandHandler("mystock", admin.cmd_mystock))
    app.add_handler(CommandHandler("addbalance", admin.cmd_addbalance))
    app.add_handler(CommandHandler("subbalance", admin.cmd_subbalance))
    app.add_handler(CommandHandler("userinfo", admin.cmd_userinfo))
    app.add_handler(CommandHandler("deposits", admin.cmd_deposits))
    app.add_handler(CommandHandler("setkey", admin.cmd_setkey))
    app.add_handler(CommandHandler("db_wipe", admin.cmd_db_wipe))
    app.add_handler(CommandHandler("statusbot", admin.cmd_statusbot))
    app.add_handler(CommandHandler("ban", admin.cmd_ban))
    app.add_handler(CommandHandler("unban", admin.cmd_unban))
    app.add_handler(CommandHandler("stats", admin.cmd_stats))
    app.add_handler(CommandHandler("pre77balance", admin.cmd_pre77balance))
    app.add_handler(CommandHandler("pending", admin.cmd_pending))
    app.add_handler(CommandHandler("deliver", admin.cmd_deliver))
    app.add_handler(CommandHandler("refund", admin.cmd_refund))
    app.add_handler(CommandHandler("clearcache", handlers.cmd_clearcache if hasattr(handlers, 'cmd_clearcache') else admin.cmd_clearcache))
    app.add_handler(CommandHandler("broadcast", admin.cmd_broadcast))

    # CALLBACK QUERY ROUTING (CC SHOP & MENU)
    app.add_handler(CallbackQueryHandler(handlers.cb_menu, pattern="^menu$"))
    app.add_handler(CallbackQueryHandler(handlers.cb_help, pattern="^help$"))
    
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
    app.add_handler(CallbackQueryHandler(admin.cb_admin_stats, pattern="^admin_stats$"))
    app.add_handler(CallbackQueryHandler(admin.cb_admin_pre77bal, pattern="^admin_pre77bal$"))
    app.add_handler(CallbackQueryHandler(admin.cb_admin_users, pattern="^admin_users$"))
    app.add_handler(CallbackQueryHandler(admin.cb_admin_orders, pattern="^admin_orders$"))
    app.add_handler(CallbackQueryHandler(admin.cb_admin_pending, pattern="^admin_pending$"))
    app.add_handler(CallbackQueryHandler(admin.cb_admin_deposits, pattern="^admin_deposits$"))

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
        app.job_queue.run_repeating(handlers.job_clear_cache if hasattr(handlers, 'job_clear_cache') else lambda c: None, interval=7200, first=60)
        app.job_queue.run_repeating(handlers.job_daily_backup if hasattr(handlers, 'job_daily_backup') else lambda c: None, interval=86400, first=300)
        app.job_queue.run_repeating(handlers.check_invoice_status_job if hasattr(handlers, 'check_invoice_status_job') else lambda c: None, interval=60, first=15)

    await app.initialize()
    await app.start()
    await app.updater.start_polling(drop_pending_updates=True)

    log.info("Bot Telegram avviato con successo in Long Polling!")
    await asyncio.Event().wait()


if __name__ == "__main__":
    asyncio.run(main())
