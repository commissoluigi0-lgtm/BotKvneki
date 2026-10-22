from __future__ import annotations

import logging
import time
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


async def post_init(app: Application):
    # Rimuove webhook precedenti o sessioni appese su Telegram
    await app.bot.delete_webhook(drop_pending_updates=True)
    db.init_db()
    app.bot_data["api"] = ShopAPI()
    log.info("Bot avviato · Markup +%.1f%%", config.MARKUP_PERCENT)


async def post_shutdown(app: Application):
    api = app.bot_data.get("api")
    if api:
        await api.close()


def main():
    # Piccola pausa di sicurezza per permettere a Render di ripulire le vecchie socket di rete
    time.sleep(3)

    app = (
        Application.builder()
        .token(config.TELEGRAM_BOT_TOKEN)
        .post_init(post_init)
        .post_shutdown(post_shutdown)
        .build()
    )

    # --- ATTIVAZIONE JOB AUTOMATICI ---
    if app.job_queue:
        # Pulisce la cache automaticamente ogni 2 ore (7200 secondi)
        app.job_queue.run_repeating(handlers.job_clear_cache, interval=7200, first=60)
        
        # Esegue il backup del DB ogni 24 ore (86400 secondi)
        app.job_queue.run_repeating(handlers.job_daily_backup, interval=86400, first=300)
        
        # Controllo automatico dello stato delle invoice di ricarica ogni 60 secondi
        app.job_queue.run_repeating(handlers.check_invoice_status_job, interval=60, first=15)

    # comandi base
    app.add_handler(CommandHandler("start", handlers.cmd_start))
    app.add_handler(CommandHandler("help", handlers.cmd_help))
    app.add_handler(CommandHandler("id", admin.cmd_id))
    app.add_handler(CommandHandler("bin", handlers.cmd_bin_lookup))

    # comandi admin
    app.add_handler(CommandHandler("admin", admin.cmd_admin))
    app.add_handler(CommandHandler("addbalance", admin.cmd_addbalance))
    app.add_handler(CommandHandler("subbalance", admin.cmd_subbalance))
    app.add_handler(CommandHandler("userinfo", admin.cmd_userinfo))
    app.add_handler(CommandHandler("deposits", admin.cmd_deposits))
    app.add_handler(CommandHandler("setkey", admin.cmd_setkey))
    
    # Comandi Admin aggiunti (Lista utenti, pulizia database e status bot)
    app.add_handler(CommandHandler("users", admin.cmd_admin_users))
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

    # callback cliente
    app.add_handler(CallbackQueryHandler(handlers.cb_menu, pattern=r"^menu$"))
    app.add_handler(CallbackQueryHandler(handlers.cb_help, pattern=r"^help$"))
    app.add_handler(CallbackQueryHandler(handlers.cb_cc, pattern=r"^cc_shop$"))
    
    # CC Shop navigazione e filtri
    app.add_handler(CallbackQueryHandler(handlers.cb_cc, pattern=r"^cc_page:\d+$"))
    app.add_handler(CallbackQueryHandler(handlers.cb_cc_search, pattern=r"^cc_search$"))
    app.add_handler(CallbackQueryHandler(handlers.cb_cc_filter, pattern=r"^cc_filter$"))
    app.add_handler(CallbackQueryHandler(handlers.cb_ccfilt, pattern=r"^ccfilt:"))
    
    # Gestione prodotto e acquisto CC
    app.add_handler(CallbackQueryHandler(handlers.cb_cc_product, pattern=r"^cc_card:"))
    app.add_handler(CallbackQueryHandler(handlers.cb_cc_buy, pattern=r"^cc_buy:"))
    app.add_handler(CallbackQueryHandler(handlers.cb_cc_buy_confirm, pattern=r"^cc_buyok:"))
    
    # Ordini e azioni utente
    app.add_handler(CallbackQueryHandler(handlers.cb_cc_orders, pattern=r"^myorders$"))
    app.add_handler(CallbackQueryHandler(handlers.cb_cc_order, pattern=r"^cc_order:"))
    app.add_handler(CallbackQueryHandler(handlers.cb_cc_reveal, pattern=r"^cc_reveal:"))
    app.add_handler(CallbackQueryHandler(handlers.cb_cc_refund, pattern=r"^cc_refund:"))
    
    app.add_handler(CallbackQueryHandler(handlers.cb_mysaldo, pattern=r"^mysaldo$"))
    app.add_handler(CallbackQueryHandler(handlers.cb_topup, pattern=r"^topup$"))
    app.add_handler(CallbackQueryHandler(handlers.cb_support, pattern=r"^support$"))

    # Callback per il Logout Manuale (Sicurezza 2FA & Session Binding)
    app.add_handler(CallbackQueryHandler(handlers.cb_logout, pattern=r"^auth_logout$"))

    # callback admin
    app.add_handler(CallbackQueryHandler(admin.cb_admin, pattern=r"^admin$"))
    app.add_handler(CallbackQueryHandler(admin.cb_admin_stats, pattern=r"^admin_stats$"))
    app.add_handler(CallbackQueryHandler(admin.cb_admin_pre77bal, pattern=r"^admin_pre77bal$"))
    app.add_handler(CallbackQueryHandler(admin.cb_admin_users, pattern=r"^admin_users$"))
    app.add_handler(CallbackQueryHandler(admin.cb_admin_orders, pattern=r"^admin_orders$"))
    app.add_handler(CallbackQueryHandler(admin.cb_admin_pending, pattern=r"^admin_pending$"))
    app.add_handler(CallbackQueryHandler(admin.cb_admin_deposits, pattern=r"^admin_deposits$"))
    app.add_handler(CallbackQueryHandler(admin.cmd_clearcache, pattern=r"^admin_clearcache$"))
    
    # Callback inline per la lista utenti admin
    app.add_handler(CallbackQueryHandler(admin.cb_admin_users, pattern=r"^admin_users_list$"))

    # testo libero (ricerca + consegna admin)
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handlers.on_text))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, admin.on_delivery_text, block=False))
    
    app.add_error_handler(handlers.error_handler)

    log.info("Polling...")
    app.run_polling(allowed_updates=["message", "callback_query"], drop_pending_updates=True)


if __name__ == "__main__":
    main()
