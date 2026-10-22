from __future__ import annotations

import logging
import time
import os
from aiohttp import web
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
    """Middleware aiohttp per bloccare richieste eccessive dallo stesso IP."""
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
    
    window = 10.0
    max_requests = 40
    
    history[:] = [t for t in history if now - t < window]
    
    if len(history) >= max_requests:
        log.warning("SIEM SECURITY ALERT | Rate limit IP superato da: %s (%d req/10s)", client_ip, len(history))
        return web.json_response(
            {"error": "Too many requests. Slow down."}, 
            status=429,
            headers={"Retry-After": "10"}
        )
        
    history.append(now)
    return await handler(request)


async def pre77_webhook_endpoint(request: web.Request) -> web.Response:
    """Riceve, verifica la firma HMAC e smista le chiamate Webhook in arrivo dai server."""
    try:
        body_bytes = await request.read()
        sig_header = request.headers.get("X-Pre77-Signature", "")
        
        secret = getattr(config, "PRE77_WEBHOOK_SECRET", "")
        if secret and not handlers.verify_pre77_signature(body_bytes, sig_header, secret):
            log.warning("SIEM SECURITY | Tentativo di accesso Webhook con firma non valida.")
            return web.json_response({"error": "Invalid signature"}, status=401)

        data = await request.json()
        context = request.app.get("bot_context")
        
        if context:
            await handlers.handle_pre77_webhook(data, context)
            
        return web.json_response({"ok": True})
    except Exception as e:
        log.error("Errore elaborazione webhook: %s", e)
        return web.json_response({"error": str(e)}, status=400)


async def post_init(app: Application):
    await app.bot.delete_webhook(drop_pending_updates=True)
    db.init_db()
    api = ShopAPI()
    app.bot_data["api"] = api
    
    # --- AGGANCIO SICURO AIOHTTP (MIDDLEWARE & ROUTE PRE77) ---
    web_app = app.bot_data.get("web_app")
    if web_app:
        web_app.middlewares.append(ip_rate_limit_middleware)
        web_app["bot_context"] = app
        web_app.router.add_post("/webhook/pre77", pre77_webhook_endpoint)
        log.info("Middleware anti-DDoS e rotta Webhook /webhook/pre77 registrati con successo su aiohttp.")

    RENDER_URL = os.environ.get("RENDER_EXTERNAL_URL") or "https://botkvneki.onrender.com"
    if RENDER_URL:
        wh_url = f"{RENDER_URL}/webhook/pre77"
        try:
            await api.set_webhook(wh_url)
            log.info("Webhook registrato con successo: %s", wh_url)
        except Exception as e:
            log.error("Impossibile registrare Webhook: %s", e)

    log.info("Bot avviato in modalità Webhook · Markup +%.1f%%", config.MARKUP_PERCENT)


async def post_shutdown(app: Application):
    api = app.bot_data.get("api")
    if api:
        await api.close()


def main():
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
        app.job_queue.run_repeating(handlers.job_clear_cache, interval=7200, first=60)
        app.job_queue.run_repeating(handlers.job_daily_backup, interval=86400, first=300)
        app.job_queue.run_repeating(handlers.check_invoice_status_job, interval=60, first=15)

    # comandi base e admin
    app.add_handler(CommandHandler("start", handlers.cmd_start))
    app.add_handler(CommandHandler("help", handlers.cmd_help))
    app.add_handler(CommandHandler("id", admin.cmd_id))
    app.add_handler(CommandHandler("bin", handlers.cmd_bin_lookup))

    app.add_handler(CommandHandler("admin", admin.cmd_admin))
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

    # callback cliente & carrello / ricarica dinamica
    app.add_handler(CallbackQueryHandler(handlers.cb_menu, pattern=r"^menu$"))
    app.add_handler(CallbackQueryHandler(handlers.cb_help, pattern=r"^help$"))
    app.add_handler(CallbackQueryHandler(handlers.cb_cc, pattern=r"^cc_shop$"))
    app.add_handler(CallbackQueryHandler(handlers.cb_cc, pattern=r"^cc_page:\d+$"))
    app.add_handler(CallbackQueryHandler(handlers.cb_cc_search, pattern=r"^cc_search$"))
    app.add_handler(CallbackQueryHandler(handlers.cb_cc_filter, pattern=r"^cc_filter$"))
    app.add_handler(CallbackQueryHandler(handlers.cb_ccfilt, pattern=r"^ccfilt:"))
    
    app.add_handler(CallbackQueryHandler(handlers.cb_cc_product, pattern=r"^cc_card:"))
    app.add_handler(CallbackQueryHandler(handlers.cb_cc_hold_and_buy, pattern=r"^cc_hold:"))
    app.add_handler(CallbackQueryHandler(handlers.cb_cc_buy_confirm, pattern=r"^cc_buyok:"))
    
    # Carrello e Checkout multiplo
    app.add_handler(CallbackQueryHandler(handlers.cb_cc_add_cart, pattern=r"^cc_cart_add:"))
    app.add_handler(CallbackQueryHandler(handlers.cb_cc_view_cart, pattern=r"^cc_view_cart$"))
    app.add_handler(CallbackQueryHandler(handlers.cb_cc_remove_cart, pattern=r"^cc_cart_del:"))
    app.add_handler(CallbackQueryHandler(handlers.cb_cc_checkout_exec, pattern=r"^cc_checkout_exec$"))
    app.add_handler(CallbackQueryHandler(handlers.cb_cc_export_txt, pattern=r"^cc_export_txt$"))
    
    app.add_handler(CallbackQueryHandler(handlers.cb_cc_orders, pattern=r"^myorders$"))
    app.add_handler(CallbackQueryHandler(handlers.cb_cc_order, pattern=r"^cc_order:"))
    app.add_handler(CallbackQueryHandler(handlers.cb_cc_reveal, pattern=r"^cc_reveal:"))
    app.add_handler(CallbackQueryHandler(handlers.cb_cc_start_checker, pattern=r"^cc_check:"))
    
    # Handler per Rimborso Guidato
    app.add_handler(CallbackQueryHandler(handlers.cb_cc_refund_menu, pattern=r"^cc_ref_menu:\d+$"))
    app.add_handler(CallbackQueryHandler(handlers.cb_cc_refund_exec, pattern=r"^cc_ref_exec:\d+:(.+)"))
    
    app.add_handler(CallbackQueryHandler(handlers.cb_mysaldo, pattern=r"^mysaldo$"))
    app.add_handler(CallbackQueryHandler(handlers.cb_topup, pattern=r"^topup$"))
    app.add_handler(CallbackQueryHandler(handlers.cb_topup_asset, pattern=r"^topup_asset:"))
    app.add_handler(CallbackQueryHandler(handlers.cb_support, pattern=r"^support$"))
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
    app.add_handler(CallbackQueryHandler(admin.cb_admin_users, pattern=r"^admin_users_list$"))

    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handlers.on_text))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, admin.on_delivery_text, block=False))
    
    app.add_error_handler(handlers.error_handler)

    PORT = int(os.environ.get("PORT", 10000))
    RENDER_URL = os.environ.get("RENDER_EXTERNAL_URL") or "https://botkvneki.onrender.com"

    webhook_url = f"{RENDER_URL}/{config.TELEGRAM_BOT_TOKEN}"
    log.info("Avvio del server Webhook sulla porta %s con URL: %s", PORT, webhook_url)

    # Avvio pulito compatibile al 100% con python-telegram-bot v22.5
    app.run_webhook(
        listen="0.0.0.0",
        port=PORT,
        url_path=config.TELEGRAM_BOT_TOKEN,
        webhook_url=webhook_url,
        allowed_updates=["message", "callback_query"],
        drop_pending_updates=True,
    )


if __name__ == "__main__":
    main()
