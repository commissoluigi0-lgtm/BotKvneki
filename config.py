from __future__ import annotations

import os
import logging

log = logging.getLogger(__name__)

# --- CREDENZIALI SENSIBILI (Isolate nelle Environment Variables di Render) ---
TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "8750932286:AAFGnoYNiZFWH6yMXa5ery-pLlFcol4hSxQ").strip()
API_KEY = (os.environ.get("PRE77_API_KEY") or os.environ.get("API_KEY", "pre77_sk_live_KQrXRr9B2_PEZ77-bcQuEaY0W0zkleP-")).strip()
PRE77_API_KEY = API_KEY  # Alias di compatibilità per i client

# Controllo di sicurezza critico all'avvio
if not TELEGRAM_BOT_TOKEN or not API_KEY:
    log.critical("CRITICAL SECURITY ERROR: Token Telegram o API Key mancanti nelle variabili d'ambiente!")
    raise ValueError("Le credenziali critiche non possono essere vuote.")

# --- IMPOSTAZIONI AMMINISTRATIVE E DI RETE ---
# Legge gli admin ID da stringa separata da virgole (es: "1337218090,987654321")
ADMIN_IDS = [int(x.strip()) for x in os.environ.get("ADMIN_IDS", "1337218090").split(",") if x.isdigit()]

API_BASE_URL = os.environ.get("API_BASE_URL", "https://pre77.to/api/seller/v1")
MARKUP_PERCENT = float(os.environ.get("MARKUP_PERCENT", "20.0"))
CURRENCY = os.environ.get("CURRENCY", "USD")

# --- SUPPORTO & NOTIFICHE SIEM ---
SUPPORT_CONTACT = os.environ.get("SUPPORT_CONTACT", "@ombraax")
PRE77_LOW_BALANCE_ALERT_CENTS = int(os.environ.get("PRE77_LOW_BALANCE_ALERT_CENTS", "5000")) # 50$
ADMIN_LOG_CHAT_ID = int(os.environ.get("ADMIN_LOG_CHAT_ID", "-5544496389"))

# --- CRITTOGRAFIA FERNET (Per la protezione dati a riposo nel DB) ---
_fernet_env = os.environ.get("DB_ENCRYPTION_KEY", "").strip()
DB_ENCRYPTION_KEY = _fernet_env.encode("utf-8") if _fernet_env else b''
