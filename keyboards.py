from telegram import InlineKeyboardButton, InlineKeyboardMarkup

def main_menu():
    return InlineKeyboardMarkup([
        # Sezione principale in evidenza
        [InlineKeyboardButton("🛍️ Shop CC & Cataloghi", callback_data="cc_shop")],
        
        # Sezione utente affiancata (Saldo e Storico ordini)
        [
            InlineKeyboardButton("💰 Il mio Saldo", callback_data="mysaldo"),
            InlineKeyboardButton("📦 I Miei Ordini", callback_data="myorders")
        ],
        
        # Supporto e informazioni
        [
            InlineKeyboardButton("💳 Ricarica", callback_data="topup"),
            InlineKeyboardButton("🎧 Supporto", callback_data="support")
        ],
        [InlineKeyboardButton("❓ Aiuto & Info", callback_data="help")],
    ])

def client_menu():
    return main_menu()
# ==================== CC SHOP KEYBOARDS (MODERN REDESIGN) ====================

def cc_catalog_kb(rows, page, has_prev, has_next, client_price_fn):
    kb = []
    for row in rows:
        card_id = row.get("id")
        bin_val = row.get("bin", "N/A")
        
        # L'API restituisce il prezzo in dollari decimali in 'priceUsd' (es. 2.01)
        raw_usd = (
            row.get("priceUsd")
            or row.get("price")
            or 0.0
        )
        
        try:
            usd_val = float(raw_usd)
        except (TypeError, ValueError):
            usd_val = 0.0
            
        # Convertiamo i dollari in centesimi per darli in pasto a client_price_fn che applica il markup (+20%)
        cents = int(round(usd_val * 100))
        price = client_price_fn(cents) / 100
        
        country = row.get("countryCode", row.get("country", "??"))
        vendor = row.get("vendor", "CC")
        
        label = f"💳 {vendor.upper()} · {bin_val} ({country}) · ${price:.2f}"
        kb.append([InlineKeyboardButton(label, callback_data=f"cc_card:{card_id}")])
    
    nav = []
    if has_prev:
        nav.append(InlineKeyboardButton("⬅️ Indietro", callback_data=f"cc_page:{page-1}"))
    nav.append(InlineKeyboardButton(f"📄 Pag. {page}", callback_data="cc_noop"))
    if has_next:
        nav.append(InlineKeyboardButton("Avanti ➡️", callback_data=f"cc_page:{page+1}"))
    if nav:
        kb.append(nav)
        
    kb.append([
        InlineKeyboardButton("🔍 Cerca", callback_data="cc_search"),
        InlineKeyboardButton("⚙️ Filtri", callback_data="cc_filter"),
        InlineKeyboardButton("🛒 Carrello", callback_data="cc_cart")
    ])
    kb.append([InlineKeyboardButton("🏠 Menu Principale", callback_data="menu")])
    
    return InlineKeyboardMarkup(kb)
def cc_product_kb(card_id: str):
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("🛒 Acquista Immediatamente", callback_data=f"cc_buy:{card_id}")],
        [InlineKeyboardButton("⬅️ Torna al Catalogo", callback_data="cc_page:1")],
    ])

def cc_buy_confirm_kb(card_id: str):
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("✅ Conferma e Paga", callback_data=f"cc_buyok:{card_id}")],
        [InlineKeyboardButton("❌ Annulla", callback_data=f"cc_card:{card_id}")],
    ])

def cc_filters_kb(f):
    refund_status = "✅ Sì" if f.get("refund_allowed") else "❌ No / Tutti"
    price_label = f.get('price_label', 'Tutti i prezzi')
    
    return InlineKeyboardMarkup([
        [InlineKeyboardButton(f"🔄 Rimborso Garantito: {refund_status}", callback_data="ccfilt:refund")],
        [InlineKeyboardButton(f"💵 Filtro Prezzo: {price_label}", callback_data="ccfilt:price")],
        [InlineKeyboardButton("🔄 Reset Tutti i Filtri", callback_data="ccfilt:reset")],
        [InlineKeyboardButton("🔍 Applica e Cerca", callback_data="cc_search")],
        [InlineKeyboardButton("⬅️ Torna al Catalogo", callback_data="cc_page:1")],
    ])

def cc_cart_kb(items):
    kb = []
    for item in items:
        card_id = item.get("id")
        bin_val = item.get("bin", "")
        price = item.get("priceCents", 0) / 100
        kb.append([
            InlineKeyboardButton(f"🗑 Rimuovi {bin_val} (${price:.2f})", callback_data=f"cc_cart_del:{card_id}")
        ])
    
    if items:
        kb.append([InlineKeyboardButton("💳 Procedi al Checkout", callback_data="cc_checkout")])
    
    kb.append([InlineKeyboardButton("⬅️ Torna al Catalogo", callback_data="cc_page:1")])
    return InlineKeyboardMarkup(kb)

def cc_orders_kb(purchases):
    rows = []
    for p in purchases:
        pid = p.get("id", "")
        title = p.get("product_title", "Carta")
        rows.append([InlineKeyboardButton(f"💳 {title} (#{pid})", callback_data=f"cc_order:{pid}")])
    rows.append([InlineKeyboardButton("🏠 Menu Principale", callback_data="menu")])
    return InlineKeyboardMarkup(rows)

def cc_order_kb(oid, status):
    kb = []
    if status == "COMPLETED":
        kb.append([InlineKeyboardButton("👁 Rivela Dati Carta", callback_data=f"cc_reveal:{oid}")])
        kb.append([InlineKeyboardButton("🔄 Richiedi Rimborso", callback_data=f"cc_refund:{oid}")])
    kb.append([InlineKeyboardButton("📦 I Miei Ordini", callback_data="myorders")])
    kb.append([InlineKeyboardButton("🏠 Menu Principale", callback_data="menu")])
    return InlineKeyboardMarkup(kb)

def back_menu():
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("⬅️ Menu Principale", callback_data="menu")]
    ])

def admin_menu():
    return InlineKeyboardMarkup([
        [
            InlineKeyboardButton("📊 /stats", callback_data="admin_stats"),
            InlineKeyboardButton("💵 /pre77balance", callback_data="admin_pre77bal")
        ],
        [
            InlineKeyboardButton("👥 /userinfo", callback_data="admin_users"),
            InlineKeyboardButton("🧾 /orders", callback_data="admin_orders")
        ],
        [
            InlineKeyboardButton("⏳ /pending", callback_data="admin_pending"),
            InlineKeyboardButton("🧹 /clearcache", callback_data="admin_clearcache")
        ],
        [
            InlineKeyboardButton("🏠 Menu Principale", callback_data="menu")
        ],
    ])
def back_admin():
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("⬅️ Pannello Admin", callback_data="admin")]
    ])
def cc_filter_vendor_kb():
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("💳 VISA", callback_data="ccfilt:set_vendor:VISA"),
         InlineKeyboardButton("💳 MASTERCARD", callback_data="ccfilt:set_vendor:MASTERCARD")],
        [InlineKeyboardButton("💳 AMEX", callback_data="ccfilt:set_vendor:AMEX"),
         InlineKeyboardButton("🔄 Tutti i Brand", callback_data="ccfilt:set_vendor:Tutti")],
        [InlineKeyboardButton("⬅️ Indietro", callback_data="cc_filter")],
    ])

def cc_filter_country_kb():
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("🇺🇸 US", callback_data="ccfilt:set_country:US"),
         InlineKeyboardButton("🇬🇧 UK", callback_data="ccfilt:set_country:UK"),
         InlineKeyboardButton("🇨🇦 CA", callback_data="ccfilt:set_country:CA")],
        [InlineKeyboardButton("🇪🇺 EU / Altri", callback_data="ccfilt:set_country:EU"),
         InlineKeyboardButton("🔄 Tutti i Paesi", callback_data="ccfilt:set_country:Tutti")],
        [InlineKeyboardButton("⬅️ Indietro", callback_data="cc_filter")],
    ])

def cc_filter_type_kb():
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("🟢 Credit", callback_data="ccfilt:set_type:CREDIT"),
         InlineKeyboardButton("🔵 Debit", callback_data="ccfilt:set_type:DEBIT")],
        [InlineKeyboardButton("🔄 Entrambi", callback_data="ccfilt:set_type:Tutti")],
        [InlineKeyboardButton("⬅️ Indietro", callback_data="cc_filter")],
    ])