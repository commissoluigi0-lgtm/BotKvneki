from telegram import InlineKeyboardButton, InlineKeyboardMarkup

def client_menu():
    keyboard = [
        [InlineKeyboardButton("🛍 CC Shop", callback_data="cc_shop:1")],
        [InlineKeyboardButton("🛒 Carrello", callback_data="cc_view_cart"), InlineKeyboardButton("💰 Saldo", callback_data="mysaldo")],
        [InlineKeyboardButton("📦 Ordini", callback_data="myorders"), InlineKeyboardButton("🛠 Supporto", callback_data="support")]
    ]
    return InlineKeyboardMarkup(keyboard)

def back_menu():
    return InlineKeyboardMarkup([[InlineKeyboardButton("🏠 Menu Principale", callback_data="menu")]])

def cc_catalog_kb(rows: list, current_page: int, has_prev: bool, has_next: bool, price_calculator_fn):
    keyboard = []
    for item in rows:
        card_id = str(item.get("id") or "0")
        bin_val = str(item.get("bin") or "000000")
        country = str(item.get("countryCode") or "US")
        vendor = str(item.get("vendor") or "VISA")
        base_name = str(item.get("baseName") or item.get("type") or "Base")
        
        # Prezzo in USD diretto (es. priceUsd = 7 -> $7.00)
        raw_price = item.get("priceUsd") or item.get("price") or 7
        try:
            price_val = float(raw_price)
        except (TypeError, ValueError):
            price_val = 7.0
            
        # Markup del 20%
        final_price = price_val * 1.20
        price_formatted = f"${final_price:.2f}"
        
        # Etichetta pulita con Seller Kvneki forzato
        label = f"💳 {bin_val} | {country} {vendor} | {base_name[:18]} | {price_formatted} | Kvneki"
        
        # Inviamo l'ID carta pulito
        keyboard.append([InlineKeyboardButton(label, callback_data=f"cc_prod:{card_id}")])

    nav_row = []
    if has_prev:
        nav_row.append(InlineKeyboardButton("⬅️ Indietro", callback_data=f"cc_shop:{current_page - 1}"))
    if has_next:
        nav_row.append(InlineKeyboardButton("Avanti ➡️", callback_data=f"cc_shop:{current_page + 1}"))
    if nav_row:
        keyboard.append(nav_row)

    keyboard.append([InlineKeyboardButton("🔍 Cerca BIN", callback_data="cc_search")])
    keyboard.append([InlineKeyboardButton("🏠 Menu Principale", callback_data="menu")])
    return InlineKeyboardMarkup(keyboard)

def cc_orders_kb(orders: list):
    keyboard = []
    for o in orders:
        keyboard.append([InlineKeyboardButton(f"🧾 Ordine #{o['id']} ({o['status']})", callback_data=f"cc_order:{o['id']}")])
    keyboard.append([InlineKeyboardButton("🏠 Menu", callback_data="menu")])
    return InlineKeyboardMarkup(keyboard)

def cc_order_kb(oid: int, status: str):
    keyboard = [
        [InlineKeyboardButton("👁 Rivelare Dati", callback_data=f"cc_reveal:{oid}")],
        [InlineKeyboardButton("🔙 I Miei Ordini", callback_data="myorders")]
    ]
    return InlineKeyboardMarkup(keyboard)
