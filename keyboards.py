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
        card_id = str(item.get("id") or item.get("cardId") or "0")
        bin_val = str(item.get("bin") or item.get("bin_code") or item.get("prefix") or "414720")
        vendor = str(item.get("vendor") or item.get("brand") or "Visa")
        country = str(item.get("country") or "US")
        base_type = str(item.get("base") or item.get("type") or item.get("base_type") or "HQ Base")
        
        raw_cents = item.get("priceCents") or item.get("price_cents") or item.get("price") or 201
        try:
            raw_cents = int(float(raw_cents))
        except (TypeError, ValueError):
            raw_cents = 201
            
        final_sell_cents = price_calculator_fn(raw_cents)
        price_formatted = f"${final_sell_cents / 100:.2f}"
        
        # ETICHETTA BOTTONE CON DATA E SELLER KVNEKI
        label = f"💳 {bin_val} | {country} {vendor} | {base_type} | {price_formatted} | Kvneki"
        
        # FORMATO PULITO E COMPATTO PER ENTRARE NEI 64 BYTE DI TELEGRAM
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
