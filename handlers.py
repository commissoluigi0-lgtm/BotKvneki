# ==================== SISTEMA DI HOLD & CHECKER ====================

async def cb_cc_hold_and_buy(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    """Esegue l'hold della carta per 30 secondi prima di procedere all'acquisto."""
    if await _check_access(update, ctx):
        return
    q = update.callback_query
    await q.answer()
    cid = q.data.split(":", 1)[1]
    u = update.effective_user
    api = ctx.bot_data["api"]

    c = await _find_card(ctx, cid)
    if not c:
        await q.edit_message_text("Carta non disponibile.", reply_markup=back_menu())
        return

    # Esegue l'hold per 30 secondi
    try:
        hold_res = await api.cc_hold([cid])
        if not hold_res.get("ok", True) and not hold_res.get("held"):
            await q.edit_message_text("⚠️ Impossibile bloccare la carta: potrebbe essere già in hold o venduta.", reply_markup=back_menu())
            return
    except APIError as e:
        await q.edit_message_text(f"❌ Errore durante l'hold: {esc(e.message)}", reply_markup=back_menu())
        return

    total = client_price(_extract_cents(c))
    bal = db.get_balance(u.id)

    if bal < total:
        await q.edit_message_text(f"💸 Saldo insufficiente. Hai {money(bal)}, servono {money(total)}.", parse_mode=ParseMode.HTML, reply_markup=back_menu())
        return

    # Mostra la conferma con il blocco attivo
    keyboard = [
        [InlineKeyboardButton("✅ Conferma Acquisto (Hold attivo)", callback_data=f"cc_buyok:{cid}")],
        [InlineKeyboardButton("🔙 Annulla", callback_data="cc_shop")]
    ]
    await q.edit_message_text(
        f"🔒 <b>Carta bloccata per 30 secondi!</b>\n\n"
        f"BIN: <code>{esc(c.get('bin'))}</code>\n"
        f"Totale: <b>{money(total)}</b>\n\n"
        f"<i>Procedi con la conferma prima che scada l'hold.</i>",
        parse_mode=ParseMode.HTML,
        reply_markup=InlineKeyboardMarkup(keyboard)
    )


async def cb_cc_start_checker(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    """Avvia il checker per un ordine CC completato."""
    if await _check_access(update, ctx):
        return
    q = update.callback_query
    await q.answer()
    
    parts = q.data.split(":")
    oid = int(parts[1]) if len(parts) > 1 else 0
    o = db.get_order(oid)
    
    if not o or o["tg_id"] != update.effective_user.id:
        await q.edit_message_text("Ordine non trovato.", reply_markup=back_menu())
        return

    api = ctx.bot_data["api"]
    try:
        check_res = await api.cc_check(o["pre77_purchase_id"])
        check_id = check_res.get("checkId")
    except APIError as e:
        await q.edit_message_text(f"❌ Errore avvio checker: {esc(e.message)}", reply_markup=cc_order_kb(oid, o["status"]))
        return

    await q.edit_message_text("🔄 <b>Checker avviato...</b> Attendere il responso.", parse_mode=ParseMode.HTML)

    # Polling dello stato del checker (fino a 5 tentativi)
    import asyncio
    status = "PENDING"
    result = "In elaborazione"
    
    for _ in range(5):
        await asyncio.sleep(3)
        try:
            poll_res = await api.cc_get_check(o["pre77_purchase_id"], check_id)
            status = poll_res.get("status", "PENDING")
            result = poll_res.get("result", status)
            if status != "PENDING":
                break
        except Exception:
            pass

    status_icon = "🟢" if status in ("LIVE", "valid") else "🔴"
    await q.edit_message_text(
        f"📊 <b>Risultato Checker #{oid}</b>\n\n"
        f"Stato: {status_icon} <b>{esc(status)}</b>\n"
        f"Dettaglio: <code>{esc(result)}</code>",
        parse_mode=ParseMode.HTML,
        reply_markup=cc_order_kb(oid, o["status"])
    )
