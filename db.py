from __future__ import annotations

import hashlib
import json
import math
import secrets
import sqlite3
import time
import html
from contextlib import contextmanager
from pathlib import Path
import pyotp
from cryptography.fernet import Fernet
import shutil
import os
from datetime import datetime
import config

DB_PATH = Path(__file__).parent / "shop.db"
SCHEMA_PATH = Path(__file__).parent / "schema.sql"

SESSION_TIMEOUT_SECONDS = 900  # 15 Minuti di inattività


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=15.0, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db():
    conn = _connect()
    try:
        conn.executescript(SCHEMA_PATH.read_text())
        # Compatibilità colonne esistenti
        for col_def in [
            ("is_banned", "INTEGER DEFAULT 0"),
            ("is_verified", "INTEGER DEFAULT 0"),
            ("access_key_hash", "TEXT"),
            ("key_salt", "TEXT"),
            ("is_key_active", "INTEGER DEFAULT 0"),
            ("bound_chat_id", "INTEGER DEFAULT NULL"),
            ("last_activity", "REAL DEFAULT 0"),
        ]:
            try:
                conn.execute(f"ALTER TABLE users ADD COLUMN {col_def[0]} {col_def[1]}")
            except sqlite3.OperationalError:
                pass
    finally:
        conn.close()


@contextmanager
def _tx():
    conn = _connect()
    try:
        conn.execute("BEGIN IMMEDIATE")
        yield conn
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise
    finally:
        conn.close()


def esc(v) -> str:
    """Funzione di sanificazione/escape HTML per i dati del database."""
    return html.escape(str(v if v is not None else ""))


def update_last_activity(tg_id: int):
    """Aggiorna il timestamp dell'ultima interazione dell'utente."""
    conn = _connect()
    try:
        conn.execute("UPDATE users SET last_activity = ? WHERE tg_id = ?", (time.time(), tg_id))
        conn.commit()
    finally:
        conn.close()


def check_and_expire_session(tg_id: int) -> bool:
    """
    Controlla se la sessione dell'utente è scaduta per inattività (> 15 min).
    Se scaduta, disattiva la chiave (is_key_active = 0) e restituisce True.
    """
    conn = _connect()
    try:
        row = conn.execute("SELECT last_activity, is_key_active FROM users WHERE tg_id = ?", (tg_id,)).fetchone()
        if not row or not row["is_key_active"]:
            return False

        last_act = row["last_activity"] or 0
        now = time.time()

        if now - last_act > SESSION_TIMEOUT_SECONDS:
            conn.execute("UPDATE users SET is_key_active = 0 WHERE tg_id = ?", (tg_id,))
            conn.commit()
            return True
        return False
    finally:
        conn.close()


def logout_user(tg_id: int):
    """Effettua il logout manuale dell'utente."""
    conn = _connect()
    try:
        conn.execute("UPDATE users SET is_key_active = 0 WHERE tg_id = ?", (tg_id,))
        conn.commit()
    finally:
        conn.close()


def generate_user_key(tg_id: int) -> str:
    """Genera un segreto TOTP univoco (base32) per Google Authenticator."""
    secret = pyotp.random_base32()
    conn = _connect()
    try:
        conn.execute(
            "UPDATE users SET access_key_hash = ?, is_key_active = 0, bound_chat_id = NULL WHERE tg_id = ?",
            (secret, tg_id)
        )
        conn.commit()
    finally:
        conn.close()
    return secret


def verify_user_key(tg_id: int, input_code: str, chat_id: int) -> bool:
    """Verifica il codice TOTP a 6 cifre e vincola la chat/dispositivo."""
    conn = _connect()
    try:
        row = conn.execute("SELECT access_key_hash, bound_chat_id FROM users WHERE tg_id = ?", (tg_id,)).fetchone()
        if not row or not row["access_key_hash"]:
            return False
            
        secret = row["access_key_hash"]
        
        # Scarta le vecchie chiavi esadecimali (64 caratteri) non compatibili con Google Auth
        if len(secret) == 64:
            return False
            
        bound_chat = row["bound_chat_id"]
        
        if bound_chat and bound_chat != chat_id:
            return False
            
        totp = pyotp.TOTP(secret)
        if totp.verify(input_code.strip(), valid_window=1):
            conn.execute(
                "UPDATE users SET is_key_active = 1, bound_chat_id = ?, last_activity = ? WHERE tg_id = ?",
                (chat_id, time.time(), tg_id)
            )
            conn.commit()
            return True
        return False
    finally:
        conn.close()


def check_chat_binding(tg_id: int, chat_id: int) -> bool:
    """Verifica che la sessione appartenga alla stessa chat autorizzata."""
    conn = _connect()
    try:
        row = conn.execute("SELECT bound_chat_id FROM users WHERE tg_id = ? AND is_key_active = 1", (tg_id,)).fetchone()
        if row and row["bound_chat_id"] is not None:
            return row["bound_chat_id"] == chat_id
        return True
    finally:
        conn.close()


def is_key_activated(tg_id: int) -> bool:
    u = get_user(tg_id)
    return bool(u and u.get("is_key_active", 0) == 1)


def ensure_user(tg_id: int, username, first_name):
    conn = _connect()
    try:
        conn.execute(
            "INSERT OR IGNORE INTO users (tg_id, username, first_name, is_banned, is_verified, is_key_active) VALUES (?, ?, ?, 0, 0, 0)",
            (tg_id, username, first_name),
        )
        if username or first_name:
            conn.execute(
                "UPDATE users SET username = COALESCE(?, username), "
                "first_name = COALESCE(?, first_name) WHERE tg_id = ?",
                (username, first_name, tg_id),
            )
    finally:
        conn.close()


def get_user(tg_id: int):
    conn = _connect()
    try:
        row = conn.execute("SELECT * FROM users WHERE tg_id = ?", (tg_id,)).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def is_banned(tg_id: int) -> bool:
    u = get_user(tg_id)
    return bool(u and u.get("is_banned", 0) == 1)


def set_ban(tg_id: int, banned: bool = True) -> bool:
    conn = _connect()
    try:
        cur = conn.execute(
            "UPDATE users SET is_banned = ? WHERE tg_id = ?",
            (1 if banned else 0, tg_id),
        )
        return cur.rowcount > 0
    finally:
        conn.close()


def is_verified(tg_id: int) -> bool:
    u = get_user(tg_id)
    return bool(u and u.get("is_verified", 0) == 1)


def set_verified(tg_id: int, verified: bool = True) -> bool:
    conn = _connect()
    try:
        cur = conn.execute(
            "UPDATE users SET is_verified = ? WHERE tg_id = ?",
            (1 if verified else 0, tg_id),
        )
        return cur.rowcount > 0
    finally:
        conn.close()


def get_balance(tg_id: int) -> int:
    u = get_user(tg_id)
    return u["balance_cents"] if u else 0


def credit(tg_id: int, amount_cents: int, type_: str, note: str = "") -> int:
    if amount_cents <= 0:
        raise ValueError("amount positivo richiesto")
    with _tx() as c:
        c.execute(
            "UPDATE users SET balance_cents = balance_cents + ? WHERE tg_id = ?",
            (amount_cents, tg_id),
        )
        c.execute(
            "INSERT INTO transactions (tg_id, amount_cents, type, note) VALUES (?, ?, ?, ?)",
            (tg_id, amount_cents, type_, note),
        )
        row = c.execute("SELECT balance_cents FROM users WHERE tg_id = ?", (tg_id,)).fetchone()
        return row["balance_cents"]


def try_debit(tg_id: int, amount_cents: int, type_: str, note: str = "") -> bool:
    if amount_cents <= 0:
        raise ValueError("amount positivo richiesto")
    with _tx() as c:
        cur = c.execute(
            "UPDATE users SET balance_cents = balance_cents - ? "
            "WHERE tg_id = ? AND balance_cents >= ?",
            (amount_cents, tg_id, amount_cents),
        )
        if cur.rowcount == 0:
            return False
        c.execute(
            "INSERT INTO transactions (tg_id, amount_cents, type, note) VALUES (?, ?, ?, ?)",
            (tg_id, -amount_cents, type_, note),
        )
        return True


def list_transactions(tg_id: int, limit: int = 15):
    conn = _connect()
    try:
        rows = conn.execute(
            "SELECT * FROM transactions WHERE tg_id = ? ORDER BY id DESC LIMIT ?",
            (tg_id, limit),
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def create_order(tg_id: int, product_id: str, title: str, qty: int,
                 client_paid_cents: int, pre77_cost_cents: int,
                 pre77_purchase_id, delivery_lines, status: str) -> int:
    conn = _connect()
    try:
        cur = conn.execute(
            "INSERT INTO orders (tg_id, pre77_purchase_id, product_id, product_title, "
            "quantity, client_paid_cents, pre77_cost_cents, delivery_lines, status) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (tg_id, pre77_purchase_id, product_id, title, qty,
             client_paid_cents, pre77_cost_cents,
             json.dumps(delivery_lines or [], ensure_ascii=False), status),
        )
        return cur.lastrowid
    finally:
        conn.close()


def update_order_status(order_id: int, status: str, delivery_lines=None) -> bool:
    conn = _connect()
    try:
        if delivery_lines is not None:
            cur = conn.execute(
                "UPDATE orders SET status = ?, delivery_lines = ? WHERE id = ?",
                (status, json.dumps(delivery_lines, ensure_ascii=False), order_id),
            )
        else:
            cur = conn.execute(
                "UPDATE orders SET status = ? WHERE id = ?",
                (status, order_id),
            )
        return cur.rowcount > 0
    finally:
        conn.close()


def list_orders(tg_id: int, limit: int = 20):
    conn = _connect()
    try:
        rows = conn.execute(
            "SELECT * FROM orders WHERE tg_id = ? ORDER BY id DESC LIMIT ?",
            (tg_id, limit),
        ).fetchall()
        return [_row_to_order(r) for r in rows]
    finally:
        conn.close()


def list_pending_orders(limit: int = 30):
    conn = _connect()
    try:
        rows = conn.execute(
            "SELECT * FROM orders WHERE status = 'PENDING' ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [_row_to_order(r) for r in rows]
    finally:
        conn.close()


def get_order(order_id: int):
    conn = _connect()
    try:
        row = conn.execute("SELECT * FROM orders WHERE id = ?", (order_id,)).fetchone()
        return _row_to_order(row) if row else None
    finally:
        conn.close()


def _row_to_order(r):
    d = dict(r)
    try:
        d["delivery_lines"] = json.loads(d["delivery_lines"] or "[]")
    except ValueError:
        d["delivery_lines"] = []
    return d


def global_stats() -> dict:
    conn = _connect()
    try:
        users = conn.execute("SELECT COUNT(*) AS n FROM users").fetchone()["n"]
        orders = conn.execute(
            "SELECT COUNT(*) AS n, "
            "COALESCE(SUM(client_paid_cents),0) AS revenue, "
            "COALESCE(SUM(pre77_cost_cents),0) AS cost "
            "FROM orders WHERE status = 'COMPLETED'"
        ).fetchone()
        deposits = conn.execute(
            "SELECT COALESCE(SUM(amount_cents),0) AS total FROM transactions "
            "WHERE type = 'TOPUP'"
        ).fetchone()["total"]
        liabilities = conn.execute(
            "SELECT COALESCE(SUM(balance_cents),0) AS total FROM users"
        ).fetchone()["total"]
        pending = conn.execute(
            "SELECT COUNT(*) AS n FROM orders WHERE status = 'PENDING'"
        ).fetchone()["n"]
        return {
            "users": users,
            "orders": orders["n"],
            "revenue_cents": orders["revenue"],
            "cost_cents": orders["cost"],
            "margin_cents": orders["revenue"] - orders["cost"],
            "topups_cents": deposits,
            "liabilities_cents": liabilities,
            "pending": pending,
        }
    finally:
        conn.close()


def check_login_lock(tg_id: int) -> int:
    """Restituisce i secondi rimanenti di blocco se l'utente è sospeso, altrimenti 0."""
    conn = _connect()
    try:
        row = conn.execute("SELECT lock_until FROM login_attempts WHERE tg_id = ?", (tg_id,)).fetchone()
        if row and row["lock_until"]:
            remaining = row["lock_until"] - time.time()
            if remaining > 0:
                return int(remaining)
        return 0
    finally:
        conn.close()


def record_failed_login(tg_id: int) -> bool:
    """Registra un tentativo fallito. Ritorna True se l'utente viene bloccato (>= 3 tentativi)."""
    conn = _connect()
    try:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS login_attempts (
                tg_id INTEGER PRIMARY KEY,
                attempts INTEGER DEFAULT 0,
                lock_until REAL DEFAULT 0
            )
        """)
        row = conn.execute("SELECT attempts, lock_until FROM login_attempts WHERE tg_id = ?", (tg_id,)).fetchone()
        now = time.time()
        
        attempts = (row["attempts"] + 1) if row else 1
        if attempts >= 3:
            lock_until = now + 300
            conn.execute("INSERT OR REPLACE INTO login_attempts (tg_id, attempts, lock_until) VALUES (?, ?, ?)", (tg_id, attempts, lock_until))
            conn.commit()
            return True
        else:
            conn.execute("INSERT OR REPLACE INTO login_attempts (tg_id, attempts, lock_until) VALUES (?, ?, 0)", (tg_id, attempts))
            conn.commit()
            return False
    finally:
        conn.close()


def clear_failed_logins(tg_id: int):
    """Pulisce i tentativi errati dopo un login riuscito."""
    conn = _connect()
    try:
        conn.execute("DELETE FROM login_attempts WHERE tg_id = ?", (tg_id,))
        conn.commit()
    finally:
        conn.close()


def _get_cipher():
    key = getattr(config, "DB_ENCRYPTION_KEY", None)
    if not key:
        key = Fernet.generate_key()
    return Fernet(key)


def encrypt_data(plain_text: str | None) -> str | None:
    """Cifra una stringa in chiaro prima di salvarla nel DB."""
    if not plain_text:
        return plain_text
    cipher = _get_cipher()
    return cipher.encrypt(plain_text.encode("utf-8")).decode("utf-8")


def decrypt_data(encrypted_text: str | None) -> str | None:
    """Decifra una stringa cifrata letta dal DB."""
    if not encrypted_text:
        return encrypted_text
    try:
        cipher = _get_cipher()
        return cipher.decrypt(encrypted_text.encode("utf-8")).decode("utf-8")
    except Exception:
        return encrypted_text


def get_session_remaining_minutes(tg_id: int) -> int:
    """Restituisce i minuti interi rimanenti prima della scadenza della sessione (15 min)."""
    conn = _connect()
    try:
        row = conn.execute("SELECT last_activity, is_key_active FROM users WHERE tg_id = ?", (tg_id,)).fetchone()
        if not row or not row["is_key_active"]:
            return 0

        last_act = row["last_activity"] or 0
        now = time.time()
        elapsed = now - last_act
        remaining_seconds = SESSION_TIMEOUT_SECONDS - elapsed

        if remaining_seconds <= 0:
            return 0
        
        return int(math.ceil(remaining_seconds / 60))
    finally:
        conn.close()


def get_all_users(limit: int = 50) -> list[dict]:
    """Recupera la lista degli utenti registrati per il pannello admin."""
    conn = _connect()
    try:
        rows = conn.execute(
            "SELECT tg_id, username, first_name, balance_cents, is_banned, is_verified, is_key_active, last_activity "
            "FROM users ORDER BY tg_id DESC LIMIT ?",
            (limit,)
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def wipe_database(admin_pin: str, expected_pin: str) -> bool:
    """
    Svuota completamente la tabella degli utenti e delle transazioni/ordini 
    previa verifica di un PIN crittografico o chiave admin.
    """
    if admin_pin != expected_pin:
        return False
        
    conn = _connect()
    try:
        conn.execute("BEGIN IMMEDIATE")
        conn.execute("DELETE FROM orders")
        conn.execute("DELETE FROM transactions")
        conn.execute("DELETE FROM login_attempts")
        conn.execute("DELETE FROM users")
        conn.execute("COMMIT")
        return True
    except Exception:
        conn.execute("ROLLBACK")
        raise
    finally:
        conn.close()


def backup_database(backup_dir: str = "backups") -> str:
    """Crea una copia di backup del database SQLite (`shop.db`)."""
    os.makedirs(backup_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_path = os.path.join(backup_dir, f"bot_backup_{timestamp}.db")
    
    if os.path.exists(DB_PATH):
        shutil.copy2(DB_PATH, backup_path)
        return backup_path
    return ""