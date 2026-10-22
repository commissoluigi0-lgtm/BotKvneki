CREATE TABLE IF NOT EXISTS users (
    tg_id         INTEGER PRIMARY KEY,
    username      TEXT,
    first_name    TEXT,
    balance_cents INTEGER NOT NULL DEFAULT 0,
    created_at    TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS transactions (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    tg_id        INTEGER NOT NULL,
    amount_cents INTEGER NOT NULL,
    type         TEXT NOT NULL,
    note         TEXT,
    created_at   TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (tg_id) REFERENCES users(tg_id)
);
CREATE INDEX IF NOT EXISTS idx_tx_user ON transactions(tg_id, id DESC);

CREATE TABLE IF NOT EXISTS orders (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    tg_id              INTEGER NOT NULL,
    pre77_purchase_id  TEXT,
    product_id         TEXT NOT NULL,
    product_title      TEXT,
    quantity           INTEGER NOT NULL,
    client_paid_cents  INTEGER NOT NULL,
    pre77_cost_cents   INTEGER,
    delivery_lines     TEXT,
    status             TEXT NOT NULL DEFAULT 'PENDING',
    created_at         TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (tg_id) REFERENCES users(tg_id)
);
CREATE INDEX IF NOT EXISTS idx_orders_user ON orders(tg_id, id DESC);
