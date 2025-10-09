CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    totp_secret TEXT,
    is_2fa_enabled BOOLEAN DEFAULT 0,
    is_admin BOOLEAN DEFAULT 0,
    is_protected BOOLEAN DEFAULT 0
);
