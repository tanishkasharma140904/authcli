-- 0001_init.sql: initial schema for the auth CLI.
-- All timestamps are stored as Unix epoch seconds (UTC).

CREATE TABLE IF NOT EXISTS users (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    username          TEXT    NOT NULL UNIQUE COLLATE NOCASE,
    password_hash     TEXT    NOT NULL,                -- bcrypt hash, never the plaintext
    totp_secret       TEXT,                            -- base32 TOTP secret; NULL when 2FA is off
    totp_enabled      INTEGER NOT NULL DEFAULT 0 CHECK (totp_enabled IN (0, 1)),
    totp_last_counter INTEGER NOT NULL DEFAULT 0,      -- last accepted TOTP time-step (replay protection)
    failed_attempts   INTEGER NOT NULL DEFAULT 0,      -- consecutive failed logins
    locked_until      INTEGER,                         -- account locked until this time, if set
    created_at        INTEGER NOT NULL,
    last_login_at     INTEGER
);

CREATE TABLE IF NOT EXISTS sessions (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    token_hash  TEXT    NOT NULL UNIQUE,               -- SHA-256 of the session token
    user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at  INTEGER NOT NULL,
    expires_at  INTEGER NOT NULL,
    revoked_at  INTEGER                                -- set on logout
);

CREATE INDEX IF NOT EXISTS idx_sessions_user_id    ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);
