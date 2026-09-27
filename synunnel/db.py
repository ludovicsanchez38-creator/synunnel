"""SQLite : source de vérité des comptes et des routes."""

import sqlite3
from datetime import UTC, datetime
from pathlib import Path

from flask import current_app, g

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('pending', 'approved')),
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS blocked_emails (
    email TEXT PRIMARY KEY,
    blocked_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS domains (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS records (
    id INTEGER PRIMARY KEY,
    domain_id INTEGER NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    type TEXT NOT NULL,
    content TEXT NOT NULL,
    ttl INTEGER NOT NULL,
    UNIQUE(domain_id, name, type, content)
);
CREATE TABLE IF NOT EXISTS machines (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    ip TEXT NOT NULL UNIQUE,
    public_key TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL,
    UNIQUE(user_id, name)
);
CREATE TABLE IF NOT EXISTS addresses (
    id INTEGER PRIMARY KEY,
    domain_id INTEGER NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
    machine_id INTEGER NOT NULL REFERENCES machines(id) ON DELETE CASCADE,
    hostname TEXT NOT NULL UNIQUE,
    port INTEGER NOT NULL CHECK(port BETWEEN 1 AND 65535),
    protected INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_addresses_host ON addresses(hostname);
CREATE TABLE IF NOT EXISTS access_codes (
    code_hash TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    hostname TEXT NOT NULL,
    next_path TEXT NOT NULL,
    expires_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS host_sessions (
    token_hash TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    hostname TEXT NOT NULL,
    expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_host_sessions_host ON host_sessions(hostname);
CREATE TABLE IF NOT EXISTS attempts (
    id INTEGER PRIMARY KEY,
    kind TEXT NOT NULL,
    key TEXT NOT NULL,
    at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_attempts ON attempts(kind, key, at);
CREATE TABLE IF NOT EXISTS admin_audit (
    id INTEGER PRIMARY KEY,
    at TEXT NOT NULL,
    ip TEXT NOT NULL,
    method TEXT NOT NULL,
    path TEXT NOT NULL,
    status INTEGER NOT NULL,
    target_user_id INTEGER
);
"""


def now_iso() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        conn = sqlite3.connect(current_app.config["DATABASE"], timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA busy_timeout=10000")
        g.db = conn
    return g.db


def close_db(_error: BaseException | None = None) -> None:
    conn = g.pop("db", None)
    if conn is not None:
        conn.close()


def init_db() -> None:
    path = Path(current_app.config["DATABASE"])
    path.parent.mkdir(parents=True, exist_ok=True)
    db = get_db()
    db.execute("PRAGMA journal_mode=WAL")
    db.executescript(SCHEMA)
    db.commit()
