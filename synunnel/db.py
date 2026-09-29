"""SQLite : source de vérité des comptes et des routes."""

import os
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
    created_at TEXT NOT NULL,
    session_version INTEGER NOT NULL DEFAULT 0
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
CREATE TABLE IF NOT EXISTS domain_claims (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    token TEXT NOT NULL,
    selectors TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    domain_id INTEGER,
    UNIQUE(user_id, name)
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
    shared INTEGER NOT NULL DEFAULT 0 CHECK(shared IN (0, 1)),
    created_at TEXT NOT NULL,
    route_token TEXT NOT NULL DEFAULT (lower(hex(randomblob(12)))),
    guest_codes INTEGER NOT NULL DEFAULT 0 CHECK(guest_codes IN (0, 1)),
    guest_version INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_addresses_host ON addresses(hostname);
CREATE TABLE IF NOT EXISTS address_grants (
    address_id INTEGER NOT NULL REFERENCES addresses(id) ON DELETE CASCADE,
    email TEXT NOT NULL,
    PRIMARY KEY(address_id, email)
);
CREATE INDEX IF NOT EXISTS idx_address_grants_email ON address_grants(email);
CREATE TABLE IF NOT EXISTS access_codes (
    code_hash TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    hostname TEXT NOT NULL,
    next_path TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    session_version INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS host_sessions (
    token_hash TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    hostname TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    session_version INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_host_sessions_host ON host_sessions(hostname);
CREATE TABLE IF NOT EXISTS attempts (
    id INTEGER PRIMARY KEY,
    kind TEXT NOT NULL,
    key TEXT NOT NULL,
    at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_attempts ON attempts(kind, key, at);
CREATE INDEX IF NOT EXISTS idx_attempts_at ON attempts(at);
CREATE TABLE IF NOT EXISTS api_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    prefix TEXT NOT NULL,
    scopes TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    last_used_at INTEGER,
    revoked_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_api_tokens_user ON api_tokens(user_id);
CREATE TABLE IF NOT EXISTS api_audit (
    id INTEGER PRIMARY KEY,
    at TEXT NOT NULL,
    user_id INTEGER NOT NULL,
    token_id INTEGER,
    action TEXT NOT NULL,
    resource TEXT NOT NULL,
    ip TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_api_audit_at ON api_audit(at);
CREATE TABLE IF NOT EXISTS invitations (
    code_hash TEXT PRIMARY KEY,
    email TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    used_at TEXT
);
CREATE TABLE IF NOT EXISTS zone_removals (
    name TEXT PRIMARY KEY,
    at TEXT NOT NULL,
    forced INTEGER NOT NULL DEFAULT 0 CHECK(forced IN (0, 1))
);
CREATE TABLE IF NOT EXISTS id_counters (
    name TEXT PRIMARY KEY,
    last INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS totp_enrollments (
    user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    enrollment_hash TEXT NOT NULL,
    secret_enc TEXT NOT NULL,
    credential_version INTEGER NOT NULL,
    session_version INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS recovery_codes (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash TEXT NOT NULL,
    used_at INTEGER,
    UNIQUE(user_id, code_hash)
);
CREATE TABLE IF NOT EXISTS login_challenges (
    challenge_hash TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    session_version INTEGER NOT NULL,
    credential_version INTEGER NOT NULL,
    next_url TEXT NOT NULL DEFAULT '',
    expires_at INTEGER NOT NULL,
    used_at INTEGER
);
CREATE INDEX IF NOT EXISTS idx_login_challenges_expiry ON login_challenges(expires_at);
CREATE TABLE IF NOT EXISTS password_resets (
    token_hash TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    kind TEXT NOT NULL CHECK(kind IN ('email', 'admin')),
    scope TEXT NOT NULL CHECK(scope IN ('password', '2fa', 'both')),
    credential_version INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    used_at INTEGER
);
CREATE INDEX IF NOT EXISTS idx_password_resets_user ON password_resets(user_id);
CREATE INDEX IF NOT EXISTS idx_password_resets_expiry ON password_resets(expires_at);
CREATE TABLE IF NOT EXISTS email_verifications (
    token_hash TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    email TEXT NOT NULL,
    credential_version INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    used_at INTEGER
);
CREATE INDEX IF NOT EXISTS idx_email_verifications_expiry ON email_verifications(expires_at);
CREATE TABLE IF NOT EXISTS security_events (
    id INTEGER PRIMARY KEY,
    at TEXT NOT NULL,
    user_id INTEGER,
    actor TEXT NOT NULL,
    event TEXT NOT NULL,
    via TEXT NOT NULL DEFAULT '',
    ip TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_security_events_at ON security_events(at);
CREATE TABLE IF NOT EXISTS guest_challenges (
    challenge_hash TEXT PRIMARY KEY,
    address_id INTEGER NOT NULL REFERENCES addresses(id) ON DELETE CASCADE,
    email TEXT NOT NULL,
    route_token TEXT NOT NULL,
    guest_version INTEGER NOT NULL,
    next_path TEXT NOT NULL,
    mac TEXT NOT NULL,
    dummy INTEGER NOT NULL CHECK(dummy IN (0, 1)),
    attempts INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    used_at INTEGER
);
CREATE INDEX IF NOT EXISTS idx_guest_challenges_couple ON guest_challenges(address_id, email);
CREATE INDEX IF NOT EXISTS idx_guest_challenges_expiry ON guest_challenges(expires_at);
CREATE TABLE IF NOT EXISTS guest_access_codes (
    code_hash TEXT PRIMARY KEY,
    address_id INTEGER NOT NULL REFERENCES addresses(id) ON DELETE CASCADE,
    email TEXT NOT NULL,
    route_token TEXT NOT NULL,
    guest_version INTEGER NOT NULL,
    next_path TEXT NOT NULL,
    expires_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS guest_host_sessions (
    token_hash TEXT PRIMARY KEY,
    address_id INTEGER NOT NULL REFERENCES addresses(id) ON DELETE CASCADE,
    email TEXT NOT NULL,
    route_token TEXT NOT NULL,
    guest_version INTEGER NOT NULL,
    hostname TEXT NOT NULL,
    expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_guest_host_sessions_host ON guest_host_sessions(hostname);
CREATE TABLE IF NOT EXISTS guest_quota (
    id INTEGER PRIMARY KEY,
    kind TEXT NOT NULL,
    key TEXT NOT NULL,
    at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_guest_quota ON guest_quota(kind, key, at);
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


ID_TABLES = {"users", "domain_claims", "domains", "records", "machines", "addresses"}


def allocate_id(db: sqlite3.Connection, table: str) -> int:
    """Identifiant jamais réutilisé, à appeler sous le verrou d'écriture de l'insertion.

    SQLite réattribue le plus grand identifiant supprimé : une session, un jeton de route ou une
    suppression rejouée viserait alors une autre ressource, parfois d'un autre compte.
    """
    if table not in ID_TABLES:
        raise ValueError(table)
    row = db.execute("SELECT last FROM id_counters WHERE name=?", (table,)).fetchone()
    current = db.execute(f"SELECT COALESCE(MAX(id), 0) FROM {table}").fetchone()[0]
    value = max(row[0] if row else 0, current) + 1
    db.execute("INSERT INTO id_counters(name,last) VALUES(?,?) ON CONFLICT(name) DO UPDATE SET last=excluded.last",
               (table, value))
    return value


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


def _private_files(path: Path) -> None:
    """Base et journaux en 0600 : la base porte des empreintes et des secrets chiffrés."""
    for candidate in (path, Path(f"{path}-wal"), Path(f"{path}-shm")):
        try:
            if candidate.exists() and candidate.stat().st_uid == os.getuid():
                candidate.chmod(0o600)
        except OSError:
            pass


def init_db() -> None:
    path = Path(current_app.config["DATABASE"])
    path.parent.mkdir(parents=True, exist_ok=True)
    db = get_db()
    db.execute("PRAGMA journal_mode=WAL")
    db.executescript(SCHEMA)
    # Migration des bases du premier MVP. Le verrou sérialise deux workers au démarrage.
    db.execute("BEGIN IMMEDIATE")
    address_columns = {row[1] for row in db.execute("PRAGMA table_info(addresses)")}
    if "shared" not in address_columns:
        db.execute("ALTER TABLE addresses ADD COLUMN shared INTEGER NOT NULL DEFAULT 0 CHECK(shared IN (0, 1))")
    for column in ("guest_codes INTEGER NOT NULL DEFAULT 0 CHECK(guest_codes IN (0, 1))",
                   "guest_version INTEGER NOT NULL DEFAULT 0"):
        # Accès invité désactivé par défaut, y compris pour les adresses existantes.
        if column.split()[0] not in address_columns:
            db.execute(f"ALTER TABLE addresses ADD COLUMN {column}")
    if "route_token" not in address_columns:
        # Chaque incarnation d'une adresse porte son propre jeton : une ancienne route encore
        # chargée dans Caddy ne peut pas être réautorisée par une adresse recréée au même nom.
        db.execute("ALTER TABLE addresses ADD COLUMN route_token TEXT")
        db.execute("UPDATE addresses SET route_token=lower(hex(randomblob(12))) WHERE route_token IS NULL")
    for table in sorted(ID_TABLES):
        # Amorçage à la mise à niveau : la marge couvre les identifiants supprimés avant l'existence
        # des compteurs, que MAX(id) ne voit plus.
        db.execute(f"INSERT OR IGNORE INTO id_counters(name,last) SELECT ?, COALESCE(MAX(id), 0) + "
                   f"CASE WHEN COUNT(*) > 0 THEN 1000 ELSE 0 END FROM {table}", (table,))
    domain_columns = {row[1] for row in db.execute("PRAGMA table_info(domains)")}
    for column in ("delegation_active INTEGER", "delegation_ns TEXT", "delegation_checked_at INTEGER"):
        if column.split()[0] not in domain_columns:
            db.execute(f"ALTER TABLE domains ADD COLUMN {column}")
    if "forced" not in {row[1] for row in db.execute("PRAGMA table_info(zone_removals)")}:
        # Retrait forcé par l'administrateur : repris jusqu'au bout après un échec PowerDNS.
        db.execute("ALTER TABLE zone_removals ADD COLUMN forced INTEGER NOT NULL DEFAULT 0 CHECK(forced IN (0, 1))")
    if "domain_id" not in {row[1] for row in db.execute("PRAGMA table_info(domain_claims)")}:
        db.execute("ALTER TABLE domain_claims ADD COLUMN domain_id INTEGER")
    for table in ("users", "access_codes", "host_sessions"):
        if "session_version" not in {row[1] for row in db.execute(f"PRAGMA table_info({table})")}:
            db.execute(f"ALTER TABLE {table} ADD COLUMN session_version INTEGER NOT NULL DEFAULT 0")
    user_columns = {row[1] for row in db.execute("PRAGMA table_info(users)")}
    for column in ("credential_version INTEGER NOT NULL DEFAULT 0", "totp_secret_enc TEXT", "totp_enabled_at TEXT",
                   "totp_last_step INTEGER NOT NULL DEFAULT 0", "email_verified_at TEXT"):
        if column.split()[0] not in user_columns:
            db.execute(f"ALTER TABLE users ADD COLUMN {column}")
    if "credential_version" not in {row[1] for row in db.execute("PRAGMA table_info(api_tokens)")}:
        # Les jetons existants reçoivent la version courante de leur compte : ils restent valables
        # jusqu'au prochain changement de justificatif, qui les rendra caducs.
        db.execute("ALTER TABLE api_tokens ADD COLUMN credential_version INTEGER NOT NULL DEFAULT 0")
        db.execute("UPDATE api_tokens SET credential_version="
                   "(SELECT credential_version FROM users WHERE users.id=api_tokens.user_id)")
    db.commit()
    _private_files(path)
