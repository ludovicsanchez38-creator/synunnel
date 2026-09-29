-- Schéma de la base Synunnel 0.1.0a1 (commit da241d1), pour tester la mise à niveau.
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
    route_token TEXT NOT NULL DEFAULT (lower(hex(randomblob(12))))
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
    at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS id_counters (
    name TEXT PRIMARY KEY,
    last INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS admin_audit (
    id INTEGER PRIMARY KEY,
    at TEXT NOT NULL,
    ip TEXT NOT NULL,
    method TEXT NOT NULL,
    path TEXT NOT NULL,
    status INTEGER NOT NULL,
    target_user_id INTEGER
);
