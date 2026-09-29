"""Routes Caddy des adresses publiées : chemins réservés de Synunnel et cookie d'accès retiré."""

import re
import runpy
import sqlite3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_caddy_routes_reserve_synunnel_paths_and_strip_the_access_cookie():
    sync = runpy.run_path(str(ROOT / "scripts/synunnel-sync.py"))
    db = sqlite3.connect(":memory:")
    db.executescript(
        "CREATE TABLE users(id INTEGER, status TEXT); CREATE TABLE domains(id INTEGER, user_id INTEGER);"
        "CREATE TABLE machines(id INTEGER, user_id INTEGER, ip TEXT);"
        "CREATE TABLE addresses(hostname TEXT, port INTEGER, domain_id INTEGER, machine_id INTEGER, route_token TEXT);"
        "INSERT INTO users VALUES(1,'approved'); INSERT INTO domains VALUES(1,1); INSERT INTO machines VALUES(1,1,'10.88.0.2');"
        f"INSERT INTO addresses VALUES('nas.exemple.fr',80,1,1,'{'a' * 24}');"
    )
    config = sync["caddy_routes"](db)
    assert "path /__synunnel/*" in config
    line = next(item for item in config.splitlines() if "header_up Cookie" in item)
    found = re.search(r'header_up Cookie "([^"]+)" "([^"]+)"', line)
    # Jamais de remplacement vide : Caddy 2.6 poserait alors le motif lui-même comme cookie.
    assert found and found.group(2) == "$2"
    strip = re.compile(found.group(1).replace("[[:space:]]", r"\s"))
    for raw, expected in (("__Host-synunnel-access=abc", ""), ("a=1; __Host-synunnel-access=abc; b=2", "a=1; b=2"),
                          ("__Host-synunnel-access=abc; b=2", "b=2"), ("a=1", "a=1")):
        assert strip.sub(r"\2", raw) == expected, raw


def test_caddy_logs_redact_link_tokens_cookies_and_authorization():
    config = (ROOT / "config/Caddyfile").read_text()
    block = config[config.index("log default"):config.index("email __ACME_EMAIL__")]
    for needle in ("format filter", "request>uri query", "replace token REDACTED", "replace code REDACTED",
                   "request>headers>Cookie delete", "request>headers>Authorization delete"):
        assert needle in block, needle
    # L'essai de bout en bout insère local_certs devant cette ligne : elle doit rester telle quelle.
    assert "\n    email " in config
