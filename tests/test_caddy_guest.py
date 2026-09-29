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
    pattern = re.search(r'header_up Cookie "([^"]+)" ""', line).group(1).replace("[[:space:]]", r"\s")
    strip = re.compile(pattern)
    for raw, expected in (("__Host-synunnel-access=abc", ""), ("a=1; __Host-synunnel-access=abc; b=2", "a=1; b=2"),
                          ("__Host-synunnel-access=abc; b=2", "b=2"), ("a=1", "a=1")):
        assert strip.sub("", raw).rstrip("; ") == expected, raw
