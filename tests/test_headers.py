# ruff: noqa: F811  (la fixture vient de test_api)
"""En-têtes de durcissement : HSTS avec sous-domaines sur le seul tableau de bord, Server de gunicorn retiré."""

import runpy
import sqlite3
from pathlib import Path

from test_api import app  # noqa: F401

ROOT = Path(__file__).resolve().parents[1]


def _block(config: str, opening: str) -> str:
    """Le bloc Caddy qui commence à `opening`, jusqu'à son accolade fermante seule sur sa ligne."""
    lines = config[config.index(opening):].splitlines()
    return "\n".join(lines[:next(i for i, line in enumerate(lines) if line.strip() == "}")])


def test_hsts_covers_subdomains_on_the_dashboard_only(app):
    client = app.test_client()
    dashboard = client.get("/login", base_url="https://synunnel.fr")
    assert dashboard.headers["Strict-Transport-Security"] == "max-age=31536000; includeSubDomains"
    # Sur l'adresse d'un utilisateur, ses sous-domaines ne sont pas les nôtres.
    user_host = client.head("/__synunnel/auth/callback?code=x", base_url="https://nas.exemple.fr")
    assert user_host.headers["Strict-Transport-Security"] == "max-age=31536000"
    assert "Strict-Transport-Security" not in client.get("/login", base_url="http://synunnel.fr").headers


def test_caddy_strips_the_gunicorn_server_header():
    render = runpy.run_path(str(ROOT / "scripts/render-caddy.py"))["render_caddy"]
    dashboard = render((ROOT / "config/Caddyfile").read_text(), "synunnel.fr", "", "admin@example.org")
    assert "header_down -Server" in _block(dashboard, "reverse_proxy 127.0.0.1:8000")

    sync = runpy.run_path(str(ROOT / "scripts/synunnel-sync.py"))
    db = sqlite3.connect(":memory:")
    db.executescript(
        "CREATE TABLE users(id INTEGER, status TEXT); CREATE TABLE domains(id INTEGER, user_id INTEGER);"
        "CREATE TABLE machines(id INTEGER, user_id INTEGER, ip TEXT);"
        "CREATE TABLE addresses(hostname TEXT, port INTEGER, domain_id INTEGER, machine_id INTEGER, route_token TEXT);"
        "INSERT INTO users VALUES(1,'approved'); INSERT INTO domains VALUES(1,1); INSERT INTO machines VALUES(1,1,'10.88.0.2');"
        f"INSERT INTO addresses VALUES('nas.exemple.fr',80,1,1,'{'a' * 24}');"
    )
    routes = sync["caddy_routes"](db)
    # Retiré sur les deux passages vers l'application (chemins réservés, contrôle d'accès)...
    assert routes.count("header_down -Server") == 2
    # ...jamais sur le service de la machine : son en-tête appartient à l'utilisateur.
    assert "header_down" not in _block(routes, "reverse_proxy 10.88.0.2:80")
