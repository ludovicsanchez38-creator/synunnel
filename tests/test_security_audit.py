# ruff: noqa: F811  (la fixture app vient de test_api)
"""Non-régression des audits de sécurité du 29/09/2026 (accès, API, système).

Chaque test reprend une preuve d'audit et vérifie le comportement corrigé.
"""

import hashlib
import re
import runpy
import sqlite3
import subprocess
import time
from pathlib import Path

from test_api import ALL, PASSWORD, account, app, bearer, create_token, key  # noqa: F401
from test_app import add_domain, csrf, register_approve_login

from synunnel.db import get_db

ROOT = Path(__file__).resolve().parents[1]
SYNC = runpy.run_path(str(ROOT / "scripts/synunnel-sync.py"))
NON_CANONICAL = "A" * 42 + "B="  # mêmes 32 octets que « A…A= » pour Python, refusée par wireguard-tools


def token_filter() -> re.Pattern:
    """Motif réellement généré dans les routes Caddy, traduit de RE2 vers Python."""
    db = sqlite3.connect(":memory:")
    db.executescript(
        "CREATE TABLE users(id INTEGER, status TEXT); CREATE TABLE domains(id INTEGER, user_id INTEGER);"
        "CREATE TABLE machines(id INTEGER, user_id INTEGER, ip TEXT);"
        "CREATE TABLE addresses(hostname TEXT, port INTEGER, domain_id INTEGER, machine_id INTEGER, route_token TEXT);"
        "INSERT INTO users VALUES(1,'approved'); INSERT INTO domains VALUES(1,1); INSERT INTO machines VALUES(1,1,'10.88.0.2');"
        f"INSERT INTO addresses VALUES('nas.exemple.fr',80,1,1,'{'a' * 24}');"
    )
    line = next(item for item in SYNC["caddy_routes"](db).splitlines() if "header_regexp Authorization" in item)
    pattern = line.split("Authorization", 1)[1].strip()
    flags = re.IGNORECASE if pattern.startswith("(?i)") else 0
    return re.compile(pattern.removeprefix("(?i)").replace("[[:space:]]", r"\s"), flags)


def test_non_canonical_wireguard_key_is_refused_everywhere(app, tmp_path):
    owner = account(app, "cle@example.net")
    token = create_token(owner, ("machines",))
    refused = app.test_client().post("/api/v1/machines", headers=bearer(token),
                                     json={"name": "x", "public_key": NON_CANONICAL})
    assert refused.status_code == 422
    # Même si une telle clé arrivait en base, la synchronisation l'écarte au lieu de bloquer tout wg0.
    with app.app_context():
        db = get_db()
        user_id = db.execute("SELECT id FROM users").fetchone()[0]
        db.execute("INSERT INTO machines(user_id,name,ip,public_key,created_at) VALUES(?,?,?,?,?)",
                   (user_id, "bad", "10.88.0.9", NON_CANONICAL, "t"))
        db.execute("INSERT INTO machines(user_id,name,ip,public_key,created_at) VALUES(?,?,?,?,?)",
                   (user_id, "good", "10.88.0.10", key(5), "t"))
        db.commit()
    server_key = tmp_path / "server.key"
    server_key.write_text(key(42))
    SYNC["wireguard_config"].__globals__["WG_KEY_PATH"] = server_key
    conn = sqlite3.connect(app.config["DATABASE"])
    conn.row_factory = sqlite3.Row
    config = SYNC["wireguard_config"](conn)
    assert NON_CANONICAL not in config and key(5) in config


def test_caddy_failure_does_not_stop_wireguard_and_the_reverse(tmp_path):
    calls = []
    glb = SYNC["apply"].__globals__
    glb["WG_CONFIG_PATH"], glb["CADDY_ROUTES_PATH"] = tmp_path / "wg0.conf", tmp_path / "routes.caddy"
    glb["APPLIED_WG"], glb["APPLIED_CADDY"] = tmp_path / "applied-wg", tmp_path / "applied-caddy"
    glb["wireguard_active"] = lambda: False

    def fake_run(*args, input=None):
        calls.append(args[:2])
        if args[:2] == ("/usr/bin/systemctl", "start"):
            raise subprocess.CalledProcessError(1, args)
        return subprocess.CompletedProcess(args, 0, b"", b"")

    glb["run"] = fake_run
    try:
        SYNC["apply"]("[Interface]\n", "# routes\n")
    except SystemExit as exc:
        assert "apply_wireguard" in str(exc)
    assert (tmp_path / "routes.caddy").read_text() == "# routes\n"
    assert ("/usr/bin/systemctl", "reload") in calls
    # Caddy appliqué : l'empreinte est posée ; un second passage ne recharge plus rien.
    calls.clear()
    try:
        SYNC["apply"]("[Interface]\n", "# routes\n")
    except SystemExit:
        pass
    assert ("/usr/bin/systemctl", "reload") not in calls


def test_token_filter_covers_every_case_the_api_accepts(app):
    owner = account(app, "casse@example.net")
    token = create_token(owner, "read")
    pattern = token_filter()
    for scheme in ("Bearer", "bearer", "BEARER", "BeArEr"):
        header = f"{scheme} {token}"
        assert app.test_client().get("/api/v1/me", headers={"Authorization": header}).status_code == 200
        assert pattern.search(header), scheme


def test_unicode_spaces_are_refused_by_api_and_caught_by_filter(app):
    owner = account(app, "nbsp@example.net")
    token = create_token(owner, "read")
    pattern = token_filter()
    for header in (f"Bearer \u00a0{token}", f"Bearer  {token}", f"Bearer\t{token}"):
        assert app.test_client().get("/api/v1/me", headers={"Authorization": header}).status_code == 401
        assert pattern.search(header)


def test_public_address_requires_sharing_permission(app):
    owner = account(app, "proteg@example.net")
    domain_id = add_domain(owner, "proteg.example.net")
    full = create_token(owner)
    only_addresses = create_token(owner, ("addresses",))
    client = app.test_client()
    machine_id = client.post("/api/v1/machines", headers=bearer(full),
                             json={"name": "nas", "public_key": key(21)}).json["machine"]["id"]
    body = {"domain_id": domain_id, "machine_id": machine_id, "name": "nas", "port": 5000}
    assert client.post("/api/v1/addresses", headers=bearer(only_addresses),
                       json={**body, "protected": False}).status_code == 403
    assert client.post("/api/v1/addresses", headers=bearer(only_addresses),
                       json={**body, "protected": True}).status_code == 201
    assert client.post("/api/v1/addresses", headers=bearer(full),
                       json={**body, "name": "www", "protected": False}).status_code == 201


def test_long_dkim_record_and_documented_limits(app):
    owner = account(app, "dkim@example.net")
    domain_id = add_domain(owner, "dkim.example.net")
    token = create_token(owner)
    dkim = "v=DKIM1; k=rsa; p=" + "M" * 392
    created = app.test_client().post(f"/api/v1/domains/{domain_id}/records", headers=bearer(token),
                                     json={"name": "sel._domainkey", "type": "TXT", "content": dkim})
    assert created.status_code == 201
    document = app.test_client().get("/api/v1/openapi.json").json["paths"]
    content = document["/domains/{domain_id}/records"]["post"]["requestBody"]["content"]["application/json"]
    assert content["schema"]["properties"]["content"]["maxLength"] == 4096
    for path, method in (("/domains", "post"), ("/machines", "post"), ("/addresses/{address_id}/access", "put")):
        responses = document[path][method]["responses"]
        assert {"400", "403", "422"} <= set(responses), (path, responses.keys())


def test_verified_domains_are_not_counted_twice(app):
    app.config["MAX_DOMAINS_PER_USER"] = 2
    owner = account(app, "quota@example.net")
    add_domain(owner, "un.example.net")
    token = create_token(owner)
    second = app.test_client().post("/api/v1/domains", headers=bearer(token),
                                    json={"domain": "deux.example.net", "mail_records_checked": True})
    assert second.status_code == 201


def test_rate_limits_are_cheap_and_ipv6_aware(app):
    owner = account(app, "cout@example.net")
    token = create_token(owner, "read")
    client = app.test_client()
    statuses = {client.get("/api/v1/me", headers=bearer("syn_" + "x" * 43),
                           environ_base={"REMOTE_ADDR": f"2001:db8::{n:x}"}).status_code for n in range(40)}
    assert statuses == {401, 429}
    with app.app_context():
        db = get_db()
        before = db.execute("SELECT COUNT(*) FROM attempts").fetchone()[0]
        plan = " ".join(row[3] for row in db.execute("EXPLAIN QUERY PLAN DELETE FROM attempts WHERE at < 1"))
    for _ in range(20):
        assert client.get("/api/v1/machines", headers=bearer(token)).status_code == 200
    with app.app_context():
        # Une lecture n'écrit rien en base, et la purge ne parcourt jamais toute la table.
        assert get_db().execute("SELECT COUNT(*) FROM attempts").fetchone()[0] == before
    assert "SCAN" not in plan


def test_verify_rate_limit_says_when_to_retry(app):
    owner = account(app, "retry@example.net")
    token = create_token(owner)
    client = app.test_client()
    claim = client.post("/api/v1/domains", headers=bearer(token),
                        json={"domain": "retry.example.net", "mail_records_checked": True}).json["claim"]
    responses = [client.post(f"/api/v1/claims/{claim['id']}/verify", headers=bearer(token)) for _ in range(21)]
    assert responses[-1].status_code == 429 and responses[-1].headers["Retry-After"]


def test_unexpected_input_gives_client_errors(app):
    owner = account(app, "entrees@example.net")
    token = create_token(owner)
    client = app.test_client()
    assert client.get("/api/v1/claims/99999999999999999999", headers=bearer(token)).status_code == 404
    nested = client.post("/api/v1/machines", data="[" * 5000 + "]" * 5000,
                         headers={**bearer(token), "Content-Type": "application/json"})
    assert nested.status_code == 400
    not_allowed = client.put("/api/v1/machines", json={}, headers=bearer(token))
    assert not_allowed.status_code == 405 and "POST" in not_allowed.headers["Allow"]


def test_record_replay_with_new_ttl_updates_it(app):
    owner = account(app, "ttl@example.net")
    domain_id = add_domain(owner, "ttl.example.net")
    token = create_token(owner)
    client = app.test_client()
    body = {"name": "@", "type": "TXT", "content": "bonjour", "ttl": 3600}
    first = client.post(f"/api/v1/domains/{domain_id}/records", headers=bearer(token), json=body)
    again = client.post(f"/api/v1/domains/{domain_id}/records", headers=bearer(token), json={**body, "ttl": 600})
    assert again.status_code == 200 and again.json["record"]["id"] == first.json["record"]["id"]
    assert again.json["record"]["ttl"] == 600


def test_invisible_or_lookalike_characters_are_refused(app):
    owner = account(app, "unicode@example.net")
    domain_id = add_domain(owner, "unicode.example.net")
    token = create_token(owner)
    client = app.test_client()
    accepted = [name for n, name in enumerate(("nas", "nas" + chr(0x200B), "n" + chr(0x202E) + "as", "nas" + chr(0x7F)))
                if client.post("/api/v1/machines", headers=bearer(token),
                               json={"name": name, "public_key": key(60 + n)}).status_code == 201]
    assert accepted == ["nas"]
    machine_id = client.get("/api/v1/machines", headers=bearer(token)).json["machines"][0]["id"]
    address_id = client.post("/api/v1/addresses", headers=bearer(token), json={
        "domain_id": domain_id, "machine_id": machine_id, "name": "u", "port": 80,
        "protected": True}).json["address"]["id"]
    grant = client.put(f"/api/v1/addresses/{address_id}/access", headers=bearer(token),
                       json={"shared": True, "emails": ["аlice@example.net", "bob\u200b@example.net"]})
    assert grant.status_code == 422


def test_audit_keeps_what_was_deleted(app):
    owner = account(app, "journal@example.net")
    domain_id = add_domain(owner, "journal.example.net")
    token = create_token(owner)
    client = app.test_client()
    record_id = client.post(f"/api/v1/domains/{domain_id}/records", headers=bearer(token),
                            json={"name": "mail", "type": "A", "content": "192.0.2.25"}).json["record"]["id"]
    client.delete(f"/api/v1/domains/{domain_id}/records/{record_id}", headers=bearer(token))
    with app.app_context():
        row = get_db().execute("SELECT resource, ip FROM api_audit WHERE action='record.delete'").fetchone()
    assert "192.0.2.25" in row["resource"] and row["ip"]


def test_failed_attempts_elsewhere_do_not_lock_the_owner_out(app):
    victim = app.test_client()
    register_approve_login(app, victim, "cible@example.net")
    other = app.test_client()
    token = csrf(other)
    for _ in range(10):
        other.post("/login", data={"csrf_token": token, "email": "cible@example.net", "password": "mauvais-000"},
                   environ_base={"REMOTE_ADDR": "203.0.113.7"})
    fresh = app.test_client()
    response = fresh.post("/login", data={"csrf_token": csrf(fresh), "email": "cible@example.net",
                                          "password": PASSWORD}, environ_base={"REMOTE_ADDR": "198.51.100.20"})
    assert response.status_code == 302


def test_reused_user_id_does_not_inherit_a_session(app):
    first = app.test_client()
    first_id = register_approve_login(app, first, "ancien@example.net")
    with app.app_context():
        db = get_db()
        db.execute("DELETE FROM users WHERE id=?", (first_id,))
        db.commit()
    newcomer = app.test_client()
    # Les identifiants ne sont plus jamais réattribués, et la version de session est aléatoire.
    assert register_approve_login(app, newcomer, "nouveau@example.net") != first_id
    assert b"nouveau@example.net" not in first.get("/dashboard").data


def test_admin_decisions_are_bound_to_the_address(app):
    admin = {"Authorization": "Bearer test-admin-token-only"}
    client = app.test_client()
    client.post("/register", data={"csrf_token": csrf(client), "email": "demande@example.net",
                                   "password": PASSWORD})
    user_id = client.get("/admin/api/pending", headers=admin).json["pending"][0]["id"]
    assert client.post(f"/admin/api/users/{user_id}/approve", headers=admin).status_code == 400
    assert client.post(f"/admin/api/users/{user_id}/approve", headers=admin,
                       json={"email": "autre@example.net"}).status_code == 404
    assert client.post(f"/admin/api/users/{user_id}/approve", headers=admin,
                       json={"email": "demande@example.net"}).status_code == 200


def test_invitation_mode_prevents_preregistration(app):
    app.config["REGISTRATION_MODE"] = "invitation"
    admin = {"Authorization": "Bearer test-admin-token-only"}
    attacker = app.test_client()
    # Un tiers qui préinscrit l'adresse sans le code n'obtient rien.
    attacker.post("/register", data={"csrf_token": csrf(attacker), "email": "invite@example.net",
                                     "password": "mot-de-passe-de-l-attaquant", "invitation": "au-hasard"})
    code = attacker.post("/admin/api/invitations", headers=admin, json={"email": "invite@example.net"}).json["code"]
    guest = app.test_client()
    guest.post("/register", data={"csrf_token": csrf(guest), "email": "invite@example.net", "password": PASSWORD,
                                  "invitation": code})
    login = guest.post("/login", data={"csrf_token": csrf(guest), "email": "invite@example.net", "password": PASSWORD})
    assert login.status_code == 302
    # Le code est à usage unique.
    other = app.test_client()
    other.post("/register", data={"csrf_token": csrf(other), "email": "invite@example.net", "password": "x" * 14,
                                  "invitation": code})
    with app.app_context():
        assert get_db().execute("SELECT COUNT(*) FROM users").fetchone()[0] == 1


def test_admin_can_suspend_an_approved_account(app):
    admin = {"Authorization": "Bearer test-admin-token-only"}
    client = app.test_client()
    user_id = register_approve_login(app, client, "compromis@example.net")
    token = create_token(client)
    suspended = client.post(f"/admin/api/users/{user_id}/suspend", headers=admin)
    assert suspended.status_code == 200 and suspended.json["status"] == "suspended"
    assert client.get("/dashboard").status_code == 302
    assert app.test_client().get("/api/v1/me", headers=bearer(token)).status_code == 401


def test_dashboard_session_has_an_absolute_lifetime(app, monkeypatch):
    client = app.test_client()
    register_approve_login(app, client, "longue@example.net")
    start = time.time()
    for hours in range(11, 72, 11):
        monkeypatch.setattr("time.time", lambda h=hours: start + h * 3600)
        client.get("/dashboard")
    monkeypatch.setattr("time.time", lambda: start + 72 * 3600)
    assert client.get("/dashboard").status_code == 302


def test_non_ascii_secrets_are_refused_not_crashing(app):
    client = app.test_client()
    assert client.get("/admin/api/pending", headers={"Authorization": "Bearer é"}).status_code == 401
    assert client.post("/login", data={"csrf_token": "é", "email": "a@b.cd", "password": "x"}).status_code == 400


def test_login_form_relays_to_protected_address_through_a_page(app):
    owner = app.test_client()
    user_id = register_approve_login(app, owner, "relais@example.net")
    domain_id = add_domain(owner, "relais.example.net")
    with app.app_context():
        db = get_db()
        db.execute("INSERT INTO machines(user_id,name,ip,public_key,created_at) VALUES(?,?,?,?,?)",
                   (user_id, "nas", "10.88.0.4", key(70), "t"))
        db.commit()
        machine_id = db.execute("SELECT id FROM machines").fetchone()[0]
    owner.post("/addresses", data={"csrf_token": csrf(owner), "domain_id": domain_id, "machine_id": machine_id,
                                   "name": "prive", "port": "80", "protected": "1"})
    browser = app.test_client()
    page = browser.post("/login", data={"csrf_token": csrf(browser), "email": "relais@example.net",
                                        "password": PASSWORD, "next": "https://prive.relais.example.net/"})
    body = page.get_data(as_text=True)
    # Chromium bloque une redirection hors domaine après un formulaire (CSP form-action) : une page relaie.
    assert page.status_code == 200 and 'http-equiv="refresh"' in body and "prive.relais.example.net" in body
    assert hashlib.sha256(b"x").hexdigest()  # sentinelle d'import


def test_domain_page_never_queries_dns(app, monkeypatch):
    owner = account(app, "cache@example.net")
    domain_id = add_domain(owner, "cache.example.net")

    def forbidden(*args, **kwargs):
        raise AssertionError("requête DNS sortante depuis une page")

    monkeypatch.setattr("synunnel.actions.delegation_status", forbidden)
    page = owner.get(f"/domains/{domain_id}")
    assert page.status_code == 200 and "Vérification en cours" in page.get_data(as_text=True)


def test_domain_can_be_deleted_by_owner_and_admin(app):
    owner = account(app, "suppr@example.net")
    domain_id = add_domain(owner, "suppr.example.net")
    token = create_token(owner)
    client = app.test_client()
    machine_id = client.post("/api/v1/machines", headers=bearer(token),
                             json={"name": "nas", "public_key": key(80)}).json["machine"]["id"]
    client.post("/api/v1/addresses", headers=bearer(token), json={
        "domain_id": domain_id, "machine_id": machine_id, "name": "nas", "port": 80, "protected": True})
    assert client.delete(f"/api/v1/domains/{domain_id}", headers=bearer(token)).status_code == 409
    admin = {"Authorization": "Bearer test-admin-token-only"}
    removed = client.post("/admin/api/domains/delete", headers=admin, json={"name": "suppr.example.net"})
    assert removed.status_code == 200
    with app.app_context():
        db = get_db()
        assert db.execute("SELECT COUNT(*) FROM domains").fetchone()[0] == 0
        assert db.execute("SELECT COUNT(*) FROM addresses").fetchone()[0] == 0
    # Le vrai titulaire peut maintenant revendiquer le domaine.
    assert client.post("/api/v1/domains", headers=bearer(token),
                       json={"domain": "suppr.example.net", "mail_records_checked": True}).status_code == 201


def test_import_and_records_are_bounded_and_valid(app, monkeypatch):
    app.config["MAX_RECORDS_PER_DOMAIN"] = 3
    owner = account(app, "import@example.net")
    token = create_token(owner)
    client = app.test_client()
    monkeypatch.setattr("synunnel.actions.snapshot_records", lambda domain, selectors: [
        ("@", "TXT", f'"valeur {n}"', 3600) for n in range(5)])
    claim = client.post("/api/v1/domains", headers=bearer(token),
                        json={"domain": "gros.example.net", "mail_records_checked": True}).json["claim"]
    import test_app
    test_app.PROOFS["gros.example.net"] = {claim["txt_record"]["value"]}
    refused = client.post(f"/api/v1/claims/{claim['id']}/verify", headers=bearer(token))
    assert refused.status_code == 422
    app.config["MAX_RECORDS_PER_DOMAIN"] = 200
    monkeypatch.setattr("synunnel.actions.snapshot_records", lambda domain, selectors: [
        ("@", "MX", f"10 mail.{domain}.", 3600)])
    domain_id = client.post(f"/api/v1/claims/{claim['id']}/verify", headers=bearer(token)).json["domain"]["id"]
    for body in ({"name": "@", "type": "CNAME", "content": "ailleurs.example."},
                 {"name": "x", "type": "AAAA", "content": "fe80::1%eth0"},
                 {"name": "_" + "a" * 63, "type": "TXT", "content": "long"}):
        assert client.post(f"/api/v1/domains/{domain_id}/records", headers=bearer(token),
                           json=body).status_code == 422, body
