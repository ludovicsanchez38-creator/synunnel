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

import pytest
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


# ---------------------------------------------------------------- revue Codex du design 2FA (C1 à C16)

def _mfa():
    import test_mfa
    return test_mfa


def test_c1_activation_ends_password_only_sessions_and_accesses(app, monkeypatch):
    mfa = _mfa()
    clock = {"now": 1_790_000_010.0}
    monkeypatch.setattr("synunnel.account._now", lambda: clock["now"])
    client = account(app, "c1@example.net")
    other = app.test_client()
    assert mfa.password_step(other, "c1@example.net").status_code == 302
    token = create_token(client)
    domain_id = add_domain(client, "c1.example.net")
    with app.app_context():
        db = get_db()
        uid = db.execute("SELECT id FROM users").fetchone()[0]
        db.execute("INSERT INTO machines(id,user_id,name,ip,public_key,created_at) VALUES(900,?,?,?,?,?)",
                   (uid, "m", "10.88.0.9", key(9), "x"))
        db.commit()
    client.post("/addresses", data={"csrf_token": csrf(client), "domain_id": domain_id, "machine_id": 900,
                                     "name": "nas", "port": "80", "protected": "1"})
    with app.app_context():
        db = get_db()
        db.execute("INSERT INTO host_sessions(token_hash,user_id,hostname,expires_at,session_version) "
                   "SELECT ?, id, 'nas.c1.example.net', ?, session_version FROM users",
                   (hashlib.sha256(b"ancien-acces").hexdigest(), int(time.time()) + 3600))
        db.commit()
    mfa.enroll(client, clock)
    assert client.get("/dashboard").status_code == 200
    assert other.get("/dashboard").status_code == 302
    assert client.get("/api/v1/me", headers=bearer(token)).status_code == 401
    with app.app_context():
        assert get_db().execute("SELECT COUNT(*) FROM host_sessions").fetchone()[0] == 0


def test_c2_require_2fa_applies_to_protected_addresses(app, monkeypatch):
    client = account(app, "c2@example.net")
    domain_id = add_domain(client, "c2.example.net")
    with app.app_context():
        db = get_db()
        uid = db.execute("SELECT id FROM users").fetchone()[0]
        db.execute("INSERT INTO machines(id,user_id,name,ip,public_key,created_at) VALUES(901,?,?,?,?,?)",
                   (uid, "m", "10.88.0.10", key(10), "x"))
        db.commit()
    client.post("/addresses", data={"csrf_token": csrf(client), "domain_id": domain_id, "machine_id": 901,
                                     "name": "nas", "port": "80", "protected": "1"})
    with app.app_context():
        db = get_db()
        route = db.execute("SELECT route_token FROM addresses").fetchone()[0]
        db.execute("INSERT INTO host_sessions(token_hash,user_id,hostname,expires_at,session_version) "
                   "SELECT ?, id, 'nas.c2.example.net', ?, session_version FROM users",
                   (hashlib.sha256(b"acces-ouvert").hexdigest(), int(time.time()) + 3600))
        db.commit()
    visitor = app.test_client()
    visitor.set_cookie("__Host-synunnel-access", "acces-ouvert", domain="nas.c2.example.net", secure=True)
    path = f"/internal/caddy/auth?route={route}"
    assert visitor.get(path, base_url="https://nas.c2.example.net").status_code == 204
    app.config["REQUIRE_2FA"] = True
    assert visitor.get(path, base_url="https://nas.c2.example.net").status_code == 302


def test_c3_token_creation_racing_a_credential_change_yields_no_token(app, monkeypatch):
    client = account(app, "c3@example.net")
    from synunnel import account as accounts
    real = accounts.verify_password

    def verify_then_change(hash_value, password):
        result = real(hash_value, password)
        with app.app_context():
            db = get_db()
            db.execute("UPDATE users SET credential_version=credential_version+1")
            db.commit()
        return result

    monkeypatch.setattr(accounts, "verify_password", verify_then_change)
    assert create_token(client) is None
    with app.app_context():
        assert get_db().execute("SELECT COUNT(*) FROM api_tokens").fetchone()[0] == 0


def test_c3_web_mutation_rechecks_the_account_under_lock(app, monkeypatch):
    client = account(app, "c3web@example.net")
    from synunnel import actions
    real = actions.normalize_domain

    def suspend_then_normalize(*args, **kwargs):
        with app.app_context():
            db = get_db()
            db.execute("UPDATE users SET status='pending', session_version=session_version+1")
            db.commit()
        return real(*args, **kwargs)

    monkeypatch.setattr(actions, "normalize_domain", suspend_then_normalize)
    client.post("/domains", data={"csrf_token": csrf(client), "domain": "c3web.example.net", "mail_checked": "1"})
    with app.app_context():
        assert get_db().execute("SELECT COUNT(*) FROM domain_claims").fetchone()[0] == 0


def test_c4_failed_codes_are_limited_across_challenges(app, monkeypatch):
    mfa = _mfa()
    clock = {"now": 1_790_000_010.0}
    monkeypatch.setattr("synunnel.account._now", lambda: clock["now"])
    client = account(app, "c4@example.net")
    secret, _ = mfa.enroll(client, clock)
    for attempt in range(5):
        browser = app.test_client()  # nouveau challenge à chaque fois : le compteur ne repart pas de zéro
        assert mfa.password_step(browser, "c4@example.net").status_code == 302
        bad = mfa.totp(secret, clock, offset=5)
        assert browser.post("/login/2fa", data={"csrf_token": csrf(browser), "code": bad}).status_code == 401, attempt
    browser = app.test_client()
    assert mfa.password_step(browser, "c4@example.net").status_code == 302
    clock["now"] += 30
    assert browser.post("/login/2fa", data={"csrf_token": csrf(browser),
                                            "code": mfa.totp(secret, clock)}).status_code == 429


def test_c6_suspension_kills_recovery_tickets_for_good(app):
    client = account(app, "c6@example.net")
    admin = {"Authorization": "Bearer test-admin-token-only"}
    with app.app_context():
        uid = get_db().execute("SELECT id FROM users").fetchone()[0]
    ticket = client.post(f"/admin/api/users/{uid}/recovery", headers=admin,
                         json={"email": "c6@example.net", "scope": "password"}).json["ticket"]
    assert client.post(f"/admin/api/users/{uid}/suspend", headers=admin).status_code == 200
    assert client.post(f"/admin/api/users/{uid}/approve", headers=admin, json={"email": "c6@example.net"}).status_code == 200
    visitor = app.test_client()
    assert visitor.post("/recover", data={"csrf_token": csrf(visitor), "email": "c6@example.net", "ticket": ticket,
                                          "new_password": "nouveau-mot-de-passe-456"}).status_code == 400


def test_c7_consumed_or_expired_challenge_is_refused(app, monkeypatch):
    mfa = _mfa()
    clock = {"now": 1_790_000_010.0}
    monkeypatch.setattr("synunnel.account._now", lambda: clock["now"])
    client = account(app, "c7@example.net")
    secret, _ = mfa.enroll(client, clock)
    browser = app.test_client()
    assert mfa.password_step(browser, "c7@example.net").status_code == 302
    with browser.session_transaction() as state:
        old = dict(state)
    clock["now"] += 30
    assert browser.post("/login/2fa", data={"csrf_token": csrf(browser), "code": mfa.totp(secret, clock)}).status_code == 302
    replay = app.test_client()
    with replay.session_transaction() as state:
        state.update(old)  # l'ancien cookie de session partielle, rejoué
    clock["now"] += 30
    refused = replay.post("/login/2fa", data={"csrf_token": old["csrf"], "code": mfa.totp(secret, clock)})
    assert refused.status_code == 302 and refused.headers["Location"].endswith("/login")
    assert replay.get("/dashboard").status_code == 302
    slow = app.test_client()
    assert mfa.password_step(slow, "c7@example.net").status_code == 302
    clock["now"] += 301
    late = slow.post("/login/2fa", data={"csrf_token": csrf(slow), "code": mfa.totp(secret, clock)})
    assert late.status_code == 302 and late.headers["Location"].endswith("/login")


def test_c9_a_login_code_cannot_authorize_another_action(app, monkeypatch):
    mfa = _mfa()
    clock = {"now": 1_790_000_010.0}
    monkeypatch.setattr("synunnel.account._now", lambda: clock["now"])
    client = account(app, "c9@example.net")
    secret, _ = mfa.enroll(client, clock)
    browser = app.test_client()
    assert mfa.login_2fa(browser, "c9@example.net", secret, clock).status_code == 302
    same = mfa.totp(secret, clock)
    browser.post("/security/2fa/disable", data={"csrf_token": csrf(browser), "password": PASSWORD, "code": same})
    with app.app_context():
        assert get_db().execute("SELECT totp_enabled_at FROM users").fetchone()[0]


def test_c14_smtp_is_implicit_tls_with_verified_certificate(app, monkeypatch, tmp_path):
    import ssl

    from synunnel.mailer import Mailer
    captured = {}

    class FakeSMTP:
        def __init__(self, host, port, context=None, timeout=None):
            captured.update(host=host, port=port, context=context, timeout=timeout)

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def login(self, user, password):
            captured.update(user=user, password=password)

        def send_message(self, message, from_addr=None, to_addrs=None):
            captured.update(message=message, from_addr=from_addr, to_addrs=to_addrs)

    monkeypatch.setattr("synunnel.mailer.smtplib.SMTP_SSL", FakeSMTP)
    secret_file = tmp_path / "smtp-password"
    secret_file.write_text("mot de passe \"avec\" $(espaces)\n")
    mailer = Mailer({"SMTP_HOST": "smtp.mail.ovh.net", "SMTP_PORT": "465", "SMTP_USER": "noreply@synunnel.fr",
                     "SMTP_FROM": "noreply@synunnel.fr", "SMTP_PASSWORD_FILE": str(secret_file)})
    assert mailer.enabled
    mailer.send_now("dest@example.net", "Objet", "Corps")
    assert captured["host"] == "smtp.mail.ovh.net" and captured["port"] == 465
    assert captured["context"].verify_mode == ssl.CERT_REQUIRED and captured["context"].check_hostname
    assert captured["password"] == 'mot de passe "avec" $(espaces)'
    assert captured["to_addrs"] == ["dest@example.net"] and captured["from_addr"] == "noreply@synunnel.fr"
    for bad in ("dest@example.net\r\nBcc: x@y.z", "pas-une-adresse"):
        with pytest.raises(ValueError):
            mailer.send_now(bad, "Objet", "Corps")
    assert not Mailer({"SMTP_HOST": "smtp.mail.ovh.net", "SMTP_PORT": "587", "SMTP_USER": "a@b.c",
                       "SMTP_FROM": "a@b.c", "SMTP_PASSWORD_FILE": str(secret_file)}).enabled


def test_c14_installer_generates_totp_key_and_never_sources_the_smtp_password():
    script = (ROOT / "scripts/install.sh").read_text()
    assert "TOTP_KEY" in script and "openssl rand -hex 32" in script
    assert re.search(r"grep -q '\^TOTP_KEY=' /etc/synunnel/synunnel.env", script)
    assert "source \"$SMTP_PASSWORD_FILE\"" not in script and ". \"$SMTP_PASSWORD_FILE\"" not in script
    assert "SMTP_PORT" in script and "465" in script


def test_c15_security_changes_are_audited_and_reset_attempts_bounded(app, monkeypatch):
    client = account(app, "c15@example.net")
    client.post("/security/password", data={"csrf_token": csrf(client), "password": PASSWORD,
                                            "new_password": "nouveau-mot-de-passe-456"})
    with app.app_context():
        events = [row[0] for row in get_db().execute("SELECT event FROM security_events")]
    assert "password.change" in events
    visitor = app.test_client()
    statuses = [visitor.post("/reset", data={"csrf_token": csrf(visitor), "token": "faux" * 11,
                                             "email": "c15@example.net", "password": "nouveau-mot-de-passe-789"}
                             ).status_code for _ in range(11)]
    assert statuses[:10] == [400] * 10 and statuses[10] == 429


def test_c16_migration_is_idempotent_and_reconcile_purges(app, monkeypatch):
    from synunnel.db import init_db
    with app.app_context():
        init_db()
        init_db()
    client = account(app, "c16@example.net")
    assert client.get("/dashboard").status_code == 200
    with app.app_context():
        db = get_db()
        db.execute("INSERT INTO login_challenges(challenge_hash,user_id,session_version,credential_version,next_url,"
                   "expires_at) SELECT 'vieux', id, 0, 0, '', 1 FROM users")
        db.commit()
    monkeypatch.setattr("synunnel.create_app", lambda: app)
    reconcile = runpy.run_path(str(ROOT / "scripts/reconcile.py"))
    monkeypatch.setitem(reconcile["main"].__globals__, "create_app", lambda: app)
    monkeypatch.setitem(reconcile["main"].__globals__, "project_runtime", lambda _app: True)
    reconcile["main"]()
    with app.app_context():
        assert get_db().execute("SELECT COUNT(*) FROM login_challenges").fetchone()[0] == 0


# ---------------------------------------------------------------- revue Codex du diff v0.2 (D1 à D7)

def _clock(monkeypatch):
    clock = {"now": 1_790_000_010.0}
    monkeypatch.setattr("synunnel.account._now", lambda: clock["now"])
    monkeypatch.setattr("synunnel.guest._now", lambda: clock["now"])
    return clock


def _bump_versions(app) -> None:
    """Réinitialisation concurrente : écrite par une autre connexion, comme une autre requête."""
    conn = sqlite3.connect(app.config["DATABASE"], timeout=10)
    conn.execute("UPDATE users SET credential_version=credential_version+1, session_version=session_version+1")
    conn.commit()
    conn.close()


def _reset_after_commit(app, monkeypatch) -> None:
    """Une réinitialisation s'intercale entre le commit du changement et l'émission du cookie :
    `release_attempts` s'exécute précisément là, hors transaction."""
    from synunnel import actions
    real_release = actions.release_attempts
    state = {"done": False}

    def release_then_reset(*ids):
        real_release(*ids)
        if len(ids) == 2 and not state["done"]:  # essais de second facteur rendus après le commit
            state["done"] = True
            _bump_versions(app)

    monkeypatch.setattr(actions, "release_attempts", release_then_reset)


def test_d1_second_step_session_dies_with_a_concurrent_reset(app, monkeypatch):
    mfa = _mfa()
    clock = _clock(monkeypatch)
    client = account(app, "d1@example.net")
    secret, _ = mfa.enroll(client, clock)
    browser = app.test_client()
    assert mfa.password_step(browser, "d1@example.net").status_code == 302
    _reset_after_commit(app, monkeypatch)
    clock["now"] += 30
    assert browser.post("/login/2fa", data={"csrf_token": csrf(browser),
                                            "code": mfa.totp(secret, clock)}).status_code == 302
    assert browser.get("/dashboard").status_code == 302


def test_d1_refreshed_session_dies_with_a_concurrent_reset(app, monkeypatch):
    mfa = _mfa()
    clock = _clock(monkeypatch)
    client = account(app, "d1b@example.net")
    secret, _ = mfa.enroll(client, clock)
    _reset_after_commit(app, monkeypatch)
    clock["now"] += 30
    assert client.post("/security/password", data={"csrf_token": csrf(client), "password": PASSWORD,
                                                   "new_password": "nouveau-mot-de-passe-456",
                                                   "code": mfa.totp(secret, clock)}).status_code == 302
    assert client.get("/dashboard").status_code == 302


def test_d3_concurrent_wrong_codes_cannot_exceed_the_budget(app, monkeypatch):
    from concurrent.futures import ThreadPoolExecutor
    mfa = _mfa()
    clock = _clock(monkeypatch)
    client = account(app, "d3@example.net")
    secret, _ = mfa.enroll(client, clock)
    with app.app_context():
        db = get_db()
        uid = db.execute("SELECT id FROM users").fetchone()[0]
        db.executemany("INSERT INTO attempts(kind,key,at) VALUES('mfa_user',?,?)", [(str(uid), int(time.time()))] * 4)
        db.commit()
    browsers = [app.test_client() for _ in range(8)]
    for browser in browsers:
        assert mfa.password_step(browser, "d3@example.net").status_code == 302
    wrong = mfa.totp(secret, clock, offset=7)

    def attempt(browser):
        return browser.post("/login/2fa", data={"csrf_token": csrf(browser), "code": wrong}).status_code

    with ThreadPoolExecutor(8) as pool:
        statuses = sorted(pool.map(attempt, browsers))
    assert statuses.count(401) == 1 and statuses.count(429) == 7
    with app.app_context():
        assert get_db().execute("SELECT COUNT(*) FROM attempts WHERE kind='mfa_user'").fetchone()[0] == 5


def test_d5_d6_errors_of_sensitive_pages_are_not_cached(app):
    visitor = app.test_client()
    for _ in range(5):
        visitor.post("/forgot", data={"csrf_token": csrf(visitor), "email": "x@example.org"})
    refused = visitor.post("/forgot", data={"csrf_token": csrf(visitor), "email": "x@example.org"})
    assert refused.status_code == 429 and refused.headers["Cache-Control"] == "no-store"
    assert visitor.post("/reset", data={}).headers["Cache-Control"] == "no-store"  # 400 CSRF


def test_d7_upgrade_of_a_real_0_1_database(tmp_path, monkeypatch):
    from conftest import instance_config

    from synunnel import create_app
    path = tmp_path / "ancienne.db"
    old = sqlite3.connect(path)
    old.executescript((ROOT / "tests/fixtures/schema-0.1.sql").read_text())
    old.execute("INSERT INTO users(id,email,password_hash,status,created_at,session_version) "
                "VALUES(1,'ancien@example.net','x','approved','2026-09-27',3)")
    token = "syn_" + "A" * 43
    old.execute("INSERT INTO api_tokens(user_id,name,token_hash,prefix,scopes,created_at,expires_at) "
                "VALUES(1,'agent',?,?,'domains',?,?)",
                (hashlib.sha256(token.encode()).hexdigest(), token[:10], "2026-09-27", int(time.time()) + 3600))
    old.execute("INSERT INTO domains(id,user_id,name,created_at) VALUES(1,1,'ancien.example.net','x')")
    old.execute("INSERT INTO machines(id,user_id,name,ip,public_key,created_at) VALUES(1,1,'m','10.88.0.2',?,'x')",
                (key(3),))
    old.execute("INSERT INTO addresses(id,domain_id,machine_id,hostname,port,protected,created_at,shared) "
                "VALUES(1,1,1,'nas.ancien.example.net',80,1,'x',1)")
    old.commit()
    old.close()
    upgraded = create_app(instance_config(SECRET_KEY="s", ADMIN_TOKEN="a", DATABASE=str(path),
                                          WG_SERVER_PUBLIC_KEY="k"))
    client = upgraded.test_client()
    assert client.get("/api/v1/me", headers={"Authorization": f"Bearer {token}"}).status_code == 200
    with upgraded.app_context():
        db = get_db()
        user = db.execute("SELECT credential_version, email_verified_at, totp_enabled_at FROM users").fetchone()
        assert tuple(user) == (0, None, None)
        assert tuple(db.execute("SELECT guest_codes, guest_version FROM addresses").fetchone()) == (0, 0)
        assert db.execute("SELECT credential_version FROM api_tokens").fetchone()[0] == 0
    import stat as stat_module
    assert stat_module.S_IMODE(path.stat().st_mode) == 0o600
    create_app(instance_config(SECRET_KEY="s", ADMIN_TOKEN="a", DATABASE=str(path), WG_SERVER_PUBLIC_KEY="k"))
