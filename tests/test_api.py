"""API pour agents : authentification, portées, isolation, JSON strict, contrat OpenAPI."""

import base64
import re
import runpy
import sqlite3
import time
from pathlib import Path

import pytest
from conftest import instance_config
from test_app import PROOFS, add_domain, csrf, register_approve_login

from synunnel import create_app
from synunnel.db import get_db

ROOT = Path(__file__).resolve().parents[1]
PASSWORD = "mot-de-passe-long-123"


@pytest.fixture
def app(tmp_path, monkeypatch):
    app = create_app(instance_config(
        SECRET_KEY="test-secret-only", ADMIN_TOKEN="test-admin-token-only",
        DATABASE=str(tmp_path / "synunnel.db"), WG_SERVER_PUBLIC_KEY="c2VydmV1ci1jbGUtcHVibGlxdWUtZGUtdGVzdC0tLS0=",
    ))
    PROOFS.clear()
    monkeypatch.setattr("synunnel.actions.ownership_proof", lambda domain: PROOFS.get(domain, set()))
    monkeypatch.setattr("synunnel.actions.snapshot_records",
                        lambda domain, selectors: [("@", "MX", f"10 mail.{domain}.", 3600)])
    monkeypatch.setattr("synunnel.actions.delegation_status", lambda domain, nameservers: (False, []))
    return app


def key(n: int) -> str:
    return base64.b64encode(bytes([n]) * 32).decode()


ALL = ("domains", "machines", "addresses", "sharing")


def create_token(client, scope="deploy", days: int = 30, password: str = PASSWORD) -> str | None:
    permissions = {"read": (), "deploy": ALL}.get(scope, scope) if isinstance(scope, str) else scope
    response = client.post("/tokens", data={"csrf_token": csrf(client), "name": "agent", "permissions": list(permissions),
                                            "days": str(days), "password": password})
    match = re.search(rb"syn_[A-Za-z0-9_-]{40,}", response.data)
    if match:
        assert response.headers["Cache-Control"] == "no-store"
    return match.group(0).decode() if match else None


def bearer(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def account(app, email: str):
    client = app.test_client()
    register_approve_login(app, client, email)
    return client


def test_token_creation_requires_password_and_is_shown_once(app):
    owner = account(app, "jeton@example.net")
    assert create_token(owner, password="faux-mot-de-passe") is None
    token = create_token(owner)
    assert token
    page = owner.get("/tokens").data.decode()
    assert token not in page and token[:10] in page
    with app.app_context():
        stored = get_db().execute("SELECT token_hash FROM api_tokens").fetchone()[0]
        assert token not in stored and len(stored) == 64


def test_authentication_boundaries(app):
    alice = account(app, "alice@example.net")
    bob = account(app, "bob@example.net")
    alice_token = create_token(alice, "read")
    bob_token = create_token(bob, "read")
    anonymous = app.test_client()
    missing = anonymous.get("/api/v1/me")
    assert missing.status_code == 401 and "Bearer" in missing.headers["WWW-Authenticate"]
    assert missing.headers["Cache-Control"] == "no-store"
    assert missing.json["error"]["code"] == "unauthorized"
    assert anonymous.get("/api/v1/me", headers=bearer("syn_" + "x" * 43)).status_code == 401
    # Un cookie de session seul n'ouvre jamais l'API, et ne passe pas par le contrôle CSRF.
    assert alice.get("/api/v1/me").status_code == 401
    assert alice.post("/api/v1/machines", json={"name": "x", "public_key": key(1)}).status_code == 401
    # Cookie d'Alice + jeton de Bob : seul le jeton compte.
    assert alice.get("/api/v1/me", headers=bearer(bob_token)).json["email"] == "bob@example.net"
    assert "Set-Cookie" not in alice.get("/api/v1/me", headers=bearer(bob_token)).headers
    # Un jeton ne donne rien sur les pages du tableau de bord ni sur l'API d'administration.
    assert anonymous.get("/dashboard", headers=bearer(alice_token)).status_code == 302
    assert anonymous.get("/admin/api/pending", headers=bearer(alice_token)).status_code == 401


def test_revoked_expired_and_read_only_tokens(app):
    owner = account(app, "portee@example.net")
    reader = create_token(owner, "read")
    writer = create_token(owner, "deploy")
    client = app.test_client()
    denied = client.post("/api/v1/machines", json={"name": "nas", "public_key": key(2)}, headers=bearer(reader))
    assert denied.status_code == 403
    with app.app_context():
        db = get_db()
        db.execute("UPDATE api_tokens SET expires_at=? WHERE scopes<>''", (int(time.time()) - 1,))
        db.commit()
    assert client.get("/api/v1/me", headers=bearer(writer)).status_code == 401
    owner.post("/tokens/revoke-all", data={"csrf_token": csrf(owner)})
    assert client.get("/api/v1/me", headers=bearer(reader)).status_code == 401


def test_machine_and_address_lifecycle_without_private_key(app):
    owner = account(app, "deploie@example.net")
    domain_id = add_domain(owner, "deploie.example.net")
    token = create_token(owner, "deploy")
    client = app.test_client()
    created = client.post("/api/v1/machines", json={"name": "nas", "public_key": key(3)}, headers=bearer(token))
    assert created.status_code == 201
    body = created.get_data(as_text=True)
    assert "PrivateKey" not in body and "private" not in body.lower()
    assert created.json["peer"]["allowed_ips"] == "10.88.0.1/32"
    machine_id = created.json["machine"]["id"]
    replay = client.post("/api/v1/machines", json={"name": "nas", "public_key": key(3)}, headers=bearer(token))
    assert replay.status_code == 200 and replay.json["machine"]["id"] == machine_id

    address = client.post("/api/v1/addresses", headers=bearer(token), json={
        "domain_id": domain_id, "machine_id": machine_id, "name": "nas", "port": 5000, "protected": True})
    assert address.status_code == 201
    assert address.json["address"]["protected"] is True
    assert "route_token" not in address.get_data(as_text=True)
    address_id = address.json["address"]["id"]
    assert client.post("/api/v1/addresses", headers=bearer(token), json={
        "domain_id": domain_id, "machine_id": machine_id, "name": "nas", "port": 5000, "protected": True}).status_code == 200
    assert client.delete(f"/api/v1/machines/{machine_id}", headers=bearer(token)).status_code == 409
    assert client.delete(f"/api/v1/addresses/{address_id}", headers=bearer(token)).status_code == 200
    assert client.delete(f"/api/v1/addresses/{address_id}", headers=bearer(token)).status_code == 404
    assert client.delete(f"/api/v1/machines/{machine_id}", headers=bearer(token)).status_code == 200
    with app.app_context():
        actions = [row[0] for row in get_db().execute("SELECT action FROM api_audit ORDER BY id")]
    assert actions == ["token.create", "machine.create", "address.create", "address.delete", "machine.delete"]


def test_accounts_are_isolated_through_the_api(app):
    alice = account(app, "iso-a@example.net")
    bob = account(app, "iso-b@example.net")
    domain_id = add_domain(alice, "iso.example.net")
    alice_token = create_token(alice, "deploy")
    bob_token = create_token(bob, "deploy")
    client = app.test_client()
    machine_id = client.post("/api/v1/machines", json={"name": "a", "public_key": key(4)},
                             headers=bearer(alice_token)).json["machine"]["id"]
    assert client.get(f"/api/v1/domains/{domain_id}", headers=bearer(bob_token)).status_code == 404
    assert client.delete(f"/api/v1/machines/{machine_id}", headers=bearer(bob_token)).status_code == 404
    bob_machine = client.post("/api/v1/machines", json={"name": "b", "public_key": key(5)},
                              headers=bearer(bob_token)).json["machine"]["id"]
    # Bob ne peut ni publier sur le domaine d'Alice, ni viser la machine d'Alice depuis son compte.
    assert client.post("/api/v1/addresses", headers=bearer(bob_token), json={
        "domain_id": domain_id, "machine_id": bob_machine, "name": "x", "port": 80, "protected": True}).status_code == 404
    assert client.get("/api/v1/machines", headers=bearer(bob_token)).json["machines"][0]["name"] == "b"


def test_strict_json(app):
    owner = account(app, "json@example.net")
    token = create_token(owner, "deploy")
    client = app.test_client()
    assert client.post("/api/v1/machines", data="name=x", headers=bearer(token)).status_code == 415
    assert client.post("/api/v1/machines", json=["x"], headers=bearer(token)).status_code == 400
    assert client.post("/api/v1/machines", json={"name": "x", "public_key": key(6), "private_key": "k"},
                       headers=bearer(token)).status_code == 422
    assert client.post("/api/v1/addresses", json={"domain_id": True, "machine_id": 1, "name": "x", "port": 80, "protected": True},
                       headers=bearer(token)).status_code == 422
    assert client.post("/api/v1/machines", json={"name": "x", "public_key": "pas-une-cle"},
                       headers=bearer(token)).status_code == 422
    unknown = client.get("/api/v1/inconnu", headers=bearer(token))
    assert unknown.status_code == 404 and unknown.json["error"]["code"] == "not_found"
    assert client.put("/api/v1/machines", json={}, headers=bearer(token)).status_code == 405


def test_revocation_during_operation_is_caught_under_lock(app, monkeypatch):
    owner = account(app, "course@example.net")
    token = create_token(owner, "deploy")
    from synunnel import actions
    original = actions.valid_public_key

    def revoke_then_check(value):
        with app.app_context():
            db = sqlite3.connect(app.config["DATABASE"])
            db.execute("UPDATE api_tokens SET revoked_at='maintenant'")
            db.commit()
            db.close()
        return original(value)

    monkeypatch.setattr(actions, "valid_public_key", revoke_then_check)
    response = app.test_client().post("/api/v1/machines", json={"name": "nas", "public_key": key(7)},
                                      headers=bearer(token))
    assert response.status_code == 401
    with app.app_context():
        assert get_db().execute("SELECT COUNT(*) FROM machines").fetchone()[0] == 0


def test_reused_machine_id_is_rechecked_under_lock(app, monkeypatch):
    alice = account(app, "reuse-a@example.net")
    account(app, "reuse-b@example.net")
    domain_id = add_domain(alice, "reuse.example.net")
    with app.app_context():
        db = get_db()
        alice_id, bob_id = [row[0] for row in db.execute("SELECT id FROM users ORDER BY id")]
        db.execute("INSERT INTO machines(id,user_id,name,ip,public_key,created_at) VALUES(7,?,?,?,?,?)",
                   (alice_id, "a", "10.88.0.7", key(8), "t"))
        db.commit()
    from synunnel import actions
    original = actions.relative_name

    def swap_machine(value, **kwargs):
        # Entre le premier contrôle et l'écriture, la machine 7 d'Alice disparaît et l'identifiant
        # est réattribué à une machine de Bob.
        db = sqlite3.connect(app.config["DATABASE"])
        db.execute("DELETE FROM machines WHERE id=7")
        db.execute("INSERT INTO machines(id,user_id,name,ip,public_key,created_at) VALUES(7,?,?,?,?,?)",
                   (bob_id, "b", "10.88.0.8", key(9), "t"))
        db.commit()
        db.close()
        return original(value, **kwargs)

    monkeypatch.setattr(actions, "relative_name", swap_machine)
    response = alice.post("/addresses", data={"csrf_token": csrf(alice), "domain_id": domain_id,
                                              "machine_id": 7, "name": "nas", "port": "80"})
    assert response.status_code in (302, 404)
    with app.app_context():
        assert get_db().execute("SELECT COUNT(*) FROM addresses").fetchone()[0] == 0


def test_openapi_matches_routes(app):
    document = app.test_client().get("/api/v1/openapi.json").json
    documented = {(path, method.upper()) for path, item in document["paths"].items() for method in item
                  if method in {"get", "post", "put", "delete", "patch"}}
    exposed = set()
    for rule in app.url_map.iter_rules():
        if rule.rule.startswith("/api/v1/") and rule.endpoint != "api.openapi":
            path = re.sub(r"<(?:int:)?(\w+)>", r"{\1}", rule.rule.removeprefix("/api/v1"))
            exposed |= {(path, method) for method in rule.methods - {"HEAD", "OPTIONS"}}
    assert documented == exposed
    assert document["servers"][0]["url"] == "https://synunnel.fr/api/v1"


def test_published_addresses_refuse_synunnel_tokens():
    routes = runpy.run_path(str(ROOT / "scripts/synunnel-sync.py"))["caddy_routes"]
    db = sqlite3.connect(":memory:")
    db.executescript(
        "CREATE TABLE users(id INTEGER, status TEXT); CREATE TABLE domains(id INTEGER, user_id INTEGER);"
        "CREATE TABLE machines(id INTEGER, user_id INTEGER, ip TEXT);"
        "CREATE TABLE addresses(hostname TEXT, port INTEGER, domain_id INTEGER, machine_id INTEGER, route_token TEXT);"
        "INSERT INTO users VALUES(1,'approved'),(2,'approved'); INSERT INTO domains VALUES(1,1);"
        "INSERT INTO machines VALUES(1,1,'10.88.0.2'),(2,2,'10.88.0.3');"
        f"INSERT INTO addresses VALUES('nas.exemple.fr',80,1,1,'{'a' * 24}'),('vol.exemple.fr',80,1,2,'{'b' * 24}');"
    )
    rendered = routes(db)
    assert "header_regexp Authorization ^[Bb]earer[[:space:]]+syn_" in rendered
    # Une adresse dont la machine appartient à un autre compte n'est jamais routée.
    assert "nas.exemple.fr" in rendered and "vol.exemple.fr" not in rendered


def test_agent_can_onboard_a_domain_and_manage_everything(app):
    owner = account(app, "complet@example.net")
    token = create_token(owner)
    client = app.test_client()
    claim = client.post("/api/v1/domains", headers=bearer(token),
                        json={"domain": "agent.example.net", "mail_records_checked": True})
    assert claim.status_code == 201
    txt = claim.json["claim"]["txt_record"]
    assert txt["name"] == "_synunnel.agent.example.net" and txt["value"].startswith("synunnel-verification=")
    claim_id = claim.json["claim"]["id"]
    assert client.post("/api/v1/domains", headers=bearer(token),
                       json={"domain": "agent.example.net", "mail_records_checked": True}).status_code == 200
    missing = client.post(f"/api/v1/claims/{claim_id}/verify", headers=bearer(token))
    assert missing.status_code == 422 and missing.json["error"]["code"] == "proof_missing"
    PROOFS["agent.example.net"] = {txt["value"]}
    verified = client.post(f"/api/v1/claims/{claim_id}/verify", headers=bearer(token))
    assert verified.status_code == 201
    domain_id = verified.json["domain"]["id"]
    replay = client.post(f"/api/v1/claims/{claim_id}/verify", headers=bearer(token))
    assert replay.status_code == 200 and replay.json["domain"]["id"] == domain_id
    record = client.post(f"/api/v1/domains/{domain_id}/records", headers=bearer(token),
                         json={"name": "@", "type": "TXT", "content": "bonjour"})
    assert record.status_code == 201
    record_id = record.json["record"]["id"]
    assert client.post(f"/api/v1/domains/{domain_id}/records", headers=bearer(token),
                       json={"name": "@", "type": "TXT", "content": "bonjour"}).status_code == 200
    assert client.delete(f"/api/v1/domains/{domain_id}/records/{record_id}", headers=bearer(token)).status_code == 200
    machine = client.post("/api/v1/machines", headers=bearer(token), json={"name": "nas", "public_key": key(11)})
    public = client.post("/api/v1/addresses", headers=bearer(token), json={
        "domain_id": domain_id, "machine_id": machine.json["machine"]["id"], "name": "www", "port": 80,
        "protected": False})
    assert public.status_code == 201 and public.json["address"]["protected"] is False
    private = client.post("/api/v1/addresses", headers=bearer(token), json={
        "domain_id": domain_id, "machine_id": machine.json["machine"]["id"], "name": "nas", "port": 5000,
        "protected": True}).json["address"]["id"]
    shared = client.put(f"/api/v1/addresses/{private}/access", headers=bearer(token),
                        json={"shared": True, "emails": ["ami@example.net"]})
    assert shared.status_code == 200 and shared.json["emails"] == ["ami@example.net"]
    assert client.get(f"/api/v1/addresses/{private}/access", headers=bearer(token)).json["shared"] is True
    # Le partage ne s'applique qu'aux adresses protégées.
    assert client.put(f"/api/v1/addresses/{public.json['address']['id']}/access", headers=bearer(token),
                      json={"shared": True, "emails": ["ami@example.net"]}).status_code == 404


def test_permissions_are_enforced_one_by_one(app):
    owner = account(app, "perm@example.net")
    domain_id = add_domain(owner, "perm.example.net")
    only_machines = create_token(owner, ("machines",))
    client = app.test_client()
    assert client.post("/api/v1/machines", headers=bearer(only_machines),
                       json={"name": "nas", "public_key": key(12)}).status_code == 201
    machine_id = client.get("/api/v1/machines", headers=bearer(only_machines)).json["machines"][0]["id"]
    for method, path, body in (
        ("post", "/api/v1/domains", {"domain": "autre.example", "mail_records_checked": True}),
        ("post", f"/api/v1/domains/{domain_id}/records", {"name": "@", "type": "TXT", "content": "x"}),
        ("post", "/api/v1/addresses", {"domain_id": domain_id, "machine_id": machine_id, "name": "a", "port": 1,
                                       "protected": True}),
    ):
        denied = getattr(client, method)(path, headers=bearer(only_machines), json=body)
        assert denied.status_code == 403 and denied.json["error"]["code"] == "forbidden"
    assert client.get("/api/v1/me", headers=bearer(only_machines)).json["token"]["permissions"] == ["machines"]


def test_mail_check_must_be_a_real_true(app):
    owner = account(app, "mail@example.net")
    token = create_token(owner)
    client = app.test_client()
    assert client.post("/api/v1/domains", headers=bearer(token),
                       json={"domain": "mail.example", "mail_records_checked": "false"}).status_code == 422
    assert client.post("/api/v1/domains", headers=bearer(token),
                       json={"domain": "mail.example", "mail_records_checked": False}).status_code == 422
