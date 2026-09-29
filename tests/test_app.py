"""Tests du parcours d'autorisation et des frontières entre comptes."""

import base64
import re
from pathlib import Path
from urllib.parse import urlsplit

import pytest
from conftest import instance_config

from synunnel import create_app
from synunnel.db import get_db

PROOFS: dict[str, set[str]] = {}


@pytest.fixture
def app(tmp_path, monkeypatch):
    app = create_app(instance_config(
        SECRET_KEY="test-secret-only",
        ADMIN_TOKEN="test-admin-token-only",
        DATABASE=str(tmp_path / "synunnel.db"),
        WG_SERVER_PUBLIC_KEY="test-server-public-key",
    ))
    PROOFS.clear()
    monkeypatch.setattr("synunnel.web.ownership_proof", lambda domain: PROOFS.get(domain, set()))
    counter = iter(range(1, 250))

    def keypair():
        n = next(counter)
        return (base64.b64encode(bytes([n]) * 32).decode(), base64.b64encode(bytes([n, 255]) * 16).decode())

    monkeypatch.setattr("synunnel.web.generate_keypair", keypair)
    monkeypatch.setattr(
        "synunnel.web.snapshot_records",
        lambda domain, selectors: [("@", "MX", f"10 mail.{domain}.", 3600), ("@", "TXT", '"v=spf1 -all"', 3600)],
    )
    monkeypatch.setattr("synunnel.web.delegation_status", lambda domain, nameservers: (False, []))
    return app


def csrf(client) -> str:
    with client.session_transaction() as state:
        if "csrf" in state:
            return state["csrf"]
    page = client.get("/login")
    return re.search(rb'name="csrf_token" value="([^"]+)"', page.data).group(1).decode()


def register_approve_login(app, client, email: str) -> int:
    token = csrf(client)
    response = client.post("/register", data={
        "csrf_token": token, "email": email, "password": "mot-de-passe-long-123",
    })
    assert response.status_code == 302
    pending = client.get("/admin/api/pending", headers={"Authorization": "Bearer test-admin-token-only"}).json["pending"]
    user_id = next(item["id"] for item in pending if item["email"] == email)
    response = client.post(f"/admin/api/users/{user_id}/approve", headers={"Authorization": "Bearer test-admin-token-only"})
    assert response.status_code == 200
    response = client.post("/login", data={
        "csrf_token": csrf(client), "email": email, "password": "mot-de-passe-long-123",
    })
    assert response.status_code == 302
    return user_id


def login_dashboard(client, email: str) -> None:
    page = client.get("/login", base_url="https://synunnel.fr")
    token = re.search(rb'name="csrf_token" value="([^"]+)"', page.data).group(1).decode()
    response = client.post("/login", base_url="https://synunnel.fr", data={
        "csrf_token": token, "email": email, "password": "mot-de-passe-long-123",
    })
    assert response.status_code == 302


def claim_domain(client, name: str) -> tuple[int, str]:
    response = client.post("/domains", data={
        "csrf_token": csrf(client), "domain": name, "mail_checked": "1", "selectors": "",
    })
    assert response.status_code == 302
    assert "/claims/" in response.headers["Location"]
    claim_id = int(response.headers["Location"].split("/")[-1])
    page = client.get(f"/claims/{claim_id}").data.decode()
    return claim_id, re.search(r"synunnel-verification=[A-Za-z0-9_-]+", page).group(0)


def add_domain(client, name: str) -> int:
    claim_id, proof = claim_domain(client, name)
    PROOFS.setdefault(name, set()).add(proof)
    response = client.post(f"/claims/{claim_id}/verify", data={"csrf_token": csrf(client)})
    assert response.status_code == 302
    assert "/domains/" in response.headers["Location"]
    return int(response.headers["Location"].split("/")[-1])


def test_admin_pending_reject_blocks_email_and_audits(app):
    client = app.test_client()
    token = csrf(client)
    assert client.post("/register", data={"csrf_token": token, "email": "refuse@example.net", "password": "long-secret-123"}).status_code == 302
    assert client.get("/admin/api/pending").status_code == 401
    pending = client.get("/admin/api/pending", headers={"Authorization": "Bearer test-admin-token-only"}).json["pending"]
    assert len(pending) == 1
    user_id = pending[0]["id"]
    assert client.post(f"/admin/api/users/{user_id}/reject", headers={"Authorization": "Bearer test-admin-token-only"}).json["email_blocked"]
    # Même réponse qu'une inscription normale, mais aucun compte n'est recréé.
    assert client.post("/register", data={"csrf_token": token, "email": "refuse@example.net", "password": "long-secret-123"}).status_code == 302
    with app.app_context():
        assert get_db().execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0
        assert get_db().execute("SELECT COUNT(*) FROM admin_audit").fetchone()[0] == 3


def test_csrf_and_pending_account_have_no_rights(app):
    client = app.test_client()
    assert client.post("/register", data={"email": "x@example.net", "password": "long-secret-123"}).status_code == 400
    token = csrf(client)
    assert client.post("/register", data={"csrf_token": token, "email": "x@example.net", "password": "long-secret-123"}).status_code == 302
    assert client.post("/login", data={"csrf_token": token, "email": "x@example.net", "password": "long-secret-123"}).status_code == 403
    assert client.get("/dashboard").status_code == 302


def test_two_users_cannot_read_or_modify_each_others_resources(app):
    alice = app.test_client()
    bob = app.test_client()
    alice_id = register_approve_login(app, alice, "alice@example.net")
    bob_id = register_approve_login(app, bob, "bob@example.net")
    domain_id = add_domain(alice, "alice.example.net")
    assert alice.get("/dashboard").status_code == 200
    assert alice.get(f"/domains/{domain_id}").status_code == 200
    assert alice.post(f"/domains/{domain_id}/records", data={
        "csrf_token": csrf(alice), "name": "_acme-challenge", "type": "TXT",
        "content": "preuve-test", "ttl": "300",
    }).status_code == 302
    with app.app_context():
        db = get_db()
        db.execute("INSERT INTO machines(user_id,name,ip,public_key,created_at) VALUES(?,?,?,?,?)",
                   (alice_id, "salon", "10.88.0.2", "a" * 44, "2026-09-27"))
        db.commit()
        machine_id = db.execute("SELECT id FROM machines WHERE user_id=?", (alice_id,)).fetchone()[0]
        record_id = db.execute("SELECT id FROM records WHERE domain_id=?", (domain_id,)).fetchone()[0]
        assert db.execute("SELECT 1 FROM records WHERE domain_id=? AND name='_acme-challenge'", (domain_id,)).fetchone()
    address = alice.post("/addresses", data={
        "csrf_token": csrf(alice), "domain_id": domain_id, "machine_id": machine_id,
        "name": "nas", "port": "5000", "protected": "1",
    })
    assert address.status_code == 302
    with app.app_context():
        address_id = get_db().execute("SELECT id FROM addresses WHERE hostname='nas.alice.example.net'").fetchone()[0]
    assert bob.get(f"/domains/{domain_id}").status_code == 404
    assert bob.post(f"/domains/{domain_id}/records", data={"csrf_token": csrf(bob), "name": "evil", "type": "A", "content": "1.2.3.4"}).status_code == 404
    assert bob.post(f"/domains/{domain_id}/records/{record_id}/delete", data={"csrf_token": csrf(bob)}).status_code == 404
    assert bob.post(f"/machines/{machine_id}/delete", data={"csrf_token": csrf(bob)}).status_code == 404
    assert bob.post(f"/addresses/{address_id}/delete", data={"csrf_token": csrf(bob)}).status_code == 404
    assert bob.post("/addresses", data={
        "csrf_token": csrf(bob), "domain_id": domain_id, "machine_id": machine_id,
        "name": "evil", "port": "8000",
    }).status_code == 404
    with app.app_context():
        assert get_db().execute("SELECT COUNT(*) FROM addresses WHERE id=?", (address_id,)).fetchone()[0] == 1
        assert get_db().execute("SELECT COUNT(*) FROM domains WHERE user_id=?", (bob_id,)).fetchone()[0] == 0


def test_ask_and_protected_address_callback_is_single_use(app):
    client = app.test_client()
    user_id = register_approve_login(app, client, "owner@example.net")
    domain_id = add_domain(client, "owner.example.net")
    with app.app_context():
        db = get_db()
        db.execute("INSERT INTO machines(user_id,name,ip,public_key,created_at) VALUES(?,?,?,?,?)",
                   (user_id, "home", "10.88.0.2", "b" * 44, "2026-09-27"))
        db.commit()
        machine_id = db.execute("SELECT id FROM machines").fetchone()[0]
    client.post("/addresses", data={
        "csrf_token": csrf(client), "domain_id": domain_id, "machine_id": machine_id,
        "name": "private", "port": "8123", "protected": "1",
    })
    assert client.get("/internal/caddy/ask?domain=unknown.owner.example.net").status_code == 403
    assert client.get("/internal/caddy/ask?domain=private.owner.example.net").status_code == 204
    assert client.get("/internal/caddy/ask?domain=synunnel.fr").status_code == 204
    assert client.get("/internal/caddy/ask?domain=www.synunnel.com").status_code == 204
    browser = app.test_client()
    denied = browser.get("/internal/caddy/auth", base_url="https://private.owner.example.net", headers={"X-Forwarded-Uri": "/hello"})
    assert denied.status_code == 302
    login_page = browser.get("/login", base_url="https://synunnel.fr")
    login_csrf = re.search(rb'name="csrf_token" value="([^"]+)"', login_page.data).group(1).decode()
    approved = browser.post("/login", base_url="https://synunnel.fr", data={
        "csrf_token": login_csrf, "email": "owner@example.net", "password": "mot-de-passe-long-123",
        "next": "https://private.owner.example.net/hello",
    })
    assert approved.status_code == 302
    callback = urlsplit(approved.headers["Location"])
    assert callback.hostname == "private.owner.example.net"
    first = browser.get(callback.path + "?" + callback.query, base_url="https://private.owner.example.net")
    assert first.status_code == 302
    assert first.headers["Location"] == "/hello"
    assert "Secure" in first.headers["Set-Cookie"] and "HttpOnly" in first.headers["Set-Cookie"]
    assert browser.get(callback.path + "?" + callback.query, base_url="https://private.owner.example.net").status_code == 403
    assert browser.get("/internal/caddy/auth", base_url="https://private.owner.example.net").status_code == 204


def test_rate_limit_and_machine_private_key_not_persisted(app):
    client = app.test_client()
    user_id = register_approve_login(app, client, "machine@example.net")
    response = client.post("/machines", data={"csrf_token": csrf(client), "name": "Salon"})
    assert response.status_code == 200
    assert b"PrivateKey = " in response.data
    assert response.headers["Cache-Control"] == "no-store"
    private = re.search(rb"PrivateKey = ([A-Za-z0-9+/=]+)", response.data).group(1)
    with app.app_context():
        row = get_db().execute("SELECT public_key FROM machines WHERE user_id=?", (user_id,)).fetchone()
        assert row is not None
        assert private != row["public_key"].encode()
        assert private not in Path(app.config["DATABASE"]).read_bytes()
    assert private not in client.get("/dashboard").data

    guest = app.test_client()
    token = csrf(guest)
    for _ in range(4):
        assert guest.post("/register", data={"csrf_token": token, "email": "invalide", "password": "x"}).status_code == 400
    assert guest.post("/register", data={"csrf_token": token, "email": "invalide", "password": "x"}).status_code == 429


def test_shared_access_list_revocation_pending_and_other_owner(app):
    owner = app.test_client()
    listed = app.test_client()
    unlisted = app.test_client()
    pending = app.test_client()
    other_owner = app.test_client()
    owner_id = register_approve_login(app, owner, "owner@example.net")
    register_approve_login(app, listed, "listed@example.net")
    register_approve_login(app, unlisted, "unlisted@example.net")
    register_approve_login(app, other_owner, "other@example.net")
    login_dashboard(owner, "owner@example.net")
    login_dashboard(listed, "listed@example.net")
    login_dashboard(unlisted, "unlisted@example.net")
    login_dashboard(other_owner, "other@example.net")
    domain_id = add_domain(owner, "shared.example.net")
    with app.app_context():
        db = get_db()
        machine_id = db.execute(
            "INSERT INTO machines(user_id,name,ip,public_key,created_at) VALUES(?,?,?,?,?)",
            (owner_id, "shared", "10.88.0.2", "c" * 44, "2026-09-27"),
        ).lastrowid
        db.commit()
    assert owner.post("/addresses", data={
        "csrf_token": csrf(owner), "domain_id": domain_id, "machine_id": machine_id,
        "name": "private", "port": "8080", "protected": "1",
    }).status_code == 302
    with app.app_context():
        address_id = get_db().execute(
            "SELECT id FROM addresses WHERE hostname='private.shared.example.net'",
        ).fetchone()[0]
    path = f"/addresses/{address_id}/access"
    assert other_owner.get(path).status_code == 404
    assert other_owner.post(path, data={"csrf_token": csrf(other_owner), "shared": "1",
                                        "emails": "other@example.net"}).status_code == 404
    assert owner.post(path, data={"csrf_token": csrf(owner), "shared": "1",
                                  "emails": "listed@example.net, pending@example.net"}).status_code == 302
    host = "https://private.shared.example.net"
    next_url = host + "/hello"
    approved = listed.get("/login", base_url="https://synunnel.fr", query_string={"next": next_url})
    assert approved.status_code == 302
    callback = urlsplit(approved.headers["Location"])
    assert callback.hostname == "private.shared.example.net"
    assert listed.get(callback.path + "?" + callback.query, base_url=host).status_code == 302
    assert listed.get("/internal/caddy/auth", base_url=host).status_code == 204
    assert owner.get("/login", base_url="https://synunnel.fr", query_string={"next": next_url}).status_code == 302

    assert unlisted.get("/login", base_url="https://synunnel.fr", query_string={"next": next_url}).headers["Location"] == "/dashboard"
    assert other_owner.get("/login", base_url="https://synunnel.fr", query_string={"next": next_url}).headers["Location"] == "/dashboard"
    token = csrf(pending)
    assert pending.post("/register", data={"csrf_token": token, "email": "pending@example.net",
                                           "password": "mot-de-passe-long-123"}).status_code == 302
    assert pending.post("/login", data={"csrf_token": token, "email": "pending@example.net",
                                        "password": "mot-de-passe-long-123", "next": next_url}).status_code == 403
    assert pending.get("/internal/caddy/auth", base_url=host).status_code == 302

    admin = {"Authorization": "Bearer test-admin-token-only"}
    pending_id = next(item["id"] for item in owner.get("/admin/api/pending", headers=admin).json["pending"]
                      if item["email"] == "pending@example.net")
    assert owner.post(f"/admin/api/users/{pending_id}/reject", headers=admin).status_code == 200
    assert pending.post("/login", data={"csrf_token": token, "email": "pending@example.net",
                                        "password": "mot-de-passe-long-123", "next": next_url}).status_code == 401

    assert owner.post(path, data={"csrf_token": csrf(owner), "shared": "1",
                                  "emails": "pending@example.net"}).status_code == 302
    # Le navigateur conserve le cookie d'accès, mais le contrôle relit la liste.
    assert listed.get("/internal/caddy/auth", base_url=host).status_code == 302
    with app.app_context():
        assert get_db().execute(
            "SELECT COUNT(*) FROM host_sessions WHERE hostname=?", ("private.shared.example.net",),
        ).fetchone()[0] == 0


def test_apex_address_keeps_copied_mail_records(app):
    client = app.test_client()
    owner_id = register_approve_login(app, client, "apex@example.net")
    domain_id = add_domain(client, "apex.example.net")
    with app.app_context():
        db = get_db()
        machine_id = db.execute(
            "INSERT INTO machines(user_id,name,ip,public_key,created_at) VALUES(?,?,?,?,?)",
            (owner_id, "landing", "10.88.0.3", "d" * 44, "2026-09-27"),
        ).lastrowid
        db.commit()
    assert client.post("/addresses", data={"csrf_token": csrf(client), "domain_id": domain_id,
                                          "machine_id": machine_id, "name": "@", "port": "18080",
                                          "protected": "1"}).status_code == 302
    with app.app_context():
        db = get_db()
        assert db.execute("SELECT hostname FROM addresses WHERE domain_id=?", (domain_id,)).fetchone()[0] == "apex.example.net"
        assert db.execute("SELECT COUNT(*) FROM records WHERE domain_id=? AND type='MX'", (domain_id,)).fetchone()[0] == 1


def test_domain_needs_txt_proof_and_cannot_be_squatted(app):
    owner = app.test_client()
    squatter = app.test_client()
    register_approve_login(app, owner, "owner@example.net")
    register_approve_login(app, squatter, "squatter@example.net")
    squat_claim, squat_proof = claim_domain(squatter, "victime.example")
    # Sans l'enregistrement TXT dans le DNS du domaine, aucune zone n'est créée.
    response = squatter.post(f"/claims/{squat_claim}/verify", data={"csrf_token": csrf(squatter)})
    assert "/claims/" in response.headers["Location"]
    with app.app_context():
        assert get_db().execute("SELECT COUNT(*) FROM domains").fetchone()[0] == 0
    # La preuve d'un autre compte ne vaut rien pour le squatteur.
    owner_claim, owner_proof = claim_domain(owner, "victime.example")
    assert owner_proof != squat_proof
    PROOFS["victime.example"] = {owner_proof}
    squatter.post(f"/claims/{squat_claim}/verify", data={"csrf_token": csrf(squatter)})
    with app.app_context():
        assert get_db().execute("SELECT COUNT(*) FROM domains").fetchone()[0] == 0
    assert squatter.get(f"/claims/{owner_claim}").status_code == 404
    response = owner.post(f"/claims/{owner_claim}/verify", data={"csrf_token": csrf(owner)})
    assert "/domains/" in response.headers["Location"]
    with app.app_context():
        db = get_db()
        assert db.execute("SELECT u.email FROM domains d JOIN users u ON u.id=d.user_id").fetchone()[0] == "owner@example.net"
        assert db.execute("SELECT COUNT(*) FROM domain_claims").fetchone()[0] == 0


def test_instance_domains_are_reserved(app):
    client = app.test_client()
    register_approve_login(app, client, "reserve@example.net")
    for name in ("synunnel.fr", "x.synunnel.fr", "www.synunnel.com"):
        response = client.post("/domains", data={
            "csrf_token": csrf(client), "domain": name, "mail_checked": "1", "selectors": "",
        })
        assert response.headers["Location"].endswith("/dashboard")
    with app.app_context():
        assert get_db().execute("SELECT COUNT(*) FROM domain_claims").fetchone()[0] == 0


def test_register_does_not_reveal_existing_accounts(app):
    client = app.test_client()
    data = {"csrf_token": csrf(client), "email": "deja@example.net", "password": "long-secret-123"}
    first = client.post("/register", data=data)
    second = client.post("/register", data=data)
    assert first.status_code == second.status_code == 302
    assert first.headers["Location"] == second.headers["Location"]


def test_logout_closes_protected_address_sessions(app):
    client = app.test_client()
    user_id = register_approve_login(app, client, "sortie@example.net")
    with app.app_context():
        db = get_db()
        db.execute("INSERT INTO host_sessions(token_hash,user_id,hostname,expires_at) VALUES(?,?,?,?)",
                   ("x" * 64, user_id, "nas.example.net", 4102444800))
        db.commit()
    assert client.post("/logout", data={"csrf_token": csrf(client)}).status_code == 302
    with app.app_context():
        assert get_db().execute("SELECT COUNT(*) FROM host_sessions").fetchone()[0] == 0
