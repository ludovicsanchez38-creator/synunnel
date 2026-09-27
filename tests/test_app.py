"""Tests du parcours d'autorisation et des frontières entre comptes."""

import re
from pathlib import Path
from urllib.parse import urlsplit

import pytest

from synunnel import create_app
from synunnel.db import get_db


@pytest.fixture
def app(tmp_path, monkeypatch):
    app = create_app({
        "TESTING": True,
        "SECRET_KEY": "test-secret-only",
        "ADMIN_TOKEN": "test-admin-token-only",
        "DATABASE": str(tmp_path / "synunnel.db"),
        "PDNS_ENABLED": False,
        "SYNC_COMMAND": "",
        "WG_SERVER_PUBLIC_KEY": "test-server-public-key",
    })
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


def add_domain(client, name: str) -> int:
    response = client.post("/domains", data={
        "csrf_token": csrf(client), "domain": name, "mail_checked": "1", "selectors": "",
    })
    assert response.status_code == 302
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
    assert client.post("/register", data={"csrf_token": token, "email": "refuse@example.net", "password": "long-secret-123"}).status_code == 403
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
    assert client.get("/internal/caddy/ask?domain=synunnel.synoptia.fr").status_code == 204
    browser = app.test_client()
    denied = browser.get("/internal/caddy/auth", base_url="https://private.owner.example.net", headers={"X-Forwarded-Uri": "/hello"})
    assert denied.status_code == 302
    login_page = browser.get("/login", base_url="https://synunnel.synoptia.fr")
    login_csrf = re.search(rb'name="csrf_token" value="([^"]+)"', login_page.data).group(1).decode()
    approved = browser.post("/login", base_url="https://synunnel.synoptia.fr", data={
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
