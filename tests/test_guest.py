# ruff: noqa: F811  (la fixture app vient de test_api)
"""Accès invité par code envoyé par mail (design docs/design/acces-invite-code-mail.md, v2)."""

import re
from pathlib import Path
from urllib.parse import urlsplit

import pytest
from test_api import account, app, bearer, create_token, key  # noqa: F401
from test_app import add_domain, csrf

from synunnel.db import get_db

ROOT = Path(__file__).resolve().parents[1]
ADMIN = {"Authorization": "Bearer test-admin-token-only"}
HOST = "nas.hote.example.net"
GUEST = "invite@example.org"


@pytest.fixture
def clock(monkeypatch):
    state = {"now": 1_790_000_010.0}
    monkeypatch.setattr("synunnel.account._now", lambda: state["now"])
    monkeypatch.setattr("synunnel.guest._now", lambda: state["now"])
    return state


@pytest.fixture
def mails(app):
    sent = []
    app.config["MAIL_TRANSPORT"] = sent.append
    return sent


def flush(app) -> None:
    app.extensions["synunnel_mailer"].flush(5)


def codes_in(mails) -> list[str]:
    return [re.search(r"\b(\d{6})\b", message.get_content()).group(1) for message in mails]


def protected_address(app, owner_email: str = "proprio@example.net", guests=(GUEST,), option: bool = True):
    owner = account(app, owner_email)
    domain_id = add_domain(owner, "hote.example.net")
    with app.app_context():
        db = get_db()
        uid = db.execute("SELECT id FROM users WHERE email=?", (owner_email,)).fetchone()[0]
        db.execute("INSERT INTO machines(id,user_id,name,ip,public_key,created_at) VALUES(950,?,?,?,?,?)",
                   (uid, "nas", "10.88.0.50", key(50), "x"))
        db.commit()
    owner.post("/addresses", data={"csrf_token": csrf(owner), "domain_id": domain_id, "machine_id": 950,
                                    "name": "nas", "port": "5000", "protected": "1"})
    with app.app_context():
        address_id = get_db().execute("SELECT id FROM addresses WHERE hostname=?", (HOST,)).fetchone()[0]
    set_access(owner, address_id, guests, option)
    return owner, address_id


def set_access(owner, address_id: int, guests, option: bool):
    data = {"csrf_token": csrf(owner), "shared": "1" if guests else "", "emails": "\n".join(guests)}
    if option:
        data["guest_codes"] = "1"
    response = owner.post(f"/addresses/{address_id}/access", data=data)
    assert response.status_code == 302


def route(app) -> str:
    with app.app_context():
        return get_db().execute("SELECT route_token FROM addresses WHERE hostname=?", (HOST,)).fetchone()[0]


def ask_code(client, email: str = GUEST, host: str = HOST):
    target = f"https://{host}/tableau?x=1"
    page = client.get("/access/code", query_string={"next": target})
    assert page.status_code == 200 and page.headers["Cache-Control"] == "no-store"
    return client.post("/access/code", data={"csrf_token": csrf(client), "email": email, "next": target})


def verify(client, code: str):
    return client.post("/access/verify", data={"csrf_token": csrf(client), "code": code})


def enter(app, client, code: str):
    """Code saisi, puis le relais vers l'hôte : renvoie le navigateur de l'hôte, avec son cookie."""
    relay = verify(client, code)
    assert relay.status_code == 200, relay.get_data(as_text=True)[:300]
    link = re.search(r'href="([^"]+)">Continuer', relay.get_data(as_text=True)).group(1).replace("&amp;", "&")
    target = urlsplit(link)
    assert target.hostname == HOST and target.path == "/__synunnel/auth/callback"
    host_browser = app.test_client()
    back = host_browser.get(f"{target.path}?{target.query}", base_url=f"https://{HOST}")
    assert back.status_code == 302 and back.headers["Location"] == "/tableau?x=1"
    return host_browser


def allowed(app, browser) -> bool:
    return browser.get(f"/internal/caddy/auth?route={route(app)}", base_url=f"https://{HOST}").status_code == 204


def guest_session(app, client, mails):
    assert ask_code(client).status_code == 302
    flush(app)
    return enter(app, client, codes_in(mails)[-1])


# ------------------------------------------------------------------ parcours

def test_guest_receives_a_code_and_enters(app, mails, clock):
    protected_address(app)
    visitor = app.test_client()
    answer = ask_code(visitor)
    assert answer.status_code == 302 and answer.headers["Location"].endswith("/access/verify")
    flush(app)
    assert [message["To"] for message in mails] == [GUEST]
    assert mails[0]["Subject"] == f"Ton code d'accès à {HOST}"
    body = mails[0].get_content()
    assert "https://" not in body and "Si tu n'as rien demandé, ignore ce mail." in body
    browser = enter(app, visitor, codes_in(mails)[0])
    cookie = browser.get_cookie("__Host-synunnel-access", domain=HOST)
    assert cookie is not None and cookie.secure and cookie.http_only
    assert allowed(app, browser)


def test_code_is_stored_as_a_mac_only(app, mails, clock):
    protected_address(app)
    ask_code(app.test_client())
    flush(app)
    code = codes_in(mails)[0]
    with app.app_context():
        rows = [dict(row) for row in get_db().execute("SELECT * FROM guest_challenges")]
    assert rows and all(code not in str(value) for row in rows for value in row.values())


def test_same_answer_whoever_asks(app, mails, clock):
    _owner, _address_id = protected_address(app, guests=(GUEST, "bloque@example.org", "compte@example.org"))
    account(app, "compte@example.org")
    with app.app_context():
        db = get_db()
        db.execute("INSERT INTO blocked_emails(email,blocked_at) VALUES('bloque@example.org','x')")
        db.commit()
    answers = [ask_code(app.test_client(), email) for email in
               (GUEST, "inconnu@example.org", "bloque@example.org", "compte@example.org", "proprio@example.net")]
    assert {(answer.status_code, answer.headers["Location"]) for answer in answers} == {(302, answers[0].headers["Location"])}
    flush(app)
    assert [message["To"] for message in mails] == [GUEST]  # ni inconnu, ni bloqué, ni compte, ni propriétaire


def test_disabled_option_sends_nothing_and_is_the_default(app, mails, clock):
    _owner, _address_id = protected_address(app, option=False)
    with app.app_context():
        assert get_db().execute("SELECT guest_codes FROM addresses").fetchone()[0] == 0
    assert ask_code(app.test_client()).status_code == 302
    flush(app)
    assert mails == []


def test_dummy_challenge_is_never_exchangeable(app, mails, clock):
    owner, address_id = protected_address(app, guests=("autre@example.org",))
    visitor = app.test_client()
    ask_code(visitor)  # GUEST n'est pas invité : challenge factice
    set_access(owner, address_id, ("autre@example.org", GUEST), True)
    for code in ("000000", "123456", "999999"):
        assert verify(visitor, code).status_code == 400
    flush(app)
    assert mails == []


def test_five_failures_kill_the_challenge_and_the_daily_budget(app, mails, clock):
    protected_address(app)
    visitor = app.test_client()
    ask_code(visitor)
    flush(app)
    code = codes_in(mails)[0]
    wrong = "000000" if code != "000000" else "111111"
    for _ in range(5):
        assert verify(visitor, wrong).status_code == 400
    assert verify(visitor, code).status_code == 400  # challenge mort après 5 échecs
    # Budget cumulatif : 5 échecs en 24 h pour ce couple, les nouveaux challenges sont factices.
    again = app.test_client()
    assert ask_code(again).status_code == 302
    flush(app)
    assert len(mails) == 1
    clock["now"] += 86401
    later = app.test_client()
    ask_code(later)
    flush(app)
    assert len(mails) == 2


def test_code_expires_after_ten_minutes(app, mails, clock):
    protected_address(app)
    visitor = app.test_client()
    ask_code(visitor)
    flush(app)
    clock["now"] += 601
    assert verify(visitor, codes_in(mails)[0]).status_code == 400


def test_a_code_opens_only_once(app, mails, clock):
    protected_address(app)
    visitor = app.test_client()
    ask_code(visitor)
    flush(app)
    with visitor.session_transaction() as state:
        saved = dict(state)
    code = codes_in(mails)[0]
    enter(app, visitor, code)
    replay = app.test_client()
    with replay.session_transaction() as state:
        state.update(saved)
    assert verify(replay, code).status_code == 400


def test_request_quotas_keep_the_same_answer(app, mails, clock):
    protected_address(app)
    visitor = app.test_client()
    statuses = [ask_code(visitor).status_code for _ in range(7)]
    assert statuses == [302] * 7
    flush(app)
    assert len(mails) == 3  # au plus 3 challenges vivants par couple, puis factices
    for n in range(3):
        ask_code(visitor, f"x{n}@example.org")
    assert ask_code(visitor, "encore@example.org").status_code == 429  # 10 demandes par heure et par IP


def test_grant_removed_then_restored_kills_old_sessions_and_challenges(app, mails, clock):
    owner, address_id = protected_address(app)
    first = app.test_client()
    browser = guest_session(app, first, mails)
    assert allowed(app, browser)
    pending = app.test_client()
    ask_code(pending)
    flush(app)
    set_access(owner, address_id, ("autre@example.org",), True)
    set_access(owner, address_id, ("autre@example.org", GUEST), True)
    assert not allowed(app, browser)
    assert verify(pending, codes_in(mails)[-1]).status_code == 400


def test_owner_suspension_then_reapproval_revives_nothing(app, mails, clock):
    owner, _address_id = protected_address(app)
    browser = guest_session(app, app.test_client(), mails)
    with app.app_context():
        uid = get_db().execute("SELECT id FROM users WHERE email='proprio@example.net'").fetchone()[0]
    assert owner.post(f"/admin/api/users/{uid}/suspend", headers=ADMIN).status_code == 200
    assert owner.post(f"/admin/api/users/{uid}/approve", headers=ADMIN,
                      json={"email": "proprio@example.net"}).status_code == 200
    assert not allowed(app, browser)


def test_option_disabled_at_each_step(app, mails, clock):
    owner, address_id = protected_address(app)
    browser = guest_session(app, app.test_client(), mails)
    pending = app.test_client()
    ask_code(pending)
    flush(app)
    set_access(owner, address_id, (GUEST,), False)
    assert not allowed(app, browser)
    assert verify(pending, codes_in(mails)[-1]).status_code == 400


def test_guest_who_gets_an_account_loses_the_guest_path(app, mails, clock):
    protected_address(app)
    browser = guest_session(app, app.test_client(), mails)
    account(app, GUEST)
    assert not allowed(app, browser)


def test_require_2fa_cuts_guest_codes_unless_explicitly_allowed(app, mails, clock):
    protected_address(app)
    browser = guest_session(app, app.test_client(), mails)
    app.config["REQUIRE_2FA"] = True
    assert not allowed(app, browser)
    ask_code(app.test_client())
    flush(app)
    assert len(mails) == 1
    app.config["GUEST_CODES_WITH_2FA"] = True
    assert allowed(app, browser)


def test_guest_session_is_bound_to_its_host(app, mails, clock):
    protected_address(app)
    browser = guest_session(app, app.test_client(), mails)
    token = browser.get_cookie("__Host-synunnel-access", domain=HOST).value
    other = app.test_client()
    other.set_cookie("__Host-synunnel-access", token, domain="autre.hote.example.net", secure=True)
    assert other.get(f"/internal/caddy/auth?route={route(app)}", base_url="https://autre.hote.example.net").status_code != 204


def test_guest_logout_by_post_and_cookie_replay(app, mails, clock):
    protected_address(app)
    browser = guest_session(app, app.test_client(), mails)
    token = browser.get_cookie("__Host-synunnel-access", domain=HOST).value
    page = browser.get("/__synunnel/logout", base_url=f"https://{HOST}")
    assert page.status_code == 200 and page.headers["Cache-Control"] == "no-store"
    form_token = re.search(r'name="csrf_token" value="([^"]+)"', page.get_data(as_text=True)).group(1)
    refused = browser.post("/__synunnel/logout", base_url=f"https://{HOST}", data={"csrf_token": "faux"})
    assert refused.status_code == 400 and allowed(app, browser)
    out = browser.post("/__synunnel/logout", base_url=f"https://{HOST}", data={"csrf_token": form_token})
    assert out.status_code == 200 and "__Host-synunnel-access=;" in out.headers["Set-Cookie"]
    replay = app.test_client()
    replay.set_cookie("__Host-synunnel-access", token, domain=HOST, secure=True)
    assert not allowed(app, replay)


def test_smtp_failure_changes_nothing_in_the_answer(app, clock):
    protected_address(app)

    def broken(message):
        raise OSError("SMTP injoignable")

    app.config["MAIL_TRANSPORT"] = broken
    assert ask_code(app.test_client()).status_code == 302
    flush(app)


def test_access_page_offers_codes_only_with_mail(app, mails):
    owner, address_id = protected_address(app, option=False)
    page = owner.get(f"/addresses/{address_id}/access").get_data(as_text=True)
    assert 'name="guest_codes"' in page and "Un seul facteur" in page
    del app.config["MAIL_TRANSPORT"]
    page = owner.get(f"/addresses/{address_id}/access").get_data(as_text=True)
    assert 'name="guest_codes"' not in page


def test_login_page_offers_the_code_path_for_guest_addresses(app, mails):
    protected_address(app)
    page = app.test_client().get("/login", query_string={"next": f"https://{HOST}/"}).get_data(as_text=True)
    assert "Recevoir un code par mail" in page
    assert "Recevoir un code par mail" not in app.test_client().get("/login").get_data(as_text=True)


def test_published_hosts_only_reach_their_reserved_paths(app, mails):
    protected_address(app)
    for path in ("/dashboard", "/login", "/api/v1/me", "/access/code"):
        assert app.test_client().get(path, base_url=f"https://{HOST}").status_code == 404, path


# ------------------------------------------------------------------ API et Caddy

def test_api_sets_and_reads_the_guest_option(app, mails):
    owner, address_id = protected_address(app, option=False)
    token = create_token(owner)
    client = app.test_client()
    put = client.put(f"/api/v1/addresses/{address_id}/access", headers=bearer(token),
                     json={"shared": True, "emails": [GUEST], "guest_codes": True})
    assert put.status_code == 200 and put.json["guest_codes"] is True
    assert client.get(f"/api/v1/addresses/{address_id}/access", headers=bearer(token)).json["guest_codes"] is True
    # Champ absent : l'option garde sa valeur.
    kept = client.put(f"/api/v1/addresses/{address_id}/access", headers=bearer(token),
                      json={"shared": True, "emails": [GUEST, "b@example.org"]})
    assert kept.json["guest_codes"] is True
    spec = client.get("/api/v1/openapi.json").json
    body = spec["paths"]["/addresses/{address_id}/access"]["put"]["requestBody"]["content"]["application/json"]["schema"]
    assert body["properties"]["guest_codes"]["type"] == "boolean"
