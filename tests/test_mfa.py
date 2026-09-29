# ruff: noqa: F811  (la fixture app vient de test_api)
"""Double authentification, mot de passe oublié et récupération (design v2 du 29/09/2026)."""

import base64
import re
import stat
from pathlib import Path

import pytest
from conftest import instance_config
from test_api import PASSWORD, account, app, bearer, create_token  # noqa: F401
from test_app import csrf

from synunnel import create_app, security
from synunnel.db import get_db

ADMIN = {"Authorization": "Bearer test-admin-token-only"}
NEW_PASSWORD = "nouveau-mot-de-passe-456"


@pytest.fixture
def clock(monkeypatch):
    state = {"now": 1_790_000_010.0}
    monkeypatch.setattr("synunnel.account._now", lambda: state["now"])
    return state


@pytest.fixture
def mails(app):
    sent = []
    app.config["MAIL_TRANSPORT"] = sent.append
    return sent


def flush(app) -> None:
    app.extensions["synunnel_mailer"].flush(5)


def secret_bytes(b32: str) -> bytes:
    return base64.b32decode(b32 + "=" * (-len(b32) % 8))


def totp(b32: str, clock, offset: int = 0) -> str:
    return security.code_at(secret_bytes(b32), security.current_step(clock["now"]) + offset)


def user_id(app, email: str) -> int:
    with app.app_context():
        return get_db().execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()[0]


def start_enrollment(client, password: str = PASSWORD):
    page = client.post("/security/2fa/start", data={"csrf_token": csrf(client), "password": password})
    text = page.get_data(as_text=True)
    secret = re.search(r'id="totp-secret">([A-Z2-7 ]+)<', text)
    enrollment = re.search(r'name="enrollment" value="([^"]+)"', text)
    return page, (secret.group(1).replace(" ", "") if secret else None), (enrollment.group(1) if enrollment else None)


def enroll(client, clock) -> tuple[str, list[str]]:
    page, secret, enrollment = start_enrollment(client)
    assert page.status_code == 200 and secret and enrollment
    clock["now"] += 30
    done = client.post("/security/2fa/confirm", data={"csrf_token": csrf(client), "enrollment": enrollment,
                                                      "code": totp(secret, clock)})
    assert done.status_code == 200, done.get_data(as_text=True)[:500]
    codes = re.findall(r'<li class="recovery-code">([A-Z2-7-]+)</li>', done.get_data(as_text=True))
    assert len(codes) == 10
    return secret, codes


def password_step(client, email: str, password: str = PASSWORD, next_url: str = ""):
    return client.post("/login", data={"csrf_token": csrf(client), "email": email, "password": password,
                                       "next": next_url})


def login_2fa(client, email: str, secret: str, clock, next_url: str = ""):
    first = password_step(client, email, next_url=next_url)
    assert first.status_code == 302 and first.headers["Location"].endswith("/login/2fa")
    clock["now"] += 30
    return client.post("/login/2fa", data={"csrf_token": csrf(client), "code": totp(secret, clock)})


def signed_in(client) -> bool:
    return client.get("/dashboard").status_code == 200


# ------------------------------------------------------------------ primitives

def test_totp_rfc6238_vectors():
    secret = b"12345678901234567890"
    # Vecteurs SHA-1 de la RFC 6238, annexe B (six derniers chiffres).
    for moment, expected in ((59, "287082"), (1111111109, "081804"), (1111111111, "050471"),
                             (1234567890, "005924"), (2000000000, "279037"), (20000000000, "353130")):
        assert security.code_at(secret, security.current_step(moment)) == expected


def test_matching_step_window_and_strict_format():
    secret = security.new_secret()
    now = 1_790_000_010.0
    center = security.current_step(now)
    for offset in (-1, 0, 1):
        assert security.matching_step(secret, security.code_at(secret, center + offset), now) == center + offset
    assert security.matching_step(secret, security.code_at(secret, center + 2), now) is None
    good = security.code_at(secret, center)
    for bad in (good[:5], " " + good, good + "\n", "１２３４５６", None, 123456):
        assert security.matching_step(secret, bad, now) is None


def test_secret_encryption_is_bound_to_user_and_key():
    key, other = bytes(range(32)), bytes(32)
    secret = security.new_secret()
    sealed = security.encrypt_secret(key, 7, secret)
    assert sealed.startswith("v1:") and security.decrypt_secret(key, 7, sealed) == secret
    assert security.encrypt_secret(key, 7, secret) != sealed  # nonce unique
    for attempt in ((other, 7, sealed), (key, 8, sealed), (key, 7, sealed[:-4] + "AAAA"), (key, 7, "clair")):
        with pytest.raises(security.SecretUnavailable):
            security.decrypt_secret(*attempt)


def test_recovery_codes_have_100_bits_and_normalize():
    codes = security.new_recovery_codes()
    assert len(codes) == 10 and len(set(codes)) == 10
    assert all(re.fullmatch(r"[A-Z2-7]{20}", code) for code in codes)
    shown = security.format_recovery(codes[0])
    assert shown.count("-") == 3 and security.normalize_recovery(shown.lower()) == codes[0]
    assert security.normalize_recovery("ABCDE") is None


def test_totp_key_is_required():
    config = instance_config(SECRET_KEY="s", ADMIN_TOKEN="a", DATABASE=":memory:", TOTP_KEY="")
    with pytest.raises((RuntimeError, ValueError)):
        create_app(config)


# ------------------------------------------------------------------ activation

def test_enrollment_needs_password_and_a_valid_first_code(app, clock):
    client = account(app, "moi@example.net")
    refused, secret, _ = start_enrollment(client, password="mauvais-mot-de-passe")
    assert secret is None and refused.status_code in (302, 401)
    page, secret, enrollment = start_enrollment(client)
    assert page.headers["Cache-Control"] == "no-store" and "<svg" in page.get_data(as_text=True)
    clock["now"] += 30
    wrong = client.post("/security/2fa/confirm", data={"csrf_token": csrf(client), "enrollment": enrollment,
                                                       "code": "000000" if totp(secret, clock) != "000000" else "111111"})
    assert wrong.status_code == 401
    with app.app_context():
        assert get_db().execute("SELECT totp_enabled_at FROM users").fetchone()[0] is None
    done = client.post("/security/2fa/confirm", data={"csrf_token": csrf(client), "enrollment": enrollment,
                                                      "code": totp(secret, clock)})
    assert done.status_code == 200 and done.headers["Cache-Control"] == "no-store"
    with app.app_context():
        row = get_db().execute("SELECT totp_enabled_at, totp_secret_enc FROM users").fetchone()
    assert row[0] and row[1].startswith("v1:")
    # Ni le secret en base32 ni ses octets n'apparaissent en clair dans la base.
    raw = b"".join(Path(app.config["DATABASE"] + suffix).read_bytes() for suffix in ("", "-wal")
                   if Path(app.config["DATABASE"] + suffix).exists())
    assert secret.encode() not in raw and secret_bytes(secret) not in raw
    assert signed_in(client)


def test_second_tab_enrollment_invalidates_the_first(app, clock):
    client = account(app, "onglets@example.net")
    _, first_secret, first_id = start_enrollment(client)
    _, second_secret, second_id = start_enrollment(client)
    clock["now"] += 30
    stale = client.post("/security/2fa/confirm", data={"csrf_token": csrf(client), "enrollment": first_id,
                                                       "code": totp(first_secret, clock)})
    assert stale.status_code in (302, 409)
    with app.app_context():
        assert get_db().execute("SELECT totp_enabled_at FROM users").fetchone()[0] is None
    ok = client.post("/security/2fa/confirm", data={"csrf_token": csrf(client), "enrollment": second_id,
                                                    "code": totp(second_secret, clock)})
    assert ok.status_code == 200


def test_enrollment_expires(app, clock):
    client = account(app, "lent@example.net")
    _, secret, enrollment = start_enrollment(client)
    clock["now"] += 601
    late = client.post("/security/2fa/confirm", data={"csrf_token": csrf(client), "enrollment": enrollment,
                                                      "code": totp(secret, clock)})
    assert late.status_code in (302, 409)


# ------------------------------------------------------------------ connexion

def test_login_is_two_steps_and_partial_session_has_no_rights(app, clock):
    client = account(app, "deux@example.net")
    secret, _ = enroll(client, clock)
    browser = app.test_client()
    first = password_step(browser, "deux@example.net")
    assert first.status_code == 302 and first.headers["Location"].endswith("/login/2fa")
    for path in ("/dashboard", "/tokens", "/security"):
        assert browser.get(path).status_code == 302
    assert browser.get("/login/2fa").status_code == 200
    clock["now"] += 30
    bad = browser.post("/login/2fa", data={"csrf_token": csrf(browser), "code": totp(secret, clock, offset=5)})
    assert bad.status_code == 401 and not signed_in(browser)
    good = browser.post("/login/2fa", data={"csrf_token": csrf(browser), "code": totp(secret, clock)})
    assert good.status_code == 302 and signed_in(browser)


def test_a_code_is_never_accepted_twice(app, clock):
    client = account(app, "rejeu@example.net")
    secret, _ = enroll(client, clock)
    clock["now"] += 30
    code = totp(secret, clock)
    one, two = app.test_client(), app.test_client()
    assert password_step(one, "rejeu@example.net").status_code == 302
    assert password_step(two, "rejeu@example.net").status_code == 302
    assert one.post("/login/2fa", data={"csrf_token": csrf(one), "code": code}).status_code == 302
    assert two.post("/login/2fa", data={"csrf_token": csrf(two), "code": code}).status_code == 401
    # Un code du pas suivant, accepté en avance, ferme aussi le pas courant.
    clock["now"] += 30
    ahead = totp(secret, clock, offset=1)
    three = app.test_client()
    assert password_step(three, "rejeu@example.net").status_code == 302
    assert three.post("/login/2fa", data={"csrf_token": csrf(three), "code": ahead}).status_code == 302
    four = app.test_client()
    assert password_step(four, "rejeu@example.net").status_code == 302
    assert four.post("/login/2fa", data={"csrf_token": csrf(four), "code": totp(secret, clock)}).status_code == 401


def test_recovery_code_logs_in_once(app, clock):
    client = account(app, "secours@example.net")
    _, codes = enroll(client, clock)
    for expected in (302, 401):
        browser = app.test_client()
        assert password_step(browser, "secours@example.net").status_code == 302
        response = browser.post("/login/2fa", data={"csrf_token": csrf(browser), "code": codes[0].lower()})
        assert response.status_code == expected


def test_protected_address_login_keeps_next_through_second_factor(app, clock):
    client = account(app, "suite@example.net")
    secret, _ = enroll(client, clock)
    first = password_step(app.test_client(), "suite@example.net", next_url="https://ailleurs.example/")
    assert first.status_code == 302  # un « next » refusé ne bloque pas la connexion
    browser = app.test_client()
    done = login_2fa(browser, "suite@example.net", secret, clock)
    assert done.status_code == 302 and done.headers["Location"].endswith("/dashboard")


# ------------------------------------------------------------------ désactivation, codes, mot de passe

def test_disable_needs_password_and_code(app, clock):
    client = account(app, "retrait@example.net")
    secret, _ = enroll(client, clock)
    other = app.test_client()
    assert login_2fa(other, "retrait@example.net", secret, clock).status_code == 302
    clock["now"] += 30
    refused = client.post("/security/2fa/disable", data={"csrf_token": csrf(client), "password": "faux-mot-de-passe",
                                                         "code": totp(secret, clock)})
    assert refused.status_code in (302, 401)
    with app.app_context():
        assert get_db().execute("SELECT totp_enabled_at FROM users").fetchone()[0]
    done = client.post("/security/2fa/disable", data={"csrf_token": csrf(client), "password": PASSWORD,
                                                      "code": totp(secret, clock)})
    assert done.status_code == 302
    with app.app_context():
        assert get_db().execute("SELECT totp_enabled_at FROM users").fetchone()[0] is None
        assert get_db().execute("SELECT COUNT(*) FROM recovery_codes").fetchone()[0] == 0
    assert signed_in(client) and not signed_in(other)


def test_regenerating_recovery_codes_retires_the_old_ones(app, clock):
    client = account(app, "regen@example.net")
    secret, old = enroll(client, clock)
    clock["now"] += 30
    page = client.post("/security/recovery-codes", data={"csrf_token": csrf(client), "password": PASSWORD,
                                                         "code": totp(secret, clock)})
    assert page.status_code == 200 and page.headers["Cache-Control"] == "no-store"
    new = re.findall(r'<li class="recovery-code">([A-Z2-7-]+)</li>', page.get_data(as_text=True))
    assert len(new) == 10 and not set(new) & set(old)
    browser = app.test_client()
    assert password_step(browser, "regen@example.net").status_code == 302
    assert browser.post("/login/2fa", data={"csrf_token": csrf(browser), "code": old[1]}).status_code == 401
    assert browser.post("/login/2fa", data={"csrf_token": csrf(browser), "code": new[1]}).status_code == 302


def test_change_password_needs_code_and_revokes_everything(app, clock):
    client = account(app, "change@example.net")
    secret, _ = enroll(client, clock)
    clock["now"] += 30
    token = create_token(client, code=totp(secret, clock))
    assert token and client.get("/api/v1/me", headers=bearer(token)).status_code == 200
    other = app.test_client()
    assert login_2fa(other, "change@example.net", secret, clock).status_code == 302
    no_code = client.post("/security/password", data={"csrf_token": csrf(client), "password": PASSWORD,
                                                      "new_password": NEW_PASSWORD})
    assert no_code.status_code in (302, 401)
    clock["now"] += 30
    done = client.post("/security/password", data={"csrf_token": csrf(client), "password": PASSWORD,
                                                   "new_password": NEW_PASSWORD, "code": totp(secret, clock)})
    assert done.status_code == 302
    assert signed_in(client) and not signed_in(other)
    assert client.get("/api/v1/me", headers=bearer(token)).status_code == 401
    assert password_step(app.test_client(), "change@example.net").status_code == 401
    browser = app.test_client()
    assert password_step(browser, "change@example.net", password=NEW_PASSWORD).headers["Location"].endswith("/login/2fa")


def test_token_creation_requires_the_second_factor(app, clock):
    client = account(app, "jeton@example.net")
    secret, _ = enroll(client, clock)
    assert create_token(client) is None
    clock["now"] += 30
    assert create_token(client, code=totp(secret, clock))


# ------------------------------------------------------------------ REQUIRE_2FA

def test_require_2fa_limits_accounts_without_factor(app, clock):
    client = account(app, "oblige@example.net")
    token = create_token(client)
    assert client.get("/api/v1/me", headers=bearer(token)).status_code == 200
    app.config["REQUIRE_2FA"] = True
    # Session, jeton et page déjà ouverts : plus rien ne passe sans facteur.
    assert client.get("/dashboard").headers["Location"].endswith("/security")
    assert client.get("/security").status_code == 200
    refused = client.get("/api/v1/me", headers=bearer(token))
    assert refused.status_code == 403 and refused.json["error"]["code"] == "mfa_required"
    fresh = app.test_client()
    assert password_step(fresh, "oblige@example.net").headers["Location"].endswith("/security")
    assert fresh.get("/tokens").headers["Location"].endswith("/security")
    enroll(fresh, clock)
    assert signed_in(fresh)
    assert fresh.get("/api/v1/me", headers=bearer(token)).status_code == 401  # révoqué à l'activation


# ------------------------------------------------------------------ récupération par l'administrateur

def test_admin_recovery_ticket_removes_factor_only_when_used(app, clock):
    client = account(app, "perdu@example.net")
    enroll(client, clock)
    uid = user_id(app, "perdu@example.net")
    assert client.post(f"/admin/api/users/{uid}/recovery", headers=ADMIN,
                       json={"email": "autre@example.net", "scope": "2fa"}).status_code == 404
    assert client.post(f"/admin/api/users/{uid}/recovery", headers=ADMIN,
                       json={"email": "perdu@example.net", "scope": "tout"}).status_code == 422
    issued = client.post(f"/admin/api/users/{uid}/recovery", headers=ADMIN,
                         json={"email": "perdu@example.net", "scope": "2fa"})
    assert issued.status_code == 200 and len(issued.json["ticket"]) >= 43
    # Émettre le ticket ne retire rien : le mot de passe seul ne suffit toujours pas.
    assert password_step(app.test_client(), "perdu@example.net").headers["Location"].endswith("/login/2fa")
    visitor = app.test_client()
    page = visitor.get("/recover")
    assert page.status_code == 200 and page.headers["Cache-Control"] == "no-store"
    wrong = visitor.post("/recover", data={"csrf_token": csrf(visitor), "email": "perdu@example.net",
                                           "ticket": issued.json["ticket"], "password": "faux-mot-de-passe"})
    assert wrong.status_code == 400
    used = visitor.post("/recover", data={"csrf_token": csrf(visitor), "email": "perdu@example.net",
                                          "ticket": issued.json["ticket"], "password": PASSWORD})
    assert used.status_code == 302
    assert not signed_in(client)
    again = visitor.post("/recover", data={"csrf_token": csrf(visitor), "email": "perdu@example.net",
                                           "ticket": issued.json["ticket"], "password": PASSWORD})
    assert again.status_code == 400
    browser = app.test_client()
    assert password_step(browser, "perdu@example.net").headers["Location"].endswith("/dashboard")


def test_admin_password_ticket_keeps_the_factor(app, clock):
    client = account(app, "oubli@example.net")
    enroll(client, clock)
    uid = user_id(app, "oubli@example.net")
    ticket = client.post(f"/admin/api/users/{uid}/recovery", headers=ADMIN,
                         json={"email": "oubli@example.net", "scope": "password"}).json["ticket"]
    visitor = app.test_client()
    short = visitor.post("/recover", data={"csrf_token": csrf(visitor), "email": "oubli@example.net",
                                           "ticket": ticket, "new_password": "court"})
    assert short.status_code == 400
    done = visitor.post("/recover", data={"csrf_token": csrf(visitor), "email": "oubli@example.net",
                                          "ticket": ticket, "new_password": NEW_PASSWORD})
    assert done.status_code == 302
    browser = app.test_client()
    assert password_step(browser, "oubli@example.net", password=NEW_PASSWORD).headers["Location"].endswith("/login/2fa")


def test_admin_can_mark_an_address_verified(app):
    client = account(app, "verif@example.net")
    uid = user_id(app, "verif@example.net")
    assert client.post(f"/admin/api/users/{uid}/verify-email", headers=ADMIN,
                       json={"email": "autre@example.net"}).status_code == 404
    assert client.post(f"/admin/api/users/{uid}/verify-email", headers=ADMIN,
                       json={"email": "verif@example.net"}).status_code == 200
    with app.app_context():
        assert get_db().execute("SELECT email_verified_at FROM users WHERE id=?", (uid,)).fetchone()[0]


# ------------------------------------------------------------------ mot de passe oublié par mail

def verified_account(app, email: str):
    client = account(app, email)
    uid = user_id(app, email)
    assert client.post(f"/admin/api/users/{uid}/verify-email", headers=ADMIN, json={"email": email}).status_code == 200
    return client


def forgot(client, email: str):
    return client.post("/forgot", data={"csrf_token": csrf(client), "email": email})


def reset_link(message) -> str:
    body = message.get_content()
    return re.search(r"https://\S+/reset\?token=[A-Za-z0-9_-]+", body).group(0)


def test_forgot_is_generic_and_mail_goes_to_verified_addresses_only(app, mails):
    verified_account(app, "boite@example.net")
    account(app, "nonverifiee@example.net")
    visitor = app.test_client()
    answers = [forgot(visitor, email) for email in ("boite@example.net", "nonverifiee@example.net",
                                                     "inconnu@example.net")]
    assert {answer.status_code for answer in answers} == {302}
    assert len({answer.headers["Location"] for answer in answers}) == 1
    flush(app)
    assert [message["To"] for message in mails] == ["boite@example.net"]
    assert mails[0]["From"].endswith("<noreply@synunnel.fr>") or "noreply" in mails[0]["From"]
    assert reset_link(mails[0]).startswith("https://synunnel.fr/reset?token=")


def test_forgot_link_ignores_the_host_header(app, mails):
    verified_account(app, "hote@example.net")
    visitor = app.test_client()
    sent = visitor.post("/forgot", data={"csrf_token": csrf(visitor), "email": "hote@example.net"},
                        headers={"X-Forwarded-Host": "piege.example"})
    assert sent.status_code == 302
    flush(app)
    assert reset_link(mails[0]).startswith("https://synunnel.fr/")


def test_forgot_limits_keep_the_generic_answer(app, mails):
    verified_account(app, "quota@example.net")
    visitor = app.test_client()
    statuses = [forgot(visitor, "quota@example.net").status_code for _ in range(5)]
    assert statuses == [302] * 5
    flush(app)
    assert len(mails) == 3  # au-delà de 3 demandes par heure et par adresse : réponse générique, pas de mail
    assert forgot(visitor, "quota@example.net").status_code == 429  # 5 par heure et par adresse IP


def test_forgot_answer_does_not_wait_for_smtp(app):
    verified_account(app, "panne@example.net")

    def broken(message):
        raise OSError("serveur SMTP injoignable")

    app.config["MAIL_TRANSPORT"] = broken
    visitor = app.test_client()
    assert forgot(visitor, "panne@example.net").status_code == 302
    flush(app)


def test_reset_by_mail_link(app, mails, clock):
    client = verified_account(app, "lien@example.net")
    secret, _ = enroll(client, clock)
    clock["now"] += 30
    token = create_token(client, code=totp(secret, clock))
    visitor = app.test_client()
    forgot(visitor, "lien@example.net")
    flush(app)
    link = reset_link(mails[-1])
    value = link.rsplit("=", 1)[1]
    page = visitor.get(link.replace("https://synunnel.fr", ""))
    assert page.status_code == 200 and page.headers["Cache-Control"] == "no-store"
    assert visitor.get(link.replace("https://synunnel.fr", "")).status_code == 200  # le GET ne consomme rien
    wrong = visitor.post("/reset", data={"csrf_token": csrf(visitor), "token": value, "email": "autre@example.net",
                                         "password": NEW_PASSWORD})
    assert wrong.status_code == 400
    done = visitor.post("/reset", data={"csrf_token": csrf(visitor), "token": value, "email": "lien@example.net",
                                        "password": NEW_PASSWORD})
    assert done.status_code == 302 and not signed_in(visitor)
    assert not signed_in(client)
    assert client.get("/api/v1/me", headers=bearer(token)).status_code == 401
    again = visitor.post("/reset", data={"csrf_token": csrf(visitor), "token": value, "email": "lien@example.net",
                                         "password": NEW_PASSWORD})
    assert again.status_code == 400
    # La double authentification reste exigée après une réinitialisation par mail.
    browser = app.test_client()
    assert password_step(browser, "lien@example.net", password=NEW_PASSWORD).headers["Location"].endswith("/login/2fa")
    flush(app)
    assert any("mot de passe" in message["Subject"].lower() for message in mails[1:])  # notification


def test_reset_link_expires_and_dies_with_a_password_change(app, mails, clock):
    client = verified_account(app, "expire@example.net")
    visitor = app.test_client()
    forgot(visitor, "expire@example.net")
    forgot(visitor, "expire@example.net")
    flush(app)
    late, stale = (reset_link(message).rsplit("=", 1)[1] for message in mails[:2])
    clock["now"] += 30
    client.post("/security/password", data={"csrf_token": csrf(client), "password": PASSWORD,
                                            "new_password": NEW_PASSWORD})
    assert visitor.post("/reset", data={"csrf_token": csrf(visitor), "token": stale, "email": "expire@example.net",
                                        "password": "encore-un-autre-789"}).status_code == 400
    forgot(visitor, "expire@example.net")
    flush(app)
    fresh = reset_link(mails[-1]).rsplit("=", 1)[1]
    clock["now"] += 31 * 60
    assert visitor.post("/reset", data={"csrf_token": csrf(visitor), "token": fresh, "email": "expire@example.net",
                                        "password": "encore-un-autre-789"}).status_code == 400
    assert late


def test_email_verification_from_the_account(app, mails, clock):
    client = account(app, "moi-meme@example.net")
    assert client.post("/security/email", data={"csrf_token": csrf(client), "password": "faux-mot-de-passe"}
                       ).status_code in (302, 401)
    assert client.post("/security/email", data={"csrf_token": csrf(client), "password": PASSWORD}).status_code == 302
    flush(app)
    link = re.search(r"https://synunnel\.fr(/security/email/confirm\?token=[A-Za-z0-9_-]+)",
                     mails[-1].get_content()).group(1)
    visitor = app.test_client()
    assert visitor.get(link).status_code == 200
    with app.app_context():
        assert get_db().execute("SELECT email_verified_at FROM users").fetchone()[0] is None
    value = link.rsplit("=", 1)[1]
    assert visitor.post("/security/email/confirm", data={"csrf_token": csrf(visitor), "token": value}).status_code == 302
    with app.app_context():
        assert get_db().execute("SELECT email_verified_at FROM users").fetchone()[0]


# ------------------------------------------------------------------ hygiène

def test_no_secret_in_the_session_cookie(app, clock):
    client = account(app, "cookie@example.net")
    _, secret, enrollment = start_enrollment(client)
    serializer = app.session_interface.get_signing_serializer(app)
    cookie = client.get_cookie(app.config["SESSION_COOKIE_NAME"]).value
    content = str(serializer.loads(cookie))
    assert secret not in content and enrollment not in content
    clock["now"] += 30
    done = client.post("/security/2fa/confirm", data={"csrf_token": csrf(client), "enrollment": enrollment,
                                                      "code": totp(secret, clock)})
    codes = re.findall(r'<li class="recovery-code">([A-Z2-7-]+)</li>', done.get_data(as_text=True))
    content = str(serializer.loads(client.get_cookie(app.config["SESSION_COOKIE_NAME"]).value))
    assert not any(code in content or code.replace("-", "") in content for code in codes)


def test_security_pages_are_not_cached(app):
    client = account(app, "cache@example.net")
    for path in ("/security", "/forgot", "/recover", "/reset?token=x"):
        assert client.get(path).headers["Cache-Control"] == "no-store", path


def test_database_files_are_private(app):
    client = account(app, "droits@example.net")
    assert client.get("/dashboard").status_code == 200
    for suffix in ("", "-wal", "-shm"):
        path = Path(app.config["DATABASE"] + suffix)
        if path.exists():
            assert stat.S_IMODE(path.stat().st_mode) == 0o600, suffix


def test_unreadable_secret_fails_closed(app, clock):
    client = account(app, "cle@example.net")
    secret, _ = enroll(client, clock)
    app.config["TOTP_KEY_BYTES"] = bytes(32)  # clé changée : le secret ne se déchiffre plus
    browser = app.test_client()
    assert password_step(browser, "cle@example.net").status_code == 302
    clock["now"] += 30
    assert browser.post("/login/2fa", data={"csrf_token": csrf(browser), "code": totp(secret, clock)}).status_code == 401
    assert not signed_in(browser)
