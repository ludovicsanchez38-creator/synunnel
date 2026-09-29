# ruff: noqa: F811  (les fixtures viennent de test_api et test_guest)
"""Constat 6 de la revue Codex : une requête HEAD n'émet ni ne consomme de code d'accès."""

import re
from urllib.parse import quote, urlsplit

from test_api import app  # noqa: F401
from test_guest import (  # noqa: F401
    HOST,
    ask_code,
    codes_in,
    flush,
    mails,
    protected_address,
    verify,
)

from synunnel.db import get_db

TABLES = ("access_codes", "guest_access_codes", "host_sessions", "guest_host_sessions")


def _counts(app) -> dict:
    with app.app_context():
        return {table: get_db().execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] for table in TABLES}


def test_head_on_login_with_next_issues_no_access_code(app):
    owner, _ = protected_address(app)
    target = "/login?next=" + quote(f"https://{HOST}/tableau", safe="")
    before = _counts(app)
    assert owner.head(target).status_code == 302
    assert _counts(app) == before
    assert owner.get(target).status_code == 302 and _counts(app)["access_codes"] == before["access_codes"] + 1


def test_head_on_the_callback_consumes_no_account_code(app):
    owner, _ = protected_address(app)
    issued = owner.get("/login?next=" + quote(f"https://{HOST}/tableau", safe=""))
    callback = urlsplit(issued.headers["Location"])
    assert callback.path == "/__synunnel/auth/callback"
    host = app.test_client()
    before = _counts(app)
    host.head(f"{callback.path}?{callback.query}", base_url=f"https://{HOST}")
    assert _counts(app) == before
    entered = host.get(f"{callback.path}?{callback.query}", base_url=f"https://{HOST}")
    assert entered.status_code == 302 and entered.headers["Location"] == "/tableau"


def test_head_on_the_callback_consumes_no_guest_transfer_code(app, mails):
    protected_address(app)
    visitor = app.test_client()
    assert ask_code(visitor).status_code == 302
    flush(app)
    relay = verify(visitor, codes_in(mails)[-1])
    link = re.search(r'href="([^"]+)">Continuer', relay.get_data(as_text=True)).group(1).replace("&amp;", "&")
    callback = urlsplit(link)
    host = app.test_client()
    before = _counts(app)
    host.head(f"{callback.path}?{callback.query}", base_url=f"https://{HOST}")
    assert _counts(app) == before
    entered = host.get(f"{callback.path}?{callback.query}", base_url=f"https://{HOST}")
    assert entered.status_code == 302 and entered.headers["Location"] == "/tableau?x=1"
