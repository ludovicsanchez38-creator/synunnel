"""Non-régression des sept bloquants relevés par l'UltraJury du 29/09/2026 avant la mise en production de la 0.2."""
# ruff: noqa: F811

import re

from test_app import add_domain, app, claim_domain, register_approve_login  # noqa: F401

TITLE = re.compile(r"<title>(.*?)</title>", re.DOTALL)


def test_page_titles_never_contain_markup_or_csrf_token(app):
    """Bloquant 1 : le bloc title de domain.html avalait la section de suppression et le jeton CSRF."""
    client = app.test_client()
    anonymous = ["/login", "/register", "/forgot", "/reset", "/recover"]
    for path in anonymous:
        body = client.get(path).data.decode()
        titles = TITLE.findall(body)
        assert titles, path
        for title in titles:
            assert "<" not in title and "csrf" not in title.lower(), (path, title[:120])
    register_approve_login(app, client, "titres@example.org")
    domain_id = add_domain(client, "titres.example")
    claim_id, _proof = claim_domain(client, "autre-titre.example")
    for path in ["/dashboard", "/tokens", "/security", f"/domains/{domain_id}", f"/claims/{claim_id}"]:
        response = client.get(path)
        assert response.status_code == 200, path
        for title in TITLE.findall(response.data.decode()):
            assert "<" not in title and "csrf" not in title.lower(), (path, title[:120])


COUNTED = ("attempts", "guest_quota", "guest_challenges", "login_challenges", "password_resets", "security_events",
           "users")


def _counts(app) -> dict:
    from synunnel.db import get_db
    with app.app_context():
        db = get_db()
        return {table: db.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] for table in COUNTED}


def test_head_behaves_like_get_and_writes_nothing(app):
    """Bloquant 2 : HEAD passait dans la branche POST des vues, hors du contrôle CSRF."""
    paths = ["/login", "/register", "/forgot", "/reset?token=abc", "/recover", "/security/email/confirm?token=abc",
             "/access/code?next=https%3A%2F%2Fnas.example%2F", "/access/verify", "/login/2fa", "/__synunnel/logout"]
    client = app.test_client()
    before = _counts(app)
    for path in paths:
        get = client.get(path)
        head = client.head(path)
        assert head.status_code == get.status_code, (path, get.status_code, head.status_code)
        assert head.data == b"", path
    # Une session qui porte un challenge de connexion : HEAD ne doit ni consommer ni compter un essai.
    with client.session_transaction() as state:
        state["challenge"] = "challenge-fictif"
    assert client.head("/login/2fa").status_code == client.get("/login/2fa").status_code
    assert _counts(app) == before


def test_csrf_is_required_for_every_method_except_safe_ones(app):
    client = app.test_client()
    for method in ("POST", "PUT", "PATCH", "DELETE"):
        response = client.open("/forgot", method=method, data={"email": "x@example.org"})
        assert response.status_code in {400, 405}, (method, response.status_code)
        if method == "POST":
            assert response.status_code == 400


def test_dependencies_are_pinned_patched_and_installed_from_the_lock():
    """Bloquant 3 : cryptography < 47 (7 avis connus) et installation hors verrou, outils de dev compris."""
    import tomllib
    from pathlib import Path

    root = Path(__file__).resolve().parent.parent
    lock = {p["name"]: p["version"] for p in tomllib.loads((root / "uv.lock").read_text())["package"]}
    pinned = dict(re.findall(r"^([A-Za-z0-9_.-]+)==([^\s\;]+)", (root / "requirements.lock").read_text(), re.MULTILINE))
    assert pinned, "requirements.lock vide"
    for name, version in pinned.items():
        assert lock.get(name) == version, f"{name} : {version} dans requirements.lock, {lock.get(name)} dans uv.lock"
    major, minor, patch = (int(x) for x in pinned["cryptography"].split(".")[:3])
    assert (major, minor, patch) >= (50, 0, 1)
    assert "--hash=sha256:" in (root / "requirements.lock").read_text()
    for dev in ("pytest", "ruff"):
        assert dev not in pinned
    installer = (root / "scripts" / "install.sh").read_text()
    assert "--require-hashes" in installer and "requirements.lock" in installer
    assert "[dev]" not in installer and "install -e" not in installer


ADMIN = {"Authorization": "Bearer test-admin-token-only"}


def test_admin_api_is_refused_through_the_public_proxy(app):
    """Bloquant 4 : l'API d'administration ne répond qu'en local, jamais à travers Caddy."""
    client = app.test_client()
    assert client.get("/admin/api/pending", headers=ADMIN).status_code == 200
    for proxied in ({"X-Real-IP": "203.0.113.9"}, {"X-Forwarded-For": "203.0.113.9"}):
        response = client.get("/admin/api/pending", headers={**ADMIN, **proxied})
        assert response.status_code == 404, proxied


def test_admin_limiter_applies_before_the_token_comparison(app):
    client = app.test_client()
    for _ in range(20):
        assert client.get("/admin/api/pending", headers={"Authorization": "Bearer mauvais"}).status_code == 401
    # Au-delà du plafond, même le bon jeton attend : la comparaison n'est plus tentée.
    assert client.get("/admin/api/pending", headers=ADMIN).status_code == 429


def test_caddy_template_hides_admin_api_on_the_public_name():
    import importlib.util
    from pathlib import Path

    root = Path(__file__).resolve().parent.parent
    spec = importlib.util.spec_from_file_location("render_caddy", root / "scripts" / "render-caddy.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    rendered = module.render_caddy((root / "config" / "Caddyfile").read_text(), "synunnel.fr", "", "admin@example.org")
    block = rendered.split("handle @synunnel_dashboard {", 1)[1].split("# __REDIRECT", 1)[0]
    admin = block.index("path /admin/*")
    assert block.index("respond 404", admin) < block.index("reverse_proxy 127.0.0.1:8000")


def test_post_without_csrf_token_is_still_refused_on_every_form(app):
    client = app.test_client()
    for path in ["/login", "/register", "/forgot", "/reset", "/recover", "/security/email/confirm", "/access/code",
                 "/access/verify", "/login/2fa", "/__synunnel/logout"]:
        assert client.post(path, data={"email": "x@example.org"}).status_code == 400, path
    before = _counts(app)
    for _ in range(20):
        client.head("/forgot")
        client.head("/access/code?next=https%3A%2F%2Fnas.example%2F")
    assert _counts(app) == before


def test_totp_secret_sealed_with_cryptography_46_still_opens_after_the_upgrade():
    """Bloquant 3 : un secret chiffré en production sous cryptography 46.0.7 reste lisible en 50.x."""
    from synunnel import security

    sealed_by_46 = "v1:AAECAwQFBgcICQoLItGFJ06VAswtiOKt95vCEP6ZOVjlAmxBE+9+WY2EorzBB9uw"
    assert security.decrypt_secret(bytes.fromhex("11" * 32), 42, sealed_by_46) == b"12345678901234567890"
