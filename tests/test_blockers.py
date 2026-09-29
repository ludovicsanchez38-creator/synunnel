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
