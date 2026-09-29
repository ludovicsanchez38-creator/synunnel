# ruff: noqa: F811  (les fixtures viennent de test_app)
"""Relevé de délégation et refus de suppression : constats 1 à 3 de la revue Codex du 29/09/2026."""

import dns.flags
import dns.message
import dns.name
import dns.rcode
import dns.rrset
import pytest
from test_app import add_domain, app, register_approve_login  # noqa: F401

from synunnel import dns as synunnel_dns

DOMAIN = "client.example."
OURS = ("ns1.synunnel.fr.", "ns2.synunnel.fr.")


def _response(rcode=dns.rcode.NOERROR, authority=(), answer=(), truncated=False, authoritative=False):
    response = dns.message.make_response(dns.message.make_query(DOMAIN, "NS"))
    if authoritative:
        response.flags |= dns.flags.AA
    response.set_rcode(rcode)
    for section, rrsets in ((response.authority, authority), (response.answer, answer)):
        for name, kind, *values in rrsets:
            section.append(dns.rrset.from_text(name, 3600, "IN", kind, *values))
    if truncated:
        response.flags |= dns.flags.TC
    return response


@pytest.fixture
def parent(monkeypatch):
    """Zone parente fictive : deux serveurs publics, et la réponse que chacun donnera à la question NS
    (`response` pour tous, ou `by_server` pour les faire diverger)."""
    state = {"response": None, "by_server": {}, "udp_calls": 0, "fallback_calls": 0, "asked": []}
    addresses = {"a.nic.example.": "9.9.9.9", "b.nic.example.": "149.112.112.112"}

    class Target:
        def __init__(self, name):
            self.target = dns.name.from_text(name)

    def resolve(name, kind, lifetime=None):
        return [Target(host) for host in addresses] if kind == "NS" else [addresses[str(name)]]

    def udp(query, where, timeout=None, **kwargs):
        state["udp_calls"] += 1
        return state["response"]

    def udp_with_fallback(query, where, timeout=None, **kwargs):
        state["fallback_calls"] += 1
        state["asked"].append(where)
        return state["by_server"].get(where, state["response"]), False

    monkeypatch.setattr("dns.resolver.resolve", resolve)
    monkeypatch.setattr("dns.query.udp", udp)
    monkeypatch.setattr("dns.query.udp_with_fallback", udp_with_fallback)
    return state


def test_complete_delegation_is_active(parent):
    parent["response"] = _response(authority=[(DOMAIN, "NS", *OURS)])
    assert synunnel_dns.delegation_status("client.example", OURS) == (True, sorted(OURS))


@pytest.mark.parametrize("rcode", [dns.rcode.SERVFAIL, dns.rcode.REFUSED, dns.rcode.FORMERR])
def test_parent_error_is_unknown_never_a_proof_of_removal(parent, rcode):
    parent["response"] = _response(rcode=rcode)
    assert synunnel_dns.delegation_status("client.example", OURS)[0] is None


def test_truncated_answer_is_retried_over_tcp_and_never_read_as_complete(parent):
    parent["response"] = _response(authority=[(DOMAIN, "NS", "ns.ailleurs.net.")], truncated=True)
    assert synunnel_dns.delegation_status("client.example", OURS)[0] is None
    # La question passe par la reprise TCP de dnspython, jamais par UDP seul.
    assert parent["fallback_calls"] >= 1 and parent["udp_calls"] == 0


def test_ns_records_of_another_name_prove_nothing(parent):
    parent["response"] = _response(authority=[("autre.example.", "NS", "ns.ailleurs.net.")])
    assert synunnel_dns.delegation_status("client.example", OURS)[0] is None


PARENT_SOA = ("example.", "SOA", "a.nic.example. h.example. 1 2 3 4 5")


def test_authoritative_answer_without_delegation_and_with_the_parent_soa_is_a_removal(parent):
    parent["response"] = _response(authority=[PARENT_SOA], authoritative=True)
    assert synunnel_dns.delegation_status("client.example", OURS) == (False, [])
    parent["response"] = _response(rcode=dns.rcode.NXDOMAIN, authority=[PARENT_SOA], authoritative=True)
    assert synunnel_dns.delegation_status("client.example", OURS) == (False, [])


@pytest.mark.parametrize("response", [
    # Réponse négative sans le bit AA : elle ne vient pas d'un serveur qui fait autorité.
    lambda: _response(rcode=dns.rcode.NXDOMAIN),
    lambda: _response(rcode=dns.rcode.NXDOMAIN, authority=[PARENT_SOA]),
    lambda: _response(authority=[PARENT_SOA]),
    # SOA d'une autre zone que la parente (la racine), même avec AA.
    lambda: _response(authority=[(".", "SOA", "a.root. h.root. 1 2 3 4 5")], authoritative=True),
    # NS du domaine dans la section réponse, sans AA : une réponse de cache, qui ne prouve rien.
    lambda: _response(answer=[(DOMAIN, "NS", "ns1.hebergeur.net.")]),
], ids=["nxdomain-sans-aa", "nxdomain-soa-sans-aa", "nodata-sans-aa", "soa-racine", "ns-de-cache"])
def test_negative_or_cached_answers_without_authority_prove_nothing(parent, response):
    parent["response"] = response()
    assert synunnel_dns.delegation_status("client.example", OURS)[0] is None


def test_delegation_to_another_host_only_is_a_removal(parent):
    parent["response"] = _response(authority=[(DOMAIN, "NS", "ns1.hebergeur.net.", "ns2.hebergeur.net.")])
    assert synunnel_dns.delegation_status("client.example", OURS) == (False, ["ns1.hebergeur.net.",
                                                                             "ns2.hebergeur.net."])


def test_authoritative_answer_of_the_child_zone_proves_nothing_about_the_parent(parent):
    """Constat 14 : un serveur de la parente qui héberge aussi l'enfant répond pour l'enfant (AA, section
    réponse) ; la délégation de la parente peut encore désigner l'instance."""
    parent["response"] = _response(answer=[(DOMAIN, "NS", "ns1.hebergeur.net.")], authoritative=True)
    assert synunnel_dns.delegation_status("client.example", OURS)[0] is None


def test_every_parent_server_is_asked_and_a_disagreement_is_unknown(parent):
    """Constat 15 : un seul serveur de la parente ne décide plus ; un désaccord vaut indéterminé."""
    removed = _response(authority=[(DOMAIN, "NS", "ns1.hebergeur.net.")])
    parent["by_server"] = {"9.9.9.9": removed, "149.112.112.112": _response(authority=[(DOMAIN, "NS", *OURS)])}
    status, seen = synunnel_dns.delegation_status("client.example", OURS)
    assert sorted(parent["asked"]) == ["149.112.112.112", "9.9.9.9"]
    assert synunnel_dns.still_designated(status, seen, OURS) is not False
    parent["by_server"] = {"9.9.9.9": removed, "149.112.112.112": _response(rcode=dns.rcode.SERVFAIL)}
    assert synunnel_dns.delegation_status("client.example", OURS)[0] is None
    parent["by_server"] = {}
    parent["response"] = removed
    assert synunnel_dns.delegation_status("client.example", OURS) == (False, ["ns1.hebergeur.net."])


def _domain_exists(app, domain_id: int) -> bool:
    from synunnel.db import get_db
    with app.app_context():
        return get_db().execute("SELECT 1 FROM domains WHERE id=?", (domain_id,)).fetchone() is not None


def test_partial_delegation_still_blocks_deletion(app, monkeypatch):
    """Constat 1 : un seul serveur de l'instance encore désigné suffit à refuser."""
    from test_api import bearer, create_token

    client = app.test_client()
    register_approve_login(app, client, "partielle@example.org")
    domain_id = add_domain(client, "partielle.example")
    token = create_token(client)
    monkeypatch.setattr("synunnel.actions.delegation_status",
                        lambda domain, ns: (False, ["ns.hebergeur.net.", "ns1.synunnel.fr."]))
    refused = client.delete(f"/api/v1/domains/{domain_id}", headers=bearer(token))
    assert refused.status_code == 409 and refused.json["error"]["code"] == "delegation_active"
    assert _domain_exists(app, domain_id)


def test_deletion_decides_on_its_own_observation_not_on_a_cache_rewritten_meanwhile(app, monkeypatch):
    """Constat 3 : un relevé plus ancien qui termine après celui de la suppression ne la débloque pas."""
    from test_api import bearer, create_token

    from synunnel import actions
    from synunnel.db import get_db

    client = app.test_client()
    register_approve_login(app, client, "course@example.org")
    domain_id = add_domain(client, "course.example")
    token = create_token(client)
    monkeypatch.setattr("synunnel.actions.delegation_status", lambda domain, ns: (True, list(OURS)))
    original = actions.refresh_delegation

    def refresh_then_stale_writer(app_, domain):
        result = original(app_, domain)
        db = get_db()
        with db:  # un relevé engagé plus tôt, qui termine maintenant et écrit « non délégué »
            db.execute("UPDATE domains SET delegation_active=0 WHERE id=?", (domain["id"],))
        return result

    monkeypatch.setattr("synunnel.actions.refresh_delegation", refresh_then_stale_writer)
    refused = client.delete(f"/api/v1/domains/{domain_id}", headers=bearer(token))
    assert refused.status_code == 409 and refused.json["error"]["code"] == "delegation_active"
    assert _domain_exists(app, domain_id)


def test_an_older_observation_never_overwrites_a_newer_one(app):
    from synunnel import actions
    from synunnel.db import get_db

    client = app.test_client()
    register_approve_login(app, client, "ordre@example.org")
    domain_id = add_domain(client, "ordre.example")
    with app.app_context():
        db = get_db()
        with db:
            db.execute("UPDATE domains SET delegation_active=1, delegation_checked_at=? WHERE id=?",
                       (4102444800, domain_id))
        domain = db.execute("SELECT * FROM domains WHERE id=?", (domain_id,)).fetchone()
        actions.refresh_delegation(app, domain)  # relevé courant (False) plus ancien que celui en base
        assert db.execute("SELECT delegation_active FROM domains WHERE id=?", (domain_id,)).fetchone()[0] == 1
