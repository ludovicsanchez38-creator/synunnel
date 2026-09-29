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
    state = {"response": None, "by_server": {}, "udp_calls": 0, "fallback_calls": 0, "asked": [], "slow": set()}
    addresses = {"a.nic.example.": "9.9.9.9", "b.nic.example.": "149.112.112.112"}
    state["addresses"] = addresses

    class Target:
        def __init__(self, name):
            self.target = dns.name.from_text(name)

    def resolve(name, kind, lifetime=None):
        import time

        if kind == "NS":
            time.sleep(state.get("discovery", 0))
            return [Target(host) for host in addresses]
        return [addresses[str(name)]]

    def udp(query, where, timeout=None, **kwargs):
        state["udp_calls"] += 1
        return state["response"]

    def udp_with_fallback(query, where, timeout=None, **kwargs):
        import time

        state["fallback_calls"] += 1
        state["asked"].append(where)
        if where in state["slow"]:
            time.sleep(1)
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


def test_reconcile_rechecks_the_delegation_before_removing_a_pending_zone(app, monkeypatch):
    """Constat 10 : une suppression dont le retrait PowerDNS a échoué était rejouée sans nouveau relevé, même
    si la délégation était revenue vers l'instance entre-temps."""
    import runpy
    from pathlib import Path

    from synunnel.db import get_db, init_db

    def pending(name):
        with app.app_context():
            return get_db().execute("SELECT 1 FROM zone_removals WHERE name=?", (name,)).fetchone() is not None

    with app.app_context():
        init_db()
        db = get_db()
        with db:
            for name in ("revenue.example", "douteuse.example", "partie.example"):
                db.execute("INSERT INTO zone_removals(name,at) VALUES(?,'2026-09-29T00:00:00')", (name,))
    states = {"revenue.example": (True, list(OURS)), "douteuse.example": (None, []),
              "partie.example": (False, ["ns1.hebergeur.net."])}
    monkeypatch.setattr("synunnel.create_app", lambda: app)
    reconcile = runpy.run_path(str(Path(__file__).resolve().parent.parent / "scripts/reconcile.py"))
    monkeypatch.setitem(reconcile["main"].__globals__, "create_app", lambda: app)
    monkeypatch.setitem(reconcile["main"].__globals__, "project_runtime", lambda _app: True)
    monkeypatch.setitem(reconcile["main"].__globals__, "delegation_status", lambda domain, ns: states[domain])
    reconcile["main"]()
    assert pending("revenue.example") and pending("douteuse.example") and not pending("partie.example")


def _five_parents(parent):
    parent["addresses"].update({"c.nic.example.": "8.8.8.8", "d.nic.example.": "8.8.4.4",
                                "e.nic.example.": "1.1.1.1"})


def test_every_parent_server_is_asked_even_beyond_four(parent):
    """Troisième passe Codex, constat 15 : quatre serveurs montraient le retrait, le cinquième désignait
    encore l'instance et n'était jamais interrogé."""
    _five_parents(parent)
    parent["response"] = _response(authority=[(DOMAIN, "NS", "ns1.hebergeur.net.")])
    parent["by_server"] = {"1.1.1.1": _response(authority=[(DOMAIN, "NS", *OURS)])}
    status, seen = synunnel_dns.delegation_status("client.example", OURS)
    assert len(set(parent["asked"])) == 5
    assert synunnel_dns.still_designated(status, seen, OURS) is True


def test_a_parent_server_too_slow_makes_the_delegation_unknown(parent, monkeypatch):
    _five_parents(parent)
    monkeypatch.setattr("synunnel.dns.DELEGATION_DEADLINE", 0.3)
    parent["response"] = _response(authority=[(DOMAIN, "NS", "ns1.hebergeur.net.")])
    parent["slow"] = {"8.8.4.4"}
    assert synunnel_dns.delegation_status("client.example", OURS)[0] is None


def test_complete_only_when_every_parent_lists_every_instance_server(parent):
    """Constat 21 : un parent qui ne cite que NS1 et un autre que NS2 ne font pas une délégation complète."""
    parent["by_server"] = {"9.9.9.9": _response(authority=[(DOMAIN, "NS", OURS[0])]),
                           "149.112.112.112": _response(authority=[(DOMAIN, "NS", OURS[1])])}
    status, seen = synunnel_dns.delegation_status("client.example", OURS)
    assert status is False and synunnel_dns.still_designated(status, seen, OURS) is True


def _run_reconcile(app, monkeypatch, **overrides):
    import runpy
    from pathlib import Path

    monkeypatch.setattr("synunnel.create_app", lambda: app)
    reconcile = runpy.run_path(str(Path(__file__).resolve().parent.parent / "scripts/reconcile.py"))
    glob = reconcile["main"].__globals__
    monkeypatch.setitem(glob, "create_app", lambda: app)
    monkeypatch.setitem(glob, "project_runtime", lambda _app: True)
    for key, value in overrides.items():
        monkeypatch.setitem(glob, key, value)
    reconcile["main"]()
    return glob


def test_forced_admin_removal_is_completed_even_while_still_delegated(app, monkeypatch):
    """Troisième passe Codex, constat 16 : après un échec PowerDNS, la reprise perdait le caractère forcé du
    retrait décidé par l'administrateur et gardait la zone tant qu'elle était déléguée."""
    from synunnel.db import get_db, init_db

    client = app.test_client()
    register_approve_login(app, client, "forcee@example.org")
    add_domain(client, "forcee.example")
    monkeypatch.setattr("synunnel.actions.remove_zone", lambda app_, name, generation=None: False)  # PowerDNS en échec
    reply = client.post("/admin/api/domains/delete", json={"name": "forcee.example"},
                        headers={"Authorization": "Bearer test-admin-token-only"})
    assert reply.status_code == 200 and reply.json["synced"] is False
    monkeypatch.undo()
    with app.app_context():
        init_db()
        db = get_db()
        assert db.execute("SELECT forced FROM zone_removals WHERE name='forcee.example'").fetchone()[0] == 1
        with db:
            db.execute("INSERT INTO zone_removals(name,at) VALUES('normale.example','2026-09-29T00:00:00')")
    _run_reconcile(app, monkeypatch, delegation_status=lambda domain, ns: (True, list(OURS)))
    with app.app_context():
        names = {row[0] for row in get_db().execute("SELECT name FROM zone_removals")}
    assert names == {"normale.example"}


def test_pending_removals_cannot_starve_the_active_zones(app, monkeypatch):
    """Troisième passe Codex, constat 17 : des retraits dont les relevés traînent consommaient tout le budget
    du rapprochement, sans qu'aucune zone active ne soit projetée."""
    import time as real_time

    from synunnel.db import get_db, init_db

    client = app.test_client()
    register_approve_login(app, client, "active@example.org")
    add_domain(client, "active.example")
    with app.app_context():
        init_db()
        db = get_db()
        with db:
            for index in range(30):
                db.execute("INSERT INTO zone_removals(name,at) VALUES(?,'2026-09-29T00:00:00')",
                           (f"retrait{index}.example",))
    clock = {"now": 0.0}

    class VirtualTime:
        @staticmethod
        def monotonic():
            return clock["now"]

        @staticmethod
        def time():
            return real_time.time()

    checks, projected = [], []

    def slow_status(domain, ns):
        clock["now"] += 10  # quatre serveurs parents injoignables : chaque relevé traîne
        checks.append(domain)
        return None, []

    glob = _run_reconcile(app, monkeypatch, time=VirtualTime, delegation_status=slow_status,
                          project_zone=lambda app_, domain: projected.append(domain["name"]) or True,
                          refresh_delegation=lambda app_, domain: None)
    assert projected == ["active.example"]
    assert len(checks) <= glob["REMOVAL_BUDGET_SECONDS"] // 10 + 1


def test_owner_deletion_can_be_reserved_to_the_administrator_without_touching_the_code(app):
    """Option prête pour l'alpha, sans bascule par défaut : OWNER_DOMAIN_DELETION=0 réserve la suppression
    d'un domaine à l'administrateur (tableau de bord et API) ; par défaut, le titulaire garde la main."""
    from test_api import bearer, create_token
    from test_app import csrf

    assert app.config["OWNER_DOMAIN_DELETION"] is True
    app.config["OWNER_DOMAIN_DELETION"] = False
    client = app.test_client()
    register_approve_login(app, client, "reserve@example.org")
    domain_id = add_domain(client, "reserve.example")
    token = create_token(client)
    refused = client.delete(f"/api/v1/domains/{domain_id}", headers=bearer(token))
    assert refused.status_code == 403 and refused.json["error"]["code"] == "admin_only"
    page = client.get(f"/domains/{domain_id}/delete").data.decode()
    assert 'name="confirm_name"' not in page and "administrateur" in page
    client.post(f"/domains/{domain_id}/delete", data={"csrf_token": csrf(client), "confirm_name": "reserve.example"})
    assert _domain_exists(app, domain_id)
    forced = client.post("/admin/api/domains/delete", json={"name": "reserve.example"},
                         headers={"Authorization": "Bearer test-admin-token-only"})
    assert forced.status_code == 200 and not _domain_exists(app, domain_id)



def test_delegation_deadline_counts_from_the_start_discovery_included(parent, monkeypatch):
    """Quatrième passe Codex, constat 23 : le délai « global » ne partait qu'après la découverte des
    serveurs parents."""
    import time

    monkeypatch.setattr("synunnel.dns.DELEGATION_DEADLINE", 0.4)
    parent["discovery"] = 0.3
    parent["response"] = _response(authority=[(DOMAIN, "NS", "ns1.hebergeur.net.")])
    parent["slow"] = {"9.9.9.9"}
    started = time.monotonic()
    assert synunnel_dns.delegation_status("client.example", OURS)[0] is None
    assert time.monotonic() - started < 0.6


def test_a_stale_removal_authorisation_never_erases_a_newer_incarnation(app, monkeypatch):
    """Quatrième passe Codex, constat 22 : un retrait forcé lu au début du rapprochement servait encore
    après que le même nom avait été recréé puis supprimé normalement (retrait non forcé, délégation revenue).
    Chaque retrait porte une génération, revérifiée sous transaction juste avant l'effacement."""
    from synunnel import actions
    from synunnel.db import get_db, init_db

    with app.app_context():
        init_db()
        db = get_db()
        with db:
            db.execute("INSERT INTO zone_removals(name,at,forced,generation) "
                       "VALUES('reprise.example','2026-09-29T00:00:00',1,'ancienne')")
    real_remove = actions.remove_zone
    seen = []

    def recreate_then_remove(app_, name, generation=None):
        # Entre l'autorisation lue et l'effacement : le nom est recréé, puis supprimé par son titulaire
        # (PowerDNS en échec) ; la délégation, elle, désigne de nouveau l'instance.
        db = get_db()
        with db:
            db.execute("INSERT INTO domains(user_id,name,created_at) SELECT id,'reprise.example','2026-09-30' "
                       "FROM users LIMIT 1")
            db.execute("DELETE FROM domains WHERE name='reprise.example'")
            db.execute("INSERT OR REPLACE INTO zone_removals(name,at,forced,generation) "
                       "VALUES('reprise.example','2026-09-30T00:00:00',0,'nouvelle')")
        seen.append(generation)
        return real_remove(app_, name, generation=generation)

    client = app.test_client()
    register_approve_login(app, client, "reprise@example.org")
    _run_reconcile(app, monkeypatch, remove_zone=recreate_then_remove,
                   delegation_status=lambda domain, ns: (True, list(OURS)))
    with app.app_context():
        row = get_db().execute("SELECT forced, generation FROM zone_removals WHERE name='reprise.example'").fetchone()
    assert seen == ["ancienne"] and row is not None and tuple(row) == (0, "nouvelle")


def test_powerdns_deletion_runs_outside_the_sqlite_write_lock(app, monkeypatch):
    """Cinquième passe Codex, constat 24 : l'effacement PowerDNS tournait sous BEGIN IMMEDIATE ; des
    effacements lents bloquaient toute écriture de l'application (« database is locked », HTTP 500)."""
    import sqlite3

    from synunnel import actions
    from synunnel.db import get_db, init_db

    writes = []

    class SlowPowerDNS:
        def delete_zone(self, name):
            # Pendant l'appel à PowerDNS, une autre requête doit pouvoir écrire sans attendre.
            other = sqlite3.connect(app.config["DATABASE"], timeout=0.2)
            other.execute("INSERT INTO attempts(kind,key,at) VALUES('essai','verrou',0)")
            other.commit()
            other.close()
            writes.append(name)

    app.config["PDNS_ENABLED"] = True
    monkeypatch.setattr("synunnel.actions._pdns", lambda app_: SlowPowerDNS())
    with app.app_context():
        init_db()
        db = get_db()
        with db:
            db.execute("INSERT INTO zone_removals(name,at,forced,generation) VALUES('lente.example','x',0,'g1')")
        assert actions.remove_zone(app, "lente.example", generation="g1") is True
        assert writes == ["lente.example"]
        assert db.execute("SELECT 1 FROM zone_removals WHERE name='lente.example'").fetchone() is None


def test_older_removals_receive_a_generation_so_the_check_is_never_skipped(app):
    """Cinquième passe Codex, résidu du constat 22 : un retrait antérieur à la colonne gardait
    generation=NULL, ce qui désactivait la vérification."""
    from synunnel.db import get_db, init_db

    with app.app_context():
        db = get_db()
        with db:
            db.execute("INSERT INTO zone_removals(name,at,forced) VALUES('ancien.example','x',1)")
        init_db()
        row = db.execute("SELECT generation FROM zone_removals WHERE name='ancien.example'").fetchone()
        assert row[0]
