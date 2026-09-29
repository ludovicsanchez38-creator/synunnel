#!/usr/bin/env python3
"""Rapprochement périodique : ramène PowerDNS, WireGuard et Caddy sur l'état voulu en base.

Lancé par le minuteur synunnel-reconcile sous l'utilisateur synunnel. Une mise à jour
qui a échoué pendant une requête (serveur DNS injoignable, synchronisation refusée) est
terminée ici. Les zones présentes dans PowerDNS mais absentes de la base sont signalées,
jamais supprimées automatiquement.
"""

import sys
import time

import requests

from synunnel import create_app
from synunnel.actions import _pdns, project_runtime, project_zone, refresh_delegation, remove_zone
from synunnel.db import get_db

RETENTION_DAYS = 90
BUDGET_SECONDS = 200


def main() -> int:
    app = create_app()
    failures = 0
    started = time.monotonic()
    with app.app_context():
        db = get_db()
        # 1. Données de travail expirées, en premier : rien ne doit pouvoir les affamer.
        now = int(time.time())
        cutoff = f"-{RETENTION_DAYS} days"
        with db:
            db.execute("DELETE FROM attempts WHERE at < ?", (now - 86400,))
            db.execute("DELETE FROM access_codes WHERE expires_at < ?", (now,))
            db.execute("DELETE FROM host_sessions WHERE expires_at < ?", (now,))
            db.execute("DELETE FROM invitations WHERE expires_at < ? AND used_at IS NULL", (now,))
            db.execute("DELETE FROM domain_claims WHERE created_at < strftime('%Y-%m-%dT%H:%M:%S', 'now', '-30 days')")
            db.execute("DELETE FROM admin_audit WHERE at < strftime('%Y-%m-%dT%H:%M:%S', 'now', ?)", (cutoff,))
            db.execute("DELETE FROM api_audit WHERE at < strftime('%Y-%m-%dT%H:%M:%S', 'now', ?)", (cutoff,))
        # 2. Zones de domaines supprimés, pas encore retirées de PowerDNS.
        for row in db.execute("SELECT name FROM zone_removals").fetchall():
            if not remove_zone(app, row["name"]):
                failures += 1
                print(f"Zone {row['name']} supprimée en base, pas encore dans PowerDNS.", file=sys.stderr)
        # 3. Tunnel et routes : rapides, et indépendants de PowerDNS.
        if not project_runtime(app):
            failures += 1
            print("Synchronisation WireGuard et Caddy en échec.", file=sys.stderr)
        # 4. Zones DNS dans un budget de temps, en commençant chaque fois ailleurs : une zone lente ou un
        #    PowerDNS figé n'empêche plus les autres d'avancer d'une exécution à l'autre.
        domains = db.execute("SELECT id, name FROM domains ORDER BY id").fetchall()
        if domains:
            offset = int(time.time() // 300) % len(domains)
            domains = domains[offset:] + domains[:offset]
        for domain in domains:
            if time.monotonic() - started > BUDGET_SECONDS:
                print("Budget de temps atteint : les zones restantes passeront au prochain rapprochement.",
                      file=sys.stderr)
                break
            if not project_zone(app, domain):
                failures += 1
                print(f"Zone {domain['name']} non synchronisée.", file=sys.stderr)
            refresh_delegation(app, domain)
        if app.config["PDNS_ENABLED"]:
            try:
                orphans = _pdns(app).zone_names() - {row["name"] for row in db.execute("SELECT name FROM domains")}
            except requests.RequestException as exc:
                failures += 1
                print(f"Liste des zones PowerDNS indisponible : {exc}", file=sys.stderr)
            else:
                for name in sorted(orphans):
                    print(f"Zone {name} présente dans PowerDNS sans domaine en base : à examiner.", file=sys.stderr)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
