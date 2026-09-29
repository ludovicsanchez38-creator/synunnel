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
from synunnel.actions import _pdns, project_runtime
from synunnel.db import get_db

RETENTION_DAYS = 90


def main() -> int:
    app = create_app()
    failures = 0
    with app.app_context():
        db = get_db()
        domains = db.execute("SELECT id, name FROM domains ORDER BY name").fetchall()
        if app.config["PDNS_ENABLED"]:
            pdns = _pdns(app)
            for domain in domains:
                try:
                    pdns.ensure_zone(domain["name"])
                    pdns.sync_zone(db, domain["id"], domain["name"], app.config["PUBLIC_IPV4"],
                                   app.config["PUBLIC_IPV6"])
                except requests.RequestException as exc:
                    failures += 1
                    print(f"Zone {domain['name']} non synchronisée : {exc}", file=sys.stderr)
            try:
                orphans = pdns.zone_names() - {domain["name"] for domain in domains}
            except requests.RequestException as exc:
                failures += 1
                print(f"Liste des zones PowerDNS indisponible : {exc}", file=sys.stderr)
            else:
                for name in sorted(orphans):
                    print(f"Zone {name} présente dans PowerDNS sans domaine en base : à examiner.",
                          file=sys.stderr)
        if not project_runtime(app):
            failures += 1
            print("Synchronisation WireGuard et Caddy en échec.", file=sys.stderr)
        # Données de travail expirées.
        now = int(time.time())
        cutoff = f"-{RETENTION_DAYS} days"
        with db:
            db.execute("DELETE FROM attempts WHERE at < ?", (now - 86400,))
            db.execute("DELETE FROM access_codes WHERE expires_at < ?", (now,))
            db.execute("DELETE FROM host_sessions WHERE expires_at < ?", (now,))
            db.execute("DELETE FROM domain_claims WHERE created_at < strftime('%Y-%m-%dT%H:%M:%S', 'now', '-30 days')")
            db.execute("DELETE FROM admin_audit WHERE at < strftime('%Y-%m-%dT%H:%M:%S', 'now', ?)", (cutoff,))
            db.execute("DELETE FROM api_audit WHERE at < strftime('%Y-%m-%dT%H:%M:%S', 'now', ?)", (cutoff,))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
