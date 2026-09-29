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
            # Preuves de courte durée : l'expiration est vérifiée à l'usage, la purge ne fait que ranger.
            db.execute("DELETE FROM login_challenges WHERE expires_at < ? OR used_at IS NOT NULL", (now,))
            db.execute("DELETE FROM totp_enrollments WHERE expires_at < ?", (now,))
            db.execute("DELETE FROM password_resets WHERE expires_at < ?", (now - 86400,))
            db.execute("DELETE FROM email_verifications WHERE expires_at < ?", (now - 86400,))
            db.execute("DELETE FROM security_events WHERE at < strftime('%Y-%m-%dT%H:%M:%S', 'now', '-365 days')")
            db.execute("DELETE FROM guest_challenges WHERE expires_at < ?", (now - 86400,))
            db.execute("DELETE FROM guest_access_codes WHERE expires_at < ?", (now,))
            db.execute("DELETE FROM guest_host_sessions WHERE expires_at < ?", (now,))
            db.execute("DELETE FROM guest_quota WHERE at < ?", (now - 2 * 86400,))
        # 2. Tunnel et routes : rapides, et indépendants de PowerDNS.
        if not project_runtime(app):
            failures += 1
            print("Synchronisation WireGuard et Caddy en échec.", file=sys.stderr)
        # 3. Zones de domaines supprimés dont le délai de retrait est passé, dans le budget.
        due = db.execute("SELECT name FROM zone_removals WHERE not_before<=? ORDER BY at", (int(time.time()),))
        for row in due.fetchall():
            if time.monotonic() - started > BUDGET_SECONDS:
                break
            if not remove_zone(app, row["name"]):
                failures += 1
                print(f"Zone {row['name']} supprimée en base, pas encore dans PowerDNS.", file=sys.stderr)
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
                # Une zone supprimée dont le retrait attend l'expiration des caches n'est pas orpheline.
                kept = {row["name"] for row in db.execute("SELECT name FROM domains UNION SELECT name FROM zone_removals")}
                orphans = _pdns(app).zone_names() - kept
            except requests.RequestException as exc:
                failures += 1
                print(f"Liste des zones PowerDNS indisponible : {exc}", file=sys.stderr)
            else:
                for name in sorted(orphans):
                    print(f"Zone {name} présente dans PowerDNS sans domaine en base : à examiner.", file=sys.stderr)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
