#!/usr/bin/env python3
"""Aligne les NS et SOA des zones enregistrées sur la configuration actuelle."""

import os
import sqlite3

from synunnel.dns import PowerDNS, configured_nameservers


def main() -> None:
    db = sqlite3.connect(f"file:{os.environ['DATABASE']}?mode=ro", uri=True)
    names = [row[0] for row in db.execute("SELECT name FROM domains ORDER BY name")]
    db.close()
    pdns = PowerDNS(os.environ["PDNS_API_URL"], os.environ["PDNS_API_KEY"], configured_nameservers())
    changed = sum(pdns.migrate_authority(name, os.environ["SOA_RNAME"]) for name in names)
    print(f"Zones NS/SOA vérifiées : {len(names)} ; modifiées : {changed}.")


if __name__ == "__main__":
    main()
