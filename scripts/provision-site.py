#!/usr/bin/env python3
"""CLI d'administration pour rattacher un site à un compte Synunnel approuvé."""

import argparse
import os
import shlex
from pathlib import Path

from synunnel import create_app
from synunnel.provision import provision_site


def read_env(path: Path) -> dict[str, str]:
    values = {}
    for line in path.read_text().splitlines():
        if not line or line.startswith("#"):
            continue
        key, sep, raw = line.partition("=")
        if not sep:
            raise ValueError("Ligne de configuration invalide.")
        parsed = shlex.split(raw) if raw else [""]
        if len(parsed) != 1:
            raise ValueError(f"Valeur de configuration invalide : {key}.")
        values[key] = parsed[0]
    return values


def main() -> None:
    if os.geteuid() == 0:
        raise SystemExit("Exécute ce CLI sous le compte synunnel, sans root.")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--user-email", required=True)
    parser.add_argument("--domain", required=True)
    parser.add_argument("--machine-name", required=True)
    parser.add_argument("--machine-ip", required=True)
    parser.add_argument("--machine-public-key-file", type=Path)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--hosts", required=True, help="Noms séparés par une virgule, @ pour la racine")
    parser.add_argument("--mail-records-verified", action="store_true")
    args = parser.parse_args()
    os.environ.update(read_env(Path("/etc/synunnel/synunnel.env")))
    app = create_app()
    with app.app_context():
        result = provision_site(
            app, user_email=args.user_email, domain_name=args.domain,
            machine_name=args.machine_name, machine_ip=args.machine_ip,
            machine_public_key=(args.machine_public_key_file.read_text().strip()
                                if args.machine_public_key_file else None),
            port=args.port, hosts=args.hosts.split(","),
            mail_records_verified=args.mail_records_verified,
        )
    print(f"Rattachement terminé : {result['copied_records']} enregistrements DNS copiés, "
          f"{result['addresses']} adresses protégées.")


if __name__ == "__main__":
    main()
