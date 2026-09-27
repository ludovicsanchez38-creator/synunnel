#!/usr/bin/env python3
"""Crée un pair pour un compte approuvé et écrit sa configuration dans un flux SSH."""

import argparse
import os
import sys
from pathlib import Path

from synunnel import create_app
from synunnel.provision import create_machine_config


def main() -> None:
    if os.geteuid() == 0:
        raise SystemExit("Exécute ce CLI sous le compte synunnel, sans root.")
    if sys.stdout.isatty():
        raise SystemExit("La configuration privée doit être transmise par un pipe SSH, pas affichée.")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--user-email", required=True)
    parser.add_argument("--machine-name", required=True)
    parser.add_argument("--machine-ip", required=True)
    args = parser.parse_args()
    from runpy import run_path

    read_env = run_path(str(Path(__file__).with_name("provision-site.py")))["read_env"]
    os.environ.update(read_env(Path("/etc/synunnel/synunnel.env")))
    app = create_app()
    with app.app_context():
        config = create_machine_config(
            app, user_email=args.user_email, machine_name=args.machine_name,
            machine_ip=args.machine_ip,
        )
    sys.stdout.write(config)
    sys.stdout.flush()


if __name__ == "__main__":
    main()
