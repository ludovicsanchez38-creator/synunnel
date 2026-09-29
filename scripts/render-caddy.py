#!/usr/bin/env python3
"""Rend le Caddyfile depuis les noms configurés, sans contenu non validé."""

import os
import re
import sys
from pathlib import Path

HOST_RE = re.compile(r"^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$")
EMAIL_RE = re.compile(r"^[a-zA-Z0-9._+@-]+$")


def render_caddy(template: str, dashboard: str, redirect_hosts: str, email: str) -> str:
    hosts = [host.strip().lower() for host in redirect_hosts.split(",") if host.strip()]
    all_hosts = [dashboard.lower(), *hosts]
    if (
        not all(HOST_RE.fullmatch(host) and "." in host and ".." not in host for host in all_hosts)
        or len(set(all_hosts)) != len(all_hosts)
        or not EMAIL_RE.fullmatch(email)
    ):
        raise ValueError("Hôtes ou adresse ACME invalides.")
    if not hosts:
        # Aucun nom de redirection : on retire le bloc entier plutôt qu'un matcher vide.
        template = re.sub(r"\n *# __REDIRECT_START__\n.*?# __REDIRECT_END__\n", "\n", template, flags=re.DOTALL)
    return (template.replace("__DASHBOARD_HOST__", dashboard.lower())
            .replace("__REDIRECT_HOSTS__", " ".join(hosts))
            .replace("__ACME_EMAIL__", email))


def main() -> None:
    if len(sys.argv) != 3:
        raise SystemExit("Usage : render-caddy.py TEMPLATE SORTIE")
    template = Path(sys.argv[1]).read_text()
    rendered = render_caddy(
        template, os.environ["DASHBOARD_HOST"], os.environ.get("REDIRECT_HOSTS", ""),
        os.environ["ACME_EMAIL"],
    )
    Path(sys.argv[2]).write_text(rendered)


if __name__ == "__main__":
    main()
