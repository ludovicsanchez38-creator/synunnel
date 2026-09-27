#!/usr/bin/env python3
"""Migre une fois les noms de l'instance du MVP vers synunnel.fr."""

import os
import shutil
import sys
import tempfile
from pathlib import Path

CHANGES = {
    "DASHBOARD_HOST": ("synunnel.synoptia.fr", "synunnel.fr"),
    "NS1_HOST": ("ns1.synunnel.synoptia.fr", "ns1.synunnel.fr"),
    "NS2_HOST": ("ns2.synunnel.synoptia.fr", "ns2.synunnel.fr"),
    "SOA_RNAME": (None, "hostmaster.synunnel.fr."),
    "REDIRECT_HOSTS": (None, "synunnel.com,www.synunnel.com"),
}


def migrate_content(original: str) -> tuple[str, bool]:
    lines = original.splitlines()
    seen = set()
    updated = []
    for line in lines:
        key, sep, value = line.partition("=")
        if sep and key in CHANGES:
            old, new = CHANGES[key]
            if value not in {old, new}:
                raise ValueError(f"Valeur personnalisée pour {key} : migration manuelle requise.")
            line = f"{key}={new}"
            seen.add(key)
        updated.append(line)
    missing = set(CHANGES) - seen
    if missing & {"DASHBOARD_HOST", "NS1_HOST", "NS2_HOST"}:
        raise ValueError("Un nom d'hôte manque dans la configuration existante.")
    updated.extend(f"{key}={CHANGES[key][1]}" for key in CHANGES if key in missing)
    result = "\n".join(updated) + "\n"
    return result, result != original


def main() -> None:
    if os.geteuid() != 0:
        raise SystemExit("Exécution root requise.")
    path = Path(sys.argv[1] if len(sys.argv) > 1 else "/etc/synunnel/synunnel.env")
    original = path.read_text()
    new, changed = migrate_content(original)
    if not changed:
        print("Noms d'instance déjà à jour.")
        return
    backup = path.with_name(path.name + ".pre-domain-2")
    if not backup.exists():
        shutil.copy2(path, backup)
    info = path.stat()
    with tempfile.NamedTemporaryFile(mode="w", dir=path.parent, prefix=".synunnel-env-", delete=False) as tmp:
        tmp.write(new)
        tmp.flush()
        os.fsync(tmp.fileno())
        name = tmp.name
    os.chown(name, info.st_uid, info.st_gid)
    os.chmod(name, info.st_mode & 0o777)
    os.replace(name, path)
    print("Noms d'instance mis à jour ; sauvegarde locale créée.")


if __name__ == "__main__":
    main()
