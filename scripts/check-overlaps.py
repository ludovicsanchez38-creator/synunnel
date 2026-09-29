#!/usr/bin/env python3
"""Signale les zones imbriquées qu'une base antérieure à la v0.1 alpha aurait pu contenir.

Rien n'est supprimé : chaque paire doit être résolue par l'administrateur, et
l'installation s'arrête tant qu'il en reste une.
"""

import os
import sqlite3
import sys
from pathlib import Path


def nested_pairs(names: list[str]) -> list[tuple[str, str]]:
    return [(parent, child) for parent in names for child in names if child.endswith(f".{parent}")]


def main() -> None:
    path = Path(os.environ["DATABASE"])
    if not path.exists():
        return
    db = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    pairs = nested_pairs([row[0] for row in db.execute("SELECT name FROM domains")])
    db.close()
    for parent, child in pairs:
        print(f"La zone {child} est contenue dans {parent} : supprime l'une des deux, "
              "puis relance l'installation.", file=sys.stderr)
    if pairs:
        sys.exit(1)


if __name__ == "__main__":
    main()
