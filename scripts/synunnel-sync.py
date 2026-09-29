#!/usr/bin/env python3
"""Synchronise les pairs WireGuard et les routes Caddy depuis la base validée.

Installé root:root, appelé uniquement par sudoers depuis le service synunnel.
"""

import base64
import binascii
import fcntl
import hashlib
import ipaddress
import os
import re
import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path

DB_PATH = Path("/var/lib/synunnel/synunnel.db")
WG_KEY_PATH = Path("/etc/wireguard/synunnel-server.key")
WG_CONFIG_PATH = Path("/etc/wireguard/wg0.conf")
CADDY_ROUTES_PATH = Path("/etc/caddy/synunnel-routes.caddy")
CADDYFILE_PATH = Path("/etc/caddy/Caddyfile")
LOCK_PATH = Path("/run/synunnel-sync.lock")
FIREWALL_PATH = Path("/etc/synunnel/wg0-firewall.nft")
# Empreintes de ce qui a réellement été appliqué (et non seulement écrit) : dans /run, elles
# disparaissent au redémarrage, ce qui force une réapplication complète.
APPLIED_WG = Path("/run/synunnel-applied-wg")
APPLIED_CADDY = Path("/run/synunnel-applied-caddy")


def digest(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def applied(marker: Path, text: str) -> bool:
    return marker.exists() and marker.read_text() == digest(text)
HOST_RE = re.compile(r"^[a-z0-9-]+(?:\.[a-z0-9-]+)+$")
TOKEN_RE = re.compile(r"^[0-9a-f]{24}$")


def run(*args: str, input: bytes | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(args, input=input, check=True, capture_output=True, timeout=15)


def atomic_write(path: Path, content: str, mode: int) -> None:
    with tempfile.NamedTemporaryFile(mode="w", dir=path.parent, prefix=f".{path.name}.", delete=False) as tmp:
        tmp.write(content)
        tmp.flush()
        os.fsync(tmp.fileno())
        tmp_name = tmp.name
    os.chmod(tmp_name, mode)
    os.replace(tmp_name, path)


def valid_key(key: str) -> bool:
    """Forme canonique exigée, comme wireguard-tools : une clé qu'il refuserait bloquerait tout wg0."""
    try:
        raw = base64.b64decode(key, validate=True)
    except (ValueError, binascii.Error, TypeError):
        return False
    return len(raw) == 32 and base64.b64encode(raw).decode() == key


def wireguard_config(db: sqlite3.Connection) -> str:
    private = WG_KEY_PATH.read_text().strip()
    if not valid_key(private):
        raise ValueError("Clé WireGuard du serveur invalide")
    lines = [
        "[Interface]", "Address = 10.88.0.1/24", "ListenPort = 51820",
        f"PrivateKey = {private}",
        f"PreUp = /usr/sbin/nft -f {FIREWALL_PATH}",
        "PostDown = /usr/sbin/nft delete table inet synunnel_wg", "",
    ]
    seen: set[str] = set()
    rows = db.execute(
        "SELECT m.ip, m.public_key FROM machines m JOIN users u ON u.id=m.user_id AND u.status='approved' "
        "ORDER BY m.ip"
    )
    for row in rows:
        ip = ipaddress.ip_address(row["ip"])
        # Un pair invalide est écarté et signalé : il ne doit jamais empêcher les autres de fonctionner.
        if ip not in ipaddress.ip_network("10.88.0.0/24") or ip == ipaddress.ip_address("10.88.0.1"):
            print(f"Pair écarté, adresse hors plage : {row['ip']}", file=sys.stderr)
            continue
        if not valid_key(row["public_key"]) or row["public_key"] in seen:
            print(f"Pair écarté, clé publique invalide ou en double : {row['ip']}", file=sys.stderr)
            continue
        seen.add(row["public_key"])
        lines.extend(["[Peer]", f"PublicKey = {row['public_key']}", f"AllowedIPs = {ip}/32", ""])
    return "\n".join(lines)


def caddy_routes(db: sqlite3.Connection) -> str:
    lines = ["# Routes générées depuis la base Synunnel. Ne pas éditer à la main."]
    rows = db.execute(
        "SELECT a.hostname,a.port,m.ip,a.route_token FROM addresses a "
        "JOIN domains d ON d.id=a.domain_id JOIN users u ON u.id=d.user_id "
        "JOIN machines m ON m.id=a.machine_id AND m.user_id=d.user_id "
        "WHERE u.status='approved' ORDER BY a.hostname"
    )
    for n, row in enumerate(rows, 1):
        host, port, ip, token = row
        if not HOST_RE.fullmatch(host) or not 1 <= port <= 65535 or not TOKEN_RE.fullmatch(token or ""):
            raise ValueError("Route Caddy invalide")
        parsed_ip = ipaddress.ip_address(ip)
        if parsed_ip not in ipaddress.ip_network("10.88.0.0/24"):
            raise ValueError("IP de route hors tunnel")
        lines.extend([
            f"@synunnel_host_{n} host {host}",
            f"handle @synunnel_host_{n} {{",
            f"    @synunnel_callback_{n} path /__synunnel/auth/callback",
            f"    handle @synunnel_callback_{n} {{",
            "        reverse_proxy 127.0.0.1:8000",
            "    }",
            # Un jeton d'API Synunnel envoyé par erreur à cette adresse ne doit jamais
            # atteindre le service qui s'y trouve.
            f"    @synunnel_token_{n} header_regexp Authorization (?i)^bearer[[:space:]]+syn_",
            f"    handle @synunnel_token_{n} {{",
            '        respond "Jeton Synunnel refusé sur cette adresse" 421',
            "    }",
            f"    @synunnel_internal_{n} path /internal/*",
            f"    handle @synunnel_internal_{n} {{",
            "        respond 404",
            "    }",
            "    handle {",
            "        forward_auth 127.0.0.1:8000 {",
            f"            uri /internal/caddy/auth?route={token}",
            "        }",
            f"        reverse_proxy {parsed_ip}:{port}",
            "    }",
            "}",
        ])
    return "\n".join(lines) + "\n"


def wireguard_active() -> bool:
    return subprocess.run(
        ["/usr/bin/systemctl", "is-active", "--quiet", "wg-quick@wg0"],
        check=False, capture_output=True, timeout=10,
    ).returncode == 0


def read_snapshot() -> tuple[str, str]:
    """Lit pairs et routes dans une seule transaction : les deux reflètent le même état."""
    db = sqlite3.connect(f"file:{DB_PATH}?mode=ro", uri=True, isolation_level=None)
    db.row_factory = sqlite3.Row
    try:
        db.execute("BEGIN")
        return wireguard_config(db), caddy_routes(db)
    finally:
        db.close()


def main() -> None:
    if os.geteuid() != 0:
        raise SystemExit("Exécution root requise")
    # Deux workers peuvent déclencher une synchronisation au même moment : on les sérialise.
    with open(LOCK_PATH, "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        apply(*read_snapshot())


def apply(new_wg: str, new_routes: str) -> None:
    """WireGuard puis Caddy, chacun de son côté : l'échec de l'un n'empêche pas l'autre d'être appliqué."""
    failures = []
    for step in (apply_wireguard, apply_caddy):
        try:
            step(new_wg, new_routes)
        except Exception as exc:  # noqa: BLE001 - on tente les deux, on échoue ensuite
            failures.append(f"{step.__name__} : {exc}")
    if failures:
        raise SystemExit("Synchronisation incomplète : " + " ; ".join(failures))


def apply_wireguard(new_wg: str, _routes: str) -> None:
    old_wg = WG_CONFIG_PATH.read_text() if WG_CONFIG_PATH.exists() else ""
    if new_wg == old_wg and applied(APPLIED_WG, new_wg) and wireguard_active():
        return
    # Écrit mais jamais appliqué (interruption, redémarrage) : on réapplique, c'est idempotent.
    atomic_write(WG_CONFIG_PATH, new_wg, 0o600)
    try:
        if wireguard_active():
            stripped = run("/usr/bin/wg-quick", "strip", str(WG_CONFIG_PATH)).stdout
            with tempfile.NamedTemporaryFile(mode="wb", dir="/run", prefix="synunnel-wg-", delete=False) as tmp:
                tmp.write(stripped)
                stripped_path = tmp.name
            try:
                run("/usr/bin/wg", "syncconf", "wg0", stripped_path)
            finally:
                os.unlink(stripped_path)
        else:
            run("/usr/bin/systemctl", "start", "wg-quick@wg0")
    except Exception:
        if old_wg != new_wg:
            atomic_write(WG_CONFIG_PATH, old_wg, 0o600)
        APPLIED_WG.unlink(missing_ok=True)
        raise
    atomic_write(APPLIED_WG, digest(new_wg), 0o600)


def apply_caddy(_wg: str, new_routes: str) -> None:
    old_routes = CADDY_ROUTES_PATH.read_text() if CADDY_ROUTES_PATH.exists() else ""
    if new_routes == old_routes and applied(APPLIED_CADDY, new_routes):
        return
    atomic_write(CADDY_ROUTES_PATH, new_routes, 0o644)
    try:
        run("/usr/bin/caddy", "validate", "--config", str(CADDYFILE_PATH), "--adapter", "caddyfile")
        run("/usr/bin/systemctl", "reload", "caddy")
    except Exception:
        if old_routes != new_routes:
            atomic_write(CADDY_ROUTES_PATH, old_routes, 0o644)
        APPLIED_CADDY.unlink(missing_ok=True)
        raise
    atomic_write(APPLIED_CADDY, digest(new_routes), 0o600)


if __name__ == "__main__":
    main()
