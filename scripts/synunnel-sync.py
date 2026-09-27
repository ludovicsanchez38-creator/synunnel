#!/usr/bin/env python3
"""Synchronise les pairs WireGuard et les routes Caddy depuis la base validée.

Installé root:root, appelé uniquement par sudoers depuis le service synunnel.
"""

import base64
import binascii
import ipaddress
import os
import re
import sqlite3
import subprocess
import tempfile
from pathlib import Path

DB_PATH = Path("/var/lib/synunnel/synunnel.db")
WG_KEY_PATH = Path("/etc/wireguard/synunnel-server.key")
WG_CONFIG_PATH = Path("/etc/wireguard/wg0.conf")
CADDY_ROUTES_PATH = Path("/etc/caddy/synunnel-routes.caddy")
CADDYFILE_PATH = Path("/etc/caddy/Caddyfile")
HOST_RE = re.compile(r"^[a-z0-9-]+(?:\.[a-z0-9-]+)+$")


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
    try:
        return len(base64.b64decode(key, validate=True)) == 32
    except (ValueError, binascii.Error):
        return False


def wireguard_config(db: sqlite3.Connection) -> str:
    private = WG_KEY_PATH.read_text().strip()
    if not valid_key(private):
        raise ValueError("Clé WireGuard du serveur invalide")
    lines = [
        "[Interface]", "Address = 10.88.0.1/24", "ListenPort = 51820",
        f"PrivateKey = {private}", "",
    ]
    for row in db.execute("SELECT ip,public_key FROM machines ORDER BY ip"):
        ip = ipaddress.ip_address(row["ip"])
        if ip not in ipaddress.ip_network("10.88.0.0/24") or ip in (ipaddress.ip_address("10.88.0.1"),):
            raise ValueError("Adresse WireGuard hors plage")
        if not valid_key(row["public_key"]):
            raise ValueError("Clé publique d'un pair invalide")
        lines.extend(["[Peer]", f"PublicKey = {row['public_key']}", f"AllowedIPs = {ip}/32", ""])
    return "\n".join(lines)


def caddy_routes(db: sqlite3.Connection) -> str:
    lines = ["# Routes générées depuis la base Synunnel. Ne pas éditer à la main."]
    rows = db.execute(
        "SELECT a.hostname,a.port,m.ip FROM addresses a "
        "JOIN domains d ON d.id=a.domain_id JOIN users u ON u.id=d.user_id "
        "JOIN machines m ON m.id=a.machine_id WHERE u.status='approved' ORDER BY a.hostname"
    )
    for n, row in enumerate(rows, 1):
        host, port, ip = row
        if not HOST_RE.fullmatch(host) or not 1 <= port <= 65535:
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
            f"    @synunnel_internal_{n} path /internal/*",
            f"    handle @synunnel_internal_{n} {{",
            "        respond 404",
            "    }",
            "    handle {",
            "        forward_auth 127.0.0.1:8000 {",
            "            uri /internal/caddy/auth",
            "        }",
            f"        reverse_proxy {parsed_ip}:{port}",
            "    }",
            "}",
        ])
    return "\n".join(lines) + "\n"


def main() -> None:
    if os.geteuid() != 0:
        raise SystemExit("Exécution root requise")
    db = sqlite3.connect(f"file:{DB_PATH}?mode=ro", uri=True)
    db.row_factory = sqlite3.Row
    new_wg = wireguard_config(db)
    new_routes = caddy_routes(db)
    db.close()

    old_wg = WG_CONFIG_PATH.read_text() if WG_CONFIG_PATH.exists() else ""
    old_routes = CADDY_ROUTES_PATH.read_text() if CADDY_ROUTES_PATH.exists() else ""
    if new_wg != old_wg:
        atomic_write(WG_CONFIG_PATH, new_wg, 0o600)
        try:
            if subprocess.run(
                ["/usr/bin/systemctl", "is-active", "--quiet", "wg-quick@wg0"],
                check=False, capture_output=True, timeout=10,
            ).returncode == 0:
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
            atomic_write(WG_CONFIG_PATH, old_wg, 0o600)
            raise
    if new_routes != old_routes:
        atomic_write(CADDY_ROUTES_PATH, new_routes, 0o644)
        try:
            run("/usr/bin/caddy", "validate", "--config", str(CADDYFILE_PATH), "--adapter", "caddyfile")
            run("/usr/bin/systemctl", "reload", "caddy")
        except Exception:
            atomic_write(CADDY_ROUTES_PATH, old_routes, 0o644)
            raise


if __name__ == "__main__":
    main()
