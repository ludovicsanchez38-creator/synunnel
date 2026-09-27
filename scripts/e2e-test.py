#!/usr/bin/env python3
"""Essai intégré éphémère sur un VPS Synunnel sans domaine délégué.

Crée un pair WireGuard dans un espace réseau local et une zone .test,
sert une page par Caddy avec sa CA interne, puis remet la configuration.
"""

import os
import sqlite3
import subprocess
import tempfile
import time
from pathlib import Path

from argon2 import PasswordHasher

from synunnel.dns import PowerDNS

DOMAIN = "e2e.synunnel.test"
HOST = f"nas.{DOMAIN}"
PROTECTED = f"prive.{DOMAIN}"
UNKNOWN = f"inconnu.{DOMAIN}"
EMAIL = "e2e@synunnel.invalid"
NS = "sn-e2e"
VETH_HOST = "sn-e2e-host"
VETH_PEER = "sn-e2e-peer"
PAGE = "SYNUNNEL_E2E_WIREGUARD_OK"
CONFIG = Path("/etc/caddy/Caddyfile")


def run(*args: str, check: bool = True, **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run(args, check=check, capture_output=True, text=True, timeout=15, **kwargs)


def env_file() -> dict[str, str]:
    values = {}
    for line in Path("/etc/synunnel/synunnel.env").read_text().splitlines():
        if "=" in line and not line.startswith("#"):
            key, value = line.split("=", 1)
            values[key] = value.strip("'")
    return values


def main() -> None:
    if os.geteuid() != 0:
        raise SystemExit("L'essai doit être lancé avec sudo.")
    values = env_file()
    db = sqlite3.connect(values["DATABASE"], timeout=10)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys=ON")
    if db.execute("SELECT 1 FROM domains WHERE name=?", (DOMAIN,)).fetchone():
        raise SystemExit("La zone de test existe déjà ; aucune donnée n'a été touchée.")
    if db.execute("SELECT 1 FROM users WHERE email=?", (EMAIL,)).fetchone():
        raise SystemExit("Le compte de test existe déjà ; aucune donnée n'a été touchée.")
    if NS in run("ip", "netns", "list").stdout:
        raise SystemExit("L'espace réseau de test existe déjà ; aucune donnée n'a été touchée.")

    pdns = PowerDNS(values["PDNS_API_URL"], values["PDNS_API_KEY"], (
        f"{values.get('NS1_HOST', 'ns1.synunnel.synoptia.fr')}.",
        f"{values.get('NS2_HOST', 'ns2.synunnel.synoptia.fr')}.",
    ))
    original_caddy = CONFIG.read_text()
    private = run("wg", "genkey").stdout.strip()
    public = run("wg", "pubkey", input=private + "\n").stdout.strip()
    temp_dir = Path(tempfile.mkdtemp(prefix="synunnel-e2e-", dir="/run"))
    page_file = temp_dir / "index.html"
    page_file.write_text(PAGE + "\n")
    private_file = temp_dir / "client.key"
    private_file.write_text(private + "\n")
    private_file.chmod(0o600)
    http_server = None
    zone_created = False
    netns_created = False
    caddy_changed = False
    try:
        pdns.create_zone(DOMAIN)
        zone_created = True
        with db:
            user_id = db.execute(
                "INSERT INTO users(email,password_hash,status,created_at) VALUES(?,?,'approved',?)",
                (EMAIL, PasswordHasher().hash(private), "2026-09-27T00:00:00Z"),
            ).lastrowid
            domain_id = db.execute(
                "INSERT INTO domains(user_id,name,created_at) VALUES(?,?,?)",
                (user_id, DOMAIN, "2026-09-27T00:00:00Z"),
            ).lastrowid
            db.executemany(
                "INSERT INTO records(domain_id,name,type,content,ttl) VALUES(?,?,?,?,?)",
                [
                    (domain_id, "@", "MX", f"10 mail.{DOMAIN}.", 300),
                    (domain_id, "@", "TXT", '"v=spf1 -all"', 300),
                    (domain_id, "_dmarc", "TXT", '"v=DMARC1; p=reject"', 300),
                ],
            )
            machine_id = db.execute(
                "INSERT INTO machines(user_id,name,ip,public_key,created_at) VALUES(?,?,?,?,?)",
                (user_id, "test-local", "10.88.0.2", public, "2026-09-27T00:00:00Z"),
            ).lastrowid
            db.execute(
                "INSERT INTO addresses(domain_id,machine_id,hostname,port,protected,created_at) "
                "VALUES(?,?,?,?,0,?)",
                (domain_id, machine_id, HOST, 18080, "2026-09-27T00:00:00Z"),
            )
            db.execute(
                "INSERT INTO addresses(domain_id,machine_id,hostname,port,protected,created_at) "
                "VALUES(?,?,?,?,1,?)",
                (domain_id, machine_id, PROTECTED, 18080, "2026-09-27T00:00:00Z"),
            )
            pdns.sync_zone(db, domain_id, DOMAIN, values["PUBLIC_IPV4"], values["PUBLIC_IPV6"])
        run("/usr/local/sbin/synunnel-sync")

        run("ip", "netns", "add", NS)
        netns_created = True
        run("ip", "link", "add", VETH_HOST, "type", "veth", "peer", "name", VETH_PEER)
        run("ip", "link", "set", VETH_PEER, "netns", NS)
        run("ip", "addr", "add", "172.31.250.1/30", "dev", VETH_HOST)
        run("ip", "link", "set", VETH_HOST, "up")
        run("ip", "netns", "exec", NS, "ip", "addr", "add", "172.31.250.2/30", "dev", VETH_PEER)
        run("ip", "netns", "exec", NS, "ip", "link", "set", "lo", "up")
        run("ip", "netns", "exec", NS, "ip", "link", "set", VETH_PEER, "up")
        run("ip", "netns", "exec", NS, "ip", "link", "add", "wg-e2e", "type", "wireguard")
        run(
            "ip", "netns", "exec", NS, "wg", "set", "wg-e2e", "private-key", str(private_file),
            "peer", values["WG_SERVER_PUBLIC_KEY"], "allowed-ips", "10.88.0.1/32",
            "endpoint", "172.31.250.1:51820", "persistent-keepalive", "25",
        )
        run("ip", "netns", "exec", NS, "ip", "addr", "add", "10.88.0.2/32", "dev", "wg-e2e")
        run("ip", "netns", "exec", NS, "ip", "link", "set", "wg-e2e", "up")
        run("ip", "netns", "exec", NS, "ip", "route", "add", "10.88.0.1/32", "dev", "wg-e2e")
        http_server = subprocess.Popen(
            ["ip", "netns", "exec", NS, "python3", "-m", "http.server", "18080", "--bind", "10.88.0.2", "--directory", str(temp_dir)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        # Un paquet sortant apprend à wg0 l'endpoint du pair local.
        run("ip", "netns", "exec", NS, "ping", "-c", "1", "-W", "2", "10.88.0.1", check=False)
        time.sleep(1)

        test_caddy = original_caddy.replace("{\n    email", "{\n    local_certs\n    email", 1)
        if test_caddy == original_caddy:
            raise RuntimeError("Le Caddyfile n'a pas le format attendu pour le test.")
        CONFIG.write_text(test_caddy)
        caddy_changed = True
        run("caddy", "validate", "--config", str(CONFIG), "--adapter", "caddyfile")
        run("systemctl", "reload", "caddy")

        dns_a = run("dig", "+short", f"@{values['PUBLIC_IPV4']}", HOST, "A").stdout.strip()
        dns_mx = run("dig", "+short", f"@{values['PUBLIC_IPV4']}", DOMAIN, "MX").stdout.strip()
        if values["PUBLIC_IPV4"] not in dns_a or f"mail.{DOMAIN}." not in dns_mx:
            raise AssertionError(f"Réponse DNS incorrecte : A={dns_a!r}, MX={dns_mx!r}")
        print(f"DNS A et MX via dig @{values['PUBLIC_IPV4']} : OK")

        cert = Path("/var/lib/caddy/.local/share/caddy/pki/authorities/local/root.crt")
        command = ["curl", "--noproxy", "*", "--silent", "--show-error", "--fail", "--resolve", f"{HOST}:443:{values['PUBLIC_IPV4']}"]
        if cert.exists():
            command.extend(["--cacert", str(cert)])
        else:
            command.append("--insecure")
        page = run(*command, f"https://{HOST}/").stdout
        if PAGE not in page:
            raise AssertionError(f"La réponse Caddy ne vient pas du service WireGuard : {page[:200]!r}")
        handshakes = run("wg", "show", "wg0", "latest-handshakes").stdout.splitlines()
        if not any(line.split()[0] == public and int(line.split()[1]) > 0 for line in handshakes):
            raise AssertionError("La poignée de main WireGuard manque.")
        print("Page HTTPS via Caddy et service derrière le pair WireGuard : OK")

        guarded = run(
            "curl", "--noproxy", "*", "--silent", "--show-error", "--insecure", "--max-time", "8",
            "--resolve", f"{PROTECTED}:443:{values['PUBLIC_IPV4']}",
            "--dump-header", "-", "--output", "/dev/null", f"https://{PROTECTED}/",
        ).stdout.lower()
        if " 302 " not in guarded or f"location: https://{values['DASHBOARD_HOST']}/login?" not in guarded:
            raise AssertionError(f"La route protégée ne redirige pas vers la connexion : {guarded[:300]!r}")
        print("Adresse protégée redirigée par Caddy vers la connexion : OK")

        rejected = run(
            "curl", "--noproxy", "*", "--silent", "--show-error", "--insecure", "--max-time", "8",
            "--resolve", f"{UNKNOWN}:443:{values['PUBLIC_IPV4']}", f"https://{UNKNOWN}/",
            check=False,
        )
        if rejected.returncode == 0:
            raise AssertionError("Le nom d'hôte non déclaré a été accepté.")
        print("Nom d'hôte non déclaré refusé au TLS : OK")
    finally:
        if caddy_changed:
            CONFIG.write_text(original_caddy)
            run("systemctl", "reload", "caddy")
        if http_server:
            http_server.terminate()
            try:
                http_server.wait(timeout=3)
            except subprocess.TimeoutExpired:
                http_server.kill()
                http_server.wait(timeout=3)
        if netns_created:
            run("ip", "netns", "delete", NS, check=False)
            run("ip", "link", "delete", VETH_HOST, check=False)
        with db:
            db.execute("DELETE FROM users WHERE email=?", (EMAIL,))
        if zone_created:
            pdns.delete_zone(DOMAIN)
        run("/usr/local/sbin/synunnel-sync")
        for path in (private_file, page_file):
            path.unlink(missing_ok=True)
        temp_dir.rmdir()
        db.close()


if __name__ == "__main__":
    main()
