"""Rattachement administratif d'un site local à un compte déjà approuvé."""

import base64
import binascii
import ipaddress
import secrets
import shlex
import subprocess
from collections.abc import Callable

from flask import Flask

from .db import get_db, now_iso
from .dns import PowerDNS, fqdn, normalize_domain, relative_name, snapshot_records


def _refuse_nested(db, domain_name: str) -> None:
    if db.execute(
        "SELECT 1 FROM domains WHERE substr(?1, -length(name) - 1)='.' || name "
        "OR substr(name, -length(?1) - 1)='.' || ?1", (domain_name,),
    ).fetchone():
        raise ValueError("Ce domaine recouvre une zone déjà gérée par l'instance.")


def generate_keypair() -> tuple[str, str]:
    """Paire WireGuard (privée, publique) générée par l'outil officiel."""
    private = subprocess.run(["wg", "genkey"], check=True, capture_output=True, text=True).stdout.strip()
    public = subprocess.run(["wg", "pubkey"], input=private + "\n", check=True,
                            capture_output=True, text=True).stdout.strip()
    return private, public


def provision_site(
    app: Flask, *, user_email: str, domain_name: str, machine_name: str, machine_ip: str,
    machine_public_key: str | None, port: int, hosts: list[str], mail_records_verified: bool,
    snapshot: Callable[[str, list[str]], list[tuple[str, str, str, int]]] = snapshot_records,
) -> dict[str, int]:
    if not mail_records_verified:
        raise ValueError("Vérifie les enregistrements mail publics avant le rattachement.")
    domain_name = normalize_domain(domain_name, app.config.get("RESERVED_DOMAINS", ()))
    hosts = [relative_name(host, host_only=True) for host in hosts]
    if not hosts or len(set(hosts)) != len(hosts):
        raise ValueError("Il faut au moins un nom d'hôte distinct.")
    if not 1 <= port <= 65535:
        raise ValueError("Port invalide.")
    ip = ipaddress.ip_address(machine_ip)
    if ip not in ipaddress.ip_network("10.88.0.0/24") or ip in (
        ipaddress.ip_address("10.88.0.0"), ipaddress.ip_address("10.88.0.1"),
        ipaddress.ip_address("10.88.0.255"),
    ):
        raise ValueError("Adresse machine hors du tunnel.")
    if machine_public_key is not None and not _valid_key(machine_public_key):
        raise ValueError("Clé publique WireGuard invalide.")

    db = get_db()
    user = db.execute("SELECT id FROM users WHERE email=? AND status='approved'", (user_email.lower(),)).fetchone()
    if user is None:
        raise ValueError("Compte approuvé introuvable.")
    user_id = user["id"]
    existing_domain = db.execute("SELECT id,user_id FROM domains WHERE name=?", (domain_name,)).fetchone()
    if existing_domain and existing_domain["user_id"] != user_id:
        raise ValueError("Domaine déjà rattaché à un autre compte.")
    if existing_domain is None:
        _refuse_nested(db, domain_name)
    copied = snapshot(domain_name, []) if existing_domain is None else []
    if existing_domain is None and not copied:
        raise ValueError("Copie DNS vide : zone non créée.")

    pdns = None
    zone_created = False
    if app.config["PDNS_ENABLED"]:
        pdns = PowerDNS(app.config["PDNS_API_URL"], app.config["PDNS_API_KEY"], (
            f"{app.config['NS1_HOST']}.", f"{app.config['NS2_HOST']}.",
        ))
        if existing_domain is None:
            pdns.create_zone(domain_name)
            zone_created = True
    try:
        with db:
            if existing_domain is None:
                # Contrôle refait sous verrou : une vérification web concurrente a pu créer
                # entre-temps une zone parente ou enfant.
                db.execute("BEGIN IMMEDIATE")
                _refuse_nested(db, domain_name)
                domain_id = db.execute(
                    "INSERT INTO domains(user_id,name,created_at) VALUES(?,?,?)",
                    (user_id, domain_name, now_iso()),
                ).lastrowid
                db.executemany(
                    "INSERT INTO records(domain_id,name,type,content,ttl) VALUES(?,?,?,?,?)",
                    [(domain_id, *record) for record in copied],
                )
            else:
                domain_id = existing_domain["id"]
            machine = db.execute("SELECT * FROM machines WHERE user_id=? AND name=?",
                                 (user_id, machine_name)).fetchone()
            if machine is None:
                if machine_public_key is None:
                    raise ValueError("Machine absente : fournir sa clé publique ou la créer d'abord.")
                if db.execute("SELECT 1 FROM machines WHERE ip=? OR public_key=?",
                              (str(ip), machine_public_key)).fetchone():
                    raise ValueError("IP ou clé WireGuard déjà utilisée.")
                machine_id = db.execute(
                    "INSERT INTO machines(user_id,name,ip,public_key,created_at) VALUES(?,?,?,?,?)",
                    (user_id, machine_name, str(ip), machine_public_key, now_iso()),
                ).lastrowid
            else:
                if machine["ip"] != str(ip) or (machine_public_key is not None
                                                and machine["public_key"] != machine_public_key):
                    raise ValueError("Machine existante avec une autre IP ou clé.")
                machine_id = machine["id"]
            for host in hosts:
                hostname = fqdn(host, domain_name).rstrip(".")
                address = db.execute("SELECT * FROM addresses WHERE hostname=?", (hostname,)).fetchone()
                if address is None:
                    conflicts = ("CNAME",) if host == "@" else ("A", "AAAA", "CNAME")
                    marks = ",".join("?" for _ in conflicts)
                    if db.execute(
                        f"SELECT 1 FROM records WHERE domain_id=? AND name=? AND type IN ({marks})",
                        (domain_id, host, *conflicts),
                    ).fetchone():
                        raise ValueError(f"Enregistrement DNS incompatible sur {hostname}.")
                    db.execute(
                        "INSERT INTO addresses(domain_id,machine_id,hostname,port,protected,shared,created_at,route_token) "
                        "VALUES(?,?,?,?,1,1,?,?)",
                        (domain_id, machine_id, hostname, port, now_iso(), secrets.token_hex(12)),
                    )
                elif (address["domain_id"] != domain_id or address["machine_id"] != machine_id
                      or address["port"] != port or not address["protected"] or not address["shared"]):
                    raise ValueError(f"Adresse existante avec une configuration différente : {hostname}.")
            if pdns:
                pdns.sync_zone(db, domain_id, domain_name, app.config["PUBLIC_IPV4"],
                               app.config["PUBLIC_IPV6"])
    except Exception:
        if zone_created:
            pdns.delete_zone(domain_name)
        raise
    if app.config.get("SYNC_COMMAND"):
        subprocess.run(shlex.split(app.config["SYNC_COMMAND"]), check=True, capture_output=True, timeout=20)
    return {"domain_id": domain_id, "machine_id": machine_id, "copied_records": len(copied),
            "addresses": len(hosts)}


def _valid_key(key: str) -> bool:
    try:
        return len(base64.b64decode(key, validate=True)) == 32
    except (ValueError, binascii.Error):
        return False


def create_machine_config(
    app: Flask, *, user_email: str, machine_name: str, machine_ip: str,
    keypair: tuple[str, str] | None = None,
) -> str:
    """Crée le pair et retourne sa configuration privée pour un flux SSH unique."""
    ip = ipaddress.ip_address(machine_ip)
    if ip not in ipaddress.ip_network("10.88.0.0/24") or ip in (
        ipaddress.ip_address("10.88.0.0"), ipaddress.ip_address("10.88.0.1"),
        ipaddress.ip_address("10.88.0.255"),
    ) or not 1 <= len(machine_name) <= 80:
        raise ValueError("Nom ou adresse de machine invalide.")
    db = get_db()
    user = db.execute("SELECT id FROM users WHERE email=? AND status='approved'", (user_email.lower(),)).fetchone()
    if user is None:
        raise ValueError("Compte approuvé introuvable.")
    if db.execute("SELECT 1 FROM machines WHERE ip=? OR (user_id=? AND name=?)",
                  (str(ip), user["id"], machine_name)).fetchone():
        raise ValueError("Machine ou IP déjà utilisée.")
    if keypair is None:
        private, public = generate_keypair()
    else:
        private, public = keypair
    if not _valid_key(private) or not _valid_key(public):
        raise ValueError("Clé WireGuard invalide.")
    with db:
        machine_id = db.execute(
            "INSERT INTO machines(user_id,name,ip,public_key,created_at) VALUES(?,?,?,?,?)",
            (user["id"], machine_name, str(ip), public, now_iso()),
        ).lastrowid
    if app.config.get("SYNC_COMMAND"):
        try:
            subprocess.run(shlex.split(app.config["SYNC_COMMAND"]), check=True,
                           capture_output=True, timeout=20)
        except Exception:
            with db:
                db.execute("DELETE FROM machines WHERE id=?", (machine_id,))
            raise
    return (
        "[Interface]\n"
        f"PrivateKey = {private}\nAddress = {ip}/32\n\n"
        "[Peer]\n"
        f"PublicKey = {app.config['WG_SERVER_PUBLIC_KEY']}\n"
        f"Endpoint = {app.config['WG_ENDPOINT']}\n"
        "AllowedIPs = 10.88.0.1/32\nPersistentKeepalive = 25\n"
    )
