"""Rattachement administratif d'un site local à un compte déjà approuvé."""

import base64
import binascii
import ipaddress
import secrets
import shlex
import subprocess
from collections.abc import Callable

from flask import Flask

from .db import allocate_id, get_db, now_iso
from .dns import canonical_content, fqdn, normalize_domain, relative_name, snapshot_records
from .keys import generate_keypair


def _refuse_nested(db, domain_name: str) -> None:
    if db.execute(
        "SELECT 1 FROM domains WHERE substr(?, -length(name) - 1)='.' || name "
        "OR substr(name, -length(?) - 1)='.' || ?", (domain_name, domain_name, domain_name),
    ).fetchone():
        raise ValueError("Ce domaine recouvre une zone déjà gérée par l'instance.")


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
    # Mêmes contrôles de contenu qu'une saisie ; l'administrateur n'est pas tenu par le quota.
    copied = [(rel if rel == "@" else relative_name(rel), kind, canonical_content(kind, content), ttl)
              for rel, kind, content, ttl in copied]
    if existing_domain is None and not copied:
        raise ValueError("Copie DNS vide : zone non créée.")

    # Tout est vérifié et écrit sous un seul verrou d'écriture, sans appel réseau ; PowerDNS et le
    # tunnel sont mis à jour ensuite et le rapprochement automatique termine en cas d'échec. Le verrou de
    # zone, pris avant, attend qu'un retrait en cours du même nom ait fini d'effacer l'ancienne zone.
    from . import actions  # import tardif : actions dépend de ce module pour les clés
    with actions.name_lock(app, domain_name), db:
        db.execute("BEGIN IMMEDIATE")
        if existing_domain is None:
            # Contrôle refait sous verrou : une vérification web concurrente a pu créer
            # entre-temps une zone parente ou enfant.
            _refuse_nested(db, domain_name)
            domain_id = db.execute(
                "INSERT INTO domains(id,user_id,name,created_at) VALUES(?,?,?,?)",
                (allocate_id(db, "domains"), user_id, domain_name, now_iso()),
            ).lastrowid
            for record in copied:
                db.execute("INSERT INTO records(id,domain_id,name,type,content,ttl) VALUES(?,?,?,?,?,?)",
                           (allocate_id(db, "records"), domain_id, *record))
            db.execute("DELETE FROM zone_removals WHERE name=?", (domain_name,))
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
                "INSERT INTO machines(id,user_id,name,ip,public_key,created_at) VALUES(?,?,?,?,?,?)",
                (allocate_id(db, "machines"), user_id, machine_name, str(ip), machine_public_key, now_iso()),
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
                    "INSERT INTO addresses(id,domain_id,machine_id,hostname,port,protected,shared,created_at,route_token) "
                    "VALUES(?,?,?,?,?,1,1,?,?)",
                    (allocate_id(db, "addresses"), domain_id, machine_id, hostname, port, now_iso(),
                     secrets.token_hex(12)),
                )
            elif (address["domain_id"] != domain_id or address["machine_id"] != machine_id
                  or address["port"] != port or not address["protected"] or not address["shared"]):
                raise ValueError(f"Adresse existante avec une configuration différente : {hostname}.")
    if not actions.project_zone(app, {"id": domain_id, "name": domain_name}):
        print("PowerDNS pas encore à jour : le rapprochement automatique terminera.")
    if app.config.get("SYNC_COMMAND"):
        try:
            subprocess.run(shlex.split(app.config["SYNC_COMMAND"]), check=True, capture_output=True, timeout=20)
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            print("Synchronisation du tunnel en échec : le rapprochement automatique terminera.")
    return {"domain_id": domain_id, "machine_id": machine_id, "copied_records": len(copied),
            "addresses": len(hosts)}


def _valid_key(key: str) -> bool:
    try:
        raw = base64.b64decode(key, validate=True)
    except (ValueError, binascii.Error, TypeError):
        return False
    return len(raw) == 32 and base64.b64encode(raw).decode() == key


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
        db.execute("BEGIN IMMEDIATE")
        if db.execute("SELECT 1 FROM machines WHERE ip=? OR public_key=? OR (user_id=? AND name=?)",
                      (str(ip), public, user["id"], machine_name)).fetchone():
            raise ValueError("Machine, IP ou clé déjà utilisée.")
        db.execute(
            "INSERT INTO machines(id,user_id,name,ip,public_key,created_at) VALUES(?,?,?,?,?,?)",
            (allocate_id(db, "machines"), user["id"], machine_name, str(ip), public, now_iso()),
        )
    if app.config.get("SYNC_COMMAND"):
        try:
            subprocess.run(shlex.split(app.config["SYNC_COMMAND"]), check=True,
                           capture_output=True, timeout=20)
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            # Pas de suppression compensatoire : le pair est en base, le rapprochement l'installera.
            print("Synchronisation du tunnel en échec : le rapprochement automatique terminera.")
    return (
        "[Interface]\n"
        f"PrivateKey = {private}\nAddress = {ip}/32\n\n"
        "[Peer]\n"
        f"PublicKey = {app.config['WG_SERVER_PUBLIC_KEY']}\n"
        f"Endpoint = {app.config['WG_ENDPOINT']}\n"
        "AllowedIPs = 10.88.0.1/32\nPersistentKeepalive = 25\n"
    )
