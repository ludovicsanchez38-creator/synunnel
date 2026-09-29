"""Règles métier partagées par le tableau de bord et l'API.

Chaque contrôle de sécurité (propriété, preuve TXT, recouvrement, quotas, verrous,
conflits DNS, jetons de route) n'existe qu'ici. Les routes HTML et JSON se contentent
de traduire les paramètres et les erreurs.
"""

import re
import secrets
import shlex
import sqlite3
import subprocess
import time

import requests
from flask import Flask

from .db import get_db, now_iso
from .dns import (
    VERIFY_LABEL,
    PowerDNS,
    canonical_content,
    delegation_status,
    fqdn,
    normalize_domain,
    ownership_proof,
    relative_name,
    snapshot_records,
)
from .provision import generate_keypair

EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
MACHINE_NAME_MAX = 80


class ActionError(Exception):
    """Refus d'une action, avec le statut HTTP et un code stable pour les agents."""

    def __init__(self, status: int, code: str, message: str):
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message


def _invalid(message: str) -> ActionError:
    return ActionError(422, "invalid", message)


def rate_limit(kind: str, key: str, limit: int, window: int) -> None:
    db = get_db()
    now = int(time.time())
    db.execute("DELETE FROM attempts WHERE at < ?", (now - 86400,))
    count = db.execute(
        "SELECT COUNT(*) FROM attempts WHERE kind=? AND key=? AND at>=?",
        (kind, key, now - window),
    ).fetchone()[0]
    if count >= limit:
        db.commit()
        raise ActionError(429, "rate_limited", "Trop de tentatives. Réessaie plus tard.")
    db.execute("INSERT INTO attempts(kind, key, at) VALUES (?, ?, ?)", (kind, key, now))
    db.commit()


def _pdns(app: Flask) -> PowerDNS:
    return PowerDNS(app.config["PDNS_API_URL"], app.config["PDNS_API_KEY"], (
        f"{app.config['NS1_HOST']}.", f"{app.config['NS2_HOST']}.",
    ))


def sync_zone(app: Flask, db, domain) -> None:
    if app.config["PDNS_ENABLED"]:
        _pdns(app).sync_zone(
            db, domain["id"], domain["name"], app.config["PUBLIC_IPV4"], app.config["PUBLIC_IPV6"],
        )


def sync_runtime(app: Flask) -> None:
    command = app.config.get("SYNC_COMMAND", "")
    if command:
        subprocess.run(shlex.split(command), check=True, capture_output=True, timeout=20)


def refuse_overlap(db, domain: str) -> None:
    """Refuse un domaine qui contient une zone existante ou qui est contenu dans l'une d'elles."""
    row = db.execute(
        "SELECT name FROM domains WHERE name=? OR substr(?, -length(name) - 1)='.' || name "
        "OR substr(name, -length(?) - 1)='.' || ? LIMIT 1",
        (domain, domain, domain, domain),
    ).fetchone()
    if row is not None:
        if row["name"] == domain:
            raise ActionError(409, "conflict", "Ce domaine est déjà enregistré.")
        raise ActionError(409, "conflict", f"Ce domaine recouvre la zone {row['name']}, déjà gérée par l'instance.")


def parse_grants(raw: str | list[str]) -> list[str]:
    parts = raw if isinstance(raw, list) else re.split(r"[,;\s]+", raw.strip())
    if not all(isinstance(part, str) for part in parts):
        raise _invalid("Liste invalide : des adresses mail sous forme de texte.")
    emails = sorted({part.strip().lower() for part in parts if part.strip()})
    if len(emails) > 100 or any(len(email) > 254 or not EMAIL_RE.fullmatch(email) for email in emails):
        raise _invalid("Liste invalide : au maximum 100 adresses mail valides.")
    return emails


# ---------------------------------------------------------------- propriété

def owned_domain(user_id: int, domain_id: int):
    row = get_db().execute("SELECT * FROM domains WHERE id=? AND user_id=?", (domain_id, user_id)).fetchone()
    if row is None:
        raise ActionError(404, "not_found", "Domaine introuvable.")
    return row


def owned_machine(user_id: int, machine_id: int):
    row = get_db().execute("SELECT * FROM machines WHERE id=? AND user_id=?", (machine_id, user_id)).fetchone()
    if row is None:
        raise ActionError(404, "not_found", "Machine introuvable.")
    return row


def owned_claim(user_id: int, claim_id: int):
    row = get_db().execute(
        "SELECT * FROM domain_claims WHERE id=? AND user_id=?", (claim_id, user_id),
    ).fetchone()
    if row is None:
        raise ActionError(404, "not_found", "Demande introuvable.")
    return row


def owned_address(user_id: int, address_id: int):
    row = get_db().execute(
        "SELECT a.*, d.name AS domain_name FROM addresses a JOIN domains d ON d.id=a.domain_id "
        "WHERE a.id=? AND d.user_id=?", (address_id, user_id),
    ).fetchone()
    if row is None:
        raise ActionError(404, "not_found", "Adresse introuvable.")
    return row


def claim_proof(claim) -> dict[str, str]:
    return {"type": "TXT", "name": f"{VERIFY_LABEL}.{claim['name']}",
            "value": f"synunnel-verification={claim['token']}"}


# ---------------------------------------------------------------- lecture

def account_overview(user_id: int) -> dict:
    db = get_db()
    return {
        "domains": db.execute("SELECT * FROM domains WHERE user_id=? ORDER BY name", (user_id,)).fetchall(),
        "claims": db.execute("SELECT * FROM domain_claims WHERE user_id=? ORDER BY name", (user_id,)).fetchall(),
        "machines": db.execute("SELECT * FROM machines WHERE user_id=? ORDER BY name", (user_id,)).fetchall(),
        "addresses": db.execute(
            "SELECT a.*, d.name AS domain_name, m.name AS machine_name, "
            "(SELECT COUNT(*) FROM address_grants g WHERE g.address_id=a.id) AS grant_count "
            "FROM addresses a JOIN domains d ON d.id=a.domain_id JOIN machines m ON m.id=a.machine_id "
            "WHERE d.user_id=? ORDER BY a.hostname", (user_id,),
        ).fetchall(),
    }


def domain_view(app: Flask, user_id: int, domain_id: int) -> dict:
    domain = owned_domain(user_id, domain_id)
    records = get_db().execute(
        "SELECT * FROM records WHERE domain_id=? ORDER BY name,type,content", (domain_id,),
    ).fetchall()
    nameservers = (f"{app.config['NS1_HOST']}.", f"{app.config['NS2_HOST']}.")
    active, parent_ns = delegation_status(domain["name"], nameservers)
    return {"domain": domain, "records": records, "active": active, "parent_ns": parent_ns,
            "nameservers": nameservers}


# ---------------------------------------------------------------- domaines

def create_claim(app: Flask, user_id: int, domain_raw: str, selectors: list[str], mail_checked: bool):
    try:
        domain = normalize_domain(domain_raw, app.config["RESERVED_DOMAINS"])
        clean = [relative_name(item.strip()) for item in selectors if item.strip()]
    except ValueError as exc:
        raise _invalid(str(exc)) from exc
    if len(clean) > 20 or any("." in item or item == "@" for item in clean):
        raise _invalid("Au maximum 20 sélecteurs DKIM simples.")
    if not mail_checked:
        raise _invalid("Confirme la vérification des enregistrements mail et des sélecteurs DKIM.")
    db = get_db()
    with db:
        db.execute("BEGIN IMMEDIATE")
        refuse_overlap(db, domain)
        owned = db.execute("SELECT COUNT(*) FROM domains WHERE user_id=?", (user_id,)).fetchone()[0]
        pending = db.execute(
            "SELECT COUNT(*) FROM domain_claims WHERE user_id=? AND name<>?", (user_id, domain),
        ).fetchone()[0]
        if owned + pending >= app.config["MAX_DOMAINS_PER_USER"]:
            raise ActionError(409, "quota", "Nombre maximal de domaines atteint pour ce compte.")
        db.execute(
            "INSERT INTO domain_claims(user_id,name,token,selectors,created_at) VALUES(?,?,?,?,?) "
            "ON CONFLICT(user_id,name) DO UPDATE SET selectors=excluded.selectors",
            (user_id, domain, secrets.token_urlsafe(24), ",".join(clean), now_iso()),
        )
    return db.execute("SELECT * FROM domain_claims WHERE user_id=? AND name=?", (user_id, domain)).fetchone()


def cancel_claim(user_id: int, claim_id: int) -> None:
    owned_claim(user_id, claim_id)
    with get_db() as db:
        db.execute("DELETE FROM domain_claims WHERE id=? AND user_id=?", (claim_id, user_id))


def verify_claim(app: Flask, user_id: int, claim_id: int) -> tuple[int, int]:
    """Preuve TXT puis création de la zone. Renvoie (id du domaine, nombre d'enregistrements copiés)."""
    claim = owned_claim(user_id, claim_id)
    rate_limit("verify", str(user_id), 20, 3600)
    domain = claim["name"]
    db = get_db()
    try:
        # Une réservation ajoutée après la demande s'applique aussi à la vérification.
        normalize_domain(domain, app.config["RESERVED_DOMAINS"])
    except ValueError as exc:
        raise _invalid(str(exc)) from exc
    refuse_overlap(db, domain)
    try:
        proof = ownership_proof(domain)
    except ValueError as exc:
        raise ActionError(422, "dns_unreachable", str(exc)) from exc
    if claim_proof(claim)["value"] not in proof:
        raise ActionError(422, "proof_missing", "Enregistrement de vérification introuvable. S'il vient d'être "
                          "ajouté, réessaie dans quelques minutes.")
    selectors = [item for item in claim["selectors"].split(",") if item]
    try:
        snapshot = snapshot_records(domain, selectors)
    except ValueError as exc:
        raise _invalid(str(exc)) from exc
    if not snapshot:
        raise _invalid("Aucun enregistrement public trouvé ; la copie DNS serait vide.")
    pdns = _pdns(app) if app.config["PDNS_ENABLED"] else None
    try:
        if pdns:
            pdns.create_zone(domain)
    except requests.RequestException as exc:
        raise ActionError(502, "dns_backend", "Le serveur DNS de l'instance a refusé la création de la zone.") from exc
    try:
        with db:
            db.execute("BEGIN IMMEDIATE")
            if not db.execute(
                "SELECT 1 FROM domain_claims WHERE id=? AND user_id=? AND name=? AND token=?",
                (claim_id, user_id, domain, claim["token"]),
            ).fetchone():
                raise ActionError(409, "conflict", "Cette demande a été annulée entre-temps.")
            owned = db.execute("SELECT COUNT(*) FROM domains WHERE user_id=?", (user_id,)).fetchone()[0]
            if owned >= app.config["MAX_DOMAINS_PER_USER"]:
                raise ActionError(409, "quota", "Nombre maximal de domaines atteint pour ce compte.")
            refuse_overlap(db, domain)
            domain_id = db.execute(
                "INSERT INTO domains(user_id,name,created_at) VALUES(?,?,?)", (user_id, domain, now_iso()),
            ).lastrowid
            db.executemany(
                "INSERT INTO records(domain_id,name,type,content,ttl) VALUES(?,?,?,?,?)",
                [(domain_id, *record) for record in snapshot],
            )
            # La preuve est faite : les demandes concurrentes sur ce nom tombent.
            db.execute("DELETE FROM domain_claims WHERE name=?", (domain,))
            if pdns:
                pdns.sync_zone(db, domain_id, domain, app.config["PUBLIC_IPV4"], app.config["PUBLIC_IPV6"])
    except Exception as exc:
        if pdns:
            try:
                pdns.delete_zone(domain)
            except requests.RequestException:
                pass
        if isinstance(exc, ActionError):
            raise
        if isinstance(exc, sqlite3.IntegrityError):
            raise ActionError(409, "conflict", "Ce domaine est déjà enregistré.") from exc
        if isinstance(exc, requests.RequestException):
            raise ActionError(502, "dns_backend", "Le serveur DNS de l'instance a refusé la zone.") from exc
        raise
    return domain_id, len(snapshot)


def add_record(app: Flask, user_id: int, domain_id: int, name_raw: str, kind_raw: str, content_raw: str,
               ttl_raw) -> int:
    domain = owned_domain(user_id, domain_id)
    try:
        name = relative_name(str(name_raw))
        kind = str(kind_raw).upper()
        content = canonical_content(kind, str(content_raw))
        ttl = int(ttl_raw)
        fqdn(name, domain["name"])
    except (ValueError, TypeError) as exc:
        raise _invalid(str(exc) or "Enregistrement invalide.") from exc
    if not 300 <= ttl <= 86400:
        raise _invalid("TTL entre 300 et 86 400 secondes.")
    db = get_db()
    try:
        with db:
            db.execute("BEGIN IMMEDIATE")
            existing = db.execute("SELECT type FROM records WHERE domain_id=? AND name=?", (domain_id, name)).fetchall()
            if (kind == "CNAME" and existing) or (kind != "CNAME" and any(row["type"] == "CNAME" for row in existing)):
                raise ActionError(409, "conflict", "Un CNAME ne peut partager son nom avec un autre enregistrement.")
            host = fqdn(name, domain["name"]).rstrip(".")
            if kind in {"A", "AAAA", "CNAME"} and db.execute(
                "SELECT 1 FROM addresses WHERE hostname=?", (host,),
            ).fetchone():
                raise ActionError(409, "conflict",
                                  "Cette adresse est gérée par Synunnel ; supprime-la avant de modifier son DNS.")
            record_id = db.execute(
                "INSERT INTO records(domain_id,name,type,content,ttl) VALUES(?,?,?,?,?)",
                (domain_id, name, kind, content, ttl),
            ).lastrowid
            sync_zone(app, db, domain)
    except sqlite3.IntegrityError as exc:
        raise ActionError(409, "conflict", "Cet enregistrement existe déjà.") from exc
    except requests.RequestException as exc:
        raise ActionError(502, "dns_backend", "Le serveur DNS de l'instance a refusé la modification.") from exc
    return record_id


def delete_record(app: Flask, user_id: int, domain_id: int, record_id: int) -> None:
    domain = owned_domain(user_id, domain_id)
    db = get_db()
    try:
        with db:
            cursor = db.execute("DELETE FROM records WHERE id=? AND domain_id=?", (record_id, domain_id))
            if cursor.rowcount != 1:
                raise ActionError(404, "not_found", "Enregistrement introuvable.")
            sync_zone(app, db, domain)
    except requests.RequestException as exc:
        raise ActionError(502, "dns_backend", "Le serveur DNS de l'instance a refusé la modification.") from exc


# ---------------------------------------------------------------- machines

def create_machine(app: Flask, user_id: int, name_raw: str) -> dict:
    name = str(name_raw).strip()
    if not 1 <= len(name) <= MACHINE_NAME_MAX or any(ord(char) < 32 for char in name):
        raise _invalid("Nom de machine invalide.")
    db = get_db()
    private_key, public_key = generate_keypair()
    machine_id = None
    try:
        with db:
            # Quota et choix de l'IP sous verrou d'écriture : deux ajouts simultanés ne
            # peuvent ni dépasser le quota ni viser la même adresse.
            db.execute("BEGIN IMMEDIATE")
            owned = db.execute("SELECT COUNT(*) FROM machines WHERE user_id=?", (user_id,)).fetchone()[0]
            if owned >= app.config["MAX_MACHINES_PER_USER"]:
                raise ActionError(409, "quota", "Nombre maximal de machines atteint pour ce compte.")
            used = {row[0] for row in db.execute("SELECT ip FROM machines")}
            ip = next((f"10.88.0.{n}" for n in range(2, 255) if f"10.88.0.{n}" not in used), None)
            if ip is None:
                raise ActionError(409, "exhausted", "Plage d'adresses WireGuard épuisée.")
            machine_id = db.execute(
                "INSERT INTO machines(user_id,name,ip,public_key,created_at) VALUES(?,?,?,?,?)",
                (user_id, name, ip, public_key, now_iso()),
            ).lastrowid
        sync_runtime(app)
    except sqlite3.IntegrityError as exc:
        raise ActionError(409, "conflict", "Une machine porte déjà ce nom sur ce compte.") from exc
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        with db:
            db.execute("DELETE FROM machines WHERE id=? AND user_id=?", (machine_id, user_id))
        try:
            sync_runtime(app)
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            pass
        raise ActionError(502, "sync_failed", "Synchronisation WireGuard échouée ; la machine a été annulée.") from exc
    config = (
        "[Interface]\n"
        f"PrivateKey = {private_key}\nAddress = {ip}/32\n\n"
        "[Peer]\n"
        f"PublicKey = {app.config['WG_SERVER_PUBLIC_KEY']}\n"
        f"Endpoint = {app.config['WG_ENDPOINT']}\n"
        "AllowedIPs = 10.88.0.1/32\nPersistentKeepalive = 25\n"
    )
    return {"id": machine_id, "name": name, "ip": ip, "public_key": public_key, "config": config}


def delete_machine(app: Flask, user_id: int, machine_id: int) -> None:
    owned_machine(user_id, machine_id)
    db = get_db()
    with db:
        # Vérification et suppression sous le même verrou : une adresse ajoutée entre les deux
        # serait sinon supprimée en cascade sans que son propriétaire le sache.
        db.execute("BEGIN IMMEDIATE")
        if db.execute("SELECT 1 FROM addresses WHERE machine_id=?", (machine_id,)).fetchone():
            raise ActionError(409, "in_use", "Supprime d'abord les adresses liées à cette machine.")
        db.execute("DELETE FROM machines WHERE id=? AND user_id=?", (machine_id, user_id))
    try:
        sync_runtime(app)
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        raise ActionError(502, "sync_failed", "Machine supprimée de la base ; la synchronisation WireGuard a "
                          "échoué, relance-la.") from exc


# ---------------------------------------------------------------- adresses

def create_address(app: Flask, user_id: int, domain_id, machine_id, name_raw: str, port_raw,
                   protected: bool) -> dict:
    try:
        domain_id = int(domain_id)
        machine_id = int(machine_id)
        port = int(port_raw)
    except (TypeError, ValueError) as exc:
        raise _invalid("Domaine, machine ou port invalide.") from exc
    domain = owned_domain(user_id, domain_id)
    owned_machine(user_id, machine_id)
    try:
        name = relative_name(str(name_raw), host_only=True)
        hostname = fqdn(name, domain["name"]).rstrip(".")
    except ValueError as exc:
        raise _invalid(str(exc)) from exc
    if not 1 <= port <= 65535:
        raise _invalid("Port invalide.")
    db = get_db()
    conflict_types = ("CNAME",) if name == "@" else ("A", "AAAA", "CNAME")
    try:
        with db:
            db.execute("BEGIN IMMEDIATE")
            if db.execute(
                f"SELECT 1 FROM records WHERE domain_id=? AND name=? AND type IN ({','.join('?' for _ in conflict_types)})",
                (domain_id, name, *conflict_types),
            ).fetchone():
                raise ActionError(409, "conflict", "Un enregistrement DNS incompatible existe déjà pour ce nom.")
            address_id = db.execute(
                "INSERT INTO addresses(domain_id,machine_id,hostname,port,protected,created_at,route_token) "
                "VALUES(?,?,?,?,?,?,?)",
                (domain_id, machine_id, hostname, port, int(bool(protected)), now_iso(), secrets.token_hex(12)),
            ).lastrowid
            sync_zone(app, db, domain)
    except sqlite3.IntegrityError as exc:
        raise ActionError(409, "conflict", "Cette adresse existe déjà.") from exc
    except requests.RequestException as exc:
        raise ActionError(502, "dns_backend", "Le serveur DNS de l'instance a refusé l'adresse.") from exc
    try:
        sync_runtime(app)
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        with db:
            db.execute("DELETE FROM addresses WHERE id=?", (address_id,))
            try:
                sync_zone(app, db, domain)
            except requests.RequestException:
                pass
        try:
            sync_runtime(app)
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            pass
        raise ActionError(502, "sync_failed", "Synchronisation Caddy échouée ; l'adresse a été annulée.") from exc
    return {"id": address_id, "hostname": hostname}


def delete_address(app: Flask, user_id: int, address_id: int) -> None:
    row = owned_address(user_id, address_id)
    domain = {"id": row["domain_id"], "name": row["domain_name"]}
    db = get_db()
    try:
        with db:
            db.execute("DELETE FROM addresses WHERE id=?", (address_id,))
            db.execute("DELETE FROM host_sessions WHERE hostname=?", (row["hostname"],))
            db.execute("DELETE FROM access_codes WHERE hostname=?", (row["hostname"],))
            sync_zone(app, db, domain)
    except requests.RequestException as exc:
        raise ActionError(502, "dns_backend", "Le serveur DNS de l'instance a refusé la suppression.") from exc
    try:
        sync_runtime(app)
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        raise ActionError(502, "sync_failed", "Adresse retirée de la base et du DNS ; le contrôle d'accès bloque "
                          "déjà l'ancienne route. Relance la synchronisation Caddy.") from exc


def protected_address(user_id: int, address_id: int):
    row = owned_address(user_id, address_id)
    if not row["protected"]:
        raise ActionError(404, "not_found", "Adresse protégée introuvable.")
    return row


def access_list(user_id: int, address_id: int) -> tuple:
    address = protected_address(user_id, address_id)
    emails = [row[0] for row in get_db().execute(
        "SELECT email FROM address_grants WHERE address_id=? ORDER BY email", (address_id,),
    )]
    return address, emails


def set_access(user_id: int, address_id: int, shared: bool, emails_raw) -> list[str]:
    address = protected_address(user_id, address_id)
    emails = parse_grants(emails_raw)
    if shared and not emails:
        raise _invalid("Ajoute au moins une adresse mail pour activer l'accès partagé.")
    with get_db() as db:
        db.execute("UPDATE addresses SET shared=? WHERE id=?", (int(bool(shared)), address_id))
        db.execute("DELETE FROM address_grants WHERE address_id=?", (address_id,))
        if shared:
            db.executemany("INSERT INTO address_grants(address_id,email) VALUES(?,?)",
                           [(address_id, email) for email in emails])
        # Les cookies et codes précédents sont révoqués à chaque changement.
        db.execute("DELETE FROM host_sessions WHERE hostname=?", (address["hostname"],))
        db.execute("DELETE FROM access_codes WHERE hostname=?", (address["hostname"],))
    return emails if shared else []
