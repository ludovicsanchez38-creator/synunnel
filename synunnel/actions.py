"""Règles métier partagées par le tableau de bord et l'API.

Chaque contrôle de sécurité (propriété, preuve TXT, recouvrement, quotas, verrous,
conflits DNS, jetons de route) n'existe qu'ici. Les routes HTML et JSON se contentent
de traduire les paramètres et les erreurs.

La base SQLite fait foi. Chaque mutation vérifie ses conditions et écrit sous un même
verrou d'écriture (BEGIN IMMEDIATE), sans appel réseau pendant ce verrou. PowerDNS,
WireGuard et Caddy sont ensuite mis à jour ; si l'un d'eux échoue, l'état voulu reste en
base et le rapprochement périodique (scripts/reconcile.py) le termine.
"""

import base64
import fcntl
import ipaddress
import random
import re
import secrets
import shlex
import sqlite3
import subprocess
import time
import unicodedata
from collections.abc import Callable

import requests
from flask import Flask, current_app

from .db import allocate_id, get_db, now_iso
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
    still_designated,
)
from .keys import generate_keypair

EMAIL_RE = re.compile(r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$")
MACHINE_NAME_MAX = 80
Guard = Callable[[sqlite3.Connection], None] | None


class ActionError(Exception):
    """Refus d'une action, avec le statut HTTP et un code stable pour les agents."""

    def __init__(self, status: int, code: str, message: str, headers: dict | None = None):
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message
        self.headers = headers or {}


class _Replay(Exception):
    """Demande déjà satisfaite : on sort de la transaction sans rien écrire, puis on reprojette."""

    def __init__(self, result: dict):
        super().__init__()
        self.result = result


def _invalid(message: str) -> ActionError:
    return ActionError(422, "invalid", message)


def client_bucket(raw: str | None) -> str:
    """Clé de limitation d'une adresse : une IPv6 compte pour son /64, qu'un seul abonné détient en entier."""
    try:
        ip = ipaddress.ip_address(raw or "")
    except ValueError:
        return "inconnue"
    if ip.version == 6:
        if ip.ipv4_mapped:
            return str(ip.ipv4_mapped)
        return str(ipaddress.ip_network(f"{ip}/64", strict=False))
    return str(ip)


def limit_reached(kind: str, key: str, limit: int, window: int) -> bool:
    return get_db().execute(
        "SELECT COUNT(*) FROM attempts WHERE kind=? AND key=? AND at>=?", (kind, key, int(time.time()) - window),
    ).fetchone()[0] >= limit


def record_attempt(kind: str, key: str) -> None:
    db = get_db()
    now = int(time.time())
    if random.random() < 0.01:
        # Purge occasionnelle et indexée : jamais un parcours de table à chaque requête.
        db.execute("DELETE FROM attempts WHERE at < ?", (now - 86400,))
    db.execute("INSERT INTO attempts(kind, key, at) VALUES (?, ?, ?)", (kind, key, now))
    db.commit()


def reserve_attempt(kind: str, key: str, limit: int, window: int) -> int | None:
    """Compte et réserve un essai sous un même verrou, sur une connexion à part de celle de la
    requête : des requêtes simultanées ne peuvent pas toutes voir une place libre. Renvoie
    l'identifiant de la réservation, ou None si la limite est atteinte."""
    conn = sqlite3.connect(current_app.config["DATABASE"], timeout=10, isolation_level=None)
    try:
        conn.execute("PRAGMA busy_timeout=10000")
        conn.execute("BEGIN IMMEDIATE")
        now = int(time.time())
        used = conn.execute("SELECT COUNT(*) FROM attempts WHERE kind=? AND key=? AND at>=?",
                            (kind, key, now - window)).fetchone()[0]
        if used >= limit:
            conn.execute("ROLLBACK")
            return None
        attempt_id = conn.execute("INSERT INTO attempts(kind, key, at) VALUES (?, ?, ?)", (kind, key, now)).lastrowid
        conn.execute("COMMIT")
        return attempt_id
    finally:
        conn.close()


def release_attempts(*attempt_ids: int | None) -> None:
    """Rend des réservations : un essai réussi ne compte pas comme un échec."""
    ids = [item for item in attempt_ids if item]
    if not ids:
        return
    conn = sqlite3.connect(current_app.config["DATABASE"], timeout=10, isolation_level=None)
    try:
        conn.execute("PRAGMA busy_timeout=10000")
        conn.executemany("DELETE FROM attempts WHERE id=?", [(item,) for item in ids])
    finally:
        conn.close()


def rate_limit(kind: str, key: str, limit: int, window: int) -> None:
    if limit_reached(kind, key, limit, window):
        raise ActionError(429, "rate_limited", "Trop de tentatives. Réessaie plus tard.", {"Retry-After": str(window)})
    record_attempt(kind, key)


def clean_label(value, maximum: int, what: str) -> str:
    """Texte affiché à un humain : sans caractère de contrôle ni caractère invisible ou de mise en forme."""
    text = unicodedata.normalize("NFC", value.strip()) if isinstance(value, str) else ""
    if not 1 <= len(text) <= maximum or any(unicodedata.category(char) in {"Cc", "Cf", "Co", "Cs", "Zl", "Zp"}
                                             for char in text):
        raise ActionError(422, "invalid", f"{what} invalide (1 à {maximum} caractères visibles).")
    return text


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


def zone_lock(app: Flask, name: str):
    """Verrou de fichier par zone : deux projections ne s'entrelacent jamais, la plus récente lit la base
    après la plus ancienne et gagne toujours."""
    from pathlib import Path
    folder = Path(app.config["DATABASE"]).parent / "locks"
    folder.mkdir(mode=0o700, exist_ok=True)
    handle = open(folder / f"zone-{name}.lock", "w")  # noqa: SIM115 - libéré par l'appelant
    fcntl.flock(handle, fcntl.LOCK_EX)
    return handle


def project_zone(app: Flask, domain) -> bool:
    """Applique la zone voulue à PowerDNS, sans verrou SQLite. False : le rapprochement finira."""
    if not app.config["PDNS_ENABLED"]:
        return True
    lock = zone_lock(app, domain["name"])
    try:
        # Sous le verrou de zone, on relit l'incarnation courante : un domaine supprimé entre-temps
        # n'est jamais recréé dans PowerDNS par une projection engagée avant sa suppression.
        current = get_db().execute("SELECT id FROM domains WHERE id=? AND name=?",
                                   (domain["id"], domain["name"])).fetchone()
        if current is None:
            return True
        pdns = _pdns(app)
        pdns.ensure_zone(domain["name"])
        pdns.sync_zone(get_db(), domain["id"], domain["name"], app.config["PUBLIC_IPV4"], app.config["PUBLIC_IPV6"],
                       deadline=time.monotonic() + 60)
    except requests.RequestException:
        return False
    finally:
        lock.close()
    return True


def project_runtime(app: Flask) -> bool:
    """Régénère WireGuard et Caddy depuis la base. False : le rapprochement finira."""
    try:
        sync_runtime(app)
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return False
    return True


def _begin(db, guard: Guard) -> None:
    db.execute("BEGIN IMMEDIATE")
    if guard is not None:
        # Le jeton ou le compte peut avoir été révoqué pendant les vérifications DNS :
        # on le recontrôle sous le verrou qui accepte l'opération.
        guard(db)


def refuse_overlap(db, domain: str, user_id: int) -> None:
    """Refuse un domaine qui contient une zone existante ou qui est contenu dans l'une d'elles.

    Le nom d'une zone d'un autre compte n'est jamais révélé.
    """
    row = db.execute(
        "SELECT name, user_id FROM domains WHERE name=? OR substr(?, -length(name) - 1)='.' || name "
        "OR substr(name, -length(?) - 1)='.' || ? LIMIT 1",
        (domain, domain, domain, domain),
    ).fetchone()
    if row is None:
        return
    if row["user_id"] != user_id:
        raise ActionError(409, "unavailable", "Ce domaine ne peut pas être ajouté sur cette instance.")
    if row["name"] == domain:
        raise ActionError(409, "conflict", "Ce domaine est déjà dans ton espace.")
    raise ActionError(409, "conflict", f"Ce domaine recouvre ta zone {row['name']}.")


def parse_grants(raw: str | list[str]) -> list[str]:
    parts = raw if isinstance(raw, list) else re.split(r"[,;\s]+", raw.strip())
    if not all(isinstance(part, str) for part in parts):
        raise _invalid("Liste invalide : des adresses mail sous forme de texte.")
    # Adresses en ASCII seulement : un « а » cyrillique ou un caractère invisible ne doit pas
    # pouvoir passer pour l'adresse d'une autre personne.
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
        "claims": db.execute("SELECT * FROM domain_claims WHERE user_id=? AND domain_id IS NULL ORDER BY name",
                             (user_id,)).fetchall(),
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
    # État de délégation relevé par le rapprochement automatique : afficher une page ne déclenche
    # jamais de requête DNS sortante.
    active = None if domain["delegation_active"] is None else bool(domain["delegation_active"])
    parent_ns = (domain["delegation_ns"] or "").split(",") if domain["delegation_ns"] else []
    return {"domain": domain, "records": records, "active": active, "parent_ns": parent_ns,
            "nameservers": nameservers, "checked_at": domain["delegation_checked_at"]}


def refresh_delegation(app: Flask, domain) -> tuple[bool | None, list[str]]:
    """Relève la délégation, l'inscrit pour l'affichage et la renvoie. Un relevé commencé avant celui déjà
    en base ne l'écrase pas : deux relevés concurrents laissent toujours le plus récent."""
    nameservers = (f"{app.config['NS1_HOST']}.", f"{app.config['NS2_HOST']}.")
    started = int(time.time())
    active, parent_ns = delegation_status(domain["name"], nameservers)
    with get_db() as db:
        db.execute("UPDATE domains SET delegation_active=?, delegation_ns=?, delegation_checked_at=? "
                   "WHERE id=? AND (delegation_checked_at IS NULL OR delegation_checked_at<=?)",
                   (None if active is None else int(active), ",".join(parent_ns)[:1000], started,
                    domain["id"], started))
    return active, parent_ns


# ---------------------------------------------------------------- domaines

def create_claim(app: Flask, user_id: int, domain_raw: str, selectors: list[str], mail_checked: bool,
                 guard: Guard = None, audit: Callable | None = None):
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
        _begin(db, guard)
        existing = db.execute("SELECT * FROM domain_claims WHERE user_id=? AND name=?",
                              (user_id, domain)).fetchone()
        if existing is not None and existing["domain_id"] is not None:
            raise ActionError(409, "conflict", "Ce domaine est déjà dans ton espace.")
        if existing is not None and existing["selectors"] == ",".join(clean):
            return existing, False
        refuse_overlap(db, domain, user_id)
        owned = db.execute("SELECT COUNT(*) FROM domains WHERE user_id=?", (user_id,)).fetchone()[0]
        pending = db.execute(
            "SELECT COUNT(*) FROM domain_claims WHERE user_id=? AND name<>? AND domain_id IS NULL", (user_id, domain),
        ).fetchone()[0]
        if owned + pending >= app.config["MAX_DOMAINS_PER_USER"]:
            raise ActionError(409, "quota", "Nombre maximal de domaines atteint pour ce compte.")
        db.execute(
            "INSERT INTO domain_claims(id,user_id,name,token,selectors,created_at) VALUES(?,?,?,?,?,?) "
            "ON CONFLICT(user_id,name) DO UPDATE SET selectors=excluded.selectors",
            (allocate_id(db, "domain_claims"), user_id, domain, secrets.token_urlsafe(24), ",".join(clean), now_iso()),
        )
        if audit:
            audit(db, "claim.create", f"claim {domain}")
    row = db.execute("SELECT * FROM domain_claims WHERE user_id=? AND name=?", (user_id, domain)).fetchone()
    return row, existing is None


def cancel_claim(user_id: int, claim_id: int, guard: Guard = None, audit: Callable | None = None) -> None:
    db = get_db()
    with db:
        _begin(db, guard)
        gone = db.execute("SELECT name FROM domain_claims WHERE id=? AND user_id=? AND domain_id IS NULL",
                          (claim_id, user_id)).fetchone()
        if gone is None:
            raise ActionError(404, "not_found", "Demande introuvable.")
        db.execute("DELETE FROM domain_claims WHERE id=?", (claim_id,))
        if audit:
            audit(db, "claim.delete", f"claim:{claim_id} {gone['name']}")


def verify_claim(app: Flask, user_id: int, claim_id: int, guard: Guard = None, audit: Callable | None = None) -> dict:
    """Preuve TXT puis création de la zone. Renvoie l'id du domaine, les enregistrements copiés et
    si PowerDNS est déjà à jour."""
    claim = owned_claim(user_id, claim_id)
    if claim["domain_id"] is not None:
        done = get_db().execute("SELECT id FROM domains WHERE id=? AND user_id=?",
                                (claim["domain_id"], user_id)).fetchone()
        if done is not None:
            synced = project_zone(app, {"id": done["id"], "name": claim["name"]})
            return {"domain_id": done["id"], "copied": 0, "synced": synced, "created": False}
    rate_limit("verify", str(user_id), 20, 3600)
    domain = claim["name"]
    db = get_db()
    try:
        # Une réservation ajoutée après la demande s'applique aussi à la vérification.
        normalize_domain(domain, app.config["RESERVED_DOMAINS"])
    except ValueError as exc:
        raise _invalid(str(exc)) from exc
    refuse_overlap(db, domain, user_id)
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
    if len(snapshot) > app.config["MAX_RECORDS_PER_DOMAIN"]:
        raise _invalid(f"La zone publique compte {len(snapshot)} enregistrements, au-delà du quota de "
                       f"{app.config['MAX_RECORDS_PER_DOMAIN']} : demande à l'administrateur.")
    checked = []
    for rel, kind, content, ttl in snapshot:
        try:
            checked.append((relative_name(rel) if rel != "@" else "@", kind, canonical_content(kind, content), ttl))
        except ValueError as exc:
            raise _invalid(f"Enregistrement public refusé ({rel} {kind}) : {exc}") from exc
    snapshot = checked
    try:
        with db:
            _begin(db, guard)
            if not db.execute(
                "SELECT 1 FROM domain_claims WHERE id=? AND user_id=? AND name=? AND token=? AND domain_id IS NULL",
                (claim_id, user_id, domain, claim["token"]),
            ).fetchone():
                raise ActionError(409, "conflict", "Cette demande a été annulée entre-temps.")
            owned = db.execute("SELECT COUNT(*) FROM domains WHERE user_id=?", (user_id,)).fetchone()[0]
            if owned >= app.config["MAX_DOMAINS_PER_USER"]:
                raise ActionError(409, "quota", "Nombre maximal de domaines atteint pour ce compte.")
            refuse_overlap(db, domain, user_id)
            domain_id = db.execute(
                "INSERT INTO domains(id,user_id,name,created_at) VALUES(?,?,?,?)",
                (allocate_id(db, "domains"), user_id, domain, now_iso()),
            ).lastrowid
            for record in snapshot:
                db.execute("INSERT INTO records(id,domain_id,name,type,content,ttl) VALUES(?,?,?,?,?,?)",
                           (allocate_id(db, "records"), domain_id, *record))
            db.execute("DELETE FROM zone_removals WHERE name=?", (domain,))
            # La preuve est faite : les demandes concurrentes sur ce nom tombent, celle-ci garde
            # le lien vers le domaine pour qu'une vérification rejouée retrouve son résultat.
            db.execute("DELETE FROM domain_claims WHERE name=? AND id<>?", (domain, claim_id))
            db.execute("UPDATE domain_claims SET domain_id=? WHERE id=?", (domain_id, claim_id))
            if audit:
                audit(db, "domain.create", f"domain:{domain_id} {domain}")
    except sqlite3.IntegrityError as exc:
        raise ActionError(409, "unavailable", "Ce domaine ne peut pas être ajouté sur cette instance.") from exc
    synced = project_zone(app, {"id": domain_id, "name": domain})
    return {"domain_id": domain_id, "copied": len(snapshot), "synced": synced, "created": True}


def add_record(app: Flask, user_id: int, domain_id: int, name_raw: str, kind_raw: str, content_raw: str,
               ttl_raw, guard: Guard = None, audit: Callable | None = None) -> dict:
    domain = owned_domain(user_id, domain_id)
    try:
        name = relative_name(str(name_raw))
        kind = str(kind_raw).upper()
        content = canonical_content(kind, str(content_raw))
        ttl = int(ttl_raw)
        host = fqdn(name, domain["name"]).rstrip(".")
    except (ValueError, TypeError) as exc:
        raise _invalid(str(exc) or "Enregistrement invalide.") from exc
    if not 300 <= ttl <= 86400:
        raise _invalid("TTL entre 300 et 86 400 secondes.")
    if kind == "CNAME" and name == "@":
        # SOA et NS vivent toujours à la racine : PowerDNS refuserait la zone entière.
        raise _invalid("Un CNAME ne peut pas être posé à la racine du domaine.")
    db = get_db()
    created = True
    try:
        with db:
            _begin(db, guard)
            owned_domain(user_id, domain_id)
            same = db.execute("SELECT id, ttl FROM records WHERE domain_id=? AND name=? AND type=? AND content=?",
                              (domain_id, name, kind, content)).fetchone()
            if same is not None:
                # Même enregistrement rejoué : rien à créer ; seul un TTL différent est mis à jour.
                record_id, created = same["id"], False
                if same["ttl"] != ttl:
                    db.execute("UPDATE records SET ttl=? WHERE id=?", (ttl, record_id))
                    if audit:
                        audit(db, "record.update", f"record:{record_id} {name} {kind} ttl={ttl}")
            else:
                count = db.execute("SELECT COUNT(*) FROM records WHERE domain_id=?", (domain_id,)).fetchone()[0]
                if count >= app.config["MAX_RECORDS_PER_DOMAIN"]:
                    raise ActionError(409, "quota", "Nombre maximal d'enregistrements atteint pour ce domaine.")
                existing = db.execute("SELECT type FROM records WHERE domain_id=? AND name=?",
                                      (domain_id, name)).fetchall()
                if (kind == "CNAME" and existing) or (kind != "CNAME" and any(row["type"] == "CNAME"
                                                                              for row in existing)):
                    raise ActionError(409, "conflict",
                                      "Un CNAME ne peut partager son nom avec un autre enregistrement.")
                if kind in {"A", "AAAA", "CNAME"} and db.execute(
                    "SELECT 1 FROM addresses WHERE hostname=?", (host,),
                ).fetchone():
                    raise ActionError(409, "conflict",
                                      "Cette adresse est gérée par Synunnel ; supprime-la avant de modifier son DNS.")
                record_id = db.execute(
                    "INSERT INTO records(id,domain_id,name,type,content,ttl) VALUES(?,?,?,?,?,?)",
                    (allocate_id(db, "records"), domain_id, name, kind, content, ttl),
                ).lastrowid
                if audit:
                    audit(db, "record.create", f"record:{record_id} {name} {kind} {content[:120]}")
    except sqlite3.IntegrityError as exc:
        raise ActionError(409, "conflict", "Cet enregistrement existe déjà.") from exc
    return {"id": record_id, "synced": project_zone(app, domain), "created": created}


def delete_record(app: Flask, user_id: int, domain_id: int, record_id: int, guard: Guard = None,
                  audit: Callable | None = None) -> dict:
    domain = owned_domain(user_id, domain_id)
    db = get_db()
    with db:
        _begin(db, guard)
        gone = db.execute(
            "SELECT r.name, r.type, r.content FROM records r JOIN domains d ON d.id=r.domain_id "
            "WHERE r.id=? AND d.id=? AND d.user_id=?", (record_id, domain_id, user_id),
        ).fetchone()
        if gone is None:
            raise ActionError(404, "not_found", "Enregistrement introuvable.")
        db.execute("DELETE FROM records WHERE id=?", (record_id,))
        if audit:
            audit(db, "record.delete", f"record:{record_id} {gone['name']} {gone['type']} {gone['content'][:120]}")
    return {"synced": project_zone(app, domain)}


def remove_zone(app: Flask, name: str) -> bool:
    """Retire une zone de PowerDNS ; en cas d'échec, la pierre tombale reste et le rapprochement réessaie."""
    lock = zone_lock(app, name) if app.config["PDNS_ENABLED"] else None
    try:
        db = get_db()
        if db.execute("SELECT 1 FROM domains WHERE name=?", (name,)).fetchone():
            # Le nom a une nouvelle incarnation : l'ancienne suppression ne la vise pas.
            with db:
                db.execute("DELETE FROM zone_removals WHERE name=?", (name,))
            return True
        if lock is not None:
            _pdns(app).delete_zone(name)
        with db:
            db.execute("DELETE FROM zone_removals WHERE name=?", (name,))
    except requests.RequestException:
        return False
    finally:
        if lock is not None:
            lock.close()
    return True


def delete_domain(app: Flask, user_id: int | None, domain_id: int, guard: Guard = None,
                  audit: Callable | None = None, force: bool = False) -> dict:
    """Supprime un domaine et sa zone. Le propriétaire doit d'abord retirer ses adresses et rendre la
    délégation à son hébergeur ; l'administrateur (user_id None, force) passe outre, par exemple pour
    rendre un domaine à son vrai titulaire."""
    designated = None
    if not force:
        # Relevé de délégation propre à cette suppression, hors verrou (requêtes DNS) : tant que la zone
        # parente désigne encore un serveur de l'instance, retirer la zone couperait le domaine entier,
        # site et messagerie compris. La décision porte sur ce relevé-ci, jamais sur le cache partagé
        # qu'un relevé concurrent peut réécrire entre-temps.
        current = (owned_domain(user_id, domain_id) if user_id is not None else
                   get_db().execute("SELECT * FROM domains WHERE id=?", (domain_id,)).fetchone())
        if current is not None:
            active, seen = refresh_delegation(app, current)
            designated = still_designated(active, seen, (f"{app.config['NS1_HOST']}.",
                                                         f"{app.config['NS2_HOST']}."))
    db = get_db()
    with db:
        _begin(db, guard)
        if user_id is None:
            domain = db.execute("SELECT * FROM domains WHERE id=?", (domain_id,)).fetchone()
            if domain is None:
                raise ActionError(404, "not_found", "Domaine introuvable.")
        else:
            domain = owned_domain(user_id, domain_id)
        if not force and db.execute("SELECT 1 FROM addresses WHERE domain_id=?", (domain_id,)).fetchone():
            raise ActionError(409, "in_use", "Supprime d'abord les adresses de ce domaine.")
        if not force and designated is None:
            raise ActionError(409, "delegation_unknown",
                              "Impossible de vérifier la délégation du domaine pour l'instant : réessaie dans "
                              "quelques minutes.")
        if not force and designated:
            raise ActionError(409, "delegation_active",
                              "Ce domaine est encore délégué à cette instance : remets d'abord les serveurs de noms "
                              "de ton hébergeur chez ton registrar, puis réessaie une fois la délégation retirée.")
        hostnames = [row[0] for row in db.execute("SELECT hostname FROM addresses WHERE domain_id=?", (domain_id,))]
        for hostname in hostnames:
            db.execute("DELETE FROM host_sessions WHERE hostname=?", (hostname,))
            db.execute("DELETE FROM access_codes WHERE hostname=?", (hostname,))
        db.execute("DELETE FROM domain_claims WHERE domain_id=?", (domain_id,))
        db.execute("DELETE FROM domains WHERE id=?", (domain_id,))
        db.execute("INSERT OR REPLACE INTO zone_removals(name, at) VALUES(?,?)", (domain["name"], now_iso()))
        if audit:
            audit(db, "domain.delete", f"domain:{domain_id} {domain['name']}")
    synced = remove_zone(app, domain["name"])
    if hostnames:
        synced = project_runtime(app) and synced
    return {"synced": synced, "name": domain["name"]}


# ---------------------------------------------------------------- machines

def valid_public_key(value) -> bool:
    """Forme canonique exigée, comme wireguard-tools : les bits de bourrage doivent être nuls."""
    try:
        raw = base64.b64decode(value, validate=True) if isinstance(value, str) else b""
    except ValueError:
        return False
    return len(raw) == 32 and base64.b64encode(raw).decode() == value


def _insert_machine(app: Flask, user_id: int, name_raw, public_key: str, guard: Guard,
                    audit: Callable | None = None) -> dict:
    name = clean_label(name_raw, MACHINE_NAME_MAX, "Nom de machine")
    if not valid_public_key(public_key):
        raise _invalid("Clé publique WireGuard invalide.")
    db = get_db()
    try:
        with db:
            # Quota et choix de l'IP sous verrou d'écriture : deux ajouts simultanés ne
            # peuvent ni dépasser le quota ni viser la même adresse.
            _begin(db, guard)
            same = db.execute("SELECT id, name, ip FROM machines WHERE user_id=? AND public_key=?",
                              (user_id, public_key)).fetchone()
            if same is not None and same["name"] == name:
                # Même demande rejouée (réponse perdue) : on renvoie la machine déjà créée.
                raise _Replay({"id": same["id"], "name": same["name"], "ip": same["ip"], "created": False})
            owned = db.execute("SELECT COUNT(*) FROM machines WHERE user_id=?", (user_id,)).fetchone()[0]
            if owned >= app.config["MAX_MACHINES_PER_USER"]:
                raise ActionError(409, "quota", "Nombre maximal de machines atteint pour ce compte.")
            used = {row[0] for row in db.execute("SELECT ip FROM machines")}
            ip = next((f"10.88.0.{n}" for n in range(2, 255) if f"10.88.0.{n}" not in used), None)
            if ip is None:
                raise ActionError(409, "exhausted", "Plage d'adresses WireGuard épuisée.")
            machine_id = db.execute(
                "INSERT INTO machines(id,user_id,name,ip,public_key,created_at) VALUES(?,?,?,?,?,?)",
                (allocate_id(db, "machines"), user_id, name, ip, public_key, now_iso()),
            ).lastrowid
            if audit:
                audit(db, "machine.create", f"machine:{machine_id} {name} {ip}")
    except _Replay as replay:
        return {**replay.result, "synced": project_runtime(app)}
    except sqlite3.IntegrityError as exc:
        raise ActionError(409, "conflict", "Nom de machine ou clé publique déjà utilisés.") from exc
    return {"id": machine_id, "name": name, "ip": ip, "created": True, "synced": project_runtime(app)}


def peer_settings(app: Flask, ip: str) -> dict:
    return {"address": f"{ip}/32", "server_public_key": app.config["WG_SERVER_PUBLIC_KEY"],
            "endpoint": app.config["WG_ENDPOINT"], "allowed_ips": "10.88.0.1/32", "persistent_keepalive": 25}


def create_machine(app: Flask, user_id: int, name_raw: str, guard: Guard = None) -> dict:
    """Tableau de bord : la paire est générée ici et la clé privée montrée une seule fois à l'humain."""
    private_key, public_key = generate_keypair()
    machine = _insert_machine(app, user_id, name_raw, public_key, guard)
    peer = peer_settings(app, machine["ip"])
    machine["config"] = (
        "[Interface]\n"
        f"PrivateKey = {private_key}\nAddress = {peer['address']}\n\n"
        "[Peer]\n"
        f"PublicKey = {peer['server_public_key']}\n"
        f"Endpoint = {peer['endpoint']}\n"
        f"AllowedIPs = {peer['allowed_ips']}\nPersistentKeepalive = {peer['persistent_keepalive']}\n"
    )
    return machine


def register_machine(app: Flask, user_id: int, name_raw, public_key, guard: Guard, audit: Callable) -> dict:
    """API : la machine a généré sa paire elle-même ; seule la clé publique arrive ici."""
    machine = _insert_machine(app, user_id, name_raw, public_key, guard, audit)
    machine["peer"] = peer_settings(app, machine["ip"])
    return machine


def delete_machine(app: Flask, user_id: int, machine_id: int, guard: Guard = None,
                   audit: Callable | None = None) -> dict:
    db = get_db()
    with db:
        # Vérification et suppression sous le même verrou : une adresse ajoutée entre les deux
        # serait sinon supprimée en cascade sans que son propriétaire le sache.
        _begin(db, guard)
        machine = owned_machine(user_id, machine_id)
        if db.execute("SELECT 1 FROM addresses WHERE machine_id=?", (machine_id,)).fetchone():
            raise ActionError(409, "in_use", "Supprime d'abord les adresses liées à cette machine.")
        db.execute("DELETE FROM machines WHERE id=? AND user_id=?", (machine_id, user_id))
        if audit:
            audit(db, "machine.delete", f"machine:{machine_id} {machine['name']} {machine['ip']}")
    return {"synced": project_runtime(app)}


# ---------------------------------------------------------------- adresses

def create_address(app: Flask, user_id: int, domain_id, machine_id, name_raw, port_raw, protected: bool,
                   guard: Guard = None, audit: Callable | None = None) -> dict:
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
            _begin(db, guard)
            # Propriété revérifiée sous le verrou : un identifiant supprimé puis réattribué à un
            # autre compte ne peut pas être associé à cette adresse.
            owned_domain(user_id, domain_id)
            owned_machine(user_id, machine_id)
            same = db.execute(
                "SELECT id FROM addresses WHERE hostname=? AND domain_id=? AND machine_id=? AND port=? AND protected=?",
                (hostname, domain_id, machine_id, port, int(bool(protected))),
            ).fetchone()
            if same is not None:
                # Même demande rejouée : l'adresse existe déjà telle quelle.
                raise _Replay({"id": same["id"], "hostname": hostname, "created": False})
            count = db.execute(
                "SELECT COUNT(*) FROM addresses a JOIN domains d ON d.id=a.domain_id WHERE d.user_id=?", (user_id,),
            ).fetchone()[0]
            if count >= app.config["MAX_ADDRESSES_PER_USER"]:
                raise ActionError(409, "quota", "Nombre maximal d'adresses atteint pour ce compte.")
            if db.execute(
                f"SELECT 1 FROM records WHERE domain_id=? AND name=? AND type IN ({','.join('?' for _ in conflict_types)})",
                (domain_id, name, *conflict_types),
            ).fetchone():
                raise ActionError(409, "conflict", "Un enregistrement DNS incompatible existe déjà pour ce nom.")
            address_id = db.execute(
                "INSERT INTO addresses(id,domain_id,machine_id,hostname,port,protected,created_at,route_token) "
                "VALUES(?,?,?,?,?,?,?,?)",
                (allocate_id(db, "addresses"), domain_id, machine_id, hostname, port, int(bool(protected)), now_iso(),
                 secrets.token_hex(12)),
            ).lastrowid
            if audit:
                audit(db, "address.create", f"address:{address_id} {hostname} port={port} "
                                        f"{'protégée' if protected else 'publique'}")
    except _Replay as replay:
        return {**replay.result, "synced": project_zone(app, domain) & project_runtime(app)}
    except sqlite3.IntegrityError as exc:
        raise ActionError(409, "conflict", "Cette adresse existe déjà.") from exc
    synced = project_zone(app, domain) & project_runtime(app)
    return {"id": address_id, "hostname": hostname, "created": True, "synced": synced}


def delete_address(app: Flask, user_id: int, address_id: int, guard: Guard = None,
                   audit: Callable | None = None) -> dict:
    db = get_db()
    with db:
        _begin(db, guard)
        row = owned_address(user_id, address_id)
        db.execute("DELETE FROM addresses WHERE id=?", (address_id,))
        db.execute("DELETE FROM host_sessions WHERE hostname=?", (row["hostname"],))
        db.execute("DELETE FROM access_codes WHERE hostname=?", (row["hostname"],))
        if audit:
            audit(db, "address.delete", f"address:{address_id} {row['hostname']}")
    domain = {"id": row["domain_id"], "name": row["domain_name"]}
    return {"synced": project_zone(app, domain) & project_runtime(app)}


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


def set_access(user_id: int, address_id: int, shared: bool, emails_raw, guest_codes: bool | None = None,
               guard: Guard = None, audit: Callable | None = None) -> list[str]:
    """`guest_codes` : accès invité par code mail ; None garde la valeur actuelle."""
    emails = parse_grants(emails_raw)
    if shared and not emails:
        raise _invalid("Ajoute au moins une adresse mail pour activer l'accès partagé.")
    db = get_db()
    with db:
        _begin(db, guard)
        address = protected_address(user_id, address_id)
        option = int(bool(address["guest_codes"] if guest_codes is None else guest_codes))
        current = [row[0] for row in db.execute(
            "SELECT email FROM address_grants WHERE address_id=? ORDER BY email", (address_id,))]
        if (bool(address["shared"]) == bool(shared) and current == (emails if shared else current)
                and option == address["guest_codes"]):
            return emails if shared else []
        # Tout changement de liste, de partage ou d'option change la version invitée de l'adresse :
        # challenges, codes et sessions d'invités antérieurs ne valent plus rien.
        db.execute("UPDATE addresses SET shared=?, guest_codes=?, guest_version=guest_version+1 WHERE id=?",
                   (int(bool(shared)), option, address_id))
        db.execute("DELETE FROM address_grants WHERE address_id=?", (address_id,))
        if shared:
            db.executemany("INSERT INTO address_grants(address_id,email) VALUES(?,?)",
                           [(address_id, email) for email in emails])
        # Les cookies et codes précédents sont révoqués à chaque changement.
        db.execute("DELETE FROM host_sessions WHERE hostname=?", (address["hostname"],))
        db.execute("DELETE FROM access_codes WHERE hostname=?", (address["hostname"],))
        for table in ("guest_challenges", "guest_access_codes", "guest_host_sessions"):
            db.execute(f"DELETE FROM {table} WHERE address_id=?", (address_id,))
        if audit:
            audit(db, "access.update", f"address:{address_id} {address['hostname']} "
                                       f"shared={int(bool(shared))} {len(emails)} adresse(s) invités={option}")
    return emails if shared else []
