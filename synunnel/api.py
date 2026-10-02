"""API pour agents : jetons par compte, permissions explicites, JSON strict.

Un agent peut tout faire sur son compte, dans la limite des permissions cochées à la
création du jeton : domaines (demande, preuve TXT, enregistrements), machines, adresses et
partage d'accès. Une machine est déclarée avec sa seule clé publique : la clé privée est
générée sur la machine et ne transite jamais par l'API. Les jetons se créent et se révoquent
uniquement depuis le tableau de bord. Le cookie de session n'est jamais lu ici.
"""

import re
import secrets
import threading
import time
from collections import deque
from functools import wraps

from flask import Blueprint, Flask, current_app, g, jsonify, request
from werkzeug.exceptions import HTTPException

from . import actions, security
from .db import get_db, now_iso

TOKEN_PREFIX = "syn_"
# Permission -> libellé. La lecture est toujours accordée.
PERMISSIONS = {
    "domains": "Domaines et enregistrements DNS",
    "machines": "Machines",
    "addresses": "Adresses protégées",
    "sharing": "Partage d'accès et adresses publiques",
}
TOKEN_DURATIONS = (7, 30)
MAX_ACTIVE_TOKENS = 5

bp = Blueprint("api", __name__, url_prefix="/api/v1")


def new_token() -> str:
    return TOKEN_PREFIX + secrets.token_urlsafe(32)


class ApiError(Exception):
    def __init__(self, status: int, code: str, message: str, headers: dict | None = None):
        super().__init__(message)
        self.status, self.code, self.message, self.headers = status, code, message, headers or {}


def _error(status: int, code: str, message: str, headers: dict | None = None):
    response = jsonify({"error": {"code": code, "message": message}})
    response.status_code = status
    for key, value in (headers or {}).items():
        response.headers[key] = value
    return response


def _unauthorized(message: str) -> ApiError:
    return ApiError(401, "unauthorized", message, {"WWW-Authenticate": 'Bearer realm="synunnel"'})


def _limit(kind: str, key: str, limit: int, window: int) -> None:
    try:
        actions.rate_limit(kind, key, limit, window)
    except actions.ActionError as exc:
        raise ApiError(429, "rate_limited", exc.message, {"Retry-After": str(window)}) from exc


_READS: dict[int, deque] = {}
_READS_LOCK = threading.Lock()


def _limit_reads(user_id: int, limit: int = 300, window: int = 60) -> None:
    """Lectures limitées en mémoire, par processus : aucune écriture en base pour une simple lecture."""
    now = time.monotonic()
    with _READS_LOCK:
        hits = _READS.setdefault(user_id, deque())
        while hits and now - hits[0] > window:
            hits.popleft()
        if len(hits) >= limit:
            raise ApiError(429, "rate_limited", "Trop de lectures. Réessaie plus tard.", {"Retry-After": str(window)})
        hits.append(now)


def _refuse_anonymous() -> None:
    """Un échec d'authentification compte pour l'adresse (/64 en IPv6) et pour toute l'instance."""
    ip = actions.client_ip()
    if actions.limit_reached("api_auth", ip, 20, 600) or actions.limit_reached("api_auth_all", "*", 2000, 600):
        raise ApiError(429, "rate_limited", "Trop d'échecs d'authentification.", {"Retry-After": "600"})
    actions.record_attempt("api_auth", ip)
    actions.record_attempt("api_auth_all", "*")


# Un jeton ne vaut que pour la version des justificatifs qui l'a émis : un changement de mot de
# passe, de 2FA ou une suspension le rend caduc, même s'il a été inséré pendant ce changement.
TOKEN_SQL = ("SELECT t.*, u.email, u.totp_enabled_at FROM api_tokens t JOIN users u ON u.id=t.user_id "
             "AND u.status='approved' AND u.credential_version=t.credential_version ")


def _token_row(db, token_id: int):
    return db.execute(TOKEN_SQL + "WHERE t.id=? AND t.revoked_at IS NULL AND t.expires_at>?",
                      (token_id, int(time.time()))).fetchone()


def _mfa_missing(row) -> bool:
    return bool(current_app.config.get("REQUIRE_2FA")) and not row["totp_enabled_at"]


TOKEN_HEADER_RE = re.compile(r"^[Bb][Ee][Aa][Rr][Ee][Rr] (syn_[A-Za-z0-9_-]{40,80})$")


def _authenticate():
    # Forme stricte, en ASCII, sans aucune normalisation : ce que l'API accepte, le filtre des
    # adresses publiées le reconnaît forcément.
    match = TOKEN_HEADER_RE.fullmatch(request.headers.get("Authorization", ""))
    value = match.group(1) if match else ""
    if not match:
        _refuse_anonymous()
        raise _unauthorized("Jeton d'API manquant ou mal formé.")
    db = get_db()
    row = db.execute(TOKEN_SQL + "WHERE t.token_hash=? AND t.revoked_at IS NULL AND t.expires_at>?",
                     (security.digest(value), int(time.time()))).fetchone()
    if row is None:
        _refuse_anonymous()
        raise _unauthorized("Jeton d'API invalide, expiré ou révoqué.")
    if _mfa_missing(row):
        raise ApiError(403, "mfa_required", "Cette instance exige la double authentification : active-la dans "
                                            "le tableau de bord, puis crée un nouveau jeton.")
    now = int(time.time())
    if not row["last_used_at"] or now - row["last_used_at"] >= 60:
        with db:
            db.execute("UPDATE api_tokens SET last_used_at=? WHERE id=?", (now, row["id"]))
    g.api_token = {"id": row["id"], "user_id": row["user_id"], "email": row["email"],
                   "permissions": sorted(set(row["scopes"].split(",")) & set(PERMISSIONS)),
                   "name": row["name"], "prefix": row["prefix"], "expires_at": row["expires_at"]}


def _guard(db) -> None:
    """Recontrôle du jeton et du compte sous le verrou qui accepte une écriture."""
    row = _token_row(db, g.api_token["id"])
    if row is None:
        raise actions.ActionError(401, "unauthorized", "Jeton d'API révoqué ou expiré pendant l'opération.")
    if _mfa_missing(row):
        raise actions.ActionError(403, "mfa_required", "Cette instance exige la double authentification.")


def _audit(db, action: str, resource: str) -> None:
    db.execute(
        "INSERT INTO api_audit(at,user_id,token_id,action,resource,ip) VALUES(?,?,?,?,?,?)",
        (now_iso(), g.api_token["user_id"], g.api_token["id"], action, resource[:300], actions.client_ip()),
    )


def endpoint(permission: str | None = None):
    """None : lecture, accordée à tout jeton valide. Sinon, permission d'écriture exigée."""
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            _authenticate()
            if permission is None:
                _limit_reads(g.api_token["user_id"])
            else:
                if permission not in g.api_token["permissions"]:
                    raise ApiError(403, "forbidden", f"Ce jeton n'a pas la permission « {permission} ».")
                _limit("api_write", str(g.api_token["user_id"]), 60, 60)
            return fn(*args, **kwargs)
        return wrapper
    return decorator


LIMITS = {"content": 4096, "domain": 253}


def _payload(fields: dict[str, type], required: set[str]) -> dict:
    """Corps JSON strict : objet, champs connus, types exacts (un booléen n'est pas un entier)."""
    if request.mimetype != "application/json":
        raise ApiError(415, "unsupported_media_type", "Corps attendu en application/json.")
    try:
        data = request.get_json(silent=True)
    except RecursionError:
        data = None
    if not isinstance(data, dict):
        raise ApiError(400, "bad_request", "Le corps doit être un objet JSON.")
    unknown = set(data) - set(fields)
    if unknown:
        raise ApiError(422, "invalid", f"Champs inconnus : {', '.join(sorted(unknown))}.")
    missing = required - set(data)
    if missing:
        raise ApiError(422, "invalid", f"Champs manquants : {', '.join(sorted(missing))}.")
    for key, value in data.items():
        expected = fields[key]
        if expected is list:
            if type(value) is not list or len(value) > 100 or any(type(item) is not str or len(item) > 254
                                                                   for item in value):
                raise ApiError(422, "invalid", f"{key} doit être une liste de 100 chaînes au plus.")
            continue
        if type(value) is not expected:
            raise ApiError(422, "invalid", f"Type inattendu pour {key}.")
        if expected is str and len(value) > LIMITS.get(key, 255):
            raise ApiError(422, "invalid", f"{key} est trop long ({LIMITS.get(key, 255)} caractères au plus).")
        if expected is int and not 0 < value < 2**31:
            raise ApiError(422, "invalid", f"{key} hors limites.")
    return data


def _run(fn, *args, **kwargs):
    try:
        return fn(*args, **kwargs)
    except actions.ActionError as exc:
        raise ApiError(exc.status, exc.code, exc.message, exc.headers) from exc


# ---------------------------------------------------------------- représentations (liste blanche)

def _claim(row) -> dict:
    return {"id": row["id"], "domain": row["name"], "created_at": row["created_at"],
            "txt_record": actions.claim_proof(row)}


def _record(row) -> dict:
    return {"id": row["id"], "name": row["name"], "type": row["type"], "content": row["content"], "ttl": row["ttl"]}


def _domain(row) -> dict:
    return {"id": row["id"], "name": row["name"], "created_at": row["created_at"]}


def _machine(row) -> dict:
    return {"id": row["id"], "name": row["name"], "ip": row["ip"], "public_key": row["public_key"],
            "created_at": row["created_at"]}


def _address(row) -> dict:
    return {"id": row["id"], "hostname": row["hostname"], "domain_id": row["domain_id"],
            "machine_id": row["machine_id"], "port": row["port"], "protected": bool(row["protected"]),
            "shared": bool(row["shared"]), "created_at": row["created_at"]}


# ---------------------------------------------------------------- routes

def route(rule: str, **options):
    return bp.route(rule, provide_automatic_options=False, **options)


@route("/me", methods=["GET"])
@endpoint()
def me():
    user_id = g.api_token["user_id"]
    overview = actions.account_overview(user_id)
    config = current_app.config
    return jsonify({
        "email": g.api_token["email"],
        "token": {"name": g.api_token["name"], "prefix": g.api_token["prefix"],
                  "permissions": g.api_token["permissions"], "expires_at": g.api_token["expires_at"]},
        "usage": {"domains": len(overview["domains"]), "pending_claims": len(overview["claims"]),
                  "machines": len(overview["machines"]), "addresses": len(overview["addresses"])},
        "quotas": {"domains": config["MAX_DOMAINS_PER_USER"], "machines": config["MAX_MACHINES_PER_USER"],
                   "addresses": config["MAX_ADDRESSES_PER_USER"], "records_per_domain": config["MAX_RECORDS_PER_DOMAIN"]},
        "nameservers": [config["NS1_HOST"], config["NS2_HOST"]],
    })


# ---- domaines

@route("/domains", methods=["GET"])
@endpoint()
def list_domains():
    return jsonify({"domains": [_domain(row) for row in actions.account_overview(g.api_token["user_id"])["domains"]]})


@route("/domains", methods=["POST"])
@endpoint("domains")
def create_claim():
    data = _payload({"domain": str, "dkim_selectors": list, "mail_records_checked": bool},
                    {"domain", "mail_records_checked"})
    claim, created = _run(actions.create_claim, current_app, g.api_token["user_id"], data["domain"],
                          data.get("dkim_selectors", []), data["mail_records_checked"], _guard, _audit)
    return jsonify({"claim": _claim(claim)}), 201 if created else 200


@route("/claims", methods=["GET"])
@endpoint()
def list_claims():
    return jsonify({"claims": [_claim(row) for row in actions.account_overview(g.api_token["user_id"])["claims"]]})


@route("/claims/<int:claim_id>", methods=["GET"])
@endpoint()
def get_claim(claim_id: int):
    claim = _run(actions.owned_claim, g.api_token["user_id"], claim_id)
    return jsonify({"claim": _claim(claim), "verified_domain_id": claim["domain_id"]})


@route("/claims/<int:claim_id>", methods=["DELETE"])
@endpoint("domains")
def delete_claim(claim_id: int):
    _run(actions.cancel_claim, g.api_token["user_id"], claim_id, _guard, _audit)
    return jsonify({"deleted": True})


@route("/claims/<int:claim_id>/verify", methods=["POST"])
@endpoint("domains")
def verify_claim(claim_id: int):
    result = _run(actions.verify_claim, current_app, g.api_token["user_id"], claim_id, _guard, _audit)
    domain = _run(actions.owned_domain, g.api_token["user_id"], result["domain_id"])
    return jsonify({"domain": _domain(domain), "copied_records": result["copied"],
                    "synced": result["synced"]}), 201 if result["created"] else 200


@route("/domains/<int:domain_id>", methods=["GET"])
@endpoint()
def get_domain(domain_id: int):
    domain = _run(actions.owned_domain, g.api_token["user_id"], domain_id)
    records = get_db().execute(
        "SELECT id,name,type,content,ttl FROM records WHERE domain_id=? ORDER BY name,type,content", (domain_id,),
    ).fetchall()
    return jsonify({**_domain(domain), "records": [_record(row) for row in records],
                    "nameservers": [current_app.config["NS1_HOST"], current_app.config["NS2_HOST"]]})


@route("/domains/<int:domain_id>", methods=["DELETE"])
@endpoint("domains")
def delete_domain(domain_id: int):
    result = _run(actions.delete_domain, current_app, g.api_token["user_id"], domain_id, _guard, _audit)
    return jsonify({"deleted": True, "synced": result["synced"]})


@route("/domains/<int:domain_id>/records", methods=["POST"])
@endpoint("domains")
def create_record(domain_id: int):
    data = _payload({"name": str, "type": str, "content": str, "ttl": int}, {"name", "type", "content"})
    result = _run(actions.add_record, current_app, g.api_token["user_id"], domain_id, data["name"], data["type"],
                  data["content"], data.get("ttl", 3600), _guard, _audit)
    row = get_db().execute(
        "SELECT r.id,r.name,r.type,r.content,r.ttl FROM records r JOIN domains d ON d.id=r.domain_id "
        "WHERE r.id=? AND d.id=? AND d.user_id=?", (result["id"], domain_id, g.api_token["user_id"]),
    ).fetchone()
    if row is None:
        raise ApiError(409, "conflict", "L'enregistrement a été modifié entre-temps ; relis le domaine.")
    return jsonify({"record": _record(row), "synced": result["synced"]}), 201 if result["created"] else 200


@route("/domains/<int:domain_id>/records/<int:record_id>", methods=["DELETE"])
@endpoint("domains")
def delete_record(domain_id: int, record_id: int):
    result = _run(actions.delete_record, current_app, g.api_token["user_id"], domain_id, record_id, _guard, _audit)
    return jsonify({"deleted": True, "synced": result["synced"]})


# ---- machines

@route("/machines", methods=["GET"])
@endpoint()
def list_machines():
    return jsonify({"machines": [_machine(row) for row in actions.account_overview(g.api_token["user_id"])["machines"]]})


@route("/machines", methods=["POST"])
@endpoint("machines")
def create_machine():
    data = _payload({"name": str, "public_key": str}, {"name", "public_key"})
    result = _run(actions.register_machine, current_app, g.api_token["user_id"], data["name"], data["public_key"],
                  _guard, _audit)
    row = _run(actions.owned_machine, g.api_token["user_id"], result["id"])
    body = {"machine": _machine(row), "peer": result["peer"], "synced": result["synced"]}
    return jsonify(body), 201 if result["created"] else 200


@route("/machines/<int:machine_id>", methods=["DELETE"])
@endpoint("machines")
def delete_machine(machine_id: int):
    result = _run(actions.delete_machine, current_app, g.api_token["user_id"], machine_id, _guard, _audit)
    return jsonify({"deleted": True, "synced": result["synced"]})


# ---- adresses et partage

@route("/addresses", methods=["GET"])
@endpoint()
def list_addresses():
    rows = actions.account_overview(g.api_token["user_id"])["addresses"]
    return jsonify({"addresses": [_address(row) for row in rows]})


@route("/addresses", methods=["POST"])
@endpoint("addresses")
def create_address():
    data = _payload({"domain_id": int, "machine_id": int, "name": str, "port": int, "protected": bool},
                    {"domain_id", "machine_id", "name", "port", "protected"})
    if not data["protected"] and "sharing" not in g.api_token["permissions"]:
        # Ouvrir un service à tout Internet est une décision d'accès : elle exige la permission « sharing ».
        raise ApiError(403, "forbidden", "Publier une adresse sans protection exige aussi la permission « sharing ».")
    result = _run(actions.create_address, current_app, g.api_token["user_id"], data["domain_id"],
                  data["machine_id"], data["name"], data["port"], data["protected"], _guard, _audit)
    row = _run(actions.owned_address, g.api_token["user_id"], result["id"])
    return jsonify({"address": _address(row), "synced": result["synced"]}), 201 if result["created"] else 200


@route("/addresses/<int:address_id>", methods=["DELETE"])
@endpoint("addresses")
def delete_address(address_id: int):
    result = _run(actions.delete_address, current_app, g.api_token["user_id"], address_id, _guard, _audit)
    return jsonify({"deleted": True, "synced": result["synced"]})


@route("/addresses/<int:address_id>/access", methods=["GET"])
@endpoint()
def get_access(address_id: int):
    address, emails = _run(actions.access_list, g.api_token["user_id"], address_id)
    return jsonify({"shared": bool(address["shared"]), "emails": emails if address["shared"] else [],
                    "guest_codes": bool(address["guest_codes"])})


@route("/addresses/<int:address_id>/access", methods=["PUT"])
@endpoint("sharing")
def put_access(address_id: int):
    from . import guest
    data = _payload({"shared": bool, "emails": list, "guest_codes": bool}, {"shared", "emails"})
    option = data.get("guest_codes")
    if option and not guest.instance_allows():
        raise ApiError(409, "unavailable", "Cette instance ne propose pas l'accès invité par code mail.")
    emails = _run(actions.set_access, g.api_token["user_id"], address_id, data["shared"], data["emails"],
                  option, _guard, _audit)
    address, _emails = _run(actions.access_list, g.api_token["user_id"], address_id)
    return jsonify({"shared": data["shared"], "emails": emails, "guest_codes": bool(address["guest_codes"])})


@route("/openapi.json", methods=["GET"])
def openapi():
    from .openapi import document
    return jsonify(document(current_app))


@bp.before_request
def bounded_identifiers():
    # Un identifiant hors de la plage SQLite n'existe pas : 404 plutôt qu'une erreur interne.
    for value in (request.view_args or {}).values():
        if isinstance(value, int) and not 0 < value < 2**31:
            raise ApiError(404, "not_found", "Ressource introuvable.")


def register(app: Flask) -> None:
    app.register_blueprint(bp)

    @app.errorhandler(ApiError)
    def api_error(exc: ApiError):
        return _error(exc.status, exc.code, exc.message, exc.headers)

    @app.errorhandler(HTTPException)
    def http_error(exc: HTTPException):
        if request.path.startswith("/api/"):
            code = {404: "not_found", 405: "method_not_allowed", 413: "payload_too_large",
                    500: "internal_error"}.get(exc.code, "http_error")
            # Jamais le détail technique d'une erreur interne dans la réponse.
            message = "Erreur interne." if (exc.code or 500) >= 500 else (exc.description or "Erreur HTTP.")
            headers = {"Allow": ", ".join(sorted(exc.valid_methods))} if getattr(exc, "valid_methods", None) else None
            return _error(exc.code or 500, code, message, headers)
        return exc

