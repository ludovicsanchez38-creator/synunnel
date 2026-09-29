"""Accès invité par code envoyé par mail, pour des personnes sans compte Synunnel.

Design : docs/design/acces-invite-code-mail.md (v2). Un invité n'est jamais un compte : ses
challenges, codes de transfert et sessions d'hôte vivent dans leurs propres tables, liés à une
adresse (`address_id`, `route_token`, `guest_version`). La politique est revérifiée à chaque
requête : option active sur l'adresse, invité toujours sur la liste, toujours sans compte ni
adresse bloquée, propriétaire approuvé, versions identiques, instance qui l'autorise.

Un challenge est toujours créé, réel ou factice : même réponse, même chemin, même travail à la
vérification ; seul un challenge réel déclenche un mail (par la file asynchrone) et peut aboutir.
"""

import hashlib
import hmac
import secrets
import sqlite3
import time
from pathlib import Path
from urllib.parse import quote, urlsplit

from flask import (
    Flask,
    abort,
    current_app,
    flash,
    make_response,
    redirect,
    render_template,
    request,
    send_file,
    session,
    url_for,
)

from . import actions, security
from .account import client_ip, mailer, no_store, record_event
from .db import get_db

COOKIE = "__Host-synunnel-access"
CODE_TTL = 600
MAX_ATTEMPTS = 5
FAIL_BUDGET = (5, 86400)  # échecs cumulés par couple (adresse, email) avant de ne plus envoyer de code
LIVE_PER_COUPLE = 3
REQUESTS_PER_IP = (10, 3600)
REQUESTS_PER_EMAIL = (5, 3600)
VERIFY_PER_IP = (30, 900)
MAILS_PER_HOST = (50, 3600)  # budget interne d'envoi : jamais visible dans la réponse
TRANSFER_TTL = 120
SESSION_TTL = 43200

POLICY_SQL = (
    "SELECT a.id FROM addresses a JOIN domains d ON d.id=a.domain_id "
    "JOIN users o ON o.id=d.user_id AND o.status='approved' "
    "WHERE a.id=? AND a.protected=1 AND a.shared=1 AND a.guest_codes=1 AND a.route_token=? AND a.guest_version=? "
    "AND EXISTS (SELECT 1 FROM address_grants g WHERE g.address_id=a.id AND g.email=?) "
    "AND NOT EXISTS (SELECT 1 FROM users u WHERE u.email=?) "
    "AND NOT EXISTS (SELECT 1 FROM blocked_emails b WHERE b.email=?)"
)


def _now() -> float:
    return time.time()


def instance_allows(app: Flask | None = None) -> bool:
    """Politique d'instance : SMTP configuré, option d'instance, et 2FA exigée seulement si l'administrateur
    l'autorise explicitement pour les invités (un invité n'a qu'un facteur, sa boîte mail)."""
    app = app or current_app
    if not app.config.get("GUEST_CODES", True):
        return False
    if app.config.get("REQUIRE_2FA") and not app.config.get("GUEST_CODES_WITH_2FA"):
        return False
    return app.extensions["synunnel_mailer"].enabled


def authorized(db, address_id: int, route_token: str, guest_version: int, email: str) -> bool:
    if not instance_allows():
        return False
    return db.execute(POLICY_SQL, (address_id, route_token, guest_version, email, email, email)).fetchone() is not None


def _key() -> bytes:
    return hashlib.sha256(b"synunnel-guest:" + current_app.config["SECRET_KEY"].encode()).digest()


def _mac(label: str, value: str) -> str:
    return hmac.new(_key(), f"{label}:{value}".encode(), hashlib.sha256).hexdigest()


def reserve(kind: str, key: str, limit: int, window: int) -> bool:
    """Quota atomique : compte et réserve sous un même verrou, sur une connexion à part de celle de
    la requête. Chaque demande est comptée, acceptée ou non."""
    conn = sqlite3.connect(current_app.config["DATABASE"], timeout=10, isolation_level=None)
    try:
        conn.execute("PRAGMA busy_timeout=10000")
        conn.execute("BEGIN IMMEDIATE")
        now = int(_now())
        used = conn.execute("SELECT COUNT(*) FROM guest_quota WHERE kind=? AND key=? AND at>?",
                            (kind, key, now - window)).fetchone()[0]
        conn.execute("INSERT INTO guest_quota(kind,key,at) VALUES(?,?,?)", (kind, key, now))
        conn.execute("COMMIT")
        return used < limit
    finally:
        conn.close()


def _failures(db, address_id: int, email: str) -> int:
    return db.execute("SELECT COUNT(*) FROM guest_quota WHERE kind='fail' AND key=? AND at>?",
                      (f"{address_id}|{email}", int(_now()) - FAIL_BUDGET[1])).fetchone()[0]


def parse_next(value: str) -> tuple[str, str] | None:
    """Syntaxe stricte d'une destination : https, sans port, sans identifiants (même vides), sans fragment."""
    try:
        parsed = urlsplit(value or "")
        if parsed.scheme != "https" or not parsed.hostname or parsed.port or "@" in parsed.netloc:
            return None
        if parsed.fragment or "\\" in value:
            return None
        path = parsed.path or "/"
        if not path.startswith("/") or path.startswith("//"):
            return None
        if parsed.query:
            path += "?" + parsed.query
        return parsed.hostname.lower(), path
    except ValueError:
        return None


def guest_address(db, hostname: str):
    return db.execute("SELECT id, hostname, route_token, guest_version, guest_codes FROM addresses "
                      "WHERE hostname=? AND protected=1", (hostname,)).fetchone()


def offers_codes(next_url: str) -> bool:
    """La page de connexion propose le code par mail si l'adresse visée l'accepte."""
    target = parse_next(next_url)
    if target is None or not instance_allows():
        return False
    row = guest_address(get_db(), target[0])
    return row is not None and bool(row["guest_codes"])


def session_allows(db, token: str, hostname: str, route_token: str) -> bool:
    row = db.execute(
        "SELECT address_id, email, route_token, guest_version FROM guest_host_sessions "
        "WHERE token_hash=? AND hostname=? AND expires_at>?",
        (security.digest(token), hostname, int(_now())),
    ).fetchone()
    return (row is not None and hmac.compare_digest(row["route_token"], route_token)
            and authorized(db, row["address_id"], row["route_token"], row["guest_version"], row["email"]))


def exchange_transfer_code(db, code: str, hostname: str):
    """Callback d'hôte, branche invitée : code de transfert à usage unique -> session d'hôte."""
    row = db.execute(
        "SELECT c.address_id, c.email, c.route_token, c.guest_version, c.next_path FROM guest_access_codes c "
        "JOIN addresses a ON a.id=c.address_id AND a.hostname=? WHERE c.code_hash=? AND c.expires_at>?",
        (hostname, security.digest(code), int(_now())),
    ).fetchone()
    if row is None or not authorized(db, row["address_id"], row["route_token"], row["guest_version"], row["email"]):
        return None
    token = secrets.token_urlsafe(32)
    with db:
        if db.execute("DELETE FROM guest_access_codes WHERE code_hash=?", (security.digest(code),)).rowcount != 1:
            return None
        db.execute(
            "INSERT INTO guest_host_sessions(token_hash,address_id,email,route_token,guest_version,hostname,expires_at) "
            "VALUES(?,?,?,?,?,?,?)",
            (security.digest(token), row["address_id"], row["email"], row["route_token"], row["guest_version"],
             hostname, int(_now()) + SESSION_TTL),
        )
    return token, row["next_path"]


def register(app: Flask) -> None:
    def form_page(next_url: str, status: int = 200):
        return no_store((render_template("guest_code.html", next_url=next_url), status))

    @app.route("/access/code", methods=["GET", "POST"])
    def guest_code():
        if request.method == "GET":
            return form_page(request.args.get("next", "")[:2000])
        if not reserve("req_ip", client_ip(), *REQUESTS_PER_IP):
            abort(429, "Trop de demandes. Réessaie plus tard.")
        next_url = request.form.get("next", "")[:2000]
        email = request.form.get("email", "").strip().lower()[:254]
        target = parse_next(next_url)
        db = get_db()
        address = guest_address(db, target[0]) if target else None
        if address is None or not actions.EMAIL_RE.fullmatch(email):
            flash("Adresse mail ou destination invalide.", "error")
            return form_page(next_url, 400)
        now = int(_now())
        # Chaque vérification et chaque réservation sont faites pour toute demande, invitée ou non :
        # aucune ressource observable (quota d'envoi de l'hôte compris) ne dépend de l'éligibilité.
        eligible = authorized(db, address["id"], address["route_token"], address["guest_version"], email)
        email_ok = reserve("req_email", email, *REQUESTS_PER_EMAIL)
        host_ok = reserve("mail_host", address["hostname"], *MAILS_PER_HOST)
        challenge = security.new_token()
        code = f"{secrets.randbelow(10**6):06d}"
        label = security.digest(challenge)
        with db:
            db.execute("BEGIN IMMEDIATE")
            # Budget d'échecs et plafond de challenges vivants lus sous le verrou de l'insertion.
            failures = _failures(db, address["id"], email)
            live = db.execute(
                "SELECT COUNT(*) FROM guest_challenges WHERE address_id=? AND email=? AND dummy=0 AND used_at IS NULL "
                "AND expires_at>? AND attempts<?", (address["id"], email, now, MAX_ATTEMPTS),
            ).fetchone()[0]
            real = eligible and email_ok and host_ok and failures < FAIL_BUDGET[0] and live < LIVE_PER_COUPLE
            db.execute(
                "INSERT INTO guest_challenges(challenge_hash,address_id,email,route_token,guest_version,next_path,"
                "mac,dummy,attempts,created_at,expires_at) VALUES(?,?,?,?,?,?,?,?,0,?,?)",
                # Challenge factice : MAC d'une valeur aléatoire, qu'aucun code à six chiffres n'atteint.
                (label, address["id"], email, address["route_token"], address["guest_version"], target[1],
                 _mac(label, code if real else security.new_token()), 0 if real else 1, now, now + CODE_TTL),
            )
            record_event(db, None, "guest.request", via=f"{address['hostname']} {email}", actor="guest")
        session["guest_challenge"] = challenge
        if real:
            mailer().enqueue(
                email, f"Ton code d'accès à {address['hostname']}",
                f"Bonjour,\n\nVoici ton code d'accès à {address['hostname']} : {code}\n\n"
                "Il est valable 10 minutes et ne sert qu'une fois. Saisis-le sur la page qui te l'a demandé.\n\n"
                "Si tu n'as rien demandé, ignore ce mail.\n\nSynunnel",
            )
        return redirect(url_for("guest_verify"))

    @app.route("/access/verify", methods=["GET", "POST"])
    def guest_verify():
        if request.method == "GET":
            return no_store(render_template("guest_verify.html"))
        if not reserve("verify_ip", client_ip(), *VERIFY_PER_IP):
            abort(429, "Trop de tentatives. Réessaie plus tard.")
        value = session.get("guest_challenge", "")
        code = request.form.get("code", "").strip()
        now = int(_now())
        db = get_db()
        label = security.digest(value) if value else ""

        def refuse():
            flash("Code incorrect ou expiré.", "error")
            return no_store((render_template("guest_verify.html"), 400))

        transfer = secrets.token_urlsafe(32)
        with db:
            # Une seule transaction : lecture du challenge, budget cumulatif du couple, comparaison,
            # puis soit l'échec compté, soit la consommation. Même travail pour un challenge factice.
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT * FROM guest_challenges WHERE challenge_hash=? AND used_at IS NULL AND expires_at>? "
                "AND attempts<?", (label, now, MAX_ATTEMPTS),
            ).fetchone() if value else None
            if row is None:
                db.rollback()
                return refuse()
            budget_left = _failures(db, row["address_id"], row["email"]) < FAIL_BUDGET[0]
            matches = bool(security.CODE_RE.fullmatch(code)) and hmac.compare_digest(_mac(label, code), row["mac"])
            if not (matches and budget_left) or row["dummy"]:
                db.execute("UPDATE guest_challenges SET attempts=attempts+1 WHERE challenge_hash=?", (label,))
                db.execute("INSERT INTO guest_quota(kind,key,at) VALUES('fail',?,?)",
                           (f"{row['address_id']}|{row['email']}", now))
                if row["attempts"] + 1 >= MAX_ATTEMPTS or not budget_left:
                    record_event(db, None, "guest.lock", via=f"address:{row['address_id']} {row['email']}",
                                 actor="guest")
                db.commit()
                return refuse()
            used = db.execute(
                "UPDATE guest_challenges SET used_at=? WHERE challenge_hash=? AND used_at IS NULL AND expires_at>? "
                "AND attempts<? AND dummy=0", (now, label, now, MAX_ATTEMPTS),
            ).rowcount
            host = db.execute("SELECT hostname FROM addresses WHERE id=?", (row["address_id"],)).fetchone()
            if used != 1 or host is None or not authorized(db, row["address_id"], row["route_token"],
                                                             row["guest_version"], row["email"]):
                db.rollback()
                return refuse()
            db.execute(
                "INSERT INTO guest_access_codes(code_hash,address_id,email,route_token,guest_version,next_path,"
                "expires_at) VALUES(?,?,?,?,?,?,?)",
                (security.digest(transfer), row["address_id"], row["email"], row["route_token"], row["guest_version"],
                 row["next_path"], now + TRANSFER_TTL),
            )
            record_event(db, None, "guest.enter", via=f"{host['hostname']} {row['email']}", actor="guest")
        session.pop("guest_challenge", None)
        target = f"https://{host['hostname']}/__synunnel/auth/callback?code={quote(transfer)}"
        return no_store(render_template("continue.html", target=target, hostname=host["hostname"]))

    def logout_token(cookie: str) -> str:
        return _mac("logout", security.digest(cookie))

    @app.route("/__synunnel/logout", methods=["GET", "POST"])
    def guest_logout():
        hostname = request.host.split(":", 1)[0].lower()
        cookie = request.cookies.get(COOKIE, "")
        if request.method == "GET":
            return no_store(render_template("guest_logout.html", hostname=hostname, active=bool(cookie),
                                            form_token=logout_token(cookie) if cookie else ""))
        if not cookie or not hmac.compare_digest(request.form.get("csrf_token", ""), logout_token(cookie)):
            return no_store((render_template("guest_logout.html", hostname=hostname, active=bool(cookie),
                                             form_token=logout_token(cookie) if cookie else "", refused=True), 400))
        db = get_db()
        with db:
            # Seule la session de cet hôte se ferme : celle d'un invité, ou l'accès de cet hôte pour un compte.
            db.execute("DELETE FROM guest_host_sessions WHERE token_hash=? AND hostname=?",
                       (security.digest(cookie), hostname))
            db.execute("DELETE FROM host_sessions WHERE token_hash=? AND hostname=?",
                       (security.digest(cookie), hostname))
            record_event(db, None, "guest.logout", via=hostname, actor="guest")
        response = make_response(no_store(render_template("guest_logout.html", hostname=hostname, active=False,
                                                          form_token="", done=True)))
        response.delete_cookie(COOKIE, path="/", secure=True, httponly=True, samesite="Lax")
        return response

    @app.get("/__synunnel/site.css")
    def guest_css():
        return send_file(Path(app.root_path) / "static" / "site.css", mimetype="text/css", max_age=3600)
