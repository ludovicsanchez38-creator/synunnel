"""Interface et API de Synunnel."""

import hashlib
import hmac
import os
import re
import secrets
import shlex
import sqlite3
import subprocess
import time
from functools import wraps
from urllib.parse import quote, urlsplit

import requests
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from flask import (
    Flask,
    abort,
    flash,
    g,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from werkzeug.middleware.proxy_fix import ProxyFix

from . import VERSION_LABEL
from .db import close_db, get_db, init_db, now_iso
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
    system_reservations,
)
from .provision import generate_keypair

PASSWORDS = PasswordHasher()
EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
ACCESS_COOKIE = "__Host-synunnel-access"
# Vérifié quand le compte n'existe pas : même coût qu'une vraie tentative.
DUMMY_HASH = PASSWORDS.hash(secrets.token_hex(16))
REQUIRED_SETTINGS = ("PUBLIC_IPV4", "WG_ENDPOINT", "DASHBOARD_HOST", "NS1_HOST", "NS2_HOST")


def _hash_token(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _client_ip() -> str:
    if request.remote_addr in {"127.0.0.1", "::1"}:
        return request.headers.get("X-Real-IP", request.remote_addr)
    return request.remote_addr or "unknown"


def _rate_limit(kind: str, key: str, limit: int, window: int) -> None:
    db = get_db()
    now = int(time.time())
    db.execute("DELETE FROM attempts WHERE at < ?", (now - 86400,))
    count = db.execute(
        "SELECT COUNT(*) FROM attempts WHERE kind=? AND key=? AND at>=?",
        (kind, key, now - window),
    ).fetchone()[0]
    if count >= limit:
        db.commit()
        abort(429, "Trop de tentatives. Réessaie plus tard.")
    db.execute("INSERT INTO attempts(kind, key, at) VALUES (?, ?, ?)", (kind, key, now))
    db.commit()


def _login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if g.user is None:
            return redirect(url_for("login", next=request.url))
        return fn(*args, **kwargs)
    return wrapper


def _owned_domain(domain_id: int):
    row = get_db().execute(
        "SELECT * FROM domains WHERE id=? AND user_id=?", (domain_id, g.user["id"]),
    ).fetchone()
    if row is None:
        abort(404)
    return row


def _owned_machine(machine_id: int):
    row = get_db().execute(
        "SELECT * FROM machines WHERE id=? AND user_id=?", (machine_id, g.user["id"]),
    ).fetchone()
    if row is None:
        abort(404)
    return row


def _refuse_overlap(db, domain: str) -> None:
    """Refuse un domaine qui contient une zone existante ou qui est contenu dans l'une d'elles."""
    row = db.execute(
        "SELECT name FROM domains WHERE name=?1 OR substr(?1, -length(name) - 1)='.' || name "
        "OR substr(name, -length(?1) - 1)='.' || ?1 LIMIT 1",
        (domain,),
    ).fetchone()
    if row is not None:
        if row["name"] == domain:
            raise ValueError("Ce domaine est déjà enregistré.")
        raise ValueError(f"Ce domaine recouvre la zone {row['name']}, déjà gérée par l'instance.")


def _pdns(app: Flask) -> PowerDNS:
    return PowerDNS(app.config["PDNS_API_URL"], app.config["PDNS_API_KEY"], (
        f"{app.config['NS1_HOST']}.", f"{app.config['NS2_HOST']}.",
    ))


def _sync_zone(app: Flask, db, domain) -> None:
    if app.config["PDNS_ENABLED"]:
        _pdns(app).sync_zone(
            db, domain["id"], domain["name"], app.config["PUBLIC_IPV4"], app.config["PUBLIC_IPV6"],
        )


def _sync_runtime(app: Flask) -> None:
    command = app.config.get("SYNC_COMMAND", "")
    if command:
        subprocess.run(shlex.split(command), check=True, capture_output=True, timeout=20)


def _authorized_protected_user(hostname: str, user_id: int) -> bool:
    return get_db().execute(
        "SELECT 1 FROM addresses a JOIN domains d ON d.id=a.domain_id "
        "JOIN users u ON u.id=? AND u.status='approved' "
        "WHERE a.hostname=? AND a.protected=1 AND "
        "(d.user_id=u.id OR (a.shared=1 AND EXISTS ("
        "SELECT 1 FROM address_grants g WHERE g.address_id=a.id AND g.email=u.email)))",
        (user_id, hostname),
    ).fetchone() is not None


def _parse_grants(raw: str) -> list[str]:
    emails = sorted({part.lower() for part in re.split(r"[,;\s]+", raw.strip()) if part})
    if len(emails) > 100 or any(len(email) > 254 or not EMAIL_RE.fullmatch(email) for email in emails):
        raise ValueError("Liste invalide : au maximum 100 adresses mail valides.")
    return emails


def _validate_next(value: str, user_id: int) -> tuple[str, str] | None:
    try:
        parsed = urlsplit(value)
        if parsed.scheme != "https" or not parsed.hostname or parsed.port or parsed.username:
            return None
        hostname = parsed.hostname.lower()
        if parsed.fragment:
            return None
        if not _authorized_protected_user(hostname, user_id):
            return None
        path = parsed.path or "/"
        if not path.startswith("/") or path.startswith("//"):
            return None
        if parsed.query:
            path += "?" + parsed.query
        return hostname, path
    except ValueError:
        return None


def _redirect_after_login(next_url: str, user_id: int):
    target = _validate_next(next_url, user_id) if next_url else None
    if target is None:
        return redirect(url_for("dashboard"))
    hostname, path = target
    code = secrets.token_urlsafe(32)
    db = get_db()
    db.execute(
        "INSERT INTO access_codes(code_hash,user_id,hostname,next_path,expires_at) VALUES(?,?,?,?,?)",
        (_hash_token(code), user_id, hostname, path, int(time.time()) + 120),
    )
    db.commit()
    return redirect(f"https://{hostname}/__synunnel/auth/callback?code={quote(code)}")


def create_app(config_override: dict | None = None) -> Flask:
    app = Flask(__name__)
    app.config.update(
        SECRET_KEY=os.getenv("SECRET_KEY"),
        ADMIN_TOKEN=os.getenv("ADMIN_TOKEN"),
        PDNS_API_KEY=os.getenv("PDNS_API_KEY"),
        PDNS_API_URL=os.getenv("PDNS_API_URL", "http://127.0.0.1:8081/api/v1/servers/localhost"),
        DATABASE=os.getenv("DATABASE", "/var/lib/synunnel/synunnel.db"),
        PUBLIC_IPV4=os.getenv("PUBLIC_IPV4", ""),
        PUBLIC_IPV6=os.getenv("PUBLIC_IPV6", ""),
        WG_ENDPOINT=os.getenv("WG_ENDPOINT", ""),
        WG_SERVER_PUBLIC_KEY=os.getenv("WG_SERVER_PUBLIC_KEY", ""),
        DASHBOARD_HOST=os.getenv("DASHBOARD_HOST", ""),
        NS1_HOST=os.getenv("NS1_HOST", ""),
        NS2_HOST=os.getenv("NS2_HOST", ""),
        REDIRECT_HOSTS=os.getenv("REDIRECT_HOSTS", ""),
        EXTRA_RESERVED_DOMAINS=os.getenv("RESERVED_DOMAINS", ""),
        MAX_DOMAINS_PER_USER=int(os.getenv("MAX_DOMAINS_PER_USER", "20")),
        MAX_MACHINES_PER_USER=int(os.getenv("MAX_MACHINES_PER_USER", "10")),
        SYNC_COMMAND=os.getenv("SYNC_COMMAND", "/usr/bin/sudo -n /usr/local/sbin/synunnel-sync"),
        PDNS_ENABLED=True,
        SESSION_COOKIE_NAME="__Host-synunnel",
        SESSION_COOKIE_SECURE=True,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        PERMANENT_SESSION_LIFETIME=43200,
        MAX_CONTENT_LENGTH=65536,
    )
    if config_override:
        app.config.update(config_override)
    if not app.config["SECRET_KEY"] or not app.config["ADMIN_TOKEN"]:
        raise RuntimeError("SECRET_KEY et ADMIN_TOKEN doivent être configurés hors du dépôt.")
    missing = [name for name in REQUIRED_SETTINGS if not app.config[name]]
    if missing:
        raise RuntimeError(f"Réglages de l'instance manquants : {', '.join(missing)}.")
    app.config["RESERVED_DOMAINS"] = system_reservations(
        [app.config["DASHBOARD_HOST"], app.config["NS1_HOST"], app.config["NS2_HOST"],
         *app.config["REDIRECT_HOSTS"].split(",")],
        app.config["EXTRA_RESERVED_DOMAINS"].split(","),
    )
    app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)
    app.teardown_appcontext(close_db)
    with app.app_context():
        init_db()

    @app.before_request
    def before_request():
        g.user = None
        if "user_id" in session:
            # La version de session change à chaque déconnexion : les autres navigateurs
            # connectés au même compte perdent alors leur session.
            g.user = get_db().execute(
                "SELECT id,email,status FROM users WHERE id=? AND status='approved' AND session_version=?",
                (session["user_id"], session.get("sv", -1)),
            ).fetchone()
            if g.user is None:
                session.clear()
        if request.method in {"POST", "PUT", "PATCH", "DELETE"} and not request.path.startswith("/admin/api/"):
            expected = session.get("csrf", "")
            supplied = request.form.get("csrf_token", "")
            if not expected or not hmac.compare_digest(expected, supplied):
                abort(400, "Jeton CSRF manquant ou invalide.")

    @app.context_processor
    def context():
        if "csrf" not in session:
            session["csrf"] = secrets.token_urlsafe(32)
        return {"csrf_token": session["csrf"], "current_user": g.get("user"), "app_version": VERSION_LABEL}

    @app.after_request
    def security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; style-src 'self'; img-src 'self'; form-action 'self'; "
            "frame-ancestors 'none'; base-uri 'none'"
        )
        if request.is_secure:
            response.headers["Strict-Transport-Security"] = "max-age=31536000"
        if request.path.startswith("/admin/api/"):
            target = request.view_args.get("user_id") if request.view_args else None
            db = get_db()
            db.execute(
                "INSERT INTO admin_audit(at,ip,method,path,status,target_user_id) VALUES(?,?,?,?,?,?)",
                (now_iso(), _client_ip(), request.method, request.path, response.status_code, target),
            )
            db.commit()
            response.headers["Cache-Control"] = "no-store"
        return response

    @app.get("/")
    def index():
        return redirect(url_for("dashboard" if g.user else "login"))

    @app.route("/register", methods=["GET", "POST"])
    def register():
        if request.method == "GET":
            return render_template("register.html")
        _rate_limit("register", _client_ip(), 5, 3600)
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        if not EMAIL_RE.fullmatch(email) or len(email) > 254 or len(password) < 12:
            flash("Adresse mail invalide ou mot de passe de moins de 12 caractères.", "error")
            return render_template("register.html"), 400
        db = get_db()
        # Réponse identique pour une adresse nouvelle, déjà inscrite ou bloquée :
        # la page ne doit pas révéler qui possède un compte.
        password_hash = PASSWORDS.hash(password)
        if not db.execute("SELECT 1 FROM blocked_emails WHERE email=?", (email,)).fetchone():
            try:
                with db:
                    db.execute(
                        "INSERT INTO users(email,password_hash,status,created_at) VALUES(?,?,'pending',?)",
                        (email, password_hash, now_iso()),
                    )
            except sqlite3.IntegrityError:
                pass
        flash("Demande enregistrée. Le compte sera utilisable après validation par l'administrateur.", "success")
        return redirect(url_for("login"))

    @app.route("/login", methods=["GET", "POST"])
    def login():
        next_url = request.values.get("next", "")
        if request.method == "GET":
            if g.user:
                return _redirect_after_login(next_url, g.user["id"])
            return render_template("login.html", next_url=next_url)
        email = request.form.get("email", "").strip().lower()
        _rate_limit("login_ip", _client_ip(), 10, 900)
        _rate_limit("login_email", email, 10, 900)
        row = get_db().execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
        try:
            valid = PASSWORDS.verify(row["password_hash"] if row else DUMMY_HASH, request.form.get("password", ""))
            valid = valid and row is not None
        except VerifyMismatchError:
            valid = False
        if not valid:
            flash("Identifiants invalides.", "error")
            return render_template("login.html", next_url=next_url), 401
        if row["status"] != "approved":
            flash("Compte en attente de validation.", "error")
            return render_template("login.html", next_url=next_url), 403
        session.clear()
        session["user_id"] = row["id"]
        session["sv"] = row["session_version"]
        session["csrf"] = secrets.token_urlsafe(32)
        session.permanent = True
        return _redirect_after_login(next_url, row["id"])

    @app.post("/logout")
    def logout():
        if g.user:
            # Se déconnecter ferme aussi les accès ouverts sur les adresses protégées.
            with get_db() as db:
                db.execute("UPDATE users SET session_version=session_version+1 WHERE id=?", (g.user["id"],))
                db.execute("DELETE FROM host_sessions WHERE user_id=?", (g.user["id"],))
                db.execute("DELETE FROM access_codes WHERE user_id=?", (g.user["id"],))
        session.clear()
        return redirect(url_for("login"))

    @app.get("/dashboard")
    @_login_required
    def dashboard():
        db = get_db()
        domains = db.execute("SELECT * FROM domains WHERE user_id=? ORDER BY name", (g.user["id"],)).fetchall()
        claims = db.execute(
            "SELECT * FROM domain_claims WHERE user_id=? ORDER BY name", (g.user["id"],),
        ).fetchall()
        machines = db.execute("SELECT * FROM machines WHERE user_id=? ORDER BY name", (g.user["id"],)).fetchall()
        addresses = db.execute(
            "SELECT a.*, d.name AS domain_name, m.name AS machine_name, "
            "(SELECT COUNT(*) FROM address_grants g WHERE g.address_id=a.id) AS grant_count "
            "FROM addresses a "
            "JOIN domains d ON d.id=a.domain_id JOIN machines m ON m.id=a.machine_id "
            "WHERE d.user_id=? ORDER BY a.hostname", (g.user["id"],),
        ).fetchall()
        return render_template("dashboard.html", domains=domains, claims=claims, machines=machines,
                               addresses=addresses)

    @app.post("/domains")
    @_login_required
    def add_domain():
        db = get_db()
        try:
            domain = normalize_domain(request.form.get("domain", ""), app.config["RESERVED_DOMAINS"])
            raw_selectors = request.form.get("selectors", "").replace(";", ",")
            selectors = [relative_name(item.strip()) for item in raw_selectors.split(",") if item.strip()]
            if len(selectors) > 20 or any("." in item or item == "@" for item in selectors):
                raise ValueError("Au maximum 20 sélecteurs DKIM simples.")
            if not request.form.get("mail_checked"):
                raise ValueError("Confirme la vérification des enregistrements mail et des sélecteurs DKIM.")
            with db:
                db.execute("BEGIN IMMEDIATE")
                _refuse_overlap(db, domain)
                owned = db.execute("SELECT COUNT(*) FROM domains WHERE user_id=?", (g.user["id"],)).fetchone()[0]
                pending = db.execute(
                    "SELECT COUNT(*) FROM domain_claims WHERE user_id=? AND name<>?", (g.user["id"], domain),
                ).fetchone()[0]
                if owned + pending >= app.config["MAX_DOMAINS_PER_USER"]:
                    raise ValueError("Nombre maximal de domaines atteint pour ce compte.")
                db.execute(
                    "INSERT INTO domain_claims(user_id,name,token,selectors,created_at) VALUES(?,?,?,?,?) "
                    "ON CONFLICT(user_id,name) DO UPDATE SET selectors=excluded.selectors",
                    (g.user["id"], domain, secrets.token_urlsafe(24), ",".join(selectors), now_iso()),
                )
            claim_id = db.execute(
                "SELECT id FROM domain_claims WHERE user_id=? AND name=?", (g.user["id"], domain),
            ).fetchone()[0]
        except (ValueError, sqlite3.IntegrityError) as exc:
            flash(str(exc), "error")
            return redirect(url_for("dashboard"))
        return redirect(url_for("claim_detail", claim_id=claim_id))

    def _owned_claim(claim_id: int):
        row = get_db().execute(
            "SELECT * FROM domain_claims WHERE id=? AND user_id=?", (claim_id, g.user["id"]),
        ).fetchone()
        if row is None:
            abort(404)
        return row

    @app.get("/claims/<int:claim_id>")
    @_login_required
    def claim_detail(claim_id: int):
        claim = _owned_claim(claim_id)
        return render_template("claim.html", claim=claim, label=f"{VERIFY_LABEL}.{claim['name']}",
                               value=f"synunnel-verification={claim['token']}")

    @app.post("/claims/<int:claim_id>/delete")
    @_login_required
    def delete_claim(claim_id: int):
        _owned_claim(claim_id)
        with get_db() as db:
            db.execute("DELETE FROM domain_claims WHERE id=? AND user_id=?", (claim_id, g.user["id"]))
        flash("Demande annulée.", "success")
        return redirect(url_for("dashboard"))

    @app.post("/claims/<int:claim_id>/verify")
    @_login_required
    def verify_claim(claim_id: int):
        claim = _owned_claim(claim_id)
        _rate_limit("verify", str(g.user["id"]), 20, 3600)
        domain = claim["name"]
        db = get_db()
        try:
            # Une réservation ajoutée après la demande s'applique aussi à la vérification.
            normalize_domain(domain, app.config["RESERVED_DOMAINS"])
            _refuse_overlap(db, domain)
            if f"synunnel-verification={claim['token']}" not in ownership_proof(domain):
                raise ValueError("Enregistrement de vérification introuvable. S'il vient d'être ajouté, "
                                 "réessaie dans quelques minutes.")
            selectors = [item for item in claim["selectors"].split(",") if item]
            snapshot = snapshot_records(domain, selectors)
            if not snapshot:
                raise ValueError("Aucun enregistrement public trouvé ; la copie DNS serait vide.")
            pdns = _pdns(app) if app.config["PDNS_ENABLED"] else None
            if pdns:
                pdns.create_zone(domain)
            try:
                with db:
                    db.execute("BEGIN IMMEDIATE")
                    _refuse_overlap(db, domain)
                    domain_id = db.execute(
                        "INSERT INTO domains(user_id,name,created_at) VALUES(?,?,?)",
                        (g.user["id"], domain, now_iso()),
                    ).lastrowid
                    db.executemany(
                        "INSERT INTO records(domain_id,name,type,content,ttl) VALUES(?,?,?,?,?)",
                        [(domain_id, *record) for record in snapshot],
                    )
                    # La preuve est faite : les demandes concurrentes sur ce nom tombent.
                    db.execute("DELETE FROM domain_claims WHERE name=?", (domain,))
                    if pdns:
                        pdns.sync_zone(db, domain_id, domain, app.config["PUBLIC_IPV4"], app.config["PUBLIC_IPV6"])
            except Exception:
                if pdns:
                    pdns.delete_zone(domain)
                raise
        except (ValueError, sqlite3.IntegrityError) as exc:
            flash(str(exc), "error")
            return redirect(url_for("claim_detail", claim_id=claim_id))
        except requests.RequestException:
            flash("Le serveur DNS de l'instance a refusé la création de la zone. Réessaie ou préviens "
                  "l'administrateur.", "error")
            return redirect(url_for("claim_detail", claim_id=claim_id))
        flash(f"Domaine vérifié. Zone {domain} créée avec {len(snapshot)} enregistrements repris. "
              "Vérifie-la avant délégation.", "success")
        return redirect(url_for("domain_detail", domain_id=domain_id))

    @app.get("/domains/<int:domain_id>")
    @_login_required
    def domain_detail(domain_id: int):
        domain = _owned_domain(domain_id)
        rows = get_db().execute(
            "SELECT * FROM records WHERE domain_id=? ORDER BY name,type,content", (domain_id,),
        ).fetchall()
        nameservers = (f"{app.config['NS1_HOST']}.", f"{app.config['NS2_HOST']}.")
        active, parent_ns = delegation_status(domain["name"], nameservers)
        return render_template("domain.html", domain=domain, records=rows, active=active,
                               parent_ns=parent_ns, nameservers=nameservers)

    @app.post("/domains/<int:domain_id>/records")
    @_login_required
    def add_record(domain_id: int):
        domain = _owned_domain(domain_id)
        db = get_db()
        try:
            name = relative_name(request.form.get("name", ""))
            kind = request.form.get("type", "").upper()
            content = canonical_content(kind, request.form.get("content", ""))
            ttl = int(request.form.get("ttl", "3600"))
            if not 300 <= ttl <= 86400:
                raise ValueError("TTL entre 300 et 86 400 secondes.")
            existing = db.execute("SELECT type FROM records WHERE domain_id=? AND name=?", (domain_id, name)).fetchall()
            if (kind == "CNAME" and existing) or (kind != "CNAME" and any(row["type"] == "CNAME" for row in existing)):
                raise ValueError("Un CNAME ne peut partager son nom avec un autre enregistrement.")
            host = fqdn(name, domain["name"]).rstrip(".")
            if kind in {"A", "AAAA", "CNAME"} and db.execute(
                "SELECT 1 FROM addresses WHERE hostname=?", (host,),
            ).fetchone():
                raise ValueError("Cette adresse est gérée par Synunnel ; supprime-la avant de modifier son DNS.")
            with db:
                db.execute(
                    "INSERT INTO records(domain_id,name,type,content,ttl) VALUES(?,?,?,?,?)",
                    (domain_id, name, kind, content, ttl),
                )
                _sync_zone(app, db, domain)
        except (ValueError, sqlite3.IntegrityError) as exc:
            flash(str(exc), "error")
        else:
            flash("Enregistrement ajouté.", "success")
        return redirect(url_for("domain_detail", domain_id=domain_id))

    @app.post("/domains/<int:domain_id>/records/<int:record_id>/delete")
    @_login_required
    def delete_record(domain_id: int, record_id: int):
        domain = _owned_domain(domain_id)
        db = get_db()
        with db:
            cursor = db.execute("DELETE FROM records WHERE id=? AND domain_id=?", (record_id, domain_id))
            if cursor.rowcount != 1:
                abort(404)
            _sync_zone(app, db, domain)
        flash("Enregistrement supprimé.", "success")
        return redirect(url_for("domain_detail", domain_id=domain_id))

    @app.post("/machines")
    @_login_required
    def add_machine():
        name = request.form.get("name", "").strip()
        if not 1 <= len(name) <= 80:
            flash("Nom de machine invalide.", "error")
            return redirect(url_for("dashboard"))
        db = get_db()
        private_key, public_key = generate_keypair()
        try:
            with db:
                # Quota et choix de l'IP sous verrou d'écriture : deux ajouts simultanés ne
                # peuvent ni dépasser le quota ni viser la même adresse.
                db.execute("BEGIN IMMEDIATE")
                owned = db.execute("SELECT COUNT(*) FROM machines WHERE user_id=?", (g.user["id"],)).fetchone()[0]
                if owned >= app.config["MAX_MACHINES_PER_USER"]:
                    raise ValueError("Nombre maximal de machines atteint pour ce compte.")
                used = {row[0] for row in db.execute("SELECT ip FROM machines")}
                ip = next((f"10.88.0.{n}" for n in range(2, 255) if f"10.88.0.{n}" not in used), None)
                if ip is None:
                    raise ValueError("Plage d'adresses WireGuard épuisée.")
                cursor = db.execute(
                    "INSERT INTO machines(user_id,name,ip,public_key,created_at) VALUES(?,?,?,?,?)",
                    (g.user["id"], name, ip, public_key, now_iso()),
                )
            _sync_runtime(app)
        except ValueError as exc:
            flash(str(exc), "error")
            return redirect(url_for("dashboard"))
        except (sqlite3.IntegrityError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
            if "cursor" in locals():
                with db:
                    db.execute("DELETE FROM machines WHERE id=? AND user_id=?", (cursor.lastrowid, g.user["id"]))
                _sync_runtime(app)
            flash("La machine n'a pas pu être ajoutée. Vérifie son nom ou la synchronisation WireGuard.", "error")
            return redirect(url_for("dashboard"))
        config = (
            "[Interface]\n"
            f"PrivateKey = {private_key}\nAddress = {ip}/32\n\n"
            "[Peer]\n"
            f"PublicKey = {app.config['WG_SERVER_PUBLIC_KEY']}\n"
            f"Endpoint = {app.config['WG_ENDPOINT']}\n"
            "AllowedIPs = 10.88.0.1/32\nPersistentKeepalive = 25\n"
        )
        response = app.make_response(render_template("machine_created.html", name=name, config=config))
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.post("/machines/<int:machine_id>/delete")
    @_login_required
    def delete_machine(machine_id: int):
        _owned_machine(machine_id)
        db = get_db()
        if db.execute("SELECT 1 FROM addresses WHERE machine_id=?", (machine_id,)).fetchone():
            flash("Supprime d'abord les adresses liées à cette machine.", "error")
            return redirect(url_for("dashboard"))
        with db:
            db.execute("DELETE FROM machines WHERE id=?", (machine_id,))
        _sync_runtime(app)
        flash("Machine supprimée.", "success")
        return redirect(url_for("dashboard"))

    @app.post("/addresses")
    @_login_required
    def add_address():
        try:
            domain_id = int(request.form.get("domain_id", ""))
            machine_id = int(request.form.get("machine_id", ""))
            domain = _owned_domain(domain_id)
            _owned_machine(machine_id)
            name = relative_name(request.form.get("name", ""), host_only=True)
            hostname = fqdn(name, domain["name"]).rstrip(".")
            port = int(request.form.get("port", ""))
            if not 1 <= port <= 65535:
                raise ValueError("Port invalide.")
            db = get_db()
            conflict_types = ("CNAME",) if name == "@" else ("A", "AAAA", "CNAME")
            if db.execute(
                f"SELECT 1 FROM records WHERE domain_id=? AND name=? AND type IN ({','.join('?' for _ in conflict_types)})",
                (domain_id, name, *conflict_types),
            ).fetchone():
                raise ValueError("Un enregistrement DNS incompatible existe déjà pour ce nom.")
            with db:
                cursor = db.execute(
                    "INSERT INTO addresses(domain_id,machine_id,hostname,port,protected,created_at,route_token) "
                    "VALUES(?,?,?,?,?,?,?)",
                    (domain_id, machine_id, hostname, port, int(bool(request.form.get("protected"))), now_iso(),
                     secrets.token_hex(12)),
                )
                _sync_zone(app, db, domain)
            try:
                _sync_runtime(app)
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
                with db:
                    db.execute("DELETE FROM addresses WHERE id=?", (cursor.lastrowid,))
                    _sync_zone(app, db, domain)
                _sync_runtime(app)
                raise ValueError("Synchronisation Caddy échouée ; l'adresse a été annulée.")
        except (ValueError, sqlite3.IntegrityError) as exc:
            flash(str(exc), "error")
            return redirect(url_for("dashboard"))
        flash(f"Adresse {hostname} créée.", "success")
        return redirect(url_for("dashboard"))

    @app.route("/addresses/<int:address_id>/access", methods=["GET", "POST"])
    @_login_required
    def address_access(address_id: int):
        db = get_db()
        address = db.execute(
            "SELECT a.* FROM addresses a JOIN domains d ON d.id=a.domain_id "
            "WHERE a.id=? AND d.user_id=?", (address_id, g.user["id"]),
        ).fetchone()
        if address is None or not address["protected"]:
            abort(404)
        if request.method == "POST":
            try:
                emails = _parse_grants(request.form.get("emails", ""))
                shared = bool(request.form.get("shared"))
                if shared and not emails:
                    raise ValueError("Ajoute au moins une adresse mail pour activer l'accès partagé.")
                with db:
                    db.execute("UPDATE addresses SET shared=? WHERE id=?", (int(shared), address_id))
                    db.execute("DELETE FROM address_grants WHERE address_id=?", (address_id,))
                    if shared:
                        db.executemany(
                            "INSERT INTO address_grants(address_id,email) VALUES(?,?)",
                            [(address_id, email) for email in emails],
                        )
                    # Les cookies et codes précédents sont révoqués à chaque changement.
                    db.execute("DELETE FROM host_sessions WHERE hostname=?", (address["hostname"],))
                    db.execute("DELETE FROM access_codes WHERE hostname=?", (address["hostname"],))
            except ValueError as exc:
                flash(str(exc), "error")
            else:
                flash(f"Accès mis à jour : {len(emails) if shared else 0} adresse(s) autorisée(s).", "success")
            return redirect(url_for("address_access", address_id=address_id))
        emails = [row[0] for row in db.execute(
            "SELECT email FROM address_grants WHERE address_id=? ORDER BY email", (address_id,),
        )]
        return render_template("address_access.html", address=address, emails=emails)

    @app.post("/addresses/<int:address_id>/delete")
    @_login_required
    def delete_address(address_id: int):
        db = get_db()
        row = db.execute(
            "SELECT a.*, d.id AS domain_id, d.name AS domain_name FROM addresses a "
            "JOIN domains d ON d.id=a.domain_id WHERE a.id=? AND d.user_id=?",
            (address_id, g.user["id"]),
        ).fetchone()
        if row is None:
            abort(404)
        domain = {"id": row["domain_id"], "name": row["domain_name"]}
        with db:
            db.execute("DELETE FROM addresses WHERE id=?", (address_id,))
            db.execute("DELETE FROM host_sessions WHERE hostname=?", (row["hostname"],))
            _sync_zone(app, db, domain)
        try:
            _sync_runtime(app)
            flash("Adresse supprimée.", "success")
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            flash("Adresse retirée de la base et du DNS ; le contrôle d'accès bloque encore l'ancienne route. Relance la synchronisation Caddy.", "error")
        return redirect(url_for("dashboard"))

    def admin_required(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            header = request.headers.get("Authorization", "")
            supplied = header[7:] if header.startswith("Bearer ") else ""
            if not hmac.compare_digest(supplied, app.config["ADMIN_TOKEN"]):
                return jsonify({"error": "non autorisé"}), 401
            return fn(*args, **kwargs)
        return wrapper

    @app.get("/admin/api/pending")
    @admin_required
    def admin_pending():
        rows = get_db().execute(
            "SELECT id,email,created_at FROM users WHERE status='pending' ORDER BY created_at,id"
        ).fetchall()
        return jsonify({"pending": [dict(row) for row in rows]})

    @app.post("/admin/api/users/<int:user_id>/approve")
    @admin_required
    def admin_approve(user_id: int):
        db = get_db()
        with db:
            cursor = db.execute("UPDATE users SET status='approved' WHERE id=? AND status='pending'", (user_id,))
        if cursor.rowcount != 1:
            return jsonify({"error": "compte en attente introuvable"}), 404
        return jsonify({"id": user_id, "status": "approved"})

    @app.post("/admin/api/users/<int:user_id>/reject")
    @admin_required
    def admin_reject(user_id: int):
        db = get_db()
        row = db.execute("SELECT email FROM users WHERE id=? AND status='pending'", (user_id,)).fetchone()
        if row is None:
            return jsonify({"error": "compte en attente introuvable"}), 404
        with db:
            db.execute("INSERT OR IGNORE INTO blocked_emails(email,blocked_at) VALUES(?,?)", (row["email"], now_iso()))
            db.execute("DELETE FROM users WHERE id=?", (user_id,))
        return jsonify({"id": user_id, "status": "rejected", "email_blocked": True})

    @app.get("/internal/caddy/ask")
    def caddy_ask():
        name = request.args.get("domain", "").lower().rstrip(".")
        redirect_hosts = {host.strip() for host in app.config["REDIRECT_HOSTS"].split(",") if host.strip()}
        if name == app.config["DASHBOARD_HOST"] or name in redirect_hosts:
            return "", 204
        row = get_db().execute(
            "SELECT 1 FROM addresses a JOIN domains d ON d.id=a.domain_id "
            "JOIN users u ON u.id=d.user_id WHERE a.hostname=? AND u.status='approved'",
            (name,),
        ).fetchone()
        return ("", 204) if row else ("", 403)

    @app.get("/internal/caddy/auth")
    def caddy_auth():
        hostname = request.host.split(":", 1)[0].lower()
        # Le jeton identifie la route exacte que Caddy s'apprête à suivre : une route périmée
        # (adresse supprimée puis recréée vers une autre machine) ne correspond plus à rien.
        route = request.args.get("route", "")
        row = get_db().execute(
            "SELECT a.protected, d.user_id FROM addresses a "
            "JOIN domains d ON d.id=a.domain_id JOIN users u ON u.id=d.user_id "
            "WHERE a.hostname=? AND a.route_token=? AND u.status='approved'",
            (hostname, route),
        ).fetchone()
        if row is None:
            return "", 403
        if not row["protected"]:
            return "", 204
        token = request.cookies.get(ACCESS_COOKIE, "")
        if token:
            found = get_db().execute(
                "SELECT user_id FROM host_sessions WHERE token_hash=? AND hostname=? AND expires_at>?",
                (_hash_token(token), hostname, int(time.time())),
            ).fetchone()
            if found and _authorized_protected_user(hostname, found["user_id"]):
                return "", 204
        original = request.headers.get("X-Forwarded-Uri", "/")
        if not original.startswith("/") or original.startswith("//"):
            original = "/"
        destination = f"https://{hostname}{original}"
        return redirect(f"https://{app.config['DASHBOARD_HOST']}/login?next={quote(destination, safe='')}")

    @app.get("/__synunnel/auth/callback")
    def access_callback():
        hostname = request.host.split(":", 1)[0].lower()
        code = request.args.get("code", "")
        if not code or len(code) > 128:
            abort(403)
        db = get_db()
        row = db.execute(
            "SELECT c.user_id,c.hostname,c.next_path FROM access_codes c "
            "JOIN users u ON u.id=c.user_id AND u.status='approved' "
            "WHERE c.code_hash=? AND c.hostname=? AND c.expires_at>?",
            (_hash_token(code), hostname, int(time.time())),
        ).fetchone()
        if row is None or not _authorized_protected_user(hostname, row["user_id"]):
            abort(403)
        token = secrets.token_urlsafe(32)
        with db:
            deleted = db.execute("DELETE FROM access_codes WHERE code_hash=?", (_hash_token(code),))
            if deleted.rowcount != 1:
                abort(403)
            db.execute(
                "INSERT INTO host_sessions(token_hash,user_id,hostname,expires_at) VALUES(?,?,?,?)",
                (_hash_token(token), row["user_id"], hostname, int(time.time()) + 43200),
            )
        response = redirect(row["next_path"])
        response.set_cookie(ACCESS_COOKIE, token, secure=True, httponly=True, samesite="Lax", max_age=43200, path="/")
        response.headers["Cache-Control"] = "no-store"
        return response

    return app
