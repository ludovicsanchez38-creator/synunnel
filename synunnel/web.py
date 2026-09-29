"""Interface et API de Synunnel."""

import hashlib
import hmac
import os
import secrets
import time
from functools import wraps
from urllib.parse import quote

from flask import (
    Flask,
    abort,
    flash,
    g,
    jsonify,
    make_response,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from flask.sessions import SecureCookieSessionInterface
from werkzeug.middleware.proxy_fix import ProxyFix

from . import VERSION_LABEL, account, actions, api, guest, legal, security
from .account import PASSWORDS
from .db import allocate_id, close_db, get_db, init_db, now_iso
from .dns import (
    system_reservations,
)
from .mailer import Mailer

EMAIL_RE = actions.EMAIL_RE
SESSION_MAX_AGE = 86400
ACCESS_COOKIE = "__Host-synunnel-access"
SENSITIVE_PATHS = ("/login", "/logout", "/register", "/security", "/forgot", "/reset", "/recover", "/tokens",
                   "/access/", "/__synunnel/")
# Vérifié quand le compte n'existe pas : même coût qu'une vraie tentative.
DUMMY_HASH = PASSWORDS.hash(secrets.token_hex(16))
PENDING = " La mise en service se termine automatiquement dans quelques minutes."
REQUIRED_SETTINGS = ("PUBLIC_IPV4", "WG_ENDPOINT", "DASHBOARD_HOST", "NS1_HOST", "NS2_HOST")


def _hash_token(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _client_ip() -> str:
    raw = request.remote_addr
    if raw in {"127.0.0.1", "::1"}:
        raw = request.headers.get("X-Real-IP", raw)
    return actions.client_bucket(raw)


def _same_secret(expected: str, supplied: str) -> bool:
    # Comparaison en octets : une valeur non ASCII est un refus, jamais une erreur interne.
    return bool(expected) and hmac.compare_digest(expected.encode(), supplied.encode())


def _rate_limit(kind: str, key: str, limit: int, window: int) -> None:
    try:
        actions.rate_limit(kind, key, limit, window)
    except actions.ActionError as exc:
        abort(exc.status, exc.message)


def _login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if g.user is None:
            if g.get("enrolling") is not None:
                # Instance qui exige la 2FA : un compte sans facteur n'a accès qu'à son activation.
                return redirect(url_for("security_page"))
            return redirect(url_for("login", next=request.url))
        return fn(*args, **kwargs)
    return wrapper


def _web_guard(db) -> None:
    """Recontrôle du compte sous le verrou d'écriture, comme l'API le fait pour ses jetons."""
    row = db.execute("SELECT totp_enabled_at FROM users WHERE id=? AND status='approved' AND session_version=?",
                     (g.user["id"], session.get("sv", -1))).fetchone()
    if row is None or (account.require_2fa() and not row["totp_enabled_at"]):
        raise actions.ActionError(401, "unauthorized", "Session expirée : reconnecte-toi.")


def _authorized_protected_user(hostname: str, user_id: int) -> bool:
    # Le visiteur (propriétaire ou invité) doit lui-même satisfaire l'exigence de 2FA de l'instance.
    policy, params = account.policy_sql()
    return get_db().execute(
        "SELECT 1 FROM addresses a JOIN domains d ON d.id=a.domain_id "
        f"JOIN users u ON u.id=? AND u.status='approved' AND {policy} "
        "WHERE a.hostname=? AND a.protected=1 AND "
        "(d.user_id=u.id OR (a.shared=1 AND EXISTS ("
        "SELECT 1 FROM address_grants g WHERE g.address_id=a.id AND g.email=u.email)))",
        (user_id, *params, hostname),
    ).fetchone() is not None


def _validate_next(value: str, user_id: int) -> tuple[str, str] | None:
    # Syntaxe stricte commune aux deux voies (compte, invité), puis autorisation propre au compte.
    target = guest.parse_next(value)
    if target is None or not _authorized_protected_user(target[0], user_id):
        return None
    return target


def _redirect_after_login(next_url: str, user_id: int):
    target = _validate_next(next_url, user_id) if next_url else None
    if target is None:
        return redirect(url_for("dashboard"))
    hostname, path = target
    code = secrets.token_urlsafe(32)
    db = get_db()
    # Le code porte la version de session qui l'a émis : une déconnexion survenue pendant
    # cette requête le rend inutilisable, même s'il est inséré après elle.
    db.execute(
        "INSERT INTO access_codes(code_hash,user_id,hostname,next_path,expires_at,session_version) "
        "VALUES(?,?,?,?,?,?)",
        (_hash_token(code), user_id, hostname, path, int(time.time()) + 120, session.get("sv", -1)),
    )
    db.commit()
    target = f"https://{hostname}/__synunnel/auth/callback?code={quote(code)}"
    if request.method == "POST":
        # Après un envoi de formulaire, la CSP (form-action 'self') interdit à Chromium de suivre une
        # redirection vers un autre domaine : une page du tableau de bord prend le relais.
        response = make_response(render_template("continue.html", target=target, hostname=hostname))
        response.headers["Cache-Control"] = "no-store"
        return response
    return redirect(target)


class SessionInterface(SecureCookieSessionInterface):
    """Aucune session sur l'API : ni lecture ni renouvellement du cookie du tableau de bord."""

    def open_session(self, app, request):
        if request.path.startswith("/api/"):
            return self.null_session_class()
        return super().open_session(app, request)


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
        MAX_ADDRESSES_PER_USER=int(os.getenv("MAX_ADDRESSES_PER_USER", "50")),
        # « invitation » : l'administrateur remet un code à usage unique lié à une adresse, qui vaut
        # approbation. « approval » : inscription libre puis approbation manuelle (voir SECURITE.md).
        REGISTRATION_MODE=os.getenv("REGISTRATION_MODE", "invitation"),
        MAX_RECORDS_PER_DOMAIN=int(os.getenv("MAX_RECORDS_PER_DOMAIN", "200")),
        SYNC_COMMAND=os.getenv("SYNC_COMMAND", "/usr/bin/sudo -n /usr/local/sbin/synunnel-sync"),
        # Clé dédiée au chiffrement des secrets TOTP (64 caractères hexadécimaux), distincte de SECRET_KEY.
        TOTP_KEY=os.getenv("TOTP_KEY", ""),
        REQUIRE_2FA=os.getenv("REQUIRE_2FA", "0") == "1",
        # Accès invité par code mail : possible par défaut (option par adresse, désactivée), coupé si la
        # 2FA est exigée, sauf choix explicite GUEST_CODES_WITH_2FA=1.
        GUEST_CODES=os.getenv("GUEST_CODES", "1") == "1",
        GUEST_CODES_WITH_2FA=os.getenv("GUEST_CODES_WITH_2FA", "0") == "1",
        SMTP_HOST=os.getenv("SMTP_HOST", ""),
        SMTP_PORT=os.getenv("SMTP_PORT", "465"),
        SMTP_USER=os.getenv("SMTP_USER", ""),
        SMTP_FROM=os.getenv("SMTP_FROM", ""),
        SMTP_PASSWORD_FILE=os.getenv("SMTP_PASSWORD_FILE", ""),
        # Exploitant de l'instance : nom affiché, contact, mentions légales et notice de confidentialité
        # (fichiers Markdown de l'exploitant, voir docs/modeles/).
        OPERATOR_NAME=os.getenv("OPERATOR_NAME", ""),
        ADMIN_CONTACT=os.getenv("ADMIN_CONTACT", ""),
        LEGAL_FILE=os.getenv("LEGAL_FILE", ""),
        PRIVACY_FILE=os.getenv("PRIVACY_FILE", ""),
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
    try:
        app.config["TOTP_KEY_BYTES"] = security.parse_key(app.config["TOTP_KEY"])
    except ValueError as exc:
        raise RuntimeError(str(exc)) from exc
    missing = [name for name in REQUIRED_SETTINGS if not app.config[name]]
    if missing:
        raise RuntimeError(f"Réglages de l'instance manquants : {', '.join(missing)}.")
    app.config["RESERVED_DOMAINS"] = system_reservations(
        [app.config["DASHBOARD_HOST"], app.config["NS1_HOST"], app.config["NS2_HOST"],
         *app.config["REDIRECT_HOSTS"].split(",")],
        app.config["EXTRA_RESERVED_DOMAINS"].split(","),
    )
    app.extensions["synunnel_mailer"] = Mailer(app.config, lambda: app.config.get("MAIL_TRANSPORT"))
    if app.config["SMTP_HOST"] and not app.extensions["synunnel_mailer"].configured:
        app.logger.warning("SMTP configuré mais inutilisable (réglages ou fichier du mot de passe illisible) : "
                           "aucun mail ne partira.")
    app.session_interface = SessionInterface()
    app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)
    api.register(app)
    app.teardown_appcontext(close_db)
    with app.app_context():
        init_db()

    @app.before_request
    def before_request():
        g.user = None
        g.enrolling = None
        hostname = request.host.split(":", 1)[0].lower()
        if (hostname != app.config["DASHBOARD_HOST"] and not request.path.startswith(("/__synunnel/", "/internal/caddy/"))
                and get_db().execute("SELECT 1 FROM addresses WHERE hostname=?", (hostname,)).fetchone()):
            # Une adresse publiée n'atteint l'application que par ses chemins réservés.
            abort(404)
        if request.path.startswith("/api/"):
            # L'API s'authentifie par jeton uniquement : ni cookie ni jeton CSRF ici.
            return
        if "user_id" in session:
            # La version de session change à chaque déconnexion et à chaque changement de
            # justificatif : les autres navigateurs connectés au même compte perdent leur session.
            row = get_db().execute(
                "SELECT id,email,status,totp_enabled_at,email_verified_at,credential_version FROM users "
                "WHERE id=? AND status='approved' AND session_version=?",
                (session["user_id"], session.get("sv", -1)),
            ).fetchone()
            if row is not None and int(time.time()) - session.get("auth_at", 0) > SESSION_MAX_AGE:
                # Durée absolue : même utilisée sans interruption, une session se renouvelle par un mot de passe.
                row = None
            if row is not None and row["totp_enabled_at"] and session.get("mfa") != 1:
                # Compte à double authentification : une session qui ne l'a pas prouvée ne vaut rien.
                row = None
            if row is not None and not account.satisfies_policy(row):
                g.enrolling = row
            else:
                g.user = row
            if row is None:
                session.clear()
        # /admin/api/ s'authentifie par jeton ; /__synunnel/ (hôtes publiés) porte son propre jeton de formulaire.
        # Toute méthode autre que GET, HEAD et OPTIONS exige le jeton : une requête HEAD n'atteint jamais
        # la branche d'écriture d'une vue (les vues n'écrivent que sur POST).
        mutating = (request.method not in {"GET", "HEAD", "OPTIONS"}
                    and not request.path.startswith(("/admin/api/", "/__synunnel/")))
        if mutating and not _same_secret(session.get("csrf", ""), request.form.get("csrf_token", "")):
            abort(400, "Jeton CSRF manquant ou invalide.")

    @app.context_processor
    def context():
        if "csrf" not in session:
            session["csrf"] = secrets.token_urlsafe(32)
        return {"csrf_token": session["csrf"], "current_user": g.get("user"), "app_version": VERSION_LABEL,
                "operator_name": app.config["OPERATOR_NAME"], "admin_contact": app.config["ADMIN_CONTACT"],
                "dashboard_host": app.config["DASHBOARD_HOST"],
                "enrolling_user": g.get("enrolling"),
                "invitation_mode": app.config["REGISTRATION_MODE"] != "approval"}

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
        if request.path.startswith(("/api/", *SENSITIVE_PATHS)):
            # Authentification, récupération, sécurité, accès invité : jamais en cache, erreurs comprises.
            response.headers["Cache-Control"] = "no-store"
        if request.path.startswith("/admin/api/"):
            if g.get("admin_ok"):
                target = request.view_args.get("user_id") if request.view_args else None
                db = get_db()
                db.execute(
                    "INSERT INTO admin_audit(at,ip,method,path,status,target_user_id) VALUES(?,?,?,?,?,?)",
                    (now_iso(), _client_ip(), request.method, request.path[:200], response.status_code, target),
                )
                db.commit()
            response.headers["Cache-Control"] = "no-store"
        return response

    @app.get("/mentions-legales")
    def legal_notice():
        return render_template("legal.html", title="Mentions légales", content=legal.load(app.config["LEGAL_FILE"]))

    @app.get("/confidentialite")
    def privacy_notice():
        return render_template("legal.html", title="Confidentialité",
                               content=legal.load(app.config["PRIVACY_FILE"]))

    @app.get("/")
    def index():
        return redirect(url_for("dashboard" if g.user else "login"))

    @app.route("/register", methods=["GET", "POST"])
    def register():
        invitation_mode = app.config["REGISTRATION_MODE"] != "approval"
        if request.method != "POST":
            return render_template("register.html", invitation_mode=invitation_mode)
        _rate_limit("register", _client_ip(), 5, 3600)
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        if not EMAIL_RE.fullmatch(email) or len(email) > 254 or len(password) < 12:
            flash("Adresse mail invalide ou mot de passe de moins de 12 caractères.", "error")
            return render_template("register.html", invitation_mode=invitation_mode), 400
        _rate_limit("register_email", email, 5, 3600)
        db = get_db()
        # Réponse identique pour une adresse nouvelle, déjà inscrite, bloquée ou un code faux :
        # la page ne doit pas révéler qui possède un compte.
        password_hash = PASSWORDS.hash(password)
        code = request.form.get("invitation", "").strip()
        with db:
            db.execute("BEGIN IMMEDIATE")
            blocked = db.execute("SELECT 1 FROM blocked_emails WHERE email=?", (email,)).fetchone()
            exists = db.execute("SELECT 1 FROM users WHERE email=?", (email,)).fetchone()
            invitation = None
            if invitation_mode and code:
                invitation = db.execute(
                    "SELECT code_hash FROM invitations WHERE code_hash=? AND email=? AND used_at IS NULL AND expires_at>?",
                    (_hash_token(code), email, int(time.time())),
                ).fetchone()
            if not blocked and not exists and (invitation or not invitation_mode):
                db.execute(
                    "INSERT INTO users(id,email,password_hash,status,created_at,session_version) VALUES(?,?,?,?,?,?)",
                    # Version tirée au hasard : aucune ancienne session ne peut ouvrir ce compte.
                    (allocate_id(db, "users"), email, password_hash, "approved" if invitation else "pending",
                     now_iso(), secrets.randbits(62)),
                )
                if invitation:
                    db.execute("UPDATE invitations SET used_at=? WHERE code_hash=?", (now_iso(), invitation["code_hash"]))
        if invitation_mode:
            flash("Si le code d'invitation correspond à cette adresse, ton compte est prêt : connecte-toi.", "success")
        else:
            flash("Demande enregistrée. Le compte sera utilisable après validation par l'administrateur.", "success")
        return redirect(url_for("login"))

    @app.route("/login", methods=["GET", "POST"])
    def login():
        next_url = request.values.get("next", "")
        if request.method != "POST":
            if g.user:
                return _redirect_after_login(next_url, g.user["id"])
            return render_template("login.html", next_url=next_url, guest_codes=guest.offers_codes(next_url))
        email = request.form.get("email", "").strip().lower()[:254]
        ip = _client_ip()
        # Seuls les échecs comptent, par adresse et par couple adresse-compte : un tiers qui se trompe
        # de mot de passe depuis ailleurs ne peut pas empêcher le titulaire de se connecter.
        # Chaque essai est réservé atomiquement avant la vérification, puis rendu s'il réussit.
        slots = []
        for kind, key, limit in (("login_ip", ip, 30), ("login_pair", f"{email}|{ip}", 5), ("login_email", email, 50)):
            slot = actions.reserve_attempt(kind, key, limit, 900)
            if slot is None:
                actions.release_attempts(*slots)
                abort(429, "Trop de tentatives. Réessaie plus tard.")
            slots.append(slot)
        row = get_db().execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
        valid = account.verify_password(row["password_hash"] if row else DUMMY_HASH, request.form.get("password", ""))
        valid = valid and row is not None
        if not valid:
            flash("Identifiants invalides.", "error")
            return render_template("login.html", next_url=next_url), 401
        actions.release_attempts(*slots)
        if row["status"] != "approved":
            flash("Compte en attente de validation.", "error")
            return render_template("login.html", next_url=next_url), 403
        if row["totp_enabled_at"]:
            return account.begin_second_step(row, next_url)
        account.open_session(row["id"], row["session_version"], mfa=False)
        if not account.satisfies_policy(row):
            return redirect(url_for("security_page"))
        return _redirect_after_login(next_url, row["id"])

    @app.post("/logout")
    def logout():
        if g.user or g.enrolling:
            # Se déconnecter ferme aussi les accès ouverts sur les adresses protégées.
            with get_db() as db:
                uid = (g.user or g.enrolling)["id"]
                db.execute("UPDATE users SET session_version=session_version+1 WHERE id=?", (uid,))
                db.execute("DELETE FROM host_sessions WHERE user_id=?", (uid,))
                db.execute("DELETE FROM access_codes WHERE user_id=?", (uid,))
        session.clear()
        return redirect(url_for("login"))

    @app.get("/dashboard")
    @_login_required
    def dashboard():
        return render_template("dashboard.html", **actions.account_overview(g.user["id"]))

    def _flash_error(exc: actions.ActionError):
        if exc.status == 401:
            abort(401)
        if exc.status == 404:
            abort(404)
        if exc.status == 429:
            abort(429, exc.message)
        flash(exc.message, "error")

    @app.post("/domains")
    @_login_required
    def add_domain():
        raw_selectors = request.form.get("selectors", "").replace(";", ",").split(",")
        try:
            claim, _created = actions.create_claim(app, g.user["id"], request.form.get("domain", ""), raw_selectors,
                                                   bool(request.form.get("mail_checked")), guard=_web_guard)
        except actions.ActionError as exc:
            _flash_error(exc)
            return redirect(url_for("dashboard"))
        return redirect(url_for("claim_detail", claim_id=claim["id"]))

    @app.get("/claims/<int:claim_id>")
    @_login_required
    def claim_detail(claim_id: int):
        try:
            claim = actions.owned_claim(g.user["id"], claim_id)
        except actions.ActionError:
            abort(404)
        proof = actions.claim_proof(claim)
        return render_template("claim.html", claim=claim, label=proof["name"], value=proof["value"])

    @app.post("/claims/<int:claim_id>/delete")
    @_login_required
    def delete_claim(claim_id: int):
        try:
            actions.cancel_claim(g.user["id"], claim_id, guard=_web_guard)
        except actions.ActionError as exc:
            _flash_error(exc)
        else:
            flash("Demande annulée.", "success")
        return redirect(url_for("dashboard"))

    @app.post("/claims/<int:claim_id>/verify")
    @_login_required
    def verify_claim(claim_id: int):
        try:
            result = actions.verify_claim(app, g.user["id"], claim_id, guard=_web_guard)
        except actions.ActionError as exc:
            _flash_error(exc)
            return redirect(url_for("claim_detail", claim_id=claim_id))
        flash(f"Domaine vérifié. Zone créée avec {result['copied']} enregistrements repris. "
              "Vérifie-la avant délégation." + ("" if result["synced"] else PENDING), "success")
        return redirect(url_for("domain_detail", domain_id=result["domain_id"]))

    @app.get("/domains/<int:domain_id>")
    @_login_required
    def domain_detail(domain_id: int):
        try:
            view = actions.domain_view(app, g.user["id"], domain_id)
        except actions.ActionError:
            abort(404)
        return render_template("domain.html", **view)

    @app.post("/domains/<int:domain_id>/records")
    @_login_required
    def add_record(domain_id: int):
        try:
            actions.add_record(app, g.user["id"], domain_id, request.form.get("name", ""),
                               request.form.get("type", ""), request.form.get("content", ""),
                               request.form.get("ttl", "3600"), guard=_web_guard)
        except actions.ActionError as exc:
            _flash_error(exc)
        else:
            flash("Enregistrement ajouté.", "success")
        return redirect(url_for("domain_detail", domain_id=domain_id))

    @app.route("/domains/<int:domain_id>/delete", methods=["GET", "POST"])
    @_login_required
    def delete_domain(domain_id: int):
        try:
            domain = actions.owned_domain(g.user["id"], domain_id)
        except actions.ActionError:
            abort(404)
        if request.method != "POST":
            return render_template("domain_delete.html", domain=domain)
        # Confirmation sans JavaScript : le nom du domaine, retapé.
        if request.form.get("confirm_name", "").strip().lower().rstrip(".") != domain["name"]:
            flash("Le nom retapé ne correspond pas au domaine : rien n'a été supprimé.", "error")
            return redirect(url_for("delete_domain", domain_id=domain_id))
        try:
            result = actions.delete_domain(app, g.user["id"], domain_id, guard=_web_guard)
        except actions.ActionError as exc:
            _flash_error(exc)
            return redirect(url_for("domain_detail", domain_id=domain_id))
        flash(f"Domaine {result['name']} supprimé. Sa zone reste servie par l'instance pendant 48 heures, le "
              "temps que les résolveurs oublient l'ancienne délégation, puis elle est retirée." +
              ("" if result["synced"] else PENDING), "success")
        return redirect(url_for("dashboard"))

    @app.post("/domains/<int:domain_id>/records/<int:record_id>/delete")
    @_login_required
    def delete_record(domain_id: int, record_id: int):
        try:
            actions.delete_record(app, g.user["id"], domain_id, record_id, guard=_web_guard)
        except actions.ActionError as exc:
            _flash_error(exc)
        else:
            flash("Enregistrement supprimé.", "success")
        return redirect(url_for("domain_detail", domain_id=domain_id))

    @app.post("/machines")
    @_login_required
    def add_machine():
        try:
            machine = actions.create_machine(app, g.user["id"], request.form.get("name", ""), guard=_web_guard)
        except actions.ActionError as exc:
            _flash_error(exc)
            return redirect(url_for("dashboard"))
        response = app.make_response(render_template("machine_created.html", name=machine["name"],
                                                     config=machine["config"]))
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.post("/machines/<int:machine_id>/delete")
    @_login_required
    def delete_machine(machine_id: int):
        try:
            actions.delete_machine(app, g.user["id"], machine_id, guard=_web_guard)
        except actions.ActionError as exc:
            _flash_error(exc)
        else:
            flash("Machine supprimée.", "success")
        return redirect(url_for("dashboard"))

    @app.post("/addresses")
    @_login_required
    def add_address():
        try:
            address = actions.create_address(
                app, g.user["id"], request.form.get("domain_id", ""), request.form.get("machine_id", ""),
                request.form.get("name", ""), request.form.get("port", ""), bool(request.form.get("protected")),
                guard=_web_guard,
            )
        except actions.ActionError as exc:
            _flash_error(exc)
            return redirect(url_for("dashboard"))
        flash(f"Adresse {address['hostname']} créée." + ("" if address["synced"] else PENDING), "success")
        return redirect(url_for("dashboard"))

    @app.route("/addresses/<int:address_id>/access", methods=["GET", "POST"])
    @_login_required
    def address_access(address_id: int):
        try:
            address, emails = actions.access_list(g.user["id"], address_id)
        except actions.ActionError:
            abort(404)
        if request.method == "POST":
            try:
                # Case absente quand l'instance ne permet pas l'accès invité : l'option garde sa valeur.
                option = bool(request.form.get("guest_codes")) if guest.instance_allows() else None
                granted = actions.set_access(g.user["id"], address_id, bool(request.form.get("shared")),
                                             request.form.get("emails", ""), guest_codes=option, guard=_web_guard)
            except actions.ActionError as exc:
                _flash_error(exc)
            else:
                flash(f"Accès mis à jour : {len(granted)} adresse(s) autorisée(s).", "success")
            return redirect(url_for("address_access", address_id=address_id))
        return render_template("address_access.html", address=address, emails=emails,
                               guest_available=guest.instance_allows())

    @app.post("/addresses/<int:address_id>/delete")
    @_login_required
    def delete_address(address_id: int):
        try:
            actions.delete_address(app, g.user["id"], address_id, guard=_web_guard)
        except actions.ActionError as exc:
            _flash_error(exc)
        else:
            flash("Adresse supprimée.", "success")
        return redirect(url_for("dashboard"))

    @app.get("/tokens")
    @_login_required
    def tokens():
        rows = get_db().execute(
            "SELECT id,name,prefix,scopes,created_at,expires_at,last_used_at,revoked_at FROM api_tokens "
            "WHERE user_id=? ORDER BY revoked_at IS NOT NULL, created_at DESC", (g.user["id"],),
        ).fetchall()
        now = int(time.time())
        rows = [{**dict(row), "labels": [api.PERMISSIONS[item] for item in row["scopes"].split(",")
                                         if item in api.PERMISSIONS]} for row in rows]
        return render_template("tokens.html", tokens=rows, now=now, durations=api.TOKEN_DURATIONS,
                               with_factor=bool(g.user["totp_enabled_at"]), permissions=api.PERMISSIONS,
                               api_base=f"https://{app.config['DASHBOARD_HOST']}/api/v1")

    @app.post("/tokens")
    @_login_required
    def create_token():
        _rate_limit("token_create", str(g.user["id"]), 10, 3600)
        name = request.form.get("name", "").strip()
        chosen = [item for item in request.form.getlist("permissions") if item in api.PERMISSIONS]
        try:
            days = int(request.form.get("days", ""))
        except ValueError:
            days = 0
        db = get_db()
        # Authentification récente exigée : le mot de passe (et le code de 2FA) est redemandé à chaque
        # création. Les versions lues ici sont recontrôlées sous le verrou de l'insertion.
        row = db.execute("SELECT password_hash, session_version, credential_version, totp_enabled_at FROM users "
                         "WHERE id=?", (g.user["id"],)).fetchone()
        if not account.verify_password(row["password_hash"], request.form.get("password", "")):
            flash("Mot de passe incorrect.", "error")
            return redirect(url_for("tokens"))
        with_factor = bool(row["totp_enabled_at"])
        try:
            name = actions.clean_label(name, 60, "Nom")
        except actions.ActionError:
            name = ""
        if not name or days not in api.TOKEN_DURATIONS or len(chosen) != len(request.form.getlist("permissions")):
            flash("Nom, permissions ou durée invalides.", "error")
            return redirect(url_for("tokens"))
        value = api.new_token()
        now = int(time.time())
        slots = account.reserve_mfa(g.user["id"]) if with_factor else ()
        with db:
            db.execute("BEGIN IMMEDIATE")
            if account.locked_user(db, g.user["id"], row["session_version"], row["credential_version"]) is None:
                # Mot de passe, 2FA ou statut changés pendant la vérification : aucun jeton n'est créé.
                db.rollback()
                actions.release_attempts(*slots)
                flash("Tes identifiants ont changé pendant l'opération : recommence.", "error")
                return redirect(url_for("tokens"))
            if with_factor and not account.consume_factor(db, g.user["id"], request.form.get("code", ""),
                                                          row["credential_version"]):
                db.rollback()
                flash("Code de double authentification incorrect.", "error")
                return redirect(url_for("tokens"))
            active = db.execute(
                "SELECT COUNT(*) FROM api_tokens WHERE user_id=? AND revoked_at IS NULL AND expires_at>?",
                (g.user["id"], now),
            ).fetchone()[0]
            if active >= api.MAX_ACTIVE_TOKENS:
                db.rollback()
                actions.release_attempts(*slots)
                flash(f"{api.MAX_ACTIVE_TOKENS} jetons actifs au plus : révoque d'abord un jeton.", "error")
                return redirect(url_for("tokens"))
            token_id = db.execute(
                "INSERT INTO api_tokens(user_id,name,token_hash,prefix,scopes,created_at,expires_at,"
                "credential_version) VALUES(?,?,?,?,?,?,?,?)",
                (g.user["id"], name, api.hash_token(value), value[:10], ",".join(sorted(set(chosen))), now_iso(),
                 now + days * 86400, row["credential_version"]),
            ).lastrowid
            db.execute("INSERT INTO api_audit(at,user_id,token_id,action,resource) VALUES(?,?,?,?,?)",
                       (now_iso(), g.user["id"], token_id, "token.create", f"token:{token_id}"))
        # Réservations rendues hors de toute transaction (elles passent par une autre connexion).
        actions.release_attempts(*slots)
        # Le jeton n'est montré qu'ici : ni flash, ni session, ni URL.
        response = app.make_response(render_template(
            "token_created.html", name=name, days=days, token=value,
            granted=[api.PERMISSIONS[item] for item in sorted(set(chosen))],
            api_base=f"https://{app.config['DASHBOARD_HOST']}/api/v1",
        ))
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.post("/tokens/<int:token_id>/revoke")
    @_login_required
    def revoke_token(token_id: int):
        with get_db() as db:
            revoked = db.execute(
                "UPDATE api_tokens SET revoked_at=? WHERE id=? AND user_id=? AND revoked_at IS NULL",
                (now_iso(), token_id, g.user["id"]),
            ).rowcount
            if revoked:
                db.execute("INSERT INTO api_audit(at,user_id,token_id,action,resource) VALUES(?,?,?,?,?)",
                           (now_iso(), g.user["id"], token_id, "token.revoke", f"token:{token_id}"))
        if not revoked:
            abort(404)
        flash("Jeton révoqué.", "success")
        return redirect(url_for("tokens"))

    @app.post("/tokens/revoke-all")
    @_login_required
    def revoke_all_tokens():
        with get_db() as db:
            count = db.execute("UPDATE api_tokens SET revoked_at=? WHERE user_id=? AND revoked_at IS NULL",
                               (now_iso(), g.user["id"])).rowcount
            db.execute("INSERT INTO api_audit(at,user_id,token_id,action,resource) VALUES(?,?,?,?,?)",
                       (now_iso(), g.user["id"], None, "token.revoke_all", f"tokens:{count}"))
        flash(f"{count} jeton(s) révoqué(s).", "success")
        return redirect(url_for("tokens"))

    def _decision_email() -> str:
        data = request.get_json(silent=True)
        email = data.get("email") if isinstance(data, dict) else None
        if not isinstance(email, str) or not email.strip():
            abort(400, "Adresse mail attendue dans le corps JSON : {\"email\": \"...\"}.")
        return email.strip().lower()

    def admin_required(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            # L'API d'administration ne répond qu'en local (127.0.0.1:8000, par SSH sur le VPS) : une requête
            # passée par Caddy porte X-Real-IP ou X-Forwarded-For, posés par le proxy, et reçoit un 404.
            if request.headers.get("X-Real-IP") or request.headers.get("X-Forwarded-For"):
                abort(404)
            header = request.headers.get("Authorization", "")
            supplied = header[7:] if header.startswith("Bearer ") else ""
            # Plafond vérifié avant la comparaison : au-delà, même le bon jeton attend.
            if actions.limit_reached("admin_auth", _client_ip(), 20, 600):
                return jsonify({"error": "trop de tentatives"}), 429
            if not _same_secret(app.config["ADMIN_TOKEN"], supplied):
                # Refus comptés sans rien écrire dans le journal : un anonyme ne remplit pas la base.
                actions.record_attempt("admin_auth", _client_ip())
                return jsonify({"error": "non autorisé"}), 401
            g.admin_ok = True
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
        email = _decision_email()
        db = get_db()
        with db:
            db.execute("BEGIN IMMEDIATE")
            # La décision porte sur un couple identifiant-adresse : une demande remplacée entre la
            # lecture de la liste et la décision n'est jamais approuvée à sa place. Une adresse
            # bloquée n'est jamais approuvée.
            cursor = db.execute(
                "UPDATE users SET status='approved' WHERE id=? AND email=? AND status='pending' "
                "AND email NOT IN (SELECT email FROM blocked_emails)", (user_id, email),
            )
        if cursor.rowcount != 1:
            return jsonify({"error": "compte en attente introuvable pour cette adresse"}), 404
        return jsonify({"id": user_id, "status": "approved"})

    @app.post("/admin/api/users/<int:user_id>/reject")
    @admin_required
    def admin_reject(user_id: int):
        email = _decision_email()
        db = get_db()
        with db:
            db.execute("BEGIN IMMEDIATE")
            if db.execute("SELECT 1 FROM domains WHERE user_id=? UNION SELECT 1 FROM machines WHERE user_id=?",
                          (user_id, user_id)).fetchone():
                # Compte suspendu qui a encore des domaines ou des machines : les retirer d'abord,
                # pour que leurs zones et pairs soient nettoyés proprement.
                db.rollback()
                return jsonify({"error": "compte avec domaines ou machines : retire-les d'abord"}), 409
            deleted = db.execute("DELETE FROM users WHERE id=? AND email=? AND status='pending'",
                                 (user_id, email)).rowcount
            if deleted != 1:
                db.rollback()
                return jsonify({"error": "compte en attente introuvable pour cette adresse"}), 404
            db.execute("INSERT OR IGNORE INTO blocked_emails(email,blocked_at) VALUES(?,?)", (email, now_iso()))
        return jsonify({"id": user_id, "status": "rejected", "email_blocked": True})

    @app.post("/admin/api/domains/delete")
    @admin_required
    def admin_delete_domain():
        """Retire un domaine et ses adresses, par exemple pour le rendre à son titulaire actuel."""
        data = request.get_json(silent=True)
        name = data.get("name") if isinstance(data, dict) else None
        row = get_db().execute("SELECT id FROM domains WHERE name=?", (str(name or "").lower().rstrip("."),)).fetchone()
        if row is None:
            return jsonify({"error": "domaine introuvable"}), 404
        result = actions.delete_domain(app, None, row["id"], force=True)
        return jsonify({"name": result["name"], "status": "deleted", "synced": result["synced"]})

    @app.post("/admin/api/invitations")
    @admin_required
    def admin_invite():
        """Code d'invitation à usage unique, lié à une adresse, valable 7 jours. Il vaut approbation."""
        email = _decision_email()
        if not EMAIL_RE.fullmatch(email) or len(email) > 254:
            return jsonify({"error": "adresse invalide"}), 422
        code = secrets.token_urlsafe(18)
        expires = int(time.time()) + 7 * 86400
        with get_db() as db:
            db.execute("DELETE FROM invitations WHERE email=? AND used_at IS NULL", (email,))
            db.execute("INSERT INTO invitations(code_hash,email,created_at,expires_at) VALUES(?,?,?,?)",
                       (_hash_token(code), email, now_iso(), expires))
        return jsonify({"email": email, "code": code, "expires_at": expires})

    @app.post("/admin/api/users/<int:user_id>/recovery")
    @admin_required
    def admin_recovery(user_id: int):
        """Ticket de récupération (mot de passe, 2FA ou les deux), à remettre par un canal connu."""
        email = _decision_email()
        data = request.get_json(silent=True)
        scope = data.get("scope") if isinstance(data, dict) else None
        if scope not in account.SCOPES:
            return jsonify({"error": "scope vaut password, 2fa ou both"}), 422
        issued = account.issue_ticket(user_id, email, scope)
        if issued is None:
            return jsonify({"error": "compte approuvé introuvable pour cette adresse"}), 404
        return jsonify({"id": user_id, "email": email, "scope": scope, **issued,
                        "url": f"https://{app.config['DASHBOARD_HOST']}/recover"})

    @app.post("/admin/api/users/<int:user_id>/verify-email")
    @admin_required
    def admin_verify_email(user_id: int):
        """L'administrateur atteste, après vérification humaine, que la boîte appartient au titulaire."""
        email = _decision_email()
        db = get_db()
        with db:
            db.execute("BEGIN IMMEDIATE")
            cursor = db.execute("UPDATE users SET email_verified_at=COALESCE(email_verified_at, ?) "
                                "WHERE id=? AND email=? AND status='approved'", (now_iso(), user_id, email))
            if cursor.rowcount != 1:
                db.rollback()
                return jsonify({"error": "compte approuvé introuvable pour cette adresse"}), 404
            account.record_event(db, user_id, "email.verify", via="admin", actor="admin")
        return jsonify({"id": user_id, "email": email, "email_verified": True})

    @app.post("/admin/api/users/<int:user_id>/suspend")
    @admin_required
    def admin_suspend(user_id: int):
        """Suspend un compte approuvé : sessions, accès, jetons et services coupés, données conservées."""
        db = get_db()
        with db:
            db.execute("BEGIN IMMEDIATE")
            cursor = db.execute("UPDATE users SET status='pending' WHERE id=? AND status='approved'", (user_id,))
            if cursor.rowcount != 1:
                db.rollback()
                return jsonify({"error": "compte approuvé introuvable"}), 404
            # Nouvelle version des justificatifs : jetons d'API, tickets et liens émis avant la
            # suspension restent morts même après une réapprobation.
            account.invalidate_credentials(db, user_id)
            # Accès invités de ses adresses : une réapprobation ne les ressuscite pas.
            db.execute("UPDATE addresses SET guest_version=guest_version+1 WHERE domain_id IN "
                       "(SELECT id FROM domains WHERE user_id=?)", (user_id,))
            account.record_event(db, user_id, "account.suspend", actor="admin")
        # Routes et pairs du compte disparaissent de Caddy et de WireGuard à la synchronisation.
        synced = actions.project_runtime(app)
        return jsonify({"id": user_id, "status": "suspended", "synced": synced})

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
            policy, params = account.policy_sql()
            found = get_db().execute(
                "SELECT s.user_id FROM host_sessions s JOIN users u ON u.id=s.user_id "
                f"AND u.session_version=s.session_version AND {policy} "
                "WHERE s.token_hash=? AND s.hostname=? AND s.expires_at>?",
                (*params, _hash_token(token), hostname, int(time.time())),
            ).fetchone()
            if found and _authorized_protected_user(hostname, found["user_id"]):
                return "", 204
            if guest.session_allows(get_db(), token, hostname, route):
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
        policy, params = account.policy_sql()
        row = db.execute(
            "SELECT c.user_id,c.hostname,c.next_path,c.session_version FROM access_codes c "
            "JOIN users u ON u.id=c.user_id AND u.status='approved' AND u.session_version=c.session_version "
            f"AND {policy} WHERE c.code_hash=? AND c.hostname=? AND c.expires_at>?",
            (*params, _hash_token(code), hostname, int(time.time())),
        ).fetchone()
        if row is None:
            exchanged = guest.exchange_transfer_code(db, code, hostname)
            if exchanged is None:
                abort(403)
            token, next_path = exchanged
            response = redirect(next_path)
            response.set_cookie(ACCESS_COOKIE, token, secure=True, httponly=True, samesite="Lax", max_age=43200,
                                path="/")
            response.headers["Cache-Control"] = "no-store"
            return response
        if not _authorized_protected_user(hostname, row["user_id"]):
            abort(403)
        token = secrets.token_urlsafe(32)
        with db:
            deleted = db.execute("DELETE FROM access_codes WHERE code_hash=?", (_hash_token(code),))
            if deleted.rowcount != 1:
                abort(403)
            db.execute(
                "INSERT INTO host_sessions(token_hash,user_id,hostname,expires_at,session_version) "
                "VALUES(?,?,?,?,?)",
                (_hash_token(token), row["user_id"], hostname, int(time.time()) + 43200, row["session_version"]),
            )
        response = redirect(row["next_path"])
        response.set_cookie(ACCESS_COOKIE, token, secure=True, httponly=True, samesite="Lax", max_age=43200, path="/")
        response.headers["Cache-Control"] = "no-store"
        return response

    account.register(app, _redirect_after_login)
    guest.register(app)
    return app
