"""Comptes : double authentification, mot de passe oublié, récupération, vérification d'adresse.

Deux versions portées par chaque compte gouvernent tout ce qui est émis :
- `session_version` : une session, un accès d'adresse ou un code d'accès d'une version
  antérieure ne vaut plus rien ;
- `credential_version` : incrémentée à chaque changement de justificatif (mot de passe, 2FA,
  suspension). Jetons d'API, jetons de réinitialisation, tickets de récupération, challenges de
  connexion et enrôlements portent la version qui les a émis et meurent avec elle.

Chaque consommation (pas TOTP, code de secours, challenge, jeton) est une mise à jour
conditionnelle sous BEGIN IMMEDIATE : deux requêtes simultanées ne peuvent pas réussir toutes
les deux avec la même preuve.
"""

import time

from argon2 import PasswordHasher
from argon2.exceptions import VerificationError, VerifyMismatchError
from flask import (
    Flask,
    abort,
    current_app,
    flash,
    g,
    make_response,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from . import actions, security
from .db import get_db, now_iso

PASSWORDS = PasswordHasher()
MIN_PASSWORD = 12
CHALLENGE_TTL = 300
ENROLLMENT_TTL = 600
RESET_TTL = 1800
TICKET_TTL = 86400
VERIFY_TTL = 86400
MFA_USER_LIMIT = (5, 900)
MFA_IP_LIMIT = (30, 900)
SCOPES = ("password", "2fa", "both")
NOTICE_FOOTER = ("\n\nSi ce n'est pas toi, préviens tout de suite l'administrateur de l'instance.\n\n"
                 "Synunnel")
NOTICES = {
    "password.change": ("Ton mot de passe Synunnel a changé",
                        "Le mot de passe de ton compte Synunnel vient d'être changé."),
    "password.reset": ("Ton mot de passe Synunnel a été réinitialisé",
                       "Le mot de passe de ton compte Synunnel vient d'être réinitialisé."),
    "2fa.enable": ("Double authentification activée",
                   "La double authentification vient d'être activée sur ton compte Synunnel."),
    "2fa.disable": ("Double authentification désactivée",
                    "La double authentification vient d'être désactivée sur ton compte Synunnel."),
    "2fa.codes": ("Nouveaux codes de secours",
                  "De nouveaux codes de secours viennent d'être générés ; les anciens ne valent plus rien."),
    "recovery": ("Compte Synunnel récupéré",
                 "Un ticket de récupération remis par l'administrateur vient d'être utilisé sur ton compte."),
}


def _now() -> float:
    """Horloge des preuves à durée de vie (TOTP, challenges, jetons). Remplaçable en test."""
    return time.time()


def require_2fa(app: Flask | None = None) -> bool:
    return bool((app or current_app).config.get("REQUIRE_2FA"))


def satisfies_policy(user) -> bool:
    return not require_2fa() or bool(user["totp_enabled_at"])


def policy_sql() -> tuple[str, tuple]:
    """Fragment SQL (alias `u`) : la 2FA est exigée par l'instance et doit être active."""
    return "(? = 0 OR u.totp_enabled_at IS NOT NULL)", (int(require_2fa()),)


def mailer():
    return current_app.extensions["synunnel_mailer"]


def no_store(response):
    response = make_response(response)
    response.headers["Cache-Control"] = "no-store"
    return response


def verify_password(password_hash: str, password: str) -> bool:
    try:
        return bool(PASSWORDS.verify(password_hash, password or ""))
    except (VerifyMismatchError, VerificationError):
        return False


# ---------------------------------------------------------------- preuves

def reserve_mfa(user_id: int) -> tuple[int, int]:
    """Réserve atomiquement un essai de second facteur, pour le compte et pour l'adresse IP, AVANT le
    verrou d'écriture de la requête. Un échec garde sa réservation (il compte) ; un succès, ou une
    sortie sans vérification, la rend par `actions.release_attempts`."""
    user_slot = actions.reserve_attempt("mfa_user", str(user_id), *MFA_USER_LIMIT)
    ip_slot = actions.reserve_attempt("mfa_ip", actions.client_ip(), *MFA_IP_LIMIT) if user_slot else None
    if not user_slot or not ip_slot:
        actions.release_attempts(user_slot, ip_slot)
        abort(429, "Trop de tentatives. Réessaie plus tard.")
    return user_slot, ip_slot


def reserve_or_429(kind: str, key: str, limit: int, window: int) -> int:
    slot = actions.reserve_attempt(kind, key, limit, window)
    if slot is None:
        abort(429, "Trop de tentatives. Réessaie plus tard.")
    return slot


def consume_factor(db, user_id: int, code: str, credential_version: int) -> bool:
    """Code TOTP ou code de secours, consommé une seule fois. À appeler sous BEGIN IMMEDIATE."""
    value = (code or "").strip()
    row = db.execute(
        "SELECT totp_secret_enc FROM users WHERE id=? AND totp_enabled_at IS NOT NULL AND credential_version=?",
        (user_id, credential_version),
    ).fetchone()
    if row is None:
        return False
    if security.CODE_RE.fullmatch(value):
        try:
            secret = security.decrypt_secret(current_app.config["TOTP_KEY_BYTES"], user_id, row["totp_secret_enc"])
        except security.SecretUnavailable:
            return False
        step = security.matching_step(secret, value, _now())
        if step is None:
            return False
        # Le pas reconnu est retenu : ni ce code ni un code d'un pas antérieur ne repasseront.
        return db.execute(
            "UPDATE users SET totp_last_step=? WHERE id=? AND totp_last_step<? AND credential_version=?",
            (step, user_id, step, credential_version),
        ).rowcount == 1
    normalized = security.normalize_recovery(value)
    if normalized is None:
        return False
    return db.execute(
        "UPDATE recovery_codes SET used_at=? WHERE user_id=? AND code_hash=? AND used_at IS NULL",
        (int(_now()), user_id, security.digest(normalized)),
    ).rowcount == 1


def invalidate_credentials(db, user_id: int, revoke_tokens: bool = True) -> None:
    """Changement de justificatif : tout ce qui a été émis avant meurt. Sous BEGIN IMMEDIATE."""
    now = int(_now())
    db.execute("UPDATE users SET credential_version=credential_version+1, session_version=session_version+1 "
               "WHERE id=?", (user_id,))
    for table in ("host_sessions", "access_codes", "login_challenges", "totp_enrollments"):
        db.execute(f"DELETE FROM {table} WHERE user_id=?", (user_id,))
    db.execute("UPDATE password_resets SET used_at=? WHERE user_id=? AND used_at IS NULL", (now, user_id))
    db.execute("UPDATE email_verifications SET used_at=? WHERE user_id=? AND used_at IS NULL", (now, user_id))
    if revoke_tokens:
        db.execute("UPDATE api_tokens SET revoked_at=? WHERE user_id=? AND revoked_at IS NULL", (now_iso(), user_id))


def record_event(db, user_id: int | None, event: str, via: str = "", actor: str = "user") -> None:
    db.execute("INSERT INTO security_events(at,user_id,actor,event,via,ip) VALUES(?,?,?,?,?,?)",
                (now_iso(), user_id, actor, event, via, actions.client_ip() if request else ""))


def notify(user_id: int, event: str) -> None:
    subject, text = NOTICES[event]
    row = get_db().execute("SELECT email, email_verified_at FROM users WHERE id=?", (user_id,)).fetchone()
    if row is not None and row["email_verified_at"]:
        mailer().enqueue(row["email"], subject, text + NOTICE_FOOTER)


def locked_user(db, user_id: int, session_version: int | None = None, credential_version: int | None = None):
    row = db.execute("SELECT * FROM users WHERE id=? AND status='approved'", (user_id,)).fetchone()
    if row is None:
        return None
    if session_version is not None and row["session_version"] != session_version:
        return None
    if credential_version is not None and row["credential_version"] != credential_version:
        return None
    return row


def open_session(user_id: int, session_version: int, mfa: bool) -> None:
    """La version vient de la preuve vérifiée (mot de passe lu, challenge consommé sous verrou), jamais
    d'une relecture après commit : une révocation concurrente rend alors ce cookie périmé."""
    session.clear()
    session["user_id"] = user_id
    session["sv"] = session_version
    session["auth_at"] = int(time.time())
    session["csrf"] = security.new_token()
    session["mfa"] = 1 if mfa else 0
    session.permanent = True


def version_after_change(db, user_id: int) -> int:
    """Version de session produite par le changement en cours, lue sous son verrou, avant le commit."""
    return db.execute("SELECT session_version FROM users WHERE id=?", (user_id,)).fetchone()[0]


def refresh_session(session_version: int, mfa: bool) -> None:
    """Session courante reconduite avec la version que ce changement a produite (lue avant commit)."""
    session["sv"] = session_version
    session["mfa"] = 1 if mfa else 0
    session["csrf"] = security.new_token()


def begin_second_step(user, next_url: str):
    """Mot de passe correct, 2FA active : un challenge côté serveur, rien d'authentifié."""
    value = security.new_token()
    db = get_db()
    with db:
        db.execute("BEGIN IMMEDIATE")
        db.execute(
            "INSERT INTO login_challenges(challenge_hash,user_id,session_version,credential_version,next_url,"
            "expires_at) VALUES(?,?,?,?,?,?)",
            (security.digest(value), user["id"], user["session_version"], user["credential_version"],
             (next_url or "")[:2000], int(_now()) + CHALLENGE_TTL),
        )
    session.clear()
    session["challenge"] = value
    session["csrf"] = security.new_token()
    return redirect(url_for("login_2fa"))


def issue_ticket(user_id: int, email: str, scope: str) -> dict | None:
    """Ticket de récupération remis par l'administrateur. Rien n'est retiré à l'émission."""
    value = security.new_token()
    now = int(_now())
    db = get_db()
    with db:
        db.execute("BEGIN IMMEDIATE")
        user = db.execute("SELECT id, credential_version FROM users WHERE id=? AND email=? AND status='approved'",
                          (user_id, email)).fetchone()
        if user is None:
            db.rollback()
            return None
        db.execute("UPDATE password_resets SET used_at=? WHERE user_id=? AND kind='admin' AND used_at IS NULL",
                   (now, user_id))
        db.execute(
            "INSERT INTO password_resets(token_hash,user_id,kind,scope,credential_version,created_at,expires_at) "
            "VALUES(?,?,?,?,?,?,?)",
            (security.digest(value), user_id, "admin", scope, user["credential_version"], now, now + TICKET_TTL),
        )
        record_event(db, user_id, "recovery.issue", via=scope, actor="admin")
    return {"ticket": value, "expires_at": now + TICKET_TTL}


# ---------------------------------------------------------------- routes

def register(app: Flask, redirect_after_login) -> None:
    def current():
        return g.get("user") or g.get("enrolling")

    def reauth(user_id: int, password: str):
        slot = reserve_or_429("reauth", str(user_id), 10, 900)
        row = get_db().execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
        if row is None or not verify_password(row["password_hash"], password):
            flash("Mot de passe incorrect.", "error")
            return None
        actions.release_attempts(slot)
        return row

    def enroll_page(user, secret: bytes, enrollment: str, status: int = 200):
        uri = security.otpauth_uri(secret, user["email"], "Synunnel")
        b32 = security.secret_base32(secret)
        grouped = " ".join(b32[i:i + 4] for i in range(0, len(b32), 4))
        return no_store((render_template("totp_enroll.html", qr=security.qr_svg(uri), secret=grouped,
                                         enrollment=enrollment), status))

    def codes_page(codes: list[str]):
        return no_store(render_template("recovery_codes.html", codes=[security.format_recovery(c) for c in codes]))

    def store_codes(db, user_id: int) -> list[str]:
        codes = security.new_recovery_codes()
        db.execute("DELETE FROM recovery_codes WHERE user_id=?", (user_id,))
        db.executemany("INSERT INTO recovery_codes(user_id,code_hash) VALUES(?,?)",
                       [(user_id, security.digest(code)) for code in codes])
        return codes

    @app.get("/security")
    def security_page():
        user = current()
        if user is None:
            return redirect(url_for("login"))
        remaining = get_db().execute("SELECT COUNT(*) FROM recovery_codes WHERE user_id=? AND used_at IS NULL",
                                     (user["id"],)).fetchone()[0]
        return no_store(render_template("security.html", account=user, enrolling=g.get("user") is None,
                                        remaining=remaining, mail_enabled=mailer().enabled))

    @app.post("/security/2fa/start")
    def totp_start():
        user = current()
        if user is None:
            return redirect(url_for("login"))
        row = reauth(user["id"], request.form.get("password", ""))
        if row is None:
            return redirect(url_for("security_page"))
        if row["totp_enabled_at"]:
            flash("La double authentification est déjà active.", "error")
            return redirect(url_for("security_page"))
        enrollment, secret = security.new_token(), security.new_secret()
        db = get_db()
        with db:
            db.execute("BEGIN IMMEDIATE")
            if locked_user(db, row["id"], session.get("sv", -1), row["credential_version"]) is None:
                db.rollback()
                abort(401)
            # Un seul enrôlement en cours par compte : un second onglet remplace le premier.
            db.execute(
                "INSERT OR REPLACE INTO totp_enrollments(user_id,enrollment_hash,secret_enc,credential_version,"
                "session_version,expires_at) VALUES(?,?,?,?,?,?)",
                (row["id"], security.digest(enrollment),
                 security.encrypt_secret(app.config["TOTP_KEY_BYTES"], row["id"], secret),
                 row["credential_version"], row["session_version"], int(_now()) + ENROLLMENT_TTL),
            )
        return enroll_page(row, secret, enrollment)

    @app.post("/security/2fa/confirm")
    def totp_confirm():
        user = current()
        if user is None:
            return redirect(url_for("login"))
        uid = user["id"]
        enrollment = request.form.get("enrollment", "")
        slots = reserve_mfa(uid)
        db = get_db()
        with db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT e.secret_enc FROM totp_enrollments e JOIN users u ON u.id=e.user_id "
                "AND u.status='approved' AND u.credential_version=e.credential_version "
                "AND u.session_version=e.session_version AND u.totp_enabled_at IS NULL "
                "WHERE e.user_id=? AND e.enrollment_hash=? AND e.expires_at>? AND u.session_version=?",
                (uid, security.digest(enrollment), int(_now()), session.get("sv", -1)),
            ).fetchone()
            secret = None
            if row is not None:
                try:
                    secret = security.decrypt_secret(app.config["TOTP_KEY_BYTES"], uid, row["secret_enc"])
                except security.SecretUnavailable:
                    secret = None
            if secret is None:
                db.rollback()
                actions.release_attempts(*slots)
                flash("Activation expirée ou remplacée par une autre : recommence.", "error")
                return redirect(url_for("security_page"))
            step = security.matching_step(secret, request.form.get("code", "").strip(), _now())
            if step is None:
                db.rollback()
                flash("Code incorrect : vérifie l'heure de ton téléphone et réessaie.", "error")
                return enroll_page(user, secret, enrollment, 401)
            invalidate_credentials(db, uid)
            db.execute("UPDATE users SET totp_secret_enc=?, totp_enabled_at=?, totp_last_step=? WHERE id=?",
                       (row["secret_enc"], now_iso(), step, uid))
            codes = store_codes(db, uid)
            record_event(db, uid, "2fa.enable")
            new_version = version_after_change(db, uid)
        actions.release_attempts(*slots)
        refresh_session(new_version, mfa=True)
        notify(uid, "2fa.enable")
        return codes_page(codes)

    def factor_action(event: str, change):
        """Mot de passe redemandé, puis, dans UNE transaction : compte recontrôlé, code consommé,
        changement appliqué. `change(db, row)` renvoie le résultat de l'opération."""
        user = g.get("user")
        if user is None:
            return None, redirect(url_for("login"))
        row = reauth(user["id"], request.form.get("password", ""))
        if row is None or not row["totp_enabled_at"]:
            return None, redirect(url_for("security_page"))
        slots = reserve_mfa(row["id"])
        db = get_db()
        with db:
            db.execute("BEGIN IMMEDIATE")
            if locked_user(db, row["id"], session.get("sv", -1), row["credential_version"]) is None:
                db.rollback()
                actions.release_attempts(*slots)
                abort(401)
            if not consume_factor(db, row["id"], request.form.get("code", ""), row["credential_version"]):
                db.rollback()
                flash("Code de double authentification incorrect.", "error")
                return None, redirect(url_for("security_page"))
            record_event(db, row["id"], event)
            result = change(db, row)
        actions.release_attempts(*slots)
        return result, None

    @app.post("/security/2fa/disable")
    def totp_disable():
        def disable(db, row):
            invalidate_credentials(db, row["id"])
            db.execute("UPDATE users SET totp_secret_enc=NULL, totp_enabled_at=NULL, totp_last_step=0 WHERE id=?",
                       (row["id"],))
            db.execute("DELETE FROM recovery_codes WHERE user_id=?", (row["id"],))
            return row["id"], version_after_change(db, row["id"])

        result, refused = factor_action("2fa.disable", disable)
        if refused is not None:
            return refused
        uid, new_version = result
        refresh_session(new_version, mfa=False)
        notify(uid, "2fa.disable")
        flash("Double authentification désactivée. Tes autres sessions et tes jetons d'API sont coupés.", "success")
        return redirect(url_for("security_page"))

    @app.post("/security/recovery-codes")
    def recovery_codes():
        result, refused = factor_action("2fa.codes", lambda db, row: (row["id"], store_codes(db, row["id"])))
        if refused is not None:
            return refused
        uid, codes = result
        notify(uid, "2fa.codes")
        return codes_page(codes)

    @app.post("/security/password")
    def change_password():
        user = g.get("user")
        if user is None:
            return redirect(url_for("login"))
        new_password = request.form.get("new_password", "")
        if len(new_password) < MIN_PASSWORD:
            flash(f"Le nouveau mot de passe doit faire au moins {MIN_PASSWORD} caractères.", "error")
            return redirect(url_for("security_page"))
        row = reauth(user["id"], request.form.get("password", ""))
        if row is None:
            return redirect(url_for("security_page"))
        with_factor = bool(row["totp_enabled_at"])
        new_hash = PASSWORDS.hash(new_password)
        slots = reserve_mfa(row["id"]) if with_factor else ()
        db = get_db()
        with db:
            db.execute("BEGIN IMMEDIATE")
            if locked_user(db, row["id"], session.get("sv", -1), row["credential_version"]) is None:
                db.rollback()
                actions.release_attempts(*slots)
                abort(401)
            if with_factor and not consume_factor(db, row["id"], request.form.get("code", ""),
                                                  row["credential_version"]):
                db.rollback()
                flash("Code de double authentification incorrect.", "error")
                return redirect(url_for("security_page"))
            invalidate_credentials(db, row["id"])
            db.execute("UPDATE users SET password_hash=? WHERE id=?", (new_hash, row["id"]))
            record_event(db, row["id"], "password.change")
            new_version = version_after_change(db, row["id"])
        actions.release_attempts(*slots)
        refresh_session(new_version, mfa=with_factor)
        notify(row["id"], "password.change")
        flash("Mot de passe changé. Tes autres sessions et tes jetons d'API sont coupés.", "success")
        return redirect(url_for("security_page"))

    @app.post("/security/email")
    def email_verify_request():
        user = g.get("user")
        if user is None:
            return redirect(url_for("login"))
        if not mailer().enabled:
            flash("L'envoi de mails n'est pas configuré sur cette instance : demande à l'administrateur "
                  "de vérifier ton adresse.", "error")
            return redirect(url_for("security_page"))
        row = reauth(user["id"], request.form.get("password", ""))
        if row is None:
            return redirect(url_for("security_page"))
        reserve_or_429("email_verify", str(row["id"]), 3, 3600)
        value = security.new_token()
        now = int(_now())
        db = get_db()
        with db:
            db.execute("BEGIN IMMEDIATE")
            if locked_user(db, row["id"], session.get("sv", -1), row["credential_version"]) is None:
                db.rollback()
                abort(401)
            db.execute("UPDATE email_verifications SET used_at=? WHERE user_id=? AND used_at IS NULL", (now, row["id"]))
            db.execute("INSERT INTO email_verifications(token_hash,user_id,email,credential_version,expires_at) "
                       "VALUES(?,?,?,?,?)",
                       (security.digest(value), row["id"], row["email"], row["credential_version"], now + VERIFY_TTL))
        link = f"https://{app.config['DASHBOARD_HOST']}/security/email/confirm?token={value}"
        mailer().enqueue(row["email"], "Vérifie ton adresse Synunnel",
                         "Pour confirmer que cette boîte est bien la tienne et pouvoir récupérer ton compte "
                         f"par mail, ouvre ce lien (valable 24 heures) puis valide :\n\n{link}" + NOTICE_FOOTER)
        flash(f"Un lien de vérification vient de partir vers {row['email']}.", "success")
        return redirect(url_for("security_page"))

    @app.route("/security/email/confirm", methods=["GET", "POST"])
    def email_verify_confirm():
        if request.method != "POST":
            return no_store(render_template("email_confirm.html", token=request.args.get("token", "")[:200]))
        slot = reserve_or_429("verify_ip", actions.client_ip(), 10, 900)
        value = request.form.get("token", "")
        now = int(_now())
        db = get_db()
        with db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT v.user_id FROM email_verifications v JOIN users u ON u.id=v.user_id AND u.status='approved' "
                "AND u.credential_version=v.credential_version AND u.email=v.email "
                "WHERE v.token_hash=? AND v.used_at IS NULL AND v.expires_at>?",
                (security.digest(value), now),
            ).fetchone()
            if row is not None:
                db.execute("UPDATE email_verifications SET used_at=? WHERE token_hash=?", (now, security.digest(value)))
                db.execute("UPDATE users SET email_verified_at=COALESCE(email_verified_at, ?) WHERE id=?",
                           (now_iso(), row["user_id"]))
                record_event(db, row["user_id"], "email.verify", via="email")
        if row is None:
            flash("Lien invalide ou expiré.", "error")
            return no_store((render_template("email_confirm.html", token=""), 400))
        actions.release_attempts(slot)
        flash("Adresse vérifiée : elle pourra servir à récupérer ton compte.", "success")
        return redirect(url_for("security_page" if g.get("user") else "login"))

    @app.route("/forgot", methods=["GET", "POST"])
    def forgot():
        if request.method != "POST":
            return no_store(render_template("forgot.html", mail_enabled=mailer().enabled))
        reserve_or_429("forgot_ip", actions.client_ip(), 5, 3600)
        email = request.form.get("email", "").strip().lower()[:254]
        # Mêmes étapes et même réponse, qu'un compte existe ou non ; l'envoi part dans une file.
        if actions.EMAIL_RE.fullmatch(email):
            allowed = actions.reserve_attempt("forgot_email", email, 3, 3600) is not None
            if allowed and mailer().enabled:
                value = security.new_token()
                now = int(_now())
                db = get_db()
                with db:
                    db.execute("BEGIN IMMEDIATE")
                    user = db.execute(
                        "SELECT id, credential_version FROM users WHERE email=? AND status='approved' "
                        "AND email_verified_at IS NOT NULL", (email,),
                    ).fetchone()
                    if user is not None:
                        db.execute("UPDATE password_resets SET used_at=? WHERE user_id=? AND kind='email' "
                                   "AND used_at IS NULL", (now, user["id"]))
                        db.execute(
                            "INSERT INTO password_resets(token_hash,user_id,kind,scope,credential_version,"
                            "created_at,expires_at) VALUES(?,?,?,?,?,?,?)",
                            (security.digest(value), user["id"], "email", "password", user["credential_version"],
                             now, now + RESET_TTL),
                        )
                if user is not None:
                    link = f"https://{app.config['DASHBOARD_HOST']}/reset?token={value}"
                    mailer().enqueue(email, "Réinitialiser ton mot de passe Synunnel",
                                     "Une réinitialisation du mot de passe de ton compte Synunnel a été demandée. "
                                     f"Ce lien est valable 30 minutes et ne sert qu'une fois :\n\n{link}\n\n"
                                     "Ta double authentification, si elle est active, restera exigée."
                                     + NOTICE_FOOTER)
        flash("Si un compte avec une adresse vérifiée correspond, un lien vient de partir. "
              "Il est valable 30 minutes.", "success")
        return redirect(url_for("login"))

    def refuse(template: str, message: str = "Lien, code ou adresse invalide, ou déjà utilisé, ou expiré."):
        flash(message, "error")
        return no_store((render_template(template, token=""), 400))

    @app.route("/reset", methods=["GET", "POST"])
    def reset_password():
        if request.method != "POST":
            return no_store(render_template("reset.html", token=request.args.get("token", "")[:200]))
        slot = reserve_or_429("reset_ip", actions.client_ip(), 10, 900)
        value = request.form.get("token", "")
        email = request.form.get("email", "").strip().lower()[:254]
        password = request.form.get("password", "")
        if len(password) < MIN_PASSWORD:
            return refuse("reset.html", f"Le nouveau mot de passe doit faire au moins {MIN_PASSWORD} caractères.")
        return consume_ticket("email", value, email, slot, new_password=password)

    @app.route("/recover", methods=["GET", "POST"])
    def recover():
        if request.method != "POST":
            return no_store(render_template("recover.html", token=""))
        slot = reserve_or_429("recover_ip", actions.client_ip(), 10, 900)
        return consume_ticket("admin", request.form.get("ticket", "").strip(),
                              request.form.get("email", "").strip().lower()[:254], slot,
                              new_password=request.form.get("new_password", ""),
                              current_password=request.form.get("password", ""))

    def consume_ticket(kind: str, value: str, email: str, slot: int, new_password: str = "",
                       current_password: str = ""):
        """Un refus garde la réservation d'essai (il compte) ; un succès la rend."""
        template = "reset.html" if kind == "email" else "recover.html"
        now = int(_now())
        db = get_db()
        # Le jeton est vérifié avant tout calcul Argon2.
        row = db.execute(
            "SELECT r.user_id, r.scope, r.credential_version, u.password_hash FROM password_resets r "
            "JOIN users u ON u.id=r.user_id AND u.status='approved' AND u.credential_version=r.credential_version "
            "WHERE r.token_hash=? AND r.kind=? AND r.used_at IS NULL AND r.expires_at>? AND u.email=?",
            (security.digest(value), kind, now, email),
        ).fetchone()
        scope = row["scope"] if row is not None else ""
        new_hash = None
        if row is not None and scope in ("password", "both"):
            if len(new_password) < MIN_PASSWORD:
                return refuse(template, f"Le nouveau mot de passe doit faire au moins {MIN_PASSWORD} caractères.")
            new_hash = PASSWORDS.hash(new_password)
        if row is None or (scope == "2fa" and not verify_password(row["password_hash"], current_password)):
            return refuse(template)
        uid = row["user_id"]
        with db:
            db.execute("BEGIN IMMEDIATE")
            consumed = db.execute(
                "UPDATE password_resets SET used_at=? WHERE token_hash=? AND used_at IS NULL AND expires_at>?",
                (now, security.digest(value), now),
            ).rowcount
            if consumed != 1 or locked_user(db, uid, credential_version=row["credential_version"]) is None:
                db.rollback()
                return refuse(template)
            invalidate_credentials(db, uid)
            if new_hash is not None:
                db.execute("UPDATE users SET password_hash=? WHERE id=?", (new_hash, uid))
            if scope in ("2fa", "both"):
                db.execute("UPDATE users SET totp_secret_enc=NULL, totp_enabled_at=NULL, totp_last_step=0 "
                           "WHERE id=?", (uid,))
                db.execute("DELETE FROM recovery_codes WHERE user_id=?", (uid,))
            record_event(db, uid, "password.reset" if kind == "email" else f"recovery.{scope}", via=kind)
        actions.release_attempts(slot)
        session.clear()
        notify(uid, "password.reset" if kind == "email" else "recovery")
        flash("C'est fait : connecte-toi." + (" La double authentification reste exigée."
                                              if kind == "email" else ""), "success")
        return redirect(url_for("login"))

    @app.route("/login/2fa", methods=["GET", "POST"])
    def login_2fa():
        value = session.get("challenge")
        if not value:
            return redirect(url_for("login"))
        if request.method != "POST":
            return no_store(render_template("login_2fa.html"))
        now = int(_now())
        db = get_db()
        row = db.execute(
            "SELECT c.user_id, c.next_url, c.session_version, c.credential_version FROM login_challenges c "
            "JOIN users u ON u.id=c.user_id AND u.status='approved' AND u.session_version=c.session_version "
            "AND u.credential_version=c.credential_version AND u.totp_enabled_at IS NOT NULL "
            "WHERE c.challenge_hash=? AND c.used_at IS NULL AND c.expires_at>?",
            (security.digest(value), now),
        ).fetchone()

        def expired():
            session.pop("challenge", None)
            flash("La connexion a expiré : recommence.", "error")
            return redirect(url_for("login"))

        if row is None:
            return expired()
        uid = row["user_id"]
        slots = reserve_mfa(uid)
        with db:
            db.execute("BEGIN IMMEDIATE")
            used = db.execute(
                "UPDATE login_challenges SET used_at=? WHERE challenge_hash=? AND used_at IS NULL AND expires_at>?",
                (now, security.digest(value), now),
            ).rowcount
            if used != 1 or locked_user(db, uid, row["session_version"], row["credential_version"]) is None:
                db.rollback()
                actions.release_attempts(*slots)
                return expired()
            if not consume_factor(db, uid, request.form.get("code", ""), row["credential_version"]):
                db.rollback()
                flash("Code incorrect.", "error")
                return no_store((render_template("login_2fa.html"), 401))
        actions.release_attempts(*slots)
        # Version du challenge, vérifiée sous le verrou : jamais une relecture postérieure au commit.
        open_session(uid, row["session_version"], mfa=True)
        return redirect_after_login(row["next_url"], uid)

