#!/usr/bin/env python3
"""Essai intégré éphémère, à lancer UNIQUEMENT sur une machine jetable.

Crée un pair WireGuard dans un espace réseau local et une zone .test,
sert une page par Caddy avec sa CA interne, puis remet la configuration.
Pendant l'essai, le Caddyfile, la base, PowerDNS et WireGuard réels sont modifiés :
ne jamais le lancer sur une instance qui sert de vrais utilisateurs.
"""

import base64
import email
import hashlib
import importlib.metadata
import importlib.util
import json
import os
import re
import secrets
import socket
import sqlite3
import ssl
import subprocess
import tempfile
import threading
import time
from pathlib import Path
from urllib.parse import quote

from argon2 import PasswordHasher

from synunnel import security
from synunnel.dns import PowerDNS

DOMAIN = "e2e.synunnel.test"
HOST = f"nas.{DOMAIN}"
PROTECTED = f"prive.{DOMAIN}"
UNKNOWN = f"inconnu.{DOMAIN}"
# Domaine sans zone ni adresse, pour le refus de suppression : la zone parente (.test) n'existe pas, la
# délégation ne se vérifie donc pas et la suppression doit être refusée (409), rien n'étant retiré.
SPARE = "e2e-suppr.synunnel.test"
EMAIL = "e2e@synunnel.invalid"
NS = "sn-e2e"
VETH_HOST = "sn-e2e-host"
VETH_PEER = "sn-e2e-peer"
PAGE = "SYNUNNEL_E2E_WIREGUARD_OK"
CONFIG = Path("/etc/caddy/Caddyfile")
GUEST_EMAIL = "invite-e2e@synunnel.invalid"
SMTP_NAME = "smtp-e2e.synunnel.test"
SMTP_ENV = Path("/run/synunnel-e2e.env")
SMTP_PASSWORD = Path("/run/synunnel-e2e-smtp-password")
DROPIN = Path("/run/systemd/system/synunnel.service.d/zz-e2e.conf")
HOSTS = Path("/etc/hosts")
# Service de la machine : sert la page, et « /cookie » renvoie l'en-tête Cookie reçu, pour vérifier que
# le cookie d'accès Synunnel n'y arrive jamais.
BACKEND = """
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
PAGE = sys.argv[1]
class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/":
            body = (PAGE + "\\n").encode()
        elif self.path == "/cookie":
            body = ("COOKIE=[" + str(self.headers.get("Cookie")) + "]").encode()
        else:
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *args):
        pass
HTTPServer(("10.88.0.2", 18080), Handler).serve_forever()
"""


def serve_smtp(context: ssl.SSLContext, inbox: list[str], stop: threading.Event) -> None:
    """Boîte SMTPS simulée : accepte tout, garde les messages en mémoire."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", 465))
    server.listen(5)
    server.settimeout(0.5)
    while not stop.is_set():
        try:
            conn, _ = server.accept()
        except TimeoutError:
            continue
        try:
            with context.wrap_socket(conn, server_side=True) as tls:
                stream = tls.makefile("rwb")

                def say(line: str, stream=stream) -> None:
                    stream.write(line.encode() + b"\r\n")
                    stream.flush()

                say("220 e2e ESMTP")
                lines: list[str] | None = None
                while raw := stream.readline():
                    line = raw.decode(errors="replace").rstrip("\r\n")
                    if lines is not None:
                        if line == ".":
                            inbox.append("\n".join(lines))
                            lines = None
                            say("250 OK")
                        else:
                            lines.append(line[1:] if line.startswith("..") else line)
                        continue
                    verb = line[:4].upper()
                    if verb == "EHLO":
                        say("250-e2e")
                        say("250 AUTH PLAIN LOGIN")
                    elif verb == "AUTH":
                        say("235 OK")
                    elif verb == "DATA":
                        lines = []
                        say("354 go")
                    elif verb == "QUIT":
                        say("221 bye")
                        break
                    else:
                        say("250 OK")
        except (OSError, ssl.SSLError):
            continue
    server.close()


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
    if os.environ.get("SYNUNNEL_E2E_DISPOSABLE") != "1":
        raise SystemExit("Essai réservé à une machine jetable : relance avec SYNUNNEL_E2E_DISPOSABLE=1.")
    values = env_file()
    # L'essai tourne avec l'environnement installé : il doit être celui du verrou, sans outils de développement.
    if importlib.util.find_spec("pytest") or importlib.util.find_spec("ruff"):
        raise AssertionError("L'environnement installé contient des outils de développement.")
    crypto = tuple(int(part) for part in importlib.metadata.version("cryptography").split(".")[:3])
    if crypto < (50, 0, 1):
        raise AssertionError(f"cryptography {crypto} installée, 50.0.1 au moins attendue.")
    print("Environnement installé depuis le verrou, sans outils de développement, cryptography à jour : OK")
    db = sqlite3.connect(values["DATABASE"], timeout=10)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys=ON")
    if db.execute("SELECT 1 FROM domains WHERE name=?", (DOMAIN,)).fetchone():
        raise SystemExit("La zone de test existe déjà ; aucune donnée n'a été touchée.")
    if db.execute("SELECT 1 FROM domains WHERE name=?", (SPARE,)).fetchone():
        raise SystemExit("Le domaine de test existe déjà ; aucune donnée n'a été touchée.")
    if db.execute("SELECT 1 FROM users WHERE email=?", (EMAIL,)).fetchone():
        raise SystemExit("Le compte de test existe déjà ; aucune donnée n'a été touchée.")
    if NS in run("ip", "netns", "list").stdout:
        raise SystemExit("L'espace réseau de test existe déjà ; aucune donnée n'a été touchée.")

    pdns = PowerDNS(values["PDNS_API_URL"], values["PDNS_API_KEY"], (
        f"{values['NS1_HOST']}.", f"{values['NS2_HOST']}.",
    ))
    original_caddy = CONFIG.read_text()
    private = run("wg", "genkey").stdout.strip()
    public = run("wg", "pubkey", input=private + "\n").stdout.strip()
    password = secrets.token_urlsafe(24)
    # La page servie et la clé privée vivent dans deux répertoires distincts :
    # le serveur HTTP de l'essai ne voit que le premier.
    web_dir = Path(tempfile.mkdtemp(prefix="synunnel-e2e-web-", dir="/run"))
    web_dir.chmod(0o755)
    page_file = web_dir / "index.html"
    page_file.write_text(PAGE + "\n")
    page_file.chmod(0o644)
    key_dir = Path(tempfile.mkdtemp(prefix="synunnel-e2e-key-", dir="/run"))
    private_file = key_dir / "client.key"
    private_file.write_text(private + "\n")
    private_file.chmod(0o600)
    http_server = None
    inbox: list[str] = []
    smtp_stop = threading.Event()
    smtp_dirs: list[Path] = []
    hosts_original: list[str] = []
    zone_created = False
    netns_created = False
    caddy_changed = False
    completed = False
    try:
        pdns.create_zone(DOMAIN)
        zone_created = True
        with db:
            user_id = db.execute(
                "INSERT INTO users(email,password_hash,status,created_at) VALUES(?,?,'approved',?)",
                (EMAIL, PasswordHasher().hash(password), "2026-09-27T00:00:00Z"),
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
                "INSERT INTO addresses(domain_id,machine_id,hostname,port,protected,created_at,route_token) "
                "VALUES(?,?,?,?,0,?,?)",
                (domain_id, machine_id, HOST, 18080, "2026-09-27T00:00:00Z", secrets.token_hex(12)),
            )
            db.execute(
                "INSERT INTO addresses(domain_id,machine_id,hostname,port,protected,created_at,route_token) "
                "VALUES(?,?,?,?,1,?,?)",
                (domain_id, machine_id, PROTECTED, 18080, "2026-09-27T00:00:00Z", secrets.token_hex(12)),
            )
            api_token = "syn_" + secrets.token_urlsafe(32)
            db.execute(
                "INSERT INTO api_tokens(user_id,name,token_hash,prefix,scopes,created_at,expires_at) "
                "VALUES(?,?,?,?,?,?,?)",
                (user_id, "e2e", hashlib.sha256(api_token.encode()).hexdigest(), api_token[:10],
                 "addresses,domains,machines,sharing", "2026-09-27T00:00:00Z", int(time.time()) + 3600),
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
            ["ip", "netns", "exec", NS, "setpriv", "--reuid=nobody", "--regid=nogroup", "--clear-groups",
             "python3", "-c", BACKEND, PAGE],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, cwd=str(web_dir),
        )
        # Un paquet sortant apprend à wg0 l'endpoint du pair local.
        run("ip", "netns", "exec", NS, "ping", "-c", "1", "-W", "2", "10.88.0.1", check=False)
        time.sleep(1)

        test_caddy = original_caddy.replace("\n    email ", "\n    local_certs\n    email ", 1)
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
        leaked = run(*command, "--output", "/dev/null", "--write-out", "%{http_code}",
                     f"https://{HOST}/client.key", check=False).stdout.strip()
        if leaked == "200":
            raise AssertionError("La clé privée de l'essai est accessible par HTTP.")
        print("Clé privée de l'essai hors de portée du serveur HTTP : OK")

        # Le pair ne doit joindre aucun service du VPS par le tunnel (Caddy écoute sur toutes les interfaces).
        inbound = run("ip", "netns", "exec", NS, "curl", "--noproxy", "*", "--silent", "--max-time", "4",
                      "http://10.88.0.1/", check=False)
        if inbound.returncode == 0:
            raise AssertionError("Le pair a ouvert une connexion vers le VPS par le tunnel.")
        print("Connexion du pair vers le VPS bloquée par le pare-feu du tunnel : OK")

        dashboard_host = values["DASHBOARD_HOST"]
        dashboard = run(
            "curl", "--noproxy", "*", "--silent", "--show-error", "--insecure", "--max-time", "8",
            "--resolve", f"{dashboard_host}:443:{values['PUBLIC_IPV4']}",
            f"https://{dashboard_host}/login",
        ).stdout
        if "Synunnel" not in dashboard:
            raise AssertionError("Le tableau de bord configuré ne répond pas.")
        print(f"Tableau de bord HTTPS sur {dashboard_host} via --resolve : OK")
        for alias in [host for host in values.get("REDIRECT_HOSTS", "").split(",") if host]:
            redirected = run(
                "curl", "--noproxy", "*", "--silent", "--show-error", "--insecure", "--max-time", "8",
                "--resolve", f"{alias}:443:{values['PUBLIC_IPV4']}",
                "--dump-header", "-", "--output", "/dev/null", f"https://{alias}/essai",
            ).stdout.lower()
            if " 308 " not in redirected or f"location: https://{dashboard_host}/essai" not in redirected:
                raise AssertionError(f"Redirection absente pour {alias}.")
        print("Redirections des noms secondaires en HTTPS via --resolve : OK")

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

        base = ["curl", "--noproxy", "*", "--silent", "--show-error", "--insecure", "--max-time", "8"]
        me = run(*base, "--resolve", f"{dashboard_host}:443:{values['PUBLIC_IPV4']}",
                 "--header", f"Authorization: Bearer {api_token}", f"https://{dashboard_host}/api/v1/me").stdout
        if json.loads(me).get("email") != EMAIL:
            raise AssertionError(f"L'API ne répond pas au jeton de l'essai : {me[:200]!r}")
        print("API pour agents par HTTPS sur le tableau de bord : OK")
        leak = run(*base, "--resolve", f"{HOST}:443:{values['PUBLIC_IPV4']}", "--output", "/dev/null",
                   "--write-out", "%{http_code}", "--header", f"Authorization: Bearer {api_token}",
                   f"https://{HOST}/", check=False).stdout.strip()
        if leak != "421":
            raise AssertionError(f"Une adresse publiée a accepté un jeton Synunnel (statut {leak}).")
        shouted = run(*base, "--resolve", f"{HOST}:443:{values['PUBLIC_IPV4']}", "--output", "/dev/null",
                      "--write-out", "%{http_code}", "--header", f"Authorization: BEARER {api_token}",
                      f"https://{HOST}/", check=False).stdout.strip()
        if shouted != "421":
            raise AssertionError(f"Le filtre des jetons dépend de la casse (statut {shouted}).")
        # Un espace insécable (octet 0xA0) entre le schéma et le jeton ne doit pas faire passer le jeton.
        spaced = subprocess.run(
            [*base, "--resolve", f"{HOST}:443:{values['PUBLIC_IPV4']}", "--output", "/dev/null",
             "--write-out", "%{http_code}", "--header", b"Authorization: Bearer \xa0" + api_token.encode(),
             f"https://{HOST}/"], capture_output=True, timeout=15, check=False,
        ).stdout.decode().strip()
        if spaced != "421":
            raise AssertionError(f"Le filtre des jetons laisse passer un espace insécable (statut {spaced}).")
        print("Jeton Synunnel refusé par une adresse publiée, jamais transmis au service : OK")

        # Double authentification par HTTPS : enrôlement, connexion en deux temps, ticket de l'administrateur.
        jar, page_out = key_dir / "cookies.txt", key_dir / "page.html"
        resolve = f"{dashboard_host}:443:{values['PUBLIC_IPV4']}"

        def web(path: str, data: dict | None = None) -> tuple[int, str, str]:
            args = [*base, "--resolve", resolve, "-c", str(jar), "-b", str(jar), "--output", str(page_out),
                    "--write-out", "%{http_code} %{redirect_url}"]
            for field, value in (data or {}).items():
                args += ["--data-urlencode", f"{field}={value}"]
            status, _, location = run(*args, f"https://{dashboard_host}{path}", check=False).stdout.partition(" ")
            return int(status or 0), location, page_out.read_text() if page_out.exists() else ""

        def csrf_of(html: str) -> str:
            return re.search(r'name="csrf_token" value="([^"]+)"', html).group(1)

        def totp(b32: str, offset: int = 0) -> str:
            secret = base64.b32decode(b32 + "=" * (-len(b32) % 8))
            return security.code_at(secret, security.current_step(time.time()) + offset)

        def sign_in() -> tuple[int, str]:
            _, _, html = web("/login")
            status, location, _ = web("/login", {"csrf_token": csrf_of(html), "email": EMAIL, "password": password})
            return status, location

        if sign_in()[0] != 302:
            raise AssertionError("Connexion par mot de passe refusée.")
        _, _, html = web("/security")
        status, _, html = web("/security/2fa/start", {"csrf_token": csrf_of(html), "password": password})
        secret_b32 = re.search(r'id="totp-secret">([A-Z2-7 ]+)<', html).group(1).replace(" ", "")
        enrollment = re.search(r'name="enrollment" value="([^"]+)"', html).group(1)
        status, _, html = web("/security/2fa/confirm", {"csrf_token": csrf_of(html), "enrollment": enrollment,
                                                        "code": totp(secret_b32)})
        if status != 200 or len(re.findall(r'class="recovery-code"', html)) != 10:
            raise AssertionError(f"Activation de la double authentification refusée (statut {status}).")
        jar.unlink()
        status, location = sign_in()
        if status != 302 or not location.endswith("/login/2fa"):
            raise AssertionError(f"La connexion n'exige pas le second facteur ({status} {location}).")
        if web("/dashboard")[0] != 302:
            raise AssertionError("Une session sans second facteur ouvre le tableau de bord.")
        _, _, html = web("/login/2fa")
        # Le pas courant a servi à l'activation : le code du pas suivant, dans la fenêtre, est accepté.
        status, _, _ = web("/login/2fa", {"csrf_token": csrf_of(html), "code": totp(secret_b32, 1)})
        if status != 302 or web("/dashboard")[0] != 200:
            raise AssertionError("Connexion en deux temps refusée.")
        print("Double authentification : enrôlement et connexion en deux temps par HTTPS : OK")
        # L'API d'administration ne répond qu'en local ; par le nom public, Caddy la cache (404).
        admin_public = run(*base, "--resolve", resolve, "--output", "/dev/null", "--write-out", "%{http_code}",
                           "--header", f"Authorization: Bearer {values['ADMIN_TOKEN']}",
                           f"https://{dashboard_host}/admin/api/pending").stdout.strip()
        if admin_public != "404":
            raise AssertionError(f"L'API d'administration répond par le nom public (statut {admin_public}).")
        ticket = json.loads(run(*base, "--header", f"Authorization: Bearer {values['ADMIN_TOKEN']}",
                                "--header", "Content-Type: application/json", "--data",
                                json.dumps({"email": EMAIL, "scope": "2fa"}),
                                f"http://127.0.0.1:8000/admin/api/users/{user_id}/recovery").stdout)["ticket"]
        print("API d'administration : 404 par le nom public, joignable en local : OK")
        jar.unlink()
        _, _, html = web("/recover")
        status, _, _ = web("/recover", {"csrf_token": csrf_of(html), "email": EMAIL, "ticket": ticket,
                                        "password": password})
        status, location = sign_in()
        if status != 302 or not location.endswith("/dashboard"):
            raise AssertionError(f"Le ticket de récupération n'a pas retiré le second facteur ({status} {location}).")
        print("Ticket de récupération de l'administrateur par HTTPS : OK")

        # Accès invité par code : boîte SMTPS simulée, code lu dans le mail, accès par HTTPS, sortie.
        smtp_dir = Path(tempfile.mkdtemp(prefix="synunnel-e2e-smtp-", dir="/run"))
        smtp_dir.chmod(0o755)
        smtp_dirs.append(smtp_dir)
        ext = smtp_dir / "ext.cnf"
        ext.write_text(f"subjectAltName=DNS:{SMTP_NAME}\n")
        run("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(smtp_dir / "ca.key"),
            "-out", str(smtp_dir / "ca.crt"), "-days", "1", "-subj", "/CN=Synunnel E2E CA")
        run("openssl", "req", "-newkey", "rsa:2048", "-nodes", "-keyout", str(smtp_dir / "smtp.key"),
            "-out", str(smtp_dir / "smtp.csr"), "-subj", f"/CN={SMTP_NAME}")
        run("openssl", "x509", "-req", "-in", str(smtp_dir / "smtp.csr"), "-CA", str(smtp_dir / "ca.crt"),
            "-CAkey", str(smtp_dir / "ca.key"), "-CAcreateserial", "-out", str(smtp_dir / "smtp.crt"),
            "-days", "1", "-extfile", str(ext))
        (smtp_dir / "ca.crt").chmod(0o644)
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(str(smtp_dir / "smtp.crt"), str(smtp_dir / "smtp.key"))
        threading.Thread(target=serve_smtp, args=(context, inbox, smtp_stop), daemon=True).start()
        hosts_original.append(HOSTS.read_text())
        HOSTS.write_text(hosts_original[0] + f"127.0.0.1 {SMTP_NAME}\n")
        SMTP_PASSWORD.write_text("mot-de-passe-de-la-boite-simulee\n")
        run("chown", "root:synunnel", str(SMTP_PASSWORD))
        SMTP_PASSWORD.chmod(0o640)
        SMTP_ENV.write_text(f"SMTP_HOST={SMTP_NAME}\nSMTP_PORT=465\nSMTP_USER=noreply@synunnel.test\n"
                            f"SMTP_FROM=noreply@synunnel.test\nSMTP_PASSWORD_FILE={SMTP_PASSWORD}\n"
                            f"SSL_CERT_FILE={smtp_dir / 'ca.crt'}\n")
        DROPIN.parent.mkdir(parents=True, exist_ok=True)
        DROPIN.write_text(f"[Service]\nEnvironmentFile={SMTP_ENV}\n")
        run("systemctl", "daemon-reload")
        run("systemctl", "restart", "synunnel")
        for _ in range(30):
            if web("/login")[0] == 200:
                break
            time.sleep(0.5)
        with db:
            address_id = db.execute("SELECT id FROM addresses WHERE hostname=?", (PROTECTED,)).fetchone()[0]
            db.execute("UPDATE addresses SET shared=1, guest_codes=1 WHERE id=?", (address_id,))
            db.execute("INSERT INTO address_grants(address_id,email) VALUES(?,?)", (address_id, GUEST_EMAIL))
        jar.unlink(missing_ok=True)
        target = f"https://{PROTECTED}/"
        _, _, html = web(f"/access/code?next={target}")
        status, location, _ = web("/access/code", {"csrf_token": csrf_of(html), "email": GUEST_EMAIL, "next": target})
        if status != 302 or not location.endswith("/access/verify"):
            raise AssertionError(f"Demande de code invité refusée ({status} {location}).")
        for _ in range(40):
            if inbox:
                break
            time.sleep(0.5)
        if not inbox:
            raise AssertionError("Aucun mail de code n'est arrivé dans la boîte simulée.")
        message = email.message_from_string(inbox[-1])
        body = message.get_payload(decode=True).decode("utf-8")
        code = re.search(r"\b(\d{6})\b", body).group(1)
        # Aucun lien qui ouvre l'accès : le seul lien est celui de la notice de confidentialité de l'instance.
        if (message["To"] != GUEST_EMAIL or re.findall(r"https://\S+", body) != [f"https://{dashboard_host}/confidentialite"]
                or "Pour ne plus figurer dans la liste" not in body):
            raise AssertionError(f"Le mail de code n'a pas la forme attendue : {body[:600]!r}")
        _, _, html = web("/access/verify")
        status, _, html = web("/access/verify", {"csrf_token": csrf_of(html), "code": code})
        relay = re.search(r'href="([^"]+)">Continuer', html)
        if status != 200 or not relay:
            raise AssertionError(f"Code invité refusé (statut {status}).")
        host_args = [*base, "--resolve", f"{PROTECTED}:443:{values['PUBLIC_IPV4']}", "-c", str(jar), "-b", str(jar)]
        back = run(*host_args, "--output", "/dev/null", "--write-out", "%{http_code} %{redirect_url}",
                   relay.group(1).replace("&amp;", "&"), check=False).stdout
        if not back.startswith("302"):
            raise AssertionError(f"Le callback de l'invité n'ouvre pas l'accès ({back}).")
        if PAGE not in run(*host_args, f"https://{PROTECTED}/").stdout:
            raise AssertionError("L'invité n'atteint pas le service derrière le tunnel.")
        access = next(line.split("\t")[-1] for line in jar.read_text().splitlines()
                      if line.split("\t")[-2:-1] == ["__Host-synunnel-access"])
        seen = run(*base, "--resolve", f"{PROTECTED}:443:{values['PUBLIC_IPV4']}", "--header",
                   f"Cookie: a=1; __Host-synunnel-access={access}; b=2", f"https://{PROTECTED}/cookie").stdout
        if seen != "COOKIE=[a=1; b=2]":
            raise AssertionError(f"Le service a reçu le cookie d'accès Synunnel : {seen!r}")
        print("Accès invité par code mail (boîte SMTPS simulée), cookie retiré avant le service : OK")
        page = run(*host_args, f"https://{PROTECTED}/__synunnel/logout").stdout
        run(*host_args, "--data-urlencode", f"csrf_token={csrf_of(page)}", f"https://{PROTECTED}/__synunnel/logout")
        after = run(*base, "--resolve", f"{PROTECTED}:443:{values['PUBLIC_IPV4']}", "--output", "/dev/null",
                    "--write-out", "%{http_code}", "--header", f"Cookie: __Host-synunnel-access={access}",
                    f"https://{PROTECTED}/", check=False).stdout
        if after != "302":
            raise AssertionError(f"Le cookie de l'invité reste valable après sa sortie ({after}).")
        print("Sortie de l'invité par /__synunnel/logout, cookie rejoué refusé : OK")

        # Jeton d'API valable (les précédents sont morts avec les changements de justificatifs) : une
        # traversée qui atteindrait l'API obtiendrait un 200.
        live_token = "syn_" + secrets.token_urlsafe(32)
        with db:
            db.execute(
                "INSERT INTO api_tokens(user_id,name,token_hash,prefix,scopes,created_at,expires_at,credential_version) "
                "SELECT ?, 'e2e-traversee', ?, ?, 'domains', ?, ?, credential_version FROM users WHERE id=?",
                (user_id, hashlib.sha256(live_token.encode()).hexdigest(), live_token[:10], "2026-09-29T00:00:00Z",
                 int(time.time()) + 3600, user_id),
            )
        if run(*base, "--resolve", resolve, "--output", "/dev/null", "--write-out", "%{http_code}", "--header",
               f"Authorization: Bearer {live_token}", f"https://{dashboard_host}/api/v1/me").stdout != "200":
            raise AssertionError("Le jeton de contrôle des traversées n'ouvre pas l'API.")
        # Les chemins réservés ne mènent jamais à l'application par une traversée : ni page du tableau de
        # bord (titre « · Synunnel »), ni réponse de l'API, ni 200.
        for sneaky in ("/__synunnel/../dashboard", "/__synunnel/../login", "/__synunnel/%2e%2e/api/v1/me",
                       "/__synunnel/..%2fapi/v1/me"):
            for extra in ([], ["--header", f"Authorization: Bearer {live_token}"]):
                reply = run(*base, "--path-as-is", "--resolve", f"{PROTECTED}:443:{values['PUBLIC_IPV4']}", *extra,
                            "--write-out", "\\n%{http_code}", f"https://{PROTECTED}{sneaky}", check=False).stdout
                if EMAIL in reply or reply.rstrip().endswith("\n200") or "· Synunnel</title>" in reply:
                    raise AssertionError(f"Traversée de /__synunnel/ vers l'application : {sneaky} -> "
                                         f"{reply[-400:]!r}")
        print("Traversées de /__synunnel/ refusées : OK")

        # Mot de passe oublié par mail, de bout en bout, et journal de Caddy expurgé sur un 502.
        admin = ["--header", f"Authorization: Bearer {values['ADMIN_TOKEN']}", "--header",
                 "Content-Type: application/json"]
        run(*base, *admin, "--data", json.dumps({"email": EMAIL}),
            f"http://127.0.0.1:8000/admin/api/users/{user_id}/verify-email")
        jar.unlink(missing_ok=True)
        before = len(inbox)
        _, _, html = web("/forgot")
        web("/forgot", {"csrf_token": csrf_of(html), "email": EMAIL})
        for _ in range(40):
            if len(inbox) > before:
                break
            time.sleep(0.5)
        if len(inbox) <= before:
            raise AssertionError("Aucun lien de réinitialisation n'est arrivé dans la boîte simulée.")
        reset_body = email.message_from_string(inbox[-1]).get_payload(decode=True).decode("utf-8")
        link = re.search(r"https://\S+/reset\?token=([A-Za-z0-9_-]+)", reset_body)
        if not link or not link.group(0).startswith(f"https://{dashboard_host}/"):
            raise AssertionError("Le lien de réinitialisation n'a pas la forme attendue.")
        since = time.strftime("%Y-%m-%d %H:%M:%S")
        marker = "e2e-" + secrets.token_hex(6)
        run("systemctl", "stop", "synunnel")
        down = run(*base, "--resolve", resolve, "--output", "/dev/null", "--write-out", "%{http_code}",
                   f"{link.group(0)}&marqueur={marker}", check=False).stdout
        run("systemctl", "start", "synunnel")
        for _ in range(30):
            if web("/login")[0] == 200:
                break
            time.sleep(0.5)
        time.sleep(1)
        logged = run("journalctl", "-u", "caddy", "--since", since, "--no-pager").stdout
        entry = next((line for line in logged.splitlines() if marker in line), "")
        # L'entrée de la requête doit exister (preuve positive), avec le jeton remplacé et rien de secret.
        if down != "502" or "token=REDACTED" not in entry or link.group(1) in logged:
            raise AssertionError(f"Journal de Caddy non expurgé sur une erreur ({down}) : {entry[:300]!r}")
        print("Journal de Caddy expurgé du jeton de réinitialisation sur un 502 : OK")
        new_password = secrets.token_urlsafe(24)
        _, _, html = web(link.group(0).replace(f"https://{dashboard_host}", ""))
        status, _, _ = web("/reset", {"csrf_token": csrf_of(html), "token": link.group(1), "email": EMAIL,
                                      "password": new_password})
        _, _, html = web("/login")
        status, location, _ = web("/login", {"csrf_token": csrf_of(html), "email": EMAIL, "password": new_password})
        if status != 302 or not location.endswith("/dashboard"):
            raise AssertionError(f"Mot de passe oublié par mail : nouvelle connexion refusée ({status} {location}).")
        print("Mot de passe oublié par mail (lien lu dans la boîte simulée) : OK")

        # HEAD rend le statut de GET et n'écrit rien : ni tentative, ni quota, ni événement.
        def tally() -> list[int]:
            return [db.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                    for table in ("attempts", "guest_quota", "security_events", "password_resets")]

        before_head = tally()
        guest_page = "/access/code?next=" + quote(f"https://{PROTECTED}/", safe="")
        for path in ("/forgot", "/login", "/register", guest_page):
            expected = run(*base, "--resolve", resolve, "--output", "/dev/null", "--write-out", "%{http_code}",
                           f"https://{dashboard_host}{path}", check=False).stdout.strip()
            for _ in range(6):
                probed = run(*base, "--resolve", resolve, "--head", "--output", "/dev/null", "--write-out",
                             "%{http_code}", f"https://{dashboard_host}{path}", check=False).stdout.strip()
                if probed != expected:
                    raise AssertionError(f"HEAD {path} : {probed}, GET : {expected}.")
        if tally() != before_head:
            raise AssertionError(f"Des requêtes HEAD ont écrit en base : {before_head} -> {tally()}.")
        print("HEAD sur /forgot, /login, /register et /access/code : statut de GET, rien écrit : OK")

        # Suppression refusée tant que la délégation n'est pas vérifiée comme retirée, par l'API et par la page.
        spare_token = "syn_" + secrets.token_urlsafe(32)
        with db:
            spare_id = db.execute("INSERT INTO domains(user_id,name,created_at) VALUES(?,?,?)",
                                  (user_id, SPARE, "2026-09-27T00:00:00Z")).lastrowid
            db.execute(
                "INSERT INTO api_tokens(user_id,name,token_hash,prefix,scopes,created_at,expires_at,credential_version) "
                "SELECT ?,?,?,?,?,?,?,credential_version FROM users WHERE id=?",
                (user_id, "e2e-suppr", hashlib.sha256(spare_token.encode()).hexdigest(), spare_token[:10], "domains",
                 "2026-09-27T00:00:00Z", int(time.time()) + 3600, user_id),
            )
        reply = run(*base, "--resolve", resolve, "--request", "DELETE", "--header",
                    f"Authorization: Bearer {spare_token}", "--write-out", "\n%{http_code}",
                    f"https://{dashboard_host}/api/v1/domains/{spare_id}", check=False).stdout
        body, _, code = reply.rpartition("\n")
        refusal = json.loads(body or "{}").get("error", {}).get("code")
        if code != "409" or refusal not in {"delegation_unknown", "delegation_active"}:
            raise AssertionError(f"Suppression par l'API non refusée : {code} {body[:200]!r}")
        status, _, html = web(f"/domains/{spare_id}/delete")
        if status != 200 or 'name="confirm_name"' not in html:
            raise AssertionError(f"Page de confirmation de suppression absente ({status}).")
        status, _, _ = web(f"/domains/{spare_id}/delete", {"csrf_token": csrf_of(html), "confirm_name": SPARE})
        if status != 302 or not db.execute("SELECT 1 FROM domains WHERE id=?", (spare_id,)).fetchone():
            raise AssertionError("Le domaine a été supprimé sans délégation vérifiée.")
        print(f"Suppression refusée (409 {refusal}) par l'API et par la page, nom retapé exigé : OK")
        completed = True
    finally:
        errors: list[str] = []

        def attempt(label: str, action) -> None:
            try:
                action()
            except Exception as exc:  # noqa: BLE001 - chaque étape de remise en état doit être tentée
                errors.append(f"{label} : {exc}")

        def restore_caddy() -> None:
            CONFIG.write_text(original_caddy)
            run("systemctl", "reload", "caddy")

        def stop_http() -> None:
            http_server.terminate()
            try:
                http_server.wait(timeout=3)
            except subprocess.TimeoutExpired:
                http_server.kill()
                http_server.wait(timeout=3)

        def drop_veth() -> None:
            # Supprimer l'espace réseau emporte la paire veth : l'interface peut déjà avoir disparu.
            result = run("ip", "link", "delete", VETH_HOST, check=False)
            if result.returncode != 0 and VETH_HOST in run("ip", "-o", "link", "show").stdout:
                raise RuntimeError(result.stderr.strip())

        def drop_user() -> None:
            with db:
                db.execute("DELETE FROM users WHERE email=?", (EMAIL,))

        def restore_smtp() -> None:
            smtp_stop.set()
            DROPIN.unlink(missing_ok=True)
            SMTP_ENV.unlink(missing_ok=True)
            SMTP_PASSWORD.unlink(missing_ok=True)
            if hosts_original:
                HOSTS.write_text(hosts_original[0])
            run("systemctl", "daemon-reload")
            run("systemctl", "restart", "synunnel")
            for directory in smtp_dirs:
                for item in directory.iterdir():
                    item.unlink()
                directory.rmdir()

        if smtp_dirs or DROPIN.exists():
            attempt("boîte SMTP simulée", restore_smtp)
        if caddy_changed:
            attempt("Caddyfile", restore_caddy)
        if http_server:
            attempt("serveur HTTP", stop_http)
        if netns_created:
            attempt("espace réseau", lambda: run("ip", "netns", "delete", NS))
            attempt("interface veth", drop_veth)
        attempt("compte de test", drop_user)
        if zone_created:
            attempt("zone PowerDNS", lambda: pdns.delete_zone(DOMAIN))
        attempt("synchronisation", lambda: run("/usr/local/sbin/synunnel-sync"))
        for path in (private_file, page_file, key_dir / "cookies.txt", key_dir / "page.html"):
            attempt(str(path), lambda path=path: path.unlink(missing_ok=True))
        for directory in (key_dir, web_dir):
            attempt(str(directory), directory.rmdir)
        db.close()
        if errors:
            print("Remise en état incomplète, à vérifier à la main :\n- " + "\n- ".join(errors))
            if completed:
                raise SystemExit(1)

if __name__ == "__main__":
    main()
