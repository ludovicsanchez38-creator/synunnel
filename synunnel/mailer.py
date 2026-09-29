"""Envoi des mails de Synunnel : SMTPS (465) seulement, hors du chemin des requêtes.

Une requête ne fait que déposer le message dans une file bornée ; un fil d'arrière-plan du
processus l'envoie. La réponse HTTP ne dépend donc ni de l'existence d'un compte, ni de la
disponibilité du serveur SMTP. Le mot de passe SMTP est lu dans un fichier à part, jamais
dans l'environnement : il n'est ni sourcé par le shell ni affiché par `systemctl show`.
"""

import logging
import queue
import re
import smtplib
import ssl
import threading
from collections.abc import Callable
from email.headerregistry import Address
from email.message import EmailMessage
from email.utils import formatdate, make_msgid
from pathlib import Path

LOG = logging.getLogger("synunnel.mailer")
ADDRESS_RE = re.compile(r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$")
HOST_RE = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$")
QUEUE_SIZE = 200


class Mailer:
    def __init__(self, config, transport_lookup: Callable[[], Callable | None] | None = None):
        self.host = str(config.get("SMTP_HOST") or "")
        self.port = str(config.get("SMTP_PORT") or "465")
        self.user = str(config.get("SMTP_USER") or "")
        self.sender = str(config.get("SMTP_FROM") or "")
        self.password_file = str(config.get("SMTP_PASSWORD_FILE") or "")
        self._transport_lookup = transport_lookup or (lambda: None)
        self._queue: queue.Queue = queue.Queue(maxsize=QUEUE_SIZE)
        self._worker: threading.Thread | None = None
        self._lock = threading.Lock()

    @property
    def configured(self) -> bool:
        return bool(HOST_RE.fullmatch(self.host) and self.port == "465" and ADDRESS_RE.fullmatch(self.user)
                    and ADDRESS_RE.fullmatch(self.sender) and self.password_file.startswith("/")
                    and Path(self.password_file).is_file())

    @property
    def enabled(self) -> bool:
        return self._transport_lookup() is not None or self.configured

    def build(self, to: str, subject: str, body: str) -> EmailMessage:
        if not isinstance(to, str) or not ADDRESS_RE.fullmatch(to):
            raise ValueError("adresse de destination invalide")
        sender = self.sender or "noreply@synunnel.invalid"
        message = EmailMessage()
        local, _, domain = sender.partition("@")
        message["From"] = Address("Synunnel", local, domain)
        message["To"] = to
        message["Subject"] = subject
        message["Date"] = formatdate(localtime=True)
        message["Message-ID"] = make_msgid(domain=domain)
        message.set_content(body)
        return message

    def send_now(self, to: str, subject: str, body: str) -> None:
        message = self.build(to, subject, body)
        transport = self._transport_lookup()
        if transport is not None:
            transport(message)
            return
        if not self.configured:
            raise RuntimeError("SMTP non configuré")
        password = Path(self.password_file).read_text(encoding="utf-8").rstrip("\r\n")
        # Contexte par défaut : certificat vérifié et nom d'hôte contrôlé, aucun repli en clair.
        context = ssl.create_default_context()
        with smtplib.SMTP_SSL(self.host, int(self.port), context=context, timeout=10) as smtp:
            smtp.login(self.user, password)
            smtp.send_message(message, from_addr=self.sender, to_addrs=[to])

    def enqueue(self, to: str, subject: str, body: str) -> bool:
        if not self.enabled:
            return False
        try:
            self._queue.put_nowait((to, subject, body))
        except queue.Full:
            LOG.warning("file des mails pleine : message abandonné")
            return False
        self._ensure_worker()
        return True

    def _ensure_worker(self) -> None:
        with self._lock:
            if self._worker is None or not self._worker.is_alive():
                self._worker = threading.Thread(target=self._run, name="synunnel-mailer", daemon=True)
                self._worker.start()

    def _run(self) -> None:
        while True:
            to, subject, body = self._queue.get()
            try:
                self.send_now(to, subject, body)
            except Exception:
                LOG.exception("échec d'envoi d'un mail")
            finally:
                self._queue.task_done()

    def flush(self, timeout: float) -> None:
        """Attend que la file soit vide (tests et arrêt propre), au plus `timeout` secondes."""
        done = threading.Event()

        def wait():
            self._queue.join()
            done.set()

        threading.Thread(target=wait, daemon=True).start()
        done.wait(timeout)
