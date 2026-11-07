"""F-3 : une IP reste réservée jusqu'au retrait effectif de son ancien pair.

Exécutables aussi avec unittest, sans service système ni accès réseau.
"""

import base64
import re
import runpy
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from flask import Flask

from synunnel import actions
from synunnel.db import close_db, get_db, init_db
from synunnel.provision import create_machine_config, provision_site

ROOT = Path(__file__).resolve().parents[1]


def key(n):
    return base64.b64encode(bytes([n]) * 32).decode()


class WireGuardQuarantineTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="synunnel-f3-")
        self.addCleanup(temporary.cleanup)
        self.folder = Path(temporary.name)
        self.app = Flask(__name__)
        self.app.config.update(
            TESTING=True, DATABASE=str(self.folder / "test.db"),
            PDNS_ENABLED=False, SYNC_COMMAND="", RESERVED_DOMAINS=(),
            MAX_MACHINES_PER_USER=10, MAX_ADDRESSES_PER_USER=50,
            WG_SERVER_PUBLIC_KEY=key(42), WG_ENDPOINT="192.0.2.10:51820",
        )
        self.app.teardown_appcontext(close_db)
        context = self.app.app_context()
        context.push()
        self.addCleanup(context.pop)
        init_db()
        with get_db() as db:
            for user_id in (1, 2):
                db.execute("INSERT INTO users(id,email,password_hash,status,created_at) "
                           "VALUES(?,?,?,'approved','test')", (user_id, f"{user_id}@example.net", "unused"))
        self.enterContext(patch("synunnel.actions.project_runtime", return_value=False))
        for target in ("socket.socket.connect", "socket.create_connection", "socket.getaddrinfo"):
            self.enterContext(patch(target, side_effect=AssertionError("Réseau interdit dans ce test")))

        self.sync = runpy.run_path(str(ROOT / "scripts/synunnel-sync.py"))
        self.globals = self.sync["main"].__globals__
        for name in ("WG_KEY_PATH", "WG_CONFIG_PATH", "CADDY_ROUTES_PATH", "CADDYFILE_PATH",
                     "APPLIED_WG", "APPLIED_CADDY", "LOCK_PATH"):
            self.globals[name] = self.folder / name.lower()
        self.globals["DB_PATH"] = Path(self.app.config["DATABASE"])
        self.globals["WG_KEY_PATH"].write_text(key(42))
        self.globals["wireguard_active"] = lambda: True
        self.enterContext(patch("os.geteuid", return_value=0))
        original_temporary_file = tempfile.NamedTemporaryFile

        def temporary_file(*args, **kwargs):
            # apply_wireguard utilise /run en production ; rien n'y est écrit ici.
            kwargs["dir"] = self.folder
            return original_temporary_file(*args, **kwargs)

        self.enterContext(patch("tempfile.NamedTemporaryFile", side_effect=temporary_file))
        self.wg_failure = False
        self.caddy_failure = False
        self.calls = []
        self.peers = ""
        self.on_sync = None
        self.globals["run"] = self.fake_run

    def fake_run(self, *args, input=None):
        self.calls.append(args[:2])
        if args[:2] == ("/usr/bin/wg", "syncconf"):
            if self.on_sync:
                callback, self.on_sync = self.on_sync, None
                callback()
            if self.wg_failure:
                raise subprocess.CalledProcessError(1, args)
            self.peers = self.globals["WG_CONFIG_PATH"].read_text()
        if self.caddy_failure and args[0] == "/usr/bin/caddy":
            raise subprocess.CalledProcessError(1, args)
        return subprocess.CompletedProcess(args, 0, b"", b"")

    def machine(self, owner, n):
        return actions.register_machine(self.app, owner, f"machine-{n}", key(n), None, None)

    def address(self, owner, machine):
        with get_db() as db:
            domain_id = db.execute("INSERT INTO domains(user_id,name,created_at) VALUES(?,?,'test')",
                                   (owner, f"client{owner}.example.net")).lastrowid
        return actions.create_address(self.app, owner, domain_id, machine["id"], "nas", 80, False)

    def test_ip_supprimee_non_reattribuee_apres_echecs_wireguard(self):
        old = self.machine(1, 1)
        self.sync["main"]()
        self.wg_failure = True
        actions.delete_machine(self.app, 1, old["id"])
        for _ in range(2):
            with self.assertRaises(SystemExit):
                self.sync["main"]()
        new = self.machine(2, 2)
        self.assertNotEqual(new["ip"], old["ip"])
        self.assertIn(f"PublicKey = {key(1)}", self.peers)

    def test_nouvelle_route_non_activee_si_wireguard_echoue(self):
        old = self.machine(1, 1)
        old_address = self.address(1, old)
        self.sync["main"]()
        routes_before = self.globals["CADDY_ROUTES_PATH"].read_text()
        actions.delete_address(self.app, 1, old_address["id"])
        actions.delete_machine(self.app, 1, old["id"])
        new = self.machine(2, 2)
        self.address(2, new)
        self.wg_failure = True
        self.calls.clear()
        with self.assertRaises(SystemExit):
            self.sync["main"]()
        self.assertEqual(self.globals["CADDY_ROUTES_PATH"].read_text(), routes_before)
        self.assertNotIn(("/usr/bin/systemctl", "reload"), self.calls)

    def test_reprise_libere_ip_apres_retrait_et_active_la_route(self):
        old = self.machine(1, 1)
        self.sync["main"]()
        actions.delete_machine(self.app, 1, old["id"])
        new = self.machine(2, 2)
        self.assertNotEqual(new["ip"], old["ip"])
        address = self.address(2, new)
        self.sync["main"]()
        self.assertNotIn(f"PublicKey = {key(1)}", self.peers)
        routes = self.globals["CADDY_ROUTES_PATH"].read_text()
        self.assertIn(address["hostname"], routes)
        self.assertIn(f"reverse_proxy {new['ip']}:80", routes)
        self.assertEqual(self.machine(1, 3)["ip"], old["ip"])

    def test_suppression_pendant_synchronisation_reste_en_quarantaine(self):
        old = self.machine(1, 1)
        already_removed = self.machine(1, 4)
        actions.delete_machine(self.app, 1, already_removed["id"])
        self.on_sync = lambda: actions.delete_machine(self.app, 1, old["id"])
        self.sync["main"]()
        self.assertIn(f"PublicKey = {key(1)}", self.peers)
        self.assertNotEqual(self.machine(2, 2)["ip"], old["ip"])
        self.sync["main"]()
        self.assertEqual(self.machine(1, 3)["ip"], old["ip"])

    def test_suppression_compte_reserve_aussi_ip_de_ses_machines(self):
        old = self.machine(1, 1)
        with get_db() as db:
            db.execute("DELETE FROM users WHERE id=1")
        self.assertNotEqual(self.machine(2, 2)["ip"], old["ip"])

    def test_creation_administrative_refuse_ip_en_quarantaine(self):
        old = self.machine(1, 1)
        actions.delete_machine(self.app, 1, old["id"])
        with self.assertRaises(ValueError):
            create_machine_config(self.app, user_email="2@example.net", machine_name="nouvelle",
                                  machine_ip=old["ip"], keypair=(key(3), key(2)))

    def test_provisionnement_site_refuse_ip_en_quarantaine(self):
        old = self.machine(1, 1)
        actions.delete_machine(self.app, 1, old["id"])
        with self.assertRaises(ValueError):
            provision_site(
                self.app, user_email="2@example.net", domain_name="site.example.net",
                machine_name="nouvelle", machine_ip=old["ip"], machine_public_key=key(2),
                port=80, hosts=["@"], mail_records_verified=True,
                snapshot=lambda domain, selectors: [("@", "TXT", '"test"', 300)],
            )

    def test_panne_caddy_n_empeche_pas_retrait_pair_wireguard(self):
        old = self.machine(1, 1)
        self.sync["main"]()
        actions.delete_machine(self.app, 1, old["id"])
        self.caddy_failure = True
        self.globals["APPLIED_CADDY"].write_text("forcer une réapplication")
        with self.assertRaises(SystemExit):
            self.sync["main"]()
        self.assertNotIn(f"PublicKey = {key(1)}", self.peers)

    def test_retrait_de_toutes_routes_possible_si_wireguard_echoue(self):
        old = self.machine(1, 1)
        address = self.address(1, old)
        self.sync["main"]()
        actions.delete_address(self.app, 1, address["id"])
        self.wg_failure = True
        self.globals["APPLIED_WG"].write_text("forcer une réapplication")
        with self.assertRaises(SystemExit):
            self.sync["main"]()
        self.assertNotRegex(self.globals["CADDY_ROUTES_PATH"].read_text(), re.compile(r"reverse_proxy"))


if __name__ == "__main__":
    unittest.main()
