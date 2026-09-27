"""Migration de configuration, zones existantes et rendu Caddy."""

import base64
import runpy
import sqlite3
from pathlib import Path

from synunnel import create_app
from synunnel.db import get_db
from synunnel.dns import PowerDNS, normalize_domain
from synunnel.provision import create_machine_config, provision_site

ROOT = Path(__file__).resolve().parents[1]


def test_existing_database_gets_shared_access_columns(tmp_path):
    path = tmp_path / "old.db"
    db = sqlite3.connect(path)
    db.execute("CREATE TABLE addresses (id INTEGER PRIMARY KEY, domain_id INTEGER, machine_id INTEGER, "
               "hostname TEXT, port INTEGER, protected INTEGER, created_at TEXT)")
    db.commit()
    db.close()
    app = create_app({"TESTING": True, "SECRET_KEY": "test", "ADMIN_TOKEN": "test",
                      "DATABASE": str(path), "PDNS_ENABLED": False, "SYNC_COMMAND": ""})
    with app.app_context():
        assert "shared" in {row[1] for row in get_db().execute("PRAGMA table_info(addresses)")}
        assert get_db().execute("SELECT COUNT(*) FROM address_grants").fetchone()[0] == 0


def test_system_domains_cannot_be_claimed_by_users():
    for name in ("synunnel.fr", "x.synunnel.fr", "synunnel.com", "www.synunnel.com",
                 "synoptia.fr", "synunnel.synoptia.fr"):
        try:
            normalize_domain(name)
        except ValueError:
            pass
        else:
            raise AssertionError(f"Domaine système accepté : {name}")


def test_caddy_template_uses_configured_hosts_and_rejects_injection():
    render = runpy.run_path(str(ROOT / "scripts/render-caddy.py"))["render_caddy"]
    template = (ROOT / "config/Caddyfile").read_text()
    caddy = render(template, "synunnel.fr", "synunnel.com,www.synunnel.com", "ludo@synoptia.fr")
    assert "@synunnel_dashboard host synunnel.fr" in caddy
    assert "@synunnel_redirect host synunnel.com www.synunnel.com" in caddy
    assert "redir https://synunnel.fr{uri} 308" in caddy
    assert "__DASHBOARD_HOST__" not in caddy
    try:
        render(template, "synunnel.fr\nrespond 200", "synunnel.com", "ludo@synoptia.fr")
    except ValueError:
        pass
    else:
        raise AssertionError("Une injection de configuration a été acceptée.")


def test_env_migration_is_idempotent():
    migrate = runpy.run_path(str(ROOT / "scripts/migrate-instance-domain.py"))["migrate_content"]
    old = ("SECRET_KEY=keep-secret\nDASHBOARD_HOST=synunnel.synoptia.fr\n"
           "NS1_HOST=ns1.synunnel.synoptia.fr\nNS2_HOST=ns2.synunnel.synoptia.fr\n")
    new, changed = migrate(old)
    assert changed and "SECRET_KEY=keep-secret" in new
    assert "DASHBOARD_HOST=synunnel.fr" in new
    assert "SOA_RNAME=hostmaster.synunnel.fr." in new
    assert "REDIRECT_HOSTS=synunnel.com,www.synunnel.com" in new
    assert migrate(new) == (new, False)


def test_existing_zone_authority_changes_once():
    pdns = PowerDNS("http://localhost", "test", ("ns1.synunnel.fr.", "ns2.synunnel.fr."))
    zone = {"rrsets": [
        {"name": "example.net.", "type": "SOA", "ttl": 3600, "records": [
            {"content": "ns1.synunnel.synoptia.fr. hostmaster.synoptia.fr. 2 3600 600 1209600 300", "disabled": False},
        ]},
        {"name": "example.net.", "type": "NS", "ttl": 3600, "records": [
            {"content": "ns1.synunnel.synoptia.fr.", "disabled": False},
            {"content": "ns2.synunnel.synoptia.fr.", "disabled": False},
        ]},
        {"name": "example.net.", "type": "MX", "ttl": 3600, "records": [
            {"content": "10 mail.example.net.", "disabled": False},
        ]},
    ]}
    patches = []

    class Response:
        def json(self):
            return zone

    def request(method, _path, **kwargs):
        if method == "PATCH":
            patches.append(kwargs["json"]["rrsets"])
            zone["rrsets"][:2] = kwargs["json"]["rrsets"]
        return Response()

    pdns._request = request
    assert pdns.migrate_authority("example.net", "hostmaster.synunnel.fr.")
    assert len(patches) == 1
    assert {item["type"] for item in patches[0]} == {"SOA", "NS"}
    assert " 3 3600 " in patches[0][0]["records"][0]["content"]
    assert not pdns.migrate_authority("example.net", "hostmaster.synunnel.fr.")
    assert len(patches) == 1


def test_provision_cli_logic_requires_approved_owner_and_preserves_mail(tmp_path):
    app = create_app({"TESTING": True, "SECRET_KEY": "test", "ADMIN_TOKEN": "test",
                      "DATABASE": str(tmp_path / "provision.db"), "PDNS_ENABLED": False,
                      "SYNC_COMMAND": ""})
    key = base64.b64encode(b"a" * 32).decode()
    kwargs = {"user_email": "owner@example.net", "domain_name": "tooggy.com",
              "machine_name": "tooggy-landing", "machine_ip": "10.88.0.3",
              "machine_public_key": key, "port": 18080, "hosts": ["@", "www"],
              "mail_records_verified": True,
              "snapshot": lambda domain, selectors: [
                      ("@", "A", "213.186.33.5", 3600),
                      ("@", "MX", "1 mx1.mail.ovh.net.", 3600),
                      ("@", "TXT", '"v=spf1 include:mx.ovh.com -all"', 3600),
                      ("www", "TXT", '"3|welcome"', 3600),
                  ]}
    with app.app_context():
        db = get_db()
        db.execute("INSERT INTO users(email,password_hash,status,created_at) VALUES(?,?,?,?)",
                   ("owner@example.net", "unused", "pending", "2026-09-27"))
        db.commit()
        try:
            provision_site(app, **kwargs)
        except ValueError as exc:
            assert "approuvé" in str(exc)
        else:
            raise AssertionError("Un compte en attente a obtenu un domaine.")
        db.execute("UPDATE users SET status='approved'")
        db.commit()
        result = provision_site(app, **kwargs)
        assert result["copied_records"] == 4
        assert result["addresses"] == 2
        assert db.execute("SELECT COUNT(*) FROM records WHERE type='MX'").fetchone()[0] == 1
        assert db.execute("SELECT COUNT(*) FROM records WHERE type='TXT'").fetchone()[0] == 2
        assert db.execute("SELECT COUNT(*) FROM addresses WHERE protected=1 AND shared=1").fetchone()[0] == 2
        assert provision_site(app, **kwargs)["copied_records"] == 0
        assert provision_site(app, **{**kwargs, "machine_public_key": None})["copied_records"] == 0
        assert db.execute("SELECT COUNT(*) FROM domains").fetchone()[0] == 1


def test_cli_env_parser_accepts_empty_ipv6(tmp_path):
    read_env = runpy.run_path(str(ROOT / "scripts/provision-site.py"))["read_env"]
    path = tmp_path / "env"
    path.write_text("PUBLIC_IPV6=\nSYNC_COMMAND='/usr/bin/sudo -n /usr/local/sbin/synunnel-sync'\n")
    assert read_env(path)["PUBLIC_IPV6"] == ""
    assert read_env(path)["SYNC_COMMAND"].endswith("synunnel-sync")


def test_machine_config_stream_private_key_is_not_stored(tmp_path):
    app = create_app({"TESTING": True, "SECRET_KEY": "test", "ADMIN_TOKEN": "test",
                      "DATABASE": str(tmp_path / "machine.db"), "PDNS_ENABLED": False,
                      "SYNC_COMMAND": "", "WG_SERVER_PUBLIC_KEY": "server-public-test",
                      "WG_ENDPOINT": "51.254.137.231:51820"})
    private = base64.b64encode(b"p" * 32).decode()
    public = base64.b64encode(b"q" * 32).decode()
    with app.app_context():
        db = get_db()
        db.execute("INSERT INTO users(email,password_hash,status,created_at) VALUES(?,?,?,?)",
                   ("owner@example.net", "unused", "approved", "2026-09-27"))
        db.commit()
        config = create_machine_config(
            app, user_email="owner@example.net", machine_name="tooggy-vps",
            machine_ip="10.88.0.3", keypair=(private, public),
        )
        assert f"PrivateKey = {private}" in config
        assert "AllowedIPs = 10.88.0.1/32" in config
        assert db.execute("SELECT public_key FROM machines").fetchone()[0] == public
        assert private.encode() not in Path(app.config["DATABASE"]).read_bytes()
