# ruff: noqa: F811  (la fixture app vient de test_api)
"""Bloquant 6 de l'UltraJury : mentions légales, notice de confidentialité et information des invités."""

import re

import pytest
from test_api import account, app  # noqa: F401
from test_guest import GUEST, ask_code, flush, mails, protected_address  # noqa: F401

from synunnel.legal import render_markdown

LEGAL = "# Éditeur\n\nExploitant Test SAS, 1 rue de l'Essai, 75000 Paris.\n\n- Hébergeur : Hôte Exemple\n"
PRIVACY = "# Données traitées\n\nAdresse mail des comptes et des **invités**. Contact : [écrire](mailto:dpo@example.org).\n"


@pytest.fixture
def operator(app, tmp_path):
    (tmp_path / "mentions.md").write_text(LEGAL)
    (tmp_path / "confidentialite.md").write_text(PRIVACY)
    app.config.update(LEGAL_FILE=str(tmp_path / "mentions.md"), PRIVACY_FILE=str(tmp_path / "confidentialite.md"),
                      OPERATOR_NAME="Exploitant Test SAS", ADMIN_CONTACT="admin@example.org")
    return app


def test_legal_pages_render_the_operator_files(operator):
    client = operator.test_client()
    legal = client.get("/mentions-legales")
    assert legal.status_code == 200 and "Exploitant Test SAS, 1 rue de l&#39;Essai" in legal.data.decode()
    privacy = client.get("/confidentialite").data.decode()
    assert "<strong>invités</strong>" in privacy and 'href="mailto:dpo@example.org"' in privacy


def test_every_page_links_the_notices_and_names_the_operator(operator):
    client = operator.test_client()
    for path in ["/login", "/register", "/forgot", "/access/code?next=https%3A%2F%2Fnas.example%2F"]:
        body = client.get(path).data.decode()
        assert 'href="/mentions-legales"' in body and 'href="/confidentialite"' in body, path
        assert "Instance exploitée par Exploitant Test SAS" in body, path
        # Sous le formulaire qui collecte l'adresse, dans la même carte, un renvoi à la notice.
        card = body.split('class="card auth-card"', 1)[1].split("</section>", 1)[0]
        note = card.split('class="small legal-note"', 1)
        assert len(note) == 2 and 'href="/confidentialite"' in note[1].split("</p>", 1)[0], path


def test_without_operator_files_the_pages_say_so(app):
    client = app.test_client()
    for path in ["/mentions-legales", "/confidentialite"]:
        response = client.get(path)
        assert response.status_code == 200 and "pas encore publié" in response.data.decode(), path


def test_markdown_subset_escapes_html_and_unsafe_links():
    rendered = str(render_markdown("<script>alert(1)</script>\n\n[piège](javascript:alert(1)) [ok](https://example.org)"))
    assert "<script>" not in rendered and "&lt;script&gt;" in rendered
    assert 'href="javascript' not in rendered and 'href="https://example.org"' in rendered
    local = str(render_markdown("[notice](/confidentialite) [ailleurs](//evil.example/x) [aussi](/\\evil.example)"))
    assert 'href="/confidentialite"' in local and "evil.example" in local and 'href="//' not in local
    assert 'href="/\\' not in local


def test_guest_mail_names_the_instance_the_notice_and_a_contact(operator, mails):
    protected_address(operator)
    ask_code(operator.test_client())
    flush(operator)
    body = mails[-1].get_content()
    assert "Exploitant Test SAS" in body and "https://synunnel.fr/confidentialite" in body
    assert "admin@example.org" in body


def test_access_page_no_longer_promises_an_automatic_invitation(operator):
    owner, address_id = protected_address(operator, owner_email="texte@example.net")
    body = owner.get(f"/addresses/{address_id}/access").data.decode()
    assert "Chaque personne de la liste reçoit un code" not in body
    assert re.search(r"aucun mail n.est envoyé", body, re.IGNORECASE)


def test_installer_quotes_the_operator_name_and_confines_the_operator_files():
    import subprocess
    from pathlib import Path

    script = (Path(__file__).resolve().parent.parent / "scripts" / "install.sh").read_text()
    name_check = "if (( ${#OPERATOR_NAME} > 120 ))" + script.split("if (( ${#OPERATOR_NAME} > 120 ))", 1)[1]
    name_check = name_check.split("\nfi\n", 1)[0] + "\nfi\n"
    for value, accepted in (("Synoptïa SARL-U", True), ("L’Atelier", True), ("L'Atelier", False),
                            ('A"B', False), ("A$(id)", False), ("A`id`", False), ("A\\B", False)):
        run = subprocess.run(["bash", "-c", name_check], env={"OPERATOR_NAME": value}, capture_output=True, check=False)
        assert (run.returncode == 0) is accepted, value
    files_check = "for file_setting in SMTP_PASSWORD_FILE" + script.split("for file_setting in SMTP_PASSWORD_FILE", 1)[1]
    files_check = files_check.split("\ndone\n", 1)[0] + "\ndone\n"
    for path, accepted in (("/etc/synunnel/mentions-legales.md", True), ("", True), ("/etc/shadow", False),
                           ("/etc/synunnel/synunnel.env", False), ("/etc/synunnel/../shadow", False)):
        env = {"SMTP_PASSWORD_FILE": "", "LEGAL_FILE": path, "PRIVACY_FILE": ""}
        run = subprocess.run(["bash", "-c", files_check], env=env, capture_output=True, check=False)
        assert (run.returncode == 0) is accepted, path
    assert "OPERATOR_NAME='$OPERATOR_NAME'" in script
    completion = script.split("# Une instance antérieure peut ne pas avoir toutes les clés", 1)[1].split("\ndone\n", 1)[0]
    for key in ("OPERATOR_NAME", "ADMIN_CONTACT", "LEGAL_FILE", "PRIVACY_FILE"):
        assert key in completion
    assert "printf \"%s='%s'\\n\"" in completion


def test_readme_recipe_covers_an_instance_already_installed():
    """Constat 7 de la revue Codex : après une première installation, les quatre lignes existent (vides)
    dans synunnel.env et font foi ; passer les réglages au script ne suffit plus."""
    from pathlib import Path

    readme = (Path(__file__).resolve().parent.parent / "README.md").read_text()
    section = readme.split("**Mentions légales et confidentialité**", 1)[1].split("Le dépôt peut vivre", 1)[0]
    assert "font foi" in section and "OPERATOR_NAME='" in section and "/etc/synunnel/synunnel.env" in section
    assert "root:synunnel" in section and "relancez" in section.lower()


def test_privacy_template_tells_guests_about_the_security_log():
    """Constat 8 de la revue Codex : demandes, entrées et sorties d'un invité sont journalisées 365 jours,
    avec son adresse, le service et l'adresse IP ; la section des invités doit le dire."""
    from pathlib import Path

    template = (Path(__file__).resolve().parent.parent / "docs" / "modeles" / "confidentialite.md").read_text()
    guests = template.split("## Personnes invitées sans compte", 1)[1].split("\n## ", 1)[0]
    assert "Journal de sécurité" in guests and "365 jours" in guests and "adresse IP" in guests


def test_system_journal_is_kept_thirty_days_as_the_notice_says():
    """Mentions validées le 29/09/2026 : journaux techniques 30 jours. L'installateur pose la durée."""
    from pathlib import Path

    root = Path(__file__).resolve().parent.parent
    dropin = (root / "config" / "journald-synunnel.conf").read_text()
    assert "[Journal]" in dropin and "MaxRetentionSec=30day" in dropin
    installer = (root / "scripts" / "install.sh").read_text()
    assert "/etc/systemd/journald.conf.d/synunnel.conf" in installer
    assert "systemctl restart systemd-journald" in installer
    template = (root / "docs" / "modeles" / "confidentialite.md").read_text()
    assert "**30 jours**" in template.split("## Toute personne qui visite l'instance", 1)[1]


def test_journal_retention_is_applied_on_every_run_and_web_logs_skip_syslog():
    """Troisième passe Codex, constats 19 et 20 : un redémarrage de journald raté n'était jamais repris (le
    fichier, déjà identique, sautait l'étape), et la copie rsyslog des journaux web dépassait 30 jours."""
    from pathlib import Path

    root = Path(__file__).resolve().parent.parent
    installer = (root / "scripts" / "install.sh").read_text()
    journald = installer[installer.index("install -d -o root -g root -m 0755 /etc/systemd/journald.conf.d"):]
    journald = journald[:journald.index("systemctl restart systemd-journald")]
    assert "cmp -s" not in journald
    rsyslog = (root / "config" / "rsyslog-synunnel.conf").read_text()
    assert "$programname == 'caddy'" in rsyslog and "$programname == 'synunnel'" in rsyslog and "stop" in rsyslog
    assert "/etc/rsyslog.d/10-synunnel.conf" in installer and "systemctl restart rsyslog" in installer
    assert "SyslogIdentifier=synunnel" in (root / "config" / "synunnel-journal.conf").read_text()
