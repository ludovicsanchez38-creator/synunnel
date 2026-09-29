"""Non-régression des sept bloquants relevés par l'UltraJury du 29/09/2026 avant la mise en production de la 0.2."""
# ruff: noqa: F811

import re

from test_app import add_domain, app, claim_domain, register_approve_login  # noqa: F401

TITLE = re.compile(r"<title>(.*?)</title>", re.DOTALL)


def test_page_titles_never_contain_markup_or_csrf_token(app):
    """Bloquant 1 : le bloc title de domain.html avalait la section de suppression et le jeton CSRF."""
    client = app.test_client()
    anonymous = ["/login", "/register", "/forgot", "/reset", "/recover"]
    for path in anonymous:
        body = client.get(path).data.decode()
        titles = TITLE.findall(body)
        assert titles, path
        for title in titles:
            assert "<" not in title and "csrf" not in title.lower(), (path, title[:120])
    register_approve_login(app, client, "titres@example.org")
    domain_id = add_domain(client, "titres.example")
    claim_id, _proof = claim_domain(client, "autre-titre.example")
    for path in ["/dashboard", "/tokens", "/security", f"/domains/{domain_id}", f"/claims/{claim_id}"]:
        response = client.get(path)
        assert response.status_code == 200, path
        for title in TITLE.findall(response.data.decode()):
            assert "<" not in title and "csrf" not in title.lower(), (path, title[:120])


COUNTED = ("attempts", "guest_quota", "guest_challenges", "login_challenges", "password_resets", "security_events",
           "users")


def _counts(app) -> dict:
    from synunnel.db import get_db
    with app.app_context():
        db = get_db()
        return {table: db.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] for table in COUNTED}


def test_head_behaves_like_get_and_writes_nothing(app):
    """Bloquant 2 : HEAD passait dans la branche POST des vues, hors du contrôle CSRF."""
    paths = ["/login", "/register", "/forgot", "/reset?token=abc", "/recover", "/security/email/confirm?token=abc",
             "/access/code?next=https%3A%2F%2Fnas.example%2F", "/access/verify", "/login/2fa", "/__synunnel/logout"]
    client = app.test_client()
    before = _counts(app)
    for path in paths:
        get = client.get(path)
        head = client.head(path)
        assert head.status_code == get.status_code, (path, get.status_code, head.status_code)
        assert head.data == b"", path
    # Une session qui porte un challenge de connexion : HEAD ne doit ni consommer ni compter un essai.
    with client.session_transaction() as state:
        state["challenge"] = "challenge-fictif"
    assert client.head("/login/2fa").status_code == client.get("/login/2fa").status_code
    assert _counts(app) == before


def test_csrf_is_required_for_every_method_except_safe_ones(app):
    client = app.test_client()
    for method in ("POST", "PUT", "PATCH", "DELETE"):
        response = client.open("/forgot", method=method, data={"email": "x@example.org"})
        assert response.status_code in {400, 405}, (method, response.status_code)
        if method == "POST":
            assert response.status_code == 400


def test_dependencies_are_pinned_patched_and_installed_from_the_lock():
    """Bloquant 3 : cryptography < 47 (7 avis connus) et installation hors verrou, outils de dev compris."""
    import tomllib
    from pathlib import Path

    root = Path(__file__).resolve().parent.parent
    lock = {p["name"]: p["version"] for p in tomllib.loads((root / "uv.lock").read_text())["package"]}
    pinned = dict(re.findall(r"^([A-Za-z0-9_.-]+)==([^\s\;]+)", (root / "requirements.lock").read_text(), re.MULTILINE))
    assert pinned, "requirements.lock vide"
    for name, version in pinned.items():
        assert lock.get(name) == version, f"{name} : {version} dans requirements.lock, {lock.get(name)} dans uv.lock"
    major, minor, patch = (int(x) for x in pinned["cryptography"].split(".")[:3])
    assert (major, minor, patch) >= (50, 0, 1)
    assert "--hash=sha256:" in (root / "requirements.lock").read_text()
    for dev in ("pytest", "ruff"):
        assert dev not in pinned
    installer = (root / "scripts" / "install.sh").read_text()
    assert "--require-hashes" in installer and "requirements.lock" in installer
    assert "[dev]" not in installer and "install -e" not in installer


ADMIN = {"Authorization": "Bearer test-admin-token-only"}


def test_admin_api_is_refused_through_the_public_proxy(app):
    """Bloquant 4 : l'API d'administration ne répond qu'en local, jamais à travers Caddy."""
    client = app.test_client()
    assert client.get("/admin/api/pending", headers=ADMIN).status_code == 200
    for proxied in ({"X-Real-IP": "203.0.113.9"}, {"X-Forwarded-For": "203.0.113.9"}):
        response = client.get("/admin/api/pending", headers={**ADMIN, **proxied})
        assert response.status_code == 404, proxied


def test_admin_limiter_applies_before_the_token_comparison(app):
    client = app.test_client()
    for _ in range(20):
        assert client.get("/admin/api/pending", headers={"Authorization": "Bearer mauvais"}).status_code == 401
    # Au-delà du plafond, même le bon jeton attend : la comparaison n'est plus tentée.
    assert client.get("/admin/api/pending", headers=ADMIN).status_code == 429


def test_caddy_template_hides_admin_api_on_the_public_name():
    import importlib.util
    from pathlib import Path

    root = Path(__file__).resolve().parent.parent
    spec = importlib.util.spec_from_file_location("render_caddy", root / "scripts" / "render-caddy.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    rendered = module.render_caddy((root / "config" / "Caddyfile").read_text(), "synunnel.fr", "", "admin@example.org")
    block = rendered.split("handle @synunnel_dashboard {", 1)[1].split("# __REDIRECT", 1)[0]
    admin = block.index("path /admin/*")
    assert block.index("respond 404", admin) < block.index("reverse_proxy 127.0.0.1:8000")


def test_post_without_csrf_token_is_still_refused_on_every_form(app):
    client = app.test_client()
    for path in ["/login", "/register", "/forgot", "/reset", "/recover", "/security/email/confirm", "/access/code",
                 "/access/verify", "/login/2fa", "/__synunnel/logout"]:
        assert client.post(path, data={"email": "x@example.org"}).status_code == 400, path
    before = _counts(app)
    for _ in range(20):
        client.head("/forgot")
        client.head("/access/code?next=https%3A%2F%2Fnas.example%2F")
    assert _counts(app) == before


def test_totp_secret_sealed_with_cryptography_46_still_opens_after_the_upgrade():
    """Bloquant 3 : un secret chiffré en production sous cryptography 46.0.7 reste lisible en 50.x."""
    from synunnel import security

    sealed_by_46 = "v1:AAECAwQFBgcICQoLItGFJ06VAswtiOKt95vCEP6ZOVjlAmxBE+9+WY2EorzBB9uw"
    assert security.decrypt_secret(bytes.fromhex("11" * 32), 42, sealed_by_46) == b"12345678901234567890"


def _zone_removals(app) -> int:
    from synunnel.db import get_db
    with app.app_context():
        return get_db().execute("SELECT COUNT(*) FROM zone_removals").fetchone()[0]


def _domain_exists(app, domain_id: int) -> bool:
    from synunnel.db import get_db
    with app.app_context():
        return get_db().execute("SELECT 1 FROM domains WHERE id=?", (domain_id,)).fetchone() is not None


def test_delegated_domain_cannot_be_deleted_and_deletion_needs_the_retyped_name(app, monkeypatch):
    """Bloquant 5 : un domaine encore délégué se supprimait en un clic, site et messagerie coupés."""
    from test_app import csrf

    client = app.test_client()
    register_approve_login(app, client, "suppr@example.org")
    domain_id = add_domain(client, "suppr.example")
    page = client.get(f"/domains/{domain_id}").data.decode()
    assert f'/domains/{domain_id}/delete"' in page and 'method="post" action="/domains/' + str(domain_id) + '/delete"' not in page
    confirm = client.get(f"/domains/{domain_id}/delete")
    assert confirm.status_code == 200 and b'name="confirm_name"' in confirm.data
    for state, code in ((True, "encore délégué"), (None, "Impossible de vérifier")):
        monkeypatch.setattr("synunnel.actions.delegation_status", lambda domain, ns, state=state: (state, []))
        response = client.post(f"/domains/{domain_id}/delete", data={"csrf_token": csrf(client),
                                                                   "confirm_name": "suppr.example"})
        assert response.status_code == 302 and _domain_exists(app, domain_id)
        assert code in client.get(response.headers["Location"]).data.decode()
    assert _zone_removals(app) == 0
    monkeypatch.setattr("synunnel.actions.delegation_status", lambda domain, ns: (False, []))
    wrong = client.post(f"/domains/{domain_id}/delete", data={"csrf_token": csrf(client), "confirm_name": "autre.example"})
    assert wrong.status_code == 302 and _domain_exists(app, domain_id)
    done = client.post(f"/domains/{domain_id}/delete", data={"csrf_token": csrf(client), "confirm_name": "Suppr.Example."})
    assert done.status_code == 302 and not _domain_exists(app, domain_id)


def test_api_refuses_to_delete_a_delegated_domain(app, monkeypatch):
    from test_api import bearer, create_token

    client = app.test_client()
    register_approve_login(app, client, "api-suppr@example.org")
    domain_id = add_domain(client, "api-suppr.example")
    token = create_token(client)
    monkeypatch.setattr("synunnel.actions.delegation_status", lambda domain, ns: (True, ["ns1.synunnel.fr."]))
    refused = client.delete(f"/api/v1/domains/{domain_id}", headers=bearer(token))
    assert refused.status_code == 409 and refused.json["error"]["code"] == "delegation_active"
    assert _domain_exists(app, domain_id) and _zone_removals(app) == 0
    monkeypatch.setattr("synunnel.actions.delegation_status", lambda domain, ns: (False, []))
    assert client.delete(f"/api/v1/domains/{domain_id}", headers=bearer(token)).status_code == 200
    assert not _domain_exists(app, domain_id)


def test_services_start_through_the_venv_interpreter_not_a_console_script():
    """Les services passent par l'interpréteur de l'environnement (`python -m gunicorn`), jamais par un
    script de console : une ancienne installation renommait son environnement, ce qui cassait ces scripts."""
    from pathlib import Path

    root = Path(__file__).resolve().parent.parent
    for unit in sorted((root / "config").glob("*.service")):
        for line in unit.read_text().splitlines():
            if line.startswith("ExecStart="):
                assert line.startswith("ExecStart=@REPO_DIR@/.venv/bin/python "), (unit.name, line)
    installer = (root / "scripts" / "install.sh").read_text()
    assert '"$REPO_DIR/.venv/bin/python" -m gunicorn --version' in installer


def _installer() -> str:
    from pathlib import Path

    return (Path(__file__).resolve().parent.parent / "scripts" / "install.sh").read_text()


def test_environment_is_swapped_only_once_caddy_and_units_are_ready():
    """Constat 5 de la revue Codex : bascule avant la validation Caddy et l'écriture des unités, une instance
    arrêtée entre les deux ne redémarrait plus (ancienne unité, scripts du nouvel environnement cassés)."""
    script = _installer()
    build = script.index('python3 -m venv "$VENV_NEW"')
    validate = script.index('caddy validate --config "$CADDY_CANDIDATE"')
    units = script.index('> "$UNIT_DIR/$unit"')
    swap = script.index('swap_venv "$REPO_DIR"')
    reload = script.index("\nsystemctl daemon-reload\n", units)
    # Unités chargées avant la bascule : un arrêt entre les deux laisse systemd sur `python -m gunicorn`,
    # jamais sur l'ancien `.venv/bin/gunicorn` face à un environnement dont les scripts pointent ailleurs.
    assert build < validate < units < reload < swap
    assert 'VENV_NEW="$REPO_DIR/.venvs/' in script and 'mv "$VENV_NEW"' not in script


def _venv_functions() -> str:
    """Fonctions de bascule de l'installateur, extraites telles quelles pour être jouées sur un faux dépôt."""
    script = _installer()
    start = script.index("# --- bascule de l'environnement : début")
    return script[start:script.index("# --- bascule de l'environnement : fin")]


def _bash(tmp_path, code: str, path_dir=None):
    """Fonctions de bascule jouées sur un faux dépôt ; systemctl et le dossier des unités sont toujours
    simulés, jamais ceux de la machine qui lance les tests."""
    import os
    import subprocess

    fake = tmp_path / "systeme-simule"
    (fake / "bin").mkdir(parents=True, exist_ok=True)
    (fake / "unites").mkdir(exist_ok=True)
    (fake / "avant").mkdir(exist_ok=True)
    systemctl = fake / "bin" / "systemctl"
    if not systemctl.exists():
        systemctl.write_text(f"#!/bin/sh\necho \"$*\" >> {tmp_path}/systemctl.log\n")
        systemctl.chmod(0o755)
    path = ":".join(str(item) for item in (path_dir, fake / "bin") if item) + ":" + os.environ["PATH"]
    prelude = f'UNIT_DIR="{fake}/unites"; UNITS_PREVIOUS="{fake}/avant"; '
    return subprocess.run(["bash", "-c", _venv_functions() + prelude + code], capture_output=True, text=True,
                          check=False, env={"PATH": path}, cwd=tmp_path)


def _legacy_repo(tmp_path):
    repo = tmp_path / "depot"
    (repo / ".venv").mkdir(parents=True)
    (repo / ".venv" / "ancien").write_text("x")
    (repo / ".venvs" / "neuf").mkdir(parents=True)
    (repo / ".venvs" / "neuf" / "neuf").write_text("x")
    return repo


def test_versioned_environment_is_switched_by_an_atomic_link(tmp_path):
    """Constat 5 (résidu) : chaque environnement garde son chemin, .venv n'est qu'un lien basculé d'un seul
    renommage ; l'ancien répertoire .venv d'une installation précédente est rangé et reste désigné."""
    repo = _legacy_repo(tmp_path)
    run = _bash(tmp_path, f'swap_venv "{repo}" ".venvs/neuf" && disarm_runtime_rollback && printf "%s" "$VENV_PREVIOUS"')
    assert run.returncode == 0, run.stderr
    assert (repo / ".venv").is_symlink() and (repo / ".venv" / "neuf").exists()
    previous = run.stdout
    assert previous.startswith(".venvs/ancien-") and (repo / previous / "ancien").exists()
    (repo / ".venvs" / "suivant").mkdir()
    run = _bash(tmp_path, f'swap_venv "{repo}" ".venvs/suivant" && disarm_runtime_rollback && printf "%s" "$VENV_PREVIOUS"')
    assert run.returncode == 0 and run.stdout == ".venvs/neuf" and (repo / ".venv").resolve().name == "suivant"
    run = _bash(tmp_path, f'rollback_venv "{repo}" ".venvs/neuf"')
    assert run.returncode == 0 and (repo / ".venv").resolve().name == "neuf"


def test_interrupted_or_failed_switch_puts_the_previous_environment_back(tmp_path):
    repo = _legacy_repo(tmp_path)
    shims = tmp_path / "shims"
    shims.mkdir()
    # Signal reçu entre le rangement de l'ancien répertoire et la pose du lien.
    (shims / "ln").write_text("#!/bin/sh\nkill -TERM $PPID\nsleep 0.2\nexit 1\n")
    (shims / "ln").chmod(0o755)
    run = _bash(tmp_path, f'swap_venv "{repo}" ".venvs/neuf"', path_dir=shims)
    assert run.returncode != 0
    assert (repo / ".venv").is_dir() and not (repo / ".venv").is_symlink() and (repo / ".venv" / "ancien").exists()
    # Échec simple de la pose du lien.
    (shims / "ln").write_text("#!/bin/sh\nexit 1\n")
    run = _bash(tmp_path, f'swap_venv "{repo}" ".venvs/neuf"', path_dir=shims)
    assert run.returncode != 0 and (repo / ".venv" / "ancien").exists()


def _runtime(tmp_path):
    """Faux dépôt déjà basculé, unités d'avant gardées de côté, systemctl simulé qui note ses appels."""
    repo = _legacy_repo(tmp_path)
    units, previous, shims = tmp_path / "unites", tmp_path / "avant", tmp_path / "shims"
    for folder in (units, previous, shims):
        folder.mkdir()
    (units / "synunnel.service").write_text("nouvelle")
    (previous / "synunnel.service").write_text("ancienne")
    (shims / "systemctl").write_text(f"#!/bin/sh\necho \"$*\" >> {tmp_path}/systemctl.log\n")
    (shims / "systemctl").chmod(0o755)
    prelude = (f'REPO_DIR="{repo}"; UNIT_DIR="{units}"; UNITS_PREVIOUS="{previous}"; set -e; '
               f'swap_venv "{repo}" ".venvs/neuf"; ')
    return repo, units, shims, prelude


def test_any_failure_or_signal_before_the_health_check_restores_the_previous_runtime(tmp_path):
    """Troisième passe Codex, constat 5 : un signal après la pose du lien, pendant le contrôle de santé, ou
    un échec d'une commande avant lui, laissait le nouvel environnement actif."""
    for ending in ("false", "kill -TERM $$; sleep 1"):
        case = tmp_path / ending.split()[0]
        case.mkdir()
        repo, units, shims, prelude = _runtime(case)
        run = _bash(case, prelude + ending + "; echo jamais", path_dir=shims)
        assert run.returncode != 0 and "jamais" not in run.stdout, ending
        assert (repo / ".venv" / "ancien").exists(), ending
        assert (units / "synunnel.service").read_text() == "ancienne", ending
        assert "daemon-reload" in (case / "systemctl.log").read_text(), ending


def test_healthy_runtime_is_kept_once_the_rollback_is_disarmed(tmp_path):
    repo, units, shims, prelude = _runtime(tmp_path)
    run = _bash(tmp_path, prelude + "disarm_runtime_rollback; exit 0", path_dir=shims)
    assert run.returncode == 0 and (repo / ".venv" / "neuf").exists()
    assert (units / "synunnel.service").read_text() == "nouvelle"


def test_pruning_keeps_the_current_and_previous_environments_even_through_an_absolute_link(tmp_path):
    """Constat 18 : un lien absolu vers l'environnement précédent le faisait supprimer au nettoyage."""
    repo = tmp_path / "depot"
    for name in ("v0", "v1", "v2", "ancien-x"):
        (repo / ".venvs" / name).mkdir(parents=True)
    run = _bash(tmp_path, f'prune_venvs "{repo}" ".venvs/v2" "{repo}/.venvs/v0"')
    assert run.returncode == 0, run.stderr
    assert sorted(item.name for item in (repo / ".venvs").iterdir()) == ["v0", "v2"]


def test_installer_arms_the_rollback_through_the_swap_and_disarms_it_only_when_healthy():
    script = _installer()
    swap = script.index('swap_venv "$REPO_DIR" ".venvs/$VENV_ID"')
    healthy = script.index("if ! service_healthy; then")
    disarm = script.index("disarm_runtime_rollback", healthy)
    assert swap < healthy < disarm
    assert "arm_runtime_rollback" in script[script.index("swap_venv() {"):script.index("rollback_venv() {")]

def test_admin_api_requires_a_loopback_peer_and_no_proxy_header_even_empty(app):
    """Constat 9 de la revue Codex : la garde reposait sur la valeur des en-têtes, pas sur l'origine."""
    client = app.test_client()
    assert client.get("/admin/api/pending", headers=ADMIN).status_code == 200
    assert client.get("/admin/api/pending", headers=ADMIN, environ_base={"REMOTE_ADDR": "::1"}).status_code == 200
    remote = client.get("/admin/api/pending", headers=ADMIN, environ_base={"REMOTE_ADDR": "203.0.113.8"})
    assert remote.status_code == 404
    for empty in ({"X-Forwarded-For": ""}, {"X-Real-IP": ""}):
        assert client.get("/admin/api/pending", headers={**ADMIN, **empty}).status_code == 404, empty



def test_signal_right_after_the_link_is_renamed_restores_the_previous_environment(tmp_path):
    """Quatrième passe Codex, constat 5 : un signal entre le renommage du lien et l'armement du retour
    complet laissait le nouvel environnement actif. Le retour est armé avant tout geste."""
    for legacy in (True, False):
        case = tmp_path / ("historique" if legacy else "versionne")
        case.mkdir()
        repo = _legacy_repo(case)
        if not legacy:
            _bash(case, f'swap_venv "{repo}" ".venvs/neuf" && disarm_runtime_rollback')
            (repo / ".venvs" / "suivant").mkdir()
        shims = case / "shims"
        shims.mkdir()
        # mv réel, puis signal au script aussitôt le lien renommé.
        (shims / "mv").write_text('#!/bin/sh\n/bin/mv "$@" || exit $?\n'
                                  'case "$*" in *.venv.lien*) kill -TERM $PPID; sleep 0.3;; esac\n')
        (shims / "mv").chmod(0o755)
        target = ".venvs/neuf" if legacy else ".venvs/suivant"
        run = _bash(case, f'REPO_DIR="{repo}"; set -e; swap_venv "{repo}" "{target}"; echo jamais', path_dir=shims)
        assert run.returncode != 0 and "jamais" not in run.stdout, legacy
        if legacy:
            assert (repo / ".venv" / "ancien").exists()
        else:
            assert (repo / ".venv").resolve().name == "neuf"


def test_journal_identifier_lives_in_a_dropin_that_the_rollback_keeps():
    """Quatrième passe Codex, constat 20 : le retour arrière remettait une unité sans SyslogIdentifier,
    dont les journaux échappaient au filtre rsyslog. L'identifiant vit dans un drop-in séparé."""
    from pathlib import Path

    root = Path(__file__).resolve().parent.parent
    assert "SyslogIdentifier=synunnel" in (root / "config" / "synunnel-journal.conf").read_text()
    installer = _installer()
    assert "/etc/systemd/system/synunnel.service.d/journal.conf" in installer
    restore = installer[installer.index("restore_previous_runtime() {"):installer.index("arm_runtime_rollback() {")]
    assert "synunnel.service.d" not in restore
