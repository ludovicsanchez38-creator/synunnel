#!/usr/bin/env bash
set -euo pipefail
umask 077

# Installation idempotente pour Ubuntu 24.04. Exécuter depuis le dépôt avec sudo.
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ "$(id -u)" != 0 ]]; then
  printf 'Exécute ce script avec sudo.\n' >&2
  exit 1
fi
if [[ "$(. /etc/os-release; printf '%s' "$VERSION_ID")" != "24.04" ]]; then
  printf 'Ubuntu 24.04 requis.\n' >&2
  exit 1
fi

# Paramètres de l'instance. Premier lancement :
#   sudo env PUBLIC_IPV4=203.0.113.10 DASHBOARD_HOST=tunnel.example.org \
#     NS1_HOST=ns1.example.org NS2_HOST=ns2.example.org ACME_EMAIL=admin@example.org ./scripts/install.sh
# Lancements suivants : les valeurs déjà écrites dans /etc/synunnel/synunnel.env font foi.
if [[ -e /etc/synunnel/synunnel.env ]]; then
  if [[ -L /etc/synunnel/synunnel.env || "$(stat -c %U /etc/synunnel/synunnel.env)" != root ]] \
     || (( 8#$(stat -c %a /etc/synunnel/synunnel.env) & 8#022 )); then
    printf '/etc/synunnel/synunnel.env doit être un fichier de root, non modifiable par un autre compte.\n' >&2
    exit 1
  fi
  set -a
  # Fichier généré par ce script lors d'un lancement précédent, possédé par root.
  source /etc/synunnel/synunnel.env
  set +a
fi
for setting in PUBLIC_IPV4 PUBLIC_IPV6 DASHBOARD_HOST NS1_HOST NS2_HOST ACME_EMAIL SOA_RNAME REDIRECT_HOSTS \
  RESERVED_DOMAINS MAX_DOMAINS_PER_USER MAX_MACHINES_PER_USER MAX_ADDRESSES_PER_USER MAX_RECORDS_PER_DOMAIN \
  REQUIRE_2FA SMTP_HOST SMTP_PORT SMTP_USER SMTP_FROM SMTP_PASSWORD_FILE GUEST_CODES GUEST_CODES_WITH_2FA \
  OPERATOR_NAME ADMIN_CONTACT LEGAL_FILE PRIVACY_FILE; do
  if [[ "${!setting:-}" == *[$'\n\r']* ]]; then
    printf '%s ne doit pas contenir de retour à la ligne.\n' "$setting" >&2
    exit 1
  fi
done
missing=()
for setting in PUBLIC_IPV4 DASHBOARD_HOST NS1_HOST NS2_HOST ACME_EMAIL; do
  if [[ -z "${!setting:-}" ]]; then missing+=("$setting"); fi
done
if (( ${#missing[@]} )); then
  printf 'Paramètres manquants : %s\nVoir la section Installation du README.\n' "${missing[*]}" >&2
  exit 1
fi
PUBLIC_IPV6="${PUBLIC_IPV6:-}"
SOA_RNAME="${SOA_RNAME:-hostmaster.${DASHBOARD_HOST}.}"
REDIRECT_HOSTS="${REDIRECT_HOSTS:-}"
RESERVED_DOMAINS="${RESERVED_DOMAINS:-}"
MAX_DOMAINS_PER_USER="${MAX_DOMAINS_PER_USER:-20}"
MAX_MACHINES_PER_USER="${MAX_MACHINES_PER_USER:-10}"
MAX_ADDRESSES_PER_USER="${MAX_ADDRESSES_PER_USER:-50}"
MAX_RECORDS_PER_DOMAIN="${MAX_RECORDS_PER_DOMAIN:-200}"
REGISTRATION_MODE="${REGISTRATION_MODE:-invitation}"
# Double authentification exigée de tous les comptes (1) ou proposée (0).
REQUIRE_2FA="${REQUIRE_2FA:-0}"
# Envoi des mails (mot de passe oublié, alertes de sécurité) : SMTPS sur le port 465 seulement.
# Le mot de passe SMTP vit dans son propre fichier (SMTP_PASSWORD_FILE), jamais dans l'environnement.
SMTP_HOST="${SMTP_HOST:-}"
SMTP_PORT="${SMTP_PORT:-465}"
SMTP_USER="${SMTP_USER:-}"
SMTP_FROM="${SMTP_FROM:-}"
SMTP_PASSWORD_FILE="${SMTP_PASSWORD_FILE:-}"
# Accès invité par code mail (option par adresse) : permis par défaut, coupé si REQUIRE_2FA=1 sauf
# GUEST_CODES_WITH_2FA=1 (un invité n'a qu'un facteur, sa boîte mail).
GUEST_CODES="${GUEST_CODES:-1}"
GUEST_CODES_WITH_2FA="${GUEST_CODES_WITH_2FA:-0}"
for flag in REQUIRE_2FA GUEST_CODES GUEST_CODES_WITH_2FA; do
  if [[ "${!flag}" != 0 && "${!flag}" != 1 ]]; then
    printf '%s vaut 0 ou 1.\n' "$flag" >&2
    exit 1
  fi
done
MAIL_RE='^[A-Za-z0-9._+-]+@[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$'
# Exploitant de l'instance, affiché en pied de page et dans le mail des invités, et ses deux textes
# (Markdown, modèles dans docs/modeles/) : mentions légales et notice de confidentialité.
OPERATOR_NAME="${OPERATOR_NAME:-}"
ADMIN_CONTACT="${ADMIN_CONTACT:-}"
LEGAL_FILE="${LEGAL_FILE:-}"
PRIVACY_FILE="${PRIVACY_FILE:-}"
# Le nom est écrit entre apostrophes droites dans le fichier d'environnement, que bash et systemd relisent :
# ni apostrophe droite (l'apostrophe typographique ’ convient), ni guillemet, ni barre oblique inverse, ni $ ni `.
if (( ${#OPERATOR_NAME} > 120 )) || [[ "$OPERATOR_NAME" == *[\'\"\\\$\`]* ]]; then
  printf "OPERATOR_NAME : 120 caractères au plus, sans apostrophe droite (utilise ’), guillemet, \\, \$ ni \`.\n" >&2
  exit 1
fi
if [[ -n "$ADMIN_CONTACT" && ! "$ADMIN_CONTACT" =~ $MAIL_RE ]]; then
  printf 'ADMIN_CONTACT doit être une adresse mail.\n' >&2
  exit 1
fi
# Les fichiers que l'installateur remet à root:synunnel en 0640 restent dans /etc/synunnel/ : une faute de
# frappe ne peut pas changer les droits d'un fichier système.
for file_setting in SMTP_PASSWORD_FILE LEGAL_FILE PRIVACY_FILE; do
  if [[ -n "${!file_setting}" && ( ! "${!file_setting}" =~ ^/etc/synunnel/[A-Za-z0-9._-]+$ \
        || "${!file_setting}" == /etc/synunnel/synunnel.env || "${!file_setting}" == */.* ) ]]; then
    printf '%s doit désigner un fichier de /etc/synunnel/ (autre que synunnel.env).\n' "$file_setting" >&2
    exit 1
  fi
done
if [[ "$SMTP_PORT" != 465 ]]; then
  printf 'SMTP_PORT vaut 465 : seul SMTPS (TLS implicite) est pris en charge.\n' >&2
  exit 1
fi
SMTP_HOST_RE='^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$'
if [[ -n "$SMTP_HOST$SMTP_USER$SMTP_FROM$SMTP_PASSWORD_FILE" ]]; then
  if [[ ! "$SMTP_HOST" =~ $SMTP_HOST_RE || ! "$SMTP_USER" =~ $MAIL_RE || ! "$SMTP_FROM" =~ $MAIL_RE \
        || -z "$SMTP_PASSWORD_FILE" ]]; then
    printf 'SMTP : SMTP_HOST, SMTP_USER, SMTP_FROM et SMTP_PASSWORD_FILE vont ensemble et doivent être valides.\n' >&2
    exit 1
  fi
fi
if [[ "$REGISTRATION_MODE" != invitation && "$REGISTRATION_MODE" != approval ]]; then
  printf 'REGISTRATION_MODE vaut invitation ou approval.\n' >&2
  exit 1
fi
HOSTNAME_RE='^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$'
for list in REDIRECT_HOSTS RESERVED_DOMAINS; do
  IFS=, read -ra names <<< "${!list}"
  for name in "${names[@]}"; do
    if [[ ! "$name" =~ $HOSTNAME_RE ]]; then
      printf '%s contient un nom invalide : %s\n' "$list" "$name" >&2
      exit 1
    fi
  done
done
for quota in MAX_DOMAINS_PER_USER MAX_MACHINES_PER_USER MAX_ADDRESSES_PER_USER MAX_RECORDS_PER_DOMAIN; do
  if [[ ! "${!quota}" =~ ^[1-9][0-9]{0,2}$ ]]; then
    printf '%s doit être un entier entre 1 et 999.\n' "$quota" >&2
    exit 1
  fi
done
if [[ ! "$SOA_RNAME" =~ ^[a-z0-9.-]+\.$ || "$SOA_RNAME" == *..* ]]; then
  printf 'SOA_RNAME invalide.\n' >&2
  exit 1
fi
if [[ ! "$REPO_DIR" =~ ^[A-Za-z0-9._/-]+$ ]]; then
  printf 'Le chemin du dépôt ne doit contenir ni espace ni caractère spécial : %s\n' "$REPO_DIR" >&2
  exit 1
fi
if [[ ! "$PUBLIC_IPV4" =~ ^[0-9.]+$ || ! "$PUBLIC_IPV6" =~ ^[0-9a-fA-F:]*$ ]]; then
  printf 'Adresses publiques invalides (IPv4 en chiffres et points, IPv6 sans portée ni autre caractère).\n' >&2
  exit 1
fi
python3 -c 'import ipaddress,sys; ipaddress.IPv4Address(sys.argv[1]); sys.argv[2] and ipaddress.IPv6Address(sys.argv[2])' "$PUBLIC_IPV4" "$PUBLIC_IPV6"
for hostname in "$DASHBOARD_HOST" "$NS1_HOST" "$NS2_HOST"; do
  if [[ ! "$hostname" =~ $HOSTNAME_RE ]]; then
    printf 'Nom de serveur invalide : %s\n' "$hostname" >&2
    exit 1
  fi
done
if [[ ! "$ACME_EMAIL" =~ ^[a-zA-Z0-9._+@-]+$ ]]; then
  printf 'Adresse ACME invalide.\n' >&2
  exit 1
fi

# Paquets installés seulement une fois les paramètres vérifiés : rien ne change sur la machine avant.
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y pdns-server pdns-backend-sqlite3 caddy wireguard nftables python3-venv python3-pip \
  dnsutils acl ufw curl openssl

if ! id synunnel >/dev/null 2>&1; then
  useradd --system --home /var/lib/synunnel --shell /usr/sbin/nologin synunnel
fi
# Le service lit le dépôt là où il a été cloné : on lui ouvre seulement la traversée des
# répertoires parents qui ne sont pas déjà traversables par tous.
parent="$(dirname "$REPO_DIR")"
while [[ "$parent" != / ]]; do
  if [[ "$(stat -c %A "$parent")" != ?????????[xt] ]]; then
    acl="$(getfacl -cp "$parent" 2>/dev/null)"
    if grep -q '^user:synunnel:' <<< "$acl"; then
      : # Entrée posée par une installation précédente : on n'y touche plus.
    elif grep -Eq '^(user|group):[^:]+:|^mask::' <<< "$acl"; then
      # Ajouter une entrée recalculerait le masque et pourrait rendre des droits à d'autres comptes.
      printf '%s porte déjà des ACL : clone plutôt le dépôt dans /opt/synunnel.\n' "$parent" >&2
      exit 1
    else
      setfacl -m u:synunnel:--x "$parent"
    fi
  fi
  parent="$(dirname "$parent")"
done
if ! runuser -u synunnel -- test -r "$REPO_DIR/synunnel/__init__.py"; then
  printf "L'utilisateur synunnel ne peut pas lire %s : clone plutôt le dépôt dans /opt/synunnel.\n" "$REPO_DIR" >&2
  exit 1
fi
install -d -o synunnel -g synunnel -m 0750 /var/lib/synunnel
install -d -o root -g synunnel -m 0750 /etc/synunnel
install -d -o pdns -g pdns -m 0755 /var/lib/powerdns
install -d -o root -g root -m 0700 /etc/wireguard

if [[ ! -s /etc/wireguard/synunnel-server.key ]]; then
  wg genkey > /etc/wireguard/synunnel-server.key
  chmod 0600 /etc/wireguard/synunnel-server.key
fi
WG_PUBLIC_KEY="$(wg pubkey < /etc/wireguard/synunnel-server.key)"

if [[ ! -e /etc/synunnel/synunnel.env ]]; then
  SECRET_KEY="$(openssl rand -hex 32)"
  ADMIN_TOKEN="$(openssl rand -hex 32)"
  PDNS_API_KEY="$(openssl rand -hex 32)"
  cat > /etc/synunnel/synunnel.env <<EOF
SECRET_KEY=$SECRET_KEY
ADMIN_TOKEN=$ADMIN_TOKEN
PDNS_API_KEY=$PDNS_API_KEY
PDNS_API_URL=http://127.0.0.1:8081/api/v1/servers/localhost
DATABASE=/var/lib/synunnel/synunnel.db
PUBLIC_IPV4=$PUBLIC_IPV4
PUBLIC_IPV6=$PUBLIC_IPV6
WG_ENDPOINT=$PUBLIC_IPV4:51820
WG_SERVER_PUBLIC_KEY=$WG_PUBLIC_KEY
DASHBOARD_HOST=$DASHBOARD_HOST
NS1_HOST=$NS1_HOST
NS2_HOST=$NS2_HOST
SOA_RNAME=$SOA_RNAME
REDIRECT_HOSTS=$REDIRECT_HOSTS
ACME_EMAIL=$ACME_EMAIL
RESERVED_DOMAINS=$RESERVED_DOMAINS
MAX_DOMAINS_PER_USER=$MAX_DOMAINS_PER_USER
MAX_MACHINES_PER_USER=$MAX_MACHINES_PER_USER
MAX_ADDRESSES_PER_USER=$MAX_ADDRESSES_PER_USER
MAX_RECORDS_PER_DOMAIN=$MAX_RECORDS_PER_DOMAIN
REGISTRATION_MODE=$REGISTRATION_MODE
REQUIRE_2FA=$REQUIRE_2FA
SMTP_HOST=$SMTP_HOST
SMTP_PORT=$SMTP_PORT
SMTP_USER=$SMTP_USER
SMTP_FROM=$SMTP_FROM
SMTP_PASSWORD_FILE=$SMTP_PASSWORD_FILE
GUEST_CODES=$GUEST_CODES
GUEST_CODES_WITH_2FA=$GUEST_CODES_WITH_2FA
OPERATOR_NAME='$OPERATOR_NAME'
ADMIN_CONTACT=$ADMIN_CONTACT
LEGAL_FILE=$LEGAL_FILE
PRIVACY_FILE=$PRIVACY_FILE
SYNC_COMMAND='/usr/bin/sudo -n /usr/local/sbin/synunnel-sync'
EOF
fi
# Clé de chiffrement des secrets TOTP : générée une fois, jamais écrasée (la perdre rend illisibles
# les secrets déjà enregistrés, et les comptes concernés passent par un ticket de récupération).
if ! grep -q '^TOTP_KEY=' /etc/synunnel/synunnel.env; then
  printf 'TOTP_KEY=%s\n' "$(openssl rand -hex 32)" >> /etc/synunnel/synunnel.env
fi
# Une instance antérieure peut ne pas avoir toutes les clés : on complète le fichier sans rien écraser.
for setting in PUBLIC_IPV4 PUBLIC_IPV6 DASHBOARD_HOST NS1_HOST NS2_HOST SOA_RNAME REDIRECT_HOSTS ACME_EMAIL \
  RESERVED_DOMAINS MAX_DOMAINS_PER_USER MAX_MACHINES_PER_USER MAX_ADDRESSES_PER_USER MAX_RECORDS_PER_DOMAIN \
  REGISTRATION_MODE REQUIRE_2FA SMTP_HOST SMTP_PORT SMTP_USER SMTP_FROM SMTP_PASSWORD_FILE GUEST_CODES \
  GUEST_CODES_WITH_2FA OPERATOR_NAME ADMIN_CONTACT LEGAL_FILE PRIVACY_FILE; do
  if ! grep -q "^${setting}=" /etc/synunnel/synunnel.env; then
    # Entre apostrophes : toutes les valeurs validées plus haut en sont exemptes.
    printf "%s='%s'\n" "$setting" "${!setting}" >> /etc/synunnel/synunnel.env
  fi
done
chown root:synunnel /etc/synunnel/synunnel.env
chmod 0640 /etc/synunnel/synunnel.env
# Le fichier du mot de passe SMTP n'est jamais lu par ce script : on ne fait qu'en fixer les droits.
if [[ -n "$SMTP_PASSWORD_FILE" ]]; then
  if [[ -L "$SMTP_PASSWORD_FILE" || ! -f "$SMTP_PASSWORD_FILE" || "$(stat -c %U "$SMTP_PASSWORD_FILE")" != root ]]; then
    printf '%s doit être un fichier ordinaire de root (mot de passe SMTP seul).\n' "$SMTP_PASSWORD_FILE" >&2
    exit 1
  fi
  chown root:synunnel "$SMTP_PASSWORD_FILE"
  chmod 0640 "$SMTP_PASSWORD_FILE"
fi
# Mentions légales et notice de confidentialité : lisibles par le service, modifiables par root seul.
# Absentes, les deux pages publiques le disent : l'exploitant doit les publier avant d'ouvrir l'instance.
if [[ -z "$OPERATOR_NAME" ]]; then
  printf "Avertissement : OPERATOR_NAME non renseigné, le pied de page et le mail des invités ne nomment pas l'exploitant.\n" >&2
fi
if [[ -z "$ADMIN_CONTACT" ]]; then
  printf "Avertissement : ADMIN_CONTACT non renseigné, le mail des invités ne donne aucune adresse pour sortir d'une liste.\n" >&2
fi
for file_setting in LEGAL_FILE PRIVACY_FILE; do
  legal_path="${!file_setting}"
  if [[ -z "$legal_path" ]]; then
    printf 'Avertissement : %s non renseigné, la page correspondante indique « pas encore publié » (modèle dans docs/modeles/).\n' "$file_setting" >&2
  elif [[ -L "$legal_path" || ( -e "$legal_path" && ! -f "$legal_path" ) ]]; then
    printf '%s doit être un fichier ordinaire.\n' "$legal_path" >&2
    exit 1
  elif [[ ! -e "$legal_path" ]]; then
    printf 'Avertissement : %s absent, la page correspondante indique « pas encore publié ».\n' "$legal_path" >&2
  else
    chown root:synunnel "$legal_path"
    chmod 0640 "$legal_path"
  fi
done
set -a
# Fichier généré par ce script, possédé par root.
source /etc/synunnel/synunnel.env
set +a
LOCAL_ADDRESSES="$PUBLIC_IPV4"
if [[ -n "$PUBLIC_IPV6" ]]; then LOCAL_ADDRESSES+=",$PUBLIC_IPV6"; fi
if [[ ! "$SOA_RNAME" =~ ^[a-z0-9.-]+\.$ || "$SOA_RNAME" == *..* ]]; then
  printf 'SOA_RNAME invalide.\n' >&2
  exit 1
fi
export SOA_RNAME REDIRECT_HOSTS

if [[ -e /etc/powerdns/pdns.d/bind.conf ]]; then
  mv /etc/powerdns/pdns.d/bind.conf /etc/powerdns/pdns.d/bind.conf.disabled
fi
if [[ ! -e /var/lib/powerdns/synunnel.sqlite3 ]]; then
  runuser -u pdns -- python3 -c 'import pathlib, sqlite3; p="/var/lib/powerdns/synunnel.sqlite3"; s=pathlib.Path("/usr/share/pdns-backend-sqlite3/schema/schema.sqlite3.sql").read_text(); sqlite3.connect(p).executescript(s)'
fi
cat > /etc/powerdns/pdns.d/synunnel.conf <<EOF
launch=gsqlite3
gsqlite3-database=/var/lib/powerdns/synunnel.sqlite3
local-address=$LOCAL_ADDRESSES
local-port=53
api=yes
api-key=$PDNS_API_KEY
webserver=yes
webserver-address=127.0.0.1
webserver-allow-from=127.0.0.1
webserver-port=8081
disable-axfr=yes
version-string=anonymous
default-soa-content=$NS1_HOST. $SOA_RNAME 0 3600 600 1209600 300
EOF
chown root:pdns /etc/powerdns/pdns.d/synunnel.conf
chmod 0640 /etc/powerdns/pdns.d/synunnel.conf

# Dépendances figées : versions et empreintes de requirements.lock (généré depuis uv.lock par
# `uv export --frozen --no-dev --no-emit-project`), paquets binaires seulement, sans outils de
# développement ni installation éditable. L'environnement neuf est construit et vérifié à côté de
# l'ancien, qui continue de servir ; la bascule n'a lieu qu'une fois Caddy validé et les unités écrites.
VENV_NEW="$REPO_DIR/.venv.new"
(
  # L'environnement Python doit rester lisible par le service et par les tests.
  umask 022
  if [[ -e "$VENV_NEW" ]]; then
    python3 -c 'import shutil, sys; shutil.rmtree(sys.argv[1])' "$VENV_NEW"
  fi
  python3 -m venv "$VENV_NEW"
  "$VENV_NEW/bin/python" -m pip install --quiet --disable-pip-version-check --no-input \
    --require-hashes --only-binary=:all: --no-deps -r "$REPO_DIR/requirements.lock"
  # Le code de Synunnel est lu depuis le dépôt : un simple chemin, sans outil de construction téléchargé.
  PURELIB="$("$VENV_NEW/bin/python" -c 'import sysconfig; print(sysconfig.get_paths()["purelib"])')"
  printf '%s\n' "$REPO_DIR" > "$PURELIB/synunnel-repo.pth"
  (cd / && "$VENV_NEW/bin/python" -c 'import synunnel, cryptography, gunicorn') >/dev/null
)

# Bascule de l'environnement : l'ancien devient .venv.prev (gardé pour un retour rapide), le neuf .venv.
# Si le second renommage échoue, l'ancien est remis en place. Renommé, l'environnement garde un
# interpréteur valide (lien vers celui du système) mais ses scripts de console pointent encore vers
# .venv.new : les services passent donc par `python -m`.
swap_venv() {
  local repo="$1"
  if [[ -e "$repo/.venv.prev" ]]; then
    python3 -c 'import shutil, sys; shutil.rmtree(sys.argv[1])' "$repo/.venv.prev"
  fi
  if [[ -e "$repo/.venv" ]]; then
    mv "$repo/.venv" "$repo/.venv.prev"
  fi
  if ! mv "$repo/.venv.new" "$repo/.venv"; then
    if [[ -e "$repo/.venv.prev" && ! -e "$repo/.venv" ]]; then
      mv "$repo/.venv.prev" "$repo/.venv"
    fi
    printf "Bascule de l'environnement Python impossible : l'ancien est remis en place.\n" >&2
    return 1
  fi
  (cd / && "$repo/.venv/bin/python" -m gunicorn --version) >/dev/null
}

install -o root -g root -m 0755 "$REPO_DIR/scripts/synunnel-sync.py" /usr/local/sbin/synunnel-sync
cat > /etc/sudoers.d/synunnel <<'EOF'
synunnel ALL=(root) NOPASSWD: /usr/local/sbin/synunnel-sync
EOF
chmod 0440 /etc/sudoers.d/synunnel
visudo -cf /etc/sudoers.d/synunnel

# Caddy refuse d'importer un fichier vide : on amorce avec la ligne d'en-tête que
# synunnel-sync écrira ensuite à chaque synchronisation.
if [[ ! -s /etc/caddy/synunnel-routes.caddy ]]; then
  printf '# Routes générées depuis la base Synunnel. Ne pas éditer à la main.\n' > /etc/caddy/synunnel-routes.caddy
  chown root:root /etc/caddy/synunnel-routes.caddy
  chmod 0644 /etc/caddy/synunnel-routes.caddy
fi
CADDY_CANDIDATE="$(mktemp /etc/caddy/.synunnel-caddy.XXXXXX)"
"$VENV_NEW/bin/python" "$REPO_DIR/scripts/render-caddy.py" "$REPO_DIR/config/Caddyfile" "$CADDY_CANDIDATE"
caddy validate --config "$CADDY_CANDIDATE" --adapter caddyfile
if ! cmp -s "$CADDY_CANDIDATE" /etc/caddy/Caddyfile; then
  if [[ -e /etc/caddy/Caddyfile ]]; then
    cp -n /etc/caddy/Caddyfile /etc/caddy/Caddyfile.pre-synunnel-domain-2
  fi
  install -o root -g root -m 0644 "$CADDY_CANDIDATE" /etc/caddy/Caddyfile
fi
python3 -c 'import pathlib,sys; pathlib.Path(sys.argv[1]).unlink()' "$CADDY_CANDIDATE"
for unit in synunnel.service synunnel-reconcile.service synunnel-reconcile.timer; do
  sed "s#@REPO_DIR@#$REPO_DIR#g" "$REPO_DIR/config/$unit" > "/etc/systemd/system/$unit"
  chmod 0644 "/etc/systemd/system/$unit"
done
install -o root -g root -m 0644 "$REPO_DIR/config/wg0-firewall.nft" /etc/synunnel/wg0-firewall.nft
install -d -o root -g root -m 0755 /etc/systemd/system/caddy.service.d
install -o root -g root -m 0644 "$REPO_DIR/config/caddy-synunnel.conf" /etc/systemd/system/caddy.service.d/synunnel.conf

# Caddy validé, unités écrites et chargées (elles lancent `python -m gunicorn`, valable avec l'ancien comme
# avec le nouvel environnement) : la bascule peut avoir lieu, aucune unité chargée ne dépend plus des
# scripts de console de l'environnement.
systemctl daemon-reload
swap_venv "$REPO_DIR"
# Redémarrage complet : l'API d'administration de Caddy change de place (socket réservé à Caddy),
# un simple rechargement ne la déplacerait pas.
systemctl enable caddy
systemctl restart caddy
systemctl enable --now pdns
systemctl restart pdns
"$REPO_DIR/.venv/bin/python" "$REPO_DIR/scripts/migrate-authority.py"
"$REPO_DIR/.venv/bin/python" "$REPO_DIR/scripts/check-overlaps.py"
systemctl enable --now synunnel
systemctl enable --now synunnel-reconcile.timer
systemctl restart synunnel
for attempt in 1 2 3 4 5; do
  if curl --silent --fail http://127.0.0.1:8000/login >/dev/null; then break; fi
  sleep 1
done
curl --silent --fail http://127.0.0.1:8000/login >/dev/null
/usr/local/sbin/synunnel-sync
# Le tunnel doit revenir seul après un redémarrage du VPS.
systemctl enable wg-quick@wg0
# Mise à niveau d'une instance dont wg0 tournait déjà : on applique le pare-feu sans couper le tunnel.
if ip link show wg0 >/dev/null 2>&1 && ! nft -f /etc/synunnel/wg0-firewall.nft; then
  systemctl stop wg-quick@wg0
  printf 'Pare-feu du tunnel non appliqué : wg0 arrêté par précaution.\n' >&2
  exit 1
fi
caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile
systemctl reload caddy

# Ports publics nécessaires. UFW n'est pas activé par ce script : l'activer sans connaître
# l'accès SSH de la machine pourrait couper l'administrateur.
ufw allow 53/tcp
ufw allow 53/udp
ufw allow 80/tcp
ufw allow 443/tcp
ufw allow 51820/udp

printf 'Synunnel installé. Tableau de bord : https://%s (après ajout des DNS).\n' "$DASHBOARD_HOST"
if ! ufw status | grep -q '^Status: active'; then
  printf 'Attention : UFW est inactif. Autorise ton port SSH (ufw allow 22/tcp) puis lance ufw enable.\n'
  printf 'Le tunnel reste filtré par sa propre table nftables (synunnel_wg).\n'
fi
printf 'Jeton admin : /etc/synunnel/synunnel.env, à lire uniquement sur le VPS par une personne autorisée.\n'
