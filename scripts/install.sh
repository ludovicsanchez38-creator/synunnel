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

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y pdns-server pdns-backend-sqlite3 caddy wireguard nftables python3-venv python3-pip \
  dnsutils acl ufw curl openssl

# Paramètres de l'instance. Premier lancement :
#   sudo env PUBLIC_IPV4=203.0.113.10 DASHBOARD_HOST=tunnel.example.org \
#     NS1_HOST=ns1.example.org NS2_HOST=ns2.example.org ACME_EMAIL=admin@example.org ./scripts/install.sh
# Lancements suivants : les valeurs déjà écrites dans /etc/synunnel/synunnel.env font foi.
if [[ -e /etc/synunnel/synunnel.env ]]; then
  set -a
  # Fichier généré par ce script lors d'un lancement précédent, possédé par root.
  source /etc/synunnel/synunnel.env
  set +a
fi
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
if [[ ! "$REPO_DIR" =~ ^[A-Za-z0-9._/-]+$ ]]; then
  printf 'Le chemin du dépôt ne doit contenir ni espace ni caractère spécial : %s\n' "$REPO_DIR" >&2
  exit 1
fi
python3 -c 'import ipaddress,sys; ipaddress.IPv4Address(sys.argv[1]); sys.argv[2] and ipaddress.IPv6Address(sys.argv[2])' "$PUBLIC_IPV4" "$PUBLIC_IPV6"
for hostname in "$DASHBOARD_HOST" "$NS1_HOST" "$NS2_HOST"; do
  if [[ ! "$hostname" =~ ^[a-z0-9.-]+$ || "$hostname" != *.* ]]; then
    printf 'Nom de serveur invalide : %s\n' "$hostname" >&2
    exit 1
  fi
done
if [[ ! "$ACME_EMAIL" =~ ^[a-zA-Z0-9._+@-]+$ ]]; then
  printf 'Adresse ACME invalide.\n' >&2
  exit 1
fi

if ! id synunnel >/dev/null 2>&1; then
  useradd --system --home /var/lib/synunnel --shell /usr/sbin/nologin synunnel
fi
# Le service lit le dépôt là où il a été cloné : on lui ouvre seulement la traversée des
# répertoires parents qui ne sont pas déjà traversables par tous.
parent="$(dirname "$REPO_DIR")"
while [[ "$parent" != / ]]; do
  if [[ "$(stat -c %A "$parent")" != ?????????[xt] ]]; then
    setfacl -m u:synunnel:--x "$parent"
  fi
  parent="$(dirname "$parent")"
done
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
SYNC_COMMAND='/usr/bin/sudo -n /usr/local/sbin/synunnel-sync'
EOF
fi
for setting in DASHBOARD_HOST NS1_HOST NS2_HOST SOA_RNAME REDIRECT_HOSTS ACME_EMAIL; do
  if ! grep -q "^${setting}=" /etc/synunnel/synunnel.env; then
    printf '%s=%s\n' "$setting" "${!setting}" >> /etc/synunnel/synunnel.env
  fi
done
chown root:synunnel /etc/synunnel/synunnel.env
chmod 0640 /etc/synunnel/synunnel.env
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

(
  # L'environnement Python doit rester lisible par le service et par les tests.
  umask 022
  if [[ ! -d "$REPO_DIR/.venv" ]]; then
    python3 -m venv "$REPO_DIR/.venv"
  fi
  if command -v uv >/dev/null 2>&1; then
    uv pip install --python "$REPO_DIR/.venv/bin/python" -e "$REPO_DIR[dev]"
  else
    "$REPO_DIR/.venv/bin/python" -m pip install -e "$REPO_DIR[dev]"
  fi
)

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
"$REPO_DIR/.venv/bin/python" "$REPO_DIR/scripts/render-caddy.py" "$REPO_DIR/config/Caddyfile" "$CADDY_CANDIDATE"
caddy validate --config "$CADDY_CANDIDATE" --adapter caddyfile
if ! cmp -s "$CADDY_CANDIDATE" /etc/caddy/Caddyfile; then
  if [[ -e /etc/caddy/Caddyfile ]]; then
    cp -n /etc/caddy/Caddyfile /etc/caddy/Caddyfile.pre-synunnel-domain-2
  fi
  install -o root -g root -m 0644 "$CADDY_CANDIDATE" /etc/caddy/Caddyfile
fi
python3 -c 'import pathlib,sys; pathlib.Path(sys.argv[1]).unlink()' "$CADDY_CANDIDATE"
sed "s#@REPO_DIR@#$REPO_DIR#g" "$REPO_DIR/config/synunnel.service" > /etc/systemd/system/synunnel.service
chmod 0644 /etc/systemd/system/synunnel.service
install -o root -g root -m 0644 "$REPO_DIR/config/wg0-firewall.nft" /etc/synunnel/wg0-firewall.nft

systemctl daemon-reload
systemctl enable --now pdns
systemctl restart pdns
"$REPO_DIR/.venv/bin/python" "$REPO_DIR/scripts/migrate-authority.py"
systemctl enable --now synunnel
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
if ip link show wg0 >/dev/null 2>&1; then nft -f /etc/synunnel/wg0-firewall.nft; fi
caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile
systemctl enable --now caddy
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
