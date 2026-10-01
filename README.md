# Synunnel

Synunnel publie des services hébergés chez vous (un NAS, une domotique, un petit site) sur votre propre nom de domaine, en HTTPS, sans ouvrir le moindre port sur votre box. Un VPS sert de porte d'entrée : il répond pour votre domaine, obtient les certificats et relaie le trafic vers vos machines par un tunnel WireGuard.

> **Version 0.2 alpha.** Synunnel fonctionne de bout en bout et a été testé sur une installation neuve, mais il reste jeune. Réservez-le pour l'instant à des usages personnels ou à des proches de confiance, lisez les [limites connues](docs/SECURITE.md#limites-connues-de-la-v02-alpha) et gardez une sauvegarde de votre zone DNS actuelle avant toute délégation.

*In English: Synunnel is a self-hosted alternative to tunnel services. A single VPS runs an authoritative DNS server (PowerDNS), an HTTPS reverse proxy with on-demand certificates (Caddy) and a WireGuard hub; users delegate their own domain to it and expose services from machines behind NAT. Code comments and docs are in French. MIT licensed, alpha quality.*

## Où en est le projet

Le développement de Synunnel a commencé le 27 septembre 2026, la version 0.2 alpha était prête trois jours plus tard, et elle tourne sur synunnel.fr depuis le 1er octobre. Le code a été écrit par Codex sur un cahier des charges de Syn, l'assistante IA de Synoptïa, puis relu avant d'être publié : un audit par douze experts IA, dont les sept défauts bloquants ont été corrigés, six passes de revue de Codex, 203 tests automatiques et un essai de bout en bout sur une installation neuve.

Ce qui manque encore, ce sont des essais par d'autres personnes que son auteur : un seul domaine y est branché aujourd'hui, et les premiers essais avec des proches commencent. Si vous l'installez, traitez-le comme une alpha et dites-nous ce qui casse (les failles se signalent en privé, voir [SECURITY.md](SECURITY.md)).

## Comment ça marche

```
Navigateur ──HTTPS──> Caddy (VPS) ──WireGuard──> votre machine :port
Registrar ──NS──────> PowerDNS (VPS) : votre zone, recopiée puis gérée ici
```

1. L'administrateur vous remet un code d'invitation ; il ouvre votre compte sur le tableau de bord de l'instance.
2. Vous ajoutez votre domaine et prouvez qu'il vous appartient avec un enregistrement TXT. Synunnel recopie alors vos enregistrements publics (mail compris) dans sa propre zone.
3. Après vérification de cette copie, vous déléguez le domaine aux deux serveurs de noms de l'instance chez votre registrar.
4. Vous connectez une machine : Synunnel génère une configuration WireGuard, affichée une seule fois.
5. Vous publiez une adresse (`nas.mondomaine.fr` vers la machine et le port de votre choix), publique ou réservée à votre connexion, avec une liste de comptes invités si besoin.

## Prérequis

- Un VPS **Ubuntu 24.04** avec une IPv4 publique (IPv6 facultative), un accès SSH par clé et les ports 53 (TCP et UDP), 80, 443 et 51820/UDP joignables.
- Un nom de domaine pour l'instance elle-même, par exemple `example.org`, avec chez son hébergeur DNS :

| Nom | Type | Valeur |
| --- | --- | --- |
| `tunnel.example.org` | A (et AAAA si IPv6) | IP du VPS |
| `ns1.example.org` | A (et AAAA si IPv6) | IP du VPS |
| `ns2.example.org` | A (et AAAA si IPv6) | IP du VPS |

Les deux serveurs de noms désignent ici la même machine. Certains registrars, notamment pour les `.fr`, exigent deux serveurs réellement distincts : renseignez-vous avant de choisir vos domaines.

## Installation

```bash
sudo git clone <adresse du dépôt> /opt/synunnel
cd /opt/synunnel
sudo env PUBLIC_IPV4=203.0.113.10 \
  DASHBOARD_HOST=tunnel.example.org \
  NS1_HOST=ns1.example.org NS2_HOST=ns2.example.org \
  ACME_EMAIL=admin@example.org \
  ./scripts/install.sh
```

Paramètres facultatifs : `PUBLIC_IPV6`, `SOA_RNAME` (par défaut `hostmaster.<DASHBOARD_HOST>.`), `REDIRECT_HOSTS` (noms supplémentaires redirigés vers le tableau de bord, séparés par des virgules), `RESERVED_DOMAINS` (domaines que les comptes ne pourront pas revendiquer), les quotas `MAX_DOMAINS_PER_USER` (20), `MAX_MACHINES_PER_USER` (10), `MAX_ADDRESSES_PER_USER` (50), `MAX_RECORDS_PER_DOMAIN` (200), et `REQUIRE_2FA=1` pour imposer la double authentification à tous les comptes.

**Envoi de mails** (facultatif : lien de mot de passe oublié, vérification d'adresse, alertes de sécurité). SMTPS sur le port 465 seulement. Déposez d'abord le mot de passe de la boîte d'envoi dans un fichier de root, puis passez les réglages :

```bash
sudo install -m 0600 /dev/null /etc/synunnel/smtp-password && sudo nano /etc/synunnel/smtp-password
sudo env SMTP_HOST=smtp.example.org SMTP_USER=noreply@example.org SMTP_FROM=noreply@example.org \
  SMTP_PASSWORD_FILE=/etc/synunnel/smtp-password ./scripts/install.sh
```

Si `/etc/synunnel/synunnel.env` contient déjà des lignes `SMTP_*` (même vides), ce sont elles qui font foi : renseignez-les dans ce fichier, puis relancez le script. Le script ne lit jamais le fichier du mot de passe : il en fixe seulement les droits (root:synunnel, 0640). Publiez SPF, DKIM et DMARC pour le domaine d'envoi chez son hébergeur DNS. Sans ces réglages, le mot de passe oublié passe par un ticket de l'administrateur.

**Mentions légales et confidentialité** (à publier avant d'ouvrir l'instance au public). Complétez les modèles [docs/modeles/mentions-legales.md](docs/modeles/mentions-legales.md) et [docs/modeles/confidentialite.md](docs/modeles/confidentialite.md), déposez-les dans `/etc/synunnel/`, puis, au premier lancement ou sur une instance dont `/etc/synunnel/synunnel.env` n'a pas encore ces lignes, passez les réglages au script :

```bash
sudo install -m 0640 mentions-legales.md confidentialite.md /etc/synunnel/
sudo env OPERATOR_NAME="Exemple SAS" ADMIN_CONTACT=contact@example.org \
  LEGAL_FILE=/etc/synunnel/mentions-legales.md PRIVACY_FILE=/etc/synunnel/confidentialite.md ./scripts/install.sh
```

Si `/etc/synunnel/synunnel.env` contient déjà les lignes `OPERATOR_NAME`, `ADMIN_CONTACT`, `LEGAL_FILE` et `PRIVACY_FILE` (même vides, ce qui est le cas après une installation faite sans elles), ce sont elles qui font foi : renseignez-les dans ce fichier, entre apostrophes droites (`OPERATOR_NAME='Exemple SAS'`, `LEGAL_FILE='/etc/synunnel/mentions-legales.md'`), puis relancez `sudo ./scripts/install.sh`, qui vérifie les valeurs et donne aux deux fichiers leurs droits (root:synunnel, 0640) ; `sudo systemctl restart synunnel` ne suffit pas pour ces droits.

Les pages `/mentions-legales` et `/confidentialite` sont liées en pied de page et sous chaque formulaire ; le nom de l'exploitant et l'adresse de contact apparaissent aussi dans le mail envoyé aux invités, avec le lien vers la notice. Les textes sont relus à chaque affichage : les modifier ne demande pas de redémarrage. Ils acceptent titres (`#`), paragraphes, listes, gras et liens `https`, `mailto` ou vers une page de l'instance ; tout autre balisage est affiché tel quel. `OPERATOR_NAME` s'écrit sans apostrophe droite (utilisez ’), guillemet, `\`, `$` ni `` ` ``. Sans ces fichiers, les deux pages indiquent que le texte n'est pas encore publié. L'installateur limite aussi le journal système de la machine à 30 jours (`/etc/systemd/journald.conf.d/synunnel.conf`), la durée qu'annonce le modèle de notice : changer l'une, c'est changer l'autre.

Le dépôt peut vivre ailleurs (le service est généré pour son emplacement réel), mais `/opt/synunnel` évite de modifier les droits d'un répertoire personnel. Le script vérifie les paramètres avant de toucher à la machine, installe les paquets, crée les secrets dans `/etc/synunnel/synunnel.env` (hors du dépôt), configure PowerDNS, Caddy, WireGuard et un pare-feu dédié au tunnel, puis démarre les services. On peut le relancer sans renouveler les secrets : les valeurs déjà enregistrées font foi. Pour changer un réglage ensuite, modifiez `/etc/synunnel/synunnel.env`, puis relancez le script ou `sudo systemctl restart synunnel`.

UFW reçoit les règles des ports publics mais **n'est pas activé** par le script, pour ne pas couper votre accès SSH. Pour l'activer : `sudo ufw allow 22/tcp && sudo ufw enable` (adaptez le port SSH). Le tunnel, lui, est filtré dans tous les cas par sa propre table nftables.

Les comptes s'ouvrent par invitation (`REGISTRATION_MODE=invitation`, par défaut) : créez une invitation avec l'[API d'administration](docs/API-ADMIN.md), appelée en local sur le VPS (`http://127.0.0.1:8000/admin/api/...`, jeton dans `/etc/synunnel/synunnel.env`), puis inscrivez-vous sur `https://tunnel.example.org/register` avec le code. Le mode `approval` (inscription libre puis approbation) reste possible ; ses limites sont décrites dans l'API d'administration.

## Utilisation

**Ajouter un domaine.** Indiquez le domaine (une zone DNS existante, pas un simple nom à l'intérieur d'une zone) et, si votre messagerie en utilise, les sélecteurs DKIM qui ne sont pas standards. Synunnel affiche un enregistrement TXT `_synunnel.mondomaine.fr` à créer chez votre hébergeur DNS **actuel**. Au clic sur « Vérifier », il interroge directement les serveurs de votre domaine ; si la preuve est là, il crée la zone et y recopie les enregistrements publics (A, AAAA, MX, TXT et CAA de la racine, `www`, `_dmarc`, les sélecteurs DKIM courants et ceux indiqués).

**Vérifier avant de déléguer.** Le DNS public ne révèle ni tous les sous-domaines ni tous les sélecteurs DKIM. Comparez la zone affichée à l'export complet de votre hébergeur actuel et ajoutez ce qui manque avant de changer les serveurs de noms chez votre registrar : une omission peut interrompre votre messagerie. Retirez aussi un éventuel enregistrement DS (DNSSEC), que Synunnel ne gère pas encore.

**Connecter une machine.** La configuration WireGuard s'affiche une seule fois ; la clé privée n'est jamais conservée côté serveur. Sur la machine : `sudo wg-quick up ./synunnel.conf`, ou importez-la dans l'application WireGuard.

**Publier une adresse.** Choisissez un nom (`@` pour la racine du domaine), la machine et le port local. Une adresse protégée exige la connexion à Synunnel ; son propriétaire peut ouvrir l'accès à une liste de comptes approuvés.

**Ouvrir une adresse à des invités sans compte.** Sur la page Accès d'une adresse protégée, la case « Accès par code mail » permet aux personnes de la liste d'entrer avec un code à 6 chiffres reçu par mail, sans créer de compte (instance avec boîte d'envoi seulement). Réglages d'instance : `GUEST_CODES=0` le coupe partout ; avec `REQUIRE_2FA=1`, il faut aussi `GUEST_CODES_WITH_2FA=1`.

**Supprimer un domaine.** Par défaut, le titulaire supprime lui-même un domaine sans adresse, une fois la délégation retirée chez son registrar. `OWNER_DOMAIN_DELETION=0` réserve la suppression à l'administrateur (tableau de bord et API répondent `admin_only`), qui passe alors par l'API d'administration.

**Sécuriser son compte.** Page **Sécurité** : double authentification par application de codes (Aegis, 2FAS, Google Authenticator, un gestionnaire de mots de passe…), dix codes de secours, changement de mot de passe et vérification de l'adresse mail, qui permet ensuite de réinitialiser un mot de passe oublié. Activer la double authentification ou changer de mot de passe coupe les autres sessions et révoque les jetons d'API.

## API pour agents

Un agent IA ou un script peut tout faire sur un compte (domaines, DNS, machines, adresses, partage) avec un jeton créé depuis la page **Jetons d'API** : permissions cochées une à une, 7 ou 30 jours, révocable à tout moment. La clé privée d'une machine reste sur la machine : l'API ne reçoit que la clé publique. Guide et exemples : [docs/API.md](docs/API.md) ; description OpenAPI servie par l'instance sur `/api/v1/openapi.json`.

## Administration

- [API d'administration](docs/API-ADMIN.md) : invitations, comptes en attente, approbation, refus, suspension, tickets de récupération (mot de passe ou double authentification perdus), vérification d'adresse.
- `scripts/provision-site.py` et `scripts/create-machine-config.py` : rattachement d'un site ou d'une machine à un compte approuvé depuis le VPS, sans passer par le tableau de bord.
- État des services : `sudo systemctl status pdns caddy wg-quick@wg0 synunnel synunnel-reconcile.timer`.
- La base fait foi : si PowerDNS, WireGuard ou Caddy n'ont pas pu être mis à jour pendant une action, le rapprochement automatique (toutes les cinq minutes, `journalctl -u synunnel-reconcile`) termine le travail.
- Sauvegardes : **deux archives chiffrées, à des clés différentes, rangées hors du VPS**, jamais une seule qui mélange la base et les secrets (avec `SECRET_KEY` et la base, on peut forger une session sur n'importe quel compte ; `TOTP_KEY` ne protège les secrets de double authentification que d'une fuite de la base seule).
  - **Base** : copie cohérente des deux bases SQLite, prise avec l'API de sauvegarde de SQLite (`sqlite3 … ".backup fichier"` ou `python3 -c "import sqlite3; sqlite3.connect(SRC).backup(sqlite3.connect(DST))"`), jamais par `cp` ou `tar` d'une base ouverte en WAL : `/var/lib/synunnel/synunnel.db` et `/var/lib/powerdns/synunnel.sqlite3`. Vérifier chaque copie par `PRAGMA integrity_check`.
  - **Secrets** : `/etc/synunnel/` (fichier d'environnement, mot de passe SMTP, textes de l'exploitant), `/etc/wireguard/`, `/etc/powerdns/pdns.d/synunnel.conf` (clé de l'API PowerDNS) et `/var/lib/caddy/` (certificats et compte ACME).
  - Aucune archive en clair ne reste sur le VPS ; restauration à rejouer régulièrement sur une machine de test.

## Développement

```bash
uv sync --extra dev        # ou : python3 -m venv .venv && .venv/bin/pip install -e ".[dev]"
.venv/bin/ruff check .
.venv/bin/pytest -q
```

Après tout changement de dépendance : `uv lock`, puis `uv export --frozen --no-dev --no-emit-project --format requirements-txt -o requirements.lock`. L'installateur de production n'installe que `requirements.lock` (versions et empreintes figées, paquets binaires, sans outils de développement) ; un test vérifie que les deux fichiers concordent.

Les tests unitaires n'ont besoin d'aucun service système. `scripts/e2e-test.py` déroule un essai complet (DNS, HTTPS, tunnel, pare-feu, adresse protégée) mais **modifie la configuration réelle** de la machine : il ne se lance que sur une machine jetable, avec `SYNUNNEL_E2E_DISPOSABLE=1`.

Documentation : [architecture](docs/ARCHITECTURE.md), [sécurité et limites](docs/SECURITE.md), [API d'administration](docs/API-ADMIN.md), [historique des versions](CHANGELOG.md). Signaler une faille : [SECURITY.md](SECURITY.md).

## Licence

MIT, voir [LICENSE](LICENSE). Projet initié par [Synoptïa](https://synoptia.fr).
