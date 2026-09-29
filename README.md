# Synunnel

Synunnel publie des services hébergés chez vous (un NAS, une domotique, un petit site) sur votre propre nom de domaine, en HTTPS, sans ouvrir le moindre port sur votre box. Un VPS sert de porte d'entrée : il répond pour votre domaine, obtient les certificats et relaie le trafic vers vos machines par un tunnel WireGuard.

> **Version 0.1 alpha.** Synunnel fonctionne de bout en bout et a été testé sur une installation neuve, mais il reste jeune. Réservez-le pour l'instant à des usages personnels ou à des proches de confiance, lisez les [limites connues](docs/SECURITE.md#limites-connues-de-la-v01-alpha) et gardez une sauvegarde de votre zone DNS actuelle avant toute délégation.

*In English: Synunnel is a self-hosted alternative to tunnel services. A single VPS runs an authoritative DNS server (PowerDNS), an HTTPS reverse proxy with on-demand certificates (Caddy) and a WireGuard hub; users delegate their own domain to it and expose services from machines behind NAT. Code comments and docs are in French. MIT licensed, alpha quality.*

## Comment ça marche

```
Navigateur ──HTTPS──> Caddy (VPS) ──WireGuard──> votre machine :port
Registrar ──NS──────> PowerDNS (VPS) : votre zone, recopiée puis gérée ici
```

1. Vous créez un compte sur le tableau de bord de l'instance ; l'administrateur le valide.
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
git clone <adresse du dépôt> synunnel
cd synunnel
sudo env PUBLIC_IPV4=203.0.113.10 \
  DASHBOARD_HOST=tunnel.example.org \
  NS1_HOST=ns1.example.org NS2_HOST=ns2.example.org \
  ACME_EMAIL=admin@example.org \
  ./scripts/install.sh
```

Paramètres facultatifs : `PUBLIC_IPV6`, `SOA_RNAME` (par défaut `hostmaster.<DASHBOARD_HOST>.`), `REDIRECT_HOSTS` (noms supplémentaires redirigés vers le tableau de bord, séparés par des virgules), `RESERVED_DOMAINS` (domaines que les comptes ne pourront pas revendiquer), `MAX_DOMAINS_PER_USER` et `MAX_MACHINES_PER_USER`.

Le script vérifie les paramètres avant de toucher à la machine, installe les paquets, crée les secrets dans `/etc/synunnel/synunnel.env` (hors du dépôt), configure PowerDNS, Caddy, WireGuard et un pare-feu dédié au tunnel, puis démarre les services. On peut le relancer sans renouveler les secrets : les valeurs déjà enregistrées font foi.

UFW reçoit les règles des ports publics mais **n'est pas activé** par le script, pour ne pas couper votre accès SSH. Pour l'activer : `sudo ufw allow 22/tcp && sudo ufw enable` (adaptez le port SSH). Le tunnel, lui, est filtré dans tous les cas par sa propre table nftables.

Ensuite, créez votre compte sur `https://tunnel.example.org/register` et approuvez-le avec l'[API d'administration](docs/API-ADMIN.md) ; le jeton se trouve dans `/etc/synunnel/synunnel.env`.

## Utilisation

**Ajouter un domaine.** Indiquez le domaine et, si votre messagerie en utilise, les sélecteurs DKIM qui ne sont pas standards. Synunnel affiche un enregistrement TXT `_synunnel.mondomaine.fr` à créer chez votre hébergeur DNS **actuel**. Au clic sur « Vérifier », il interroge directement les serveurs de votre domaine ; si la preuve est là, il crée la zone et y recopie les enregistrements publics (A, AAAA, MX, TXT et CAA de la racine, `www`, `_dmarc`, les sélecteurs DKIM courants et ceux indiqués).

**Vérifier avant de déléguer.** Le DNS public ne révèle ni tous les sous-domaines ni tous les sélecteurs DKIM. Comparez la zone affichée à l'export complet de votre hébergeur actuel et ajoutez ce qui manque avant de changer les serveurs de noms chez votre registrar : une omission peut interrompre votre messagerie. Retirez aussi un éventuel enregistrement DS (DNSSEC), que Synunnel ne gère pas encore.

**Connecter une machine.** La configuration WireGuard s'affiche une seule fois ; la clé privée n'est jamais conservée côté serveur. Sur la machine : `sudo wg-quick up ./synunnel.conf`, ou importez-la dans l'application WireGuard.

**Publier une adresse.** Choisissez un nom (`@` pour la racine du domaine), la machine et le port local. Une adresse protégée exige la connexion à Synunnel ; son propriétaire peut ouvrir l'accès à une liste de comptes approuvés.

## Administration

- [API d'administration](docs/API-ADMIN.md) : comptes en attente, approbation, refus.
- `scripts/provision-site.py` et `scripts/create-machine-config.py` : rattachement d'un site ou d'une machine à un compte approuvé depuis le VPS, sans passer par le tableau de bord.
- État des services : `sudo systemctl status pdns caddy wg-quick@wg0 synunnel`.
- À sauvegarder régulièrement : `/var/lib/synunnel/`, `/var/lib/powerdns/`, `/etc/synunnel/`, `/etc/wireguard/` et `/var/lib/caddy/`.

## Développement

```bash
uv sync --extra dev        # ou : python3 -m venv .venv && .venv/bin/pip install -e ".[dev]"
.venv/bin/ruff check .
.venv/bin/pytest -q
```

Les tests unitaires n'ont besoin d'aucun service système. `scripts/e2e-test.py` déroule un essai complet (DNS, HTTPS, tunnel, pare-feu, adresse protégée) mais **modifie la configuration réelle** de la machine : il ne se lance que sur une machine jetable, avec `SYNUNNEL_E2E_DISPOSABLE=1`.

Documentation : [architecture](docs/ARCHITECTURE.md), [sécurité et limites](docs/SECURITE.md), [API d'administration](docs/API-ADMIN.md), [historique des versions](CHANGELOG.md). Signaler une faille : [SECURITY.md](SECURITY.md).

## Licence

MIT, voir [LICENSE](LICENSE). Projet initié par [Synoptïa](https://synoptia.fr).
