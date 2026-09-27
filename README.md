# Synunnel

Synunnel permet à un compte approuvé de publier un service situé derrière un pair WireGuard sur son propre domaine. PowerDNS sert les zones déléguées, Caddy gère HTTPS et le routage, et le tableau de bord permet de gérer domaines, machines, adresses et accès partagés.

Le dépôt est **local au VPS Synunnel** (`/home/ubuntu/synunnel`). Aucun dépôt public, push, mail ou changement DNS externe n'est fait par cette installation. La licence MIT reste une proposition à confirmer.

## État de cette instance

Le tableau de bord est configuré pour `https://synunnel.fr`. Les serveurs autoritaires sont `ns1.synunnel.fr` et `ns2.synunnel.fr`. `synunnel.com` et `www.synunnel.com` répondent par une redirection HTTPS 308 vers `synunnel.fr`, avec le chemin conservé. Le 27 septembre 2026, les dix enregistrements indiqués ci-dessous ont été observés dans le DNS public ; le tableau de bord et les deux redirections ont répondu avec un certificat public valide. Le comportement avait aussi été vérifié avec la CA locale temporaire de Caddy et `curl --resolve`, puis la configuration normale restaurée.

Les comptes réels et les zones sont encore vides. La landing TOOGGY est préparée sur **le VPS TOOGGY**, dans `/home/ubuntu/tooggy-landing` de cette autre machine, sans service démarré. Son rattachement dépend de la création et de l'approbation du compte personnel de Ludo. Le VPS Synunnel n'héberge aucun fichier, service ou espace réseau TOOGGY.

## Enregistrements OVH constatés

Les dix entrées suivantes étaient visibles dans le DNS public le 27 septembre 2026. Aucune n'a été créée par ce dépôt. Elles sont à conserver chez OVH ; ne pas retirer les autres enregistrements utiles. Elles **ne délèguent pas `synunnel.fr` à Synunnel** : OVH continue de servir sa zone.

| Zone OVH | Type | Nom | Valeur |
| --- | --- | --- | --- |
| `synunnel.fr` | A | `@` | `51.254.137.231` |
| `synunnel.fr` | AAAA | `@` | `2001:41d0:305:2100::f36e` |
| `synunnel.fr` | A | `ns1` | `51.254.137.231` |
| `synunnel.fr` | AAAA | `ns1` | `2001:41d0:305:2100::f36e` |
| `synunnel.fr` | A | `ns2` | `51.254.137.231` |
| `synunnel.fr` | AAAA | `ns2` | `2001:41d0:305:2100::f36e` |
| `synunnel.com` | A | `@` | `51.254.137.231` |
| `synunnel.com` | AAAA | `@` | `2001:41d0:305:2100::f36e` |
| `synunnel.com` | A | `www` | `51.254.137.231` |
| `synunnel.com` | AAAA | `www` | `2001:41d0:305:2100::f36e` |

Le domaine `tooggy.com` reste sur ses NS OVH jusqu'à la copie et à la vérification complète de sa zone, surtout ses MX et SPF OVH. Sa future délégation au registrar utilisera `ns1.synunnel.fr` et `ns2.synunnel.fr`, uniquement sur le GO de Ludo. Un seul VPS porte actuellement ces deux noms : certains registrars, notamment pour les `.fr`, peuvent demander deux serveurs réellement distincts.

## Installer sur un autre VPS Ubuntu 24.04

Prévoir une IPv4 publique, éventuellement une IPv6, un utilisateur `ubuntu` avec sudo et SSH par clé. Le script crée les utilisateurs, les secrets hors dépôt, les services systemd, les configurations PowerDNS/Caddy/WireGuard et les règles UFW nécessaires. Il préserve les secrets et la clé serveur à la relance. Le Caddyfile est **régénéré depuis la configuration** à chaque passage ; un ancien Caddyfile remplacé est sauvegardé localement.

```bash
cd /home/ubuntu/synunnel
sudo ./scripts/install.sh
```

Pour personnaliser la première installation :

```bash
sudo env PUBLIC_IPV4=203.0.113.10 PUBLIC_IPV6='' \
  DASHBOARD_HOST=tunnel.exemple.fr NS1_HOST=ns1.tunnel.exemple.fr \
  NS2_HOST=ns2.tunnel.exemple.fr SOA_RNAME=hostmaster.tunnel.exemple.fr. \
  REDIRECT_HOSTS=alias.exemple.fr,www.alias.exemple.fr \
  ACME_EMAIL=admin@exemple.fr ./scripts/install.sh
```

Les paramètres et secrets vivent dans `/etc/synunnel/synunnel.env`. Pour migrer **cette ancienne instance Synoptïa** vers les nouveaux noms, `sudo .venv/bin/python scripts/migrate-instance-domain.py` modifie seulement les valeurs attendues et sauvegarde le fichier original. Une relance de `install.sh` met à jour le SOA par défaut, les NS/SOA des zones existantes et Caddy. Le script refuse une configuration personnalisée qu'il ne sait pas migrer. Le port WireGuard et son sous-réseau restent `51820/UDP` et `10.88.0.0/24` dans cette version.

## Parcours utilisateur

1. Créer son compte sur `synunnel.fr`. Il reste en attente ; seule l'API admin peut l'approuver.
2. Ajouter son domaine. Synunnel copie les A, AAAA, MX, TXT, CAA de la racine, les enregistrements de `www`, `_dmarc` et les sélecteurs DKIM recherchés ou indiqués. **Comparer la zone copiée à l'export complet du DNS actuel avant toute délégation.** Le DNS public ne révèle pas tous les sélecteurs DKIM ou sous-domaines.
3. Créer une machine et installer immédiatement la configuration WireGuard affichée une seule fois. La clé privée cliente n'est pas conservée dans SQLite.
4. Créer une adresse vers cette machine et son port. `@` désigne la racine du domaine ; les A/AAAA copiés à la racine sont remplacés dans la zone active par ceux du VPS, tandis que MX/TXT restent. Les adresses non protégées sont publiques ; les adresses protégées exigent la connexion Synunnel.
5. Pour une adresse protégée, le propriétaire peut activer l'accès partagé et saisir jusqu'à 100 adresses mail. Chacune doit correspondre à un compte **approuvé**. Le propriétaire garde toujours l'accès. Retirer une adresse invalide ses codes et cookies ; chaque requête revérifie l'autorisation courante.

L'adresse protégée redirige vers le tableau de bord, puis revient avec un code unique de deux minutes et un cookie limité à cet hôte. Le chemin `/__synunnel/auth/callback` est réservé à cette procédure. Le mot de passe d'un utilisateur n'est jamais choisi par l'administrateur.

### Essai TOOGGY

La procédure de préparation, le transfert privé de la configuration WireGuard par SSH, l'activation sur le VPS TOOGGY et le retour arrière figurent dans le dépôt `tooggy-landing` sur cette machine. Sur Synunnel, les commandes d'administration `scripts/create-machine-config.py` et `scripts/provision-site.py` ne fonctionnent qu'avec un compte déjà approuvé ; la seconde lit le DNS public **avant** de créer `tooggy.com` et ses deux adresses protégées en mode partagé. La liste des associés reste vide jusqu'à la saisie de Ludo, et leurs adresses ne sont ni dans Git ni dans le journal.

## Contrôles et limites

```bash
cd /home/ubuntu/synunnel
.venv/bin/ruff check synunnel tests scripts
.venv/bin/pytest -q
sudo systemctl status pdns caddy wg-quick@wg0 synunnel
```

`sudo .venv/bin/python scripts/e2e-test.py` crée une zone `.test`, un pair WireGuard éphémère et un faux service, puis vérifie DNS, HTTPS, les redirections et le refus d'un hôte inconnu. Il remplace temporairement la CA de Caddy : le lancer seulement en fenêtre de maintenance lorsque des utilisateurs réels seront présents. Il restaure la configuration et supprime sa fixture après l'essai.

Il n'y a ni DNSSEC, ni second serveur DNS, ni haute disponibilité. Si le VPS Synunnel tombe après une délégation, les domaines et potentiellement la messagerie cessent de répondre. Il manque aussi une preuve automatique de propriété des domaines et des sauvegardes/restaurations périodiques. Voir [architecture](docs/ARCHITECTURE.md), [sécurité](docs/SECURITE.md), [API admin](docs/API-ADMIN.md) et [journal](docs/JOURNAL.md).
