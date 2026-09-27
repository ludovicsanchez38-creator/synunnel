# Synunnel

Synunnel permet à une personne validée par l'administrateur de publier un service de sa machine sur son domaine, sans ouvrir de port sur sa box. Le DNS autoritaire est fourni par PowerDNS, le HTTPS et le proxy par Caddy, et le lien avec la machine par WireGuard.

Le dépôt est **local au VPS** tant que Ludo n'a pas donné son accord de publication. La licence MIT est proposée pour la future publication et reste à confirmer.

## État du MVP

- Inscription en attente, validation ou refus par API d'administration, blocage des adresses refusées.
- Copie des enregistrements DNS publics avant création de zone, édition A, AAAA, CNAME, MX, TXT et CAA, contrôle de la délégation dans la zone parente.
- Un pair WireGuard par machine ; la clé privée du client apparaît une seule fois.
- Adresses HTTPS publiques ou protégées par la connexion du propriétaire. Caddy consulte l'application à chaque requête et n'obtient un certificat que pour une adresse déclarée et liée à un compte validé.
- Tests automatisés et essai intégré éphémère sans vrai domaine délégué.

## Installer sur un VPS Ubuntu 24.04

Prévoir une IPv4 publique, éventuellement une IPv6, un utilisateur `ubuntu` avec sudo, un accès SSH par clé, et les noms d'hôte du tableau de bord et des deux serveurs DNS. Le script conserve les secrets et la clé WireGuard à la relance. Il installe les paquets depuis les dépôts Ubuntu, crée les services systemd et ouvre UFW sur 53 TCP/UDP, 80 TCP, 443 TCP et 51820 UDP.

Placer ce dépôt dans `/home/ubuntu/synunnel`, puis :

```bash
cd /home/ubuntu/synunnel
sudo ./scripts/install.sh
```

Pour utiliser d'autres noms et IP dès la première installation :

```bash
sudo env PUBLIC_IPV4=203.0.113.10 PUBLIC_IPV6='' \
  DASHBOARD_HOST=tunnel.exemple.fr \
  NS1_HOST=ns1.tunnel.exemple.fr NS2_HOST=ns2.tunnel.exemple.fr \
  ACME_EMAIL=admin@exemple.fr ./scripts/install.sh
```

Ces valeurs sont conservées dans `/etc/synunnel/synunnel.env`. Après une première installation, modifier explicitement ce fichier et la configuration Caddy si les noms doivent changer ; une relance du script ne les remplace pas silencieusement. Le port WireGuard et le sous-réseau interne sont fixés à 51820/UDP et `10.88.0.0/24` dans ce MVP.

Le tableau de bord n'est joignable par son nom qu'après création de ses A et AAAA chez le fournisseur DNS actuel. Caddy émettra alors son certificat public à la première requête. Avant cette étape, on peut vérifier le service local avec `curl http://127.0.0.1:8000/login` depuis le VPS.

### Entrées DNS nécessaires pour l'instance Synoptïa

**Ludo ou Syn les créera chez Cloudflare après son GO ; le script ne modifie pas `synoptia.fr`.** Toutes ces entrées doivent être en mode **DNS uniquement**, sans proxy Cloudflare :

| Type | Nom dans `synoptia.fr` | Valeur |
| --- | --- | --- |
| A | `synunnel` | `51.254.137.231` |
| AAAA | `synunnel` | `2001:41d0:305:2100::f36e` |
| A | `ns1.synunnel` | `51.254.137.231` |
| AAAA | `ns1.synunnel` | `2001:41d0:305:2100::f36e` |
| A | `ns2.synunnel` | `51.254.137.231` |
| AAAA | `ns2.synunnel` | `2001:41d0:305:2100::f36e` |

Ces enregistrements ne délèguent pas `synoptia.fr` à Synunnel. Ils rendent seulement le tableau de bord et les noms des serveurs DNS joignables. Le domaine personnel d'un utilisateur se délègue ensuite **chez son propre registrar** vers `ns1.synunnel.synoptia.fr` et `ns2.synunnel.synoptia.fr`, après vérification de sa zone.

## Parcours utilisateur

1. Créer un compte sur le tableau de bord. Il reste en attente sans droit.
2. L'administrateur lit `GET /admin/api/pending`, puis appelle `approve` ou `reject` via son jeton. Syn peut surveiller l'API depuis une autre machine ; Synunnel n'envoie aucune notification.
3. Ajouter son domaine. L'application lit le DNS public puis crée la zone PowerDNS. Indiquer dans le formulaire les sélecteurs DKIM qui ne figurent pas parmi les sélecteurs courants recherchés.
4. **Avant de modifier le registrar**, comparer les enregistrements affichés avec ceux du fournisseur DNS actuel, particulièrement MX, SPF, DMARC, DKIM, `www` et tout service mail supplémentaire. Le DNS ne permet pas de découvrir tous les noms existants d'une zone. Ajouter à la main les enregistrements manquants.
5. Configurer les deux serveurs DNS chez le registrar, si celui-ci les accepte. Le statut de délégation interroge la zone parente ; il peut prendre le temps des caches DNS à changer.
6. Créer une machine, copier immédiatement sa configuration dans l'application WireGuard officielle, activer le tunnel et vérifier la poignée de main. Le service local doit accepter les connexions venant de `10.88.0.1` sur le port choisi.
7. Créer une adresse du domaine pour cette machine et son port. Activer l'option de connexion requise si l'accès doit être réservé au propriétaire.

L'adresse protégée redirige vers le tableau de bord, puis revient sur le domaine du service avec un cookie d'accès limité à ce nom. Le chemin `/__synunnel/auth/callback` est réservé au mécanisme d'authentification.

## Vérifier et maintenir

```bash
cd /home/ubuntu/synunnel
.venv/bin/ruff check synunnel tests scripts
.venv/bin/pytest -q
sudo systemctl status pdns caddy wg-quick@wg0 synunnel
sudo journalctl -u synunnel -n 100 --no-pager
```

L'essai intégré crée un domaine `.test`, un pair WireGuard dans un espace réseau local et une page de test. Il vérifie aussi la redirection d'une adresse protégée et le refus d'un nom inconnu. Il bascule temporairement Caddy sur sa CA interne, puis restaure la configuration et supprime les données de test. Ne le lancer qu'en fenêtre de maintenance si des utilisateurs réels sont actifs :

```bash
sudo .venv/bin/python scripts/e2e-test.py
```

Après une restauration de la base ou une interruption pendant un changement, `sudo /usr/local/sbin/synunnel-sync` régénère les routes Caddy et les pairs WireGuard à partir de la base. Les zones DNS restent synchronisées lors des opérations de l'application ; vérifier PowerDNS séparément après restauration.

## Limites assumées

- Les deux noms DNS aboutissent au **même VPS et aux mêmes IP**. Certains registrars, notamment pour les `.fr`, peuvent exiger deux serveurs distincts et refuser la délégation. Un second serveur DNS sera nécessaire.
- **Pas de DNSSEC** dans ce MVP. Avant de déléguer un domaine ayant un enregistrement DS au registrar, retirer ou adapter ce DS selon la procédure du registrar ; sinon la résolution échouera.
- **Pas de haute disponibilité** : si le VPS est indisponible, les domaines délégués ne répondent plus, et leur messagerie peut tomber. Il faut prévoir un second DNS, un plan de reprise et des sauvegardes avant un usage plus large.
- La découverte DNS ne peut pas retrouver des sélecteurs DKIM inconnus ni des sous-domaines arbitraires. Le contrôle humain de la zone avant délégation est indispensable.
- Seuls les hôtes sous le domaine sont publiables ; la racine reste réservée aux enregistrements repris. La protection d'accès est réservée au compte propriétaire.

Voir [l'architecture](docs/ARCHITECTURE.md), [la sécurité](docs/SECURITE.md), [l'API d'administration](docs/API-ADMIN.md) et [le journal factuel](docs/JOURNAL.md).
