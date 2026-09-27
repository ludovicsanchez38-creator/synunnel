# Sécurité du MVP

## Couvert et vérifié

- Mots de passe hachés avec Argon2id ; aucun mot de passe en clair dans SQLite.
- Session du tableau de bord en cookie `Secure`, `HttpOnly`, `SameSite=Lax`, sans domaine partagé ; actions web protégées par un jeton CSRF.
- Inscription et connexion limitées par IP ou adresse mail sur des fenêtres de temps enregistrées en SQLite.
- Un compte neuf reste `pending` et n'accède à aucune ressource. Un refus supprime le compte et place son adresse mail dans une liste de blocage.
- Les requêtes sur domaines, enregistrements, machines et adresses filtrent par propriétaire. Les tests automatisés essayent explicitement des lectures et modifications entre deux comptes.
- Un nom de domaine est unique ; `synoptia.fr`, `synunnel.fr`, `synunnel.com` et leurs sous-domaines sont réservés. Les enregistrements CNAME ne peuvent pas partager un nom avec un autre type. Une adresse ordinaire ne peut écraser un A/AAAA/CNAME existant ; l'adresse racine `@` remplace explicitement les A/AAAA dans la zone active, sans effacer les MX/TXT copiés.
- API d'administration avec jeton long hors dépôt, comparaison à temps constant et journal de chaque appel, y compris les refus. L'API n'envoie pas de message.
- API PowerDNS et application liées à localhost. PowerDNS n'est pas récursif, refuse AXFR et ne touche pas au résolveur local. UFW n'ouvre que SSH, 53 TCP/UDP, 80/443 TCP et 51820 UDP.
- Le service web tourne sous `synunnel`, PowerDNS sous `pdns`, Caddy sous `caddy`. Seul l'assistant de synchronisation root et `wg-quick` disposent des privilèges nécessaires. L'assistant valide ses entrées avant d'écrire les fichiers système.
- Caddy n'émet un certificat à la demande que si `ask` autorise le nom. `forward_auth` vérifie toutes les routes à chaque requête, même publiques, pour refuser une route supprimée encore chargée dans Caddy.
- La clé privée du client est générée au moment de l'ajout de machine, affichée une fois puis perdue ; seuls la clé publique, l'IP interne et le nom restent en base. La clé privée du serveur est hors dépôt, en mode 0600.
- Une adresse protégée n'est partagée qu'avec les adresses mail inscrites par son propriétaire **et** les comptes approuvés correspondants. Le propriétaire garde l'accès. L'autorisation est relue à chaque requête, même avec un cookie d'accès encore présent. Toute modification de liste supprime les codes et sessions d'accès de cet hôte. Les tests couvrent l'accès listé, non listé, en attente/refusé, retiré et inter-propriétaires.
- Le CLI de provisionnement refuse un compte non approuvé, exige la copie du DNS public avant une nouvelle zone, et crée les adresses en mode protégé/partagé avec une liste vide. La configuration privée du pair TOOGGY est destinée à un pipe SSH sans affichage ; le destinataire refuse les routes par défaut et les hooks WireGuard.

## Points encore ouverts

- **Vérification de propriété du domaine** : seuls des comptes approuvés peuvent ajouter un domaine, mais le MVP ne demande pas encore de preuve cryptographique par TXT ou par registrar. L'administrateur doit approuver uniquement des personnes de confiance et vérifier qu'elles contrôlent leur domaine. Un utilisateur approuvé malveillant pourrait réserver un domaine avant son propriétaire légitime.
- **Inventaire DNS incomplet par nature** : le DNS public ne liste pas tous les sous-domaines ni tous les sélecteurs DKIM. L'interface copie les noms demandés et exige une confirmation de vérification. Avant la délégation, comparer la zone à l'export du fournisseur actuel et ajouter les entrées absentes. Une erreur peut interrompre la messagerie.
- **Un seul serveur DNS et pas de DNSSEC** : un VPS indisponible arrête DNS et mail des domaines délégués. Si un DS existe déjà au registrar, l'absence de DNSSEC Synunnel peut casser la résolution.
- **Sauvegardes et restauration** : aucune rotation ou restauration automatisée n'est fournie. Sauvegarder régulièrement les deux SQLite, `/etc/synunnel`, `/etc/wireguard` et l'état Caddy, puis tester la restauration.
- **Réinitialisation du mot de passe et révocation globale des sessions** : pas d'interface dédiée dans le MVP. Un changement manuel de compte doit aussi nettoyer les sessions d'accès dans SQLite.
- **Identité des associés** : l'adresse mail est l'identifiant et la validation administrative reste manuelle. Il n'y a pas encore de vérification automatique de possession de la boîte mail ni de double authentification. Ludo doit vérifier l'identité avant d'approuver chaque compte.
- **Disponibilité du tunnel** : pas de supervision active des pairs ni de reprise automatique d'une machine hors ligne. Une adresse peut répondre 502 si son service local s'arrête.
- **Scalabilité** : SQLite, une seule instance d'application et un rechargement de configuration par changement suffisent au MVP, pas à une plateforme multi-serveurs.

## Exposition des secrets et journaux

`/etc/synunnel/synunnel.env` contient `SECRET_KEY`, `ADMIN_TOKEN` et `PDNS_API_KEY`. Ne jamais le copier dans le dépôt, un ticket ou un échange public. Les commandes d'exemple ne l'impriment pas. Le journal d'audit admin conserve l'heure UTC, l'IP, la méthode, le chemin et le statut, jamais le jeton. La rotation du jeton exige la modification du fichier et un redémarrage de `synunnel` ; communiquer la nouvelle valeur à Syn par un canal sécurisé.
