# Sécurité

## Protections en place

**Comptes et sessions**
- Mots de passe hachés avec Argon2id ; aucun mot de passe en clair en base.
- Session du tableau de bord en cookie `__Host-`, `Secure`, `HttpOnly`, `SameSite=Lax`, sans domaine partagé ; toutes les actions web portent un jeton CSRF, renouvelé à la connexion.
- Inscription et connexion limitées par IP et par adresse mail. Les réponses publiques ne révèlent pas si une adresse possède déjà un compte, et la connexion d'un compte inexistant coûte le même calcul qu'une vraie tentative.
- Un compte neuf reste en attente et n'a accès à rien. Un refus supprime le compte et bloque son adresse.
- La déconnexion vaut pour tous les appareils : elle invalide les autres sessions du tableau de bord (version de session vérifiée à chaque requête) et ferme les accès ouverts sur les adresses protégées.

**Domaines**
- Un domaine n'est créé qu'après une **preuve de propriété** : un TXT `_synunnel.<domaine>` propre à la demande, lu directement chez les serveurs qui font autorité pour la zone (réponse `AA` exigée, repli TCP). Tant que la preuve manque, aucune zone n'existe et le nom reste ouvert à son véritable propriétaire ; la première preuve valide l'emporte et annule les demandes concurrentes.
- Deux zones ne se recouvrent jamais : un domaine qui contient une zone existante, ou qui est contenu dans l'une d'elles, est refusé, quel que soit le compte.
- Les noms de l'instance (tableau de bord, serveurs de noms, redirections) et ceux de `RESERVED_DOMAINS` ne peuvent pas être revendiqués, ni rien de ce qu'ils contiennent ; leurs domaines parents sont réservés au nom exact. Une réservation ajoutée après coup s'applique aussi aux demandes en cours.
- Un CNAME ne partage jamais son nom ; une adresse ne peut écraser un A, AAAA ou CNAME existant ; la longueur des noms complets est contrôlée.
- Quotas de domaines et de machines par compte, comptés sous verrou d'écriture.

**Isolation entre comptes**
- Domaines, enregistrements, machines, adresses et listes d'invités sont filtrés par propriétaire ; les tests essaient explicitement des lectures et modifications croisées entre deux comptes.

**Adresses protégées**
- Un visiteur est renvoyé vers le tableau de bord, puis revient avec un code à usage unique de deux minutes, stocké sous forme d'empreinte, et un cookie limité à cet hôte (12 heures).
- L'autorisation est relue à chaque requête HTTP ; modifier la liste d'invités révoque codes et sessions de l'adresse.
- `forward_auth` contrôle toutes les routes, publiques comprises. Chaque route porte le jeton de son incarnation : une route supprimée mais encore chargée dans Caddy reste refusée, même si l'adresse est recréée au même nom vers une autre machine.
- Caddy n'émet un certificat que pour un nom autorisé par l'application (`on_demand_tls` avec `ask`).

**Système**
- L'application tourne sous l'utilisateur `synunnel`, liée à `127.0.0.1:8000` ; l'API PowerDNS est liée à `127.0.0.1:8081`. PowerDNS n'est pas récursif et refuse AXFR.
- Seul l'assistant `/usr/local/sbin/synunnel-sync` (root, appelé par une entrée sudoers limitée) écrit les configurations WireGuard et Caddy. Il revalide noms, IP, ports et clés, lit pairs et routes dans une seule transaction et sérialise ses exécutions par un verrou.
- **Pare-feu du tunnel** : la table nftables `synunnel_wg`, chargée avant chaque démarrage de `wg0`, ne laisse entrer par le tunnel que les réponses aux connexions ouvertes par le VPS (sens `reply` du suivi de connexion) et bloque tout transit d'une machine à l'autre. Une machine ne peut joindre aucun service du VPS, SSH compris, pas même par une connexion antérieure au chargement de la table. Cette table s'applique même si UFW est inactif ; si elle ne peut pas être chargée, le tunnel ne démarre pas.
- La clé privée d'une machine est générée à sa création, affichée une fois, jamais stockée. La clé du serveur est hors dépôt, en mode 0600.
- Le journal d'accès de Gunicorn n'enregistre que le chemin des requêtes, sans leurs paramètres.
- Secrets (`SECRET_KEY`, `ADMIN_TOKEN`, `PDNS_API_KEY`) dans `/etc/synunnel/synunnel.env`, root et groupe `synunnel`, mode 0640.

## Limites connues de la v0.1 alpha

- **Un seul serveur DNS, pas de DNSSEC.** Si le VPS tombe, les domaines délégués cessent de répondre, messagerie comprise. Un enregistrement DS laissé chez le registrar casse la résolution.
- **Copie DNS incomplète par nature.** Le DNS public ne liste ni tous les sous-domaines ni tous les sélecteurs DKIM. Le joker vers le VPS peut capter un nom oublié, par exemple l'hôte d'un MX. Comparer la zone à l'export du fournisseur actuel avant de déléguer.
- **Cookie d'accès transmis au service.** Pour une adresse protégée, le cookie Synunnel de cet hôte accompagne les requêtes jusqu'au service de la machine. Un service qui journalise ou renvoie les cookies l'exposerait jusqu'à son expiration.
- **WebSocket.** Une connexion WebSocket déjà ouverte n'est pas recontrôlée à chaque message : retirer un invité ne la coupe pas.
- **Ressources.** Pas de purge automatique du journal d'audit admin ; une requête anonyme sur l'API admin produit une écriture en base. Pas de quota sur le nombre d'adresses par compte.
- **Domaines déjà délégués.** Un domaine dont les serveurs de noms désignent déjà l'instance, sans zone chez elle, ne peut plus prouver sa propriété : repasser temporairement par un autre hébergeur DNS, ou demander à l'administrateur (`scripts/provision-site.py`).
- **Proxy dans un conteneur.** Le pare-feu du tunnel bloque aussi le trafic transféré depuis `wg0` : un reverse proxy qui tournerait dans un bridge Docker au lieu de Caddy sur l'hôte demanderait une règle adaptée.
- **Réutilisation des IP du tunnel.** L'IP d'une machine supprimée est réattribuable immédiatement, sans période de quarantaine.
- **Comptes.** Pas de réinitialisation de mot de passe, pas de double authentification, pas de vérification de la boîte mail : l'administrateur valide chaque compte à la main.
- **Sauvegardes.** Aucune rotation ni restauration automatisée n'est fournie (voir le README).
- **Docker sur le même VPS.** Docker insère ses propres règles de pare-feu et peut contourner UFW pour les ports qu'il publie. La table `synunnel_wg` reste active pour le tunnel.
- **Droits sur le dépôt.** L'installateur ouvre la traversée des répertoires parents du dépôt à l'utilisateur `synunnel` ; il refuse de toucher un répertoire qui porte déjà des ACL. Cloner dans `/opt/synunnel` évite toute modification de droits.
- **Dépendances.** L'installation résout les versions compatibles au moment où elle est lancée ; `uv.lock` fige les versions testées pour le développement.
- **Échelle.** SQLite et une seule instance applicative suffisent à un usage personnel, pas à une plateforme ouverte au public.

## Secrets et journaux

Ne jamais copier `/etc/synunnel/synunnel.env` dans le dépôt, un ticket ou un échange. Le journal d'audit de l'API admin conserve l'heure UTC, l'IP, la méthode, le chemin et le statut, jamais le jeton. Pour changer le jeton : modifier le fichier, puis `sudo systemctl restart synunnel`.
