# Sécurité

## Protections en place

**Comptes et sessions**
- Mots de passe hachés avec Argon2id ; aucun mot de passe en clair en base.
- Session du tableau de bord en cookie `__Host-`, `Secure`, `HttpOnly`, `SameSite=Lax`, sans domaine partagé ; toutes les actions web portent un jeton CSRF, renouvelé à la connexion.
- Inscription et connexion limitées par IP et par adresse mail. Les réponses publiques ne révèlent pas si une adresse possède déjà un compte, et la connexion d'un compte inexistant coûte le même calcul qu'une vraie tentative.
- Un compte neuf reste en attente et n'a accès à rien. Un refus supprime le compte et bloque son adresse.
- La déconnexion ferme aussi les accès ouverts sur les adresses protégées, sur tous les appareils.

**Domaines**
- Un domaine n'est créé qu'après une **preuve de propriété** : un TXT `_synunnel.<domaine>` propre au compte, lu directement chez les serveurs qui font autorité pour le domaine (sans cache). Tant que la preuve manque, aucune zone n'existe et le nom reste ouvert à son véritable propriétaire ; la première preuve valide l'emporte et annule les demandes concurrentes.
- Les noms de l'instance (tableau de bord, serveurs de noms, redirections), leurs domaines parents et ceux de `RESERVED_DOMAINS` ne peuvent pas être revendiqués.
- Un CNAME ne partage jamais son nom ; une adresse ne peut écraser un A, AAAA ou CNAME existant ; la longueur des noms complets est contrôlée.
- Quotas de domaines et de machines par compte.

**Isolation entre comptes**
- Domaines, enregistrements, machines, adresses et listes d'invités sont filtrés par propriétaire ; les tests essaient explicitement des lectures et modifications croisées entre deux comptes.

**Adresses protégées**
- Un visiteur est renvoyé vers le tableau de bord, puis revient avec un code à usage unique de deux minutes, stocké sous forme d'empreinte, et un cookie limité à cet hôte (12 heures).
- L'autorisation est relue à chaque requête HTTP ; modifier la liste d'invités révoque codes et sessions de l'adresse.
- `forward_auth` contrôle toutes les routes, publiques comprises : une route supprimée mais encore chargée dans Caddy est refusée.
- Caddy n'émet un certificat que pour un nom autorisé par l'application (`on_demand_tls` avec `ask`).

**Système**
- L'application tourne sous l'utilisateur `synunnel`, liée à `127.0.0.1:8000` ; l'API PowerDNS est liée à `127.0.0.1:8081`. PowerDNS n'est pas récursif et refuse AXFR.
- Seul l'assistant `/usr/local/sbin/synunnel-sync` (root, appelé par une entrée sudoers limitée) écrit les configurations WireGuard et Caddy. Il revalide noms, IP, ports et clés, lit pairs et routes dans une seule transaction et sérialise ses exécutions par un verrou.
- **Pare-feu du tunnel** : la table nftables `synunnel_wg`, chargée à chaque démarrage de `wg0`, bloque toute connexion ouverte depuis une machine du tunnel vers le VPS (SSH compris) et tout transit d'une machine à l'autre. Le VPS ouvre les connexions vers les machines, jamais l'inverse. Cette table s'applique même si UFW est inactif.
- La clé privée d'une machine est générée à sa création, affichée une fois, jamais stockée. La clé du serveur est hors dépôt, en mode 0600.
- Le journal d'accès de Gunicorn n'enregistre que le chemin des requêtes, sans leurs paramètres.
- Secrets (`SECRET_KEY`, `ADMIN_TOKEN`, `PDNS_API_KEY`) dans `/etc/synunnel/synunnel.env`, root et groupe `synunnel`, mode 0640.

## Limites connues de la v0.1 alpha

- **Un seul serveur DNS, pas de DNSSEC.** Si le VPS tombe, les domaines délégués cessent de répondre, messagerie comprise. Un enregistrement DS laissé chez le registrar casse la résolution.
- **Copie DNS incomplète par nature.** Le DNS public ne liste ni tous les sous-domaines ni tous les sélecteurs DKIM. Le joker vers le VPS peut capter un nom oublié, par exemple l'hôte d'un MX. Comparer la zone à l'export du fournisseur actuel avant de déléguer.
- **Cookie d'accès transmis au service.** Pour une adresse protégée, le cookie Synunnel de cet hôte accompagne les requêtes jusqu'au service de la machine. Un service qui journalise ou renvoie les cookies l'exposerait jusqu'à son expiration.
- **WebSocket.** Une connexion WebSocket déjà ouverte n'est pas recontrôlée à chaque message : retirer un invité ne la coupe pas.
- **Ressources.** Pas de purge automatique du journal d'audit admin ni des tentatives expirées ; une requête anonyme sur l'API admin produit une écriture en base. Pas de quota sur le nombre d'adresses par compte.
- **Réutilisation des IP du tunnel.** L'IP d'une machine supprimée est réattribuable immédiatement, sans période de quarantaine.
- **Comptes.** Pas de réinitialisation de mot de passe, pas de double authentification, pas de vérification de la boîte mail : l'administrateur valide chaque compte à la main.
- **Sauvegardes.** Aucune rotation ni restauration automatisée n'est fournie (voir le README).
- **Docker sur le même VPS.** Docker insère ses propres règles de pare-feu et peut contourner UFW pour les ports qu'il publie. La table `synunnel_wg` reste active pour le tunnel.
- **Dépendances.** L'installation résout les versions compatibles au moment où elle est lancée ; `uv.lock` fige les versions testées pour le développement.
- **Échelle.** SQLite et une seule instance applicative suffisent à un usage personnel, pas à une plateforme ouverte au public.

## Secrets et journaux

Ne jamais copier `/etc/synunnel/synunnel.env` dans le dépôt, un ticket ou un échange. Le journal d'audit de l'API admin conserve l'heure UTC, l'IP, la méthode, le chemin et le statut, jamais le jeton. Pour changer le jeton : modifier le fichier, puis `sudo systemctl restart synunnel`.
