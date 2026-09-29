# Sécurité

## Protections en place

**Comptes et sessions**
- Mots de passe hachés avec Argon2id ; aucun mot de passe en clair en base.
- Session du tableau de bord en cookie `__Host-`, `Secure`, `HttpOnly`, `SameSite=Lax`, sans domaine partagé, 12 h d'inactivité et 24 h au plus ; toutes les actions web portent un jeton CSRF, renouvelé à la connexion.
- Inscription limitée par adresse IP (par /64 en IPv6) et par adresse mail ; à la connexion, seuls les échecs comptent, par IP, par couple adresse-compte et par compte. Les réponses publiques ne révèlent pas si une adresse possède déjà un compte, et la connexion d'un compte inexistant coûte le même calcul qu'une vraie tentative.
- Inscription sur invitation par défaut : un code à usage unique, lié à une adresse et remis par l'administrateur, ouvre le compte ; personne ne peut préinscrire l'adresse d'un autre. En mode approbation, un compte neuf reste en attente et n'a accès à rien ; chaque décision de l'administrateur porte sur un couple identifiant-adresse, sous verrou, et une adresse bloquée n'est jamais approuvée. Un compte approuvé peut être suspendu (sessions, accès, jetons et services coupés).
- Identifiants jamais réattribués : une ancienne session, un jeton de route ou une suppression rejouée ne peut pas viser une ressource créée après.
- La déconnexion vaut pour tous les appareils : elle change la version de session du compte, vérifiée à chaque requête du tableau de bord, à l'utilisation d'un code d'accès et à chaque autorisation d'une adresse protégée. Un code émis par une requête engagée avant la déconnexion est donc refusé.

**Domaines**
- Un domaine n'est créé qu'après une **preuve de propriété** : un TXT `_synunnel.<domaine>` propre à la demande, lu directement chez les serveurs qui font autorité pour la zone (réponse `AA` exigée, repli TCP). Tant que la preuve manque, aucune zone n'existe et le nom reste ouvert à son véritable propriétaire ; la première preuve valide l'emporte et annule les demandes concurrentes.
- Un refus pour cause de zone existante ne révèle jamais le nom d'une zone d'un autre compte.
- Un domaine peut être supprimé par son titulaire (après ses adresses) ou retiré par l'administrateur, par exemple pour le rendre à son titulaire actuel ; sa zone est retirée de PowerDNS, avec reprise automatique en cas d'échec.
- La preuve TXT doit être servie par la majorité des serveurs faisant autorité qui répondent.
- Deux zones ne se recouvrent jamais : un domaine qui contient une zone existante, ou qui est contenu dans l'une d'elles, est refusé, quel que soit le compte, depuis le tableau de bord comme depuis l'outil d'administration (contrôle refait sous verrou d'écriture). À la mise à niveau, l'installateur s'arrête si une ancienne base contient des zones imbriquées et les nomme ; il ne supprime rien lui-même.
- Les noms de l'instance (tableau de bord, serveurs de noms, redirections) et ceux de `RESERVED_DOMAINS` ne peuvent pas être revendiqués, ni rien de ce qu'ils contiennent ; leurs domaines parents sont réservés au nom exact. Une réservation ajoutée après coup s'applique aussi aux demandes en cours.
- Un CNAME ne partage jamais son nom et n'est jamais posé à la racine ; labels de 63 octets et noms de 253 au plus ; adresses IP sans portée. Une adresse ne peut écraser un A, AAAA ou CNAME existant, sauf à la racine (`@`), où les A/AAAA copiés sont remplacés dans la zone active par ceux du VPS ; si l'instance n'a pas d'IPv6, aucun AAAA n'est publié pour une adresse.
- L'import d'une zone publique est borné par le quota d'enregistrements et chaque enregistrement importé est validé comme une saisie.
- Quotas de domaines et de machines par compte, comptés sous verrou d'écriture ; une demande annulée pendant sa vérification n'est pas convertie.

**Isolation entre comptes**
- Domaines, enregistrements, machines, adresses et listes d'invités sont filtrés par propriétaire ; les tests essaient explicitement des lectures et modifications croisées entre deux comptes.

**Adresses protégées**
- Un visiteur est renvoyé vers le tableau de bord, puis revient avec un code à usage unique de deux minutes, stocké sous forme d'empreinte, et un cookie limité à cet hôte (12 heures).
- L'autorisation est relue à chaque requête HTTP ; modifier la liste d'invités révoque codes et sessions de l'adresse.
- `forward_auth` contrôle toutes les routes, publiques comprises. Chaque route porte le jeton de son incarnation : une route supprimée mais encore chargée dans Caddy reste refusée, même si l'adresse est recréée au même nom vers une autre machine.
- Caddy n'émet un certificat que pour un nom autorisé par l'application (`on_demand_tls` avec `ask`).

**API pour agents**
- Jetons créés et révoqués uniquement depuis le tableau de bord, avec mot de passe redemandé ; 256 bits d'aléa, seule leur empreinte SHA-256 est gardée ; 7 ou 30 jours ; cinq actifs au plus.
- Permissions explicites par jeton (`domains`, `machines`, `addresses`, `sharing`), la lecture étant toujours permise. Jeton, compte et expiration sont recontrôlés sous le verrou d'écriture qui accepte chaque modification : une révocation pendant une opération longue l'arrête.
- Authentification Bearer exclusive : aucune session n'est ouverte ni renouvelée sur `/api/`, aucun cookie n'y est lu, aucune exemption CSRF ne dépend de la présence d'un en-tête. Un jeton n'ouvre ni le tableau de bord ni l'API d'administration.
- Corps JSON strict (champs connus, types exacts, tailles bornées), réponses construites par liste blanche (aucun jeton de route ni secret), `Cache-Control: no-store` sur toutes les réponses de l'API, erreurs JSON sans détail technique.
- La clé privée WireGuard d'une machine déclarée par l'API ne transite jamais : l'agent la génère sur la machine et n'envoie que la clé publique.
- Les adresses publiées refusent toute requête portant un jeton Synunnel (421) : un agent qui se tromperait d'adresse ne le livre jamais au service hébergé.
- Chaque écriture de l'API est journalisée (`api_audit` : compte, jeton, action, ressource) dans la même transaction que la modification ; création et révocation des jetons aussi.

**Système**
- L'application tourne sous l'utilisateur `synunnel`, liée à `127.0.0.1:8000` ; l'API PowerDNS est liée à `127.0.0.1:8081`. PowerDNS n'est pas récursif et refuse AXFR.
- La base fait foi : chaque modification vérifie ses conditions (propriété, recouvrement, quotas, conflits DNS) et écrit sous un même verrou d'écriture, sans appel réseau pendant ce verrou. PowerDNS, WireGuard et Caddy sont mis à jour ensuite : une zone à la fois (verrou par zone, lecture de la base dans un même instantané, chaque RRset appliqué séparément pour qu'un enregistrement refusé ne fige pas les autres), et une empreinte de ce qui a réellement été appliqué fait réappliquer une configuration écrite mais interrompue. Le rapprochement automatique (`synunnel-reconcile.timer`, toutes les cinq minutes) purge d'abord, répare le tunnel et les routes, puis les zones dans un budget de temps ; il signale les zones présentes dans PowerDNS sans domaine en base, sans jamais les supprimer, et retire celles des domaines supprimés.
- L'état de délégation affiché est relevé par le rapprochement : afficher une page ne déclenche aucune requête DNS sortante. Gunicorn sert l'application avec plusieurs fils, pour que les contrôles de Caddy ne soient jamais bloqués par une page lente.
- Une route Caddy n'est générée que si la machine appartient au même compte que le domaine.
- Les vérifications DNS (preuve TXT, délégation) n'interrogent que des adresses publiques, jamais le multicast ni les plages de transition, dans un budget de temps borné : un domaine hostile ne peut ni faire sonder le réseau interne de l'instance ni retenir un processus.
- Seul l'assistant `/usr/local/sbin/synunnel-sync` (root, appelé par une entrée sudoers limitée) écrit les configurations WireGuard et Caddy. L'API d'administration de Caddy écoute sur un socket dans `/run/caddy` (0750, utilisateur caddy) : l'utilisateur de l'application ne peut pas reconfigurer Caddy. Un pair à la clé invalide ou en double est écarté sans bloquer les autres, et WireGuard et Caddy sont appliqués indépendamment. Il revalide noms, IP, ports et clés, lit pairs et routes dans une seule transaction et sérialise ses exécutions par un verrou.
- **Pare-feu du tunnel** : la table nftables `synunnel_wg`, chargée avant chaque démarrage de `wg0`, ne laisse entrer par le tunnel que les réponses aux connexions ouvertes par le VPS (sens `reply` du suivi de connexion) et bloque tout transit d'une machine à l'autre. Une machine ne peut joindre aucun service du VPS, SSH compris, pas même par une connexion antérieure au chargement de la table. Cette table s'applique même si UFW est inactif ; si elle ne peut pas être chargée, le tunnel ne démarre pas.
- La clé privée d'une machine est générée à sa création, affichée une fois, jamais stockée. La clé du serveur est hors dépôt, en mode 0600.
- Le journal d'accès de Gunicorn n'enregistre que le chemin des requêtes, sans leurs paramètres.
- Secrets (`SECRET_KEY`, `ADMIN_TOKEN`, `PDNS_API_KEY`) dans `/etc/synunnel/synunnel.env`, root et groupe `synunnel`, mode 0640.

## Limites connues de la v0.1 alpha

- **Un seul serveur DNS, pas de DNSSEC.** Si le VPS tombe, les domaines délégués cessent de répondre, messagerie comprise. Un enregistrement DS laissé chez le registrar casse la résolution.
- **Copie DNS incomplète par nature.** Le DNS public ne liste ni tous les sous-domaines ni tous les sélecteurs DKIM. Le joker vers le VPS peut capter un nom oublié, par exemple l'hôte d'un MX. Comparer la zone à l'export du fournisseur actuel avant de déléguer.
- **Cookie d'accès transmis au service.** Pour une adresse protégée, le cookie Synunnel de cet hôte accompagne les requêtes jusqu'au service de la machine. Un service qui journalise ou renvoie les cookies l'exposerait jusqu'à son expiration.
- **WebSocket.** Une connexion WebSocket déjà ouverte n'est pas recontrôlée à chaque message : retirer un invité ne la coupe pas.
- **Ressources.** Une requête anonyme sur l'API d'administration produit une écriture en base (journal purgé après 90 jours par le rapprochement). Les limites de débit sont par compte, pas globales : une instance ouverte à beaucoup de comptes demanderait une limite globale en amont.
- **Domaines déjà délégués.** Un domaine dont les serveurs de noms désignent déjà l'instance, sans zone chez elle, ne peut plus prouver sa propriété : repasser temporairement par un autre hébergeur DNS, ou demander à l'administrateur (`scripts/provision-site.py`).
- **Proxy dans un conteneur.** Le pare-feu du tunnel bloque aussi le trafic transféré depuis `wg0` : un reverse proxy qui tournerait dans un bridge Docker au lieu de Caddy sur l'hôte demanderait une règle adaptée.
- **Réutilisation des IP du tunnel.** L'IP d'une machine supprimée est réattribuable immédiatement, sans période de quarantaine.
- **Comptes.** Pas de réinitialisation de mot de passe ni de double authentification. En mode approbation, la boîte mail n'est pas vérifiée : l'administrateur confirme l'identité par un autre canal. Cinquante échecs de connexion en 15 minutes, depuis plusieurs adresses, bloquent temporairement les nouvelles connexions d'un compte : c'est le prix d'une protection contre les essais distribués.
- **Sauvegardes.** Aucune rotation ni restauration automatisée n'est fournie (voir le README).
- **Docker sur le même VPS.** Docker insère ses propres règles de pare-feu et peut contourner UFW pour les ports qu'il publie. La table `synunnel_wg` reste active pour le tunnel.
- **Droits sur le dépôt.** L'installateur ouvre la traversée des répertoires parents du dépôt à l'utilisateur `synunnel` quand ils ne sont pas déjà traversables par tous. Il refuse un répertoire qui porte d'autres ACL étendues, et ne retouche jamais une entrée `synunnel` posée par une installation précédente. Cloner dans `/opt/synunnel` évite toute modification de droits.
- **Dépendances.** L'installation résout les versions compatibles au moment où elle est lancée ; `uv.lock` fige les versions testées pour le développement.
- **Échelle.** SQLite et une seule instance applicative suffisent à un usage personnel, pas à une plateforme ouverte au public.

## Secrets et journaux

Ne jamais copier `/etc/synunnel/synunnel.env` dans le dépôt, un ticket ou un échange. Le journal d'audit de l'API admin conserve l'heure UTC, l'IP, la méthode, le chemin et le statut, jamais le jeton. Pour changer le jeton : modifier le fichier, puis `sudo systemctl restart synunnel`.
