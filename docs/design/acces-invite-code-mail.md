# Design : accès invité par code envoyé par mail (v0.2, lot séparé) — version 2

Demande de Ludo le 29/09/2026 (« je pensais que ça ferait le mail avec le code à 6 chiffres comme Cloudflare », puis « go »). La version 1 a reçu un **NO-GO de Codex** (11 constats, `[I1]` à `[I11]`), vérifiés dans le code et intégrés ci-dessous. S'appuie sur `docs/design/2fa-mot-de-passe-oublie.md` (v2) : file SMTP asynchrone, `security_events`, consommation atomique, `REQUIRE_2FA`.

## Besoin

Une adresse protégée (tooggy.com) doit pouvoir s'ouvrir à des personnes **sans compte Synunnel**, listées par le propriétaire : la personne saisit son mail, reçoit un code à 6 chiffres depuis `noreply@synunnel.fr`, et entre. Les titulaires de compte gardent leur connexion (mot de passe, 2FA) : **le propriétaire n'a jamais d'accès invité** `[I1]`.

## 1. Politique

- **Option par adresse `guest_codes`**, désactivée par défaut, **y compris pour les adresses existantes** à la migration ; activation explicite par le propriétaire sur la page Accès (et par l'API, champ `guest_codes` de `PUT /addresses/{id}/access`, permission `sharing`) `[I2]`. Disponible seulement si l'instance a un SMTP.
- **Politique d'instance** : `GUEST_CODES` (défaut 1) ; quand `REQUIRE_2FA=1`, l'accès invité est **coupé** sauf si l'administrateur pose aussi `GUEST_CODES_WITH_2FA=1`, choix explicite documenté (un invité n'a qu'un facteur, sa boîte mail) `[I1]`.
- **Une adresse qui correspond à un compte** (quel que soit son statut) ou à `blocked_emails` ne reçoit jamais de code : elle suit le chemin factice (§3). Un titulaire de compte passe par son compte, avec sa 2FA ; un compte suspendu ou refusé n'a aucune porte dérobée `[I1]`.
- **Version d'autorisation invitée par adresse** : `addresses.guest_version`, incrémentée à tout changement de la liste d'accès, du partage ou de l'option, à la suspension du propriétaire (toutes ses adresses) et à la suppression de l'adresse. Chaque challenge, code de transfert et session d'invité porte `(address_id, route_token, guest_version)` ; toute différence vaut refus. Un grant retiré puis rétabli, ou une suspension suivie d'une réapprobation, ne ressuscite donc rien `[I3]`.

## 2. Tables séparées, identités séparées `[I4]`

Aucune colonne `user_id` nullable : trois tables propres aux invités, `guest_challenges`, `guest_access_codes`, `guest_host_sessions`, chacune avec `address_id REFERENCES addresses(id) ON DELETE CASCADE`, `email`, `route_token`, `guest_version`, expirations en secondes epoch. Les requêtes existantes sur `access_codes` et `host_sessions` (jointures sur `users`, déconnexion, suspension) restent inchangées. `caddy_auth` et le callback ont deux branches explicites : compte (inchangée, plus 2FA) ou invité (politique §1 vérifiée à **chaque** requête : option active, grant présent, email toujours sans compte, propriétaire approuvé, versions et route identiques). Un invité ne devient jamais `g.user` et n'emprunte jamais le `user_id` du propriétaire.

## 3. Parcours, et un seul automate pour le vrai et le factice `[I7][I11]`

1. `caddy_auth` redirige comme aujourd'hui vers `/login?next=…`. Si l'adresse visée accepte les codes invités, la page propose aussi « Recevoir un code par mail » → `/access/code?next=…`. La validation de `next` est scindée en deux : syntaxe stricte (https, pas de port, pas d'identifiants même vides, pas de fragment, hôte = adresse protégée existante) puis autorisation propre à chaque voie.
2. `POST /access/code` (CSRF du tableau de bord) : adresse normalisée. Réponse toujours identique. Un challenge est **toujours** créé côté serveur, réel si §1 est satisfait, sinon **factice** (MAC aléatoire jamais atteignable, marqué `dummy=1`, définitivement non échangeable même si un grant apparaît ensuite). `address_id`, `route_token`, `guest_version` et le chemin de retour sont **figés dans le challenge** ; la vérification ne relit jamais un nouveau `next`. Le mail d'un challenge réel part par la file asynchrone ; aucune différence de temps due au SMTP.
3. `POST /access/verify` : six chiffres ASCII. Même traitement pour les deux sortes de challenge (lecture, calcul du MAC HMAC-SHA256, écriture du compteur d'essais, même message d'erreur, même redirection). Succès (challenge réel seulement) dans une transaction : challenge consommé (`used_at IS NULL`), politique §1 revérifiée, `guest_access_code` créé (120 s, usage unique), puis la page relais existante (CSP) vers `https://hôte/__synunnel/auth/callback?code=…`.
4. Le callback crée une `guest_host_session` de 12 h, cookie `__Host-synunnel-access` (sans `Domain`, `Path=/`, `Secure`, `HttpOnly`, `SameSite=Lax`).

## 4. Force brute et quotas `[I5][I6][I8]`

- Code de 6 chiffres (`secrets.randbelow(10**6)`), 10 minutes, 5 essais par challenge.
- **Budget cumulatif d'échecs** par couple (adresse protégée, email) : 5 échecs sur 24 h, tous challenges confondus → nouveaux challenges pour ce couple rendus factices pendant 24 h (réponse inchangée). Probabilité de succès d'un attaquant sur un invité donné : au plus 5/10⁶ par jour, soit environ 0,18 % sur un an d'attaque continue qui envoie chaque jour des mails à la victime. Compromis assumé : un attaquant qui connaît l'adresse d'un invité peut le priver de code pendant 24 h ; l'invité peut toujours recevoir un compte Synunnel.
- **Quotas atomiques** : contrôle et réservation dans une même transaction `BEGIN IMMEDIATE` sur une connexion distincte de la transaction de sécurité (plus de `COUNT` puis `INSERT`) ; les refus restent comptés. Demandes : 10 / h par IP, 5 / h par email (au-delà : challenge factice, réponse inchangée) ; vérifications : 30 / 15 min par IP. **Pas de quota par hôte visible** : le budget d'envoi SMTP par hôte (50 / h, porté à 200 / h à l'implémentation : consommé par toute demande pour fermer l'oracle réel/factice, il devait rester difficile à épuiser) est interne à la file et, dépassé, rend les challenges factices sans rien changer à la réponse.
- Un nouveau challenge n'invalide pas un challenge légitime encore valable pour le même couple ; au plus 3 challenges vivants par couple.

## 5. Sortie de l'invité `[I9]`

Caddy réserve vers Flask `/__synunnel/*` (callback, `GET` et `POST /__synunnel/logout`), avant `forward_auth`. Le `GET` affiche un petit formulaire dont le jeton CSRF est un HMAC de la session d'hôte ; le `POST` le vérifie (routes `/__synunnel/` exemptées du CSRF du tableau de bord), supprime la ligne `guest_host_sessions` et efface exactement le cookie `__Host-`. La déconnexion d'un compte garde son comportement (tous ses accès par `user_id`) ; celle d'un invité ne ferme que son hôte. Tests séparés.

## 6. Cookie transmis au service `[I10]`

Caddy retire le cookie d'accès Synunnel de l'en-tête `Cookie` avant de joindre le service de la machine (`header_up Cookie` avec remplacement par expression régulière, vérifié sur Caddy 2.6.2 dans le conteneur ; sinon, limite documentée). Il est documenté qu'un code à usage unique ne rend pas le cookie non rejouable pendant ses 12 h, et qu'une connexion WebSocket déjà ouverte survit au retrait du grant (limite existante).

## 7. Mail, journal, purge

Expéditeur fixe `Synunnel <noreply@synunnel.fr>`, objet « Ton code d'accès à {hôte} », corps : le code, sa durée, « Si tu n'as rien demandé, ignore ce mail. », aucun lien qui ouvrirait l'accès. `security_events` : demande (réelle ou non, sans le dire dans la réponse), succès, verrouillage, sortie, avec l'email invité et l'adresse, jamais le code. Purge des `guest_challenges` expirés par `reconcile.py` (les sessions et codes suivent la purge par expiration existante adaptée aux nouvelles tables).

## 8. Interface

Page Accès d'une adresse : case « Accès par code mail pour ces personnes, sans compte » (décochée par défaut), texte : « Chaque personne de la liste reçoit un code à 6 chiffres par mail. Un seul facteur : réserve-le aux services qui le supportent. » Pages de code, de vérification et de sortie : `no-store`, sans JavaScript.

## 9. Tests

Réponses et chemin identiques pour autorisé / non autorisé / compte existant / adresse bloquée / option désactivée ; factice jamais échangeable ; 5 échecs = challenge mort, budget cumulatif 24 h ; expiration ; deux vérifications simultanées (un succès) ; quotas simultanés (plafond tenu) ; grant retiré puis rétabli (ancien challenge et ancienne session morts) ; suspension puis réapprobation du propriétaire (idem) ; option désactivée à chaque étape ; email devenu compte ; propriétaire refusé en invité ; `REQUIRE_2FA=1` sans et avec `GUEST_CODES_WITH_2FA` ; session d'invité refusée sur un autre hôte ; sortie par `POST` et rejeu du cookie ensuite ; cookie retiré avant le service ; MAC en base sans code en clair ; SMTP en panne sans changement de réponse. Essai de bout en bout : activation de l'option, code lu dans la boîte simulée, accès par HTTPS, sortie.
