# Design : double authentification et mot de passe oublié (v0.2) — version 2

Demande de Ludo le 29/09/2026 (« rajoute double auth et mdp oublié »). La version 1 de ce design a reçu un **NO-GO de Codex** (revue du 29/09, 16 constats) ; les constats vérifiés dans le code sont intégrés ci-dessous, numérotés `[C1]` à `[C16]`. Boîte d'envoi `noreply@synunnel.fr` en service (OVH Zimbra, SMTPS 465, DKIM, SPF et DMARC alignés).

## 0. Deux notions nouvelles, sur lesquelles tout repose

- **`users.credential_version`** (entier, incrémenté à chaque changement de justificatif : mot de passe changé ou réinitialisé, 2FA activée, désactivée ou récupérée, suspension). Chaque **jeton d'API**, **jeton de réinitialisation**, **ticket de récupération**, **challenge de connexion** et **enrôlement** porte la version qui l'a émis ; à l'usage, une version différente vaut refus. Un changement de justificatif invalide donc tout ce qui a été émis avant, sans course possible `[C3][C6]`. Les jetons d'API existants sont migrés avec la version courante.
- **Session « prouvée »** : la session Flask porte `mfa=1` quand la 2FA a été vérifiée dans cette session. `session_version` est incrémentée à toute activation, désactivation ou récupération de la 2FA : une session ouverte au mot de passe seul avant l'activation meurt `[C1]`.

## 1. TOTP (RFC 6238)

- **Vérificateur unique** pour toutes les opérations (connexion, désactivation, changement de mot de passe, régénération des codes, création de jeton) `[C9]` : exactement six chiffres ASCII, pas de 30 s, fenêtre ±1 pas, comparaison à temps constant. Le pas **reconnu** (pas le pas courant) est consommé par `UPDATE users SET totp_last_step=:pas WHERE id=:id AND totp_last_step < :pas AND credential_version=:cv` ; succès seulement si une ligne change `[C4][C9]`. Un code utilisé à la connexion ne peut donc pas servir à une autre action. Vecteurs de test de la RFC, frontières de pas, saut d'horloge.
- **Secret chiffré** `[C10]` : AES-GCM (`cryptography`), clé dédiée `TOTP_KEY` (32 octets aléatoires, générée par l'installateur, distincte de `SECRET_KEY`), nonce aléatoire de 96 bits, format versionné `v1:<base64(nonce|chiffré)>`, données associées = `user:<id>`. Déchiffrement impossible = refus fermé. Les permissions de la base et de ses fichiers `-wal`/`-shm` sont forcées à 0600 au démarrage.
- **Enrôlement côté serveur** `[C8]` : table `totp_enrollments(user_id PK, enrollment_id_hash, secret_enc, credential_version, expires_at)`, 10 minutes. Disponible seulement quand la 2FA n'est pas active (remplacer un facteur actif = le désactiver d'abord, avec l'ancien facteur). Le formulaire de confirmation porte l'identifiant d'enrôlement : un second onglet qui a relancé l'enrôlement fait échouer le premier. Le secret n'apparaît que dans la page (QR SVG inline via `segno`, base32 en clair), jamais dans le cookie, un `flash` ou une URL. Confirmation = code valide (qui consomme son pas), puis, dans une seule transaction : secret activé, 10 codes de secours créés, `credential_version` et `session_version` incrémentées, `host_sessions`, `access_codes` et **jetons d'API révoqués** (annoncé avant confirmation) `[C1][C3]`, session courante reconduite avec `mfa=1`.
- **Codes de secours** `[C11]` : 10 codes de 20 caractères base32 (100 bits), affichés groupés par 5, empreinte SHA-256, uniques par compte, consommés par `UPDATE … SET used_at=? WHERE … AND used_at IS NULL` ; la régénération (mot de passe + code) remplace l'ensemble dans une transaction. Affichage unique sur la page de réponse (`no-store`), comme les jetons d'API.
- **Désactivation** : mot de passe + code valide ; mêmes effets que l'activation (versions incrémentées, sessions, accès et jetons coupés).

## 2. Connexion en deux temps `[C7]`

- Mot de passe correct et 2FA active → création côté serveur de `login_challenges(challenge_hash, user_id, session_version, credential_version, next, expires_at, used_at)` (5 minutes) ; le cookie ne porte que l'identifiant du challenge ; CSRF renouvelé. Rien n'est authentifié.
- `/login/2fa` : challenge valide, non consommé, non expiré, compte approuvé, versions courantes, 2FA toujours active ; code TOTP ou de secours vérifié et **challenge consommé dans la même transaction** ; session complète avec `mfa=1`, CSRF renouvelé, redirection `next` validée comme aujourd'hui. Un onglet périmé échoue proprement.
- **Limites** `[C4]` : échecs 2FA comptés par compte (5 / 15 min) et par IP (30 / 15 min), enregistrés même sur refus, dans une écriture séparée de la transaction de sécurité ; un nouveau challenge ne remet rien à zéro. Mêmes compteurs pour toutes les vérifications TOTP et de secours.

## 3. `REQUIRE_2FA` (option d'instance, défaut 0) `[C2]`

Règle d'autorisation appliquée partout quand elle vaut 1 :
- **Tableau de bord** : un compte sans 2FA ne reçoit pas `g.user` ; il n'obtient qu'un état d'enrôlement restreint (page Sécurité et déconnexion). Une session sans `mfa=1` d'un compte avec 2FA est refusée (sessions ouvertes avant l'activation de l'option).
- **Adresses protégées** : `caddy_auth` et le callback vérifient que **le visiteur** (propriétaire ou invité) satisfait l'obligation ; une `host_session` ouverte sans 2FA ne vaut plus.
- **API** : les jetons d'un compte sans 2FA sont refusés (403 `mfa_required`), y compris au recontrôle sous verrou.
- Les routes publiques et l'API d'administration (jeton admin) restent hors de cette règle, explicitement.

## 4. Mot de passe oublié et récupération

Un seul mécanisme de jeton (32 octets `token_urlsafe`, empreinte SHA-256, usage unique, `credential_version` et `user_id` liés), deux voies :

- **Par mail** (si SMTP configuré) — réservé aux adresses **vérifiées** `[C13]` : `users.email_verified_at`. Une adresse est vérifiée depuis la page Sécurité (session prouvée, mot de passe redemandé) par un lien envoyé à la boîte, ou par l'admin (`POST /admin/api/users/{id}/verify-email {"email"}`, après vérification humaine). Aucun compte n'est vérifié par la migration, ni par l'approbation, ni par l'invitation.
  - `/forgot` : réponse identique et **indépendante du SMTP** `[C12]` : l'envoi part dans une file bornée traitée par un fil d'arrière-plan du processus ; compteurs (IP 5/h, adresse 3/h) appliqués avant toute distinction d'existence ; le dépassement par adresse garde la réponse générique (seul l'excès par IP répond 429). Lien `https://{DASHBOARD_HOST}/reset?token=…`, 30 minutes.
- **Par l'admin** `[C5]` : `POST /admin/api/users/{id}/recovery {"email", "scope"}` avec `scope` = `password`, `2fa` ou `both`, compte approuvé et couple id/adresse vérifiés sous verrou ; renvoie un ticket (même format, 24 h) remis par un canal connu. Rien n'est retiré à l'émission : le facteur tombe **à la consommation du ticket**.
- **`/reset` et `/recover`** : le GET n'affiche qu'un formulaire et ne consomme rien (les scanners de messagerie ouvrent les liens) `[C15]` ; le POST (CSRF valide, essais bornés par IP) vérifie le jeton **avant** tout calcul Argon2, puis dans une transaction : jeton non consommé, non expiré, compte approuvé, versions courantes → consommation, nouveau mot de passe (et/ou retrait du secret TOTP, des codes de secours et de tout enrôlement selon la portée), `credential_version` et `session_version` incrémentées, `host_sessions`, `access_codes`, challenges et tous les autres jetons du compte invalidés, jetons d'API révoqués. Aucune session n'est ouverte ; une réinitialisation de mot de passe seul **garde la 2FA**. Refus uniformes (inconnu, expiré, utilisé, compte inéligible).
- **Suspension** : incrémente `credential_version` : tout jeton et ticket émis avant est mort, même après réapprobation `[C6]`.

## 5. Changer son mot de passe (connecté)

Page Sécurité : mot de passe actuel + nouveau (12 caractères minimum) + code 2FA si active. Effets d'une réinitialisation (versions, sessions, accès, jetons d'API révoqués, annoncé avant confirmation) ; la session courante est reconduite.

## 6. Mutations sous garde `[C3]`

La création de jeton d'API recontrôle sous `BEGIN IMMEDIATE` : compte approuvé, `session_version` et `credential_version` identiques à ceux lus lors de la vérification du mot de passe et du code. Les mutations du tableau de bord passent aux actions métier la même garde que l'API (compte approuvé et version de session sous verrou).

## 7. SMTP `[C14]`

SMTPS 465 seulement (587 retiré), `ssl.create_default_context()` (certificat et nom d'hôte vérifiés, aucun repli en clair), `EmailMessage`, expéditeur fixe `SMTP_FROM`, destinataire d'enveloppe explicite = adresse canonique du compte. Configuration : `SMTP_HOST`, `SMTP_PORT=465`, `SMTP_USER`, `SMTP_FROM` dans l'env (valeurs validées, sans espaces ni guillemets) et **mot de passe dans un fichier à part** `SMTP_PASSWORD_FILE` (`/etc/synunnel/smtp-password`, root:synunnel 0640), jamais sourcé par le shell. Sans ces variables, la voie mail est absente et `/forgot` renvoie vers l'administrateur. Échec d'envoi journalisé, sans effet sur ce qui a été validé.

## 8. Notifications, audit, cache `[C15]`

- Mail de notification (si SMTP et adresse vérifiée) après : changement ou réinitialisation de mot de passe, activation, désactivation ou récupération de la 2FA, régénération des codes de secours.
- Table `security_events(at, user_id, actor, event, via, ip)` écrite **dans la transaction** du changement, sans aucun justificatif.
- `Cache-Control: no-store` sur toute page Sécurité, enrôlement, codes, reset et récupération, erreurs comprises.

## 9. Base et migrations `[C16]`

Colonnes `users.credential_version INTEGER NOT NULL DEFAULT 0`, `totp_secret_enc TEXT`, `totp_enabled_at TEXT`, `totp_last_step INTEGER NOT NULL DEFAULT 0`, `email_verified_at TEXT` ; `api_tokens.credential_version` ; tables `totp_enrollments`, `recovery_codes(user_id, code_hash UNIQUE, used_at)`, `login_challenges`, `password_resets(token_hash PK, user_id, kind, scope, credential_version, expires_at, used_at, created_at)`, `email_verifications`, `security_events`, toutes avec `REFERENCES users(id) ON DELETE CASCADE`, index d'expiration, temps en secondes epoch. Migration idempotente sous le verrou existant ; purge des expirés par `reconcile.py`, l'expiration étant de toute façon vérifiée à l'usage.

## 10. Tests (TDD), dont concurrence

Vecteurs RFC 6238 ; anti-rejeu ; session d'avant activation morte ; `REQUIRE_2FA` sur tableau de bord, API, `caddy_auth` et callback, accès déjà ouverts compris ; challenge rejoué, expiré, d'un autre onglet ; code de secours à usage unique ; enrôlement dans deux onglets ; secret chiffré (fichier de base sans secret en clair), clé absente = refus fermé ; `/forgot` identique (compte existant vérifié, non vérifié, inexistant, suspendu) et sans SMTP synchrone ; reset expiré, utilisé, d'avant suspension, d'avant changement de mot de passe ; GET sans effet ; reset de mot de passe gardant la 2FA ; ticket admin `2fa` retirant le facteur seulement à la consommation ; création de jeton chevauchant une réinitialisation (jeton mort) ; deux consommations simultanées du même jeton (un seul succès) ; même code TOTP sur deux opérations concurrentes ; absence de secret dans cookies et journaux ; SMTP en panne ; migration répétée. Essai de bout en bout : enrôlement, connexion 2FA et récupération par HTTPS dans le conteneur.

## Hors périmètre de ce lot

WebAuthn/passkeys ; vérification de l'adresse à l'inscription ; limite globale de débit ; journal d'audit consultable dans l'interface.
