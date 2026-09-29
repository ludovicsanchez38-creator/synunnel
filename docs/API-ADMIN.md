# API d'administration

L'administrateur (ou un script à lui) utilise cette API pour inviter, approuver, refuser ou suspendre des comptes, émettre des tickets de récupération, attester une adresse et retirer un domaine. Synunnel n'envoie de mails que si une boîte d'envoi est configurée (voir le README), et jamais pour les invitations. **L'API ne répond qu'en local, sur le VPS** : les appels se font sur `http://127.0.0.1:8000/admin/api/...` depuis une session SSH, avec le jeton `ADMIN_TOKEN` dans `Authorization: Bearer ...`. Par le nom public, Caddy répond 404, et l'application refuse aussi toute requête passée par un proxy (`X-Real-IP` ou `X-Forwarded-For`) : une fuite du jeton ne suffit donc pas, il faut aussi un accès SSH au serveur.

Le jeton est généré à l'installation dans `/etc/synunnel/synunnel.env`. Il reste hors du dépôt ; un outil qui l'utilise le garde dans son propre magasin de secrets, jamais dans une URL ni une messagerie. Chaque appel authentifié est journalisé dans `admin_audit` (heure UTC, IP, méthode, chemin, statut). Les appels refusés ne sont pas journalisés en base : ils sont comptés, et au-delà de 20 refus en 10 minutes depuis une même adresse, l'API répond 429, même au bon jeton (le plafond est vérifié avant la comparaison).

## Inscription : deux modes

- **`REGISTRATION_MODE=invitation`** (par défaut) : l'administrateur crée une invitation pour une adresse et remet le code à la personne par un canal qu'il connaît. Le code, à usage unique et valable 7 jours, ouvre le compte immédiatement. Personne ne peut préinscrire l'adresse d'un autre.
- **`REGISTRATION_MODE=approval`** : inscription libre, puis approbation. Synunnel ne vérifie pas la boîte mail : quelqu'un peut s'inscrire avec l'adresse d'un tiers avant lui. Avant d'approuver, confirme avec la personne, par un autre canal, qu'elle a bien créé ce compte.

## Routes

| Méthode | Chemin | Corps JSON | Effet |
| --- | --- | --- | --- |
| POST | `/admin/api/invitations` | `{"email": "..."}` | Crée une invitation ; la réponse donne le code, à transmettre à la personne |
| GET | `/admin/api/pending` | aucun | Liste les comptes en attente (mode approbation, comptes suspendus) |
| POST | `/admin/api/users/{id}/approve` | `{"email": "..."}` | Approuve le compte en attente qui porte cet identifiant **et** cette adresse |
| POST | `/admin/api/users/{id}/reject` | `{"email": "..."}` | Supprime ce compte en attente et bloque son adresse |
| POST | `/admin/api/users/{id}/suspend` | aucun | Suspend un compte approuvé : sessions, accès, jetons d'API coupés, routes et pairs retirés ; les données restent. Tickets et liens émis avant la suspension restent morts même après une réapprobation |
| POST | `/admin/api/users/{id}/recovery` | `{"email": "...", "scope": "password"}` | Ticket de récupération valable 24 h, à usage unique, à remettre par un canal connu. `scope` : `password` (nouveau mot de passe, la 2FA reste), `2fa` (retire la double authentification, mot de passe actuel exigé), `both`. Rien n'est retiré à l'émission ; la personne l'utilise sur `/recover` |
| POST | `/admin/api/users/{id}/verify-email` | `{"email": "..."}` | Atteste, après vérification humaine, que la boîte appartient au titulaire : elle pourra recevoir un lien de mot de passe oublié |
| POST | `/admin/api/domains/delete` | `{"name": "..."}` | Retire un domaine, ses adresses et sa zone, par exemple pour le rendre à son titulaire actuel |

L'adresse exigée dans le corps lie chaque décision à la demande que tu as lue : si l'identifiant a changé de titulaire entre-temps, la décision ne s'applique pas (404). Une adresse bloquée n'est jamais approuvée. Sans jeton valide : 401.

Exemple :

```bash
ssh admin@tunnel.example.org   # puis, sur le VPS :
read -rsp 'Jeton admin Synunnel : ' SYNUNNEL_ADMIN_TOKEN; printf '\n'
curl --fail --silent --show-error -H "Authorization: Bearer ${SYNUNNEL_ADMIN_TOKEN}" \
  -H 'Content-Type: application/json' -d '{"email":"ami@example.org"}' \
  http://127.0.0.1:8000/admin/api/invitations
unset SYNUNNEL_ADMIN_TOKEN
```

Le jeton se lit sur le VPS avec `sudo grep ^ADMIN_TOKEN= /etc/synunnel/synunnel.env` ; il ne quitte pas la machine.

Un script peut surveiller `pending` et prévenir l'administrateur ; la décision, elle, reste humaine.

## Récupérer un compte

Téléphone perdu sans code de secours, ou mot de passe oublié sans adresse vérifiée : vérifie d'abord l'identité de la personne par un canal que tu connais (appel, rencontre), puis émets un ticket avec la portée la plus étroite possible. Le ticket seul ne suffit pas pour la portée `2fa` : il faut aussi le mot de passe actuel. Son usage coupe toutes les sessions, révoque les jetons d'API et envoie une notification si l'adresse est vérifiée ; chaque émission et chaque usage sont écrits dans `security_events`.

```bash
read -rsp 'Jeton admin Synunnel : ' SYNUNNEL_ADMIN_TOKEN; printf '\n'
curl --fail --silent --show-error -H "Authorization: Bearer ${SYNUNNEL_ADMIN_TOKEN}" \
  -H 'Content-Type: application/json' -d '{"email":"ami@example.org","scope":"2fa"}' \
  http://127.0.0.1:8000/admin/api/users/42/recovery
unset SYNUNNEL_ADMIN_TOKEN
```
