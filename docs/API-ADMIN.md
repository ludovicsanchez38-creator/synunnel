# API d'administration

Synunnel n'envoie aucune notification : l'administrateur (ou un script à lui) utilise cette API pour inviter, approuver, refuser ou suspendre des comptes, et retirer un domaine. Tous les appels passent en HTTPS par le nom du tableau de bord, avec le jeton `ADMIN_TOKEN` dans `Authorization: Bearer ...`.

Le jeton est généré à l'installation dans `/etc/synunnel/synunnel.env`. Il reste hors du dépôt ; un outil qui l'utilise le garde dans son propre magasin de secrets, jamais dans une URL ni une messagerie. Chaque appel authentifié est journalisé dans `admin_audit` (heure UTC, IP, méthode, chemin, statut). Les appels refusés ne sont pas journalisés en base : ils sont comptés, et au-delà de 20 refus en 10 minutes depuis une même adresse, l'API répond 429.

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
| POST | `/admin/api/users/{id}/suspend` | aucun | Suspend un compte approuvé : sessions, accès, jetons d'API coupés, routes et pairs retirés ; les données restent |
| POST | `/admin/api/domains/delete` | `{"name": "..."}` | Retire un domaine, ses adresses et sa zone, par exemple pour le rendre à son titulaire actuel |

L'adresse exigée dans le corps lie chaque décision à la demande que tu as lue : si l'identifiant a changé de titulaire entre-temps, la décision ne s'applique pas (404). Une adresse bloquée n'est jamais approuvée. Sans jeton valide : 401.

Exemple :

```bash
read -rsp 'Jeton admin Synunnel : ' SYNUNNEL_ADMIN_TOKEN; printf '\n'
curl --fail --silent --show-error -H "Authorization: Bearer ${SYNUNNEL_ADMIN_TOKEN}" \
  -H 'Content-Type: application/json' -d '{"email":"ami@example.org"}' \
  https://tunnel.example.org/admin/api/invitations
unset SYNUNNEL_ADMIN_TOKEN
```

Un script peut surveiller `pending` et prévenir l'administrateur ; la décision, elle, reste humaine.
