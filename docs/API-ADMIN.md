# API d'administration

Synunnel n'envoie aucune notification. Syn interroge cette API depuis une autre machine, prévient Ludo, puis appelle la décision qu'il lui donne. Tous les appels utilisent HTTPS sur le nom du tableau de bord et le jeton `ADMIN_TOKEN` dans `Authorization: Bearer ...`.

Le jeton est généré à l'installation dans `/etc/synunnel/synunnel.env`. Il reste hors du dépôt. Syn doit le conserver dans son propre magasin de secrets ; il ne doit apparaître ni dans une URL ni dans un message Telegram. Chaque appel, même refusé, est journalisé dans `admin_audit` avec heure UTC, IP, méthode, chemin et statut.

## Routes

| Méthode | Chemin | Effet | Réponse |
| --- | --- | --- | --- |
| GET | `/admin/api/pending` | Liste les comptes en attente | `{"pending":[{"id":1,"email":"...","created_at":"..."}]}` |
| POST | `/admin/api/users/{id}/approve` | Autorise un compte en attente | `{"id":1,"status":"approved"}` |
| POST | `/admin/api/users/{id}/reject` | Supprime le compte en attente et bloque son adresse | `{"id":1,"status":"rejected","email_blocked":true}` |

Sans jeton valide : 401. Si l'identifiant n'est pas celui d'un compte en attente : 404. Aucun corps n'est requis pour les deux POST. Répéter une décision déjà appliquée donne 404 ; Syn peut ensuite relire `pending` pour confirmer l'état.

Exemple de lecture manuelle, après avoir obtenu le jeton par un canal sûr :

```bash
read -rsp 'Jeton admin Synunnel : ' SYNUNNEL_ADMIN_TOKEN
printf '\n'
curl --fail --silent --show-error \
  -H "Authorization: Bearer ${SYNUNNEL_ADMIN_TOKEN}" \
  https://synunnel.fr/admin/api/pending
unset SYNUNNEL_ADMIN_TOKEN
```

Syn peut interroger `pending` périodiquement et ne notifier Ludo qu'une fois par identifiant. Elle doit attendre son choix explicite avant `approve` ou `reject`. Synunnel ne possède aucun accès à Telegram et ne doit pas être configuré avec un jeton Telegram.
