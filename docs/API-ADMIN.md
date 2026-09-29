# API d'administration

Synunnel n'envoie aucune notification : l'administrateur (ou un script à lui) interroge cette API pour découvrir les comptes en attente, puis applique sa décision. Tous les appels utilisent HTTPS sur le nom du tableau de bord et le jeton `ADMIN_TOKEN` dans `Authorization: Bearer ...`.

Le jeton est généré à l'installation dans `/etc/synunnel/synunnel.env`. Il reste hors du dépôt. Un outil qui l'utilise doit le garder dans son propre magasin de secrets ; il ne doit apparaître ni dans une URL ni dans une messagerie. Chaque appel, même refusé, est journalisé dans `admin_audit` avec heure UTC, IP, méthode, chemin et statut.

## Routes

| Méthode | Chemin | Effet | Réponse |
| --- | --- | --- | --- |
| GET | `/admin/api/pending` | Liste les comptes en attente | `{"pending":[{"id":1,"email":"...","created_at":"..."}]}` |
| POST | `/admin/api/users/{id}/approve` | Autorise un compte en attente | `{"id":1,"status":"approved"}` |
| POST | `/admin/api/users/{id}/reject` | Supprime le compte en attente et bloque son adresse | `{"id":1,"status":"rejected","email_blocked":true}` |

Sans jeton valide : 401. Si l'identifiant n'est pas celui d'un compte en attente : 404. Aucun corps n'est requis pour les deux POST. Répéter une décision déjà appliquée donne 404 ; il suffit de relire `pending` pour confirmer l'état.

Exemple de lecture manuelle, après avoir obtenu le jeton par un canal sûr :

```bash
read -rsp 'Jeton admin Synunnel : ' SYNUNNEL_ADMIN_TOKEN
printf '\n'
curl --fail --silent --show-error \
  -H "Authorization: Bearer ${SYNUNNEL_ADMIN_TOKEN}" \
  https://tunnel.example.org/admin/api/pending
unset SYNUNNEL_ADMIN_TOKEN
```

Un script de surveillance peut interroger `pending` périodiquement et ne prévenir l'administrateur qu'une fois par identifiant. La décision `approve` ou `reject` doit rester humaine : approuver un compte lui ouvre l'ajout de domaines et de machines.
