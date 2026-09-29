[Modèle à compléter : remplace chaque passage entre crochets, supprime ce paragraphe, puis dépose le fichier dans /etc/synunnel/ et renseigne PRIVACY_FILE. Les traitements et les durées ci-dessous sont ceux du logiciel Synunnel dans sa configuration par défaut ; vérifie-les si tu as modifié l'instance. Ce modèle ne remplace pas l'avis d'un juriste.]

# Qui traite tes données

**[Raison sociale]**, [adresse], exploite cette instance et répond de ses traitements. Contact pour toute question ou demande : [adresse mail].

# Ce que l'instance enregistre

## Titulaires d'un compte

- Adresse mail, empreinte du mot de passe (jamais le mot de passe lui-même), secret de double authentification chiffré, empreintes des codes de secours, statut et date de création du compte : **tant que le compte existe**.
- Domaines, enregistrements DNS, machines (nom, adresse interne du tunnel, clé publique WireGuard), adresses publiées et listes d'accès : **tant que le compte existe**, ou jusqu'à leur suppression.
- Journal de sécurité (connexions, changements de mot de passe ou de double authentification, accès invités), avec l'adresse IP : **365 jours**.
- Journal des appels à l'API, avec l'adresse IP : **90 jours**.
- Revendications de domaine non abouties : **30 jours**.

## Personnes invitées sans compte

Le titulaire d'une adresse protégée peut inscrire ton adresse mail dans sa liste d'accès. Aucun mail ne t'est envoyé à ce moment : tu ne reçois un code que si tu le demandes toi-même sur la page du service.

- Ton adresse mail dans la liste d'accès : **tant que le titulaire l'y laisse**.
- Tes demandes de code (adresse mail, service visé, compteur d'essais, jamais le code en clair) : **24 heures après leur expiration** ; compteurs anti-abus : **48 heures**.
- Ta session sur le service : **12 heures**.
- Journal de sécurité (tes demandes de code, entrées, verrouillages après trop d'essais et sorties, avec ton adresse mail, le service visé et ton adresse IP) : **365 jours**, pour retracer un abus ou une intrusion.

Pour ne plus figurer dans une liste, demande-le à la personne qui t'a invité ou écris à [adresse mail].

## Toute personne qui visite l'instance

- Limitation des tentatives (adresse IP, type d'action) : **24 heures**.
- Journaux techniques du serveur web (adresse IP, date, méthode, chemin, statut ; jetons, codes, cookies et en-têtes d'autorisation retirés) : **30 jours** (durée posée par l'installateur pour tout le journal système).

# Pourquoi

- Fournir le service demandé par les titulaires de compte (exécution du contrat).
- Protéger les comptes et l'instance contre les intrusions et les abus (intérêt légitime de l'exploitant).
- Permettre au titulaire d'une adresse protégée d'ouvrir son service aux personnes qu'il choisit (intérêt légitime du titulaire et de l'exploitant).

# Qui d'autre les voit

- **Hébergement** : [nom de l'hébergeur], serveurs situés en [pays].
- **Envoi des mails** (codes, liens, alertes) : [nom du relais SMTP], qui voit l'adresse du destinataire et le contenu du mail.
- **Certificats HTTPS** : Let's Encrypt les délivre pour chaque adresse publiée. Les noms d'adresse figurent alors, de façon publique et permanente, dans les journaux Certificate Transparency. Ils ne contiennent aucune adresse mail.

Aucune donnée n'est vendue, ni utilisée pour de la publicité ou de la mesure d'audience.

# Cookies

Deux cookies strictement nécessaires, sans consentement à recueillir : la session du tableau de bord (12 heures sans activité, 24 heures au plus) et, sur une adresse protégée, le cookie d'accès à ce service (12 heures). Aucun cookie de mesure ou de publicité.

# Tes droits

Tu peux demander l'accès à tes données, leur rectification, leur effacement, leur portabilité, la limitation de leur traitement ou t'y opposer, en écrivant à [adresse mail]. Réponse sous un mois. Si la réponse ne te satisfait pas, tu peux saisir la CNIL ([cnil.fr](https://www.cnil.fr)).

Dernière mise à jour : [date].
