# Historique des versions

## 0.2.0a1 - 29 septembre 2026

Comptes plus sûrs, sur un design revu par une passe adversariale de Codex (NO-GO sur la première version, seize constats intégrés).

- Double authentification TOTP (applications de codes), dix codes de secours, connexion en deux temps par challenge côté serveur, anti-rejeu des codes, secret chiffré en base par une clé dédiée (`TOTP_KEY`).
- `REQUIRE_2FA=1` pour l'imposer à tous les comptes, appliqué au tableau de bord, à l'API (403 `mfa_required`) et aux adresses protégées.
- Mot de passe oublié par mail vers une adresse vérifiée (lien de 30 minutes, réponse générique, envoi SMTPS en arrière-plan), vérification d'adresse depuis la page Sécurité, changement de mot de passe connecté.
- Tickets de récupération émis par l'administrateur (mot de passe, double authentification ou les deux), consommés à l'usage ; attestation d'adresse par l'administrateur.
- Version des justificatifs : jetons d'API, liens, tickets et sessions meurent au premier changement de mot de passe, de double authentification ou à la suspension.
- Mutations du tableau de bord et création de jetons recontrôlées sous verrou ; journal `security_events`, notifications de sécurité, base en 0600.
- Page de connexion : textes selon le mode d'inscription (invitation ou approbation).

## 0.1.0a1 - 29 septembre 2026

Première version publique, en alpha.

- Tableau de bord : comptes validés par l'administrateur, domaines, machines WireGuard, adresses publiques ou protégées, accès partagé avec des comptes invités.
- DNS autoritaire PowerDNS, avec recopie des enregistrements publics avant délégation.
- Preuve de propriété d'un domaine par enregistrement TXT, lue chez ses serveurs faisant autorité.
- HTTPS automatique par Caddy (certificats à la demande, contrôlés par l'application).
- Pare-feu nftables dédié au tunnel, chargé avant l'interface : les machines ne joignent ni le VPS ni les autres machines.
- Routes Caddy liées à leur incarnation : une route périmée n'est jamais réautorisée.
- Zones sans recouvrement entre comptes, déconnexion valable sur tous les appareils.
- Installation en une commande sur Ubuntu 24.04, relançable sans perte de secrets.
- API pour agents (`/api/v1`, OpenAPI) : domaines, DNS, machines par clé publique, adresses, partage ; jetons à permissions créés depuis le tableau de bord.
- La base fait foi et les services convergent par un rapprochement automatique toutes les cinq minutes.
- Interface claire et sobre.
- Essai de bout en bout pour machine jetable ; tests unitaires hermétiques.
