# Historique des versions

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
