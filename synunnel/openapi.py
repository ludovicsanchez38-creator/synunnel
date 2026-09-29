"""Description OpenAPI 3.1 de l'API pour agents. Les tests vérifient qu'elle colle aux routes réelles."""

from flask import Flask

from . import __version__

ERROR = {"$ref": "#/components/schemas/Error"}
CLAIM = {"type": "object", "properties": {
    "id": {"type": "integer"}, "domain": {"type": "string"}, "created_at": {"type": "string"},
    "txt_record": {"type": "object", "properties": {"type": {"type": "string"}, "name": {"type": "string"},
                                                    "value": {"type": "string"}}}}}


def _json(schema: dict, description: str) -> dict:
    return {"description": description, "content": {"application/json": {"schema": schema}}}


def _errors(*codes: int) -> dict:
    labels = {400: "Corps illisible ou qui n'est pas un objet JSON", 401: "Jeton absent, invalide, expiré ou révoqué",
              403: "Permission du jeton insuffisante, ou double authentification exigée par l'instance "
                   "(code mfa_required)",
              404: "Ressource introuvable dans ce compte", 409: "Conflit, quota atteint ou ressource utilisée",
              415: "Corps attendu en application/json", 422: "Champ invalide", 429: "Trop de requêtes (voir Retry-After)"}
    return {str(code): _json(ERROR, labels[code]) for code in codes}


def _op(summary: str, permission: str | None, ok: dict, *errors: int, body: dict | None = None,
        extra_ok: dict | None = None) -> dict:
    codes = set(errors) | ({403} if permission else set()) | ({400, 415, 422} if body else set())
    operation = {"summary": summary, "security": [{"bearer": []}], "x-permission": permission or "lecture",
                 "responses": {**ok, **(extra_ok or {}), **_errors(401, 429, *sorted(codes))}}
    if body:
        operation["requestBody"] = {"required": True, "content": {"application/json": {"schema": body}}}
    return operation


def document(app: Flask) -> dict:
    def ids(*names: str) -> list[dict]:
        return [{"name": name, "in": "path", "required": True, "schema": {"type": "integer", "minimum": 1}}
                for name in names]
    return {
        "openapi": "3.1.0",
        "info": {
            "title": "Synunnel, API pour agents",
            "version": __version__,
            "description": (
                "Un jeton se crée et se révoque depuis le tableau de bord (page Jetons d'API), jamais par l'API. "
                "Tout jeton peut lire ; chaque écriture exige la permission indiquée en x-permission "
                "(domains, machines, addresses, sharing). Une machine se déclare avec sa clé publique : générez "
                "la paire sur la machine (umask 077 ; wg genkey > cle.privee ; chmod 600 cle.privee ; wg pubkey < cle.privee). Ajout d'un domaine : POST "
                "/domains renvoie l'enregistrement TXT à poser chez l'hébergeur DNS actuel, puis POST "
                "/claims/{id}/verify crée la zone et recopie les enregistrements publics ; vérifiez-la avant de "
                "déléguer le domaine aux serveurs de noms indiqués par GET /me. N'envoyez le jeton qu'à "
                "l'adresse du tableau de bord ci-dessous : les "
                "adresses publiées le refusent. Une création rejouée avec les mêmes valeurs renvoie 200 et la "
                "ressource existante. « synced » à false signifie que la mise en service se terminera au "
                "prochain rapprochement automatique (quelques minutes). Un jeton meurt au premier changement "
                "de justificatif de son compte (mot de passe, double authentification, suspension) : 401. "
                "Sur une instance qui exige la double authentification, un compte sans elle reçoit 403 "
                "mfa_required."
            ),
        },
        "servers": [{"url": f"https://{app.config['DASHBOARD_HOST']}/api/v1"}],
        "components": {
            "securitySchemes": {"bearer": {"type": "http", "scheme": "bearer", "bearerFormat": "syn_..."}},
            "schemas": {
                "Error": {"type": "object", "required": ["error"], "properties": {"error": {
                    "type": "object", "required": ["code", "message"],
                    "properties": {"code": {"type": "string"}, "message": {"type": "string"}}}}},
                "Domain": {"type": "object", "properties": {
                    "id": {"type": "integer"}, "name": {"type": "string"}, "created_at": {"type": "string"}}},
                "Machine": {"type": "object", "properties": {
                    "id": {"type": "integer"}, "name": {"type": "string"}, "ip": {"type": "string"},
                    "public_key": {"type": "string"}, "created_at": {"type": "string"}}},
                "Peer": {"type": "object", "properties": {
                    "address": {"type": "string"}, "server_public_key": {"type": "string"},
                    "endpoint": {"type": "string"}, "allowed_ips": {"type": "string"},
                    "persistent_keepalive": {"type": "integer"}}},
                "Address": {"type": "object", "properties": {
                    "id": {"type": "integer"}, "hostname": {"type": "string"}, "domain_id": {"type": "integer"},
                    "machine_id": {"type": "integer"}, "port": {"type": "integer"}, "protected": {"type": "boolean"},
                    "shared": {"type": "boolean"}, "created_at": {"type": "string"}}},
            },
        },
        "paths": {
            "/me": {"get": _op("Compte, jeton, usage, quotas et serveurs de noms", None,
                               {"200": _json({"type": "object"}, "Compte")})},
            "/domains": {
                "get": _op("Domaines du compte", None, {"200": _json({"type": "object", "properties": {
                    "domains": {"type": "array", "items": {"$ref": "#/components/schemas/Domain"}}}},
                    "Liste complète, bornée par le quota")}),
                "post": _op("Demander un domaine : renvoie le TXT de preuve à poser", "domains",
                            {"201": _json({"type": "object", "properties": {"claim": CLAIM}}, "Demande créée")},
                            409, 415, 422,
                            body={"type": "object", "additionalProperties": False,
                                  "required": ["domain", "mail_records_checked"],
                                  "properties": {"domain": {"type": "string", "maxLength": 253},
                                                 "dkim_selectors": {"type": "array", "items": {"type": "string"},
                                                                    "maxItems": 20},
                                                 "mail_records_checked": {"type": "boolean", "description":
                                                     "Doit valoir true : les sélecteurs DKIM et les "
                                                     "enregistrements mail ont été recensés"}}},
                            extra_ok={"200": _json({"type": "object"}, "Même demande rejouée")}),
            },
            "/domains/{domain_id}": {
                "get": {**_op("Domaine et ses enregistrements", None, {"200": _json(
                    {"type": "object"}, "Domaine")}, 404), "parameters": ids("domain_id")},
                "delete": {**_op("Supprimer un domaine sans adresse et qui n'est plus délégué à l'instance (sinon 409 in_use, delegation_active ou delegation_unknown) ; sa zone reste servie 48 heures (caches des résolveurs), puis est retirée du DNS de l'instance (zone_removed_after)",
                                 "domains", {"200": _json({"type": "object"}, "Supprimé")}, 404, 409),
                           "parameters": ids("domain_id")},
            },
            "/domains/{domain_id}/records": {"post": {**_op(
                "Ajouter un enregistrement (A, AAAA, CNAME, MX, TXT, CAA)", "domains",
                {"201": _json({"type": "object"}, "Enregistrement créé")}, 404, 409, 415, 422,
                body={"type": "object", "additionalProperties": False, "required": ["name", "type", "content"],
                      "properties": {"name": {"type": "string", "maxLength": 255, "description": "« @ » pour la racine"},
                                     "type": {"type": "string", "enum": ["A", "AAAA", "CNAME", "MX", "TXT", "CAA"]},
                                     "content": {"type": "string", "maxLength": 4096},
                                     "ttl": {"type": "integer", "minimum": 300, "maximum": 86400}}},
                extra_ok={"200": _json({"type": "object"}, "Enregistrement identique déjà présent")}),
                "parameters": ids("domain_id")}},
            "/domains/{domain_id}/records/{record_id}": {"delete": {**_op("Supprimer un enregistrement", "domains", {"200": _json(
                {"type": "object"}, "Supprimé")}, 404), "parameters": ids("domain_id", "record_id")}},
            "/claims": {"get": _op("Demandes de domaine en attente de preuve", None, {"200": _json(
                {"type": "object", "properties": {"claims": {"type": "array", "items": CLAIM}}}, "Liste")})},
            "/claims/{claim_id}": {
                "get": {**_op("Détail d'une demande", None, {"200": _json({"type": "object"}, "Demande")}, 404),
                        "parameters": ids("claim_id")},
                "delete": {**_op("Annuler une demande", "domains", {"200": _json({"type": "object"}, "Annulée")},
                                 404), "parameters": ids("claim_id")},
            },
            "/claims/{claim_id}/verify": {"post": {**_op(
                "Vérifier la preuve TXT et créer la zone (20 vérifications par heure et par compte, 429 avec "
                "Retry-After au-delà)", "domains",
                {"201": _json({"type": "object"}, "Zone créée")}, 404, 409, 422,
                extra_ok={"200": _json({"type": "object"}, "Déjà vérifiée : domaine existant")}),
                "parameters": ids("claim_id")}},
            "/machines": {
                "get": _op("Machines du compte", None, {"200": _json({"type": "object", "properties": {
                    "machines": {"type": "array", "items": {"$ref": "#/components/schemas/Machine"}}}}, "Liste")}),
                "post": _op(
                    "Déclarer une machine avec sa clé publique WireGuard", "machines",
                    {"201": _json({"type": "object", "properties": {
                        "machine": {"$ref": "#/components/schemas/Machine"},
                        "peer": {"$ref": "#/components/schemas/Peer"}, "synced": {"type": "boolean"}}},
                        "Machine créée")},
                    403, 409, 415, 422,
                    body={"type": "object", "additionalProperties": False, "required": ["name", "public_key"],
                          "properties": {"name": {"type": "string", "minLength": 1, "maxLength": 80},
                                         "public_key": {"type": "string", "minLength": 44, "maxLength": 44}}},
                    extra_ok={"200": _json({"type": "object"}, "Même demande rejouée : machine existante")},
                ),
            },
            "/machines/{machine_id}": {"delete": {**_op("Supprimer une machine sans adresse", "machines", {"200": _json(
                {"type": "object"}, "Supprimée")}, 403, 404, 409), "parameters": ids("machine_id")}},
            "/addresses": {
                "get": _op("Adresses du compte", None, {"200": _json({"type": "object", "properties": {
                    "addresses": {"type": "array", "items": {"$ref": "#/components/schemas/Address"}}}}, "Liste")}),
                "post": _op(
                    "Publier une adresse vers une machine et un port", "addresses",
                    {"201": _json({"type": "object", "properties": {
                        "address": {"$ref": "#/components/schemas/Address"}, "synced": {"type": "boolean"}}},
                        "Adresse créée")},
                    403, 404, 409, 415, 422,
                    body={"type": "object", "additionalProperties": False,
                          "required": ["domain_id", "machine_id", "name", "port", "protected"],
                          "properties": {"domain_id": {"type": "integer"}, "machine_id": {"type": "integer"},
                                         "name": {"type": "string", "maxLength": 255,
                                                  "description": "« nas » ou « @ » pour la racine"},
                                         "port": {"type": "integer", "minimum": 1, "maximum": 65535},
                                         "protected": {"type": "boolean", "description":
                                             "true : connexion Synunnel exigée ; false : adresse publique, qui "
                                             "exige aussi la permission sharing"}}},
                    extra_ok={"200": _json({"type": "object"}, "Même demande rejouée : adresse existante")},
                ),
            },
            "/addresses/{address_id}": {"delete": {**_op("Retirer une adresse", "addresses", {"200": _json(
                {"type": "object"}, "Retirée")}, 403, 404), "parameters": ids("address_id")}},
            "/addresses/{address_id}/access": {
                "get": {**_op("Liste d'accès d'une adresse protégée", None, {"200": _json(
                    {"type": "object"}, "Accès")}, 404), "parameters": ids("address_id")},
                "put": {**_op("Remplacer la liste d'accès (100 adresses mail au plus) et l'option d'accès invité",
                              "sharing", {"200": _json({"type": "object"}, "Accès enregistrés")}, 403, 404, 409, 415,
                              422,
                              body={"type": "object", "additionalProperties": False, "required": ["shared", "emails"],
                                    "properties": {"shared": {"type": "boolean"},
                                                   "emails": {"type": "array", "items": {"type": "string"},
                                                              "maxItems": 100},
                                                   "guest_codes": {"type": "boolean", "description":
                                                       "true : les personnes de la liste sans compte reçoivent un "
                                                       "code à 6 chiffres par mail pour entrer (un seul facteur). "
                                                       "Absent : l'option garde sa valeur. 409 si l'instance ne "
                                                       "le propose pas."}}}),
                        "parameters": ids("address_id")},
            },
        },
    }
