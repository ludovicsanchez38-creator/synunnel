"""Réglages communs : une instance fictive, jamais les valeurs d'une vraie installation."""

INSTANCE = {
    "TESTING": True,
    "PDNS_ENABLED": False,
    "SYNC_COMMAND": "",
    "PUBLIC_IPV4": "192.0.2.10",
    "PUBLIC_IPV6": "",
    "WG_ENDPOINT": "192.0.2.10:51820",
    "DASHBOARD_HOST": "synunnel.fr",
    "NS1_HOST": "ns1.synunnel.fr",
    "NS2_HOST": "ns2.synunnel.fr",
    "REDIRECT_HOSTS": "synunnel.com,www.synunnel.com",
    # Les tests historiques passent par l'inscription libre puis l'approbation ; le mode
    # invitation (par défaut en production) a ses propres tests.
    "REGISTRATION_MODE": "approval",
}


def instance_config(**overrides) -> dict:
    return {**INSTANCE, **overrides}
