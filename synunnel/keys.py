"""Génération de clés WireGuard par l'outil officiel."""

import subprocess


def generate_keypair() -> tuple[str, str]:
    """Paire WireGuard (privée, publique)."""
    private = subprocess.run(["wg", "genkey"], check=True, capture_output=True, text=True).stdout.strip()
    public = subprocess.run(["wg", "pubkey"], input=private + "\n", check=True,
                            capture_output=True, text=True).stdout.strip()
    return private, public
