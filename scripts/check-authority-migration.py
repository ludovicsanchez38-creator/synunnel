#!/usr/bin/env python3
"""Teste la migration NS/SOA sur une zone .test éphémère de PowerDNS."""

import os

import requests

from synunnel.dns import PowerDNS

DOMAIN = "authority-check.synunnel.test"


def main() -> None:
    url = os.environ["PDNS_API_URL"]
    key = os.environ["PDNS_API_KEY"]
    old = PowerDNS(url, key, ("ns1.old.invalid.", "ns2.old.invalid."))
    current = PowerDNS(url, key, (f"{os.environ['NS1_HOST']}.", f"{os.environ['NS2_HOST']}."))
    try:
        old._request("GET", f"/zones/{DOMAIN}.")
    except requests.HTTPError as exc:
        if exc.response.status_code != 404:
            raise
    else:
        raise SystemExit("Zone de contrôle déjà présente ; aucune modification.")
    old.create_zone(DOMAIN)
    try:
        if not current.migrate_authority(DOMAIN, os.environ["SOA_RNAME"]):
            raise AssertionError("La zone legacy n'a pas été migrée.")
        if current.migrate_authority(DOMAIN, os.environ["SOA_RNAME"]):
            raise AssertionError("La seconde migration n'est pas idempotente.")
        rrsets = current._request("GET", f"/zones/{DOMAIN}.").json()["rrsets"]
        apex = f"{DOMAIN}."
        soa = next(item for item in rrsets if item["name"] == apex and item["type"] == "SOA")
        ns = next(item for item in rrsets if item["name"] == apex and item["type"] == "NS")
        assert soa["records"][0]["content"].split()[:2] == [current.nameservers[0], os.environ["SOA_RNAME"]]
        assert {record["content"] for record in ns["records"]} == set(current.nameservers)
        print("Migration NS/SOA PowerDNS réelle et idempotente : OK")
    finally:
        current.delete_zone(DOMAIN)


if __name__ == "__main__":
    main()
