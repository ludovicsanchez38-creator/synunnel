"""Validation DNS, copie préalable et synchronisation PowerDNS."""

import ipaddress
import os
import re
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed

import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.query
import dns.rcode
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.resolver
import requests

DEFAULT_DKIM = ("default", "selector1", "selector2", "google", "mail", "dkim", "k1", "s1", "s2", "brevo")
RECORD_TYPES = {"A", "AAAA", "CNAME", "MX", "TXT", "CAA"}
LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
RECORD_LABEL_RE = re.compile(r"^_?[a-z0-9](?:[a-z0-9_-]{0,61}[a-z0-9])?$")


def configured_nameservers() -> tuple[str, str]:
    ns1, ns2 = os.getenv("NS1_HOST", ""), os.getenv("NS2_HOST", "")
    if not ns1 or not ns2:
        raise RuntimeError("NS1_HOST et NS2_HOST doivent être configurés.")
    return ns1.rstrip(".").lower() + ".", ns2.rstrip(".").lower() + "."


def system_reservations(hosts: list[str], extra: list[str] | None = None) -> tuple[str, ...]:
    """Noms que les comptes ne peuvent pas revendiquer.

    Un nom simple est réservé avec tout ce qu'il contient ; un nom préfixé par « = » ne
    l'est que lui-même. Les hôtes de l'instance et RESERVED_DOMAINS forment des sous-arbres ;
    leurs parents ne sont réservés qu'au nom exact, pour ne pas bloquer tout « co.uk »
    quand l'instance vit sous « example.co.uk ».
    """
    reserved: set[str] = set()
    for host in [*hosts, *(extra or [])]:
        labels = host.strip().rstrip(".").lower().split(".")
        if len(labels) < 2 or not all(labels):
            continue
        reserved.add(".".join(labels))
        reserved.update("=" + ".".join(labels[i:]) for i in range(1, len(labels) - 1))
    return tuple(sorted(reserved))


def is_reserved(domain: str, reserved: tuple[str, ...]) -> bool:
    for name in reserved:
        if name.startswith("="):
            if domain == name[1:]:
                return True
        elif domain == name or domain.endswith(f".{name}"):
            return True
    return False


def normalize_domain(value: str, reserved: tuple[str, ...] = ()) -> str:
    value = value.strip().rstrip(".").lower()
    try:
        result = value.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("Nom de domaine invalide.") from exc
    labels = result.split(".")
    if len(labels) < 2 or len(result) > 253 or any(not LABEL_RE.fullmatch(x) for x in labels):
        raise ValueError("Nom de domaine invalide.")
    if is_reserved(result, reserved):
        raise ValueError("Ce domaine est réservé par l'instance.")
    return result


def relative_name(value: str, *, host_only: bool = False) -> str:
    value = value.strip().rstrip(".").lower()
    if value == "@":
        return value
    labels = value.split(".")
    pattern = LABEL_RE if host_only else RECORD_LABEL_RE
    if not value or len(value) > 240 or any(not pattern.fullmatch(x) for x in labels):
        raise ValueError("Nom d'enregistrement invalide.")
    return value


def fqdn(name: str, domain: str) -> str:
    full = f"{domain}." if name == "@" else f"{name}.{domain}."
    if len(full) > 254:
        raise ValueError("Nom complet trop long (253 caractères au maximum).")
    return full


def canonical_content(kind: str, content: str) -> str:
    kind = kind.upper()
    if kind not in RECORD_TYPES:
        raise ValueError("Type DNS non pris en charge.")
    content = content.strip()
    if not content or len(content) > 4096:
        raise ValueError("Contenu DNS invalide.")
    if kind in {"A", "AAAA"}:
        ip = ipaddress.ip_address(content)
        if (kind == "A" and ip.version != 4) or (kind == "AAAA" and ip.version != 6):
            raise ValueError("L'adresse IP ne correspond pas au type DNS.")
        return str(ip)
    if kind == "TXT" and not content.startswith('"'):
        if len(content.encode("utf-8")) > 255:
            raise ValueError("Un segment TXT ne doit pas dépasser 255 octets ; utilise des guillemets pour plusieurs segments.")
        content = '"' + content.replace("\\", "\\\\").replace('"', '\\"') + '"'
    try:
        record = dns.rdata.from_text(
            dns.rdataclass.IN, dns.rdatatype.from_text(kind), content,
            origin=dns.name.root, relativize=False,
        )
    except (dns.exception.DNSException, ValueError) as exc:
        raise ValueError(f"Contenu {kind} invalide.") from exc
    return record.to_text()


def _lookup(name: str, kind: str) -> list[tuple[str, str, str, int]]:
    resolver = dns.resolver.Resolver(configure=True)
    resolver.timeout = 1.5
    resolver.lifetime = 3
    try:
        answer = resolver.resolve(name, kind, search=False, raise_on_no_answer=False)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return []
    if answer.rrset is None or answer.rrset.name.to_text().lower() != name.lower():
        return []
    ttl = max(300, min(int(answer.rrset.ttl), 86400))
    return [(name.lower(), kind, item.to_text(), ttl) for item in answer]


def snapshot_records(domain: str, selectors: list[str]) -> list[tuple[str, str, str, int]]:
    """Lit le DNS public avant toute création de zone locale."""
    if not _lookup(f"{domain}.", "SOA"):
        raise ValueError("Domaine introuvable dans le DNS public ; aucune zone n'a été créée.")
    checks = [(f"{domain}.", kind) for kind in ("A", "AAAA", "MX", "TXT", "CAA")]
    checks += [(f"www.{domain}.", kind) for kind in ("CNAME", "A", "AAAA", "TXT")]
    checks.append((f"_dmarc.{domain}.", "TXT"))
    checks.append((f"_domainkey.{domain}.", "TXT"))
    for selector in sorted(set(DEFAULT_DKIM) | set(selectors)):
        checks.extend((f"{selector}._domainkey.{domain}.", kind) for kind in ("CNAME", "TXT"))
    records: list[tuple[str, str, str, int]] = []
    with ThreadPoolExecutor(max_workers=8) as pool:
        futures = {pool.submit(_lookup, name, kind): (name, kind) for name, kind in checks}
        for future in as_completed(futures):
            records.extend(future.result())
    # Une entrée CNAME exclut tout autre type au même nom.
    aliases = {name for name, kind, _content, _ttl in records if kind == "CNAME"}
    records = [entry for entry in records if entry[0] not in aliases or entry[1] == "CNAME"]
    result = []
    for name, kind, content, ttl in records:
        rel = "@" if name == f"{domain}." else name[: -(len(domain) + 2)]
        result.append((rel, kind, content, ttl))
    return sorted(set(result))


def public_address(value: str) -> bool:
    """Seules les adresses routables sur Internet sont interrogées : un domaine hostile ne peut pas
    faire sonder le réseau interne de l'instance en annonçant des serveurs de noms privés."""
    try:
        return ipaddress.ip_address(value).is_global
    except ValueError:
        return False


def delegation_status(domain: str, nameservers: tuple[str, str] | None = None) -> tuple[bool | None, list[str]]:
    """Interroge directement les serveurs de la zone parente."""
    parent = dns.name.from_text(domain).parent().to_text()
    try:
        parent_ns = dns.resolver.resolve(parent, "NS", lifetime=4)
        hosts = [item.target.to_text() for item in parent_ns]
        ip = next(str(item) for item in dns.resolver.resolve(hosts[0], "A", lifetime=4) if public_address(str(item)))
        query = dns.message.make_query(f"{domain}.", "NS")
        query.flags &= ~dns.flags.RD
        response = dns.query.udp(query, ip, timeout=4)
        seen = {
            item.target.to_text().lower()
            for section in (response.answer, response.authority)
            for rrset in section if rrset.rdtype == dns.rdatatype.NS
            for item in rrset
        }
    except (dns.exception.DNSException, OSError, IndexError, StopIteration):
        return None, []
    expected = set(nameservers or configured_nameservers())
    return expected <= seen, sorted(seen)


VERIFY_LABEL = "_synunnel"


def ownership_proof(domain: str) -> set[str]:
    """Lit les TXT _synunnel.<domaine> directement chez les serveurs qui font autorité.

    La dernière question part vers ces serveurs, sans résolveur intermédiaire : un
    enregistrement ajouté il y a une minute est vu sans attendre l'expiration d'un cache.
    """
    target = dns.name.from_text(f"{VERIFY_LABEL}.{domain}.")
    resolver = dns.resolver.Resolver(configure=True)
    resolver.timeout = 2
    resolver.lifetime = 5
    try:
        zone = dns.resolver.zone_for_name(dns.name.from_text(f"{domain}."), resolver=resolver, lifetime=5)
        servers = [item.target.to_text() for item in resolver.resolve(zone, "NS")]
    except dns.exception.DNSException as exc:
        raise ValueError("Impossible de trouver les serveurs DNS actuels du domaine.") from exc
    addresses: list[str] = []
    for server in servers[:4]:
        for kind in ("A", "AAAA"):
            try:
                addresses.extend(item.to_text() for item in resolver.resolve(server, kind)
                                 if public_address(item.to_text()))
            except dns.exception.DNSException:
                continue
    values: set[str] = set()
    answered = False
    for address in addresses[:8]:
        try:
            response, _tcp = dns.query.udp_with_fallback(dns.message.make_query(target, "TXT"), address, timeout=3)
        except (dns.exception.DNSException, OSError):
            continue
        # Seule une réponse faisant autorité compte ; les serveurs secondaires en retard
        # n'empêchent pas la preuve si un autre serveur de la zone la porte déjà.
        if not response.flags & dns.flags.AA or response.rcode() not in (dns.rcode.NOERROR, dns.rcode.NXDOMAIN):
            continue
        answered = True
        values.update(
            b"".join(item.strings).decode("utf-8", "replace")
            for rrset in response.answer
            if rrset.rdtype == dns.rdatatype.TXT and rrset.name == target
            for item in rrset
        )
    if not answered:
        raise ValueError("Aucun serveur DNS du domaine n'a répondu ; réessaie dans quelques minutes.")
    return values


class PowerDNS:
    def __init__(self, base_url: str, api_key: str, nameservers: tuple[str, str] | None = None):
        self.base_url = base_url.rstrip("/")
        self.nameservers = nameservers or configured_nameservers()
        self.session = requests.Session()
        self.session.headers.update({"X-API-Key": api_key, "Content-Type": "application/json"})

    def _request(self, method: str, path: str, **kwargs) -> requests.Response:
        response = self.session.request(method, f"{self.base_url}{path}", timeout=8, **kwargs)
        response.raise_for_status()
        return response

    def create_zone(self, domain: str) -> None:
        self._request("POST", "/zones", json={
            "name": f"{domain}.", "kind": "Native", "masters": [], "nameservers": list(self.nameservers),
            "account": "synunnel",
        })

    def ensure_zone(self, domain: str) -> None:
        response = self.session.get(f"{self.base_url}/zones/{domain}.", timeout=8)
        if response.status_code == 404:
            self.create_zone(domain)
        else:
            response.raise_for_status()

    def zone_names(self) -> set[str]:
        return {item["name"].rstrip(".") for item in self._request("GET", "/zones").json()}

    def delete_zone(self, domain: str) -> None:
        self._request("DELETE", f"/zones/{domain}.")

    def migrate_authority(self, domain: str, soa_rname: str) -> bool:
        """Remplace les NS et le SOA d'une zone existante, sans toucher aux autres RRsets."""
        apex = f"{domain}."
        rrsets = self._request("GET", f"/zones/{apex}").json()["rrsets"]
        soa = next((item for item in rrsets if item["name"] == apex and item["type"] == "SOA"), None)
        ns = next((item for item in rrsets if item["name"] == apex and item["type"] == "NS"), None)
        if not soa or len(soa["records"]) != 1 or not ns:
            raise ValueError(f"SOA ou NS manquant dans {apex}")
        parts = soa["records"][0]["content"].split()
        if len(parts) != 7:
            raise ValueError(f"SOA invalide dans {apex}")
        desired_ns = set(self.nameservers)
        current_ns = {record["content"] for record in ns["records"] if not record["disabled"]}
        if parts[0] == self.nameservers[0] and parts[1] == soa_rname and current_ns == desired_ns:
            return False
        parts[0], parts[1] = self.nameservers[0], soa_rname
        parts[2] = str(int(parts[2]) + 1)
        self._request("PATCH", f"/zones/{apex}", json={"rrsets": [
            {"name": apex, "type": "SOA", "ttl": soa["ttl"], "changetype": "REPLACE",
             "records": [{"content": " ".join(parts), "disabled": False}]},
            {"name": apex, "type": "NS", "ttl": ns["ttl"], "changetype": "REPLACE",
             "records": [{"content": name, "disabled": False} for name in self.nameservers]},
        ]})
        return True

    def sync_zone(self, db, domain_id: int, domain: str, public_ipv4: str, public_ipv6: str) -> None:
        current = self._request("GET", f"/zones/{domain}.").json()["rrsets"]
        wanted: dict[tuple[str, str], list[str]] = defaultdict(list)
        ttls: dict[tuple[str, str], int] = {}
        for row in db.execute("SELECT name, type, content, ttl FROM records WHERE domain_id=?", (domain_id,)):
            key = (fqdn(row["name"], domain), row["type"])
            wanted[key].append(row["content"])
            ttls[key] = min(ttls.get(key, row["ttl"]), row["ttl"])
        for row in db.execute("SELECT hostname FROM addresses WHERE domain_id=?", (domain_id,)):
            for kind, ip in (("A", public_ipv4), ("AAAA", public_ipv6)):
                if ip:
                    key = (f"{row['hostname']}.", kind)
                    wanted[key] = [ip]
                    ttls[key] = 300
        for kind, ip in (("A", public_ipv4), ("AAAA", public_ipv6)):
            if ip:
                key = (f"*.{domain}.", kind)
                wanted[key] = [ip]
                ttls[key] = 300
        current_keys = {(item["name"], item["type"]) for item in current if item["type"] not in {"SOA", "NS"}}
        changes = []
        for name, kind in sorted(current_keys - wanted.keys()):
            changes.append({"name": name, "type": kind, "changetype": "DELETE", "records": []})
        for (name, kind), values in sorted(wanted.items()):
            changes.append({
                "name": name, "type": kind, "ttl": ttls[(name, kind)], "changetype": "REPLACE",
                "records": [{"content": value, "disabled": False} for value in sorted(set(values))],
            })
        if changes:
            self._request("PATCH", f"/zones/{domain}.", json={"rrsets": changes})
