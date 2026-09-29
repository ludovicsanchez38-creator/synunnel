"""Validation DNS, copie préalable et synchronisation PowerDNS."""

import ipaddress
import os
import re
import time
from collections import Counter, defaultdict
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
        try:
            host = host.strip().rstrip(".").lower().encode("idna").decode("ascii")
        except UnicodeError:
            continue
        labels = host.split(".")
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
    if not value or len(value) > 240 or any(len(x) > 63 or not pattern.fullmatch(x) for x in labels):
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
        if "%" in content:
            raise ValueError("Adresse IP avec portée refusée.")
        ip = ipaddress.ip_address(content)
        if (kind == "A" and ip.version != 4) or (kind == "AAAA" and ip.version != 6):
            raise ValueError("L'adresse IP ne correspond pas au type DNS.")
        return str(ip)
    if kind == "TXT" and not content.startswith('"'):
        # Une valeur longue (clé DKIM 2048 bits) est découpée en segments de 255 octets au plus,
        # comme le font les hébergeurs DNS : les résolveurs les recollent.
        segments, current = [], ""
        for char in content:
            if len((current + char).encode("utf-8")) > 255:
                segments.append(current)
                current = ""
            current += char
        segments.append(current)
        content = " ".join('"' + part.replace("\\", "\\\\").replace('"', '\\"') + '"' for part in segments)
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
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    excluded = ("192.88.99.0/24", "64:ff9b::/96", "fec0::/10")
    return ip.is_global and not ip.is_multicast and not any(
        ip.version == ipaddress.ip_network(net).version and ip in ipaddress.ip_network(net) for net in excluded
    )


def delegation_status(domain: str, nameservers: tuple[str, str] | None = None) -> tuple[bool | None, list[str]]:
    """Interroge directement un serveur de la zone parente.

    Renvoie (état, serveurs désignés) : True si la parente désigne tous les serveurs de l'instance, False
    sur une réponse exploitable qui montre la délégation ailleurs (referral de la parente) ou absente (réponse
    négative qui fait autorité, avec le SOA de la parente), None dès que la réponse ne prouve rien (erreur,
    troncature persistante, NS d'un autre nom, réponse de cache, négative sans autorité).
    Une suppression ne s'appuie que sur False, et encore faut-il qu'aucun serveur de l'instance ne figure
    dans la liste (voir still_designated).
    """
    name = dns.name.from_text(domain)
    try:
        parent_ns = dns.resolver.resolve(name.parent(), "NS", lifetime=2)
        hosts = [item.target.to_text() for item in parent_ns]
        ip = next(str(item) for item in dns.resolver.resolve(hosts[0], "A", lifetime=2) if public_address(str(item)))
        query = dns.message.make_query(name, "NS")
        query.flags &= ~dns.flags.RD
        # Réponse tronquée : reprise en TCP. Une liste de serveurs incomplète n'est jamais lue comme entière.
        response, _ = dns.query.udp_with_fallback(query, ip, timeout=2)
    except (dns.exception.DNSException, OSError, IndexError, StopIteration):
        return None, []
    if response.flags & dns.flags.TC or response.rcode() not in (dns.rcode.NOERROR, dns.rcode.NXDOMAIN):
        return None, []

    def designated(section) -> set[str]:
        # Seuls comptent les NS du domaine lui-même, pas ceux d'un autre nom glissés dans la réponse.
        return {item.target.to_text().lower() for rrset in section
                if rrset.rdtype == dns.rdatatype.NS and rrset.name == name for item in rrset}

    referral, answered = designated(response.authority), designated(response.answer)
    seen = referral | answered
    expected = {item.lower() for item in (nameservers or configured_nameservers())}
    authoritative = bool(response.flags & dns.flags.AA)
    if seen & expected:
        # Un serveur de l'instance encore cité, d'où qu'il vienne : la délégation n'est pas retirée.
        return expected <= seen, sorted(seen)
    if answered and not authoritative:
        # NS en section réponse sans AA : une réponse de cache, qui ne prouve rien.
        return None, []
    if seen:
        return False, sorted(seen)
    # Absence de délégation : seulement sur une réponse qui fait autorité, avec le SOA de la parente.
    parent_soa = any(rrset.rdtype == dns.rdatatype.SOA and rrset.name == name.parent() for rrset in response.authority)
    if authoritative and parent_soa:
        return False, []
    return None, []


def still_designated(active: bool | None, seen: list[str], nameservers: tuple[str, str]) -> bool | None:
    """Délégation vue du côté de la suppression : None si inconnue, True dès qu'un serveur de l'instance
    figure encore chez la parente (délégation partielle comprise), False seulement sinon."""
    if active is None:
        return None
    return bool(active) or bool({item.lower() for item in nameservers} & {item.lower() for item in seen})


VERIFY_LABEL = "_synunnel"


def ownership_proof(domain: str) -> set[str]:
    """Lit les TXT _synunnel.<domaine> directement chez les serveurs qui font autorité.

    La dernière question part vers ces serveurs, sans résolveur intermédiaire : un
    enregistrement ajouté il y a une minute est vu sans attendre l'expiration d'un cache.
    """
    target = dns.name.from_text(f"{VERIFY_LABEL}.{domain}.")
    deadline = time.monotonic() + 12
    resolver = dns.resolver.Resolver(configure=True)
    resolver.timeout = 2
    resolver.lifetime = 3
    try:
        zone = dns.resolver.zone_for_name(dns.name.from_text(f"{domain}."), resolver=resolver, lifetime=5)
        servers = [item.target.to_text() for item in resolver.resolve(zone, "NS")]
    except dns.exception.DNSException as exc:
        raise ValueError("Impossible de trouver les serveurs DNS actuels du domaine.") from exc
    counts: Counter = Counter()
    answered = 0
    # Une voix par serveur de noms (et non par adresse) : un serveur joignable en IPv4 et en IPv6
    # ne compte pas double.
    for server in sorted(set(servers))[:4]:
        addresses: list[str] = []
        for kind in ("A", "AAAA"):
            if time.monotonic() > deadline:
                break
            try:
                addresses.extend(item.to_text() for item in resolver.resolve(server, kind)
                                 if public_address(item.to_text()))
            except dns.exception.DNSException:
                continue
        values: set[str] | None = None
        for address in sorted(set(addresses))[:2]:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            try:
                response, _tcp = dns.query.udp_with_fallback(dns.message.make_query(target, "TXT"), address,
                                                             timeout=min(3, remaining))
            except (dns.exception.DNSException, OSError):
                continue
            # Seule une réponse faisant autorité compte.
            if not response.flags & dns.flags.AA or response.rcode() not in (dns.rcode.NOERROR,
                                                                              dns.rcode.NXDOMAIN):
                continue
            values = {
                b"".join(item.strings).decode("utf-8", "replace")
                for rrset in response.answer
                if rrset.rdtype == dns.rdatatype.TXT and rrset.name == target
                for item in rrset
            }
            break
        if values is not None:
            answered += 1
            counts.update(values)
    if not answered:
        raise ValueError("Aucun serveur DNS du domaine n'a répondu ; réessaie dans quelques minutes.")
    # La preuve doit être servie par la majorité des serveurs de noms qui ont répondu : un serveur
    # isolé, repris le temps d'une minute, ne suffit pas.
    return {value for value, seen in counts.items() if seen * 2 > answered}


class PowerDNS:
    def __init__(self, base_url: str, api_key: str, nameservers: tuple[str, str] | None = None):
        self.base_url = base_url.rstrip("/")
        self.nameservers = nameservers or configured_nameservers()
        self.session = requests.Session()
        self.session.headers.update({"X-API-Key": api_key, "Content-Type": "application/json"})

    def _request(self, method: str, path: str, **kwargs) -> requests.Response:
        response = self.session.request(method, f"{self.base_url}{path}", timeout=5, **kwargs)
        response.raise_for_status()
        return response

    def create_zone(self, domain: str) -> None:
        self._request("POST", "/zones", json={
            "name": f"{domain}.", "kind": "Native", "masters": [], "nameservers": list(self.nameservers),
            "account": "synunnel",
        })

    def ensure_zone(self, domain: str) -> None:
        response = self.session.get(f"{self.base_url}/zones/{domain}.", timeout=5)
        if response.status_code == 404:
            self.create_zone(domain)
        else:
            response.raise_for_status()

    def zone_names(self) -> set[str]:
        return {item["name"].rstrip(".") for item in self._request("GET", "/zones").json()}

    def delete_zone(self, domain: str) -> None:
        response = self.session.delete(f"{self.base_url}/zones/{domain}.", timeout=5)
        if response.status_code not in (204, 404):
            response.raise_for_status()

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

    def sync_zone(self, db, domain_id: int, domain: str, public_ipv4: str, public_ipv6: str,
                  deadline: float | None = None) -> None:
        current = self._request("GET", f"/zones/{domain}.").json()["rrsets"]
        wanted: dict[tuple[str, str], list[str]] = defaultdict(list)
        # Enregistrements et adresses lus dans un même instantané de la base.
        opened = not db.in_transaction
        if opened:
            db.execute("BEGIN")
        ttls: dict[tuple[str, str], int] = {}
        for row in db.execute("SELECT name, type, content, ttl FROM records WHERE domain_id=?", (domain_id,)):
            key = (fqdn(row["name"], domain), row["type"])
            wanted[key].append(row["content"])
            ttls[key] = min(ttls.get(key, row["ttl"]), row["ttl"])
        for row in db.execute("SELECT hostname FROM addresses WHERE domain_id=?", (domain_id,)):
            for kind, ip in (("A", public_ipv4), ("AAAA", public_ipv6)):
                key = (f"{row['hostname']}.", kind)
                if ip:
                    wanted[key] = [ip]
                    ttls[key] = 300
                else:
                    # Sans IPv6 sur l'instance, un AAAA recopié mènerait encore à l'ancien serveur et
                    # contournerait la protection de l'adresse : il n'est pas publié.
                    wanted.pop(key, None)
                    ttls.pop(key, None)
        if opened:
            db.commit()
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
        failed = []
        # Suppressions d'abord, puis chaque RRset seul : un enregistrement refusé par PowerDNS
        # n'empêche plus les autres d'être appliqués.
        for change in sorted(changes, key=lambda item: item["changetype"] != "DELETE"):
            if deadline is not None and time.monotonic() > deadline:
                failed.append("budget de temps atteint")
                break
            try:
                self._request("PATCH", f"/zones/{domain}.", json={"rrsets": [change]})
            except requests.HTTPError:
                failed.append(f"{change['name']} {change['type']}")
        if failed:
            raise requests.HTTPError(f"Refusés par PowerDNS : {', '.join(failed)}")
