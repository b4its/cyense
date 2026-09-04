"""OSINT reconnaissance — adaptation of famous open-source OSINT tooling.

Adds read-only, public-datasource OSINT checks to the website/domain engines
so a single scan surfaces the *asset* picture a human OSINT analyst would
gather, without adding invasive traffic:

  * **whois / RDAP** — registration data, expiry, registrant org, name
    servers (adaptation of ``whois`` + BootstrapRDAP). The expiry observation
    also backs the OWASP "Allowing Domains or Accounts to Expire" class.
  * **dnsrecon / dnsx** — DNS record enumeration via DNS-over-HTTPS
    (JSON ``dns.google``/Cloudflare resolver): A/AAAA, MX, NS, TXT, CNAME,
    SOA. ``TXT`` often leaks SPF/DMARC/ownership-verification strings that
    help an attacker map infrastructure.
  * **Team-Cymru asn / asnmap** — netblock + ASN + point-of-contact for the
    target IP from the public NETNAME registry (``whois.cymru.com``), mapping
    an IP to its owning organization and CIDR.

Everything is best-effort and read-only: any resolver/API failure yields fewer
findings, never a failed scan. Results are deterministic where the public
datasource allows it.
"""

from __future__ import annotations

import asyncio
import ipaddress
from typing import Any
from urllib.parse import urlparse

import httpx

# DNS-over-HTTPS JSON endpoints (RFC 8484/8427 style, GET with ``?dns=`` is
# the wire-format variant; the JSON API is ``?name=&type=``).
_DOH_ENDPOINTS = (
    "https://dns.google/resolve",
    "https://cloudflare-dns.com/dns-query",
)

# Type codes used by the JSON DoH API.
_DNS_TYPES = {
    "A": 1,
    "AAAA": 28,
    "MX": 15,
    "NS": 2,
    "TXT": 16,
    "CNAME": 5,
    "SOA": 6,
}

_DEFAULT_TIMEOUT = 10.0


def _vcard_value(ent: dict, field_name: str) -> str | None:
    """Safe vcard field extraction from an RDAP entity.

    RDAP ``vcardArray`` is ``["vcard", [[<field>, {}, "type", value], ...]]``.
    Real-world responses can be shallow/malformed (``[["vcard"], [[]]]`` or a
    field tuple shorter than 4 items) — indexing ``[1][0][3]`` directly crashed
    the whole OSINT stage. Returns the first value whose field name matches, or
    None.
    """
    vcard_array = ent.get("vcardArray")
    if not isinstance(vcard_array, (list, tuple)) or len(vcard_array) < 2:
        return None
    items = vcard_array[1]
    if not isinstance(items, (list, tuple)):
        return None
    for item in items:
        if not isinstance(item, (list, tuple)) or len(item) < 4:
            continue
        try:
            if str(item[0]).lower() == field_name:
                return str(item[3])
        except Exception:  # noqa: BLE001 — never let a malformed vcard kill OSINT
            continue
    return None


# ---------------------------------------------------------------------------
# RDAP / whois-style registration info
# ---------------------------------------------------------------------------

def _hostname_of(url_or_domain: str) -> str:
    """Best-effort hostname extraction from a URL or bare domain."""
    s = (url_or_domain or "").strip().lower()
    if "://" in s:
        s = urlparse(s).hostname or s
    s = s.split("/")[0].split(":")[0].rstrip(".")
    return s


def _registrable(host: str) -> str:
    """Strip www/subdomains to a base registrable domain (2-label default,
    with a small public-suffix heuristic for multi-label registries)."""
    from app.engines.domain_engine import normalize_domain

    if not host:
        return ""
    try:
        ipaddress.ip_address(host)
        return ""  # IPs have no RDAP domain record
    except ValueError:
        pass
    return normalize_domain(host)


async def rdap_lookup_domain(
    domain: str,
    timeout: float = _DEFAULT_TIMEOUT,
) -> dict[str, Any]:
    """Query the RDAP bootstrap for a domain's registration record.

    Returns a normalized dict (keys: domain, registrar, expiry_date,
    created_date, updated_date, status, emails, nameservers, registrant_org)
    or {} on any failure (best-effort, never raises).
    """
    host = _hostname_of(domain)
    base = _registrable(host)
    if not base:
        return {}
    try:
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as c:
            resp = await c.get(f"https://rdap.org/domain/{base}")
            resp.raise_for_status()
            data = resp.json()
    except (httpx.HTTPError, ValueError):
        return {}

    out: dict[str, Any] = {"domain": base}
    entities = data.get("entities", [])
    for event in data.get("events", []):
        action = event.get("eventAction", "")
        date = event.get("eventDate", "")
        if action == "expiration":
            out["expiry_date"] = date
        elif action == "registration":
            out["created_date"] = date
        elif action == "last changed":
            out["updated_date"] = date

    nameservers: list[str] = []
    emails: set[str] = set()
    org = ""
    registrar = ""
    for ent in entities:
        if not isinstance(ent, dict):
            continue
        roles = ent.get("roles", [])
        if not isinstance(roles, list):
            roles = []
        # Registrar / registrant org — via safe vcard extraction (malformed
        # vcardArray used to crash the whole OSINT stage).
        if "registrar" in roles:
            registrar = _vcard_value(ent, "fn") or registrar
        org = _vcard_value(ent, "org") or org
        email = _vcard_value(ent, "email")
        if email:
            emails.add(email)

    for ns in data.get("nameservers", []) if isinstance(data.get("nameservers"), list) else []:
        if isinstance(ns, dict) and ns.get("ldhName"):
            nameservers.append(ns["ldhName"])

    out["registrar"] = registrar or None
    out["registrant_org"] = org or None
    out["emails"] = sorted(emails)
    out["nameservers"] = nameservers
    out["status"] = data.get("status", [])
    return out


async def rdap_lookup_ip(
    ip: str,
    timeout: float = _DEFAULT_TIMEOUT,
) -> dict[str, Any]:
    """RDAP lookup for an IPv4/IPv6 address → netrange/ASN/org/emails."""
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return {}
    try:
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as c:
            resp = await c.get(f"https://rdap.org/ip/{ip}")
            resp.raise_for_status()
            data = resp.json()
    except (httpx.HTTPError, ValueError):
        return {}
    out: dict[str, Any] = {"ip": ip}
    out["netrange"] = data.get("handle") if data.get("handle") else data.get("name")
    out["startAddress"] = data.get("startAddress")
    out["endAddress"] = data.get("endAddress")
    out["cidr"] = (
        [c["v4prefix"] + "/" + str(c["length"]) for c in data.get("cidr0_cidrs", [])]
        if isinstance(data.get("cidr0_cidrs"), list)
        else []
    )
    org = ""
    emails: set[str] = set()
    for ent in data.get("entities", []):
        if not isinstance(ent, dict):
            continue
        org = _vcard_value(ent, "org") or org
        email = _vcard_value(ent, "email")
        if email:
            emails.add(email)
    out["org"] = org or None
    out["emails"] = sorted(emails)
    out["country"] = _vcard_country(data.get("entities", []))
    return out


def _vcard_country(entities: list[Any]) -> str | None:
    """Best-effort country code from the vcard ADR field of RDAP entities."""
    for e in entities:
        if not isinstance(e, dict):
            continue
        vcard_array = e.get("vcardArray") or []
        if not isinstance(vcard_array, (list, tuple)) or len(vcard_array) < 2:
            continue
        for item in vcard_array[1]:
            if not isinstance(item, (list, tuple)) or len(item) < 4:
                continue
            if str(item[0]).lower() != "adr":
                continue
            adr_items = item[3] if isinstance(item[3], list) else item[3].split(";")
            for x in reversed([str(a).strip() for a in adr_items]):
                if x:
                    return x
    return None


# ---------------------------------------------------------------------------
# DNS-over-HTTPS record enumeration (dnsrecon / dnsx style)
# ---------------------------------------------------------------------------

async def _doh_query(
    domain: str,
    type_code: int,
    timeout: float,
) -> list[str]:
    for endpoint in _DOH_ENDPOINTS:
        try:
            async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as c:
                resp = await c.get(
                    endpoint,
                    params={"name": domain, "type": type_code},
                )
                resp.raise_for_status()
                data = resp.json()
            answers = data.get("Answer", [])
            if not answers:
                return []
            return [a.get("data", "") for a in answers if a.get("data")]
        except (httpx.HTTPError, ValueError):
            continue
    return []


async def dns_record_enum(
    domain: str,
    timeout: float = _DEFAULT_TIMEOUT,
) -> dict[str, list[str]]:
    """Collect A/AAAA/MX/NS/TXT/CNAME/SOA records via DNS-over-HTTPS.

    Resolver outages are tolerated: each record type is tried on up to two
    resolvers and empty on failure. Returns ``{'A': [...], 'MX': [...], ...}``.
    """
    host = _hostname_of(domain)
    if not host:
        return {}
    results: dict[str, list[str]] = {}
    for label, code in _DNS_TYPES.items():
        vals = await _doh_query(host, code, timeout)
        if vals:
            results[label] = list(dict.fromkeys(vals))
    return results


# ---------------------------------------------------------------------------
# ASN / netblock via Team Cymru (asnmap / cymru whois adaptation)
# ---------------------------------------------------------------------------

async def asn_lookup(
    ip: str,
    timeout: float = _DEFAULT_TIMEOUT,
) -> dict[str, Any]:
    """Map an IP to ASN / CIDR / org via Team Cymru's whois service.

    Returns {'ip', 'asn', 'cidr', 'country', 'registrant'} or {} on failure.
    """
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return {}
    import socket

    def _query() -> dict[str, Any]:
        got: dict[str, Any] = {}
        try:
            with socket.create_connection(("whois.cymru.com", 43), timeout=timeout) as s:
                payload = f"begin\nverbose\n{ip}\nend\n".encode()
                s.sendall(payload)
                data = b""
                while True:
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                    if len(data) > 4096:
                        break
            text = data.decode(errors="replace")
            # Async response: one data row per queried IP.
            for line in text.splitlines():
                parts = line.split("|")
                if len(parts) >= 5:
                    asn = parts[0].strip()
                    if asn.isdigit():
                        got["asn"] = asn
                        got["cidr"] = parts[1].strip()
                        got["country"] = parts[2].strip()
                        got["registrant"] = parts[3].strip() or None
                        got["ip"] = parts[4].strip() or ip
                        break
        except (OSError, TimeoutError):
            return {}
        return got

    return await asyncio.get_running_loop().run_in_executor(None, _query)


# ---------------------------------------------------------------------------
# Aggregated entry point for the website engine discovery stage
# ---------------------------------------------------------------------------

async def osint_passive_gather(
    url: str,
    ip: str | None = None,
    timeout: float = _DEFAULT_TIMEOUT,
) -> dict[str, Any]:
    """Run the full OSINT bundle and normalize outputs for finding builders.

    Returns a dict with keys ``domain``, ``rdap``, ``dns``, ``asn``. Each is
    ``None``/{} when the corresponding datasource failed (best-effort).
    """
    host = _hostname_of(url)
    base = _registrable(host)
    results: dict[str, Any] = {"domain": base or host}
    if base:
        results["rdap"] = await rdap_lookup_domain(base, timeout)
        results["dns"] = await dns_record_enum(host, timeout)
    if ip:
        results["asn"] = await asn_lookup(ip, timeout)
    return results


__all__ = [
    "rdap_lookup_domain",
    "rdap_lookup_ip",
    "dns_record_enum",
    "asn_lookup",
    "osint_passive_gather",
    "_hostname_of",
    "_registrable",
]
