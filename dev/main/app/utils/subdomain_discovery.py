"""Comprehensive Subdomain Discovery & Attack Surface Mapping Engine.

Combines multi-source passive OSINT (Certificate Transparency, Wayback Machine,
AlienVault OTX, HackerTarget) and active DNS dictionary brute-forcing with wildcard
DNS detection, CNAME alias resolution, HTTP service probing, and dangling CNAME
subdomain takeover risk analysis.
"""

from __future__ import annotations

import asyncio
import ipaddress
import re
import socket
import time
import uuid
from typing import Any
from urllib.parse import urlparse

import httpx

from app.engines.domain_engine import normalize_domain
from app.utils.logger import get_logger

log = get_logger("discovery.subdomain")

# -----------------------------------------------------------------------------
# Curated High-Frequency Subdomain Dictionary (160+ Enterprise/Gov Prefixes)
# -----------------------------------------------------------------------------
EXTENDED_SUBDOMAIN_PREFIXES: list[str] = [
    # Top tier core & web
    "www", "api", "admin", "dev", "staging", "stage", "test", "mail",
    "webmail", "portal", "app", "web", "blog", "docs", "help", "support",
    "git", "gitlab", "github", "ci", "jenkins", "cdn", "static", "assets",
    "auth", "login", "sso", "idp", "identity", "oauth", "dashboard",
    "status", "monitor", "mon", "zabbix", "grafana", "kibana", "prometheus",
    # Infrastructure & Networking
    "vpn", "remote", "gateway", "gw", "proxy", "lb", "waf", "edge",
    "cpanel", "whm", "webdisk", "cpcalendars", "cpcontacts", "autodiscover",
    "dns", "ns", "ns1", "ns2", "ns3", "ns4", "mx", "mx1", "mx2",
    "smtp", "pop", "pop3", "imap", "relay", "sip", "voip", "meet", "chat",
    # Data & Storage
    "db", "database", "mysql", "postgres", "sql", "redis", "mongo", "elastic",
    "cloud", "drive", "files", "share", "storage", "s3", "backup", "data",
    # Environments & Quality Assurance
    "old", "new", "beta", "alpha", "demo", "uat", "qa", "lab", "sandbox",
    "preprod", "release", "testing", "dev1", "dev2", "staging1", "v1", "v2", "v3",
    # Enterprise & Corporate Portals
    "corp", "corporate", "internal", "intra", "intranet", "extranet",
    "office", "eoffice", "member", "client", "customer", "partner", "user",
    "account", "billing", "pay", "payment", "checkout", "shop", "store",
    # Government & Institutional Systems (Common in .go.id / .ac.id / public sector)
    "layanan", "ppid", "jdih", "sim", "sipp", "bkd", "diskominfo", "dinkes",
    "bappeda", "kepegawaian", "alumni", "sia", "siakad", "elearning", "moodle",
    "perpustakaan", "lib", "library", "dosen", "mahasiswa", "portal-layanan",
    # Services & APIs
    "service", "services", "microservice", "ws", "socket", "backend", "frontend",
    "core", "hub", "connect", "mobile", "m", "static-assets", "media", "img",
    "images", "video", "download", "downloads", "pub", "public", "secure",
    "security", "pki", "ca", "cert", "registry", "repo", "sonar", "nexus",
    "artifactory", "elk", "panel", "manager", "server", "host", "cluster",
    "k8s", "kube", "docker", "traefik", "nginx", "apache", "iis", "erp", "crm",
]

# -----------------------------------------------------------------------------
# Dangling CNAME Fingerprints for Subdomain Takeover Detection
# -----------------------------------------------------------------------------
TAKEOVER_PATTERNS: list[tuple[str, str, str]] = [
    ("github.io", "GitHub Pages", "There isn't a GitHub Pages site here"),
    ("s3.amazonaws.com", "AWS S3 Bucket", "NoSuchBucket"),
    ("s3-website", "AWS S3 Website", "NoSuchBucket"),
    ("herokuapp.com", "Heroku App", "No such app"),
    ("herokudns.com", "Heroku App", "No such app"),
    ("azurewebsites.net", "Microsoft Azure App Service", "404 Web Site not found"),
    ("cloudapp.net", "Microsoft Azure", "not found"),
    ("trafficmanager.net", "Microsoft Azure Traffic Manager", "404"),
    ("myshopify.com", "Shopify Store", "Sorry, this shop is currently unavailable"),
    ("zendesk.com", "Zendesk Help Desk", "Help Center Closed"),
    ("ghost.io", "Ghost Blog", "The thing you were looking for is no longer here"),
    ("surge.sh", "Surge Static Hosting", "project not found"),
    ("bitbucket.io", "Bitbucket Cloud", "Repository not found"),
    ("pantheonsite.io", "Pantheon Hosting", "404 Unknown Site"),
    ("wordpress.com", "WordPress.com", "Do you want to register"),
    ("fastly.net", "Fastly CDN", "Fastly error: unknown domain"),
    ("firebaseapp.com", "Google Firebase Hosting", "Site Not Found"),
    ("webflow.io", "Webflow Site", "The page you are looking for doesn't exist"),
    ("cname.vercel-dns.com", "Vercel Platform", "The deployment could not be found"),
]

_SUBDOMAIN_CLEAN_RE = re.compile(r"^[a-zA-Z0-9](?:[a-zA-Z0-9\-_]{0,61}[a-zA-Z0-9])?$")
_HTML_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


def extract_base_and_host(target: str) -> tuple[str, str]:
    """Extract (target_host, base_domain) from an arbitrary domain or URL input."""
    raw = (target or "").strip().lower()
    if "://" in raw:
        try:
            parsed = urlparse(raw)
            host = parsed.hostname or raw
        except Exception:
            host = raw.split("/")[0]
    else:
        host = raw.split("/")[0]
    host = host.split(":")[0].rstrip(".")

    # If host is an IP address, return it without a base domain
    try:
        ipaddress.ip_address(host)
        return host, host
    except ValueError:
        pass

    base_domain = normalize_domain(host) or host
    return host, base_domain


def sanitize_subdomain(sub: str, domain: str) -> str | None:
    """Validate and clean a candidate subdomain name belonging to domain."""
    s = sub.strip().lower().lstrip(".*").rstrip(".")
    if not s:
        return None
    if s == domain:
        return domain
    if not s.endswith(f".{domain}") and s != domain:
        return None
    # Verify valid DNS label characters
    labels = s.split(".")
    for lbl in labels:
        if not lbl or not _SUBDOMAIN_CLEAN_RE.match(lbl):
            return None
    return s


# -----------------------------------------------------------------------------
# Passive OSINT Harvesters
# -----------------------------------------------------------------------------

async def harvest_crtsh(domain: str, timeout: float = 12.0) -> set[str]:
    """Query Certificate Transparency logs on crt.sh for domain certificates."""
    subs: set[str] = set()
    url = "https://crt.sh/"
    params = {"q": f"%.{domain}", "output": "json"}
    try:
        async with httpx.AsyncClient(timeout=timeout, verify=False) as client:
            resp = await client.get(url, params=params)
            if resp.status_code != 200:
                return subs
            data = resp.json()
            if not isinstance(data, list):
                return subs
            for row in data:
                name_val = row.get("name_value", "")
                for line in name_val.split("\n"):
                    clean = sanitize_subdomain(line, domain)
                    if clean:
                        subs.add(clean)
    except Exception as exc:
        log.debug("crt.sh harvest warning for %s: %s", domain, exc)
    return subs


async def harvest_wayback(domain: str, timeout: float = 12.0) -> set[str]:
    """Query Wayback Machine CDX API for historical subdomains."""
    subs: set[str] = set()
    url = "https://web.archive.org/cdx/search/cdx"
    params = {
        "url": f"*.{domain}/*",
        "output": "json",
        "fl": "original",
        "collapse": "urlkey",
        "limit": 600,
    }
    try:
        async with httpx.AsyncClient(timeout=timeout, verify=False) as client:
            resp = await client.get(url, params=params)
            if resp.status_code != 200:
                return subs
            data = resp.json()
            if not isinstance(data, list) or len(data) <= 1:
                return subs
            for row in data[1:]:
                if row and isinstance(row, list) and row[0]:
                    try:
                        host = urlparse(row[0]).hostname or ""
                        clean = sanitize_subdomain(host, domain)
                        if clean:
                            subs.add(clean)
                    except Exception:
                        continue
    except Exception as exc:
        log.debug("wayback harvest warning for %s: %s", domain, exc)
    return subs


async def harvest_alienvault(domain: str, timeout: float = 8.0) -> set[str]:
    """Query AlienVault OTX Passive DNS endpoint for domain."""
    subs: set[str] = set()
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
    try:
        async with httpx.AsyncClient(timeout=timeout, verify=False) as client:
            resp = await client.get(url)
            if resp.status_code != 200:
                return subs
            data = resp.json()
            records = data.get("passive_dns") or []
            for item in records:
                hostname = str(item.get("hostname", ""))
                clean = sanitize_subdomain(hostname, domain)
                if clean:
                    subs.add(clean)
    except Exception as exc:
        log.debug("alienvault harvest warning for %s: %s", domain, exc)
    return subs


async def harvest_hackertarget(domain: str, timeout: float = 8.0) -> set[str]:
    """Query HackerTarget Host Search public reconnaissance endpoint."""
    subs: set[str] = set()
    url = "https://api.hackertarget.com/hostsearch/"
    try:
        async with httpx.AsyncClient(timeout=timeout, verify=False) as client:
            resp = await client.get(url, params={"q": domain})
            if resp.status_code != 200 or "error" in resp.text.lower():
                return subs
            for line in resp.text.splitlines():
                if "," in line:
                    host = line.split(",")[0].strip()
                    clean = sanitize_subdomain(host, domain)
                    if clean:
                        subs.add(clean)
    except Exception as exc:
        log.debug("hackertarget harvest warning for %s: %s", domain, exc)
    return subs


def extract_subdomains_from_text(text: str, domain: str) -> set[str]:
    """Extract potential subdomains mentioning domain from arbitrary HTML/JS text."""
    subs: set[str] = set()
    if not text or not domain:
        return subs
    pattern = re.compile(
        r"(?:[a-zA-Z0-9_\-]+\.)+" + re.escape(domain),
        re.IGNORECASE,
    )
    for match in pattern.finditer(text):
        candidate = match.group(0).lower().lstrip(".*").rstrip(".")
        clean = sanitize_subdomain(candidate, domain)
        if clean:
            subs.add(clean)
    return subs


# -----------------------------------------------------------------------------
# Active DNS & Wildcard DNS Detection
# -----------------------------------------------------------------------------

async def detect_wildcard_dns(domain: str) -> str | None:
    """Check if domain resolves non-existent subdomains to a wildcard IP.

    Returns the wildcard IP address if detected, otherwise None.
    """
    rnd_label = f"probe-{uuid.uuid4().hex[:10]}"
    rnd_sub = f"{rnd_label}.{domain}"
    loop = asyncio.get_running_loop()
    try:
        addrs = await loop.getaddrinfo(rnd_sub, None, family=socket.AF_INET)
        if addrs and addrs[0][4]:
            wildcard_ip = addrs[0][4][0]
            log.info("Wildcard DNS detected on %s -> %s", domain, wildcard_ip)
            return wildcard_ip
    except OSError:
        pass
    return None


async def brute_force_dns(
    domain: str,
    prefixes: list[str] | None = None,
    wildcard_ip: str | None = None,
    concurrency: int = 25,
) -> set[str]:
    """Active DNS dictionary enumeration using asynchronous address resolution."""
    candidates = prefixes or EXTENDED_SUBDOMAIN_PREFIXES
    found: set[str] = set()
    sem = asyncio.Semaphore(concurrency)
    loop = asyncio.get_running_loop()

    async def _resolve_candidate(prefix: str) -> None:
        sub = f"{prefix}.{domain}"
        async with sem:
            try:
                addrs = await loop.getaddrinfo(sub, None, family=socket.AF_INET)
                if addrs and addrs[0][4]:
                    resolved_ip = addrs[0][4][0]
                    # Discard if it resolves strictly to the wildcard IP
                    if wildcard_ip and resolved_ip == wildcard_ip:
                        return
                    found.add(sub)
            except OSError:
                pass

    await asyncio.gather(*(_resolve_candidate(p) for p in candidates), return_exceptions=True)
    return found


# -----------------------------------------------------------------------------
# Subdomain Resolution, Metadata Probing & Takeover Verification
# -----------------------------------------------------------------------------

async def resolve_subdomain_profile(
    subdomain: str,
    sources: list[str] | None = None,
    scope: str = "direct",
    probe_http: bool = True,
    http_timeout: float = 3.0,
) -> dict[str, Any]:
    """Resolve IP, CNAME, HTTP status, page title, server, and takeover posture."""
    loop = asyncio.get_running_loop()
    ips: list[str] = []
    cname: str = ""

    # 1. DNS Resolution (A / AAAA)
    try:
        addrs = await loop.getaddrinfo(subdomain, None)
        for a in addrs:
            ip = a[4][0]
            if ip not in ips:
                ips.append(ip)
    except OSError:
        pass

    # 2. CNAME Record Lookup via DNS / DoH
    try:
        # Standard DoH query to Google for clean CNAME retrieval
        async with httpx.AsyncClient(timeout=3.0, verify=False) as c:
            resp = await c.get(f"https://dns.google/resolve?name={subdomain}&type=CNAME")
            if resp.status_code == 200:
                data = resp.json()
                for ans in data.get("Answer", []):
                    if ans.get("type") == 5:  # CNAME
                        cname = str(ans.get("data", "")).rstrip(".").lower()
                        break
    except Exception:
        pass

    primary_ip = ips[0] if ips else ""
    status = "unresolved"
    http_status = None
    title = ""
    server = ""
    response_time_ms = None
    takeover_risk = None
    takeover_details = ""

    # 3. HTTP Probing (if DNS resolved and probe enabled)
    if primary_ip and probe_http:
        t0 = time.monotonic()
        # Prefer HTTPS, fall back to HTTP
        for scheme in ("https", "http"):
            test_url = f"{scheme}://{subdomain}"
            try:
                async with httpx.AsyncClient(
                    timeout=http_timeout,
                    follow_redirects=True,
                    verify=False,
                ) as client:
                    res = await client.get(test_url)
                    http_status = res.status_code
                    response_time_ms = round((time.monotonic() - t0) * 1000, 1)
                    server = res.headers.get("server", "") or res.headers.get("x-powered-by", "")

                    # Extract HTML title
                    body_text = res.text or ""
                    tm = _HTML_TITLE_RE.search(body_text[:4096])
                    if tm:
                        raw_title = tm.group(1).strip()
                        title = " ".join(raw_title.split())[:80]

                    # Check takeover pattern in response body
                    if cname:
                        for pattern, svc_name, fingerprint in TAKEOVER_PATTERNS:
                            if pattern in cname and fingerprint.lower() in body_text.lower():
                                takeover_risk = "CRITICAL"
                                takeover_details = (
                                    f"Dangling CNAME alias pointing to {svc_name} ({cname}) "
                                    f"returned takeover fingerprint: '{fingerprint}'."
                                )
                                break
                    status = "active"
                    break
            except Exception:
                continue

        if not http_status:
            # Resolvable IP via DNS, but HTTP connection refused or timed out
            status = "resolvable"

    # 4. Check for Dangling CNAME on Unresolved Host (High Takeover Risk)
    if not primary_ip and cname:
        for pattern, svc_name, _ in TAKEOVER_PATTERNS:
            if pattern in cname:
                takeover_risk = "HIGH"
                takeover_details = (
                    f"Subdomain does not resolve to an IP but has dangling CNAME to "
                    f"{svc_name} ({cname}). Unclaimed resource may allow domain takeover."
                )
                break

    return {
        "subdomain": subdomain,
        "ip": primary_ip,
        "ips": ips,
        "status": status,  # "active" | "resolvable" | "unresolved"
        "http_status": http_status,
        "title": title,
        "server": server,
        "cname": cname,
        "takeover_risk": takeover_risk,
        "takeover_details": takeover_details,
        "sources": sorted(sources or []),
        "scope": scope,
        "response_time_ms": response_time_ms,
    }


# -----------------------------------------------------------------------------
# Main Orchestration Pipelines
# -----------------------------------------------------------------------------

async def enumerate_all_subdomains(
    target: str,
    max_subdomains: int = 200,
    timeout: float = 15.0,
    probe_http: bool = True,
    sample_text: str | None = None,
) -> list[dict[str, Any]]:
    """Comprehensive discovery of target subdomains across passive & active vectors.

    Orchestrates:
      1. Extraction of target host and registrable base domain.
      2. Concurrent passive harvesting (crt.sh, Wayback Machine, AlienVault, HackerTarget).
      3. In-page link and asset scraping from target response content.
      4. Wildcard DNS detection and active dictionary brute-force.
      5. Full IP resolution, HTTP service probing, and takeover audit.
    """
    target_host, base_domain = extract_base_and_host(target)
    if not target_host or target_host == "127.0.0.1":
        return []

    # Map discovered subdomain -> set of sources
    found_map: dict[str, set[str]] = {}

    def _record(s: str, src: str) -> None:
        if s:
            found_map.setdefault(s, set()).add(src)

    # Add the apex/target itself
    _record(target_host, "target")
    if base_domain != target_host:
        _record(base_domain, "apex")

    # In-page text scraping if supplied
    if sample_text:
        for s in extract_subdomains_from_text(sample_text, base_domain):
            _record(s, "page_crawl")
        if target_host != base_domain:
            for s in extract_subdomains_from_text(sample_text, target_host):
                _record(s, "page_crawl")

    # Concurrent passive & active tasks
    async def _crtsh_job() -> None:
        # Query target_host first
        for s in await harvest_crtsh(target_host, timeout=timeout):
            _record(s, "crt.sh")
        # If target is a sub-unit (e.g. kejati-kaltim.kejaksaan.go.id), also harvest base domain
        if target_host != base_domain:
            for s in await harvest_crtsh(base_domain, timeout=timeout):
                _record(s, "crt.sh")

    async def _wayback_job() -> None:
        for s in await harvest_wayback(target_host, timeout=timeout):
            _record(s, "wayback")
        if target_host != base_domain:
            for s in await harvest_wayback(base_domain, timeout=timeout):
                _record(s, "wayback")

    async def _alienvault_job() -> None:
        for s in await harvest_alienvault(base_domain, timeout=min(timeout, 8.0)):
            _record(s, "alienvault")

    async def _hackertarget_job() -> None:
        for s in await harvest_hackertarget(base_domain, timeout=min(timeout, 8.0)):
            _record(s, "hackertarget")

    async def _dns_job() -> None:
        # Detect wildcard DNS on target_host and base_domain
        wc_target = await detect_wildcard_dns(target_host)
        # Brute force direct target_host prefixes
        for s in await brute_force_dns(target_host, wildcard_ip=wc_target):
            _record(s, "active_dns")

        # If target_host is different from base_domain, also check base_domain
        if target_host != base_domain:
            wc_base = await detect_wildcard_dns(base_domain)
            for s in await brute_force_dns(base_domain, wildcard_ip=wc_base):
                _record(s, "active_dns")

    # Execute all enumeration mechanisms concurrently with overall timeout
    try:
        await asyncio.wait_for(
            asyncio.gather(
                _crtsh_job(),
                _wayback_job(),
                _alienvault_job(),
                _hackertarget_job(),
                _dns_job(),
                return_exceptions=True,
            ),
            timeout=timeout,
        )
    except TimeoutError:
        log.debug("Subdomain enumeration reached overall timeout (%ss)", timeout)

    # Sort candidates prioritizing direct subdomains of target_host, then base_domain
    def _cand_key(h: str) -> tuple[int, int, str]:
        prio = 0 if h == target_host else (1 if h.endswith(f".{target_host}") else 2)
        return (prio, len(h), h)

    candidate_list = sorted(found_map.keys(), key=_cand_key)
    # Cap candidates to avoid excessive load
    candidate_list = candidate_list[:max_subdomains]

    # Resolve details for each candidate with bounded concurrency
    sem = asyncio.Semaphore(15)

    async def _profile_candidate(candidate: str) -> dict[str, Any]:
        is_direct = candidate == target_host or candidate.endswith(f".{target_host}")
        scope = "direct" if is_direct else "parent_domain"
        async with sem:
            return await resolve_subdomain_profile(
                subdomain=candidate,
                sources=list(found_map.get(candidate, [])),
                scope=scope,
                probe_http=probe_http,
            )

    results = await asyncio.gather(
        *(_profile_candidate(c) for c in candidate_list),
        return_exceptions=True,
    )

    profiles: list[dict[str, Any]] = []
    for r in results:
        if isinstance(r, dict) and r.get("subdomain"):
            profiles.append(r)

    # Sort profiles: Active first (by response code), Resolvable second, Unresolved last
    def _sort_key(item: dict[str, Any]) -> tuple[int, int, str]:
        st = item.get("status")
        if st == "active":
            rank = 0
        elif st == "resolvable":
            rank = 1
        else:
            rank = 2
        http_code = item.get("http_status") or 999
        return (rank, http_code, item.get("subdomain", ""))

    profiles.sort(key=_sort_key)
    return profiles


async def quick_subdomain_discovery(
    target: str,
    timeout: float = 4.5,
    sample_text: str | None = None,
) -> list[dict[str, Any]]:
    """Fast, lightweight subdomain profiling designed for pre-scan profiling (profile_target)."""
    target_host, base_domain = extract_base_and_host(target)
    if not target_host or target_host == "127.0.0.1":
        return []

    found_map: dict[str, set[str]] = {}

    def _record(s: str, src: str) -> None:
        if s:
            found_map.setdefault(s, set()).add(src)

    _record(target_host, "target")

    # In-page regex if present
    if sample_text:
        for s in extract_subdomains_from_text(sample_text, base_domain):
            _record(s, "page_crawl")

    # Fast CT log check + Top 20 DNS prefixes
    top_prefixes = [
        "www", "api", "admin", "mail", "webmail", "portal", "dev",
        "staging", "app", "vpn", "auth", "login", "cpanel", "git",
        "cloud", "db", "status", "test", "docs", "help",
    ]

    async def _fast_crtsh() -> None:
        for s in await harvest_crtsh(target_host, timeout=timeout):
            _record(s, "crt.sh")
        if target_host != base_domain:
            for s in await harvest_crtsh(base_domain, timeout=timeout):
                _record(s, "crt.sh")

    async def _fast_dns() -> None:
        wc = await detect_wildcard_dns(target_host)
        discovered = await brute_force_dns(
            target_host, prefixes=top_prefixes, wildcard_ip=wc, concurrency=15
        )
        for s in discovered:
            _record(s, "active_dns")

    try:
        await asyncio.wait_for(
            asyncio.gather(_fast_crtsh(), _fast_dns(), return_exceptions=True),
            timeout=timeout,
        )
    except TimeoutError:
        pass

    # Quick resolution for top candidates
    candidates = list(found_map.keys())[:35]
    sem = asyncio.Semaphore(12)

    async def _quick_profile(c: str) -> dict[str, Any]:
        is_direct = c == target_host or c.endswith(f".{target_host}")
        scope = "direct" if is_direct else "parent_domain"
        async with sem:
            return await resolve_subdomain_profile(
                subdomain=c,
                sources=list(found_map.get(c, [])),
                scope=scope,
                probe_http=True,
                http_timeout=2.0,
            )

    res = await asyncio.gather(*(_quick_profile(c) for c in candidates), return_exceptions=True)
    profiles = [r for r in res if isinstance(r, dict) and r.get("subdomain")]
    profiles.sort(key=lambda x: (0 if x.get("status") == "active" else 1, x.get("subdomain", "")))
    return profiles
