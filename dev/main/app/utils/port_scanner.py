"""Open port scanner for website targets (nmap-style TCP connect scan).

Performs a non-invasive TCP connect scan against a target host extracted
from a website URL — the same technique nmap's ``-sT`` uses. For each common
port it attempts a TCP connect with a short timeout; open ports are reported
with a best-effort service guess and (optionally) a banner grab.

Safety / ethics (PRD ground rules):
  * Read-only: pure TCP connect, no SYN floods, no fuzzing, no exploits.
  * Only targets the host the user pointed the scan at.
  * Rate-limited with a concurrency cap (no port-scan flood).
  * Never connects to ports outside the target host.
"""

from __future__ import annotations

import asyncio
import socket
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

# Common ports → service names (curated subset of the nmap services file).
COMMON_PORTS: dict[int, str] = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "domain",
    80: "http",
    110: "pop3",
    111: "rpcbind",
    135: "msrpc",
    139: "netbios-ssn",
    143: "imap",
    443: "https",
    445: "microsoft-ds",
    465: "smtps",
    587: "submission",
    631: "ipp",
    993: "imaps",
    995: "pop3s",
    1080: "socks-proxy",
    1433: "ms-sql-s",
    1521: "oracle",
    1723: "pptp",
    2222: "ssh",
    3000: "http-alt",
    3306: "mysql",
    3389: "ms-wbt-server",
    5432: "postgresql",
    5900: "vnc",
    5984: "couchdb",
    6379: "redis",
    7001: "weblogic",
    8000: "http-alt",
    8080: "http-proxy",
    8081: "http-proxy",
    8088: "http-alt",
    8443: "https-alt",
    8888: "http-alt",
    9000: "php-fpm",
    9090: "websm",
    9200: "elasticsearch",
    9300: "elasticsearch",
    10000: "webmin",
    11211: "memcached",
    27017: "mongod",
    50000: "http-alt",
}

# Maximum scan timeout per port (seconds) — keep scans snappy.
_DEFAULT_CONNECT_TIMEOUT = 1.5
# Default concurrency cap.
_DEFAULT_MAX_CONCURRENCY = 50
# Banner grab read limit.
_BANNER_MAX_BYTES = 512
_BANNER_TIMEOUT = 2.0


@dataclass
class PortScanResult:
    host: str
    open_ports: list[dict[str, Any]] = field(default_factory=list)
    scanned: int = 0
    duration_ms: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "host": self.host,
            "open_ports": self.open_ports,
            "ports_scanned": self.scanned,
            "duration_ms": self.duration_ms,
        }


def host_from_url(url: str) -> str:
    """Extract hostname from a URL (rejects missing/invalid)."""
    parsed = urlparse(url if "://" in url else f"http://{url}")
    host = parsed.hostname
    if not host:
        raise ValueError(f"cannot determine host from URL: {url!r}")
    # Reject whitespace / invalid hostname chars (e.g. "not a url").
    if any(ch.isspace() for ch in host):
        raise ValueError(f"invalid host in URL: {url!r}")
    return host


async def _probe_one(
    host: str,
    port: int,
    timeout: float,
    banner: bool,
) -> dict[str, Any] | None:
    """Attempt a TCP connect to (host, port). Returns port info or None."""
    try:
        # Resolve host once (IPv4/IPv6 tolerant).
        infos = await asyncio.get_event_loop().getaddrinfo(
            host, port, type=socket.SOCK_STREAM
        )
        if not infos:
            return None
        family, socktype, proto, _, sockaddr = infos[0]

        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(
                host=host, port=port, family=family, proto=proto, ssl=False
            ),
            timeout=timeout,
        )
    except (TimeoutError, OSError, ValueError):
        return None

    info: dict[str, Any] = {
        "port": port,
        "service": COMMON_PORTS.get(port, "unknown"),
        "state": "open",
    }

    # Best-effort banner grab (bounded read).
    if banner:
        try:
            banner_text = await asyncio.wait_for(
                reader.read(_BANNER_MAX_BYTES), timeout=_BANNER_TIMEOUT
            )
            banner_str = banner_text.decode("utf-8", errors="replace").strip()
            if banner_str:
                info["banner"] = banner_str[:200]
        except (TimeoutError, OSError, ValueError):
            pass

    try:
        writer.close()
        try:
            await writer.wait_closed()
        except (OSError, ConnectionError):
            pass
    except Exception:  # noqa: BLE001 — cleanup must never raise
        pass

    return info


async def scan_ports(
    host: str,
    ports: list[int] | None = None,
    *,
    timeout: float = _DEFAULT_CONNECT_TIMEOUT,
    max_concurrency: int = _DEFAULT_MAX_CONCURRENCY,
    banner: bool = True,
) -> PortScanResult:
    """Scan ``host`` for open TCP ports; returns a PortScanResult.

    ``ports`` defaults to :data:`COMMON_PORTS` keys. Concurrency is capped to
    stay polite to the target. Only open ports are returned.
    """
    started = asyncio.get_event_loop().time()
    targets = ports or list(COMMON_PORTS.keys())

    sem = asyncio.Semaphore(max_concurrency)

    async def _bounded(port: int) -> dict[str, Any] | None:
        async with sem:
            return await _probe_one(host, port, timeout, banner)

    results = await asyncio.gather(*(_bounded(p) for p in targets))
    open_ports = [r for r in results if r is not None]
    # Sort by port number for a stable report.
    open_ports.sort(key=lambda r: r["port"])

    return PortScanResult(
        host=host,
        open_ports=open_ports,
        scanned=len(targets),
        duration_ms=int((asyncio.get_event_loop().time() - started) * 1000),
    )
