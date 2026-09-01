"""Tests for the open port scanner (app/utils/port_scanner.py).

Covers: host extraction from URLs, TCP connect scanning against a local
listener, closed-port handling, and the finding conversion in
WebsiteEngine._port_scan_findings.
"""

from __future__ import annotations

import asyncio
import socket

from app.utils.port_scanner import COMMON_PORTS, host_from_url, scan_ports


def test_host_from_url() -> None:
    assert host_from_url("http://example.com/") == "example.com"
    assert host_from_url("https://example.com:8443/path") == "example.com"
    assert host_from_url("example.com") == "example.com"
    assert host_from_url("http://127.0.0.1:8080/x") == "127.0.0.1"


def test_host_from_url_invalid() -> None:
    import pytest
    with pytest.raises(ValueError):
        host_from_url("not a url")


def _start_listener(port: int) -> socket.socket:
    """Bind a TCP listener on localhost:port and return the socket."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", port))
    s.listen(1)
    s.settimeout(5)
    return s


def test_scan_ports_detects_open_listener() -> None:
    """A bound local socket must be reported as an open port."""
    listener = _start_listener(0)
    port = listener.getsockname()[1]
    try:
        result = asyncio.run(scan_ports(
            "127.0.0.1",
            ports=[port],
            timeout=1.0,
            max_concurrency=4,
            banner=False,
        ))
        assert result.scanned == 1
        assert len(result.open_ports) == 1
        assert result.open_ports[0]["port"] == port
        assert result.open_ports[0]["state"] == "open"
    finally:
        listener.close()


def test_scan_ports_ignores_closed() -> None:
    """Unused ports (nothing listening) must not be reported."""
    # Find a definitely-closed port: bind then close leaves the port free.
    probe = _start_listener(0)
    closed_port = probe.getsockname()[1]
    probe.close()

    result = asyncio.run(scan_ports(
        "127.0.0.1",
        ports=[closed_port],
        timeout=0.5,
        max_concurrency=4,
        banner=False,
    ))
    assert result.scanned == 1
    assert result.open_ports == []


def test_scan_ports_common_map() -> None:
    """The common-port map covers well-known services."""
    assert COMMON_PORTS[22] == "ssh"
    assert COMMON_PORTS[80] == "http"
    assert COMMON_PORTS[443] == "https"
    assert COMMON_PORTS[3306] == "mysql"
    assert COMMON_PORTS[5432] == "postgresql"
    assert len(COMMON_PORTS) >= 30


def test_scan_ports_banner_grab() -> None:
    """A service that sends a banner on connect should have it captured."""
    listener = _start_listener(0)
    port = listener.getsockname()[1]

    async def _accept_banner():
        conn, _ = await asyncio.get_event_loop().run_in_executor(
            None, listener.accept
        )
        conn.sendall(b"SSH-2.0-OpenSSH_9.6 test banner\r\n")
        conn.close()

    async def _run():
        asyncio.create_task(_accept_banner())
        result = await scan_ports(
            "127.0.0.1", ports=[port], timeout=1.0,
            max_concurrency=2, banner=True,
        )
        return result

    try:
        result = asyncio.run(_run())
        assert len(result.open_ports) == 1
        banner = result.open_ports[0].get("banner", "")
        assert "SSH-2.0" in banner, f"banner not captured: {banner!r}"
    finally:
        listener.close()


def test_port_scan_findings_conversion() -> None:
    """WebsiteEngine._port_scan_findings builds finding-shaped dicts."""
    from app.engines.website_engine import WebsiteEngine
    from app.utils.port_scanner import PortScanResult

    scan = PortScanResult(
        host="example.com",
        open_ports=[
            {"port": 22, "service": "ssh", "state": "open", "banner": "SSH-2.0"},
            {"port": 443, "service": "https", "state": "open"},
        ],
        scanned=50,
        duration_ms=1200,
    )
    findings = WebsiteEngine._port_scan_findings(scan, "https://example.com/")

    rules = {f["rule"] for f in findings}
    assert "PORT-SCAN-SUMMARY" in rules
    assert "PORT-OPEN" in rules
    # 1 summary + 2 open ports
    assert len(findings) == 3

    open_ports = [f for f in findings if f["rule"] == "PORT-OPEN"]
    ports = {f["evidence"]["port"] for f in open_ports}
    assert ports == {22, 443}
    # SSH (non-http) is medium; https is low
    sev_by_port = {f["evidence"]["port"]: f["severity"] for f in open_ports}
    assert sev_by_port[22] == "medium"
    assert sev_by_port[443] == "low"
    # banner is preserved in evidence
    ssh_f = next(f for f in open_ports if f["evidence"]["port"] == 22)
    assert ssh_f["evidence"]["banner"] == "SSH-2.0"


def test_port_scan_findings_no_ports() -> None:
    """Empty scan produces no findings (no summary either)."""
    from app.engines.website_engine import WebsiteEngine
    from app.utils.port_scanner import PortScanResult

    scan = PortScanResult(host="example.com", open_ports=[], scanned=50)
    findings = WebsiteEngine._port_scan_findings(scan, "https://example.com/")
    assert findings == []


def test_extract_banner_version() -> None:
    from app.utils.port_scanner import _extract_banner_version

    assert _extract_banner_version("SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu", 22) == "9.6p1"
    assert _extract_banner_version("nginx/1.24.0", 80) == "1.24.0"
    assert _extract_banner_version("8.0.35-0ubuntu0.22.04", 3306) == "8.0.35"
    assert _extract_banner_version("220 (vsFTPd 3.0.3)", 21) == "3.0.3"
    assert _extract_banner_version("", 22) is None
