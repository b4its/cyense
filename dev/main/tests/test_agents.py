"""End-to-end link-mode scan against an in-process ASGI lab app.

The Flask lab is exercised through an httpx ASGI shim so tests stay
hermetic (no external process / port needed).
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import httpx

LAB_APP_PATH = Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "vulnerable_app"
sys.path.insert(0, str(LAB_APP_PATH))


class AsgiShim:
    """Bridge httpx ASGITransport to a Flask/werkzeug app (single-threaded WSGI)."""

    def __init__(self, wsgi_app) -> None:
        self.wsgi_app = wsgi_app

    async def __call__(self, scope, receive, send):  # ASGI interface
        import io

        assert scope["type"] == "http"
        body = b""
        while True:
            message = await receive()
            body += message.get("body", b"")
            if not message.get("more_body", False):
                break

        environ = {
            "REQUEST_METHOD": scope["method"],
            "PATH_INFO": scope["path"],
            "QUERY_STRING": scope.get("query_string", b"").decode(),
            "SERVER_NAME": "lab",
            "SERVER_PORT": "80",
            "wsgi.version": (1, 0),
            "wsgi.url_scheme": "http",
            "wsgi.input": io.BytesIO(body),
            "wsgi.errors": io.StringIO(),
            "wsgi.multithread": False,
            "wsgi.multiprocess": False,
            "wsgi.run_once": False,
        }
        for key, value in scope.get("headers", []):
            name = key.decode().title().replace("-", "_")
            if name == "COOKIE":
                environ["HTTP_COOKIE"] = value.decode()
            elif name == "AUTHORIZATION":
                environ["HTTP_AUTHORIZATION"] = value.decode()
            elif name == "CONTENT_TYPE":
                environ["CONTENT_TYPE"] = value.decode()
            elif name == "CONTENT_LENGTH":
                environ["CONTENT_LENGTH"] = value.decode()

        status_code = 500
        response_headers: list[tuple[str, str]] = []

        def start_response(status, headers, exc_info=None):
            nonlocal status_code
            status_code = int(status.split(" ")[0])
            response_headers[:] = [(k, v) for k, v in headers]
            return lambda _b: None

        out = io.BytesIO()
        for chunk in self.wsgi_app(environ, start_response):
            out.write(chunk)

        await send(
            {
                "type": "http.response.start",
                "status": status_code,
                "headers": [
                    (k.encode(), v.encode()) for k, v in response_headers
                ],
            }
        )
        await send({"type": "http.response.body", "body": out.getvalue()})


async def _make_lab_client() -> httpx.AsyncClient:
    import lab_app  # noqa: PLC0415

    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=AsgiShim(lab_app.app)),
        base_url="http://lab",
    )


def test_link_scan_detects_invoice_idor_and_rejects_generic_200(tmp_path) -> None:
    """Eval cases 1 (critical IDOR) and 4 (generic-200 trap) end to end."""
    from app.agents.brain import Brain
    from app.engines.link_engine import run_link_scan

    brain = Brain(tmp_path / "brain")

    class Settings:
        request_timeout = 5.0
        rate_limit = 1000
        max_concurrency = 20
        probe_max = 5
        similarity_threshold = 0.85
        verify_retries = 2
        control_id = "99999999"

    async def _scan(url: str, scan_id: str) -> dict:
        from app.utils import http_client as hc

        transport = httpx.ASGITransport(app=AsgiShim(_lab_app().app))
        async with httpx.AsyncClient(
            transport=transport, base_url="http://lab"
        ) as probe_client:
            original_aenter = hc.HttpClient.__aenter__

            async def patched_aenter(self):
                self._client = probe_client
                return self

            original_aexit = hc.HttpClient.__aexit__

            async def patched_aexit(self, *exc):
                self._client = None

            hc.HttpClient.__aenter__ = patched_aenter  # type: ignore[method-assign]
            hc.HttpClient.__aexit__ = patched_aexit  # type: ignore[method-assign]
            try:
                return await run_link_scan(
                    scan_id=scan_id,
                    request_dict={
                        "mode": "link",
                        "url": url,
                        "headers": {},
                        "cookies": {},
                        "baseline_id": "1",
                        "probe_ids": ["2", "3"],
                        "method": "GET",
                    },
                    brain=brain,
                    reports_dir=str(tmp_path),
                    settings=Settings(),
                )
            finally:
                hc.HttpClient.__aenter__ = original_aenter  # type: ignore[method-assign]
                hc.HttpClient.__aexit__ = original_aexit  # type: ignore[method-assign]

    # Case 1: /invoice/{ID} — cross-account PII (bob) must be confirmed.
    report = asyncio.run(_scan("http://lab/invoice/{ID}", "testscan-invoice"))
    assert report["meta"]["mode"] == "link"
    assert report["summary"]["total"] >= 1
    critical = [f for f in report["findings"] if f["severity"] == "critical"]
    assert critical, "expected cross-account PII finding for /invoice/{ID}"
    # Assert bob's PII specifically — the `or`-vacuous assertion was removed
    # so a regression that flags the WRONG account would now fail.
    bob_hits = [
        f for f in critical
        if "bob@example.com" in (f.get("verification", {}).get("pii_matches") or [])
    ]
    assert bob_hits, "expected bob@example.com in PII matches of critical findings"

    # Case 4: /docs/{ID} — generic-200 trap must be rejected (no findings).
    docs_report = asyncio.run(_scan("http://lab/docs/{ID}", "testscan-docs"))
    assert docs_report["summary"]["total"] == 0, (
        "generic-200 trap must produce no confirmed findings, got "
        f"{docs_report['summary']['total']}"
    )
    assert docs_report["summary"].get("rejected_false_positives", 0) >= 1, (
        "expected rejected false positives for the /docs generic-200 trap"
    )


def _lab_app():
    import lab_app  # noqa: PLC0415

    return lab_app
