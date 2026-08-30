"""Self-contained HTML report via pure string-builder (PRD v2.0 §4.4).

Hard requirements honored here:
* NO template engine (no Jinja) — f-strings + html.escape only
* self-contained: inline CSS, zero external assets
* expandable finding rows, severity badges, REPRODUCE curl badges
"""

from __future__ import annotations

import html
from typing import Any

_SEVERITY_COLORS = {
    "critical": "#7f1d1d",
    "high": "#c2410c",
    "medium": "#a16207",
    "low": "#1d4ed8",
    "info": "#374151",
}


def _esc(value: Any) -> str:
    return html.escape(str(value))


def _badge(severity: str) -> str:
    color = _SEVERITY_COLORS.get(severity, "#374151")
    return (
        f'<span style="background:{color};color:#fff;padding:2px 10px;'
        f'border-radius:999px;font-size:12px;font-weight:600;">{_esc(severity.upper())}</span>'
    )


def _summary_chips(summary: dict[str, Any]) -> str:
    chips = []
    for key in ("critical", "high", "medium", "low", "info"):
        count = summary.get(key, 0)
        chips.append(f'<div class="chip">{_badge(key)} <strong>{count}</strong></div>')
    extra = []
    if "total" in summary:
        extra.append(f"<div class='chip'>total <strong>{summary['total']}</strong></div>")
    if "rejected_false_positives" in summary:
        extra.append(
            "<div class='chip'>rejected FP "
            f"<strong>{summary['rejected_false_positives']}</strong></div>"
        )
    if "files_scanned" in summary:
        extra.append(
            "<div class='chip'>files scanned "
            f"<strong>{summary['files_scanned']}</strong></div>"
        )
    return "".join(chips + extra)


def _finding_card(index: int, finding: dict[str, Any]) -> str:
    finding_id = _esc(finding.get("finding_id", f"F{index:03d}"))
    severity = finding.get("severity", "info")
    title = _esc(finding.get("title", "(untitled)"))
    confidence = finding.get("confidence", 0)
    rule = _esc(finding.get("rule", ""))
    location = _esc(finding.get("location") or "-")
    description = _esc(finding.get("description", ""))
    remediation = _esc(finding.get("remediation", ""))
    verification = finding.get("verification", {}) or {}
    evidence = finding.get("evidence", {}) or {}

    verification_rows = "".join(
        f"<tr><th>{_esc(k)}</th><td><pre>{_esc(_pretty(v))}</pre></td></tr>"
        for k, v in verification.items()
    )

    evidence_html = ""
    req = evidence.get("request") or {}
    resp = evidence.get("response") or {}
    if req or resp:
        curl = _curl_of(req)
        evidence_html = f"""
  <h4>curl (REPRODUCE — credentials redacted)</h4>
  <pre class="code">{_esc(curl)}</pre>
  <h4>response</h4>
  <pre class="code">status: {_esc(resp.get('status', ''))}
headers: {_esc(_pretty(resp.get('headers', {})))}
body: {_esc(resp.get('body_snippet', ''))[:400]}</pre>"""

    return f"""
<details class="finding">
  <summary>
    <span class="fid">{finding_id}</span> {_badge(severity)}
    <strong>{title}</strong>
    <span class="meta">rule={rule} · confidence={confidence:.2f} · {location}</span>
  </summary>
  <div class="body">
    <p>{description}</p>
    <h4>verification</h4>
    <table>{verification_rows}</table>
    {evidence_html}
    <h4>remediation</h4>
    <p>{remediation}</p>
  </div>
</details>"""


def _pretty(value: Any) -> str:
    if isinstance(value, (dict, list)):
        import json

        return json.dumps(value, indent=2, sort_keys=True)
    return str(value)


def _curl_of(request: dict[str, Any]) -> str:
    url = request.get("url", "")
    parts = [f"curl -i '{url}'"]
    for key, value in (request.get("headers") or {}).items():
        parts.append(f"  -H '{key}: {value}'")
    for key, _value in (request.get("cookies") or {}).items():
        parts.append(f"  --cookie '{key}=[REDACTED]'")
    return " \\\n".join(parts)


_CSS = """
body{font-family:ui-sans-serif,system-ui,sans-serif;margin:0;background:#f3f4f6;color:#111827}
header{background:#111827;color:#fff;padding:24px 32px}
header h1{margin:0;font-size:22px}header p{margin:4px 0 0;color:#9ca3af;font-size:13px}
main{max-width:960px;margin:24px auto;padding:0 16px}
.chips{display:flex;gap:8px;flex-wrap:wrap;margin:16px 0}
.chip{background:#fff;border:1px solid #e5e7eb;border-radius:8px;padding:8px 12px;
 display:flex;align-items:center;gap:8px;font-size:13px}
details.finding{background:#fff;border:1px solid #e5e7eb;border-radius:8px;margin:10px 0}
details.finding summary{cursor:pointer;padding:12px 16px;display:flex;gap:10px;
 align-items:center;flex-wrap:wrap}
details.finding .fid{font-family:ui-monospace,monospace;color:#6b7280;font-size:12px}
details.finding .meta{color:#6b7280;font-size:12px;margin-left:auto}
details.finding .body{padding:0 16px 16px;border-top:1px solid #f3f4f6}
table{border-collapse:collapse;width:100%;margin:8px 0}
th,td{border:1px solid #e5e7eb;padding:6px 10px;text-align:left;font-size:13px;vertical-align:top}
th{background:#f9fafb;width:180px}
pre.code{background:#111827;color:#e5e7eb;padding:10px 12px;border-radius:6px;
 overflow-x:auto;font-size:12px}
h4{margin:14px 0 4px;font-size:13px;text-transform:uppercase;color:#6b7280}
footer{color:#9ca3af;text-align:center;font-size:12px;padding:24px}
"""


def render_html_report(report: dict[str, Any]) -> str:
    meta = report.get("meta", {}) or {}
    summary = report.get("summary", {}) or {}
    findings = report.get("findings", []) or []

    finding_cards = "".join(_finding_card(i, f) for i, f in enumerate(findings, start=1))
    if not findings:
        finding_cards = "<p class='empty'>No findings reported. 🎉</p>"

    meta_line = " · ".join(
        f"{k}={_esc(v)}" for k, v in sorted(meta.items()) if v is not None
    )

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Cyense report {_esc(meta.get('scan_id', ''))}</title>
<style>{_CSS}</style>
</head>
<body>
<header>
  <h1>🛡️ Cyense — IDOR scan report</h1>
  <p>{meta_line}</p>
</header>
<main>
  <div class="chips">{_summary_chips(summary)}</div>
  {finding_cards}
</main>
<footer>
generated by Cyense 2.0.0 · string-builder HTML (no template engine) · credentials redacted
</footer>
</body>
</html>"""
