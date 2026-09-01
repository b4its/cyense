"""Secret scanning — TruffleHog/gitGraber-style detection in crawled content.

Scans HTML/JS/text responses for hard-coded credentials, API keys, tokens,
and private keys (adaptation of TruffleHog + Shhgit from the HackerOne 104
tools list). Pure deterministic regex — no external API.

Each finding is redacted: only the TYPE of secret and a safe prefix/suffix
are reported, never the secret value itself (ground rule #8).
"""

from __future__ import annotations

import re
from typing import Any

# (name, compiled_regex, severity, description)
_SECRET_PATTERNS: list[tuple[str, re.Pattern[str], str, str]] = [
    ("aws-access-key",
     re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"),
     "high",
     "AWS Access Key ID ter-expose di respons."),
    ("aws-secret-key",
     re.compile(r"(?i)aws.{0,20}?['\"][0-9a-zA-Z/+]{40}['\"]"),
     "critical",
     "AWS Secret Access Key ter-expose di respons."),
    ("github-token",
     re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b"),
     "critical",
     "GitHub personal/oauth token ter-expose."),
    ("slack-token",
     re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,200}\b"),
     "high",
     "Slack token ter-expose."),
    ("google-api-key",
     re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
     "high",
     "Google API key ter-expose."),
    ("stripe-key",
     re.compile(r"\bsk_live_[0-9a-zA-Z]{24,}\b"),
     "critical",
     "Stripe live secret key ter-expose."),
    ("stripe-test-key",
     re.compile(r"\bsk_test_[0-9a-zA-Z]{24,}\b"),
     "medium",
     "Stripe test key ter-expose."),
    ("jwt-token",
     re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
     "medium",
     "JWT token ter-embed di konten."),
    ("private-key-pem",
     re.compile(r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
     "critical",
     "Private key (PEM) ter-expose."),
    ("firebase-key",
     re.compile(r"(?i)firebase.{0,20}?['\"][A-Za-z0-9_-]{30,}['\"]"),
     "medium",
     "Firebase API key ter-expose."),
    ("twilio-key",
     re.compile(r"\bSK[0-9a-fA-F]{32}\b"),
     "high",
     "Twilio secret key ter-expose."),
    ("mailgun-key",
     re.compile(r"\bkey-[0-9a-zA-Z]{32}\b"),
     "high",
     "Mailgun API key ter-expose."),
    ("heroku-key",
     re.compile(r"(?i)heroku.{0,20}?['\"][0-9a-fA-F]{8}-[0-9a-fA-F-]{27}['\"]"),
     "high",
     "Heroku API key ter-expose."),
    ("generic-api-key",
     re.compile(r"(?i)(api[_-]?key|apikey|secret|token|passwd|password)\s*[:=]\s*['\"][A-Za-z0-9_\-\.]{20,}['\"]"),
     "medium",
     "Kredensial/API key generik ter-expose di respons."),
    ("mysql-dsn",
     re.compile(r"mysql://[^/\s:@]+:[^/\s@]+@[^/\s]+"),
     "critical",
     "MySQL DSN dengan kredensial ter-expose."),
    ("postgres-dsn",
     re.compile(r"postgres(?:ql)?://[^/\s:@]+:[^/\s@]+@[^/\s]+"),
     "critical",
     "PostgreSQL DSN dengan kredensial ter-expose."),
    ("s3-bucket-url",
     re.compile(r"https?://[a-z0-9.-]+\.s3[.-][a-z0-9-]*\.amazonaws\.com/"),
     "low",
     "URL bucket S3 ter-expose (cek izin publik)."),
]


def _redact_snippet(snippet: str) -> str:
    """Return a safe snippet: only reveal the secret type, never the value."""
    if len(snippet) <= 12:
        return "[REDACTED]"
    return f"{snippet[:6]}…{snippet[-4:]} [REDACTED]"


def scan_secrets(content: str) -> list[dict[str, Any]]:
    """Detect hard-coded secrets in a text body (HTML/JS/etc.).

    Returns a list of finding dicts:
      {secret_type, severity, snippet (redacted), count}
    """
    if not content:
        return []
    findings: list[dict[str, Any]] = []
    for name, regex, severity, description in _SECRET_PATTERNS:
        matches = list(regex.finditer(content))
        if not matches:
            continue
        unique = list(dict.fromkeys(m.group(0) for m in matches))
        findings.append({
            "secret_type": name,
            "severity": severity,
            "description": description,
            "count": len(matches),
            "samples": [_redact_snippet(u) for u in unique[:3]],
        })
    return findings
