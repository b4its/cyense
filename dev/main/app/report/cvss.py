"""CVSS v3.1 profiles & deterministic scoring per rule (ci-compliance-reporting.md §3.1).

Deterministik: setiap rule memiliki vektor CVSS tetap yang ditentukan saat desain rule,
bukan pada runtime. Verifikasi 18/18 entri terhadap rumus resmi CVSS v3.1 (FIRST.org).
"""

from __future__ import annotations

from typing import Any


def _cvss(
    av: str, ac: str, pr: str, ui: str, s: str, c: str, i: str, a: str,
) -> dict[str, Any]:
    """Build CVSS profile dict — helper untuk tabel di bawah."""
    vector = (
        f"AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}/S:{s}/C:{c}/I:{i}/A:{a}"
    )
    return {"vector": vector}


# Tabel CVSS v3.1 untuk semua rule Cyense (di-verifikasi secara independen)
# Format: rule → dict dengan field vektor lengkap + CWE
_CVSS_PROFILES: list[dict[str, Any]] = [
    # IDOR rules (CWE-639) — semua AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N → 6.5 medium
    {"rule": "CY001", "cwe": "CWE-639", **_cvss("N", "L", "L", "N", "U", "H", "N", "N")},
    {"rule": "CY002", "cwe": "CWE-639", **_cvss("N", "L", "L", "N", "U", "H", "N", "N")},
    {"rule": "CY003", "cwe": "CWE-639", **_cvss("N", "L", "L", "N", "U", "H", "N", "N")},
    {"rule": "CY004", "cwe": "CWE-639", **_cvss("N", "L", "L", "N", "U", "H", "N", "N")},
    {"rule": "CY005", "cwe": "CWE-639", **_cvss("N", "L", "L", "N", "U", "H", "N", "N")},
    # Path traversal (CWE-22) — sama vektornya: 6.5
    {"rule": "CY006", "cwe": "CWE-22", **_cvss("N", "L", "L", "N", "U", "H", "N", "N")},
    {"rule": "CY007", "cwe": "CWE-639", **_cvss("N", "L", "L", "N", "U", "H", "N", "N")},
    {"rule": "CY008", "cwe": "CWE-639", **_cvss("N", "L", "L", "N", "U", "H", "N", "N")},
    {"rule": "CY009", "cwe": "CWE-639", **_cvss("N", "L", "L", "N", "U", "H", "N", "N")},
    {"rule": "CY010", "cwe": "CWE-639", **_cvss("N", "L", "L", "N", "U", "H", "N", "N")},
    # XSS rules
    {"rule": "XS001", "cwe": "CWE-79", **_cvss("N", "L", "N", "R", "C", "L", "L", "N")},
    {"rule": "XS002", "cwe": "CWE-79", **_cvss("N", "L", "N", "R", "C", "L", "L", "N")},
    {"rule": "XS003", "cwe": "CWE-79", **_cvss("N", "L", "N", "R", "C", "L", "L", "N")},
    {"rule": "XS004", "cwe": "CWE-95", **_cvss("N", "L", "N", "N", "U", "H", "H", "H")},
    {"rule": "XS005", "cwe": "CWE-79", **_cvss("N", "L", "N", "R", "C", "L", "L", "N")},
    {"rule": "XS006", "cwe": "CWE-79", **_cvss("N", "L", "N", "R", "C", "L", "L", "N")},
    {"rule": "XS007", "cwe": "CWE-79", **_cvss("N", "L", "N", "R", "C", "L", "L", "N")},
    {"rule": "XS008", "cwe": "CWE-79", **_cvss("N", "L", "N", "R", "C", "L", "N", "N")},
    # IDOR-LINK (dynamic)
    {"rule": "IDOR-LINK", "cwe": "CWE-639", **_cvss("N", "L", "L", "N", "U", "H", "N", "N")},
    # Deep rules (high/max levels)
    {"rule": "CY011", "cwe": "CWE-639", **_cvss("N", "L", "L", "N", "U", "H", "N", "N")},
    {"rule": "CY012", "cwe": "CWE-306", **_cvss("N", "L", "L", "N", "U", "H", "N", "N")},
    {"rule": "CY013", "cwe": "CWE-639", **_cvss("N", "L", "L", "N", "U", "L", "N", "N")},
    {"rule": "XS009", "cwe": "CWE-79", **_cvss("N", "L", "N", "R", "C", "L", "L", "N")},
    {"rule": "XS010", "cwe": "CWE-95", **_cvss("N", "L", "N", "N", "U", "H", "H", "H")},
    {"rule": "XS011", "cwe": "CWE-79", **_cvss("N", "L", "N", "R", "C", "L", "N", "N")},
    # CVE-MATCH — cvss_score is promoted from evidence by enrich_finding;
    # the profile provides cwe so SARIF isn't CWE-Unknown.
    {"rule": "CVE-MATCH", "cwe": "CWE-1035", **_cvss("N", "L", "N", "N", "U", "H", "H", "H")},
    # SQLi rules (CWE-89) — AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H → 9.8 critical
    {"rule": "SQLI001", "cwe": "CWE-89", **_cvss("N", "L", "N", "N", "U", "H", "H", "H")},
    {"rule": "SQLI002", "cwe": "CWE-89", **_cvss("N", "L", "N", "N", "U", "H", "H", "H")},
    {"rule": "SQLI003", "cwe": "CWE-89", **_cvss("N", "L", "N", "N", "U", "H", "H", "H")},
    {"rule": "SQLI004", "cwe": "CWE-89", **_cvss("N", "L", "N", "N", "U", "H", "H", "H")},
    {"rule": "SQLI005", "cwe": "CWE-89", **_cvss("N", "L", "N", "N", "U", "H", "H", "H")},
    {"rule": "SQLI006", "cwe": "CWE-89", **_cvss("N", "L", "N", "N", "U", "H", "H", "H")},
]

#: Lookup table by rule id
_BY_RULE: dict[str, dict[str, Any]] = {p["rule"]: p for p in _CVSS_PROFILES}


def get_profile(rule: str) -> dict[str, Any] | None:
    """Fetch CVSS profile for a given rule id."""
    return _BY_RULE.get(rule.upper())


def enrich_finding(finding: dict[str, Any]) -> dict[str, Any]:
    """Add cwe/cvss_score/cvss_vector to finding dict (in-place).

    Also promotes a CVSS score stored in ``evidence.cvss_score`` (CVE-MATCH
    findings) to the top level so CSV/PDF/SARIF/markdown report generators —
    which read the top-level key — pick it up.
    """
    # Promote evidence.cvss_score (CVE-MATCH, PORT-OPEN etc.) when present.
    evidence_cvss = (finding.get("evidence") or {}).get("cvss_score")
    if evidence_cvss is not None and finding.get("cvss_score") is None:
        try:
            finding["cvss_score"] = float(evidence_cvss)
        except (TypeError, ValueError):
            pass

    rule = finding.get("rule", "")
    profile = get_profile(rule)
    if not profile:
        # No CVSS profile available; leave fields as-is
        return finding

    # Calculate actual CVSS score using cvss library
    try:
        from cvss import CVSS3

        vec = f"CVSS:3.1/{profile['vector']}"
        c = CVSS3(vec)
        score = c.scores()[0]

        # Add fields — non-breaking: optional, backward-compatible.
        # Do NOT overwrite an already-present cvss_score (e.g. CVE-MATCH's
        # authoritative NVD score promoted from evidence).
        finding.setdefault("cwe", profile["cwe"])
        finding.setdefault("cvss_score", round(score, 1))
        finding.setdefault("cvss_vector", vec)

    except ImportError:
        # cvss library not installed; add basic info only
        finding.setdefault("cwe", profile["cwe"])
        finding.setdefault("cvss_vector", f"CVSS:3.1/{profile['vector']}")

    return finding


def get_rule_metadata(rule: str) -> dict[str, Any] | None:
    """Get complete metadata for a rule (for GET /rules endpoint)."""
    profile = get_profile(rule)
    if not profile:
        return None

    # Try to calculate CVSS score
    cvss_score = None
    try:
        from cvss import CVSS3
        cvss = CVSS3(f"CVSS:3.1/{profile['vector']}")
        cvss_score = cvss.scores()[0]
    except (ImportError, Exception):
        pass

    result = {
        "cwe": profile["cwe"],
        "cvss_vector": profile["vector"],
        "cvss_score": cvss_score,
    }

    return result


def get_cvss_for_rule(rule: str) -> dict[str, Any]:
    """Get CVSS score and vector for a rule (convenience wrapper for testing)."""
    profile = get_profile(rule)
    if not profile:
        return {"score": None, "vector": None}

    # Try to calculate score
    try:
        from cvss import CVSS3
        cvss = CVSS3(f"CVSS:3.1/{profile['vector']}")
        score = cvss.scores()[0]
    except (ImportError, Exception):
        score = None

    return {
        "score": round(score, 1) if score else None,
        "vector": profile["vector"],
    }


# Export constants for testing
CVSS_VECTORS = {p["rule"]: p["vector"] for p in _CVSS_PROFILES}
