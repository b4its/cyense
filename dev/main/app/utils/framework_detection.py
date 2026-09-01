"""Framework &amp; Technology Stack Detection for website scans.

Detects web technologies from live HTTP responses using:
  * HTTP response headers (Server, X-Powered-By, etc.)
  * Meta generator tags
  * JavaScript library signatures in page source
  * CSS framework markers
  * CMS-specific paths and patterns

Each finding carries an optional detected ``version`` in evidence so the CVE
lookup can match against affected version ranges (version-aware matching).
"""

from __future__ import annotations

import re
from typing import Any

# Pre-compile regexes once at import time (avoids recompiling per page).

# Header-based detections: (suffix, header, regex, category, confidence)
# Each entry also carries a version-extraction regex for the value.
_HEADER_SPECS: list[tuple[str, str, str, str, float, str | None]] = [
    ("SERVER-NGINX",  "server", r"^nginx(?:/([\d\.]+))?",
     "server:nginx", 0.95, r"nginx/([\d\.]+)"),
    ("SERVER-APACHE", "server", r"^Apache(?:/([\d\.\-_ ]+))?",
     "server:apache", 0.95, r"Apache/([\d\.]+)"),
    ("STACK-EXPRESS", "x-powered-by", r"^Express$",
     "stack:express", 0.9, None),
    ("STACK-DJANGO",  "x-powered-by", r"^Django$",
     "stack:django", 0.9, None),
    ("STACK-FASTAPI", "x-powered-by", r"^FastAPI$",
     "stack:fastapi", 0.9, None),
    ("STACK-FLASK",   "server", r"^Werkzeug",
     "stack:flask", 0.85, r"Werkzeug/([\d\.]+)"),
    ("STACK-PYTHON",  "server", r"^Werkzeug|^Python/",
     "stack:python", 0.7, r"Python/([\d\.]+)"),
    ("STACK-ASPNET",  "server", r"^Microsoft-IIS|^Kestrel",
     "stack:aspnet", 0.8, r"(?:Microsoft-IIS|Kestrel)/([\d\.]+)"),
    ("STACK-TOMCAT",  "server", r"^Apache.*Tomcat",
     "server:tomcat", 0.85, r"Tomcat/([\d\.]+)"),
    ("STACK-NODEJS",  "x-powered-by", r"^Node\.?[Jj][Ss]$",
     "stack:nodejs", 0.8, None),
]

HEADER_INDICATORS: list[tuple[str, str, re.Pattern[str], str, float, str | None]] = [
    (suffix, header, re.compile(reg, re.I), cat, conf, vreg)
    for suffix, header, reg, cat, conf, vreg in _HEADER_SPECS
]

# CMS patterns: (suffix, regex, category, confidence, version_regex)
CMS_PATTERNS: list[tuple[str, re.Pattern[str], str, float, str | None]] = [
    ("CMS-WORDPRESS",
     re.compile(r"/wp-content/|/wp-includes/|xmlrpc\.php|"
                r'<meta[^>]*name="generator"[^>]*content="WordPress', re.I),
     "cms:wordpress", 0.85, r'WordPress\s+([\d\.]+)'),
    ("CMS-JOOMLA",
     re.compile(r'/media/system/|<meta[^>]*name="generator"[^>]*'
                r'content="Joomla', re.I),
     "cms:joomla", 0.9, r'Joomla!?\s+([\d\.]+)'),
    ("CMS-DRUPAL",
     re.compile(r"Drupal\.settings\s*=|window\.drupalSettings\s*="
                r"|META.*generator.*Drupal", re.I),
     "cms:drupal", 0.85, r'Drupal\s+([\d\.]+)'),
    ("CMS-MAGENTO",
     re.compile(r"Magento_Store|skin/frontend/mage", re.I),
     "cms:magento", 0.8, None),
    ("CMS-SHOPIFY",
     re.compile(r"cdn\.shopify\.com|shopify_shop_url", re.I),
     "ecommerce:shopify", 0.85, None),
    ("CMS-WOOCOMMERCE",
     re.compile(r"woocommerce-", re.I),
     "ecommerce:woocommerce", 0.75, None),
    ("FRAMEWORK-LARAVEL",
     re.compile(r"laravel_session|csrf-token[^>]*content=[\"']|[<]meta[^>]*name=[\"']csrf", re.I),
     "stack:laravel", 0.8, None),
    ("FRAMEWORK-RAILS",
     re.compile(r'<meta[^>]*name="csrf-param"|rails-\d+\.\d+|data-remote=', re.I),
     "stack:rails", 0.75, None),
    ("STACK-DJANGO",
     re.compile(r"csrftoken=|django\.middleware|__admin__", re.I),
     "stack:django", 0.7, None),
]

# JavaScript/library patterns: (suffix, regex, category, confidence, version_regex)
JS_PATTERNS: list[tuple[str, re.Pattern[str], str, float, str | None]] = [
    ("FRAMEWORK-REACT",
     re.compile(r"React(?:DOM)?\.createRoot|ReactDOM\.(?:render|hydrate|createPortal)"
                r"|data-reactroot|window\.React|__reactFiber", re.I),
     "framework:react", 0.9, None),
    ("FRAMEWORK-VUE",
     re.compile(r"\bVue\b\s*(?:\.version|=|\()|__VUE__|Vue\.createApp"
                r"|vue(?:js)?\.(?:production|min)\.js", re.I),
     "framework:vue", 0.85, r'Vue\.version\s*=\s*["\']([\d\.]+)["\']'),
    ("FRAMEWORK-ANGULAR",
     re.compile(r"ng-app|angular(?:\.module|\.bootstrap|\.version)|ng-version", re.I),
     "framework:angular", 0.85, r'angular\.version\s*=\s*["\']([\d\.]+)["\']'),
    ("FRAMEWORK-NEXTJS",
     re.compile(r"__NEXT_DATA__|Next\.Script", re.I),
     "framework:nextjs", 0.8, None),
    ("FRAMEWORK-NUXTJS",
     re.compile(r"__NUXT__", re.I),
     "framework:nuxtjs", 0.8, None),
    ("FRAMEWORK-SVELTE",
     re.compile(r"svelte-[a-z]+|__svelte", re.I),
     "framework:svelte", 0.7, None),
    ("LIB-JQUERY",
     re.compile(r"jQuery\s*\(function\(|\$\.fn\.extend|window\.jQuery"
                r"|jquery(?:-[\d\.]+)?(?:\.min)?\.js", re.I),
     "lib:jquery", 0.85, r"jquery[.-]([\d\.]+)(?:\.min)?\.js"),
    ("LIB-JQUERY-UI",
     re.compile(r"jquery-ui", re.I),
     "lib:jquery-ui", 0.7, r"jquery-ui[.-]([\d\.]+)"),
    ("LIB-BOOTSTRAP",
     re.compile(r"bootstrap(-[0-9]+)?\.(min\.)?css|bootstrap\.bundle", re.I),
     "framework:bootstrap", 0.8, r"bootstrap-?([\d\.]+)"),
    ("LIB-TAILWIND",
     re.compile(r"tailwindcss|tw-elements", re.I),
     "framework:tailwind", 0.7, None),
]

# Meta generator tags
_META_RE = re.compile(r'<meta[^>]*name="generator"[^>]*content="([^"]+)"', re.I)
META_PATTERNS: list[tuple[str, re.Pattern[str], str, float]] = [
    ("META-GENERATOR", _META_RE, "meta:generator", 0.7),
]


def _search(pattern: re.Pattern[str] | str, text: str) -> re.Match | None:
    """Search with a pattern that may be pre-compiled (avoids flags conflict)."""
    if isinstance(pattern, re.Pattern):
        return pattern.search(text)
    return re.search(pattern, text, re.I | re.S)


def _extract_version(text: str, version_regex: str | None) -> str | None:
    """Extract a version string from header/body text using a version regex."""
    if not version_regex or not text:
        return None
    m = re.search(version_regex, text)
    return m.group(1) if m else None


def detect_technologies(
    url: str,
    headers: dict[str, str],
    body: str | None,
) -> list[dict[str, Any]]:
    """Analyze one page's response for technology/fingerprint signals.

    Returns findings with rule IDs DETECT-*, each carrying an optional
    ``evidence.version`` when a version could be extracted.
    """
    findings: list[dict[str, Any]] = []
    headers_lc = {k.lower(): v for k, v in headers.items()}

    # --- 1. HTTP Headers (with version extraction) ---
    for suffix, header_name, regex, category, confidence, vreg in HEADER_INDICATORS:
        value = headers_lc.get(header_name)
        if value and _search(regex, value):
            version = _extract_version(value, vreg)
            cat_name = category.split(":")[-1]
            title = f"{cat_name.capitalize()} detected via HTTP header"
            evidence: dict[str, Any] = {
                "header": header_name, "value": value[:120],
                "category": category, "url": url,
            }
            if version:
                evidence["version"] = version
            findings.append(_finding(
                rule=f"DETECT-{suffix}",
                confidence=confidence,
                title=title,
                description=(
                    f"HTTP {header_name!r} contains {category} fingerprint"
                    + (f" (version {version})" if version else "") + "."
                ),
                evidence=evidence,
                remediation="Obfuscate version headers to reduce disclosure.",
            ))

    if not body:
        return findings

    # --- 2. CMS / backend patterns (with version extraction) ---
    for suffix, pattern, category, confidence, vreg in CMS_PATTERNS:
        if _search(pattern, body):
            version = _extract_version(body, vreg)
            cat_name = category.split(":")[-1]
            evidence: dict[str, Any] = {"category": category, "url": url}
            if version:
                evidence["version"] = version
            findings.append(_finding(
                rule=f"DETECT-{suffix}",
                confidence=min(confidence + 0.1, 1.0),
                title=f"CMS/framework detected: {cat_name}",
                description=(
                    f"Page fingerprint matches {cat_name}"
                    + (f" (version {version})" if version else "") + "."
                ),
                evidence=evidence,
                remediation="Patch the component and harden per security guides.",
            ))

    # --- 3. JavaScript/library patterns (with version extraction) ---
    for suffix, pattern, category, confidence, vreg in JS_PATTERNS:
        if _search(pattern, body):
            version = _extract_version(body, vreg)
            cat_name = category.split(":")[-1]
            evidence: dict[str, Any] = {"category": category, "url": url}
            if version:
                evidence["version"] = version
            findings.append(_finding(
                rule=f"DETECT-{suffix}",
                confidence=min(confidence + 0.05, 0.95),
                title=f"JavaScript technology: {cat_name}",
                description=(
                    f"Page includes {cat_name}"
                    + (f" (version {version})" if version else "") + "."
                ),
                evidence=evidence,
                remediation="Review library versions for known CVEs.",
            ))

    # --- 4. Meta generator tags ---
    for suffix, pattern, category, confidence in META_PATTERNS:
        m = _search(pattern, body)
        if m:
            generator = m.group(1)[:100]
            findings.append(_finding(
                rule=f"DETECT-{suffix}",
                confidence=min(confidence + 0.3, 0.95),
                title=f"Meta generator: {generator}",
                description=f"Meta generator reveals: {generator}.",
                evidence={"generator": generator, "category": category,
                         "url": url},
                remediation="Remove meta generator tags to limit exposure.",
            ))

    return findings


def _finding(
    *, rule: str, confidence: float, title: str,
    description: str, evidence: dict[str, Any],
    remediation: str,
) -> dict[str, Any]:
    return {
        "rule": rule,
        "severity": "info",
        "confidence": round(confidence, 2),
        "title": title,
        "description": description,
        "evidence": evidence,
        "remediation": remediation,
        "location": evidence.get("url", ""),
    }
