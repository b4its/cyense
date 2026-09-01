"""Framework &amp; Technology Stack Detection for website scans.

Detects web technologies from live HTTP responses using:
  * HTTP response headers (Server, X-Powered-By, etc.)
  * Meta generator tags
  * JavaScript library signatures in page source
  * CSS framework markers
  * CMS-specific paths and patterns

Returns findings with confidence levels — read-only analysis only.
"""

from __future__ import annotations

import re
from typing import Any

# Pre-compile regexes once at import time (avoids recompiling per page).
_HEADER_RE = {
    "server-nginx": re.compile(r"^nginx/[\d\.]+", re.I),
    "server-apache": re.compile(r"^Apache/[\d\.\-_ ]+", re.I),
    "stack-express": re.compile(r"^Express$", re.I),
    "stack-django": re.compile(r"^Django$", re.I),
    "stack-fastapi": re.compile(r"^FastAPI$", re.I),
    "stack-flask": re.compile(r"^Werkzeug", re.I),
    "stack-python": re.compile(r"^Werkzeug|^Python/", re.I),
    "stack-aspnet": re.compile(r"^Microsoft-IIS|^Kestrel", re.I),
    "stack-tomcat": re.compile(r"^Apache.*Tomcat", re.I),
    "stack-nodejs": re.compile(r"^Node\.?[Jj][Ss]$", re.I),
}

# Header-based detections: (suffix, header, compiled_regex, category, confidence)
HEADER_INDICATORS: list[tuple[str, str, re.Pattern[str], str, float]] = [
    ("SERVER-NGINX",   "server",        _HEADER_RE["server-nginx"],  "server:nginx",  0.95),
    ("SERVER-APACHE",  "server",        _HEADER_RE["server-apache"], "server:apache", 0.95),
    ("STACK-EXPRESS",  "x-powered-by",  _HEADER_RE["stack-express"], "stack:express", 0.9),
    ("STACK-DJANGO",   "x-powered-by",  _HEADER_RE["stack-django"],  "stack:django",  0.9),
    ("STACK-FASTAPI",  "x-powered-by",  _HEADER_RE["stack-fastapi"], "stack:fastapi", 0.9),
    ("STACK-FLASK",    "server",        _HEADER_RE["stack-flask"],   "stack:flask",   0.85),
    ("STACK-PYTHON",   "server",        _HEADER_RE["stack-python"],  "stack:python",  0.7),
    ("STACK-ASPNET",   "server",        _HEADER_RE["stack-aspnet"],  "stack:aspnet",  0.8),
    ("STACK-TOMCAT",   "server",        _HEADER_RE["stack-tomcat"],  "server:tomcat", 0.85),
    ("STACK-NODEJS",   "x-powered-by",  _HEADER_RE["stack-nodejs"],  "stack:nodejs",  0.8),
]

# CMS patterns: (suffix, body_regex, category, confidence)
_CMS_RE = {
    "wordpress": re.compile(
        r"/wp-content/|/wp-includes/|xmlrpc\.php|"
        r'<meta[^>]*name="generator"[^>]*content="WordPress', re.I),
    "joomla": re.compile(
        r'/media/system/|<meta[^>]*name="generator"[^>]*content="Joomla', re.I),
    "drupal": re.compile(r"Drupal\.settings\s*=|META.*generator.*Drupal", re.I),
    "magento": re.compile(r"Magento_Store|skin/frontend/mage", re.I),
    "shopify": re.compile(r"cdn\.shopify\.com|shopify_shop_url", re.I),
    "woocommerce": re.compile(r"woocommerce-", re.I),
}

CMS_PATTERNS: list[tuple[str, re.Pattern[str], str, float]] = [
    ("CMS-WORDPRESS",   _CMS_RE["wordpress"],   "cms:wordpress",   0.85),
    ("CMS-JOOMLA",      _CMS_RE["joomla"],      "cms:joomla",      0.9),
    ("CMS-DRUPAL",      _CMS_RE["drupal"],      "cms:drupal",      0.85),
    ("CMS-MAGENTO",     _CMS_RE["magento"],     "cms:magento",     0.8),
    ("CMS-SHOPIFY",     _CMS_RE["shopify"],     "ecommerce:shopify", 0.85),
    ("CMS-WOOCOMMERCE", _CMS_RE["woocommerce"], "ecommerce:woocommerce", 0.75),
]

# JavaScript/library patterns: (suffix, body_regex, category, confidence)
_JS_RE = {
    "react": re.compile(
        r"React(?:DOM)?\.createRoot|ReactDOM\.(?:render|hydrate|createPortal)"
        r"|data-reactroot|window\.React|__reactFiber", re.I),
    "vue": re.compile(
        r"\bVue\b\s*(?:\.version|=|\()|__VUE__|vue(?:js)?\.(?:production|min)\.js", re.I),
    "angular": re.compile(
        r"ng-app|angular(?:\.module|\.bootstrap|\.version)|ng-version", re.I),
    "nextjs": re.compile(r"__NEXT_DATA__|Next\.Script", re.I),
    "nuxtjs": re.compile(r"__NUXT__", re.I),
    "svelte": re.compile(r"svelte-[a-z]+|__svelte", re.I),
    "jquery": re.compile(r"jQuery\s*\(function\(|\$\.fn\.extend|window\.jQuery", re.I),
    "jquery-ui": re.compile(r"jquery-ui", re.I),
    "bootstrap": re.compile(r"bootstrap(-[0-9]+)?\.(min\.)?css|bootstrap\.bundle", re.I),
    "tailwind": re.compile(r"tailwindcss|tw-elements", re.I),
}

JS_PATTERNS: list[tuple[str, re.Pattern[str], str, float]] = [
    ("FRAMEWORK-REACT",   _JS_RE["react"],     "framework:react",   0.9),
    ("FRAMEWORK-VUE",     _JS_RE["vue"],       "framework:vue",     0.85),
    ("FRAMEWORK-ANGULAR", _JS_RE["angular"],   "framework:angular", 0.85),
    ("FRAMEWORK-NEXTJS",  _JS_RE["nextjs"],    "framework:nextjs",  0.8),
    ("FRAMEWORK-NUXTJS",  _JS_RE["nuxtjs"],    "framework:nuxtjs",  0.8),
    ("FRAMEWORK-SVELTE",  _JS_RE["svelte"],    "framework:svelte",  0.7),
    ("LIB-JQUERY",        _JS_RE["jquery"],    "lib:jquery",        0.85),
    ("LIB-JQUERY-UI",     _JS_RE["jquery-ui"], "lib:jquery-ui",     0.7),
    ("LIB-BOOTSTRAP",     _JS_RE["bootstrap"], "framework:bootstrap", 0.8),
    ("LIB-TAILWIND",      _JS_RE["tailwind"],  "framework:tailwind", 0.7),
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


def detect_technologies(
    url: str,
    headers: dict[str, str],
    body: str | None,
) -> list[dict[str, Any]]:
    """Analyze one page's response for technology/fingerprint signals.

    Returns findings with rule IDs DETECT-*.
    """
    findings: list[dict[str, Any]] = []
    headers_lc = {k.lower(): v for k, v in headers.items()}

    # --- 1. HTTP Headers ---
    for suffix, header_name, value_regex, category, confidence in HEADER_INDICATORS:
        value = headers_lc.get(header_name)
        if value and _search(value_regex, value):
            cat_name = category.split(":")[-1]
            title = f"{cat_name.capitalize()} detected via HTTP header"
            findings.append(_finding(
                rule=f"DETECT-{suffix}",
                confidence=confidence,
                title=title,
                description=f"HTTP {header_name!r} contains {category} fingerprint.",
                evidence={"header": header_name, "value": value[:120],
                         "category": category, "url": url},
                remediation="Obfuscate version headers to reduce disclosure.",
            ))

    if not body:
        return findings

    # --- 2. CMS patterns ---
    for suffix, pattern, category, confidence in CMS_PATTERNS:
        if _search(pattern, body):
            cat_name = category.split(":")[-1]
            findings.append(_finding(
                rule=f"DETECT-{suffix}",
                confidence=min(confidence + 0.1, 1.0),
                title=f"CMS detected: {cat_name}",
                description=f"Page fingerprint matches {cat_name}.",
                evidence={"category": category, "url": url},
                remediation="Patch CMS and harden per security guides.",
            ))

    # --- 3. JavaScript/library patterns ---
    for suffix, pattern, category, confidence in JS_PATTERNS:
        if _search(pattern, body):
            cat_name = category.split(":")[-1]
            findings.append(_finding(
                rule=f"DETECT-{suffix}",
                confidence=min(confidence + 0.05, 0.95),
                title=f"JavaScript technology: {cat_name}",
                description=f"Page includes {cat_name}.",
                evidence={"category": category, "url": url},
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
