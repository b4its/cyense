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

# Header-based detections: (suffix, header, value_regex, category, confidence)
HEADER_INDICATORS: list[tuple[str, str, str, str, float]] = [
    ("SERVER-NGINX",   "server", r"^nginx/[\d\.]+",        "server:nginx",   0.95),
    ("SERVER-APACHE",  "server", r"^Apache/[\d\.\-_ ]+",  "server:apache",  0.95),
    ("STACK-EXPRESS",  "x-powered-by", r"^Express$",      "stack:express",  0.9),
    ("STACK-DJANGO",   "x-powered-by", r"^Django$",       "stack:django",   0.9),
    ("STACK-FASTAPI",  "x-powered-by", r"^FastAPI$",      "stack:fastapi",  0.9),
    ("STACK-FLASK",    "server", r"^Werkzeug",            "stack:flask",    0.85),
    ("STACK-PYTHON",   "server", r"^Werkzeug|^Python/",   "stack:python",   0.7),
    ("STACK-ASPNET",   "server", r"^Microsoft-IIS|^Kestrel", "stack:aspnet", 0.8),
    ("STACK-TOMCAT",   "server", r"^Apache.*Tomcat",       "server:tomcat",  0.85),
    ("STACK-NODEJS",   "x-powered-by", r"^Node\.?[Jj][Ss]$", "stack:nodejs", 0.8),
]

# CMS patterns: (suffix, body_regex, category, confidence)
CMS_PATTERNS: list[tuple[str, str, str, float]] = [
    ("CMS-WORDPRESS",
     r"/wp-content/|/wp-includes/|xmlrpc\.php", "cms:wordpress", 0.85),
    ("CMS-WORDPRESS",
     r'<meta[^>]*name="generator"[^>]*'
     r'content="WordPress', "cms:wordpress", 0.95),
    ("CMS-JOOMLA",
     r'/media/system/|<meta[^>]*name="generator"[^>]*'
     r'content="Joomla', "cms:joomla", 0.9),
    ("CMS-DRUPAL",
     r"Drupal\.settings\s*=|META.*generator.*Drupal", "cms:drupal", 0.85),
    ("CMS-MAGENTO",
     r"Magento_Store|skin/frontend/mage", "cms:magento", 0.8),
    ("CMS-SHOPIFY",
     r"cdn\.shopify\.com|shopify_shop_url", "ecommerce:shopify", 0.85),
    ("CMS-WOOCOMMERCE",
     r"woocommerce-", "ecommerce:woocommerce", 0.75),
]

# JavaScript/library patterns: (suffix, body_regex, category, confidence)
JS_PATTERNS: list[tuple[str, str, str, float]] = [
    ("FRAMEWORK-REACT",
     r"React(?:DOM)?\.createRoot|ReactDOM\.(?:render|hydrate|createPortal)"
     r"|data-reactroot|window\.React|__reactFiber",
     "framework:react", 0.9),
    ("FRAMEWORK-VUE",
     r"\bVue\b\s*(?:\.version|=|\()|__VUE__|vue(?:js)?\.(?:production|min)\.js",
     "framework:vue", 0.85),
    ("FRAMEWORK-ANGULAR",
     r"ng-app|angular(?:\.module|\.bootstrap|\.version)|ng-version",
     "framework:angular", 0.85),
    ("FRAMEWORK-NEXTJS",
     r"__NEXT_DATA__|Next\.Script", "framework:nextjs", 0.8),
    ("FRAMEWORK-NUXTJS",
     r"__NUXT__", "framework:nuxtjs", 0.8),
    ("FRAMEWORK-SVELTE",
     r"svelte-[a-z]+|__svelte", "framework:svelte", 0.7),
    ("LIB-JQUERY",
     r"jQuery\s*\(function\(|\$\.fn\.extend|window\.jQuery",
     "lib:jquery", 0.85),
    ("LIB-JQUERY-UI", r"jquery-ui", "lib:jquery-ui", 0.7),
    ("LIB-BOOTSTRAP",
     r"bootstrap(-[0-9]+)?\.(min\.)?css|bootstrap\.bundle",
     "framework:bootstrap", 0.8),
    ("LIB-TAILWIND",
     r"tailwindcss|tw-elements", "framework:tailwind", 0.7),
]

# Meta generator tags
META_PATTERNS: list[tuple[str, str, str, float]] = [
    ("META-GENERATOR",
     r'<meta[^>]*name="generator"[^>]*content="([^"]+)"',
     "meta:generator", 0.7),
]


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
        if value and re.search(value_regex, value, re.I):
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
        if re.search(pattern, body, re.I | re.S):
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
        if re.search(pattern, body, re.I | re.S):
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
        m = re.search(pattern, body, re.I | re.S)
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
