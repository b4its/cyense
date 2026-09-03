"""System endpoints: /health (liveness) and /rules (active rules)."""

from __future__ import annotations

from fastapi import APIRouter, Request

router = APIRouter(tags=["system"])

# Shared CVSS vectors used by the static-rule catalog below.
_IDOR_VECTOR = "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"
_XSS_VECTOR = "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"
_XSS_LOW_VECTOR = "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:N/A:N"
_XSS_CRIT_VECTOR = "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"


def _program_rule(rule: str, severity: str, lang: str, cwe: str) -> dict[str, object]:
    return {
        "rule": rule,
        "severity": severity,
        "lang": lang,
        "cwe": cwe,
        "cvss_score": 6.5,
        "cvss_vector": _IDOR_VECTOR,
    }


def _xss_rule(
    rule: str,
    severity: str,
    lang: str,
    title: str,
    score: float,
    vector: str,
) -> dict[str, object]:
    return {
        "rule": rule,
        "severity": severity,
        "lang": lang,
        "cwe": "CWE-95" if rule in ("XS004", "XS010") else "CWE-79",
        "cvss_score": score,
        "cvss_vector": vector,
        "title": title,
    }


# SQLi CVSS vectors (error-based SQLi is typically high severity)
_SQLI_VECTOR = "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"


# SQLi CVSS vector (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H == 9.8)
_SQLI_VECTOR = "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"


def _sqli_rule(rule: str, lang: str, title: str) -> dict[str, object]:
    return {
        "rule": rule,
        "severity": "critical",
        "lang": lang,
        "cwe": "CWE-89",
        "cvss_score": 9.8,
        "cvss_vector": _SQLI_VECTOR,
        "title": title,
    }


def _detect_rule(rule: str, title: str) -> dict[str, object]:
    return {
        "rule": rule,
        "severity": "info",
        "lang": "all",
        "cwe": "CWE-200",
        "cvss_score": 0.0,
        "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "title": title,
    }


def _port_rule(rule: str, title: str) -> dict[str, object]:
    return {
        "rule": rule,
        "severity": "info",
        "lang": "all",
        "cwe": "CWE-200",
        "cvss_score": 0.0,
        "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "title": title,
    }


def _cve_rule(rule: str, title: str) -> dict[str, object]:
    return {
        "rule": rule,
        "severity": "high",
        "lang": "all",
        "cwe": "CWE-1035",
        "cvss_score": 7.5,
        "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "title": title,
    }


def _owasp_rule(rule: str, severity: str, title: str, cwe: str) -> dict[str, object]:
    score = {"critical": 9.8, "high": 7.5, "medium": 5.3, "low": 3.1, "info": 0.0}[severity]
    vector = "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
    if severity == "info":
        vector = "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
    return {
        "rule": rule,
        "severity": severity,
        "lang": "all",
        "cwe": cwe,
        "cvss_score": score,
        "cvss_vector": vector,
        "title": title,
    }


@router.get("/health")
async def health(request: Request) -> dict[str, str]:
    # Version comes from the FastAPI app instance (app/main.py create_app),
    # so this endpoint never drifts from the declared app version again.
    return {
        "status": "ok",
        "service": "cyense",
        "version": request.app.version,
    }


@router.get("/rules")
async def rules() -> dict[str, object]:
    """Active rules (PRD §4.2 + xss-detection feature + ci-compliance-reporting)."""
    return {
        "link": [
            {
                "rule": "IDOR-LINK",
                "description": (
                    "dynamic probing with 4-step verification "
                    "(similarity, PII, retry, control-id)"
                ),
                "severity": ["critical", "high", "medium"],
                "cwe": "CWE-639",
            }
        ],
        "program": [
            _program_rule("CY001", "high", "python", "CWE-639"),
            _program_rule("CY002", "high", "python", "CWE-639"),
            _program_rule("CY003", "high", "python", "CWE-639"),
            _program_rule("CY004", "high", "python", "CWE-639"),
            _program_rule("CY005", "high", "python", "CWE-639"),
            _program_rule("CY006", "critical", "python", "CWE-22"),
            _program_rule("CY007", "high", "js", "CWE-639"),
            _program_rule("CY008", "high", "js", "CWE-639"),
            _program_rule("CY009", "high", "php", "CWE-639"),
            _program_rule("CY010", "high", "php", "CWE-639"),
            # Deep rules (high/max levels)
            _program_rule("CY011", "high", "python", "CWE-639"),
            _program_rule("CY012", "high", "python", "CWE-306"),
            _program_rule("CY013", "medium", "python", "CWE-639"),
        ],
        "xss": [
            _xss_rule("XS001", "high", "js", "innerHTML assigned a dynamic value",
                       6.1, _XSS_VECTOR),
            _xss_rule("XS002", "high", "js", "document.write with a dynamic value",
                       6.1, _XSS_VECTOR),
            _xss_rule("XS003", "high", "js", "dangerouslySetInnerHTML fed a dynamic value",
                       6.1, _XSS_VECTOR),
            _xss_rule("XS004", "critical", "js", "eval/new Function on dynamic input",
                       9.8, _XSS_CRIT_VECTOR),
            _xss_rule("XS005", "high", "js", "v-html bound to a dynamic expression",
                       6.1, _XSS_VECTOR),
            _xss_rule("XS006", "high", "php", "PHP echo/print of superglobal input",
                       6.1, _XSS_VECTOR),
            _xss_rule("XS007", "high", "python",
                      "Jinja2 |safe filter disables auto-escaping", 6.1, _XSS_VECTOR),
            _xss_rule("XS008", "medium", "python",
                      "HTML string composed via f-string/format", 4.7, _XSS_LOW_VECTOR),
            # Deep XSS rules (high/max levels)
            _xss_rule("XS009", "high", "js", "document.cookie leaked to external origin",
                      6.1, _XSS_VECTOR),
            _xss_rule("XS010", "critical", "python", "eval/exec of user-controlled input",
                      9.8, _XSS_CRIT_VECTOR),
            _xss_rule("XS011", "medium", "python", "cross-file XSS via imported template",
                      4.7, _XSS_LOW_VECTOR),
        ],
        "sqli": [
            _sqli_rule("SQLI001", "python", "cursor.execute() with dynamic SQL"),
            _sqli_rule("SQLI002", "python", "Django raw()/extra() with user input"),
            _sqli_rule("SQLI003", "python", "SQLAlchemy text() with interpolation"),
            _sqli_rule("SQLI004", "js", "query()/execute() with concatenated SQL"),
            _sqli_rule("SQLI005", "php", "query built with superglobal/concatenation"),
            _sqli_rule("SQLI006", "all", "raw SQL string interpolating a variable"),
        ],
        "framework_detection": [
            _detect_rule("DETECT-SERVER-NGINX", "HTTP header: nginx"),
            _detect_rule("DETECT-SERVER-APACHE", "HTTP header: Apache"),
            _detect_rule("DETECT-STACK-EXPRESS", "HTTP header: Express"),
            _detect_rule("DETECT-STACK-DJANGO", "HTTP header: Django"),
            _detect_rule("DETECT-STACK-FASTAPI", "HTTP header: FastAPI"),
            _detect_rule("DETECT-STACK-FLASK", "HTTP header: Flask"),
            _detect_rule("DETECT-CMS-WORDPRESS", "CMS: WordPress"),
            _detect_rule("DETECT-CMS-JOOMLA", "CMS: Joomla"),
            _detect_rule("DETECT-CMS-DRUPAL", "CMS: Drupal"),
            _detect_rule("DETECT-FRAMEWORK-REACT", "JavaScript: React"),
            _detect_rule("DETECT-FRAMEWORK-VUE", "JavaScript: Vue.js"),
            _detect_rule("DETECT-FRAMEWORK-ANGULAR", "JavaScript: Angular"),
            _detect_rule("DETECT-LIB-JQUERY", "JavaScript: jQuery"),
            _detect_rule("DETECT-FRAMEWORK-NEXTJS", "JavaScript: Next.js"),
            _detect_rule("DETECT-FRAMEWORK-BOOTSTRAP", "CSS: Bootstrap"),
            _detect_rule("DETECT-FRAMEWORK-TAILWIND", "CSS: Tailwind"),
            _detect_rule("DETECT-META-GENERATOR", "Meta: generator tag analysis"),
            _detect_rule("DETECT-ECOMMERCE-SHOPIFY", "E-commerce: Shopify"),
            _detect_rule("DETECT-ECOMMERCE-WOOCOMMERCE", "E-commerce: WooCommerce"),
        ],
        "port_scan": [
            _port_rule("PORT-OPEN", "Open TCP port detected (nmap-style connect)"),
            _port_rule("PORT-SCAN-SUMMARY", "Summary of open ports on target host"),
        ],
        "cve_lookup": [
            _cve_rule("CVE-MATCH", "Known CVE matched to detected technology"),
        ],
        "discovery": [
            _detect_rule("SECRET-LEAK", "Hard-coded secret exposed in response"),
            _detect_rule("EXPOSED-FILE", "Sensitive file/path publicly accessible"),
            _detect_rule("DISC-JS-URL", "Endpoints extracted from JavaScript"),
            _detect_rule("DISC-HIDDEN-PARAM", "Hidden HTTP parameter discovered"),
            _detect_rule("DISC-WAYBACK", "Historical URLs from Wayback Machine"),
            _detect_rule("DISC-SUBDOMAIN", "Subdomain discovered (passive/DNS)"),
            _detect_rule("DISC-API-ENDPOINT", "API endpoint discovered (Kiterunner-style)"),
            _detect_rule("DISC-PATH", "Directory discovered (Ffuf/Dirsearch-style)"),
            _detect_rule("DISC-VHOST", "Virtual host discovered"),
            _detect_rule("WP-EXPOSED", "WordPress surface exposed (Wpscan-style)"),
            _detect_rule("SSRF-SINK", "SSRF-sink parameter detected (passive)"),
            _detect_rule("GRAPHQL-INTROSPECTION", "GraphQL introspection enabled"),
            _detect_rule("DISC-ROUTE", "Route/endpoint discovered (routing enumeration)"),
            _detect_rule("API-ROUTE", "Sensitive route discovered"),
        ],
        "owasp": [
            _owasp_rule("OWASP-SENSITIVE-001", "high", "Page served over plaintext HTTP",
                        "CWE-319"),
            _owasp_rule("OWASP-AUTH-001", "high", "Session cookie not marked HttpOnly",
                        "CWE-1004"),
            _owasp_rule("OWASP-AUTH-002", "high", "Session cookie not marked Secure",
                        "CWE-614"),
            _owasp_rule("OWASP-AUTH-003", "low", "Login form exposed", "CWE-307"),
            _owasp_rule("OWASP-CSRF-001", "medium", "State-changing form without CSRF token",
                        "CWE-352"),
            _owasp_rule("OWASP-CSRF-002", "low",
                        "Form posts data to a cross-origin destination", "CWE-352"),
            _owasp_rule("OWASP-CSRF-003", "medium",
                        "Session cookie missing SameSite attribute", "CWE-1275"),
            _owasp_rule("OWASP-CSRF-004", "high", "SameSite=None cookie without Secure",
                        "CWE-1275"),
            _owasp_rule("OWASP-DESER-001", "high",
                        "Insecure deserialization marker detected", "CWE-502"),
            _owasp_rule("OWASP-CONF-001", "info", "Server header discloses software",
                        "CWE-200"),
            _owasp_rule("OWASP-CONF-002", "info", "X-Powered-By header reveals framework",
                        "CWE-200"),
            _owasp_rule("OWASP-CONF-003", "medium",
                        "Sensitive/debug endpoint publicly exposed", "CWE-200"),
            _owasp_rule("OWASP-CONF-004", "medium", "Directory listing exposed", "CWE-548"),
            _owasp_rule("OWASP-MONITOR-001", "medium",
                        "Verbose internal error disclosed", "CWE-209"),
        ],
        "domain": [
            _detect_rule(
                "DOMAIN-HOST",
                "Finding diagregasi per-host (scan seluruh domain)",
            ),
        ],
    }
