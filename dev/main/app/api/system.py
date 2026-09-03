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


def _sec_rule(
    rule: str, title: str, cwe: str, severity: str, lang: str = "all",
) -> dict[str, object]:
    """Metadata card for a CWE-broad security rule / live check."""
    return {
        "rule": rule,
        "severity": severity,
        "lang": lang,
        "cwe": cwe,
        "cvss_score": 0.0,
        "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "title": title,
    }


def _security_catalog() -> list[dict[str, object]]:
    """Lazy CWE security rule list, sourced from the static rule module."""
    from app.program import security_rules
    return security_rules.security_rule_catalog()


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
        "security": [
            _sec_rule(s["rule"], s["title"], s["cwe"], s["severity"], s["lang"])
            for s in _security_catalog()
        ],
        "live_security": [
            _sec_rule("VERBOSE-ERROR", "Stack trace / detail error ter-expose",
                      "CWE-209", "high"),
            _sec_rule("UNHANDLED-ERROR",
                      "Pesan error server ter-expose (unhandled)", "CWE-391", "medium"),
            _sec_rule("COOKIE-NO-HTTPONLY", "Cookie tanpa flag HttpOnly",
                      "CWE-1004", "medium"),
            _sec_rule("COOKIE-NO-SECURE", "Cookie tanpa flag Secure", "CWE-614", "medium"),
            _sec_rule("COOKIE-NO-SAMESITE", "Cookie tanpa atribut SameSite",
                      "CWE-1275", "low"),
            _sec_rule("INSECURE-TRANSPORT",
                      "Kanal HTTP terang-terangan (tanpa TLS)", "CWE-319", "high"),
            _sec_rule("HSTS-MISSING",
                      "Strict-Transport-Security tidak diterapkan", "CWE-523", "medium"),
            _sec_rule("TRACE-ENABLED", "Metode HTTP TRACE diaktifkan", "CWE-693", "medium"),
            _sec_rule("INFO-X-POWERED-BY", "X-Powered-By mengungkap teknologi",
                      "CWE-200", "low"),
            _sec_rule("TLS-CERT-EXPIRED", "Sertifikat TLS telah kedaluwarsa",
                      "CWE-613", "critical"),
            _sec_rule("TLS-CERT-EXPIRY-SOON", "Sertifikat TLS segera kedaluwarsa",
                      "CWE-613", "medium"),
            _sec_rule("TLS-CERT-CHECK-FAILED", "Sertifikat TLS tidak dapat diverifikasi",
                      "CWE-295", "low"),
            _sec_rule("PLATFORM-DOTNET",
                      "Platform ASP.NET/.NET terdeteksi (CLR/native risk)", "CWE-693", "info"),
            _sec_rule("PLATFORM-JAVA",
                      "Platform Java terdeteksi (unsafe JNI/mobile code)", "CWE-859", "info"),
            _sec_rule("PLATFORM-PHP",
                      "Platform PHP terdeteksi (object injection/portability)", "CWE-889", "info"),
            _sec_rule("FOLLINA", "Payload Follina (CVE-2022-30190) terdeteksi",
                      "CWE-94", "high"),
            _sec_rule("INFO-QUERY-SECRET", "Data sensitif di query string URL",
                      "CWE-598", "medium"),
            _sec_rule("CSV-DOWNLOAD", "Endpoint CSV (risiko formula injection)",
                      "CWE-1236", "medium"),
            _sec_rule("UPLOAD-FORM", "Form upload file (Unrestricted File Upload)",
                      "CWE-434", "high"),
            _sec_rule("DESERIALIZE-ENDPOINT", "Endpoint deserialisasi object",
                      "CWE-502", "high"),
            _sec_rule("XML-ENDPOINT", "Endpoint XML/SOAP (surface XXE)",
                      "CWE-611", "medium"),
            _sec_rule("INJ-LIVE-SSTI", "Template/Expression Language injection (SSTI)",
                      "CWE-917", "high"),
            _sec_rule("INJ-LIVE-CRLF", "CRLF injection / response splitting", "CWE-93",
                      "high"),
            # OWASP community-vulnerability live checks (owasp_live.py)
            _sec_rule("OWASP-LOGIN-GET", "Form login method GET (kredensial ke URL)",
                      "CWE-598", "high"),
            _sec_rule("OWASP-PW-AUTOFILL", "Input password tanpa autocomplete=off",
                      "CWE-384", "low"),
            _sec_rule("OWASP-MIXED-CONTENT", "Halaman HTTPS memuat resource http://",
                      "CWE-319", "high"),
            _sec_rule("OWASP-EXTERNAL-NOSRI",
                      "Script/style pihak ketiga tanpa Subresource Integrity",
                      "CWE-829", "medium"),
            _sec_rule("OWASP-DESER-MAGIC", "Serialized object terdeteksi (CWE-502)",
                      "CWE-502", "medium"),
            _sec_rule("OWASP-SESSION-ENTROPY", "Session id berentropi rendah",
                      "CWE-331", "medium"),
            _sec_rule("OWASP-DISPATCHER-PARAM",
                      "Parameter selector server-side (LFI/RFI/reflection)",
                      "CWE-470", "low"),
            # OSINT recon rules (osint.py)
            _sec_rule("OSINT-RDAP", "Data registrasi domain RDAP/whois",
                      "CWE-200", "info"),
            _sec_rule("OSINT-DOMAIN-EXPIRY", "Domain mendekati/melewati kedaluwarsa",
                      "CWE-200", "low"),
            _sec_rule("OSINT-DNS", "Enumerasi record DNS (dnsrecon/dnsx)",
                      "CWE-200", "info"),
            _sec_rule("OSINT-ASN", "Netblock/ASN via Team-Cymru (asnmap)",
                      "CWE-200", "info"),
            # Reverse-engineering rules (re_analysis.py)
            _sec_rule("RE-SOURCEMAP-REF", "Source map JavaScript ter-expose",
                      "CWE-540", "medium"),
            _sec_rule("RE-VULN-JS", "Library JS rentan/usang (Retire.js-style)",
                      "CWE-829", "medium"),
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
            _detect_rule("NIKTO-HEARTBLEED", "OpenSSL 1.0.1 range (Heartbleed, CVE-2014-0160)"),
            _detect_rule("HARVEST-SUBDOMAIN-CRTSH", "Subdomain dari crt.sh (Harvester)"),
            _detect_rule("HARVEST-SUBDOMAIN-WAYBACK", "Subdomain dari Wayback (Harvester)"),
            _detect_rule("HARVEST-TECH-HEADER", "Fingerprint teknologi dari header HTTP"),
            _detect_rule("HARVEST-TECH-BODY", "Fingerprint teknologi dari body HTML"),
            _detect_rule("HARVEST-EMAIL", "Email address di content (Harvester)"),
            _detect_rule("HARVEST-IP", "IP address di content (Harvester)"),
        ],
        "domain": [
            _detect_rule(
                "DOMAIN-HOST",
                "Finding diagregasi per-host (scan seluruh domain)",
            ),
        ],
    }
