"""CWE-broad security rules — "general security / robustness" rule class.

Cyense originally shipped three static rule classes: IDOR (CY001-CY013), XSS
(XS001-XS011) and SQLi (SQLI001-SQLI006). This module adds a fourth class that
maps the broad CWE/OWASP vulnerability taxonomy onto web source code, spanning
Python / JS / PHP files.


These are **deterministic regex/AST detectors** (no LLM, $0, reproducible) that
raise *candidates* for a human to triage — exactly like the existing CY/XS/SQLI
rules. Every finding carries its CWE id so SARIF/CVSS/coverage classification in
``app/report`` and ``GET /api/v1/rules`` is consistent.

Scope note — what is **not** detectable by static web-source analysis (and is
therefore intentionally outside this module): native memory-safety issues
(buffer overflow, double-free, use-after-free / *using freed memory*, improper
pointer subtraction, string termination, memory leak, undefined behavior),
native binding issues (unsafe JNI, unsafe mobile code, unsafe function call from
a signal handler, Full-trust CLR verification issue, insecure compiler
optimization), OS/portability flaws, covert storage channels, Heartbleed
(server-level, outside an app's source), and the purely-process ones
(vulnerability scanning tools, vulnerability template). Those are documented in
``README.md`` as out-of-scope rather than half-detected here.
"""

# ruff: noqa: E501 — the rule table below is a list of long regex literals.

from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Any

_LANG_PY = "py"
_LANG_JS = "js"
_LANG_PHP = "php"
_ALL = "all"


def _langs(*names: str) -> frozenset[str]:
    return frozenset(names)


# Rule table. Each entry:
#   id, cwe, severity, title, langs, regex (str), description, remediation
# langs is a frozenset; _ALL means every supported language.
_RULES: list[tuple[str, str, str, str, frozenset[str], str, str, str]] = [
    # ------------------------------------------------------------------ #
    # Deserialization                                                   #
    # ------------------------------------------------------------------ #
    (
        "DES001", "CWE-502", "critical", "Insecure deserialization (Python)",
        _langs(_LANG_PY),
        r"\b(?:pickle\.(?:loads|load)|yaml\.load(?:\([^)]*Loader)?|marshal\.loads|shelve\.open|dill\.(?:loads|load))\s*\(",
        "Untrusted data is deserialized with an unsafe loader (pickle/yaml.load/marshal/shelve/dill).",
        "Use safe loaders: yaml.safe_load, json.loads, or explicit typing; never pickle untrusted input.",
    ),
    (
        "DES002", "CWE-502", "critical", "Insecure deserialization (PHP object injection)",
        _langs(_LANG_PHP),
        r"\bunserialize\s*\(\s*(?:\$_GET|\$_POST|\$_REQUEST|\$_COOKIE)",
        "unserialize() is fed HTTP input — PHP object injection / arbitrary object instantiation.",
        "Never unserialize user input; use json_decode or a whitelist of scalar field names.",
    ),
    # ------------------------------------------------------------------ #
    # Cryptography / randomness                                          #
    # ------------------------------------------------------------------ #
    (
        "CRYPTO001", "CWE-327", "high", "Broken/risky cryptographic algorithm",
        _ALL,
        r"\b(?:md5|md4|sha1|sha[\s-]?1)\s*\(",
        "Weak hash (MD5/SHA-1) used where a collision-resistant digest is expected.",
        "Use SHA-256+ (hashlib.sha256 / password_hash / crypto.subtle) for integrity & password hashing.",
    ),
    (
        "CRYPTO002", "CWE-327", "high", "Weak block cipher / ECB mode",
        _ALL,
        r"\b(?:DES|DES_ECB|3DES|RC2|RC4)\b|ECB\b|MODE_ECB|AES\.MODE_ECB",
        "DES/RC4 or ECB mode is used — cryptographically weak for confidentiality.",
        "Use AES-256-GCM with a fresh nonce per message (or ChaCha20-Poly1305).",
    ),
    (
        "CRYPTO003", "CWE-321", "high", "Hardcoded cryptographic key",
        _ALL,
        r"\b(?:(?:api[_-]?key|secret|secret[_-]?key|encryption[_-]?key|aes[_-]?key|private[_-]?key|token))\s*[:=]\s*['\"][A-Za-z0-9+/=_-]{12,}['\"]",
        "A cryptographic key/secret literal is committed in source.",
        "Load secrets from a secure store/env (vault, keyring) and rotate the leaked value.",
    ),
    (
        "RND001", "CWE-338", "medium", "Insecure randomness / insufficient entropy",
        _ALL,
        r"\brandom\.(?:random|randint|choice|shuffle|sample|uniform|randrange|random)\s*\(|\bMath\.random\s*\(|\brand\s*\(|\bmt_rand\s*\(",
        "A non-cryptographic PRNG is used for a security decision (token, nonce, id, salt).",
        "Use secrets.token_*, os.urandom, crypto.getRandomValues, /random_bytes, or random_int.",
    ),
    (
        "RND002", "CWE-335", "low", "PRNG seed error / weak seeding",
        _ALL,
        r"\brandom\.seed\s*\(\s*(?:time|hash|str)\b",
        "The PRNG is seeded from a predictable value (time/hash/len).",
        "Seed from os.urandom or secrets; prefer secrets module and never seed from wall-clock time.",
    ),
    # ------------------------------------------------------------------ #
    # Passwords                                                          #
    # ------------------------------------------------------------------ #
    (
        "PW001", "CWE-259", "high", "Hard-coded password",
        _ALL,
        r"\b(?:password|passwd|pwd|db[_-]?pass|db[_-]?password)\s*[:=]\s*['\"][^'\"]{4,}['\"]",
        "A password literal is committed in source.",
        "Read credentials from environment/secrets manager; use getenv/keyring at runtime.",
    ),
    (
        "PW002", "CWE-256", "high", "Password plaintext storage",
        _ALL,
        r"(?is)(?:insert\s+into|save\(|create\(|sql\.execute|INSERT)\s*[^;\n]{0,120}\bpassword\b[^;\n]{0,80}(?:request|_GET|_POST|req\.|form)",
        "A user-supplied password is persisted without hashing.",
        "Hash passwords with a slow, salted KDF (bcrypt/argon2id/scrypt) before storage.",
    ),
    (
        "PW003", "CWE-287", "medium", "Empty string password check",
        _ALL,
        r"(?i)\bpassword\b[^;(){}\n]{0,30}\s*==\s*['\"]['\"]|\b(?:password|passwd|pwd)\b\s*!==\s*['\"]['\"]",
        "Authentication compares a password to an empty string — a broken access-control shortcut.",
        "Never allow empty passwords; enforce a min-length policy and use a proper auth library.",
    ),
    (
        "PW004", "CWE-598", "medium", "Information exposure through query strings",
        _ALL,
        r"['\"]https?://[^'\"]*\?[^'\"]*\b(?:password|passwd|token|api[_-]?key|secret|access[_-]?token)=[^'\"]*['\"]",
        "Sensitive credentials are passed in a URL query string (leaked in logs/referrers/history).",
        "Use POST bodies/amazon auth headers; never place secrets in a query string.",
    ),
    # ------------------------------------------------------------------ #
    # Transport / TLS                                                    #
    # ------------------------------------------------------------------ #
    (
        "TRAN001", "CWE-319", "high", "Insecure transport (plaintext HTTP)",
        _ALL,
        r"(?i)(?:https?://)?['\"]http://[^'\"]+['\"]|\bhttp://\b",
        "A cleartext http:// URL is used for a network call or redirect.",
        "Use https:// (HSTS); redirect HTTP → HTTPS and refuse to drop to plaintext.",
    ),
    (
        "TRAN002", "CWE-295", "high", "Improper certificate validation",
        _ALL,
        r"(?i)verify\s*=\s*False|check_hostname\s*=\s*False|CERT_NONE|ssl\._create_unverified_context|setopt\s*\(\s*curl\.\s*OPT_SSL_VERIFYPEER\s*,\s*0\b|rejectUnauthorized\s*:\s*false",
        "TLS peer verification is disabled or relaxed.",
        "Keep certificate/hostname verification on; pin trusted CAs instead of disabling checks.",
    ),
    # ------------------------------------------------------------------ #
    # File handling / upload / temp                                       #
    # ------------------------------------------------------------------ #
    (
        "FILE001", "CWE-434", "high", "Unrestricted file upload",
        _ALL,
        r"(?i)(?:move_uploaded_file|save_uploaded_file|write\(|save\(|file_put_contents|createReadStream|writeFile)\s*\([^)]*(?:request|req\.files|_FILES|form|upload)",
        "User-controlled upload/bytes are written to disk without extension/type validation.",
        "Validate MIME + extension against an allowlist, store outside webroot, and re-encode the file.",
    ),
    (
        "PATH001", "CWE-22", "high", "Path traversal / directory restriction error",
        _ALL,
        r"(?i)(?:open\(|open\(|file_get_contents|read_text|readFile|include|require|os\.path\.join|Path\()\s*[^;)\n]*(?:request|req\.|_GET|_POST)",
        "A filesystem path is built from user input without containment checks.",
        "Resolve()+ensure the value stays under the allowed root (os.path.realpath / Path.resolve).",
    ),
    (
        "TMP001", "CWE-377", "medium", "Insecure temporary file",
        _ALL,
        r"(?i)\b(?:mktemp|tempfile\.mkstemp|NamedTemporaryFile|os\.tmpnam|/tmp/[A-Za-z0-9_./-]{2,})",
        "A temporary file is created with a predictable name/path.",
        "Use tempfile with a random name and restrictive permissions (0o600), and clean up after use.",
    ),
    # ------------------------------------------------------------------ #
    # HTTP / session / headers                                            #
    # ------------------------------------------------------------------ #
    (
        "CRLF001", "CWE-93", "high", "CRLF injection",
        _ALL,
        r"(?i)(?:setHeader|add_header|header\(|append_header|set_header|setresponseheader)\s*\([^)]*(?:request|req\.|_GET|_POST|input)",
        "An HTTP response header is built from user input — CRLF/header-injection risk.",
        "Sanitize/strip CRLF and validate against an allowlist before writing headers.",
    ),
    (
        "CSV001", "CWE-1236", "medium", "CSV formula injection",
        _ALL,
        r"(?i)(?:fputcsv|csv\.writer|writerow\s*\(|CsvWriter|write_row|array_to_csv)\s*\([^)]*(?:request|req\.|_GET|_POST|row|data)",
        "CSV output is built from dynamic data without neutralizing formula prefixes (=, +, -, @).",
        "Prefix cell values with a single quote or tab when they begin with = + - @ to prevent formula injection.",
    ),
    (
        "SESS001", "CWE-384", "high", "Session variable overloading / fixation",
        _ALL,
        r"(?i)(?:session\[[^]]+\]|req\.session\.[a-z_]+|request\.session\.[a-z_]+|_SESSION\[[^]]+\])\s*=\s*(?:request|req\.|_GET|_POST|input)",
        "A session value is assigned from user input without a rotation (fixation/overloading).",
        "Regenerate the session id on privilege change and never trust client-supplied session fields.",
    ),
    (
        "INFO001", "CWE-200", "low", "Sensitive data in comments & URLs",
        _ALL,
        r"(?i)password\s*[:=]\s*['\"][^'\"]{4,}['\"]|api[_-]?key\s*[:=]\s*['\"][A-Za-z0-9+/=_-]{12,}['\"]|BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY",
        "Sensitive material (credential, private key) is embedded in source/comments.",
        "Remove secrets; move to a configured secret store and revoke anything already shared.",
    ),
    # ------------------------------------------------------------------ #
    # Code / command / expression / reflection injection                 #
    # ------------------------------------------------------------------ #
    (
        "PROC001", "CWE-78", "critical", "Process control / OS command injection",
        _ALL,
        r"(?i)(?:os\.system|os\.popen|subprocess\.(?:call|Popen|run|check_output|check_call)|system\s*\(|exec\s*\(|shell_exec|passthru|proc_open|child_process\.(?:exec|spawn))\s*\([^)]*(?:request|req\.|_GET|_POST|input)\b",
        "A shell/process command is built from user input.",
        "Never pass user input to a shell; use argument-array APIs with an allowlist and `shell=False`.",
    ),
    (
        "REFL001", "CWE-470", "medium", "Unsafe use of reflection",
        _ALL,
        r"(?i)getattr\s*\([^,]+\s*,\s*(?:request|req\.|_GET|_POST|input)|call_user_func\s*\([^)]*(?:request|req\.|_GET|_POST|input)|invoke\s*\([^)]*(?:request|req\.|input)",
        "Reflection/indirect call is driven by user-controlled names.",
        "Resolve method names against a fixed allowlist instead of arbitrary user input.",
    ),
    (
        "DATA001", "CWE-94", "critical", "Improper data validation — code injection",
        _ALL,
        r"\b(?:eval|exec|new\s+Function|create_function)\s*\(\s*(?:request|req\.|_GET|_POST|input|location|document\.(?:cookie|referrer)|window\.name)|\bcompile\s*\(\s*(?:request|req\.|_GET|_POST|input)",
        "User input reaches a code-evaluating sink (eval/exec/Function) — code injection.",
        "Remove eval; use JSON.parse + an allowlist or a safe template engine with escaping.",
    ),
    # ------------------------------------------------------------------ #
    # XML / XXE                                                          #
    # ------------------------------------------------------------------ #
    (
        "XXE001", "CWE-611", "critical", "XML External Entity (XXE) processing",
        _ALL,
        r"(?i)(?:simplexml_load_string|XMLReader|libxml_disable_entity_loader|resolve_entities|LIBXML_NOENT|DocumentBuilderFactory|XmlDocument\.LoadXml|XMLResolver|SAXParserFactory|createXMLReader)\s*\(",
        "XML is parsed with external-entity resolution enabled — XXE / file & SSRF read.",
        "Disable external entities & DTDs (libxml_disable_entity_loader / setFeature('...external-general-entities',false)).",
    ),
    (
        "XML001", "CWE-20", "medium", "Missing XML validation",
        _ALL,
        r"(?i)(?:etree\.parse|ElementTree\.(?:parse|fromstring)|document\.parse\s*XML|parseString|xml\.parse|loadXML)\s*\(",
        "XML is deserialized without validating against a schema/DTD.",
        "Validate input against an expected schema and reject anything that does not match.",
    ),
    # ------------------------------------------------------------------ #
    # Error handling                                                    #
    # ------------------------------------------------------------------ #
    (
        "ERR001", "CWE-396", "low", "Catch NullPointerException / over-broad catch",
        _ALL,
        r"\bexcept\s+(?:Exception|BaseException|RuntimeError|TypeError|ValueError)\s*:|catch\s*\(\s*(?:Exception|Throwable|RuntimeException|NullPointerException)\s*[a-z]*\s*\)",
        "An over-broad exception type is caught, hiding real bugs.",
        "Catch the narrowest expected exception and log/re-raise where appropriate.",
    ),
    (
        "ERR002", "CWE-390", "low", "Missing error handling / bare except",
        _ALL,
        r"(?m)^\s*\bexcept\s*:|catch\s*\(\s*\)\b|catch\s*\{",
        "A bare except / empty catch swallows all errors silently.",
        "Handle the specific error and always surface or log the failure.",
    ),
    (
        "ERR003", "CWE-391", "medium", "Unchecked error condition",
        _ALL,
        r"(?i)(?:os\.system|subprocess\.(?:call|run|Popen)|curl_exec|file_get_contents|mysqli_query|pdo->query)\s*\([^)]*\)\s*;?\s*(?:#|//)?#?\s*(?:$|\n)",
        "A call that returns an error/status is used without checking the result.",
        "Check return/status codes and handle errors explicitly; enable exceptions where available.",
    ),
    ("NULL001", "CWE-476", "medium", "Null dereference risk",
     _ALL,
     r"(?i)(?:\$_GET|\$_POST|\$_REQUEST|req\.query|req\.params)\[[^]]+\]\s*->|(?:\$_GET|\$_POST|\$_REQUEST)\[[^]]+\]\s*\.[a-z_]+\s*\(",
     "A possibly-missing array key / nullable value is dereferenced without a guard.",
     "Guard with ?? / isset / optional chaining and fail safely when the value is missing.",
     ),
    # ------------------------------------------------------------------ #
    # Concurrency / race                                                 #
    # ------------------------------------------------------------------ #
    (
        "RACE001", "CWE-362", "medium", "Race condition (TOCTOU) on file access",
        _ALL,
        r"(?i)(?:os\.path\.exists|os\.access|is_file\s*\(|file_exists)\s*\([^)]*\)[^;\n]{0,80}(?:open|unlink|remove|rename|os\.remove)\s*\(",
        "A file is checked then used without atomicity — TOCTOU race.",
        "Open the file first and operate on the descriptor, or use an atomic compare-and-swap.",
    ),
    # ------------------------------------------------------------------ #
    # Regex / DoS                                                        #
    # ------------------------------------------------------------------ #
    (
        "REGEX001", "CWE-1333", "medium", "Overly permissive regular expression (ReDoS)",
        _ALL,
        r"re\.(?:compile|match|search|findall)\s*\(\s*[rf]?['\"][^'\"]*(?:\(\?:\S+\*\)\*|\(\.\*\)\*|\([a-z]+\+\)\+|\([A-Za-z0-9_.-]+\+\)\*|\([^)]*\)\{[0-9]+,\}*)\b",
        "A nested-quantifier regex is prone to catastrophic backtracking (ReDoS).",
        "Use a bounded/linear-time pattern (atomic groups, possessive quantifiers, or a parser library).",
    ),
    # ------------------------------------------------------------------ #
    # Obsolete / deprecated                                              #
    # ------------------------------------------------------------------ #
    (
        "OBS001", "CWE-477", "medium", "Use of obsolete methods",
        _ALL,
        r"(?i)\.(?:iteritems|iterkeys|itervalues|has_key)\s*\(|\bxrange\s*\(|\braw_input\s*\(|mysql_|ereg\s*\(|\.getchildren\s*\(",
        "An obsolete/deprecated API is in use.",
        "Migrate to the modern API (six/Python 3, PDO/mysqli prepared statements, stdlib equivalents).",
    ),
    # ------------------------------------------------------------------ #
    # Logging / privacy / least privilege                                #
    # ------------------------------------------------------------------ #
    (
        "LOG001", "CWE-532", "medium", "Poor logging practice — sensitive data",
        _ALL,
        r"(?i)logging\.(?:info|debug|warning|error)\([^)]*(?:password|passwd|secret|token|api[_-]?key|authorization|session)",
        "Sensitive values may be written to application logs.",
        "Redact secrets/PII before logging; log identifiers instead of raw credentials.",
    ),
    (
        "PRIV001", "CWE-359", "medium", "Privacy violation — PII exposure",
        _ALL,
        r"(?i)(?:email|email_address|phone|ssn|social[_-]?security|credit[_-]?card|dob|date[_-]?of[_-]?birth)\s*[:=]\s*['\"][^'\"]{3,}['\"]|\b(?:email|phone|ssn)\b[^;\n]{0,40}(?:log|print|response|write)\b",
        "Personally identifiable information is stored, logged, or returned.",
        "Minimize PII collection, pseudonymize, and redact before logging/responding.",
    ),
    (
        "LEAST001", "CWE-250", "low", "Least privilege violation",
        _ALL,
        r"(?i)chmod\s*\(\s*[^,]+\s*,\s*(?:0?o?6?6?6|0?777|0o777|stat\.S_IRWXG)|setuid\s*\(|seteuid\s*\(|\bsudo\b",
        "Permissions/privileges are set too broadly (world-writable, elevation).",
        "Grant the minimum required permissions; run as an unprivileged account with a service user.",
    ),
    (
        "BIZ001", "CWE-253", "medium", "Business logic — unchecked return value",
        _ALL,
        r"(?i)(?:\.first\s*\(|\.one\s*\(|\.find\s*\(|get_object_or_404|\.get\s*\([^)]*\))\s*\.(?:id|name|email|value|data)\b",
        "A possibly-None result is dereferenced, a business-logic skip of the null/error path.",
        "Handle the empty/None result explicitly before chaining access.",
    ),
]

# Compile regexes once (lazy).
_COMPILED: list[tuple[dict[str, Any], re.Pattern[str]]] = []
for _r in _RULES:
    _COMPILED.append(
        (
            {
                "id": _r[0],
                "cwe": _r[1],
                "severity": _r[2],
                "title": _r[3],
                "langs": _r[4],
                "description": _r[6],
                "remediation": _r[7],
            },
            re.compile(_r[5], re.IGNORECASE | re.MULTILINE),
        )
    )


def security_rule_catalog() -> list[dict[str, Any]]:
    """Return the CWE security rule catalog for ``GET /api/v1/rules``."""
    return [
        {
            "rule": spec["id"],
            "cwe": spec["cwe"],
            "severity": spec["severity"],
            "lang": {"py": "python", "js": "js", "php": "php", "all": "all"}[
                next(iter(spec["langs"])) if len(spec["langs"]) == 1 else "all"
            ],
            "title": spec["title"],
            "description": spec["description"],
            "remediation": spec["remediation"],
        }
        for spec, _ in _COMPILED
    ]


def _line_of(source: str, pos: int) -> int:
    """1-based line number for a character offset in *source*."""
    return source.count("\n", 0, pos) + 1


def analyze(code: str) -> list[tuple[str, str, int, str]]:
    """Run the full lattice of patterns and return raw matches.

    Returns a list of ``(rule_id, severity, line, matched_snippet)``.
    """
    matches: list[tuple[str, str, int, str]] = []
    for spec, rx in _COMPILED:
        for m in rx.finditer(code):
            snippet = m.group(0)
            matches.append((spec["id"], spec["severity"], _line_of(code, m.start()), snippet))
    return matches


def _findings_for(
    path: Path,
    source: str,
    scan_id: str,
    lang: str,
) -> list[Any]:
    from app.core.models import Finding, Severity, VerificationEvidence

    spec_by_id = {s["id"]: s for s, _ in _COMPILED}
    path_disc = hashlib.md5(str(path).encode("utf-8")).hexdigest()[:6]
    results: list[Any] = []
    for rule_id, severity, line, snippet in analyze(source):
        spec = spec_by_id[rule_id]
        if lang not in spec["langs"] and "all" not in spec["langs"]:
            continue
        results.append(Finding(
            finding_id=f"{scan_id}-{rule_id}-{line}-{path_disc}",
            rule=rule_id,
            severity=Severity(severity),
            confidence=0.6,
            title=spec["title"],
            description=spec["description"],
            evidence={"file": str(path), "line": line, "match": snippet.strip()[:200]},
            verification=VerificationEvidence(notes="static regex (CWE)"),
            remediation=spec["remediation"],
            location=f"{path}:{line}",
            cwe=spec["cwe"],
        ))
    return results


def analyze_python_file(path: Path, source: str, scan_id: str) -> list[Any]:
    return _findings_for(path, source, scan_id, _LANG_PY)


def analyze_js_file(path: Path, source: str, scan_id: str) -> list[Any]:
    return _findings_for(path, source, scan_id, _LANG_JS)


def analyze_php_file(path: Path, source: str, scan_id: str) -> list[Any]:
    return _findings_for(path, source, scan_id, _LANG_PHP)
