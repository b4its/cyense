"""Tests for framework/technology detection (app/utils/framework_detection.py).

Covers: HTTP header detection (nginx, Apache, Express, Django, FastAPI),
meta generator tags, CMS patterns (WordPress, Joomla, Drupal), and
JavaScript framework signatures (React, Vue, Angular, jQuery, Next.js).
"""

from __future__ import annotations

from app.utils.framework_detection import detect_technologies


def _rules(findings) -> set[str]:
    return {f["rule"] for f in findings}


# ---------------------------------------------------------------------------
# Server / Framework via HTTP Headers
# ---------------------------------------------------------------------------

def test_detect_nginx_via_server_header() -> None:
    findings = detect_technologies(
        "http://app/",
        {"Server": "nginx/1.24.0"},
        body="",
    )
    assert "DETECT-SERVER-NGINX" in _rules(findings)


def test_detect_apache_via_server_header() -> None:
    findings = detect_technologies(
        "http://app/",
        {"Server": "Apache/2.4.57 (Ubuntu)"},
        body="",
    )
    assert "DETECT-SERVER-APACHE" in _rules(findings)


def test_detect_express_via_x_powered_by() -> None:
    findings = detect_technologies(
        "http://app/",
        {"X-Powered-By": "Express"},
        body="",
    )
    assert "DETECT-STACK-EXPRESS" in _rules(findings)


def test_detect_fastapi_via_x_powered_by() -> None:
    findings = detect_technologies(
        "http://app/",
        {"x-powered-by": "FastAPI"},
        body="",
    )
    findings_by_rule = {f["rule"]: f for f in findings}
    # FastAPI detection uses x-powered-by: FastAPI (from SERVER_HEADER_PATTERNS)
    assert "DETECT-STACK-FASTAPI" in _rules(findings), findings_by_rule


def test_no_detection_on_empty_headers() -> None:
    findings = detect_technologies("http://app/", {}, body="")
    assert findings == []


# ---------------------------------------------------------------------------
# CMS Detection
# ---------------------------------------------------------------------------

def test_detect_wordpress_via_wp_content() -> None:
    body = """<html><head><link rel="stylesheet" href="/wp-content/themes/style.css">
</head><body>Hello world!</body></html>"""
    findings = detect_technologies("http://blog.example/", {"Server": "Apache"}, body=body)
    assert "DETECT-CMS-WORDPRESS" in _rules(findings)


def test_detect_wordpress_via_generator() -> None:
    body = """<html><head><meta name="generator" content="WordPress 6.3"></head></html>"""
    findings = detect_technologies("http://blog.example/", {}, body=body)
    assert "DETECT-CMS-WORDPRESS" in _rules(findings)


def test_detect_joomla_via_generator() -> None:
    body = """<meta name="generator" content="Joomla! - Open Source Content Management">"""
    findings = detect_technologies("http://joomla.example/", {}, body=body)
    assert "DETECT-CMS-JOOMLA" in _rules(findings)


def test_detect_drupal_via_settings() -> None:
    body = """<script>Drupal.settings = {"basePath":"/"};</script>"""
    findings = detect_technologies("http://drupal.example/", {}, body=body)
    assert "DETECT-CMS-DRUPAL" in _rules(findings)


# ---------------------------------------------------------------------------
# JavaScript Frameworks
# ---------------------------------------------------------------------------

def test_detect_react_via_root() -> None:
    body = """<script>ReactDOM.createRoot(document.getElementById('root'));</script>"""
    findings = detect_technologies("http://react.example/", {}, body=body)
    assert "DETECT-FRAMEWORK-REACT" in _rules(findings)


def test_detect_vue_via_version() -> None:
    body = """<script>Vue.version = "3.3.4";</script>"""
    findings = detect_technologies("http://vue.example/", {}, body=body)
    assert "DETECT-FRAMEWORK-VUE" in _rules(findings)


def test_detect_jquery_via_call() -> None:
    body = """<script>jQuery(function() { console.log("ready"); });</script>"""
    findings = detect_technologies("http://jquery.example/", {}, body=body)
    assert "DETECT-LIB-JQUERY" in _rules(findings)


def test_detect_nextjs_via_NEXT_DATA() -> None:
    body = """<script>__NEXT_DATA__ = {"props":{"pageProps":{}}};</script>"""
    findings = detect_technologies("http://next.example/", {}, body=body)
    assert "DETECT-FRAMEWORK-NEXTJS" in _rules(findings)


def test_detect_angular_via_ng_app() -> None:
    body = """<html ng-app="myApp"><body></body></html>"""
    findings = detect_technologies("http://angular.example/", {}, body=body)
    assert "DETECT-FRAMEWORK-ANGULAR" in _rules(findings)


# ---------------------------------------------------------------------------
# Negative cases (no false positives)
# ---------------------------------------------------------------------------

def test_no_false_positive_plain_html() -> None:
    body = "<html><head><title>Contact Us</title></head><body><p>Hello</p></body></html>"
    findings = detect_technologies("http://simple.example/", {}, body=body)
    # No false positive detection for any framework
    assert findings == []
