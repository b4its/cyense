"""OpenAPI/Swagger spec parser for API security scanning.

Parses OpenAPI 3.x and Swagger 2.0 specs to extract endpoints with path
parameters that are candidates for IDOR testing. Inspired by Strix's ability
to point at an API contract and test every declared endpoint.

This module is purely deterministic (no LLM) and follows the same design
principles as the rest of Cyense: cheap, reproducible, zero external deps.

Usage:
    endpoints = parse_openapi_spec("openapi.yaml")
    # → [{"method": "GET", "path": "/users/{userId}", "url_template": "http://api/users/{userId}", ...}, ...]
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any
from urllib.parse import urljoin

import yaml  # type: ignore[import-untyped]

# Path parameter patterns: {id}, {userId}, {user_id}, {ID}, etc.
_PATH_PARAM_RE = re.compile(r"\{(\w+)\}")

# Heuristic: parameter names that likely refer to object IDs
_ID_PARAM_PATTERNS = re.compile(
    r"^(id|ID|Id|uuid|UUID|guid|GUID|slug|pk|PK|"
    r"\w+_id|\w+_Id|\w+_ID|"
    r"\w+Id|\w+ID|"
    r"userId|accountId|orderId|invoiceId|docId|fileId|recordId|"
    r"user_uuid|account_uuid)$"
)


def _load_spec(spec_source: str) -> dict[str, Any]:
    """Load an OpenAPI/Swagger spec from a file path, URL, or raw string.

    Supports:
      - Local file paths (.json, .yaml, .yml)
      - HTTP(S) URLs
      - Raw JSON/YAML strings (auto-detected)
    """
    # Try as file path first
    path = Path(spec_source)
    if path.is_file():
        text = path.read_text(encoding="utf-8")
        return _parse_text(text, path.suffix)

    # Try as URL
    if spec_source.startswith(("http://", "https://")):
        import urllib.request
        with urllib.request.urlopen(spec_source, timeout=30) as resp:
            text = resp.read().decode("utf-8")
        suffix = ".yaml" if ".yaml" in spec_source or ".yml" in spec_source else ".json"
        return _parse_text(text, suffix)

    # Try as raw string
    return _parse_text(spec_source, ".json")


def _parse_text(text: str, suffix: str) -> dict[str, Any]:
    """Parse JSON or YAML text into a dict."""
    if suffix in (".json",):
        return json.loads(text)
    # Default to YAML (which is a superset of JSON)
    return yaml.safe_load(text)


def _extract_base_url(spec: dict[str, Any]) -> str:
    """Extract the base URL from an OpenAPI/Swagger spec."""
    # OpenAPI 3.x: servers[].url
    servers = spec.get("servers", [])
    if servers:
        return servers[0].get("url", "").rstrip("/")

    # Swagger 2.0: host + basePath + schemes
    host = spec.get("host", "")
    base_path = spec.get("basePath", "")
    schemes = spec.get("schemes", ["https"])
    if host:
        scheme = schemes[0] if schemes else "https"
        return f"{scheme}://{host}{base_path}".rstrip("/")

    return ""


def _is_id_param(name: str) -> bool:
    """Check if a parameter name likely refers to an object ID."""
    return bool(_ID_PARAM_PATTERNS.match(name))


def _extract_path_params(path: str) -> list[str]:
    """Extract all {param} names from a path template."""
    return _PATH_PARAM_RE.findall(path)


def _get_security_schemes(spec: dict[str, Any]) -> dict[str, Any]:
    """Extract security scheme definitions from the spec."""
    # OpenAPI 3.x
    components = spec.get("components", {})
    schemes = components.get("securitySchemes", {})
    if schemes:
        return schemes
    # Swagger 2.0
    return spec.get("securityDefinitions", {})


def _endpoint_has_auth(spec: dict[str, Any], path: str, method: str) -> bool:
    """Check if an endpoint has authentication requirements."""
    paths = spec.get("paths", {})
    path_item = paths.get(path, {})

    # Check operation-level security
    operation = path_item.get(method.lower(), {})
    if operation.get("security"):
        return True

    # Check global security
    if spec.get("security"):
        return True

    return False


def parse_openapi_spec(
    spec_source: str,
    base_url: str | None = None,
    include_all: bool = False,
) -> list[dict[str, Any]]:
    """Parse an OpenAPI/Swagger spec and extract endpoints for IDOR scanning.

    Args:
        spec_source: File path, URL, or raw spec string (JSON/YAML).
        base_url: Override the base URL from the spec.
        include_all: If True, include endpoints without path params too.

    Returns:
        List of endpoint dicts with keys:
          - method: HTTP method (GET, POST, etc.)
          - path: Path template (e.g. "/users/{userId}")
          - url_template: Full URL template
          - params: List of path parameter names
          - id_params: List of parameters that look like object IDs
          - has_auth: Whether the endpoint requires authentication
          - summary: Operation summary from spec
          - tags: Operation tags
          - operation_id: Operation ID
    """
    spec = _load_spec(spec_source)
    spec_base_url = _extract_base_url(spec)
    effective_base = (base_url or spec_base_url or "").rstrip("/")

    paths = spec.get("paths", {})
    endpoints: list[dict[str, Any]] = []

    for path, path_item in paths.items():
        if not isinstance(path_item, dict):
            continue

        for method in ("get", "post", "put", "patch", "delete"):
            operation = path_item.get(method)
            if not operation or not isinstance(operation, dict):
                continue

            params = _extract_path_params(path)
            id_params = [p for p in params if _is_id_param(p)]

            # Skip endpoints without ID params unless include_all
            if not include_all and not id_params:
                continue

            url_template = f"{effective_base}{path}" if effective_base else path

            endpoints.append({
                "method": method.upper(),
                "path": path,
                "url_template": url_template,
                "params": params,
                "id_params": id_params,
                "has_auth": _endpoint_has_auth(spec, path, method),
                "summary": operation.get("summary", ""),
                "description": operation.get("description", "")[:200],
                "tags": operation.get("tags", []),
                "operation_id": operation.get("operationId", ""),
                "parameters": [
                    {
                        "name": p.get("name", ""),
                        "in": p.get("in", ""),
                        "required": p.get("required", False),
                        "schema": p.get("schema", {}),
                    }
                    for p in (
                        operation.get("parameters", [])
                        + path_item.get("parameters", [])
                    )
                    if isinstance(p, dict)
                ],
            })

    return endpoints


def get_spec_info(spec_source: str) -> dict[str, Any]:
    """Get high-level info about an OpenAPI/Swagger spec.

    Returns:
        Dict with keys: title, version, description, base_url, total_paths,
        total_endpoints, idor_candidates, security_schemes.
    """
    spec = _load_spec(spec_source)
    info = spec.get("info", {})
    paths = spec.get("paths", {})

    total_endpoints = 0
    idor_candidates = 0
    for path, path_item in paths.items():
        if not isinstance(path_item, dict):
            continue
        for method in ("get", "post", "put", "patch", "delete"):
            if path_item.get(method):
                total_endpoints += 1
                params = _extract_path_params(path)
                if any(_is_id_param(p) for p in params):
                    idor_candidates += 1

    return {
        "title": info.get("title", "Unknown"),
        "version": info.get("version", "Unknown"),
        "description": info.get("description", "")[:500],
        "base_url": _extract_base_url(spec),
        "total_paths": len(paths),
        "total_endpoints": total_endpoints,
        "idor_candidates": idor_candidates,
        "security_schemes": list(_get_security_schemes(spec).keys()),
        "openapi_version": spec.get("openapi", spec.get("swagger", "unknown")),
    }
