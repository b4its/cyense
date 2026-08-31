"""Multi-target batch scanning (enhanced-reporting-viewer.md §3.4).

Creates one scan job per target, enqueues them through the existing worker
queue, waits for all to reach a terminal state, and aggregates the results.

Architecture note — honest scoping: the ScanWorker drains a single asyncio
queue (PRD v2.0 §5.4), so jobs submitted together execute **serially**.
"Multi-target" here means *batch submission + aggregation*, not parallel
execution; true parallelism would require multiple workers (out of scope,
kept as a future hook). This keeps the state machine and job store
guarantees intact.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any

from app.core.models import ScanRequest
from app.core.models_github import GithubScanRequest
from app.core.store import JobStore

if TYPE_CHECKING:  # heavy import — only needed for type hints (keeps module testable)
    from app.worker import ScanWorker

_TERMINAL = ("completed", "failed")


def _normalize_github_url(raw: str) -> str:
    """Accept ``https://github.com/o/r`` or ``o/r``; return the full URL."""
    raw = raw.strip()
    if raw.startswith("https://github.com/") or raw.startswith("http://github.com/"):
        return raw
    if "/" in raw and " " not in raw and "." not in raw.split("/")[0]:
        return f"https://github.com/{raw}"
    return raw


def build_request(target: dict[str, Any], common_config: dict[str, Any]) -> ScanRequest:
    """Build the correct ScanRequest subclass for a target entry."""
    config = {**common_config, **target.get("config", {})}
    # The permission gate is mandatory for every mode (422 otherwise).
    config.setdefault("i_have_permission", True)

    ttype = str(target.get("type", "")).lower()

    if ttype == "github":
        # Target-level values win; config fills the rest (no duplicate kwargs).
        github_kwargs: dict[str, Any] = {
            k: v for k, v in config.items()
            if k in ("subdir", "lang", "github_token", "force", "i_have_permission")
        }
        # Pop config values FIRST (short-circuit `or` would skip the pop).
        cfg_ref = github_kwargs.pop("ref", None)
        cfg_lang = github_kwargs.pop("lang", "auto")
        return GithubScanRequest(
            repo_url=_normalize_github_url(target["url"]),
            ref=target.get("ref") or cfg_ref,
            lang=target.get("lang") or cfg_lang,
            **github_kwargs,
        )

    if ttype in ("local", "program"):
        from app.core.models import ProgramScanRequest

        program_kwargs = {
            k: v for k, v in config.items()
            if k in ("lang", "source_type", "i_have_permission")
        }
        cfg_lang = program_kwargs.pop("lang", "python")
        return ProgramScanRequest(
            mode="program",
            lang=target.get("lang") or cfg_lang,
            **program_kwargs,
        )

    if ttype in ("url", "link"):
        from app.core.models import LinkScanRequest

        link_kwargs = {
            k: v for k, v in config.items()
            if k in ("headers", "cookies", "baseline_id", "probe_ids", "method", "i_have_permission")
        }
        return LinkScanRequest(
            mode="link",
            url=target["url"],
            **link_kwargs,
        )

    raise ValueError(f"Unknown target type: {target.get('type')!r}")


class MultiTargetScanner:
    """Batch-submits targets through the existing worker queue + aggregates."""

    def __init__(self, store: JobStore, worker: ScanWorker):
        self.store = store
        self.worker = worker

    async def scan_multiple(
        self,
        targets: list[dict[str, Any]],
        common_config: dict[str, Any] | None = None,
        poll_interval: float = 1.0,
        timeout: float = 3600.0,
    ) -> dict[str, Any]:
        """Submit all targets, wait for completion, aggregate results."""
        common_config = common_config or {}
        entries: list[tuple[str, str]] = []  # (scan_id, target label)

        for target in targets:
            request = build_request(target, common_config)
            job = self.store.create(request)
            self.worker.enqueue(job)
            label = target.get("url") or target.get("path") or target.get("type", "?")
            entries.append((job.scan_id, label))

        # Wait (serially executed by the worker) for terminal states.
        import time

        deadline = time.monotonic() + timeout
        pending = {scan_id for scan_id, _ in entries}
        while pending:
            for scan_id in list(pending):
                job = self.store.get(scan_id)
                if job is None or job.status.value in _TERMINAL:
                    pending.discard(scan_id)
            if not pending:
                break
            if time.monotonic() > deadline:
                break
            await asyncio.sleep(poll_interval)

        return self._aggregate(entries)

    def _aggregate(self, entries: list[tuple[str, str]]) -> dict[str, Any]:
        by_target: list[dict[str, Any]] = []
        total_findings = 0
        by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

        for scan_id, label in entries:
            job = self.store.get(scan_id)
            status = job.status.value if job else "unknown"
            result = self.worker.result(scan_id)

            entry: dict[str, Any] = {
                "scan_id": scan_id,
                "target": label,
                "status": status,
            }
            if job is not None and job.error:
                entry["error"] = job.error

            if result is not None:
                summary = result.get("summary", {})
                findings = result.get("findings", [])
                entry["summary"] = summary
                entry["findings_count"] = len(findings)
                total_findings += len(findings)
                for sev in by_severity:
                    by_severity[sev] += summary.get(sev, 0)
            else:
                entry["findings_count"] = 0

            by_target.append(entry)

        return {
            "total_targets": len(entries),
            "completed": sum(1 for t in by_target if t["status"] == "completed"),
            "failed": sum(1 for t in by_target if t["status"] == "failed"),
            "aggregated": {
                "total_findings": total_findings,
                "by_severity": by_severity,
            },
            "by_target": by_target,
        }


def parse_targets_file(filepath: str) -> list[dict[str, Any]]:
    """
    Parse targets from a text file.

    Format (one per line, ``#`` comments allowed)::

        github:https://github.com/user/repo1
        github:https://github.com/user/repo2?ref=develop
        local:/path/to/project
        url:https://api.example.com
    """
    targets: list[dict[str, Any]] = []

    with open(filepath, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            if ":" not in line:
                raise ValueError(f"Invalid target format: {line}")

            target_type, target_value = line.split(":", 1)
            target_type = target_type.lower()
            target: dict[str, Any] = {"type": target_type}

            if target_type == "github":
                if "?" in target_value:
                    url, params = target_value.split("?", 1)
                    target["url"] = url
                    for param in params.split("&"):
                        if "=" in param:
                            key, value = param.split("=", 1)
                            target[key] = value
                else:
                    target["url"] = target_value
            elif target_type in ("local", "program"):
                target["path"] = target_value
            elif target_type in ("url", "link"):
                target["url"] = target_value
            else:
                raise ValueError(f"Unknown target type: {target_type}")

            targets.append(target)

    return targets
