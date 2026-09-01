"""GitHub scan engine - orchestrates resolve→fetch→analyze→report pipeline.

Reuses existing program_engine for static analysis; returns identical findings
structure so parity test vs mode=program is exact (PRD §7 testing).
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from app.agents.brain import Brain
from app.agents.fetcher import FetcherAgent
from app.engines.diff_scope import DiffScope
from app.engines.program_engine import run_program_scan


class GithubEngine:
    """Orchestrate github-scan pipeline with brain cache + trajectory."""

    def __init__(
        self,
        scan_id: str,
        brain: Brain,
        reports_dir: str,
        settings: Any,
        on_stage: Any | None = None,  # callback(stage) for progress reporting
    ):
        self.scan_id = scan_id
        self.brain = brain
        self.reports_dir = reports_dir
        self.settings = settings
        self._on_stage = on_stage

    async def _notify(self, stage: str) -> None:
        """Trigger progress callback if provided."""
        if self._on_stage is not None:
            try:
                await self._on_stage(stage)
            except Exception:  # never fail a scan on progress error
                pass

    async def run(
        self,
        repo_url: str,
        ref: str | None = None,
        subdir: str | None = None,
        lang: str = "auto",
        force: bool = False,
        token: str | None = None,
        diff_base: str | None = None,
        scope_mode: str = "auto",
        level: str = "medium",
    ) -> dict[str, Any]:
        """Run full github scan pipeline."""
        started = time.monotonic()

        # Stage 1: RESOLVE & FETCH
        await self._notify("resolve")
        fetcher = FetcherAgent(self.scan_id, self.reports_dir, brain=self.brain)
        ctx = {
            "repo_url": repo_url,
            "ref": ref,
            "subdir": subdir,
            "github_token": token,
            "force": force,
            "diff_base": diff_base,
        }

        result = await fetcher(ctx)
        if not result.ok:
            return self._empty_report(f"resolve/fetch failed: {result.error}", started)

        sha = result.data.get("sha", "")

        # NOTE: the fetcher no longer returns a "cached" short-circuit — the
        # old cache-hit path returned an EMPTY findings list, which a user
        # could misread as "repo is clean". Scans always run the analyzer;
        # brain.set_repo_scan_meta below still records repo@sha metadata.

        # Extract sandbox path for analyzer
        tree_root = Path(result.data["tree_root"])

        # Stage fetch — dipanggil di sini agar progress 25→50→75 tidak melompat
        # (cli-experience.md §5.2 perbaikan bug R2; worker.py:77 sudah memetakan fetch:50)
        await self._notify("fetch")

        # Resolve diff-scope (Strix --diff-base pattern). Explicit diff_base
        # forces diff scope; otherwise follow scope_mode semantics.
        include_paths: set[str] | None = None
        if diff_base or scope_mode in ("diff", "auto"):
            scope_calc = DiffScope(
                base_dir=tree_root,
                repo_url=repo_url,
                token=token,
            )
            # Explicit diff_base overrides auto semantics so users can force
            # diff-scope outside CI without changing scope_mode.
            calc_mode = "diff" if diff_base else scope_mode
            scope_doc = await scope_calc.calculate_scope(
                mode=calc_mode,
                diff_base=diff_base,
                head=sha,
            )
            if scope_doc.get("resolved"):
                include_paths = set(scope_doc.get("include_paths", []))

        # Stage 2: ANALYZE (reuse program engine)
        await self._notify("analyze")
        analysis_result = run_program_scan(
            lang=lang,
            source_dir=tree_root,
            scan_id=self.scan_id,
            include_paths=include_paths,
            level=level,
        )

        findings = analysis_result["findings"]

        # Stage 3: REPORT (merge metadata)
        await self._notify("report")

        # Severity accessor: findings may be Pydantic Finding models or dicts
        def _severity(f):
            return (
                getattr(f, "severity", None).value
                if hasattr(f, "severity")
                else f.get("severity")
            )

        summary = {
            "total": len(findings),
            "critical": sum(1 for f in findings if _severity(f) == "critical"),
            "high": sum(1 for f in findings if _severity(f) == "high"),
            "medium": sum(1 for f in findings if _severity(f) == "medium"),
            "low": sum(1 for f in findings if _severity(f) == "low"),
            "info": sum(1 for f in findings if _severity(f) == "info"),
            "files_analyzed": analysis_result.get("files_scanned", len(findings)),
        }

        meta = {
            "scan_id": self.scan_id,
            "mode": "github",
            "engine": "github-static",
            "pipeline": ["resolve", "analyze", "report"],
            "repo": {
                "url": repo_url,
                "owner": result.data["owner"],
                "repo": result.data["repo"],
                "ref": result.data.get("ref", ref or "unknown"),
                "commit_sha": sha[:8] if sha else "unknown",
                "size_bytes": result.data.get("size_bytes", 0),
            },
        }
        if diff_base:
            meta["diff_base"] = diff_base
        if include_paths is not None:
            meta["diff_scope"] = {
                "active": True,
                "included_files": len(include_paths),
            }

        result_data = {
            "meta": meta,
            "summary": summary,
            "findings": [f.model_dump(mode="json") if hasattr(f, "model_dump") else f
                         for f in findings],
            "duration_ms": int((time.monotonic() - started) * 1000),
        }

        # Update brain memory after successful scan
        if self.brain and sha:
            self.brain.set_repo_scan_meta(
                result.data["owner"],
                result.data["repo"],
                result.data.get("ref", ref),
                sha,
            )

        return result_data

    @staticmethod
    def _empty_report(error: str, started: float) -> dict[str, Any]:
        """Return empty report structure for failures."""
        return {
            "meta": {
                "scan_id": "",
                "mode": "github",
                "engine": "github-static",
                "error": error,
            },
            "summary": {},
            "findings": [],
        }
