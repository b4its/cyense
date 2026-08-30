"""GitHub scan engine - orchestrates resolve→fetch→analyze→report pipeline.

Reuses existing program_engine for static analysis; returns identical findings
structure so parity test vs mode=program is exact (PRD §7 testing).
"""

from __future__ import annotations

import time
from typing import Any

from app.agents.brain import Brain
from app.agents.fetcher import FetcherAgent
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
        }
        
        result = await fetcher(ctx)
        if not result.ok:
            return self._empty_report(f"resolve/fetch failed: {result.error}", started)
        
        # Check cache hit response
        cached = result.data.get("cached", False)
        sha = result.data.get("sha", "")
        
        if cached and sha:
            # Return from memory (caller provides stored report)
            meta = {
                "scan_id": self.scan_id,
                "mode": "github",
                "engine": "github-static",
                "pipeline": ["resolve"],
                "meta": {"repo": result.data},
            }
            return {"meta": meta, "summary": {}, "findings": [], "cached": True}
        
        # Extract sandbox path for analyzer
        tree_root = result.data["tree_root"]
        
        # Stage 2: ANALYZE (reuse program engine)
        await self._notify("analyze")
        analysis_result = run_program_scan(
            lang=lang,
            source_dir=tree_root,
            scan_id=self.scan_id,
        )
        
        findings = analysis_result["findings"]
        
        # Stage 3: REPORT (merge metadata)
        await self._notify("report")
        
        summary = {
            "total": len(findings),
            "critical": sum(1 for f in findings if f.get("severity") == "critical"),
            "high": sum(1 for f in findings if f.get("severity") == "high"),
            "medium": sum(1 for f in findings if f.get("severity") == "medium"),
            "low": sum(1 for f in findings if f.get("severity") == "low"),
            "info": sum(1 for f in findings if f.get("severity") == "info"),
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
        
        result_data = {
            "meta": meta,
            "summary": summary,
            "findings": [f.model_dump(mode="json") if hasattr(f, "model_dump") else f
                         for f in findings],
            "duration_ms": int((time.monotonic() - started) * 1000),
        }
        
        # Update brain memory after successful scan
        if self.brain and sha:
            cache_key = f"github.com/{result.data['owner']}/{result.data['repo']}"
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
