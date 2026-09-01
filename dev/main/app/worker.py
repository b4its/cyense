"""Background scan worker — asyncio queue (PRD v2.0 §5.4 design decision).

Keeps the API responsive: POST /scans only enqueues; the worker drains the
queue and updates the job store state machine.
"""

from __future__ import annotations

import asyncio
import time
from pathlib import Path
from typing import Any

from app.core.models import ScanJob
from app.core.store import JobStore
from app.engines.github_engine import GithubEngine
from app.engines.link_engine import run_link_scan
from app.engines.program_engine import resolve_source_dir, run_program_scan
from app.report.coverage import build_coverage_document, write_coverage

# CI/Compliance Reporting modules (ci-compliance-reporting.md)
from app.report.cvss import enrich_finding
from app.report.dedupe import deduplicate_findings
from app.report.sarif import dump_sarif_report
from app.services.scan_resume import (
    load_checkpoint,
    remove_checkpoint,
    save_checkpoint,
)
from app.utils.logger import get_logger

log = get_logger("worker")


class ScanWorker:
    def __init__(self, store: JobStore, brain: Any, settings: Any) -> None:
        self.store = store
        self.brain = brain
        self.settings = settings
        self.queue: asyncio.Queue[str] = asyncio.Queue()
        self._task: asyncio.Task[None] | None = None
        self._results: dict[str, dict[str, Any]] = {}

    # -- lifecycle -------------------------------------------------------------

    def start(self) -> None:
        self._task = asyncio.get_running_loop().create_task(self._loop())

    async def stop(self) -> None:
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass

    def enqueue(self, job: ScanJob) -> None:
        self.queue.put_nowait(job.scan_id)

    # -- main loop ---------------------------------------------------------------

    async def _loop(self) -> None:
        while True:
            scan_id = await self.queue.get()
            try:
                await self._process(scan_id)
            except Exception as exc:  # robustness: never crash the worker
                log.exception("scan %s crashed", scan_id)
                try:
                    await self.store.mark_failed(scan_id, str(exc))
                except Exception:  # noqa: BLE001 — belt & braces: a second
                    # failure here (e.g. job deleted mid-scan) must never
                    # kill the loop and starve every later scan.
                    log.exception("mark_failed(%s) raised; scan was deleted?", scan_id)
            finally:
                self.queue.task_done()

    async def _process(self, scan_id: str) -> None:
        job = self.store.get(scan_id)
        if job is None:
            return
        request = job.request
        request_dict = (
            request.model_dump(mode="json")
            if hasattr(request, "model_dump")
            else dict(request)
        )

        # Resume support: if this scan is resuming from another scan_id, load its checkpoint.
        resume_from: str | None = request_dict.get("resume_from")
        checkpoint: dict[str, Any] | None = None
        if resume_from:
            checkpoint = load_checkpoint(self.settings.reports_dir, resume_from)
            if checkpoint is None:
                await self.store.mark_failed(
                    scan_id, f"cannot resume {resume_from}: no checkpoint found"
                )
                return
            # Restore original request from checkpoint so resume uses the same
            # scan parameters (mode, url, lang, scope, etc.). New-request fields
            # (e.g. a fresh --instruction) override the original.
            original_request = dict(checkpoint.get("request", {}))
            original_request.update(request_dict)
            request_dict = original_request
            self._log_event(scan_id, f"restored original request for resume from {resume_from}")

        await self.store.mark_running(scan_id, stage="recon")
        started = time.monotonic()

        # Helper callback for all modes: update stage, progress, and checkpoint.
        async def on_stage(stage: str) -> None:
            progress = {
                "resolve": 25,
                "fetch": 50,
                "analyze": 75,
                "report": 90,
                "crawl": 30,
            }.get(
                stage if isinstance(stage, str) else str(stage),
                {"recon": 25, "probe": 50, "verify": 75, "report": 90}.get(stage, 0),
            )
            await self.store.mark_stage(scan_id, stage, progress)
            # Strix-style checkpoint at each stage transition. Carry over any
            # findings recovered from the checkpoint being resumed from so a
            # re-failure preserves them (resume merge depends on this).
            save_checkpoint(
                reports_dir=self.settings.reports_dir,
                scan_id=scan_id,
                request_dict=request_dict,
                stage=stage,
                progress=progress,
                findings_so_far=checkpoint.get("findings", []) if checkpoint else [],
                extra={"resume_from": resume_from, "checkpoint_of": resume_from},
            )

        report: dict[str, Any] | None = None
        try:
            if request_dict["mode"] == "link":
                report = await run_link_scan(
                    scan_id=scan_id,
                    request_dict=request_dict,
                    brain=self.brain,
                    reports_dir=str(self.settings.reports_dir),
                    settings=self.settings,
                    on_stage=on_stage,
                )
            elif request_dict["mode"] == "github":
                # github-scan mode (PRD feature); the engine reports its own
                # resolve/analyze/report stages via the on_stage callback —
                # pre-firing all stages here made progress jump to 90% instantly
                report = await run_github_scan(
                    scan_id=scan_id,
                    repo_url=request_dict["repo_url"],
                    ref=request_dict.get("ref"),
                    subdir=request_dict.get("subdir"),
                    lang=request_dict.get("lang", "auto"),
                    token=request_dict.get("github_token"),
                    force=request_dict.get("force", False),
                    diff_base=request_dict.get("diff_base"),
                    scope_mode=request_dict.get("scope_mode", "auto"),
                    level=request_dict.get("level", "medium"),
                    scan_mode=request_dict.get("scan_mode", "standard"),
                    brain=self.brain,
                    reports_dir=str(self.settings.reports_dir),
                    settings=self.settings,
                    on_stage=on_stage,
                )
            elif request_dict["mode"] == "website":
                # Website scan: crawl + discover ID endpoints + live XSS.
                report = await run_website_scan(
                    scan_id=scan_id,
                    url=request_dict["url"],
                    max_depth=int(request_dict.get("max_depth", 2)),
                    max_pages=int(request_dict.get("max_pages", 50)),
                    rate_limit=int(request_dict.get("rate_limit", 10)),
                    headers=request_dict.get("headers") or {},
                    cookies=request_dict.get("cookies") or {},
                    brain=self.brain,
                    reports_dir=str(self.settings.reports_dir),
                    settings=self.settings,
                    on_stage=on_stage,
                )
            else:
                await self.store.mark_stage(scan_id, "recon", 25)
                await on_stage("recon")
                source_dir = request_dict.get("source_dir") or resolve_source_dir(
                    request_dict.get("source_type", "mounted"),
                    str(self.settings.workspace_dir),
                )

                # Scan-mode presets (quick|standard|deep) actually drive the
                # analyzer now — previously scan_mode was stored but never
                # passed to run_program_scan, so --scan-mode had zero effect.
                from app.core.scan_modes import get_profile

                scan_mode = request_dict.get("scan_mode", "standard")
                mode_profile = get_profile(scan_mode)
                if mode_profile is None:
                    await self.store.mark_failed(
                        scan_id, f"invalid scan mode: {scan_mode}"
                    )
                    return
                scan_types = list(mode_profile.scan_types)
                max_files = mode_profile.max_files if mode_profile.max_files > 0 else None

                await self.store.mark_stage(scan_id, "probe", 50)
                await on_stage("probe")
                result = run_program_scan(
                    lang=request_dict.get("lang", "python"),
                    source_dir=source_dir,
                    scan_id=scan_id,
                    scan_types=scan_types,
                    max_files=max_files,
                    level=request_dict.get("level", "medium"),
                )
                await self.store.mark_stage(scan_id, "report", 80)
                await on_stage("report")
                report = self._program_report(scan_id, result, started)
                report.setdefault("meta", {})["scan_mode"] = scan_mode

            # If resuming, merge previous checkpoint findings and mark as resumed.
            if checkpoint:
                prev_findings = checkpoint.get("findings", [])
                if prev_findings:
                    report.setdefault("findings", []).extend(prev_findings)
                    report["summary"] = self._recalc_summary(
                        report.get("findings", []),
                        report.get("summary", {}),
                    )
                report.setdefault("meta", {})["resumed_from"] = resume_from
                self._log_event(scan_id, f"resumed from {resume_from}")

            # Enrich findings with CVSS data (ci-compliance-reporting.md §3.1)
            self._enrich_report(report)

            # Preserve custom instruction in report meta (Strix-style audit context)
            instruction = request_dict.get("instruction")
            if instruction:
                report.setdefault("meta", {})["instruction"] = instruction

            # If the scan was deleted (DELETE /scans/{id}) while RUNNING,
            # do not resurrect its report/artifacts — discard() already
            # removed them and the user asked for deletion (PRD §4.3).
            if self.store.get(scan_id) is None:
                self._log_event(scan_id, "scan deleted while running; skipping artifact writes")
                return

            self._results[scan_id] = report
            self._dump_report(scan_id, report)

            # Write SARIF and coverage reports (ci-compliance-reporting.md §3.2, §3.5)
            self._write_compliance_artifacts(scan_id, report)

            if report.get("meta", {}).get("error"):
                # recon-level controlled failure (e.g. no placeholder found):
                # surface as FAILED, not silently completed-empty
                await self.store.mark_failed(scan_id, report["meta"]["error"])
                remove_checkpoint(self.settings.reports_dir, scan_id)
                if resume_from:
                    remove_checkpoint(self.settings.reports_dir, resume_from)
            else:
                await self.store.mark_completed(scan_id)
                remove_checkpoint(self.settings.reports_dir, scan_id)
                if resume_from:
                    remove_checkpoint(self.settings.reports_dir, resume_from)
        except Exception as exc:
            await self.store.mark_failed(scan_id, str(exc))
            # Save failed checkpoint so user can resume after fixing cause.
            # Persist any findings the engine produced before crashing so a
            # resume can merge them (the resume-merge path below depends on
            # checkpoint["findings"] actually being populated).
            # Do NOT re-raise: _loop() already logs and marks failed; re-raising
            # would cause duplicate error state and duplicate logs.
            save_checkpoint(
                reports_dir=self.settings.reports_dir,
                scan_id=scan_id,
                request_dict=request_dict,
                stage=job.stage,
                progress=job.progress,
                findings_so_far=report.get("findings", []) if report else [],
                error=str(exc),
            )

    def result(self, scan_id: str) -> dict[str, Any] | None:
        """Get cached scan result by scan_id."""
        return self._results.get(scan_id)

    def _reports_dir_for(self, scan_id: str) -> Path | None:
        """Resolve and validate a per-scan reports directory.

        Returns ``None`` if the resolved path escapes reports_dir (defense-in-
        depth against malicious scan_id values). Scan IDs are normally server-
        generated, but we validate anyway to prevent any future injection.
        """
        target = (self.settings.reports_dir / scan_id).resolve()
        try:
            target.relative_to(self.settings.reports_dir.resolve())
        except ValueError:
            log.warning("scan_id %r escapes reports_dir", scan_id)
            return None
        return target

    def discard(self, scan_id: str) -> None:
        """Drop in-memory result and on-disk artifacts (PRD §4.3 DELETE)."""
        self._results.pop(scan_id, None)
        import shutil

        try:
            target = self._reports_dir_for(scan_id)
            if target is None:
                return
            shutil.rmtree(target, ignore_errors=True)
        except OSError:
            log.warning("failed to remove artifacts for %s", scan_id)


    # -- helpers -----------------------------------------------------------------


    @staticmethod
    def _program_report(scan_id: str, result: dict[str, Any], started: float) -> dict[str, Any]:
        finding_models = result["findings"]
        findings = [
            f.model_dump(mode="json") if hasattr(f, "model_dump") else f
            for f in finding_models
        ]

        # Deduplicate findings (ci-compliance-reporting.md §3.6)
        findings = deduplicate_findings(findings)

        summary = {
            "critical": sum(1 for f in findings if f["severity"] == "critical"),
            "high": sum(1 for f in findings if f["severity"] == "high"),
            "medium": sum(1 for f in findings if f["severity"] == "medium"),
            "low": sum(1 for f in findings if f["severity"] == "low"),
            "info": sum(1 for f in findings if f["severity"] == "info"),
            "total": len(findings),
            "files_scanned": result["files_scanned"],
            "duration_ms": int((time.monotonic() - started) * 1000),
        }
        # Propagate level + active rules from program_engine to report meta
        # so consumers (CLI, viewer, SARIF) can report what depth was used.
        meta: dict[str, Any] = {
            "scan_id": scan_id,
            "mode": "program",
            "engine": "static-ast",
        }
        if "level" in result:
            meta["level"] = result["level"]
        if "level_rules_active" in result:
            meta["level_rules_active"] = result["level_rules_active"]
        return {
            "meta": meta,
            "summary": summary,
            "findings": findings,
        }

    def _dump_report(self, scan_id: str, report: dict[str, Any]) -> None:
        import json

        try:
            out_dir = self._reports_dir_for(scan_id)
            if out_dir is None:
                return
            out_dir.mkdir(parents=True, exist_ok=True)
            (out_dir / "report.json").write_text(json.dumps(report, indent=2, sort_keys=True))
        except OSError:
            log.warning("failed to dump report for %s", scan_id)

    def _enrich_report(self, report: dict[str, Any]) -> None:
        """Enrich findings with CVSS data (ci-compliance-reporting.md §3.1)."""
        findings = report.get("findings", [])
        for finding in findings:
            enrich_finding(finding)

    def _write_compliance_artifacts(self, scan_id: str, report: dict[str, Any]) -> None:
        """Write SARIF and coverage reports (ci-compliance-reporting.md §3.2, §3.5)."""

        try:
            out_dir = self._reports_dir_for(scan_id)
            if out_dir is None:
                return

            # Write SARIF report
            sarif_path = out_dir / "findings.sarif"
            dump_sarif_report(report, sarif_path)

            # Write coverage report
            coverage_doc = build_coverage_document(report)
            write_coverage(out_dir, coverage_doc)

        except Exception as exc:
            log.warning("failed to write compliance artifacts for %s: %s", scan_id, exc)

    def _log_event(self, scan_id: str, message: str) -> None:
        """Log an event to the job store (best-effort, non-blocking)."""
        try:
            import asyncio
            loop = asyncio.get_event_loop()
            if loop.is_running():
                loop.create_task(self.store.log(scan_id, message))
            else:
                loop.run_until_complete(self.store.log(scan_id, message))
        except Exception:
            pass

    @staticmethod
    def _recalc_summary(
        findings: list[dict[str, Any]],
        existing: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Recalculate summary counts from a findings list (used after resume merge).

        Preserves non-severity fields from the existing summary so resume merge
        does not strip files_scanned, duration_ms, or other engine metadata.
        """
        summary = dict(existing) if existing else {}
        summary.update({
            "critical": sum(1 for f in findings if f.get("severity") == "critical"),
            "high": sum(1 for f in findings if f.get("severity") == "high"),
            "medium": sum(1 for f in findings if f.get("severity") == "medium"),
            "low": sum(1 for f in findings if f.get("severity") == "low"),
            "info": sum(1 for f in findings if f.get("severity") == "info"),
            "total": len(findings),
        })
        return summary


async def run_github_scan(
    scan_id: str,
    repo_url: str,
    ref: str | None = None,
    subdir: str | None = None,
    lang: str = "auto",
    token: str | None = None,
    force: bool = False,
    diff_base: str | None = None,
    scope_mode: str = "auto",
    level: str = "medium",
    scan_mode: str = "standard",
    brain: Any = None,
    reports_dir: str = "",
    settings: Any = None,
    on_stage: Any = None,
) -> dict[str, Any]:
    """Run github-scan mode pipeline."""
    engine = GithubEngine(
        scan_id=scan_id,
        brain=brain,
        reports_dir=reports_dir,
        settings=settings,
        on_stage=on_stage,
    )
    return await engine.run(
        repo_url=repo_url,
        ref=ref,
        subdir=subdir,
        lang=lang,
        force=force,
        token=token,
        diff_base=diff_base,
        scope_mode=scope_mode,
        level=level,
        scan_mode=scan_mode,
    )


async def run_website_scan(
    scan_id: str,
    url: str,
    max_depth: int = 2,
    max_pages: int = 50,
    rate_limit: int = 10,
    headers: dict[str, str] | None = None,
    cookies: dict[str, str] | None = None,
    brain: Any = None,
    reports_dir: str = "",
    settings: Any = None,
    on_stage: Any = None,
) -> dict[str, Any]:
    """Run website-scan mode pipeline (crawl + IDOR discovery + live XSS)."""
    from app.engines.website_engine import WebsiteEngine

    engine = WebsiteEngine(
        scan_id=scan_id,
        brain=brain,
        reports_dir=reports_dir,
        settings=settings,
        on_stage=on_stage,
    )
    return await engine.run(
        url=url,
        max_depth=max_depth,
        max_pages=max_pages,
        rate_limit=rate_limit,
        headers=headers or {},
        cookies=cookies or {},
    )
