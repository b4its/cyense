"""API endpoints untuk remediasi (PRD §3.2 - 5 endpoint baru).

POST/GET/POST /api/v1/scans/{id}/fixes
GET/POST/POST /api/v1/fixes/{session_id}
- propose proposals (dry-run, tidak menulis)
- list proposals + diff preview
- apply dengan confirm: true
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

router = APIRouter(tags=["remediation"])


class ApplyRequest(BaseModel):
    fix_ids: list[str] = Field(default_factory=list, description="ID fixes yang akan diterapkan")
    confirm: bool = Field(default=False, description="Set true untuk konfirmasi write ke file")


class ApplyResponse(BaseModel):
    applied: list[str] = []
    failed: list[str] = []
    verified: list[str] = []
    message: str = ""


# --- Endpoints ---

@router.post("/scans/{scan_id}/fixes", status_code=202)
async def propose_fixes(
    request: Request,
    scan_id: str,
) -> dict[str, str]:
    """Generate patch proposals dari temuan scan (dry-run)."""
    session_store = request.app.state.fix_store

    # Get scan result
    report = request.app.state.worker.result(scan_id)
    if not report or "findings" not in report:
        raise HTTPException(status_code=404, detail="Scan not found or no findings")

    findings = report["findings"]
    if not findings:
        return {"message": "No findings to fix"}

    # Create fix session
    session = session_store.create_session(scan_id)

    # Run FixerAgent
    from app.remediation.fixer import FixerAgent
    agent = FixerAgent(
        scan_id=scan_id,
        reports_dir=str(request.app.state.settings.reports_dir),
        store=session_store,
        brain=request.app.state.brain,
    )

    # Generate proposals
    result = await agent.run(findings)

    return {
        "session_id": session.session_id,
        "status": "queued",
        "message": f"Proposals generated: {result.data.get('proposals_count', 0)} fixes ready",
    }


@router.get("/fixes/{session_id}")
async def get_fixes(session_id: str, request: Request) -> dict[str, Any]:
    """Get proposal list for a session."""
    session_store = request.app.state.fix_store

    session_data = session_store.get_session(session_id)
    if not session_data:
        raise HTTPException(status_code=404, detail="Fix session not found")

    proposals = session_store.get_all_proposals(session_id)

    return {
        "session_id": session_id,
        "status": session_data["status"],
        "total_proposals": len(proposals),
        "proposals": proposals,
    }


@router.get("/fixes/{session_id}/diff")
async def get_diff(session_id: str, request: Request) -> str:
    """Get unified diff of all proposals (text/plain response)."""
    session_store = request.app.state.fix_store

    session_data = session_store.get_session(session_id)
    if not session_data:
        raise HTTPException(status_code=404, detail="Session not found")

    proposals = session_store.get_all_proposals(session_id)

    # Build unified diff
    diff_lines = ["# Cyense IDOR Remediation Diff", f"# Session: {session_id}", ""]
    for prop in proposals:
        diff_text = prop.get("diff", "")
        is_actionable = (
            diff_text
            and "manual_required" not in diff_text
            and "pattern_not_found" not in diff_text
        )
        if is_actionable:
            header = (
                f"## File: {prop.get('target_file', 'unknown')} "
                f"Line {prop.get('line')} Rule: {prop.get('rule')}"
            )
            diff_lines.append(header)
            diff_lines.append(diff_text)
            diff_lines.append("")

    return "\n".join(diff_lines)


@router.post("/fixes/{session_id}/apply")
async def apply_fixes(
    session_id: str,
    body: ApplyRequest,
    request: Request,
) -> ApplyResponse:
    """Apply patches to files (requires confirm=true)."""
    session_store = request.app.state.fix_store
    settings = request.app.state.settings

    # Security gate: must confirm
    if not body.confirm:
        raise HTTPException(status_code=422, detail="confirm must be true to apply patches")

    session_data = session_store.get_session(session_id)
    if not session_data:
        raise HTTPException(status_code=404, detail="Session not found")

    if session_data["status"] == "completed":
        raise HTTPException(status_code=409, detail="Session already completed")

    # Validate same-origin for each proposal
    from pathlib import Path

    from app.remediation.applier import apply_patch, compute_file_hash, is_same_origin

    applied: list[str] = []
    failed: list[str] = []

    # Source root determination
    source_root = Path(settings.workspace_dir)
    if not source_root.exists():
        source_root = Path(settings.reports_dir).parent / "src"

    for fix_id in body.fix_ids:
        proposal = session_store.get_proposal(session_id, fix_id)
        if not proposal:
            failed.append(fix_id)
            continue

        try:
            target_path = proposal.get("target_file", "")

            # Same-origin check
            is_valid, error = is_same_origin(target_path, source_root)
            if not is_valid:
                failed.append(fix_id)
                continue

            # Check if already unchanged
            before_hash = compute_file_hash(Path(target_path))

            # Apply patch
            success, error_msg, backup = apply_patch(
                Path(target_path),
                proposal["diff"],
                source_root,
            )

            if success:
                after_hash = compute_file_hash(Path(target_path))
                unchanged = before_hash == after_hash

                # Update proposal state
                session_store.update_proposal(session_id, fix_id, {
                    "backup_path": str(backup) if backup else None,
                    "applied_at": True,
                    "before_hash": before_hash,
                    "after_hash": after_hash,
                    "unchanged": unchanged,
                })

                applied.append(fix_id)
            else:
                failed.append(fix_id)

        except Exception:
            failed.append(fix_id)

    # Mark session as completed
    session_store.complete_session(session_id)

    return ApplyResponse(
        applied=applied,
        failed=failed,
        message=f"Applied {len(applied)}, Failed {len(failed)}",
    )


@router.post("/fixes/{session_id}/revert")
async def revert_fixes(
    session_id: str,
    request: Request,
) -> dict[str, str]:
    """Revert applied patches using backups."""
    session_store = request.app.state.fix_store

    session_data = session_store.get_session(session_id)
    if not session_data:
        raise HTTPException(status_code=404, detail="Session not found")

    from pathlib import Path

    from app.remediation.applier import revert_patch

    reverted = []
    failed = []

    for prop in session_store.get_all_proposals(session_id):
        backup_path_str = prop.get("backup_path")
        if not backup_path_str:
            failed.append(prop.get("fix_id"))
            continue

        try:
            file_path = Path(prop.get("target_file"))
            backup_path = Path(backup_path_str)

            success = revert_patch(file_path, backup_path)

            if success:
                reverted.append(prop.get("fix_id"))
                session_store.update_proposal(session_id, prop.get("fix_id"), {
                    "status": "reverted",
                })
            else:
                failed.append(prop.get("fix_id"))

        except Exception:
            failed.append(prop.get("fix_id"))

    return {
        "reverted": reverted,
        "failed": failed,
    }
