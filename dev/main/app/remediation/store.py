"""In-memory fix store with JSON dump (PRD §4 - FixStore).

Mirrors JobStore pattern: in-memory dict + best-effort persistence.
Stores FixSessions and associated proposals.
"""

from __future__ import annotations

import json
import threading
import time
from pathlib import Path
from typing import Any

from app.remediation.models import FixProposal, FixSession, PatchVerification


def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


class FixStore:
    """Manages fix sessions and proposals."""

    def __init__(self, reports_dir: Path) -> None:
        self._sessions: dict[str, dict[str, Any]] = {}  # session_id -> dict
        self._proposals: list[dict[str, Any]] = []  # flat list of proposals
        self._reports_dir = Path(reports_dir)
        self._reports_dir.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    # -- lifecycle -------------------------------------------------------------

    def create_session(self, scan_id: str) -> FixSession:
        session = FixSession(
            session_id=FixSession.generate_session_id(),
            scan_id=scan_id,
            created_at=_now_iso(),
            status="active",
        )
        with self._lock:
            self._sessions[session.session_id] = {
                "session": session.model_dump(mode="json"),
                "created": session.created_at,
                "status": session.status,
                "fixes": [],
            }
        self._dump()
        return session

    def get_session(self, session_id: str) -> dict[str, Any] | None:
        with self._lock:
            return self._sessions.get(session_id)

    def list_sessions(self, scan_id: str) -> list[dict[str, Any]]:
        with self._lock:
            return [
                s for s in self._sessions.values()
                if s["session"]["scan_id"] == scan_id
            ]

    def delete_session(self, session_id: str) -> bool:
        with self._lock:
            existed = self._sessions.pop(session_id, None) is not None
        if existed:
            self._dump()
        return existed

    # -- add proposals ---------------------------------------------------------

    def add_proposal(self, session_id: str, proposal: FixProposal) -> bool:
        with self._lock:
            session = self._sessions.get(session_id)
            if not session:
                return False

            prop_dict = proposal.model_dump(mode="json")
            session["fixes"].append(prop_dict)
            self._proposals.append(prop_dict)

            # Update status
            if session["status"] == "active":
                session["status"] = "proposed"

        self._dump()
        return True

    def get_all_proposals(self, session_id: str) -> list[dict[str, Any]]:
        with self._lock:
            session = self._sessions.get(session_id)
            return session["fixes"] if session else []

    def get_proposal(self, session_id: str, fix_id: str) -> dict[str, Any] | None:
        all_props = self.get_all_proposals(session_id)
        return next((p for p in all_props if p.get("fix_id") == fix_id), None)

    def update_proposal(
        self, session_id: str, fix_id: str, updates: dict[str, Any]
    ) -> bool:
        """Merge updates into a stored proposal (e.g. backup path, hashes).

        Also mirrors the change into the flat ``self._proposals`` list so the
        ``fix_sessions.json`` dump stays consistent (otherwise backup_path /
        hashes / status written at apply time never persisted).
        """
        with self._lock:
            session = self._sessions.get(session_id)
            if not session:
                return False
            for prop in session["fixes"]:
                if prop.get("fix_id") == fix_id:
                    prop.update(updates)
                    # Mirror into the flat list (identity by session+fix_id).
                    for flat in self._proposals:
                        if (
                            flat.get("fix_id") == fix_id
                            and flat.get("session_id") == session_id
                        ):
                            flat.update(updates)
                            break
                    self._dump()
                    return True
        return False

    # -- update state ----------------------------------------------------------

    async def apply_proposals(
        self,
        session_id: str,
        fix_ids: list[str],
        verify_results: dict[str, PatchVerification],
    ) -> tuple[list[str], list[str]]:
        """Mark fixes as applied; return (applied, failed)."""
        import asyncio

        lock = asyncio.Lock()
        applied: list[str] = []
        failed: list[str] = []

        for fix_id in fix_ids:
            async with lock:
                prop = self.get_proposal(session_id, fix_id)
                if not prop:
                    failed.append(fix_id)
                    continue

                prop["status"] = "applied"
                verification = verify_results.get(fix_id)
                if verification:
                    prop["verification"] = verification.model_dump()

                if verification and verification.original_resolved:
                    prop["status"] = "verified"
                    applied.append(fix_id)
                else:
                    failed.append(fix_id)

        session = self._sessions.get(session_id)
        if session:
            session["status"] = "completed"

        self._dump()
        return applied, failed

    # -- revert ------------------------------------------------------------------

    def revert_proposal(self, session_id: str, fix_id: str) -> bool:
        with self._lock:
            prop = self.get_proposal(session_id, fix_id)
            if not prop or not prop.get("backup_path"):
                return False
            prop["status"] = "reverted"
            prop["notes"] = "reverted via /api/v1/fixes/revert"
        self._dump()
        return True

    # -- completion ------------------------------------------------------------

    def complete_session(self, session_id: str) -> bool:
        with self._lock:
            session = self._sessions.get(session_id)
            if not session:
                return False
            session["status"] = "completed"
        self._dump()
        return True

    # -- persistence -----------------------------------------------------------

    def _dump(self) -> None:
        try:
            payload = {
                "sessions": [s["session"] for s in self._sessions.values()],
                "proposals": self._proposals,
            }
            (self._reports_dir / "fix_sessions.json").write_text(
                json.dumps(payload, indent=2, sort_keys=True)
            )
        except OSError:
            pass
