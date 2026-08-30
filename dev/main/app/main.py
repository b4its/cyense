"""FastAPI application factory (PRD v2.0 §5.2).

Wires routers, job store, brain and the background worker; lifespan ensures
clean startup/shutdown of the worker loop.
"""

from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.agents.brain import Brain
from app.api import reports, scans, system, remediations  # Add remediations router
from app.core.config import settings
from app.core.store import JobStore
from app.remediation.store import FixStore
from app.utils.logger import get_logger
from app.worker import ScanWorker

log = get_logger("main")


@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.store = JobStore(settings.reports_dir)
    app.state.fix_store = FixStore(settings.reports_dir)  # Add fix store for remediation
    app.state.brain = Brain(settings.brain_dir)
    app.state.worker = ScanWorker(app.state.store, app.state.brain, settings)
    app.state.worker.start()
    log.info("cyense started (reports=%s brain=%s)", settings.reports_dir, settings.brain_dir)
    try:
        yield
    finally:
        await app.state.worker.stop()
        log.info("cyense stopped")


def create_app() -> FastAPI:
    app = FastAPI(
        title="Cyense",
        version="2.0.0",
        description=(
            "Cyber Insight Engine — agentic IDOR vulnerability scanner "
            "(link & program modes). Only scan targets you are authorized to test."
        ),
        lifespan=lifespan,
    )
    app.include_router(system.router, prefix="/api/v1")
    app.include_router(scans.router, prefix="/api/v1")
    app.include_router(reports.router, prefix="/api/v1")
    app.include_router(remediations.router, prefix="/api/v1")  # Add remediation endpoints
    return app


app = create_app()
