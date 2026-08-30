"""CLI package — thin client to Cyense FastAPI service.

Arsitektur: CLI hanya bicara ke API lewat HTTP (app/cli/client.py).
DILARANG mengimpor app.engines, app.agents, app.program, app.worker.
Lihat: instruction/feature/cli-experience.md §5.4
"""
