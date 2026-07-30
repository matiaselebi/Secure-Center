#!/usr/bin/env python3
"""Punto de entrada del dashboard unificado de SecureCenter (puerto 8899)."""

import os
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

PID_FILE = PROJECT_ROOT / "data" / "dashboard.pid"

from securecenter.config_loader import load_config  # noqa: E402
from securecenter.dashboard import build_dashboard_server  # noqa: E402
from securecenter.logger_db import LoggerDB  # noqa: E402
from securecenter.orchestrator import Orchestrator  # noqa: E402
from securecenter.projects import discover_projects  # noqa: E402


def main() -> None:
    cfg = load_config()
    projects = discover_projects(cfg)
    logger_db = LoggerDB(str(cfg.resolve_path(cfg.db_path)))
    orchestrator = Orchestrator(cfg, projects, logger_db)

    server = build_dashboard_server(cfg.dashboard_host, cfg.ports.center_dashboard, orchestrator, logger_db)

    PID_FILE.parent.mkdir(parents=True, exist_ok=True)
    PID_FILE.write_text(str(os.getpid()))

    print(f"[SecureCenter] dashboard: http://{cfg.dashboard_host}:{cfg.ports.center_dashboard}/")
    for key, project in projects.items():
        estado = "encontrado" if project.found else "NO ENCONTRADO (revisá config.yaml)"
        print(f"[SecureCenter] {key}: {estado}")
    print(f"[SecureCenter] PID: {os.getpid()} (guardado en {PID_FILE})")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[SecureCenter] deteniendo dashboard...")
    finally:
        server.shutdown()
        if PID_FILE.exists():
            PID_FILE.unlink()


if __name__ == "__main__":
    main()
