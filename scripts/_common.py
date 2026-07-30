"""Helper compartido por los scripts: arma el orquestador ya cableado."""

import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from securecenter.config_loader import load_config  # noqa: E402
from securecenter.health import health_snapshot  # noqa: E402
from securecenter.logger_db import LoggerDB  # noqa: E402
from securecenter.orchestrator import Orchestrator  # noqa: E402
from securecenter.projects import discover_projects  # noqa: E402


def build_orchestrator() -> Orchestrator:
    cfg = load_config()
    projects = discover_projects(cfg)
    logger_db = LoggerDB(str(cfg.resolve_path(cfg.db_path)))
    return Orchestrator(cfg, projects, logger_db)


def print_result(result) -> int:
    for line in result.lines:
        print(f"[SecureCenter] {line}")
    return 0 if result.ok else 1


def estado(orch) -> dict:
    """Salud actual de los tres (proxy/dns/vpn -> bool)."""
    return health_snapshot(orch.cfg)


def esperar_estado(orch, arriba: bool, keys, timeout: float = 2.5, intervalo: float = 0.25) -> dict:
    """Sondea la salud hasta que las claves pedidas lleguen al estado
    deseado (arriba=True o False), o hasta agotar el timeout. Devuelve apenas
    se cumple - mucho más rápido que una pausa fija, porque los servicios
    suelen escuchar en menos de un segundo."""
    fin = time.time() + timeout
    while True:
        h = estado(orch)
        if all(h[k] == arriba for k in keys) or time.time() >= fin:
            return h
        time.sleep(intervalo)
