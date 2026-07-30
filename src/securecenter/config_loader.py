"""Configuración de SecureCenter.

SecureCenter no reimplementa nada de los tres proyectos: los orquesta. Para
eso necesita saber DÓNDE están en el disco. Por defecto los busca solo (son
carpetas hermanas dentro de la misma carpeta de proyectos), pero todo se
puede fijar a mano en config/config.yaml si los tenés en otro lado.
"""

from dataclasses import dataclass, field
from pathlib import Path

import yaml

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent


@dataclass
class ProjectPaths:
    """Ruta a cada proyecto. Vacío ("") = autodetectar entre las carpetas
    hermanas buscando su paquete característico (src/secureproxy, etc.)."""

    proxy: str = ""
    dns: str = ""
    vpn: str = ""


@dataclass
class Ports:
    """Puertos de cada proyecto.

    Ojo con SecureProxy: tiene DOS puertos. El 8888 es por donde proxea (es
    el que dice si el servicio está vivo y el que hay que liberar para
    apagarlo) y el 8889 es su dashboard, que vive en su propio puerto.
    SecureDNS y SecureVPN usan un solo puerto para el panel."""

    proxy_service: int = 8888
    proxy_dashboard: int = 8889
    dns_dashboard: int = 8890
    vpn_dashboard: int = 8891
    center_dashboard: int = 8899


@dataclass
class Config:
    paths: ProjectPaths = field(default_factory=ProjectPaths)
    ports: Ports = field(default_factory=Ports)
    # Host donde escucha el dashboard unificado (loopback: solo tu PC).
    dashboard_host: str = "127.0.0.1"
    # DB propia de SecureCenter (eventos de orquestación: encendidos, apagados).
    db_path: str = "data/center_logs.db"

    def resolve_path(self, relative_path: str) -> Path:
        path = Path(relative_path)
        return path if path.is_absolute() else PROJECT_ROOT / path


def load_config(config_path: str | None = None) -> Config:
    if config_path is None:
        config_path = str(PROJECT_ROOT / "config" / "config.yaml")

    raw: dict = {}
    if Path(config_path).exists():
        with open(config_path, "r", encoding="utf-8") as f:
            raw = yaml.safe_load(f) or {}

    # db_path acepta la forma de los hermanos (logging: db_path) o al ras.
    db_path = raw.get("logging", {}).get("db_path") or raw.get("db_path", "data/center_logs.db")
    return Config(
        paths=ProjectPaths(**raw.get("paths", {})),
        ports=Ports(**raw.get("ports", {})),
        dashboard_host=raw.get("dashboard_host", "127.0.0.1"),
        db_path=db_path,
    )
