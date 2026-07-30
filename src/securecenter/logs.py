"""Línea de tiempo unificada: junta los eventos de los tres proyectos.

Cada proyecto guarda sus logs en su propia base SQLite, con su propio
esquema (el proxy registra requests, el DNS consultas, la VPN eventos).
Este módulo los lee en SOLO LECTURA, los normaliza a un formato común
(fecha, proyecto, tipo, detalle) y los mezcla ordenados por hora, para que
el dashboard muestre "qué pasó y cuándo" en un solo lugar.

Se abre cada base en modo ro (read-only) para no interferir jamás con el
proceso del proyecto que la está escribiendo.
"""

import sqlite3
from dataclasses import dataclass
from pathlib import Path

from .config_loader import Config
from .projects import ManagedProject


@dataclass
class LogRow:
    timestamp: str
    project: str  # "SecureProxy" | "SecureDNS" | "SecureVPN"
    kind: str  # "bloqueo" | "consulta" | "evento" ...
    detail: str
    ok: bool = True


# Cada proyecto: (archivo de db relativo, consulta, función que arma el detalle).
_SOURCES = {
    "proxy": {
        "db": "data/proxy_logs.db",
        "query": (
            "SELECT timestamp, host, reason, blocked FROM requests "
            "WHERE blocked = 1 ORDER BY id DESC LIMIT ?"
        ),
        "name": "SecureProxy",
    },
    "dns": {
        "db": "data/dns_logs.db",
        "query": (
            "SELECT timestamp, domain, reason, blocked FROM queries "
            "WHERE blocked = 1 ORDER BY id DESC LIMIT ?"
        ),
        "name": "SecureDNS",
    },
    "vpn": {
        "db": "data/vpn_logs.db",
        "query": "SELECT timestamp, event, detail, ok FROM events ORDER BY id DESC LIMIT ?",
        "name": "SecureVPN",
    },
}


def _read_ro(db_file: Path, query: str, limit: int) -> list[tuple]:
    """Lee una base SQLite en modo solo-lectura. Si no existe o no se puede
    abrir (el proyecto nunca corrió), devuelve lista vacía sin romper nada."""
    if not db_file.exists():
        return []
    try:
        uri = f"file:{db_file.as_posix()}?mode=ro"
        with sqlite3.connect(uri, uri=True, timeout=2) as conn:
            return conn.execute(query, (limit,)).fetchall()
    except sqlite3.Error:
        return []


def collect_logs(
    cfg: Config, projects: dict[str, ManagedProject], per_source: int = 40
) -> list[LogRow]:
    """Junta y ordena (más nuevo primero) los eventos de los tres."""
    rows: list[LogRow] = []

    for key, source in _SOURCES.items():
        project = projects.get(key)
        if project is None or not project.found:
            continue
        db_file = project.db_path(source["db"])
        if db_file is None:
            continue
        raw = _read_ro(db_file, source["query"], per_source)
        for record in raw:
            if key == "vpn":
                ts, event, detail, ok = record
                rows.append(
                    LogRow(str(ts), source["name"], str(event), str(detail or ""), bool(ok))
                )
            else:
                ts, target, reason, _blocked = record
                rows.append(
                    LogRow(
                        str(ts),
                        source["name"],
                        "bloqueo",
                        f"{target} - {reason}" if reason else str(target),
                    )
                )

    # Los timestamps son ISO-8601 UTC en los tres proyectos: ordenan bien
    # como texto, sin tener que parsearlos a datetime.
    rows.sort(key=lambda r: r.timestamp, reverse=True)
    return rows
