"""Línea de tiempo unificada: junta los eventos de los proyectos administrados.

Cada proyecto guarda sus logs en su propia base SQLite, con su propio
esquema (proxy, DNS, VPN, HIPS e Intel no guardan lo mismo).
Este módulo los lee en SOLO LECTURA, los normaliza a un formato común
(fecha, proyecto, tipo, detalle) y los mezcla ordenados por hora, para que
el dashboard muestre "qué pasó y cuándo" en un solo lugar.

Se abre cada base en modo ro (read-only) para no interferir jamás con el
proceso del proyecto que la está escribiendo.
"""

import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
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
    "hips": {
        "db": "data/hips_logs.db",
        # Los bans y no los intentos: un ataque de diccionario mete cientos de
        # intentos y taparía a los otros proyectos en la línea de tiempo. El
        # ban es el hecho que importa, y su motivo ya dice cuántos intentos lo
        # provocaron.
        "query": "SELECT desde, ip, motivo, aplicado FROM bans ORDER BY desde DESC LIMIT ?",
        "name": "SecureHIPS",
    },
    "intel": {
        "db": "data/intel.db",
        # No hay "eventos" acá: lo que importa de Secure-Intel es cuándo
        # actualizó cada fuente y si falló. Un feed que hace tres semanas que
        # no baja se parece muchísimo a uno que anda, y esta es la única línea
        # donde eso se ve al lado del resto de lo que pasó.
        "query": "SELECT ultima, nombre, error, ok FROM fuentes ORDER BY ultima DESC LIMIT ?",
        "name": "Secure-Intel",
    },
}


def _epoch_a_iso(valor) -> str:
    """Segundos desde 1970 al mismo formato ISO-8601 UTC que usan los otros.

    Si no se puede convertir se devuelve una cadena vacía: el evento va a
    quedar último en el orden, que es preferible a descartarlo o a romper el
    ordenamiento de todos los demás.
    """
    try:
        return datetime.fromtimestamp(float(valor), tz=timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%S"
        )
    except (TypeError, ValueError, OSError, OverflowError):
        return ""


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
    """Junta y ordena (más nuevo primero) los eventos disponibles."""
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
            elif key == "hips":
                # SecureHIPS guarda la hora como epoch (un número) y no como
                # texto ISO. Hay que convertirla acá: si entrara cruda, el
                # ordenamiento por texto pondría todos sus eventos juntos al
                # final ("1785..." ordena antes que "2026-..."), y la línea de
                # tiempo dejaría de estar ordenada justo cuando aparece un
                # bloqueo, que es cuando más se la mira.
                ts, ip, motivo, aplicado = record
                rows.append(LogRow(
                    _epoch_a_iso(ts), source["name"],
                    "bloqueo" if aplicado else "bloqueo (audit)",
                    f"{ip} - {motivo}" if motivo else str(ip),
                    bool(aplicado),
                ))
            elif key == "intel":
                # Epoch como el HIPS, misma conversión y por el mismo motivo.
                ts, nombre, error, ok = record
                rows.append(LogRow(
                    _epoch_a_iso(ts), source["name"],
                    "feed actualizado" if ok else "feed con problemas",
                    f"{nombre} - {error}" if error else str(nombre),
                    bool(ok),
                ))
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

    # Después de normalizar HIPS/Intel, los timestamps comparables son ISO-8601 UTC: ordenan bien
    # como texto, sin tener que parsearlos a datetime.
    rows.sort(key=lambda r: r.timestamp, reverse=True)
    return rows
