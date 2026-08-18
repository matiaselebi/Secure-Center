"""Llevarse lo que pasó, en un archivo que se pueda abrir en otro lado.

QUÉ SE EXPORTA

Los eventos de las fuentes compatibles en un rango de fechas, más un resumen por
proyecto y por tipo. Nada maquillado: lo que se exporta es lo que está en las
bases. Un reporte que "mejora" los datos para que se lean lindos es un reporte
en el que después no se puede confiar.

POR QUÉ CSV Y JSON Y NO PDF

Porque un reporte se exporta para hacerle algo: abrirlo en Excel, pasarlo por
un script, subirlo a otra herramienta. Para eso sirven CSV y JSON. Un PDF es
para imprimir, y nadie imprime esto. Si algún día hace falta, se genera desde
el JSON y no al revés.

EL RANGO ES POR DÍAS Y NO POR FECHAS EXACTAS

"Últimos 7 días" es lo que uno quiere el 95% de las veces, y no tiene forma de
salir mal. Dos campos de fecha son dos oportunidades de poner el mes en el
lugar del día y llevarse un archivo vacío sin entender por qué.
"""

import csv
import io
import json
import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path

from .logs import _SOURCES, _epoch_a_iso

# Los rangos que se ofrecen. Más de cuatro opciones en un menú de exportación
# es una decisión que nadie quiere tomar.
RANGOS = ((1, "hoy"), (7, "últimos 7 días"), (30, "últimos 30 días"),
          (90, "últimos 90 días"))

# Tope de filas por proyecto. Es alto a propósito (la idea es llevarse todo)
# pero existe: sin tope, exportar 90 días de una base grande arma la respuesta
# entera en memoria antes de mandar el primer byte.
MAXIMO_POR_PROYECTO = 50_000


def _desde(dias: int, ahora: float | None = None) -> float:
    """Medianoche local de hace N días, en epoch.

    Local y no UTC: si el corte fuera a mediodía UTC, en Buenos Aires "hoy"
    empezaría a las 9 de la mañana.
    """
    ahora = time.time() if ahora is None else ahora
    local = datetime.fromtimestamp(ahora).astimezone()
    medianoche = local.replace(hour=0, minute=0, second=0, microsecond=0)
    return medianoche.timestamp() - max(0, dias - 1) * 86400


def _fila_a_dict(key: str, source: dict, registro: tuple) -> dict:
    """Cada proyecto guarda distinto: acá se emparejan las columnas."""
    if key == "vpn":
        ts, evento, detalle, ok = registro
        return {"fecha": str(ts), "proyecto": source["name"], "tipo": str(evento),
                "detalle": str(detalle or ""), "ok": bool(ok)}
    if key == "hips":
        ts, ip, motivo, aplicado = registro
        return {"fecha": _epoch_a_iso(ts), "proyecto": source["name"],
                "tipo": "bloqueo" if aplicado else "bloqueo (audit)",
                "detalle": f"{ip} - {motivo}" if motivo else str(ip),
                "ok": bool(aplicado)}
    if key == "intel":
        ts, nombre, error, ok = registro
        return {"fecha": _epoch_a_iso(ts), "proyecto": source["name"],
                "tipo": "feed actualizado" if ok else "feed con problemas",
                "detalle": f"{nombre} - {error}" if error else str(nombre),
                "ok": bool(ok)}
    ts, objetivo, motivo, _bloqueado = registro
    return {"fecha": str(ts), "proyecto": source["name"], "tipo": "bloqueo",
            "detalle": f"{objetivo} - {motivo}" if motivo else str(objetivo),
            "ok": False}


# Cómo se filtra por fecha en cada base. El HIPS y Secure-Intel guardan epoch
# (un número) y los demás ISO-8601 (texto): comparar sin distinguirlos daría
# cero filas siempre, en silencio.
_COLUMNA_FECHA = {
    "proxy": ("timestamp", "iso"), "dns": ("timestamp", "iso"),
    "vpn": ("timestamp", "iso"), "hips": ("desde", "epoch"),
    "intel": ("ultima", "epoch"),
}


def recolectar(projects: dict, dias: int, ahora: float | None = None) -> list[dict]:
    """Los eventos del rango, de todos los proyectos, más nuevo primero."""
    corte = _desde(dias, ahora)
    filas = []
    for key, source in _SOURCES.items():
        project = projects.get(key)
        if project is None or not project.found:
            continue
        db_file = project.db_path(source["db"])
        if db_file is None or not Path(db_file).exists():
            continue
        columna, formato = _COLUMNA_FECHA.get(key, ("timestamp", "iso"))
        valor = corte if formato == "epoch" else (
            datetime.fromtimestamp(corte, timezone.utc).isoformat())
        # La consulta del proyecto ya trae el ORDER BY y el LIMIT; se le mete
        # el filtro de fecha antes del ORDER para no traer todo y descartar.
        sql = source["query"]
        if " ORDER BY " in sql:
            cabeza, cola = sql.split(" ORDER BY ", 1)
            union = " AND " if " WHERE " in cabeza else " WHERE "
            sql = f"{cabeza}{union}{columna} >= ? ORDER BY {cola}"
        try:
            con = sqlite3.connect(f"file:{db_file}?mode=ro", uri=True, timeout=2.0)
            registros = con.execute(sql, (valor, MAXIMO_POR_PROYECTO)).fetchall()
            con.close()
        except sqlite3.Error:
            # Una base rota no puede impedir exportar las otras cuatro.
            continue
        for registro in registros:
            filas.append(_fila_a_dict(key, source, registro))
    filas.sort(key=lambda f: f["fecha"], reverse=True)
    return filas


def _legible(iso: str) -> str:
    """La fecha como la lee una persona, en hora local."""
    try:
        momento = datetime.fromisoformat(str(iso))
    except (TypeError, ValueError):
        return ""
    if momento.tzinfo is None:
        momento = momento.replace(tzinfo=timezone.utc)
    return momento.astimezone().strftime("%d/%m/%Y %H:%M:%S")


def con_fecha_legible(filas: list[dict]) -> list[dict]:
    """Agrega `fecha_local` ADEMÁS de la cruda, no en lugar de ella.

    La cruda (ISO en UTC) es la que se guardó y la que sirve para ordenar o
    procesar en otra herramienta; no se toca. Pero abrir un CSV y encontrarse
    con `2026-08-09T04:16:49.143628+00:00` en la primera columna no le sirve
    a nadie. Es el mismo criterio que ya usan las exportaciones de SecureHIPS.
    """
    salida = []
    for fila in filas:
        copia = dict(fila)
        copia["fecha_local"] = _legible(fila.get("fecha", ""))
        salida.append(copia)
    return salida


def resumir(filas: list[dict]) -> dict:
    """Los totales, para que el archivo se pueda leer sin contar a mano."""
    por_proyecto: dict = {}
    por_tipo: dict = {}
    for fila in filas:
        por_proyecto[fila["proyecto"]] = por_proyecto.get(fila["proyecto"], 0) + 1
        por_tipo[fila["tipo"]] = por_tipo.get(fila["tipo"], 0) + 1
    return {"total": len(filas), "por_proyecto": por_proyecto, "por_tipo": por_tipo}


def a_json(filas: list[dict], dias: int, ahora: float | None = None) -> bytes:
    ahora = time.time() if ahora is None else ahora
    cuerpo = {
        "generado": datetime.fromtimestamp(ahora, timezone.utc).isoformat(),
        "rango_dias": dias,
        "desde": datetime.fromtimestamp(_desde(dias, ahora), timezone.utc).isoformat(),
        "resumen": resumir(filas),
        "eventos": con_fecha_legible(filas),
    }
    return json.dumps(cuerpo, ensure_ascii=False, indent=2).encode("utf-8")


def a_csv(filas: list[dict]) -> bytes:
    salida = io.StringIO()
    filas = con_fecha_legible(filas)
    columnas = ["fecha_local", "proyecto", "tipo", "detalle", "ok", "fecha"]
    escritor = csv.DictWriter(salida, fieldnames=columnas, extrasaction="ignore")
    escritor.writeheader()
    # CSV no es solo texto cuando se abre en Excel/LibreOffice: una celda que
    # empieza con =, +, - o @ puede interpretarse como fórmula. `detalle`
    # contiene datos que vienen de otras bases (dominios, nombres de feeds,
    # errores...), así que se neutraliza SOLO en CSV. El JSON conserva el
    # valor crudo para procesamiento automático.
    peligrosos = ("=", "+", "-", "@", "\t", "\r")
    seguras = []
    for fila in filas:
        copia = dict(fila)
        for clave in columnas:
            valor = copia.get(clave)
            if isinstance(valor, str) and valor.startswith(peligrosos):
                copia[clave] = "'" + valor
        seguras.append(copia)
    escritor.writerows(seguras)
    # utf-8-sig: sin el BOM, Excel en Windows abre el CSV en la codificación
    # del sistema y los acentos salen rotos. Es el mismo detalle que ya tienen
    # las exportaciones de SecureHIPS.
    return salida.getvalue().encode("utf-8-sig")


def nombre_de_archivo(dias: int, formato: str, ahora: float | None = None) -> str:
    ahora = time.time() if ahora is None else ahora
    fecha = datetime.fromtimestamp(ahora).strftime("%Y-%m-%d")
    return f"securecenter-{fecha}-{dias}d.{formato}"
