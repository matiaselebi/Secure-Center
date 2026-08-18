"""Vista de Secure-Agent dentro de SecureCenter, sin mezclar fuentes.

Lee la base en modo solo lectura. No importa el paquete de Secure-Agent y no
abre otro puerto: SecureCenter ya es el panel local de la suite.
"""

import html
import sqlite3
import time
from contextlib import closing
from datetime import datetime
from pathlib import Path

import yaml


def _conectar(ruta: Path):
    uri = ruta.resolve().as_uri() + "?mode=ro"
    con = sqlite3.connect(uri, uri=True, timeout=2.0)
    con.row_factory = sqlite3.Row
    return con


def _umbral(config: Path) -> float:
    try:
        datos = yaml.safe_load(config.read_text(encoding="utf-8")) or {}
        return max(1.0, float((datos.get("servidor") or {}).get(
            "minutos_para_callado", 30)))
    except (OSError, TypeError, ValueError, yaml.YAMLError):
        return 30.0


def leer(ruta: Path, ahora: float | None = None,
         minutos_para_callado: float = 30, limite_por_agente: int = 100) -> dict:
    """Resumen de agentes e inventario observado; nunca crea ni modifica DB."""
    ahora = time.time() if ahora is None else ahora
    if not ruta.is_file():
        return {"agentes": [], "inventario": {}, "hallazgos": 0, "error": ""}
    try:
        with closing(_conectar(ruta)) as con:
            tablas = {r[0] for r in con.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'")}
            if not {"envios", "hallazgos"}.issubset(tablas):
                return {"agentes": [], "inventario": {}, "hallazgos": 0,
                        "error": "la base de Secure-Agent no tiene el esquema esperado"}

            filas = con.execute("""
                SELECT e.agente, e.ts_servidor AS ultimo, e.sistema, e.de_donde,
                       s.envios, s.descartados
                FROM envios e
                JOIN (
                    SELECT agente, MAX(id) AS ultimo_id, COUNT(*) AS envios,
                           SUM(descartados) AS descartados
                    FROM envios GROUP BY agente
                ) s ON e.id = s.ultimo_id
                ORDER BY e.ts_servidor ASC
            """).fetchall()
            conteos = {r["agente"]: r["cantidad"] for r in con.execute(
                "SELECT agente, COUNT(*) AS cantidad FROM hallazgos GROUP BY agente")}
            agentes = []
            for fila in filas:
                dato = dict(fila)
                dato["hallazgos"] = conteos.get(dato["agente"], 0)
                dato["callado"] = ahora - float(dato["ultimo"] or 0) > minutos_para_callado * 60
                agentes.append(dato)

            inventario: dict[str, list] = {a["agente"]: [] for a in agentes}
            for fila in con.execute("""
                SELECT agente, tipo, clave, ultima_vez, nombre, ruta, usuario,
                       padre, origen, destino, puerto, detalle
                FROM hallazgos ORDER BY agente, ultima_vez DESC
                LIMIT ?
            """, (5000,)):
                lista = inventario.setdefault(fila["agente"], [])
                if len(lista) < max(1, limite_por_agente):
                    lista.append(dict(fila))
            return {"agentes": agentes, "inventario": inventario,
                    "hallazgos": sum(conteos.values()), "error": ""}
    except (OSError, sqlite3.Error) as exc:
        return {"agentes": [], "inventario": {}, "hallazgos": 0,
                "error": str(exc)}


def _fecha(ts: float) -> str:
    try:
        return datetime.fromtimestamp(float(ts)).astimezone().strftime("%d/%m/%Y %H:%M:%S")
    except (OSError, TypeError, ValueError):
        return "-"


def bloque(project, ahora: float | None = None) -> str:
    """HTML de la pestaña. Sólo contiene datos de Secure-Agent."""
    if project is None or not project.found or project.folder is None:
        return "<p class='warn'>Secure-Agent no está disponible.</p>"
    minutos = _umbral(project.folder / "config" / "config.yaml")
    datos = leer(project.folder / "data" / "agentes.db", ahora, minutos)
    if datos["error"]:
        return ("<p class='warn'>No pude leer Secure-Agent: "
                f"{html.escape(datos['error'])}</p>")
    if not datos["agentes"]:
        return ("<p class='subtitle'>El receptor todavía no recibió telemetría de "
                "ningún equipo.</p>")

    callados = sum(1 for a in datos["agentes"] if a["callado"])
    tarjetas = (
        f"<div class='stats'><div class='card'><div class='value'>{len(datos['agentes'])}</div>"
        "<div class='label'>Equipos conocidos</div></div>"
        f"<div class='card'><div class='value'>{len(datos['agentes']) - callados}</div>"
        "<div class='label'>Reportando</div></div>"
        f"<div class='card'><div class='value'>{callados}</div>"
        "<div class='label'>Callados</div></div>"
        f"<div class='card'><div class='value'>{datos['hallazgos']}</div>"
        "<div class='label'>Elementos observados</div></div></div>")

    equipos = []
    for agente in datos["agentes"]:
        nombre = html.escape(str(agente["agente"]))
        estado = ("<span style='color:#e3b341'>&#9679; callado</span>" if agente["callado"]
                  else "<span style='color:#7bd88f'>&#9679; reportando</span>")
        filas = []
        for item in datos["inventario"].get(agente["agente"], []):
            identidad = item["nombre"] or item["clave"]
            contexto = item["detalle"] or item["destino"] or item["ruta"] or "-"
            filas.append(
                f"<tr><td>{html.escape(str(item['tipo']))}</td>"
                f"<td>{html.escape(str(identidad))}</td>"
                f"<td>{html.escape(str(contexto)[:220])}</td>"
                f"<td class='fecha'>{_fecha(item['ultima_vez'])}</td></tr>")
        tabla = ("<table><tr><th>Tipo</th><th>Qué</th><th>Detalle</th>"
                 f"<th>Última vez visto</th></tr>{''.join(filas)}</table>" if filas else
                 "<p class='subtitle'>Todavía no hay elementos observados.</p>")
        equipos.append(
            f"<details class='project'><summary><b>{nombre}</b> &middot; {estado}"
            f" &middot; último envío {_fecha(agente['ultimo'])}</summary>"
            f"<p class='subtitle'>Sistema: {html.escape(str(agente['sistema'] or '-'))}"
            f" &middot; origen: {html.escape(str(agente['de_donde'] or '-'))}"
            f" &middot; envíos: {agente['envios']}"
            f" &middot; descartados: {agente['descartados'] or 0}</p>{tabla}</details>")

    return ("<p class='subtitle'>Vista aislada de Secure-Agent. El inventario es "
            "histórico: “última vez visto” no significa que siga activo ahora. "
            f"Un equipo se marca callado después de {minutos:g} minutos.</p>"
            + tarjetas + "".join(equipos))
