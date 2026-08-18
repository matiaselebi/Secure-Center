"""Historial de CPU, memoria y disco, y los gráficos que lo muestran.

POR QUÉ GUARDAR HISTORIAL SI YA SE VE EN VIVO

Porque el número de ahora no contesta la pregunta que uno tiene. "La memoria
está al 70%" no dice nada solo; "está al 70% y hace una semana estaba al 40%"
dice que algo tiene una fuga. Un panel en vivo muestra el estado; una serie
muestra la tendencia, y las fugas de memoria y los discos que se llenan son
problemas de tendencia.

EL GRÁFICO ES UN SVG HECHO A MANO, SIN LIBRERÍAS

El panel tiene que funcionar sin internet: es una herramienta de seguridad y
puede estar corriendo justo cuando la red no anda. Traer Chart.js de un CDN
haría que los gráficos desaparecieran exactamente en el momento en que más se
los necesita. Un `<svg>` con un `<polyline>` es media pantalla de código y no
depende de nada.

CUÁNTO SE GUARDA

Una muestra por minuto y siete días. Son unas diez mil filas, unos pocos
cientos de kilobytes. Guardar cada cinco segundos daría doce veces más datos
para dibujar exactamente la misma línea.
"""

import sqlite3
import threading
import time
from datetime import datetime

from . import sistema

SEGUNDOS_ENTRE_MUESTRAS = 60
DIAS_QUE_SE_GUARDAN = 7

RANGOS = ((1, "última hora", 3600), (24, "último día", 86400),
          (168, "última semana", 604800))


class Historial:
    """Las muestras, en la misma base que el registro de eventos."""

    def __init__(self, con: sqlite3.Connection):
        self._con = con
        self._lock = threading.RLock()
        with self._lock:
            self._con.execute("""
                CREATE TABLE IF NOT EXISTS metricas (
                    ts    REAL PRIMARY KEY,
                    cpu   REAL,
                    ram   REAL,
                    disco REAL
                )
            """)
            self._con.commit()

    def guardar(self, datos: dict, ahora: float | None = None) -> bool:
        """Una muestra. False si no había nada medible que guardar."""
        ahora = time.time() if ahora is None else ahora
        if not datos.get("disponible"):
            # Sin psutil no hay CPU ni memoria. Guardar filas con nulos
            # ensuciaría el gráfico con huecos que parecen caídas.
            return False
        with self._lock:
            self._con.execute(
                "INSERT OR REPLACE INTO metricas VALUES (?,?,?,?)",
                (ahora, datos.get("cpu_pct"), datos.get("ram_pct"),
                 datos.get("disco_pct")))
            self._con.commit()
        return True

    def podar(self, dias: int = DIAS_QUE_SE_GUARDAN, ahora: float | None = None) -> int:
        ahora = time.time() if ahora is None else ahora
        with self._lock:
            cur = self._con.execute("DELETE FROM metricas WHERE ts < ?",
                                    (ahora - dias * 86400,))
            self._con.commit()
            return cur.rowcount

    def serie(self, horas: float, ahora: float | None = None) -> list[tuple]:
        ahora = time.time() if ahora is None else ahora
        with self._lock:
            return self._con.execute(
                "SELECT ts, cpu, ram, disco FROM metricas WHERE ts >= ? ORDER BY ts",
                (ahora - horas * 3600,)).fetchall()


def _puntos(valores: list[float], ancho: int, alto: int) -> str:
    """Los valores (0 a 100) como coordenadas de un polyline."""
    if not valores:
        return ""
    if len(valores) == 1:
        return f"0,{alto - valores[0] * alto / 100:.1f} {ancho},{alto - valores[0] * alto / 100:.1f}"
    paso = ancho / (len(valores) - 1)
    return " ".join(
        f"{i * paso:.1f},{alto - max(0, min(100, v or 0)) * alto / 100:.1f}"
        for i, v in enumerate(valores)
    )


def grafico(titulo: str, valores: list[float], color: str,
            ancho: int = 320, alto: int = 90) -> str:
    """Un SVG con la serie, el máximo y el último valor.

    Se dibuja el área además de la línea porque una línea sola sobre fondo
    oscuro se pierde, y porque el área deja ver de un vistazo cuánto tiempo
    estuvo alto y no solo cuán alto llegó.
    """
    if not valores:
        return (f"<div class='grafico'><div class='grafico-cab'>{titulo}</div>"
                f"<p class='subtitle'>todavía no hay muestras</p></div>")
    linea = _puntos(valores, ancho, alto)
    area = f"0,{alto} {linea} {ancho},{alto}"
    ultimo = valores[-1] or 0
    maximo = max(v or 0 for v in valores)
    promedio = sum(v or 0 for v in valores) / len(valores)
    return (
        f"<div class='grafico'>"
        f"<div class='grafico-cab'><span>{titulo}</span>"
        f"<span style='color:{color}'>{ultimo:.0f}%</span></div>"
        f"<svg viewBox='0 0 {ancho} {alto}' preserveAspectRatio='none' "
        f"class='svg-serie' role='img' aria-label='{titulo}: {ultimo:.0f}%'>"
        f"<polygon points='{area}' fill='{color}' opacity='0.15'/>"
        f"<polyline points='{linea}' fill='none' stroke='{color}' "
        f"stroke-width='1.5' vector-effect='non-scaling-stroke'/></svg>"
        f"<div class='grafico-pie'>máximo {maximo:.0f}% &middot; "
        f"promedio {promedio:.0f}% &middot; {len(valores)} muestras</div></div>"
    )


def bloque(historial: "Historial", horas: float, ahora: float | None = None) -> str:
    """Los tres gráficos de un rango."""
    filas = historial.serie(horas, ahora)
    if not filas:
        return ("<p class='subtitle'>Todavía no hay muestras en este rango. "
                "Se toma una por minuto mientras SecureCenter está prendido, "
                "así que dejalo corriendo un rato y volvé.</p>")
    series = (
        ("CPU", [f[1] for f in filas], "#8fb8e8"),
        ("Memoria", [f[2] for f in filas], "#c39ae0"),
        ("Disco", [f[3] for f in filas], sistema.color_de_disco(filas[-1][3])),
    )
    desde = datetime.fromtimestamp(filas[0][0]).strftime("%d/%m %H:%M")
    hasta = datetime.fromtimestamp(filas[-1][0]).strftime("%d/%m %H:%M")
    graficos = "".join(grafico(t, v, c) for t, v, c in series)
    return (f"<div class='graficos'>{graficos}</div>"
            f"<p class='subtitle'>de {desde} a {hasta}</p>")
