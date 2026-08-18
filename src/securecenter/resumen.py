"""Los números de arriba de todo: qué pasó hoy, sumando las cinco bases.

POR QUÉ ESTOS NÚMEROS Y NO OTROS

Cada proyecto ya muestra sus propias estadísticas, con mucho más detalle del
que va a haber acá. Repetirlas no agrega nada. Lo único que SecureCenter puede
decir y ninguno de los cinco puede es **cuánto pasó en total y en qué capa**,
que es la pregunta con la que uno abre el panel a la mañana.

Por eso son pocos y son de hoy. "Bloqueos totales desde que instalaste" es un
número que solo sube y no significa nada; "hoy" se puede comparar con ayer.

CÓMO SE LEE: EN SOLO LECTURA Y SIN QUEJARSE

Con `mode=ro`, igual que hace SecureHIPS con las bases de sus hermanos. Y si
una base no está, está corrupta o tiene un esquema viejo, ese contador queda
en None y el panel muestra un guion. Que falte un proyecto no puede dejar la
pantalla de inicio en blanco.

EL DÍA ES EL DÍA LOCAL, NO EL UTC

Las bases guardan UTC (o epoch, en el caso del HIPS y de Secure-Intel). Si el
corte se hiciera en el mediodía UTC, en Buenos Aires "hoy" empezaría a las 9
de la mañana y los números de la madrugada aparecerían como del día anterior.
"""

import sqlite3
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

# Cada contador: de qué proyecto, en qué base, qué consulta, y cómo se llama
# en la pantalla. La columna de tiempo se pasa aparte porque no todas se
# llaman igual ni guardan lo mismo.
CONTADORES = (
    {
        "clave": "dns", "titulo": "Bloqueos DNS", "db": "data/dns_logs.db",
        "sql": "SELECT COUNT(*) FROM queries WHERE blocked = 1 AND timestamp >= ?",
        "formato": "iso",
        "ayuda": "dominios que no se resolvieron porque estaban en una lista",
    },
    {
        "clave": "proxy", "titulo": "Conexiones bloqueadas", "db": "data/proxy_logs.db",
        "sql": "SELECT COUNT(*) FROM requests WHERE blocked = 1 AND timestamp >= ?",
        "formato": "iso",
        "ayuda": "conexiones salientes cortadas",
    },
    {
        "clave": "hips", "titulo": "Intentos de entrada", "db": "data/hips_logs.db",
        "sql": "SELECT COUNT(*) FROM intentos WHERE timestamp >= ?",
        "formato": "epoch",
        "ayuda": "intentos fallidos de login contra esta máquina",
    },
    {
        "clave": "hips", "titulo": "IPs bloqueadas", "db": "data/hips_logs.db",
        "sql": "SELECT COUNT(*) FROM bans WHERE hasta > ?",
        "formato": "ahora",
        "ayuda": "bloqueos puestos en el firewall ahora mismo",
    },
    {
        "clave": "intel", "titulo": "Indicadores de Intel", "db": "data/intel.db",
        "sql": "SELECT COUNT(*) FROM indicadores",
        "formato": "sin_fecha",
        "ayuda": "dominios, IPs y rangos conocidos entre todos los feeds",
    },
)


def inicio_del_dia(ahora: float | None = None) -> datetime:
    """Medianoche de hoy en la zona horaria de la máquina, como UTC."""
    ahora = time.time() if ahora is None else ahora
    local = datetime.fromtimestamp(ahora).astimezone()
    medianoche = local.replace(hour=0, minute=0, second=0, microsecond=0)
    return medianoche.astimezone(timezone.utc)


def _valor_de_corte(formato: str, ahora: float | None = None) -> float | str:
    ahora = time.time() if ahora is None else ahora
    if formato == "ahora":
        return ahora
    desde = inicio_del_dia(ahora)
    if formato == "epoch":
        return desde.timestamp()
    return desde.isoformat()


def _contar(db_file: Path, sql: str, parametro) -> int | None:
    """Una consulta, en solo lectura, sin poder romper nada.

    Devuelve None ante cualquier problema (no existe, esquema viejo, base a
    medio escribir). El panel muestra un guion, que es honesto: no sabemos.
    Poner 0 sería peor, porque 0 parece un dato.
    """
    if db_file is None or not Path(db_file).exists():
        return None
    try:
        con = sqlite3.connect(f"file:{db_file}?mode=ro", uri=True, timeout=1.0)
    except sqlite3.Error:
        return None
    try:
        parametros = () if parametro is None else (parametro,)
        fila = con.execute(sql, parametros).fetchone()
        return int(fila[0]) if fila else None
    except (sqlite3.Error, TypeError, ValueError):
        return None
    finally:
        con.close()


def construir(projects: dict, ahora: float | None = None) -> list[dict]:
    """Los contadores listos para pintar. Nunca lanza."""
    ahora = time.time() if ahora is None else ahora
    salida = []
    for spec in CONTADORES:
        project = projects.get(spec["clave"])
        db_file = (project.db_path(spec["db"])
                   if project is not None and project.found else None)
        parametro = (None if spec["formato"] == "sin_fecha"
                     else _valor_de_corte(spec["formato"], ahora))
        salida.append({
            "titulo": spec["titulo"],
            "ayuda": spec["ayuda"],
            "valor": _contar(db_file, spec["sql"], parametro),
            "de_hoy": spec["formato"] in ("iso", "epoch"),
        })
    return salida


def total_de_hoy(contadores: list[dict]) -> int | None:
    """La suma de lo que pasó hoy, para el número grande.

    Solo suma los que son de hoy: mezclar "45 bloqueos hoy" con "48.000
    indicadores en los feeds" daría un número enorme que no significa nada.
    """
    valores = [c["valor"] for c in contadores if c["de_hoy"] and c["valor"] is not None]
    return sum(valores) if valores else None


def ayer(projects: dict, ahora: float | None = None) -> int | None:
    """Lo mismo pero de ayer, para poder comparar.

    Un número suelto no dice nada. "126, ayer 40" sí.
    """
    ahora = time.time() if ahora is None else ahora
    arranque_hoy = inicio_del_dia(ahora)
    arranque_ayer = arranque_hoy - timedelta(days=1)
    total = 0
    hubo = False
    for spec in CONTADORES:
        if spec["formato"] not in ("iso", "epoch"):
            continue
        project = projects.get(spec["clave"])
        if project is None or not project.found:
            continue
        db_file = project.db_path(spec["db"])
        columna = "timestamp"
        sql = spec["sql"].replace(f"{columna} >= ?", f"{columna} >= ? AND {columna} < ?")
        if spec["formato"] == "epoch":
            desde, hasta = arranque_ayer.timestamp(), arranque_hoy.timestamp()
        else:
            desde, hasta = arranque_ayer.isoformat(), arranque_hoy.isoformat()
        valor = _contar_dos(db_file, sql, desde, hasta)
        if valor is not None:
            total += valor
            hubo = True
    return total if hubo else None


def _contar_dos(db_file, sql: str, uno, dos) -> int | None:
    if db_file is None or not Path(db_file).exists():
        return None
    try:
        con = sqlite3.connect(f"file:{db_file}?mode=ro", uri=True, timeout=1.0)
    except sqlite3.Error:
        return None
    try:
        fila = con.execute(sql, (uno, dos)).fetchone()
        return int(fila[0]) if fila else None
    except (sqlite3.Error, TypeError, ValueError):
        return None
    finally:
        con.close()
