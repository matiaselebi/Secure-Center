"""Cómo viene la máquina: CPU, memoria, disco, tiempo prendida.

POR QUÉ ESTO ESTÁ EN SECURECENTER Y NO EN CADA PROYECTO

Porque es la única pregunta de esta suite que no es sobre seguridad sino
sobre la máquina, y ninguno de los cinco proyectos tiene por qué contestarla.
SecureCenter sí: es el que ya mira a todos, y es la primera pantalla que
alguien abre.

Y sirve para algo concreto, no es decoración. Cinco procesos de Python
corriendo todo el día se notan, y la pregunta "¿esto me está comiendo la
máquina?" es exactamente la que hace que alguien apague una herramienta de
seguridad. Mejor que la conteste el panel a que la conteste el Administrador
de tareas.

PSUTIL ES OPCIONAL A PROPÓSITO

Si no está instalado, esto devuelve "no sé" y el panel muestra un aviso con
el comando para instalarlo. No se cae, y sobre todo no impide encender ni
apagar nada. Una dependencia nueva no puede convertir al orquestador de la
suite en algo que no arranca.
"""

import platform
import shutil
import threading
import time

try:  # pragma: no cover - depende de si está instalado
    import psutil
except ImportError:  # pragma: no cover
    psutil = None

# Cuánto vale una medición antes de volver a tomarla. El panel se repinta por
# SSE cada pocos segundos y hay hasta doce navegadores conectados: sin caché,
# cada repintado recorrería la tabla de procesos del sistema entera.
SEGUNDOS_DE_CACHE = 2.0

_cache: dict = {}
_cache_hasta: float = 0.0
_cache_lock = threading.Lock()


# Primera llamada de calentamiento. `cpu_percent(interval=None)` devuelve
# 0.0 la primera vez porque no tiene con qué comparar; si no se hace acá, la
# primera pantalla que ve el usuario dice "CPU 0.0%", que parece un dato y no
# lo es. Es el mismo motivo por el que `procesos.py` cachea los objetos.
if psutil is not None:  # pragma: no cover
    try:
        psutil.cpu_percent(interval=None)
    except Exception:  # noqa: BLE001
        pass


def miles(n) -> str:
    """48123 -> «48.123». Con punto, como se escribe en Argentina."""
    try:
        return f"{int(n):,}".replace(",", ".")
    except (TypeError, ValueError):
        return "-"


def disponible() -> bool:
    return psutil is not None


def por_que_no() -> str:
    if psutil is None:
        return ("falta la librería psutil. Instalala con: "
                "venv\\Scripts\\pip install psutil")
    return ""


def color_de_disco(porcentaje: float, libre_gb: float | None = None) -> str:
    """Un mismo criterio para la portada y el gráfico de rendimiento."""
    if porcentaje >= 95 or (libre_gb is not None and libre_gb < 10):
        return "#ff8a8a"
    if porcentaje >= 90:
        return "#e0b341"
    return "#7bd88f"


def _porcentaje_de_disco() -> dict:
    """El disco donde vive SecureCenter, no todos.

    Mostrar cinco discos en la pantalla de inicio es ruido: el que importa es
    el que se llena cuando las bases de datos crecen.
    """
    try:
        uso = shutil.disk_usage(".")
    except OSError:
        return {}
    return {
        "disco_total_gb": round(uso.total / 1024 ** 3, 1),
        "disco_usado_gb": round(uso.used / 1024 ** 3, 1),
        "disco_libre_gb": round(uso.free / 1024 ** 3, 1),
        "disco_pct": round(uso.used * 100 / uso.total, 1) if uso.total else 0.0,
    }


def _temperatura() -> float | None:
    """La del CPU, si el sistema la expone.

    En Windows casi nunca está (hay que hablar con el WMI del fabricante), así
    que esto devuelve None seguido y el panel simplemente no muestra la fila.
    Prometer un dato que no vas a poder dar es peor que no prometerlo.
    """
    if psutil is None or not hasattr(psutil, "sensors_temperatures"):
        return None
    try:
        lecturas = psutil.sensors_temperatures() or {}
    except (AttributeError, OSError, NotImplementedError):
        return None
    for preferida in ("coretemp", "k10temp", "cpu_thermal", "acpitz"):
        for entrada in lecturas.get(preferida, ()):
            if entrada.current:
                return round(float(entrada.current), 1)
    for entradas in lecturas.values():
        for entrada in entradas:
            if entrada.current:
                return round(float(entrada.current), 1)
    return None


def en_palabras(segundos: float) -> str:
    """90000 -> «1 día 1 h». Para que no haya que dividir mentalmente."""
    segundos = int(max(0, segundos))
    dias, resto = divmod(segundos, 86400)
    horas, resto = divmod(resto, 3600)
    minutos = resto // 60
    if dias:
        return f"{dias} día{'s' if dias != 1 else ''} {horas} h"
    if horas:
        return f"{horas} h {minutos} min"
    return f"{minutos} min"


def snapshot(ahora: float | None = None) -> dict:
    """Estado de la máquina. Nunca lanza: si no se puede medir, va vacío."""
    global _cache, _cache_hasta

    ahora = time.time() if ahora is None else ahora
    with _cache_lock:
        if _cache and ahora < _cache_hasta:
            return dict(_cache)

        datos: dict = {
            "disponible": psutil is not None,
            "aviso": por_que_no(),
            "sistema": f"{platform.system()} {platform.release()}".strip(),
        }
        datos.update(_porcentaje_de_disco())

        if psutil is not None:
            try:
                # interval=None: devuelve el porcentaje desde la llamada anterior,
                # sin bloquear. Con interval=1 el panel tardaría un segundo en
                # cada repintado, y con doce clientes SSE eso se nota.
                datos["cpu_pct"] = round(psutil.cpu_percent(interval=None), 1)
                datos["cpu_nucleos"] = psutil.cpu_count(logical=True) or 0
                memoria = psutil.virtual_memory()
                datos["ram_pct"] = round(memoria.percent, 1)
                datos["ram_total_gb"] = round(memoria.total / 1024 ** 3, 1)
                datos["ram_usada_gb"] = round((memoria.total - memoria.available)
                                              / 1024 ** 3, 1)
                datos["encendida_hace"] = en_palabras(ahora - psutil.boot_time())
                temperatura = _temperatura()
                if temperatura is not None:
                    datos["temperatura"] = temperatura
            except (OSError, RuntimeError, ValueError) as exc:  # pragma: no cover
                datos["aviso"] = f"no pude leer el estado de la máquina: {exc}"

        _cache = dict(datos)
        _cache_hasta = ahora + SEGUNDOS_DE_CACHE
        return dict(datos)


def limpiar_cache() -> None:
    """Para los tests, que no pueden esperar a que venza."""
    global _cache, _cache_hasta
    with _cache_lock:
        _cache, _cache_hasta = {}, 0.0
