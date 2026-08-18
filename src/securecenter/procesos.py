"""Qué proceso es cada servicio: PID, RAM, CPU, desde cuándo, y qué versión.

POR QUÉ SE BUSCA POR PUERTO Y NO POR NOMBRE DE PROCESO

Porque los cinco proyectos son `python.exe`. Buscar por nombre daría cinco
procesos idénticos sin forma de saber cuál es cuál, y en una máquina con
cualquier otra cosa hecha en Python, más todavía. El puerto es lo único que
identifica a cada uno sin ambigüedad, y además es el mismo dato que ya usa
`health.py` para decir si está vivo: si el panel dice "corriendo" es porque
alguien escucha ese puerto, así que el PID que buscamos es exactamente el de
ese alguien.

EL CPU NECESITA DOS MEDICIONES

`cpu_percent()` la primera vez que se llama para un proceso devuelve 0.0
siempre, porque no tiene con qué comparar. Por eso los objetos de psutil se
guardan entre llamadas en `_procesos`: la segunda vuelta ya da un número real.
Sin eso, el panel mostraría 0% para todo, para siempre, y sería peor que no
mostrar nada porque parecería un dato.

LA VERSIÓN SALE DEL CÓDIGO, NO DE UN ARCHIVO APARTE

Se lee `__version__` del paquete del proyecto. Un archivo VERSION suelto se
desactualiza el día que alguien toca uno y se olvida del otro; el que está en
el código al menos vive al lado de lo que versiona. Si el proyecto no lo
tiene, se dice "sin versionar" y no se inventa un "1.0".
"""

import re
import threading
import time

from .procutil import listening_pids

try:  # pragma: no cover - depende de si está instalado
    import psutil
except ImportError:  # pragma: no cover
    psutil = None

# Objetos Process cacheados por PID, para que `cpu_percent` tenga contra qué
# comparar. Ver el comentario de arriba.
_procesos: dict[int, object] = {}

SEGUNDOS_DE_CACHE = 2.0
_cache: dict = {}
_cache_hasta: float = 0.0
_cache_lock = threading.RLock()

_VERSION = re.compile(r"""^__version__\s*=\s*["']([^"']+)["']""", re.M)


def disponible() -> bool:
    return psutil is not None


def version_de(project) -> str:
    """La versión declarada por el paquete del proyecto, o «sin versionar»."""
    if project is None or not getattr(project, "found", False):
        return ""
    init = project.folder / "src" / project.spec.package / "__init__.py"
    try:
        texto = init.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return "sin versionar"
    encontrada = _VERSION.search(texto)
    return encontrada.group(1) if encontrada else "sin versionar"


def _limpiar_muertos(vivos: set[int]) -> None:
    """Sin esto, `_procesos` crece para siempre.

    Cada reinicio de un servicio deja un PID viejo adentro, y en una máquina
    que queda prendida semanas eso es una fuga de memoria lenta en la
    herramienta que justamente vino a vigilar la máquina.
    """
    for pid in [p for p in _procesos if p not in vivos]:
        _procesos.pop(pid, None)


def detalle_de_puerto(port: int, ahora: float | None = None) -> dict:
    """PID, RAM, CPU y desde cuándo del proceso que escucha ese puerto.

    Diccionario vacío = no hay nadie escuchando, o no se pudo mirar. Nunca
    lanza: esto se llama para pintar una pantalla, y que falte un dato no
    puede tirar abajo el panel entero.
    """
    if psutil is None or not port:
        return {}
    ahora = time.time() if ahora is None else ahora
    try:
        pids = listening_pids(int(port))
    except Exception:  # noqa: BLE001 - pragma: no cover
        return {}
    if not pids:
        return {}
    # Si hay varios (un proceso padre y su hijo, por ejemplo), el más viejo es
    # el que se quedó con el puerto.
    pid = min(pids)
    try:
        with _cache_lock:
            proceso = _procesos.get(pid)
            if proceso is None or not proceso.is_running():
                proceso = psutil.Process(pid)
                _procesos[pid] = proceso
                # Primera llamada: se descarta, solo sirve para fijar el punto de
                # partida de la medición siguiente.
                proceso.cpu_percent(interval=None)
            with proceso.oneshot():
                memoria = proceso.memory_info().rss
                arranco = proceso.create_time()
                cpu = proceso.cpu_percent(interval=None)
                nombre = proceso.name()
    except Exception:  # noqa: BLE001 - psutil tira de todo (NoSuchProcess, AccessDenied, OSError)
        with _cache_lock:
            _procesos.pop(pid, None)
        return {"pid": pid, "sin_acceso": True}

    from .sistema import en_palabras

    return {
        "pid": pid,
        "nombre": nombre,
        "ram_mb": round(memoria / 1024 ** 2, 1),
        "cpu_pct": round(cpu, 1),
        "arranco": arranco,
        "activo_hace": en_palabras(ahora - arranco),
    }


def snapshot(puertos: dict[str, int], ahora: float | None = None) -> dict[str, dict]:
    """Lo mismo para todos los servicios de una, con caché corta."""
    global _cache, _cache_hasta

    ahora = time.time() if ahora is None else ahora
    with _cache_lock:
        if _cache and ahora < _cache_hasta and set(_cache) == set(puertos):
            return {k: dict(v) for k, v in _cache.items()}

        salida = {clave: detalle_de_puerto(port, ahora) for clave, port in puertos.items()}
        _limpiar_muertos({d["pid"] for d in salida.values() if d.get("pid")})
        _cache = {k: dict(v) for k, v in salida.items()}
        _cache_hasta = ahora + SEGUNDOS_DE_CACHE
        return {k: dict(v) for k, v in salida.items()}


def limpiar_cache() -> None:
    """Para los tests, y para después de reiniciar un servicio.

    Al reiniciar cambia el PID, y mostrar durante dos segundos el consumo del
    proceso anterior es decir algo falso justo cuando el usuario está mirando
    si el reinicio salió bien.
    """
    global _cache, _cache_hasta
    with _cache_lock:
        _cache, _cache_hasta = {}, 0.0
        _procesos.clear()
