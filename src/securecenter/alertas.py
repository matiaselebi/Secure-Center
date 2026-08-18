"""Lo que hay que mirar, separado de lo que simplemente pasó.

POR QUÉ NO ALCANZA CON LA LÍNEA DE TIEMPO

La línea de tiempo contesta "¿qué pasó?". Con cinco proyectos escribiendo,
eso son miles de filas por día, y en esa marea un servicio caído se ve igual
que el bloqueo número cuatrocientos de un dominio de publicidad. Un centro de
alertas contesta otra cosa: "¿qué necesita que yo haga algo?". Son pocas, se
acumulan hasta que las atendés, y por eso tienen estado.

LAS ALERTAS NO SON EVENTOS

Un evento pasó una vez y quedó escrito para siempre. Una alerta es una
**condición que sigue siendo cierta**: "SecureDNS está caído" no es algo que
pasó a las 14:32, es algo que está pasando. Por eso se recalculan en cada
vuelta a partir del estado actual, y lo único que se guarda es lo que vos
hiciste con ellas: si la leíste, si la silenciaste, si la resolviste.

La huella (`fingerprint`) es lo que hace que "SecureDNS caído" sea LA MISMA
alerta cinco minutos después y no una nueva. Sin eso, silenciar no serviría
para nada: volvería a aparecer en la vuelta siguiente.

RESOLVER NO ES LO MISMO QUE SILENCIAR

Silenciar es "ya sé, no me lo muestres más". Resolver es "esto ya no pasa".
La diferencia importa: si silenciás "SecureDNS caído" y mañana se cae de
nuevo después de haber estado bien, tenés que enterarte. Por eso una alerta
silenciada que **deja de cumplirse y vuelve a cumplirse** se despierta sola.
"""

import hashlib
import threading
import time

from .diagnostico import AVISO, MAL, NA, OK
from .health import APAGADO, PARCIAL

# Gravedad. Tres niveles y no cinco: con cinco nadie sabe la diferencia entre
# "media" y "moderada", y terminan usándose dos.
ALTA, MEDIA, BAJA = "alta", "media", "baja"

COLORES = {ALTA: "#ff8a8a", MEDIA: "#e3b341", BAJA: "#7bd88f"}

NUEVA, LEIDA, SILENCIADA, RESUELTA = "nueva", "leida", "silenciada", "resuelta"


def huella(clave: str) -> str:
    """Identidad estable de una alerta, para que no se duplique cada vuelta."""
    return hashlib.sha1(clave.encode("utf-8")).hexdigest()[:16]


def _alerta(clave: str, gravedad: str, titulo: str, detalle: str,
            que_hacer: str = "") -> dict:
    return {
        "huella": huella(clave), "gravedad": gravedad, "titulo": titulo,
        "detalle": detalle, "que_hacer": que_hacer,
    }


def detectar(cfg, projects, health: dict, revisiones: list[dict] | None = None) -> list[dict]:
    """Las condiciones que hoy son ciertas. No mira el historial.

    `revisiones` es lo que devuelve `diagnostico.revisar()`. Se pasa desde
    afuera y no se calcula acá para no repetir las consultas de red: el
    diagnóstico ya las hizo.
    """
    encontradas = []

    for key, estado in sorted(health.items()):
        project = projects.get(key)
        if project is None or not project.found:
            continue
        nombre = project.spec.display_name
        if estado == PARCIAL:
            # Este es el caso grave de verdad: el panel diría "arriba" y no
            # está protegiendo. Peor que apagado, porque apagado se nota.
            encontradas.append(_alerta(
                f"parcial:{key}", ALTA, f"{nombre} no responde",
                "el proceso está arriba pero no contesta como debería",
                "reinicialo desde su tarjeta y mirá la consola"))
        elif estado == APAGADO and project.falta_el_venv():
            encontradas.append(_alerta(
                f"sin-venv:{key}", MEDIA, f"{nombre} no se puede encender",
                "está en el disco pero le falta el entorno virtual",
                f"en {project.folder}: python -m venv venv"))

    for revision in (revisiones or ()):
        if revision["estado"] in {OK, NA}:
            continue
        gravedad = ALTA if revision["estado"] == MAL else MEDIA
        # Los servicios ya los cubrimos arriba con más contexto; acá quedan
        # las revisiones que no son de un proyecto (disco, internet, feeds).
        if revision["nombre"] in {s.spec.display_name for s in projects.values()
                                  if getattr(s, "spec", None)}:
            continue
        if revision["estado"] == AVISO and revision["nombre"] == "Medición de procesos":
            gravedad = BAJA
        encontradas.append(_alerta(
            f"diag:{revision['nombre']}", gravedad, revision["nombre"],
            revision["detalle"], revision.get("arreglo", "")))

    return encontradas


class RegistroDeAlertas:
    """Lo único que se guarda: qué hiciste vos con cada alerta."""

    def __init__(self, con):
        self._con = con
        self._lock = threading.RLock()
        with self._lock:
            self._con.execute("""
                CREATE TABLE IF NOT EXISTS alertas (
                    huella    TEXT PRIMARY KEY,
                    estado    TEXT NOT NULL,
                    titulo    TEXT NOT NULL DEFAULT '',
                    gravedad  TEXT NOT NULL DEFAULT 'media',
                    primera   REAL NOT NULL,
                    ultima    REAL NOT NULL,
                    tocada    REAL NOT NULL DEFAULT 0,
                    -- Si la condición seguía cumpliéndose la última vez que se
                    -- miró. Es lo que permite que una alerta silenciada se
                    -- despierte sola si deja de pasar y vuelve a pasar.
                    vigente   INTEGER NOT NULL DEFAULT 1
                )
            """)
            self._con.commit()

    def sincronizar(self, detectadas: list[dict], ahora: float | None = None) -> list[dict]:
        """Cruza lo que pasa ahora con lo que ya sabías. Devuelve la lista
        lista para mostrar, más nueva primero y por gravedad."""
        ahora = time.time() if ahora is None else ahora
        vivas = {a["huella"]: a for a in detectadas}
        with self._lock:
            guardadas = {
                fila[0]: fila for fila in self._con.execute(
                    "SELECT huella, estado, primera, vigente FROM alertas")
            }

            for h, alerta in vivas.items():
                fila = guardadas.get(h)
                if fila is None:
                    self._con.execute(
                        "INSERT INTO alertas (huella, estado, titulo, gravedad, "
                        "primera, ultima, vigente) VALUES (?,?,?,?,?,?,1)",
                        (h, NUEVA, alerta["titulo"], alerta["gravedad"], ahora, ahora))
                    continue
                estado, primera, vigente = fila[1], fila[2], fila[3]
                if not vigente and estado in (SILENCIADA, RESUELTA):
                    # Dejó de pasar y volvió a pasar: se despierta. Silenciar no
                    # puede significar "no me avises nunca más de esto".
                    estado, primera = NUEVA, ahora
                self._con.execute(
                    "UPDATE alertas SET estado=?, ultima=?, vigente=1, primera=?, "
                    "titulo=?, gravedad=? WHERE huella=?",
                    (estado, ahora, primera, alerta["titulo"], alerta["gravedad"], h))

            # Las que ya no se cumplen: se marcan no vigentes, no se borran.
            if vivas:
                marcas = ",".join("?" * len(vivas))
                self._con.execute(
                    f"UPDATE alertas SET vigente=0 WHERE huella NOT IN ({marcas})",
                    tuple(vivas))
            else:
                self._con.execute("UPDATE alertas SET vigente=0")
            self._con.commit()

            orden = {ALTA: 0, MEDIA: 1, BAJA: 2}
            salida = []
            for h, alerta in vivas.items():
                fila = self._con.execute(
                    "SELECT estado, primera, ultima FROM alertas WHERE huella=?",
                    (h,)).fetchone()
                dato = dict(alerta)
                dato["estado"] = fila[0] if fila else NUEVA
                dato["primera"] = fila[1] if fila else ahora
                dato["ultima"] = fila[2] if fila else ahora
                salida.append(dato)
        salida.sort(key=lambda a: (orden.get(a["gravedad"], 3), -a["primera"]))
        return salida

    def marcar(self, huella_: str, estado: str, ahora: float | None = None) -> bool:
        if estado not in (NUEVA, LEIDA, SILENCIADA, RESUELTA):
            return False
        ahora = time.time() if ahora is None else ahora
        with self._lock:
            cur = self._con.execute(
                "UPDATE alertas SET estado=?, tocada=? WHERE huella=?",
                (estado, ahora, huella_))
            self._con.commit()
            return cur.rowcount > 0

    def sin_atender(self) -> int:
        """Cuántas hay que nadie miró todavía, para el número del encabezado."""
        with self._lock:
            fila = self._con.execute(
                "SELECT COUNT(*) FROM alertas WHERE vigente=1 AND estado=?",
                (NUEVA,)).fetchone()
        return int(fila[0]) if fila else 0
