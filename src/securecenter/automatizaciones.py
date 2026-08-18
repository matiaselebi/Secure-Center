"""Reglas del tipo "si pasa esto, hacé esto otro".

POR QUÉ DISPARADORES Y ACCIONES FIJOS, Y NO REGLAS LIBRES

Porque la alternativa es inventar un lenguaje de scripting a medias. Empieza
con "si el CPU supera X" y termina con condiciones anidadas, variables y una
sintaxis propia que nadie más entiende, mal documentada y sin depurador. Y
sobre todo: un panel que ejecuta expresiones que alguien escribe en un campo
de texto es un panel que ejecuta código, con todo lo que eso implica en una
herramienta que corre como administrador.

Con listas cerradas, la regla se arma eligiendo de dos menús. No se puede
escribir algo inválido, no hay nada que parsear, y lo que puede pasar está
acotado a lo que dice este archivo.

EL PELIGRO REAL: EL BUCLE DE REINICIOS

"Si un servicio no responde, reinicialo" es la regla más obvia y la más
peligrosa. Si el servicio no puede arrancar (falta el venv, el puerto está
ocupado, el config está roto), la regla lo reinicia cada minuto para siempre.
Eso llena el log, gasta CPU y esconde el problema de fondo detrás de un
reinicio permanente.

Por eso hay tres frenos, y ninguno es opcional:

- **Espera entre disparos** de la misma regla (10 minutos por defecto).
- **Tope por hora**: pase lo que pase, una regla no corre más de 3 veces.
- **Se apaga sola**: después de 3 disparos seguidos que no arreglaron nada,
  la regla queda desactivada y se avisa. Una automatización que no funciona
  tiene que dejar de intentar y pedir ayuda, no insistir para siempre.

TODO VIENE APAGADO

`habilitado: false` por defecto en cada regla. Una herramienta que reinicia
servicios sola es algo que se prende a propósito, después de mirar un rato qué
hubiera hecho.
"""

import time

from .alertas import ALTA
from .diagnostico import MAL

# ------------------------------------------------------------- disparadores
#
# Cada uno recibe el contexto (estado, alertas, diagnóstico) y devuelve la
# lista de claves de proyecto afectadas, o [] si no se cumple. Devolver la
# clave y no un booleano es lo que permite que la acción sepa a QUIÉN
# reiniciar.

def _servicio_no_responde(ctx) -> list[str]:
    from .health import PARCIAL
    return [k for k, v in ctx["health"].items() if v == PARCIAL]


def _alerta_grave(ctx) -> list[str]:
    return ["*"] if any(a["gravedad"] == ALTA for a in ctx["alertas"]) else []


def _diagnostico_bajo(ctx) -> list[str]:
    puntaje = ctx.get("puntaje")
    return ["*"] if puntaje is not None and puntaje < 70 else []


def _algo_roto(ctx) -> list[str]:
    return ["*"] if any(r["estado"] == MAL for r in ctx.get("revisiones") or ()) else []


def _disco_lleno(ctx) -> list[str]:
    pct = (ctx.get("maquina") or {}).get("disco_pct")
    return ["*"] if pct is not None and pct >= 90 else []


DISPARADORES = {
    "servicio_no_responde": (
        "un servicio no responde",
        "el proceso está arriba pero no contesta: es peor que apagado, porque "
        "el panel diría que está protegiendo", _servicio_no_responde),
    "alerta_grave": (
        "aparece una alerta grave",
        "cualquier alerta de gravedad alta que no estuviera antes", _alerta_grave),
    "diagnostico_bajo": (
        "el diagnóstico baja de 70",
        "se toma del último diagnóstico que hayas corrido", _diagnostico_bajo),
    "algo_roto": (
        "el diagnóstico encuentra algo roto",
        "al menos una revisión en estado «mal»", _algo_roto),
    "disco_lleno": (
        "el disco pasa el 90%",
        "las bases de los proyectos crecen solas", _disco_lleno),
}

# ------------------------------------------------------------------ acciones

ACCIONES = {
    "reiniciar": (
        "reiniciar ese servicio",
        "solo tiene sentido con el disparador de «un servicio no responde»: "
        "los demás no señalan a ningún proyecto en particular"),
    "avisar": (
        "anotarlo en el registro de eventos",
        "queda en la línea de tiempo de SecureCenter, con la regla que lo hizo"),
    "backup": (
        "crear una copia de seguridad",
        "la configuración de los cinco, sin los .env"),
}


class Regla:
    def __init__(self, disparador: str, accion: str, habilitado: bool = False,
                 espera_minutos: int = 10, maximo_por_hora: int = 3):
        self.disparador = disparador
        self.accion = accion
        self.habilitado = bool(habilitado)
        self.espera = max(60, int(espera_minutos) * 60)
        self.maximo_por_hora = max(1, int(maximo_por_hora))
        self.ultimo_disparo = 0.0
        self.disparos = []          # marcas de tiempo de la última hora
        self.fallas_seguidas = 0
        self.apagada_por_fallas = False

    @property
    def clave(self) -> str:
        return f"{self.disparador}->{self.accion}"

    def titulo(self) -> str:
        d = DISPARADORES.get(self.disparador, (self.disparador, "", None))[0]
        a = ACCIONES.get(self.accion, (self.accion, ""))[0]
        return f"Si {d}, {a}"

    def puede_disparar(self, ahora: float) -> tuple[bool, str]:
        if not self.habilitado:
            return False, "desactivada"
        if self.apagada_por_fallas:
            return False, ("se apagó sola: tres intentos seguidos no "
                           "arreglaron nada. Revisá el problema a mano")
        if ahora - self.ultimo_disparo < self.espera:
            faltan = int((self.espera - (ahora - self.ultimo_disparo)) / 60)
            return False, f"esperando {faltan} min desde el último disparo"
        self.disparos = [d for d in self.disparos if ahora - d < 3600]
        if len(self.disparos) >= self.maximo_por_hora:
            return False, f"ya corrió {self.maximo_por_hora} veces esta hora"
        return True, ""

    def registrar_disparo(self, ahora: float, sirvio: bool) -> None:
        self.ultimo_disparo = ahora
        self.disparos.append(ahora)
        if sirvio:
            self.fallas_seguidas = 0
        else:
            self.fallas_seguidas += 1
            if self.fallas_seguidas >= 3:
                # Una automatización que no funciona tiene que dejar de
                # intentar y pedir ayuda, no insistir para siempre.
                self.apagada_por_fallas = True


def reglas_por_defecto() -> list[Regla]:
    """Las tres que tienen sentido de entrada. Todas apagadas."""
    return [
        Regla("servicio_no_responde", "reiniciar"),
        Regla("alerta_grave", "avisar"),
        Regla("disco_lleno", "avisar"),
    ]


class Motor:
    """Evalúa las reglas y ejecuta lo que corresponda. Nunca lanza."""

    def __init__(self, reglas=None, ejecutor=None):
        self.reglas = list(reglas) if reglas is not None else reglas_por_defecto()
        # `ejecutor(accion, objetivo) -> (sirvió, detalle)`. Se inyecta para
        # que los tests no reinicien nada de verdad, y para que este módulo no
        # dependa del orquestador.
        self.ejecutor = ejecutor
        self.historial: list[dict] = []

    def por_clave(self, clave: str):
        return next((r for r in self.reglas if r.clave == clave), None)

    def evaluar(self, ctx: dict, ahora: float | None = None) -> list[dict]:
        """Una vuelta. Devuelve lo que hizo (o lo que decidió no hacer)."""
        ahora = time.time() if ahora is None else ahora
        hechos = []
        for regla in self.reglas:
            # Una regla apagada ni se evalúa. Antes devolvía "se cumplió pero
            # no corrió: desactivada", y eso llenaba la pantalla de líneas
            # sobre reglas que el usuario apagó justamente para no verlas.
            if not regla.habilitado:
                continue
            entrada = DISPARADORES.get(regla.disparador)
            if entrada is None:
                continue
            try:
                objetivos = entrada[2](ctx)
            except Exception as exc:  # noqa: BLE001
                # Un disparador que explota no puede frenar a los demás.
                hechos.append({"regla": regla.clave, "corrio": False,
                               "detalle": f"el disparador falló: {exc}"})
                continue
            if not objetivos:
                continue
            puede, motivo = regla.puede_disparar(ahora)
            if not puede:
                hechos.append({"regla": regla.clave, "corrio": False,
                               "detalle": f"se cumplió pero no corrió: {motivo}"})
                continue
            objetivo = objetivos[0]
            if self.ejecutor is None:
                hechos.append({"regla": regla.clave, "corrio": False,
                               "detalle": "sin ejecutor conectado"})
                continue
            try:
                sirvio, detalle = self.ejecutor(regla.accion, objetivo)
            except Exception as exc:  # noqa: BLE001
                sirvio, detalle = False, f"la acción falló: {exc}"
            regla.registrar_disparo(ahora, sirvio)
            hecho = {"regla": regla.clave, "corrio": True, "sirvio": sirvio,
                     "objetivo": objetivo, "detalle": detalle, "cuando": ahora}
            hechos.append(hecho)
            self.historial.insert(0, hecho)
            del self.historial[50:]
        return hechos
