"""Agrupar los eventos por la cosa de la que hablan, no por quién los escribió.

EL PROBLEMA QUE RESUELVE

La línea de tiempo está ordenada por hora, que es como pasaron las cosas pero
no como uno las investiga. Cuando ves una IP rara, la pregunta no es "¿qué
pasó a las 14:32?", es **"¿qué pasó con esta IP?"**. Contestar eso hoy es
abrir cinco tablas en cinco paneles distintos y cruzar a ojo.

Una entidad es esa cosa: una IP, un dominio o un equipo, con todo lo que se
sabe de ella junto y en orden.

POR QUÉ ES EL PASO PREVIO A LA CORRELACIÓN

Porque correlacionar es preguntar "¿esta entidad aparece en dos fuentes que
juntas significan algo?". Sin agrupar primero, cada regla tendría que recorrer
la lista entera de eventos buscando coincidencias, y con seis fuentes eso se
vuelve ilegible enseguida. Con entidades, una regla es mirar una entidad y
contestar sí o no.

LO QUE UNA ENTIDAD NO HACE

No decide nada. No dice si una IP es mala. Junta y ordena, igual que
Secure-Intel junta feeds sin emitir veredictos. Quién decide es la regla de
correlación, que viene después, y la política de cada herramienta.
"""

import ipaddress

from .evento import BAJA, ORDEN_GRAVEDAD, fecha_legible

IP, DOMINIO, EQUIPO = "ip", "dominio", "equipo"


def clase_de(valor: str) -> str:
    """¿Esto es una IP o un dominio? Se detecta, no se pregunta."""
    valor = (valor or "").strip().lower()
    if not valor:
        return ""
    try:
        ipaddress.ip_address(valor)
        return IP
    except ValueError:
        return DOMINIO if "." in valor else EQUIPO


class Entidad:
    """Una IP, un dominio o un equipo, con todo lo que se sabe de ella."""

    def __init__(self, valor: str, clase: str = ""):
        # `valor` es la clave, siempre en minúsculas. `etiqueta` es cómo se
        # escribió originalmente, para mostrar: un equipo se llama
        # "PC-MATIAS" y así hay que mostrarlo, pero buscarlo escribiendo
        # "pc-matias" tiene que funcionar igual. Antes no funcionaba, y había
        # un test que confirmaba ese comportamiento en vez de marcarlo.
        self.etiqueta = (valor or "").strip()
        self.valor = self.etiqueta.lower()
        self.clase = clase or clase_de(self.valor)
        self.eventos: list = []

    # ------------------------------------------------------------ agregado

    def agregar(self, evento) -> None:
        self.eventos.append(evento)

    # ------------------------------------------------------------ lecturas

    @property
    def fuentes(self) -> set:
        """De cuántas herramientas distintas se supo de esto.

        Es el dato más importante de la entidad. Que una IP aparezca en el DNS
        y en el proxy y en el HIPS es una señal cualitativamente distinta a
        aparecer tres veces en la misma herramienta, y es lo que la primera
        regla de correlación va a mirar.
        """
        return {e.fuente for e in self.eventos}

    @property
    def tipos(self) -> set:
        return {e.tipo for e in self.eventos}

    @property
    def primera(self) -> float:
        return min((e.ts for e in self.eventos), default=0.0)

    @property
    def ultima(self) -> float:
        return max((e.ts for e in self.eventos), default=0.0)

    @property
    def gravedad(self) -> str:
        """La del evento más grave. Una entidad es tan grave como su peor
        evento: promediar la haría parecer inofensiva por tener mucho ruido
        de baja gravedad alrededor de una cosa seria."""
        if not self.eventos:
            return BAJA
        return min((e.gravedad for e in self.eventos),
                   key=lambda g: ORDEN_GRAVEDAD.get(g, 3))

    @property
    def equipos(self) -> set:
        return {e.equipo for e in self.eventos if e.equipo}

    def de_fuente(self, nombre: str) -> list:
        return [e for e in self.eventos if e.fuente == nombre]

    def contexto(self) -> dict:
        """Todo junto, listo para mostrar o para que lo mire una regla."""
        return {
            "valor": self.valor, "etiqueta": self.etiqueta, "clase": self.clase,
            "eventos": len(self.eventos),
            "fuentes": sorted(self.fuentes), "tipos": sorted(self.tipos),
            "gravedad": self.gravedad,
            "primera": self.primera, "ultima": self.ultima,
            "primera_legible": fecha_legible(self.primera),
            "ultima_legible": fecha_legible(self.ultima),
            "equipos": sorted(self.equipos),
        }

    def __repr__(self) -> str:  # pragma: no cover
        return f"<Entidad {self.valor} ({len(self.eventos)} eventos)>"


def agrupar(eventos: list) -> dict:
    """De una lista de eventos a un mapa de entidades.

    Un evento con origen Y destino alimenta a DOS entidades, y eso es lo que
    permite después seguir la cadena: la conexión bloqueada del proxy aparece
    tanto bajo la IP como bajo el dominio, así que la cadena
    dominio -> IP -> bloqueo se puede reconstruir saltando de una a otra.
    """
    entidades: dict = {}
    for evento in eventos:
        for valor in evento.indicadores:
            entidad = entidades.get(valor)
            if entidad is None:
                entidad = Entidad(valor)
                entidades[valor] = entidad
            entidad.agregar(evento)
        # El equipo es una entidad aparte: no es un indicador de red, es el
        # dueño de lo que pasó. Sin esto no se podría preguntar "qué hizo esta
        # máquina" cuando entre el agente.
        if evento.equipo:
            # En minúsculas como todo lo demás. La forma original se conserva
            # en `etiqueta` para mostrarla como corresponde.
            clave = evento.equipo.strip().lower()
            entidad = entidades.get(clave)
            if entidad is None:
                entidad = Entidad(evento.equipo, EQUIPO)
                entidades[clave] = entidad
            entidad.agregar(evento)
    return entidades


def buscar(entidades: dict, texto: str) -> "Entidad | None":
    """Una entidad por su valor exacto, sin importar mayúsculas."""
    return entidades.get((texto or "").strip().lower())


def mas_activas(entidades: dict, limite: int = 20) -> list:
    """Las que más importan primero: por gravedad, después por cuántas
    fuentes distintas las vieron, y recién después por cantidad.

    El orden no es casual. Diez eventos de una sola fuente puede ser una
    tontería repetida; dos eventos de dos fuentes distintas casi nunca lo es.
    """
    return sorted(
        entidades.values(),
        key=lambda e: (ORDEN_GRAVEDAD.get(e.gravedad, 3),
                       -len(e.fuentes), -len(e.eventos), -e.ultima),
    )[:limite]


def en_varias_fuentes(entidades: dict, minimo: int = 2) -> list:
    """Las entidades que vieron dos o más herramientas distintas.

    Es la materia prima de la correlación: exactamente lo que ninguna
    herramienta sola puede contestar sobre sí misma.
    """
    return [e for e in entidades.values() if len(e.fuentes) >= minimo]
