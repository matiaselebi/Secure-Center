"""El modelo de evento común: una sola forma para todo lo que entra.

POR QUÉ ESTA ES LA PIEZA QUE HAY QUE PENSAR BIEN

Es el enchufe. Hoy hay cinco bases con cinco esquemas distintos, y mañana van
a entrar Nmap, osquery y Suricata. Si cada fuente trae su propia forma, el
correlacionador termina lleno de `if fuente == "dns"` y agregar una séptima
fuente obliga a tocarlo entero. Con un modelo común, agregar una fuente es
escribir un adaptador de treinta líneas y no tocar nada más.

Por eso esta fase va antes que Scanner y antes que Agent: si se hiciera al
revés, cada integración inventaría su formato pensando en sí misma y después
habría que rehacerlas todas.

LAS CUATRO DECISIONES DEL MODELO

**El tiempo se guarda como número, siempre.** Las bases mezclan ISO-8601 en
texto (proxy, DNS, VPN) con epoch en float (HIPS, Intel). Ordenar eso como
texto pone todos los eventos del HIPS al final para siempre, porque "1785..."
ordena antes que "2026-...". Ya pasó una vez en la línea de tiempo. Acá se
normaliza a epoch en la puerta de entrada y no se discute más.

**Origen y destino son campos, no texto libre.** La diferencia entre
`detalle: "203.0.113.7 - fuerza bruta"` y `origen: "203.0.113.7"` es que lo
segundo se puede cruzar con otra fuente y lo primero no. Toda la correlación
depende de esto.

**Un evento puede tener MÁS DE UN indicador, y esto costó un bug.** La primera
versión tenía solo `origen` y `destino`, así que el adaptador del proxy tenía
que elegir entre guardar el dominio o la IP resuelta. Guardaba la IP y metía
el dominio en `datos`, que no se cruza con nada. Resultado: SecureDNS creaba
la entidad `malo.com`, SecureProxy creaba `203.0.113.9`, y la regla que une
las dos capas nunca disparaba, justo en el caso para el que fue escrita. Por
eso ahora el dominio es un campo propio y entra en `indicadores`.

**La gravedad la decide el adaptador, no el correlacionador.** Quien sabe si
un evento es grave es el que conoce la herramienta: un bloqueo del HIPS pesa
distinto que una consulta bloqueada del DNS. Meter esa decisión en el
correlacionador sería volver a llenarlo de casos por fuente.

**Nada se inventa.** Si una fuente no da el equipo, el campo queda vacío y no
se rellena con "desconocido" ni con la IP del servidor. Un dato inventado se
propaga a la correlación y termina en un incidente que dice algo falso.
"""

import time
from dataclasses import dataclass, field
from datetime import datetime, timezone

# Las tres gravedades, iguales a las de las alertas. Tres y no cinco, por el
# mismo motivo: con cinco nadie distingue "media" de "moderada".
ALTA, MEDIA, BAJA = "alta", "media", "baja"
ORDEN_GRAVEDAD = {ALTA: 0, MEDIA: 1, BAJA: 2}

# Qué clase de cosa pasó. Es una lista cerrada a propósito: el correlacionador
# arma reglas sobre estos tipos, y si cada adaptador inventara el suyo, las
# reglas dejarían de aplicar sin que nadie se entere.
CONSULTA_BLOQUEADA = "consulta_bloqueada"   # un nombre que no se resolvió
CONEXION_BLOQUEADA = "conexion_bloqueada"   # una conexión saliente cortada
INTENTO_ENTRADA = "intento_entrada"         # login fallido contra la máquina
BLOQUEO_APLICADO = "bloqueo_aplicado"       # una regla puesta en el firewall
CAMBIO_ESTADO = "cambio_estado"             # la VPN conectó, un feed actualizó
PROBLEMA = "problema"                       # algo falló y hay que mirarlo
# Una conexión que PASÓ el filtro y sin embargo se repite con regularidad de
# reloj. Es un tipo aparte y no un `conexion_bloqueada` por una diferencia que
# cambia lo que significa: no la agarró ninguna lista. Nadie sabe que ese
# destino es malo, y eso es exactamente lo que lo hace interesante.
RITMO_SOSPECHOSO = "ritmo_sospechoso"
# Suricata vio algo EN EL PAQUETE. Es un tipo aparte porque en modo detección
# no se bloqueó nada: es una opinión sobre tráfico que pasó, no una acción.
ALERTA_RED = "alerta_red"

TIPOS = (CONSULTA_BLOQUEADA, CONEXION_BLOQUEADA, INTENTO_ENTRADA,
         BLOQUEO_APLICADO, CAMBIO_ESTADO, RITMO_SOSPECHOSO, ALERTA_RED,
         PROBLEMA)


def a_epoch(valor) -> float:
    """Cualquier marca de tiempo a segundos desde 1970.

    Acepta epoch (número o texto numérico) e ISO-8601 con o sin zona. Si no se
    puede convertir devuelve 0.0, que deja el evento último en el orden en vez
    de romper la lista entera.
    """
    if valor is None:
        return 0.0
    if isinstance(valor, (int, float)):
        return float(valor)
    texto = str(valor).strip()
    if not texto:
        return 0.0
    try:
        return float(texto)
    except ValueError:
        pass
    try:
        momento = datetime.fromisoformat(texto)
    except ValueError:
        return 0.0
    # Sin zona horaria se asume UTC, que es lo que escriben los proyectos.
    if momento.tzinfo is None:
        momento = momento.replace(tzinfo=timezone.utc)
    return momento.timestamp()


def _limpiar(texto, tope: int = 300) -> str:
    """Texto que viene de una base ajena: acotado y sin sorpresas."""
    if texto is None:
        return ""
    return str(texto).strip()[:tope]


@dataclass
class Evento:
    """Lo que pasó, en la forma que entiende todo el resto."""

    ts: float                      # epoch, siempre número
    fuente: str                    # SecureDNS, SecureProxy, Suricata...
    tipo: str                      # uno de TIPOS
    gravedad: str = MEDIA
    # Quién lo hizo y contra qué. Vacío si la fuente no lo sabe: no se inventa.
    equipo: str = ""               # el host de la LAN, cuando se pueda saber
    origen: str = ""               # IP que inicia (o ataca)
    destino: str = ""              # IP de destino
    # El nombre, cuando la fuente lo conoce ADEMÁS de la IP. Es un campo
    # aparte y no "destino o dominio, lo que haya" porque el proxy sabe los
    # dos y los dos hacen falta: el dominio para cruzar con SecureDNS y la IP
    # para cruzar con SecureHIPS y con Intel.
    dominio: str = ""
    detalle: str = ""              # la frase legible, para mostrar
    ok: bool = True                # si la acción salió bien
    datos: dict = field(default_factory=dict)   # lo propio de cada fuente

    def __post_init__(self):
        self.ts = a_epoch(self.ts)
        self.fuente = _limpiar(self.fuente, 40)
        self.tipo = self.tipo if self.tipo in TIPOS else PROBLEMA
        self.gravedad = self.gravedad if self.gravedad in ORDEN_GRAVEDAD else MEDIA
        self.equipo = _limpiar(self.equipo, 80)
        self.origen = _limpiar(self.origen, 60).lower()
        self.destino = _limpiar(self.destino, 255).lower()
        self.dominio = _limpiar(self.dominio, 255).lower()
        self.detalle = _limpiar(self.detalle)

    @property
    def indicadores(self) -> list[str]:
        """Los valores por los que este evento se puede cruzar con otro.

        Es lo único que la correlación necesita para unir dos eventos de
        fuentes distintas: si comparten un indicador, hablan de lo mismo.
        """
        # Se devuelven SIN repetir y en orden estable: si una fuente pusiera
        # el mismo valor en dos campos, la entidad recibiría el evento dos
        # veces y todos los conteos quedarían inflados.
        vistos, salida = set(), []
        for valor in (self.origen, self.destino, self.dominio):
            if valor and valor not in vistos:
                vistos.add(valor)
                salida.append(valor)
        return salida

    def como_dict(self) -> dict:
        return {
            "ts": self.ts, "fecha": fecha_legible(self.ts), "fuente": self.fuente,
            "tipo": self.tipo, "gravedad": self.gravedad, "equipo": self.equipo,
            "origen": self.origen, "destino": self.destino,
            "dominio": self.dominio,
            "detalle": self.detalle, "ok": self.ok, "datos": dict(self.datos),
        }


def fecha_legible(ts: float) -> str:
    """La fecha en hora local, con el mismo formato que toda la suite."""
    if not ts:
        return "-"
    try:
        return datetime.fromtimestamp(float(ts)).strftime("%d/%m/%Y %H:%M:%S")
    except (TypeError, ValueError, OSError):
        return "-"


def ordenar(eventos: list) -> list:
    """Más nuevo primero, y a igualdad de hora, lo más grave primero."""
    return sorted(eventos, key=lambda e: (-e.ts, ORDEN_GRAVEDAD.get(e.gravedad, 3)))


def en_ventana(eventos: list, desde: float, hasta: float | None = None) -> list:
    """Los eventos de un rango. `hasta` vacío significa hasta ahora."""
    hasta = time.time() if hasta is None else hasta
    return [e for e in eventos if desde <= e.ts <= hasta]
