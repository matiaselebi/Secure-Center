"""Reglas que unen eventos de fuentes distintas, e incidentes que resultan.

QUÉ ES CORRELACIONAR, EN CONCRETO

Cada herramienta ve una parte y ninguna puede contestar sobre sí misma la
pregunta importante. SecureDNS sabe que se pidió un dominio de una lista.
SecureProxy sabe que salió una conexión a una IP. SecureHIPS sabe que esa IP
además probaba contraseñas. Ninguna de las tres sabe que **son la misma
historia**. Eso es lo único que hace este archivo.

POR QUÉ LAS REGLAS SON FIJAS Y NO UN LENGUAJE

Misma decisión que en las automatizaciones. Un campo de texto donde escribir
condiciones termina siendo un lenguaje de scripting a medias, sin documentar y
sin depurador, y encima significa que el panel evalúa lo que alguien escribió.
Acá cada regla es una función con nombre, comentada, que se puede leer y
probar sola.

LA CONFIANZA NO ES UN ADORNO

Cada regla dice cuánta confianza tiene en lo que afirma, y por qué. Es lo que
separa "estas dos cosas pasaron cerca" de "estas dos cosas son el mismo
ataque". Una correlación con confianza baja se muestra igual, pero se muestra
como lo que es: una coincidencia que vale la pena mirar, no una conclusión.

LO QUE NO HACE

No bloquea. Arma incidentes y los muestra. Quien decide qué hacer sigue siendo
cada herramienta con su política, y quien aplica en el firewall sigue siendo
SecureHIPS. Es la misma línea que separa a Secure-Intel de los que lo usan.
"""

import hashlib
import threading
import time

from .evento import (ALERTA_RED, ALTA, BLOQUEO_APLICADO, CONEXION_BLOQUEADA,
                     CONSULTA_BLOQUEADA, INTENTO_ENTRADA, MEDIA,
                     ORDEN_GRAVEDAD, RITMO_SOSPECHOSO, fecha_legible)

# Los tipos que significan "alguna herramienta señaló esto".
#
# Está escrito una sola vez porque lo usan tres reglas distintas. La primera
# versión lo tenía copiado en las tres, y cuando entró Suricata eso significó
# acordarse de tocar tres lugares. Olvidarse de uno no rompe ningún test: solo
# hace que una regla vea menos que las otras, para siempre, sin que nadie se
# entere.
#
# Suricata entra acá aunque en modo detección no bloquee nada, y la palabra
# que lo justifica ya estaba en el texto de las reglas: dicen "señalada", no
# "bloqueada". Que una herramienta reconozca la firma de un troyano en el
# paquete es señalar, y de los más fuertes que hay.
TIPOS_QUE_SENALAN = (CONSULTA_BLOQUEADA, CONEXION_BLOQUEADA, BLOQUEO_APLICADO,
                     ALERTA_RED)

# Cuánto tiempo puede pasar entre dos eventos para que se consideren parte de
# la misma historia. Media hora: un dominio que se resolvió a la mañana y una
# conexión a la tarde probablemente no tengan nada que ver, y unirlos daría
# incidentes inventados.
VENTANA = 1800

NUEVO, VISTO, CERRADO = "nuevo", "visto", "cerrado"

# Cuánto silencio hace falta para que lo que vuelve cuente como un episodio
# nuevo y no como el mismo de antes. Un día: si una IP dejó de aparecer 24
# horas y vuelve, es otra vez.
SILENCIO_PARA_EPISODIO_NUEVO = 86400


class Incidente:
    """Varios eventos que juntos cuentan algo que ninguno cuenta solo."""

    def __init__(self, regla: str, titulo: str, entidad: str, gravedad: str,
                 confianza: int, evidencias: list, que_significa: str = "",
                 episodio: int = 0):
        self.regla = regla
        self.titulo = titulo
        self.entidad = entidad
        self.gravedad = gravedad
        self.confianza = max(0, min(100, int(confianza)))
        self.evidencias = list(evidencias)
        self.que_significa = que_significa
        # Qué "vez" es esta. Ver `RegistroDeIncidentes`: la misma IP atacando
        # en agosto y en octubre son dos incidentes, no uno reabierto.
        self.episodio = int(episodio)
        self.estado = NUEVO

    @property
    def base(self) -> str:
        """La identidad sin el episodio: regla más entidad."""
        return hashlib.sha1(
            f"{self.regla}|{self.entidad}".encode("utf-8")).hexdigest()[:16]

    @property
    def huella(self) -> str:
        """Identidad de ESTE episodio del incidente.

        Se arma con la regla y la entidad, NO con los eventos: si entrara un
        evento más de la misma historia, sería un incidente nuevo y perderías
        el estado que ya le habías puesto.

        Pero lleva además el número de episodio, y eso arregla un problema
        real: sin él, la misma IP atacando en agosto y volviendo en octubre
        daba la misma huella, así que el ataque nuevo aparecía con el estado
        "cerrado" que le habías puesto al viejo. Un ataque nuevo que llega ya
        marcado como resuelto es la peor forma de fallar que puede tener esto.
        """
        return f"{self.base}-{self.episodio}"

    @property
    def desde(self) -> float:
        return min((e.ts for e in self.evidencias), default=0.0)

    @property
    def hasta(self) -> float:
        return max((e.ts for e in self.evidencias), default=0.0)

    def como_dict(self) -> dict:
        return {
            "huella": self.huella, "regla": self.regla, "titulo": self.titulo,
            "entidad": self.entidad, "gravedad": self.gravedad,
            "episodio": self.episodio,
            "confianza": self.confianza, "estado": self.estado,
            "que_significa": self.que_significa,
            "desde": self.desde, "hasta": self.hasta,
            "desde_legible": fecha_legible(self.desde),
            "hasta_legible": fecha_legible(self.hasta),
            "evidencias": [e.como_dict() for e in
                           sorted(self.evidencias, key=lambda x: x.ts)],
        }


def _cerca(a, b, ventana: float = VENTANA) -> bool:
    # Un timestamp inválido se normaliza a 0 para no romper la ingesta. Eso
    # no puede convertirse después en evidencia temporal: dos filas corruptas
    # con ts=0 parecían haber ocurrido exactamente al mismo tiempo.
    if a.ts <= 0 or b.ts <= 0:
        return False
    return abs(a.ts - b.ts) <= ventana


def _mejor_grupo(eventos: list, ventana: float) -> list:
    """El grupo más grande de eventos que entra en una ventana de tiempo.

    Sin esto, una regla miraba TODOS los eventos de una entidad sin importar
    cuándo pasaron, y "el proxy la bloqueó hoy y el HIPS ayer" contaba como
    dos herramientas coincidiendo. No coincidieron: pasaron dos cosas
    separadas por 24 horas.

    Se toma el grupo más grande y no el más reciente porque lo que interesa
    es el momento en que más cosas pasaron juntas, que es donde está la
    historia.
    """
    eventos = [e for e in eventos if e.ts > 0]
    if not eventos:
        return []
    ordenados = sorted(eventos, key=lambda e: e.ts)
    mejor, inicio = [], 0
    for fin in range(len(ordenados)):
        while ordenados[fin].ts - ordenados[inicio].ts > ventana:
            inicio += 1
        if fin - inicio + 1 > len(mejor):
            mejor = ordenados[inicio:fin + 1]
    return mejor


# ------------------------------------------------------------------ reglas
#
# Cada una recibe una entidad ya armada y devuelve un Incidente o None.

def regla_dominio_y_conexion(entidad, ventana: float = VENTANA):
    """Un dominio de una lista se resolvió, y después salió una conexión.

    Es la cadena más valiosa que se puede armar hoy, porque une la capa más
    temprana con la siguiente. SecureDNS vio el nombre; SecureProxy vio que
    igual se intentó la conexión. Que las dos cosas pasen sobre el mismo
    indicador quiere decir que algo en la máquina insistió después de que el
    DNS le dijera que no.
    """
    consultas = [e for e in entidad.eventos if e.tipo == CONSULTA_BLOQUEADA]
    conexiones = [e for e in entidad.eventos if e.tipo == CONEXION_BLOQUEADA]
    if not consultas or not conexiones:
        return None
    par = next(((c, x) for c in consultas for x in conexiones
                if x.ts >= c.ts - 60 and _cerca(c, x, ventana)), None)
    if par is None:
        return None
    consulta, conexion = par
    proceso = conexion.datos.get("proceso") or ""
    # Saber qué proceso lo intentó sube mucho la confianza: deja de ser "algo
    # en la máquina" y pasa a ser algo concreto.
    confianza = 85 if proceso else 70
    return Incidente(
        regla="dominio_y_conexion",
        titulo=f"Se insistió con {entidad.valor} después de que el DNS lo bloqueara",
        entidad=entidad.valor, gravedad=ALTA, confianza=confianza,
        evidencias=[consulta, conexion],
        que_significa=(
            "SecureDNS no resolvió ese nombre y aun así salió una conexión al "
            "mismo destino" + (f", abierta por {proceso}" if proceso else "") +
            ". Algo en la máquina no se conformó con la primera negativa."),
    )


def regla_dos_herramientas(entidad, ventana: float = VENTANA):
    """La misma IP o dominio, señalado por dos herramientas distintas.

    Es la señal más barata de calcular y una de las más confiables, porque
    dos herramientas que miran cosas distintas coinciden mucho menos por
    casualidad que una misma repitiéndose diez veces.

    Se exige que las dos hayan bloqueado o registrado algo, no solo que la
    hayan visto: si no, cualquier IP con tráfico normal calificaría.
    """
    relevantes = [e for e in entidad.eventos if e.tipo in TIPOS_QUE_SENALAN]
    # La ventana también acá. Sin esto, "el proxy la bloqueó hoy y el HIPS
    # ayer" se contaba como dos herramientas coincidiendo, y no coincidieron
    # en nada: pasaron dos cosas separadas por 24 horas. Se busca el grupo
    # más grande que entre en la ventana, no todos los eventos de la entidad.
    relevantes = _mejor_grupo(relevantes, ventana)
    fuentes = {e.fuente for e in relevantes}
    if len(fuentes) < 2:
        return None
    aplicado = any(e.tipo == BLOQUEO_APLICADO and e.ok for e in relevantes)
    return Incidente(
        regla="dos_herramientas",
        titulo=f"{entidad.valor} señalada por {len(fuentes)} herramientas",
        entidad=entidad.valor,
        gravedad=ALTA if aplicado else MEDIA,
        # Más fuentes, más confianza, con techo: la cuarta coincidencia agrega
        # bastante menos que la segunda.
        confianza=min(95, 55 + 15 * len(fuentes)),
        evidencias=relevantes,
        que_significa=(
            f"Coincidieron {', '.join(sorted(fuentes))}, que miran capas "
            "distintas. Dos herramientas independientes se equivocan juntas "
            "mucho menos seguido que una sola repitiéndose."),
    )


def regla_fuerza_bruta_y_salida(entidad, ventana: float = VENTANA,
                                minimo_intentos: int = 5):
    """La misma IP probó contraseñas y además hubo tráfico saliente hacia ella.

    Es el patrón que más preocupa de los tres, porque las dos direcciones
    juntas sugieren que la cosa dejó de ser solo un intento de entrar. Si
    alguien golpea la puerta Y encima algo de adentro le contesta, la pregunta
    ya no es si entraron.
    """
    intentos = [e for e in entidad.eventos if e.tipo == INTENTO_ENTRADA]
    salidas = [e for e in entidad.eventos if e.tipo == CONEXION_BLOQUEADA]
    if len(intentos) < minimo_intentos or not salidas:
        return None
    # Las dos cosas tienen que haber pasado cerca. Un ataque de agosto y una
    # conexión saliente de octubre no son la misma historia, y presentarlas
    # como una sería inventar.
    juntos = _mejor_grupo(intentos + salidas, ventana)
    intentos = [e for e in juntos if e.tipo == INTENTO_ENTRADA]
    salidas = [e for e in juntos if e.tipo == CONEXION_BLOQUEADA]
    if len(intentos) < minimo_intentos or not salidas:
        return None
    return Incidente(
        regla="fuerza_bruta_y_salida",
        titulo=f"{entidad.valor} atacó y además hubo salida hacia esa IP",
        entidad=entidad.valor, gravedad=ALTA, confianza=90,
        evidencias=sorted(intentos, key=lambda e: e.ts)[-10:] + salidas,
        que_significa=(
            f"{len(intentos)} intentos de entrada desde esa dirección y "
            f"{len(salidas)} conexión(es) saliente(s) hacia ella. Las dos "
            "direcciones juntas son lo que separa un escaneo cualquiera de "
            "algo que ya tiene un pie adentro."),
    )


def regla_proceso_y_destino_marcado(entidad, ventana: float = VENTANA):
    """QUIÉN abrió la conexión a la IP que otra herramienta señaló.

    ESTA ES LA REGLA POR LA QUE EXISTE EL PUNTO 7.

    Todas las demás fuentes miran la red. Ven que salió una conexión a una IP
    que figura en un feed, y ahí se termina lo que pueden decir. La pregunta
    que queda sin contestar es siempre la misma, y es la única que importa:
    **¿qué programa la abrió?**

    Un navegador conectándose a una IP de mala reputación es, casi siempre,
    una publicidad. El mismo destino abierto por un `powershell.exe` no es lo
    mismo ni de lejos.

    Por eso esta regla no inventa una señal nueva: agarra la que ya existía
    (el bloqueo del proxy, del DNS o del HIPS) y le pega al lado el nombre del
    proceso. Sube la confianza y sobre todo hace que el incidente se pueda
    accionar, que es distinto de que se pueda leer.
    """
    marcados = [e for e in entidad.eventos if e.tipo in TIPOS_QUE_SENALAN]
    del_agente = [e for e in entidad.eventos
                  if e.fuente == "Secure-Agent"
                  and e.datos.get("tipo_agente") == "conexion"]
    if not marcados or not del_agente:
        return None

    juntos = _mejor_grupo(marcados + del_agente, ventana)
    marcados = [e for e in juntos if e.fuente != "Secure-Agent"]
    del_agente = [e for e in juntos if e.fuente == "Secure-Agent"]
    if not marcados or not del_agente:
        return None

    procesos = sorted({e.datos.get("proceso") or "un proceso sin identificar"
                       for e in del_agente})
    equipos = sorted({e.equipo for e in del_agente if e.equipo})
    # Que el proceso venga de una cadena rara sube esto a alta sin discusión:
    # un PowerShell lanzado por un Word conectándose a una IP marcada no
    # necesita más evidencia.
    con_cadena = [e for e in del_agente if e.datos.get("cadena_rara")]
    gravedad = ALTA if con_cadena else MEDIA
    confianza = 95 if con_cadena else 80

    explicacion = (
        f"{', '.join(procesos)} en {', '.join(equipos) or 'un equipo de la casa'} "
        f"se conectó a {entidad.valor}, y esa dirección ya estaba señalada por "
        f"{len({e.fuente for e in marcados})} herramienta(s) de la suite. "
        "Saber qué programa abrió la conexión es lo que convierte esto en algo "
        "que se puede accionar: no es lo mismo un navegador que una consola.")
    if con_cadena:
        explicacion += (f" Y la cadena de ese proceso es rara: "
                        f"{con_cadena[0].datos.get('cadena')}.")

    return Incidente(
        regla="proceso_y_destino_marcado",
        titulo=f"{procesos[0]} se conectó a {entidad.valor}, que ya estaba marcada",
        entidad=entidad.valor, gravedad=gravedad, confianza=confianza,
        evidencias=sorted(marcados + del_agente, key=lambda e: e.ts)[-10:],
        que_significa=explicacion,
    )


def regla_cadena_de_proceso_rara(entidad, ventana: float = VENTANA):
    """Una consola lanzada por un documento. Vale sola, sin que nadie coincida.

    Casi todas las reglas de este archivo piden que DOS fuentes coincidan,
    porque una sola repitiéndose es fácil de confundir con ruido. Esta es la
    excepción, y está justificada: nadie abre PowerShell desde un Word por
    accidente. El patrón es tan específico que no necesita confirmación.

    Es además el único incidente que se puede levantar sin que haya pasado
    nada por la red todavía: llega ANTES de que la conexión salga.
    """
    raros = [e for e in entidad.eventos
             if e.fuente == "Secure-Agent" and e.datos.get("cadena_rara")
             and e.datos.get("tipo_agente") == "proceso"]
    if not raros:
        return None
    reciente = max(raros, key=lambda e: e.ts)
    cadena = reciente.datos.get("cadena") or ""
    cmdline = (reciente.datos.get("cmdline") or "")[:200]
    explicacion = (
        f"En {reciente.equipo or 'un equipo'} corrió esta cadena: {cadena}. "
        "Nadie abre una consola desde un documento sin querer: es el patrón "
        "más viejo y más usado que hay, el archivo trae una macro y la macro "
        "llama a la consola.")
    if cmdline:
        explicacion += f" La línea de comando fue: {cmdline}"
    return Incidente(
        regla="cadena_de_proceso_rara",
        titulo=f"Una consola lanzada desde un documento en {reciente.equipo or '?'}",
        entidad=entidad.valor, gravedad=ALTA, confianza=85,
        evidencias=sorted(raros, key=lambda e: e.ts)[-5:],
        que_significa=explicacion,
    )


# El registro. Agregar una regla es escribir la función y sumar una línea acá.
def regla_ritmo_hacia_destino_marcado(entidad, ventana: float = VENTANA):
    """Un programa que habla con reloj HACIA un destino que ya está señalado.

    Las dos mitades son débiles solas y fuertes juntas, y por eso esta regla
    existe en vez de subirle la gravedad a cualquiera de las dos.

    El ritmo solo no alcanza: un cliente de correo revisando cada cinco
    minutos da exactamente la misma firma que un implante. Si SecureProxy
    gritara por cada ritmo que ve, la pantalla se llenaría de Thunderbird y
    nadie la miraría más.

    El destino marcado solo tampoco alcanza: una IP en un feed puede ser el
    servidor de publicidad de una página que abriste una vez.

    Las dos cosas al mismo tiempo son otra cosa. Un programa que le habla a un
    destino señalado, y que le habla con una regularidad que ninguna persona
    tiene, es la descripción de un implante esperando órdenes.

    NO se pide ventana de tiempo entre las dos mitades, y es a propósito: el
    ritmo es una conclusión sobre las últimas 24 horas, no un momento. Pedir
    que "coincidan en el tiempo" con un bloqueo puntual descartaría justamente
    el caso que se busca, donde el implante viene hablando hace días y el
    bloqueo pasó una sola vez.
    """
    ritmos = [e for e in entidad.eventos if e.tipo == RITMO_SOSPECHOSO]
    marcados = [e for e in entidad.eventos if e.tipo in TIPOS_QUE_SENALAN]
    if not ritmos or not marcados:
        return None

    ritmo = min(ritmos, key=lambda e: e.datos.get("coeficiente", 1.0))
    proceso = ritmo.datos.get("proceso") or "un proceso sin identificar"
    cada = int(ritmo.datos.get("promedio") or 0)
    fuentes = sorted({e.fuente for e in marcados})

    explicacion = (
        f"{proceso} viene hablando con {entidad.valor} cada {cada} segundos, "
        f"con una regularidad que una persona navegando no produce, y ese "
        f"mismo destino ya estaba señalado por {', '.join(fuentes)}. "
        "Cada mitad por separado es común: hay programas legítimos con ritmo "
        "perfecto, y hay destinos marcados que son solo publicidad. Las dos "
        "juntas describen un implante esperando órdenes.")

    return Incidente(
        regla="ritmo_hacia_destino_marcado",
        titulo=f"{proceso} le habla a {entidad.valor} con ritmo de reloj",
        entidad=entidad.valor, gravedad=ALTA, confianza=85,
        evidencias=sorted(ritmos + marcados, key=lambda e: e.ts)[-10:],
        que_significa=explicacion,
    )


REGLAS = (
    ("dominio_y_conexion", "Se insistió con un destino que el DNS bloqueó",
     regla_dominio_y_conexion),
    ("dos_herramientas", "Un indicador señalado por dos herramientas",
     regla_dos_herramientas),
    ("fuerza_bruta_y_salida", "Ataque de entrada más tráfico de salida",
     regla_fuerza_bruta_y_salida),
    ("proceso_y_destino_marcado", "Qué programa abrió la conexión al destino marcado",
     regla_proceso_y_destino_marcado),
    ("cadena_de_proceso_rara", "Una consola lanzada desde un documento",
     regla_cadena_de_proceso_rara),
    ("ritmo_hacia_destino_marcado", "Un programa hablando con reloj a un destino marcado",
     regla_ritmo_hacia_destino_marcado),
)


def correlacionar(entidades: dict, ventana: float = VENTANA) -> list:
    """Aplica todas las reglas a todas las entidades. Nunca lanza."""
    incidentes = []
    for entidad in entidades.values():
        for nombre, _titulo, regla in REGLAS:
            try:
                incidente = regla(entidad, ventana)
            except Exception as exc:  # noqa: BLE001
                # Una regla rota no puede impedir que corran las otras dos.
                print(f"[SecureCenter] la regla {nombre} falló: {exc}")
                continue
            if incidente is not None:
                incidentes.append(incidente)
    incidentes.sort(key=lambda i: (ORDEN_GRAVEDAD.get(i.gravedad, 3),
                                   -i.confianza, -i.hasta))
    return incidentes


class RegistroDeIncidentes:
    """Lo único que se guarda: qué hiciste vos con cada incidente.

    Mismo criterio que las alertas. El incidente en sí se recalcula de los
    eventos, porque los eventos son la verdad; lo que no se puede recalcular
    es que vos ya lo miraste y decidiste que estaba bien.
    """

    def __init__(self, con):
        self._con = con
        self._lock = threading.RLock()
        with self._lock:
            self._con.execute("""
                CREATE TABLE IF NOT EXISTS incidentes (
                    huella        TEXT PRIMARY KEY,
                    base          TEXT NOT NULL DEFAULT '',
                    episodio      INTEGER NOT NULL DEFAULT 1,
                    estado        TEXT NOT NULL,
                    titulo        TEXT NOT NULL DEFAULT '',
                    gravedad      TEXT NOT NULL DEFAULT 'media',
                    primera       REAL NOT NULL,
                    ultima        REAL NOT NULL,
                    -- La hora del evento más nuevo, que NO es lo mismo que la
                    -- última vez que se miró: es lo que decide si algo volvió
                    -- después del silencio.
                    ultimo_evento REAL NOT NULL DEFAULT 0,
                    tocado        REAL NOT NULL DEFAULT 0
                )
            """)
            self._migrar_schema()
            self._con.commit()

    def _migrar_schema(self) -> None:
        """Actualiza en sitio bases creadas por versiones anteriores.

        `CREATE TABLE IF NOT EXISTS` no agrega columnas a una tabla que ya
        existe. Detect incorporó base/episodio/ultimo_evento después de su
        primera versión; sin migración, actualizar SecureCenter conservando
        center_logs.db hacía fallar el primer SELECT.
        """
        columnas = {
            fila[1] for fila in self._con.execute("PRAGMA table_info(incidentes)")
        }
        if "base" not in columnas:
            self._con.execute(
                "ALTER TABLE incidentes ADD COLUMN base TEXT NOT NULL DEFAULT ''")
            self._con.execute("UPDATE incidentes SET base=huella WHERE base='' OR base IS NULL")
        if "episodio" not in columnas:
            self._con.execute(
                "ALTER TABLE incidentes ADD COLUMN episodio INTEGER NOT NULL DEFAULT 1")
        if "ultimo_evento" not in columnas:
            self._con.execute(
                "ALTER TABLE incidentes ADD COLUMN ultimo_evento REAL NOT NULL DEFAULT 0")
            # `primera` es el mejor dato histórico disponible en el esquema
            # viejo y evita que todo reaparezca inmediatamente como episodio 2.
            self._con.execute(
                "UPDATE incidentes SET ultimo_evento=primera WHERE ultimo_evento=0")

    def sincronizar(self, incidentes: list, ahora: float | None = None,
                    silencio: float = SILENCIO_PARA_EPISODIO_NUEVO) -> list:
        """Cruza lo que pasa ahora con lo que ya sabías, respetando episodios.

        Si una entidad estuvo callada más de `silencio` y vuelve, se abre un
        episodio nuevo en vez de reabrir el viejo. Sin eso, un ataque nuevo
        aparecía con el "cerrado" que le habías puesto al de hace dos meses.
        """
        ahora = time.time() if ahora is None else ahora
        with self._lock:
            for incidente in incidentes:
                fila = self._con.execute(
                    "SELECT episodio, estado, ultimo_evento FROM incidentes "
                    "WHERE base = ? ORDER BY episodio DESC LIMIT 1",
                    (incidente.base,)).fetchone()
                if fila is None:
                    incidente.episodio = 1
                else:
                    episodio, estado, ultimo = fila[0], fila[1], fila[2] or 0
                    if incidente.hasta - ultimo > silencio:
                        # Volvió después del silencio: es otra vez.
                        incidente.episodio = int(episodio) + 1
                    else:
                        incidente.episodio = int(episodio)
                        # Si lo habías cerrado pero entró evidencia posterior,
                        # el incidente está activo otra vez y no puede quedar
                        # oculto como "cerrado". VISTO sí se conserva.
                        if estado == CERRADO and incidente.hasta > ultimo:
                            incidente.estado = NUEVO
                        else:
                            incidente.estado = estado
                self._con.execute(
                    "INSERT INTO incidentes (huella, base, episodio, estado, titulo, "
                    "gravedad, primera, ultima, ultimo_evento) "
                    "VALUES (?,?,?,?,?,?,?,?,?) ON CONFLICT(huella) DO UPDATE SET "
                    "estado=excluded.estado, ultima=excluded.ultima, titulo=excluded.titulo, "
                    "gravedad=excluded.gravedad, ultimo_evento=excluded.ultimo_evento",
                    (incidente.huella, incidente.base, incidente.episodio,
                     incidente.estado, incidente.titulo, incidente.gravedad,
                     incidente.desde, ahora, incidente.hasta))
            self._con.commit()
        return incidentes

    def marcar(self, huella: str, estado: str, ahora: float | None = None) -> bool:
        if estado not in (NUEVO, VISTO, CERRADO):
            return False
        ahora = time.time() if ahora is None else ahora
        with self._lock:
            cur = self._con.execute(
                "UPDATE incidentes SET estado=?, tocado=? WHERE huella=?",
                (estado, ahora, huella))
            self._con.commit()
            return cur.rowcount > 0

    def sin_ver(self, incidentes: list) -> int:
        return sum(1 for i in incidentes if i.estado == NUEVO)
