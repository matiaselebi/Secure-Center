"""Traducir lo que cada base guarda al modelo de evento común.

POR QUÉ UN ADAPTADOR POR FUENTE Y NO UNA FUNCIÓN CON CASOS

Porque el conocimiento de cómo guarda las cosas SecureDNS tiene que vivir en
un solo lugar, y ese lugar no puede ser el correlacionador. Con un adaptador
por fuente, agregar Suricata o Nmap mañana es escribir un archivo nuevo y no
tocar ni una línea de lo que ya funciona.

LAS BASES NO SE TOCAN

Cada proyecto sigue guardando lo que guardaba, como lo guardaba. Se lee en
`mode=ro`, igual que hace SecureHIPS con sus hermanos y SecureCenter con la
línea de tiempo. Si un esquema cambia, se arregla acá y nada más.

QUIÉN DECIDE LA GRAVEDAD

Cada adaptador, porque cada uno conoce su herramienta. Un bloqueo que se
aplicó en el firewall es grave; el mismo bloqueo en modo audit no lo es,
porque no pasó nada. Una consulta bloqueada de publicidad no es lo mismo que
una de malware. Eso solo lo sabe quien conoce la fuente.
"""

import json
import sqlite3
from pathlib import Path

from .evento import (ALTA, BAJA, BLOQUEO_APLICADO, CAMBIO_ESTADO,
                     CONEXION_BLOQUEADA, CONSULTA_BLOQUEADA, INTENTO_ENTRADA,
                     MEDIA, PROBLEMA, RITMO_SOSPECHOSO, Evento)

# Cuántas filas se traen de cada base por vuelta. Alto para que la correlación
# tenga con qué trabajar, pero acotado: sin tope, una base de cien mil filas
# se carga entera en memoria en cada repintado del panel.
POR_FUENTE = 400


def _leer(db_file, consulta: str, limite: int) -> list:
    """Una consulta en solo lectura. Devuelve [] ante cualquier problema.

    Que una base esté rota, ocupada o con un esquema viejo no puede impedir
    que se lean las otras cuatro.
    """
    if db_file is None or not Path(db_file).exists():
        return []
    try:
        con = sqlite3.connect(f"file:{db_file}?mode=ro", uri=True, timeout=2.0)
        con.row_factory = sqlite3.Row
        filas = con.execute(consulta, (limite,)).fetchall()
        con.close()
        return filas
    except sqlite3.Error:
        return []


def _columnas(db_file, tabla: str) -> set:
    """Qué columnas tiene esa tabla, ahora mismo.

    Se agregó cuando el adaptador del DNS necesitó FILTRAR por una columna
    nueva. Hasta entonces alcanzaba con el truco de "probá la consulta buena y
    si vuelve vacía probá la vieja", pero ese truco confunde dos cosas muy
    distintas: que la columna no exista y que no haya filas que cumplan la
    condición. Con un filtro nuevo, una base moderna sin resultados caía a la
    consulta vieja y se traía justo las filas que el filtro quería sacar.
    Preguntar el esquema una vez cuesta un microsegundo y no se equivoca.
    """
    if db_file is None or not Path(db_file).exists():
        return set()
    try:
        con = sqlite3.connect(f"file:{db_file}?mode=ro", uri=True, timeout=2.0)
        filas = con.execute(f"PRAGMA table_info({tabla})").fetchall()
        con.close()
        return {f[1] for f in filas}
    except sqlite3.Error:
        return set()


# --------------------------------------------------------------- SecureDNS

def _dns(db_file, limite: int) -> list:
    """Consultas bloqueadas. El destino es el dominio, no una IP.

    Es la fuente más temprana de todas: acá el bloqueo pasa ANTES de que
    exista la conexión, así que un evento del DNS seguido de uno del proxy
    hacia la misma IP es exactamente el caso que la correlación busca.

    OJO con las filas importadas de Pi-hole. Desde que SecureDNS puede
    importar las consultas de Pi-hole a su propia base (para correrles encima
    la detección de túneles y las categorías), esas filas quedan acá Y siguen
    estando en la base de Pi-hole, que este mismo módulo lee con otro
    adaptador. Sin el filtro por `origen`, cada bloqueo entraría dos veces:
    dos eventos, dos entradas en la entidad, y una regla de correlación que
    cree ver dos herramientas distintas cuando en realidad vio una sola.
    """
    columnas = _columnas(db_file, "queries")
    campos = ["timestamp", "domain", "reason", "blocked"]
    if "category" in columnas:
        campos.append("category")
    # Los esquemas viejos no tienen `origen`: ahí no hay nada importado que
    # excluir, así que la condición simplemente no se agrega.
    condicion = "blocked = 1"
    if "origen" in columnas:
        condicion += " AND (origen IS NULL OR origen != 'pihole')"
    filas = _leer(db_file, (
        f"SELECT {', '.join(campos)} FROM queries "
        f"WHERE {condicion} ORDER BY id DESC LIMIT ?"), limite)
    eventos = []
    for f in filas:
        claves = f.keys()
        categoria = (f["category"] if "category" in claves else "") or ""
        # La publicidad es comodidad, no seguridad: no puede pesar lo mismo
        # que un dominio de malware o se llena la pantalla de ruido.
        grave = BAJA if categoria in ("publicidad", "ads", "tracking") else MEDIA
        eventos.append(Evento(
            ts=f["timestamp"], fuente="SecureDNS", tipo=CONSULTA_BLOQUEADA,
            gravedad=grave, destino=f["domain"] or "",
            detalle=f"no se resolvió {f['domain']}: {f['reason'] or 'en una lista'}",
            ok=True, datos={"categoria": categoria, "motivo": f["reason"] or ""},
        ))
    return eventos


# ------------------------------------------------------------- SecureProxy

def _proxy(db_file, limite: int) -> list:
    """Conexiones salientes cortadas. Trae el dominio Y la IP resuelta.

    Los dos indicadores importan: el dominio para cruzar con SecureDNS y la IP
    para cruzar con el HIPS y con Intel. Una fuente que da los dos es la que
    permite unir las dos puntas.
    """
    filas = _leer(db_file, (
        "SELECT timestamp, host, reason, blocked, resolved_ip, process FROM requests "
        "WHERE blocked = 1 ORDER BY id DESC LIMIT ?"), limite)
    if not filas:
        filas = _leer(db_file, (
            "SELECT timestamp, host, reason, blocked FROM requests "
            "WHERE blocked = 1 ORDER BY id DESC LIMIT ?"), limite)
    eventos = []
    for f in filas:
        claves = f.keys()
        ip = (f["resolved_ip"] if "resolved_ip" in claves else "") or ""
        proceso = (f["process"] if "process" in claves else "") or ""
        eventos.append(Evento(
            ts=f["timestamp"], fuente="SecureProxy", tipo=CONEXION_BLOQUEADA,
            # Los DOS, no uno u otro. Ver el comentario de `Evento.dominio`:
            # elegir uno rompía la correlación entre el DNS y el proxy.
            gravedad=MEDIA, destino=ip, dominio=f["host"] or "",
            detalle=f"conexión cortada a {f['host']}: {f['reason'] or 'en una lista'}",
            ok=True,
            datos={"host": f["host"] or "", "ip": ip, "proceso": proceso,
                   "motivo": f["reason"] or ""},
        ))
    return eventos


def _proxy_ritmos(db_file, limite: int) -> list:
    """Lo único que solo puede contestar SecureProxy: quién y con qué ritmo.

    Es el adaptador de la fase 3 del punto 8. A SecureProxy se le sacó todo lo
    que hacían otros mejor: los feeds los baja Secure-Intel, el firewall lo
    escribe SecureHIPS, la correlación la hace este proyecto. Lo que quedó es
    esto, y es algo que ninguna otra pieza puede dar: Pi-hole ve el nombre
    consultado, Suricata ve los paquetes, y ninguno de los dos sabe que fue
    `rundll32.exe` el que abrió la conexión ni que la repite cada 60 segundos.

    La cuenta NO se hace acá. SecureProxy la deja escrita en su tabla `ritmos`
    y esto la lee, igual que todos los otros adaptadores leen tablas. Repetir
    la cuenta de este lado sería el duplicado que el punto 8 vino a sacar, y
    encima uno peligroso: dos umbrales distintos harían que el panel de un
    proyecto contradiga al del otro sin que nadie entienda por qué.
    """
    filas = _leer(db_file, (
        "SELECT proceso, destino, visto, conexiones, promedio, coeficiente, "
        "bytes, motivo FROM ritmos ORDER BY coeficiente ASC LIMIT ?"), limite)
    eventos = []
    for f in filas:
        proceso = f["proceso"] or "un proceso sin identificar"
        # Gravedad MEDIA y no ALTA, siempre. Un cliente de correo revisando
        # cada cinco minutos da exactamente esta firma. Lo que convierte esto
        # en algo grave es que OTRA fuente coincida en el destino, y de eso se
        # encarga la regla de correlación, no el adaptador.
        eventos.append(Evento(
            ts=f["visto"], fuente="SecureProxy", tipo=RITMO_SOSPECHOSO,
            gravedad=MEDIA, dominio=f["destino"] or "",
            detalle=(f"{proceso} habla con {f['destino']} cada "
                     f"{int(f['promedio'] or 0)} segundos"),
            ok=True,
            datos={"proceso": f["proceso"] or "", "host": f["destino"] or "",
                   "conexiones": f["conexiones"], "promedio": f["promedio"],
                   "coeficiente": f["coeficiente"], "bytes": f["bytes"],
                   "motivo": f["motivo"] or ""},
        ))
    return eventos


# -------------------------------------------------------------- SecureHIPS

def _hips_bans(db_file, limite: int) -> list:
    """Bloqueos puestos (o solo registrados, si está en audit).

    La gravedad distingue las dos cosas, y no es un detalle: un bloqueo en
    modo audit NO pasó. Tratarlos igual haría que el correlacionador arme
    incidentes sobre acciones que nunca ocurrieron.
    """
    filas = _leer(db_file, (
        "SELECT desde, ip, motivo, aplicado, puntaje, pais FROM bans "
        "ORDER BY desde DESC LIMIT ?"), limite)
    if not filas:
        filas = _leer(db_file, (
            "SELECT desde, ip, motivo, aplicado FROM bans "
            "ORDER BY desde DESC LIMIT ?"), limite)
    eventos = []
    for f in filas:
        claves = f.keys()
        aplicado = bool(f["aplicado"])
        puntaje = int((f["puntaje"] if "puntaje" in claves else 0) or 0)
        eventos.append(Evento(
            ts=f["desde"], fuente="SecureHIPS", tipo=BLOQUEO_APLICADO,
            gravedad=ALTA if aplicado else BAJA, origen=f["ip"] or "",
            detalle=(f"{f['ip']} bloqueada: {f['motivo'] or 'sin motivo'}"
                     if aplicado else
                     f"{f['ip']} se habría bloqueado (modo audit): "
                     f"{f['motivo'] or 'sin motivo'}"),
            ok=aplicado,
            datos={"puntaje": puntaje,
                   "pais": (f["pais"] if "pais" in claves else "") or "",
                   "motivo": f["motivo"] or ""},
        ))
    return eventos


def _hips_intentos(db_file, limite: int) -> list:
    """Los intentos de login fallidos, que son la materia prima del HIPS.

    Van con gravedad baja de a uno: un intento suelto no significa nada, son
    muchos juntos los que importan. Que sean baja no los hace inútiles: la
    correlación cuenta cuántos hay en una ventana y ahí sí pesan.
    """
    filas = _leer(db_file, (
        "SELECT timestamp, ip, usuario, servicio FROM intentos "
        "ORDER BY id DESC LIMIT ?"), limite)
    return [
        Evento(ts=f["timestamp"], fuente="SecureHIPS", tipo=INTENTO_ENTRADA,
               gravedad=BAJA, origen=f["ip"] or "",
               detalle=(f"login fallido de {f['ip']} como "
                        f"{f['usuario'] or '?'} por {f['servicio'] or '?'}"),
               ok=False,
               datos={"usuario": f["usuario"] or "", "servicio": f["servicio"] or ""})
        for f in filas
    ]


# --------------------------------------------------------------- SecureVPN

def _vpn(db_file, limite: int) -> list:
    filas = _leer(db_file, (
        "SELECT timestamp, event, detail, ok FROM events "
        "ORDER BY id DESC LIMIT ?"), limite)
    return [
        Evento(ts=f["timestamp"], fuente="SecureVPN",
               tipo=CAMBIO_ESTADO if f["ok"] else PROBLEMA,
               gravedad=BAJA if f["ok"] else MEDIA,
               detalle=f"{f['event']}: {f['detail'] or ''}".strip(": "),
               ok=bool(f["ok"]))
        for f in filas
    ]


# ------------------------------------------------------------- Secure-Intel

def _intel(db_file, limite: int) -> list:
    """Actualizaciones de feeds. No son amenazas, son salud de la plataforma.

    Entran igual porque un feed caído explica por qué dejaron de aparecer
    detecciones, y esa correlación (menos bloqueos porque la lista está vieja)
    es de las que más cuesta ver a mano.
    """
    filas = _leer(db_file, (
        "SELECT ts, fuente, ok, antes, despues, error FROM actualizaciones "
        "ORDER BY ts DESC LIMIT ?"), limite)
    if not filas:
        filas = _leer(db_file, (
            "SELECT ultima AS ts, nombre AS fuente, ok, 0 AS antes, "
            "total AS despues, error FROM fuentes ORDER BY ultima DESC LIMIT ?"), limite)
    eventos = []
    for f in filas:
        ok = bool(f["ok"])
        diferencia = int(f["despues"] or 0) - int(f["antes"] or 0)
        eventos.append(Evento(
            ts=f["ts"], fuente="Secure-Intel",
            tipo=CAMBIO_ESTADO if ok else PROBLEMA,
            gravedad=BAJA if ok else MEDIA,
            detalle=(f"{f['fuente']}: {f['despues']} indicadores "
                     f"({'+' if diferencia > 0 else ''}{diferencia})" if ok else
                     f"{f['fuente']} falló: {f['error'] or 'sin detalle'}"),
            ok=ok, datos={"feed": f["fuente"], "diferencia": diferencia},
        ))
    return eventos


# ------------------------------------------------------------ Secure-Agent

# Cadenas de proceso que casi nunca son un accidente. Está duplicado a
# propósito con la lista de Secure-Agent: allá se usa para marcar el hallazgo
# en el equipo y acá para pesarlo al lado de un bloqueo de firewall. Son dos
# decisiones distintas sobre el mismo hecho, y atarlas obligaría a SecureCenter
# a importar código de un proyecto que puede no estar instalado.
PADRES_RAROS = ("winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe",
                "acrord32.exe", "wscript.exe", "cscript.exe", "mshta.exe")


def _cadena_rara(padre: str) -> bool:
    partes = [p.strip().lower() for p in (padre or "").split("<-")]
    return len(partes) > 1 and any(p in PADRES_RAROS for p in partes[1:])


def _agente(db_file, limite: int) -> list:
    """Lo que ven los agentes adentro de cada equipo de la casa.

    ESTO ES LO QUE NINGUNA OTRA FUENTE PUEDE DAR

    Todas las demás miran la red: el proxy ve que salió una conexión, el DNS
    ve el nombre que se consultó, el scanner ve el puerto desde afuera. Ninguna
    puede decir QUÉ PROGRAMA lo hizo, porque desde la red eso no se ve.

    El agente sí, y esa es la razón entera del punto 7. Una conexión a una IP
    que figura en un feed de amenazas es un dato; la misma conexión con
    "la abrió powershell.exe, que lo lanzó un Word" es una respuesta.

    QUÉ SE TRAE Y QUÉ NO

    Solo conexiones, puertos escuchando y procesos con cadena rara. Los
    usuarios, el arranque y la versión del sistema NO entran a la línea de
    tiempo: son estado, no eventos, y meterlos generaría cincuenta eventos
    idénticos por equipo en cada refresco. Se ven aislados en la pestaña
    Agentes de SecureCenter, que lee la misma base sin mezclarlos con otras
    fuentes.
    """
    columnas = _columnas(db_file, "hallazgos")
    if not columnas:
        return []
    filas = _leer(db_file, (
        "SELECT agente, tipo, clave, ultima_vez, nombre, ruta, usuario, pid, "
        "padre, origen, destino, puerto, detalle FROM hallazgos "
        "WHERE tipo IN ('conexion', 'puerto_escuchando', 'proceso') "
        "ORDER BY ultima_vez DESC LIMIT ?"), limite)

    eventos = []
    for f in filas:
        tipo = f["tipo"]
        padre = f["padre"] or ""
        rara = _cadena_rara(padre)

        if tipo == "proceso" and not rara:
            # La lista completa de procesos de una máquina son cientos de
            # filas que no dicen nada. Solo entra la que tiene la cadena rara,
            # que es la que vale por sí sola.
            continue

        if tipo == "conexion":
            detalle = (f"{f['nombre'] or 'algo'} en {f['agente']} está conectado "
                       f"a {f['destino']}:{f['puerto']}")
            gravedad = MEDIA if rara else BAJA
        elif tipo == "puerto_escuchando":
            detalle = (f"{f['agente']} tiene el puerto {f['puerto']} abierto por "
                       f"{f['nombre'] or 'un proceso sin identificar'}")
            gravedad = BAJA
        else:
            # Una consola lanzada desde un documento. Es de las pocas cosas
            # que valen ALTA por sí solas, sin necesitar que otra fuente
            # coincida: nadie abre PowerShell desde un Word sin querer.
            detalle = f"{f['agente']}: cadena de proceso rara, {padre}"
            gravedad = ALTA

        if rara and padre:
            detalle += f" (cadena: {padre})"

        eventos.append(Evento(
            ts=f["ultima_vez"], fuente="Secure-Agent",
            tipo=CAMBIO_ESTADO if tipo != "proceso" else PROBLEMA,
            gravedad=gravedad,
            equipo=f["agente"] or "",
            # El destino va como indicador para que se cruce con lo que ven
            # las demás fuentes. Es literalmente el punto de unión de todo el
            # punto 7: la misma IP que el proxy bloqueó, acá con su proceso.
            destino=f["destino"] or "",
            detalle=detalle, ok=True,
            datos={"tipo_agente": tipo, "proceso": f["nombre"] or "",
                   "ruta": f["ruta"] or "", "cadena": padre,
                   "cadena_rara": rara, "puerto": f["puerto"] or 0,
                   "cmdline": f["detalle"] or ""},
        ))
    return eventos


# ---------------------------------------------------------- Secure-Scanner

# Cómo pesa cada novedad del inventario de red. Secure-Scanner ya calcula una
# gravedad propia, pero acá se decide otra vez y a propósito: allá la escala
# es "qué tan raro es esto para el inventario" y acá es "cuánto pesa esto al
# lado de un bloqueo de firewall". Un equipo nuevo en la red no es lo mismo
# que un ataque de fuerza bruta, y el correlacionador tiene que poder
# distinguirlos.
GRAVEDAD_DE_NOVEDAD = {
    # Algo se conectó a tu red y nunca lo habías visto. Es lo más fuerte que
    # puede decir el scanner, pero sigue siendo menos que un bloqueo aplicado.
    "equipo_nuevo": MEDIA,
    # Un servicio que antes no escuchaba, ahora escucha.
    "puerto_nuevo": MEDIA,
    "equipo_se_fue": MEDIA,
    "version_cambiada": BAJA,
    "puerto_cerrado": BAJA,
    "cambio_de_ip": BAJA,
}


def _scanner(db_file, limite: int) -> list:
    """Las novedades del inventario de red.

    POR QUÉ SE LEEN LAS NOVEDADES Y NO LA TABLA DE EQUIPOS

    Porque un evento es algo que PASÓ, y la tabla de equipos es un estado. Si
    se leyera `equipos`, cada refresco generaría un evento por cada
    dispositivo de la casa, siempre los mismos, y la línea de tiempo quedaría
    inservible. `novedades` ya es exactamente la lista de cosas que pasaron.

    LO QUE ESTO APORTA A LA CORRELACIÓN

    Un indicador que ninguna otra fuente tiene: el equipo de la casa como
    entidad propia, con su MAC. SecureDNS y Pi-hole ven IP; el scanner es el
    único que sabe que la .41 de hoy y la .23 de ayer son el mismo aparato.
    """
    columnas = _columnas(db_file, "novedades")
    if not columnas:
        return []
    filas = _leer(db_file, (
        "SELECT ts, tipo, mac, gravedad, detalle, datos FROM novedades "
        "ORDER BY id DESC LIMIT ?"), limite)
    eventos = []
    for f in filas:
        tipo = f["tipo"] or ""
        try:
            datos = json.loads(f["datos"] or "{}")
        except (ValueError, TypeError):
            datos = {}
        ip = str(datos.get("ip") or datos.get("ahora") or "")
        # El equipo es el nombre que le pusiste, si le pusiste alguno. Es lo
        # que hace que un incidente diga "la impresora" y no una MAC.
        equipo = str(datos.get("nombre") or f["mac"] or "")
        eventos.append(Evento(
            ts=f["ts"], fuente="Secure-Scanner",
            tipo=CAMBIO_ESTADO,
            gravedad=GRAVEDAD_DE_NOVEDAD.get(tipo, BAJA),
            equipo=equipo,
            # La IP va como origen para que se cruce con lo que ven las demás
            # fuentes: si el mismo aparato que apareció hoy es el que el proxy
            # vio conectándose a algo malo, la correlación lo une sola.
            origen=ip,
            detalle=f["detalle"] or tipo,
            ok=True,
            datos={"tipo": tipo, "mac": f["mac"] or "", **datos},
        ))
    return eventos


# ------------------------------------------------------------------ Pi-hole
#
# Pi-hole no es un proyecto de la suite: es el motor que resuelve abajo. Pero
# su base de consultas es, de lejos, la fuente más rica que hay disponible,
# porque ve a TODOS los dispositivos de la casa y no solo a esta máquina.
#
# SE LEE EN SOLO LECTURA Y NADA MÁS. Es la misma regla que con las bases
# hermanas, y acá pesa el doble: `pihole-FTL.db` la escribe un proceso ajeno
# que no sabe que existimos.
#
# El esquema sí es una puerta documentada: Pi-hole publica la estructura de
# esta base y la tabla de códigos de estado. `queries` es una vista que ya
# resuelve los identificadores de dominio y cliente a texto, así que no hace
# falta saber nada de las tablas internas que tiene abajo.

# Qué estados significan "bloqueado", según la documentación de Pi-hole.
# Se escriben los dos conjuntos y no solo uno porque hay un tercer caso: un
# código que no está en ninguno de los dos es uno que Pi-hole agregó después
# de que esto se escribió. Ese caso NO se adivina (ver `_pihole`).
PIHOLE_BLOQUEADAS = frozenset({1, 4, 5, 6, 7, 8, 9, 10, 11, 15, 16, 18})
PIHOLE_PERMITIDAS = frozenset({2, 3, 12, 13, 14, 17})

PIHOLE_MOTIVOS = {
    1: "está en gravity (alguna de las listas)",
    4: "coincide con una expresión de la lista negra",
    5: "está en la lista negra exacta",
    6: "lo bloqueó el servidor de arriba",
    7: "lo bloqueó el servidor de arriba",
    8: "lo bloqueó el servidor de arriba",
    9: "bloqueado al seguir el CNAME",
    10: "bloqueado al seguir el CNAME",
    11: "bloqueado al seguir el CNAME",
    15: "bloqueado porque su base estaba ocupada",
    16: "dominio especial",
    18: "lo bloqueó el servidor de arriba (EDE 15)",
}


def _pihole(db_file, limite: int) -> list:
    """Las consultas que Pi-hole bloqueó, de todos los equipos de la casa.

    POR QUÉ LOS BLOQUEOS DE GRAVITY ENTRAN CON GRAVEDAD BAJA

    Porque desde acá no se puede saber de qué lista salió. El estado 1 dice
    "estaba en gravity" y gravity es la mezcla de todas las listas cargadas:
    las de publicidad que trae Pi-hole y la nuestra de malware y phishing. Si
    todos entraran como media, una casa normal metería miles de bloqueos de
    publicidad por día al correlacionador y taparía lo que importa.

    Lo que sí se puede saber es que un bloqueo por lista negra exacta, por
    expresión o siguiendo un CNAME fue una decisión explícita, y esos entran
    como media.

    La categoría de verdad la sabe SecureDNS, que al importar estas mismas
    consultas las cruza con sus propias listas. Esos eventos entran por el
    adaptador de SecureDNS, ya categorizados, y por eso este adaptador excluye
    las filas importadas del otro lado.
    """
    columnas = _columnas(db_file, "queries")
    if not columnas:
        return []
    marcas = ",".join("?" * len(PIHOLE_BLOQUEADAS))
    # `client` puede no estar en versiones muy viejas; el resto sí o sí.
    tiene_cliente = "client" in columnas
    campos = "timestamp, domain, status" + (", client" if tiene_cliente else "")
    if db_file is None or not Path(db_file).exists():
        return []
    try:
        con = sqlite3.connect(f"file:{db_file}?mode=ro", uri=True, timeout=2.0)
        con.row_factory = sqlite3.Row
        filas = con.execute(
            f"SELECT {campos} FROM queries WHERE status IN ({marcas}) "
            "ORDER BY id DESC LIMIT ?",
            (*sorted(PIHOLE_BLOQUEADAS), limite),
        ).fetchall()
        con.close()
    except sqlite3.Error:
        return []

    eventos = []
    desconocidos = set()
    for f in filas:
        estado = int(f["status"] or 0)
        if estado not in PIHOLE_BLOQUEADAS and estado not in PIHOLE_PERMITIDAS:
            # Un código nuevo. No se adivina en qué grupo va: se anota para
            # decirlo por consola y se saltea. Contarlo como bloqueo sería
            # inventar; contarlo como permitido, esconder.
            desconocidos.add(estado)
            continue
        cliente = (f["client"] if tiene_cliente else "") or ""
        motivo = PIHOLE_MOTIVOS.get(estado, f"estado {estado}")
        eventos.append(Evento(
            ts=f["timestamp"], fuente="Pi-hole", tipo=CONSULTA_BLOQUEADA,
            # El cliente es el equipo de la casa que preguntó. Es el dato que
            # ninguna otra fuente de la suite tenía: hasta acá todo era "esta
            # máquina".
            gravedad=BAJA if estado == 1 else MEDIA,
            equipo=cliente, origen=cliente, destino=f["domain"] or "",
            detalle=f"no se resolvió {f['domain']} para {cliente or 'un equipo'}: {motivo}",
            ok=True, datos={"estado": estado, "motivo": motivo},
        ))
    if desconocidos:
        print(f"[SecureCenter] Pi-hole usó estados que no conozco "
              f"({sorted(desconocidos)}); los salteé. ¿Actualizó de versión?")
    return eventos


# ------------------------------------------------------------------ registro
#
# Qué adaptador corre sobre qué base de qué proyecto. Agregar Suricata o Nmap
# mañana es sumar una línea acá y una función arriba. Nada más.
ADAPTADORES = (
    ("dns", "data/dns_logs.db", _dns),
    ("proxy", "data/proxy_logs.db", _proxy),
    ("proxy", "data/proxy_logs.db", _proxy_ritmos),
    ("hips", "data/hips_logs.db", _hips_bans),
    ("hips", "data/hips_logs.db", _hips_intentos),
    ("vpn", "data/vpn_logs.db", _vpn),
    ("intel", "data/intel.db", _intel),
    ("scanner", "data/inventario.db", _scanner),
    ("agente", "data/agentes.db", _agente),
)


def _suricata(ruta_eve: str, limite: int) -> list:
    """Las alertas de Suricata, ya en el modelo común.

    Es el adaptador más finito del archivo porque el trabajo está en
    `suricata.py`: leer la cola de un `eve.json` de cientos de megas y traducir
    con lista blanca de campos no es algo que quepa en un adaptador.

    Fase 2 del punto 9.
    """
    from . import suricata

    return suricata.eventos(ruta_eve, limite)


def recolectar(projects: dict, por_fuente: int = POR_FUENTE,
               pihole_db: str = "", suricata_eve: str = "") -> list:
    """Todos los eventos de todas las fuentes, ya en el modelo común.

    Nunca lanza: un proyecto que no está, una base rota o un esquema viejo se
    saltean en silencio y el resto sigue.

    `pihole_db` y `suricata_eve` son rutas absolutas y van aparte del resto
    porque ni Pi-hole ni Suricata son proyectos de la suite: no tienen carpeta
    hermana, ni venv, ni script de arranque. Son motores instalados en el
    sistema. Vacío = no está, y no se intenta leer nada.
    """
    from .evento import ordenar

    eventos = []
    for clave, relativo, adaptador in ADAPTADORES:
        project = projects.get(clave)
        if project is None or not getattr(project, "found", False):
            continue
        db_file = project.db_path(relativo)
        try:
            eventos.extend(adaptador(db_file, por_fuente))
        except Exception as exc:  # noqa: BLE001
            print(f"[SecureCenter] el adaptador de {clave} falló: {exc}")
    if pihole_db:
        try:
            eventos.extend(_pihole(pihole_db, por_fuente))
        except Exception as exc:  # noqa: BLE001
            print(f"[SecureCenter] el adaptador de Pi-hole falló: {exc}")
    if suricata_eve:
        try:
            eventos.extend(_suricata(suricata_eve, por_fuente))
        except Exception as exc:  # noqa: BLE001
            print(f"[SecureCenter] el adaptador de Suricata falló: {exc}")
    return ordenar(eventos)
