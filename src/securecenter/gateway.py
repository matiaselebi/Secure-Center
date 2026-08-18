"""El Debian como router de la casa. Acá SOLO se verifica.

POR QUÉ ESTE ARCHIVO NO CONFIGURA NADA

Porque el punto 10 lo dice en una línea: "configuración, no un repo: no armes
un Secure-Router". Y tiene razón, por un motivo que se ve mejor con el ejemplo
al revés.

Un programa que te configura el gateway tiene que saber tus interfaces, tu
rango de IPs, tu proveedor, y tiene que manejar el caso en que algo salga a
mitad de camino. Cuando algo se rompa, vas a estar depurando DOS cosas: la red
y el programa que la configuró. Y el día que lo quieras deshacer, vas a
depender de que ese programa tenga bien escrito el camino de vuelta.

En cambio, cuatro archivos de configuración en `gateway/` son cuatro archivos
que se copian, se leen enteros en un minuto, y se borran para volver atrás.
Todo lo que hay que saber está escrito adentro y no adivinado por nadie.

Lo que sí falta cuando la configuración es a mano es saber si quedó bien
puesta. Eso es lo único que hace este módulo: mira y reporta, con el mismo
formato que el resto del diagnóstico. No escribe una regla, no prende un
sysctl, no toca una interfaz.

LO QUE SE VERIFICA, Y POR QUÉ CADA COSA

1. Que el reenvío esté prendido. Es lo único que convierte un equipo en
   router, y sin eso todo lo demás puede estar perfecto y no pasar nada.
2. Que la tabla `gateway` exista y que la de `securehips` siga estando. Las
   dos, separadas. Es el mecanismo por el que hay NAT sin romper la regla de
   un solo dueño del firewall.
3. Que SecureHIPS tenga cadena de `forward`. Es el agujero que este punto
   destapó: en un gateway, el tráfico del celular no pasa por `input` ni por
   `output`. Sin esa cadena, el panel dice "12 bloqueadas" y esas 12 hablan
   con toda la casa sin problema.
4. Que IPv6 no esté saliendo por afuera. Si el reenvío v6 está prendido y la
   tabla del gateway no tiene reglas v6, los equipos tienen direcciones
   públicas y salen sin pasar por nada.
5. Que esté escrito que esta máquina es ahora un punto único de falla.
"""

import platform
from pathlib import Path

OK, AVISO, MAL, NA = "ok", "aviso", "mal", "na"

RUTA_FORWARD_V4 = "/proc/sys/net/ipv4/ip_forward"
RUTA_FORWARD_V6 = "/proc/sys/net/ipv6/conf/all/forwarding"

TABLA_GATEWAY = "gateway"
TABLA_HIPS = "securehips"

# Dónde deja dnsmasq la lista de a quién le dio una IP. Pi-hole usa su propia
# ruta porque corre su propio FTL; un dnsmasq pelado usa la otra.
RUTAS_LEASES = ("/etc/pihole/dhcp.leases", "/var/lib/misc/dnsmasq.leases")

# Cuántos equipos se esperan durante la fase 2. La fase dice "probalo con UN
# dispositivo, no con la casa entera", y este número es esa frase escrita de
# forma que el programa la pueda verificar.
EQUIPOS_EN_PRUEBA = 1

# El archivo donde queda la fecha del último simulacro de salida. Lo escribe
# `gateway/salir-del-gateway.sh`, no este módulo.
RUTA_SIMULACRO = "data/ultimo-simulacro-gateway"

# Cada cuánto conviene repetir el simulacro. Seis meses: en ese plazo cambian
# las interfaces, cambia el módem del proveedor, cambia quién se acuerda.
DIAS_ENTRE_SIMULACROS = 180


def _leer_flag(ruta: str) -> bool | None:
    """El valor de un sysctl de /proc. None si no se puede leer.

    None NO es False. "No pude saber" y "está apagado" son respuestas
    distintas y llevan a filas distintas del diagnóstico.
    """
    try:
        return Path(ruta).read_text(encoding="utf-8").strip() == "1"
    except OSError:
        return None


def reenvia() -> bool | None:
    return _leer_flag(RUTA_FORWARD_V4)


def reenvia_v6() -> bool | None:
    return _leer_flag(RUTA_FORWARD_V6)


def listar_tablas() -> tuple[list, str]:
    """Las tablas de nftables. Devuelve (lista, motivo si no se pudo).

    `nft` casi siempre pide root, y SecureCenter no corre como root, que está
    bien. Cuando no se puede leer se dice: un diagnóstico que muestra "no hay
    tabla de gateway" porque le faltó permiso es peor que uno que no muestra
    nada, porque manda a arreglar algo que no está roto.
    """
    if platform.system() != "Linux":
        return [], "solo aplica en Linux"
    from . import procutil

    try:
        salida = procutil.run_quiet(["nft", "list", "tables"], timeout=10)
    except (OSError, ValueError) as exc:
        return [], f"no pude correr nft: {exc}"
    if salida.returncode != 0:
        detalle = (salida.stderr or "").strip().splitlines()
        motivo = detalle[-1] if detalle else "nft devolvió un error"
        return [], motivo

    tablas = []
    for linea in (salida.stdout or "").splitlines():
        partes = linea.split()
        # El formato es: table <familia> <nombre>
        if len(partes) >= 3 and partes[0] == "table":
            tablas.append(partes[2])
    if not tablas:
        # Cero tablas en una máquina que está reenviando paquetes es casi
        # siempre falta de permisos y no un firewall vacío: cualquier cosa que
        # toque la red (Docker, libvirt, el propio SecureHIPS) crea una tabla.
        #
        # La diferencia importa: decir "no tenés NAT" manda a arreglar algo
        # que capaz está bien, y eso es peor que decir "no pude verificar".
        return [], "nft no listó ninguna tabla; casi siempre es falta de permisos"
    return tablas, ""


def cadenas_de(tabla: str) -> tuple[list, str]:
    """Los nombres de las cadenas de una tabla, y con qué hook engancha cada una."""
    if platform.system() != "Linux":
        return [], "solo aplica en Linux"
    from . import procutil

    try:
        salida = procutil.run_quiet(
            ["nft", "list", "table", "inet", tabla], timeout=10)
    except (OSError, ValueError) as exc:
        return [], f"no pude correr nft: {exc}"
    if salida.returncode != 0:
        return [], "no pude leer la tabla"

    hooks = []
    for linea in (salida.stdout or "").splitlines():
        if "hook" in linea and "type" in linea:
            partes = linea.split()
            if "hook" in partes:
                hooks.append(partes[partes.index("hook") + 1])
    return hooks, ""


# ------------------------------------------------------------ las filas

def revisar_reenvio() -> dict:
    valor = reenvia()
    if valor is None:
        return {"nombre": "Gateway: reenvío", "estado": NA,
                "detalle": "no puedo leerlo en este sistema", "arreglo": ""}
    if not valor:
        return {"nombre": "Gateway: reenvío", "estado": NA,
                "detalle": ("esta máquina no reenvía paquetes: no es el router "
                            "de la casa. Es lo normal y no falta nada"),
                "arreglo": ""}
    return {"nombre": "Gateway: reenvío", "estado": OK,
            "detalle": "ip_forward está en 1: esta máquina es el router",
            "arreglo": ""}


def revisar_nat(tablas: list, motivo: str) -> dict:
    if motivo:
        return {"nombre": "Gateway: NAT", "estado": AVISO,
                "detalle": f"no pude leer las reglas ({motivo})",
                "arreglo": "agregá a SecureCenter al grupo que pueda correr nft, o revisá con sudo nft list tables"}
    if TABLA_GATEWAY not in tablas:
        return {
            "nombre": "Gateway: NAT", "estado": MAL,
            "detalle": ("está reenviando pero no hay tabla `gateway` con el NAT. "
                        "Los paquetes salen con la IP privada del celular como "
                        "origen y no vuelven nunca"),
            "arreglo": "sudo nft -f gateway/nftables-gateway.conf",
        }
    return {"nombre": "Gateway: NAT", "estado": OK,
            "detalle": "la tabla `gateway` está cargada", "arreglo": ""}


def revisar_convivencia(tablas: list, motivo: str) -> dict:
    """Que SecureHIPS siga siendo el dueño del firewall, en su propia tabla."""
    if motivo:
        return {"nombre": "Gateway: convivencia con SecureHIPS", "estado": AVISO,
                "detalle": f"no pude leer las reglas ({motivo})", "arreglo": ""}
    if TABLA_HIPS not in tablas:
        return {
            "nombre": "Gateway: convivencia con SecureHIPS", "estado": AVISO,
            "detalle": ("la tabla `securehips` no está cargada: los bloqueos no "
                        "se están aplicando"),
            "arreglo": "prendé SecureHIPS desde el panel",
        }
    return {
        "nombre": "Gateway: convivencia con SecureHIPS", "estado": OK,
        "detalle": ("`gateway` y `securehips` son dos tablas separadas; nftables "
                    "las evalúa por separado y ninguna pisa a la otra"),
        "arreglo": "",
    }


def revisar_bloqueos_en_reenvio(tablas: list, motivo: str) -> dict:
    """EL agujero que destapó este punto.

    En un gateway el tráfico del celular, del televisor y de la consola no
    entra por `input` ni sale por `output`: pasa por `forward`. Sin una cadena
    ahí, el panel puede decir "12 direcciones bloqueadas" mientras esas 12
    siguen hablando sin problema con toda la casa menos con el servidor.

    Un bloqueo que no bloquea es peor que no tener bloqueo, porque además te
    hace creer que estás cubierto.
    """
    if motivo or TABLA_HIPS not in tablas:
        return {"nombre": "Gateway: los bloqueos cubren a la casa", "estado": AVISO,
                "detalle": motivo or "SecureHIPS no está cargado",
                "arreglo": ""}
    hooks, error = cadenas_de(TABLA_HIPS)
    if error:
        return {"nombre": "Gateway: los bloqueos cubren a la casa", "estado": AVISO,
                "detalle": error, "arreglo": ""}
    if "forward" not in hooks:
        return {
            "nombre": "Gateway: los bloqueos cubren a la casa", "estado": MAL,
            "detalle": ("SecureHIPS no tiene cadena de forward. Sus bloqueos "
                        "cubren a ESTE servidor y a nada más: el tráfico del "
                        "celular y del televisor pasa por al lado. El panel "
                        "diría que estás protegido y no lo estarías"),
            "arreglo": ("actualizá SecureHIPS y reinicialo; la cadena se crea "
                        "sola al arrancar"),
        }
    return {"nombre": "Gateway: los bloqueos cubren a la casa", "estado": OK,
            "detalle": "SecureHIPS filtra también lo que pasa por el router",
            "arreglo": ""}


def revisar_ipv6(tablas: list) -> dict:
    """Que IPv6 no esté saliendo por un camino que no estás mirando.

    Si el reenvío v6 está prendido, los equipos de la casa reciben direcciones
    públicas y salen SIN pasar por el NAT. Todo lo que veas en el panel va a
    ser la mitad de la historia, y la otra mitad va por afuera.
    """
    valor = reenvia_v6()
    if valor is None:
        return {"nombre": "Gateway: IPv6", "estado": NA,
                "detalle": "no puedo leerlo acá", "arreglo": ""}
    if not valor:
        return {"nombre": "Gateway: IPv6", "estado": OK,
                "detalle": "el reenvío v6 está apagado, como pide la config",
                "arreglo": ""}
    return {
        "nombre": "Gateway: IPv6", "estado": AVISO,
        "detalle": ("el reenvío IPv6 está prendido. Los equipos de la casa "
                    "tienen direcciones públicas y salen sin pasar por el NAT: "
                    "revisá que la cadena forward de la tabla `gateway` filtre "
                    "v6 igual que v4, o lo que ves en el panel es la mitad"),
        "arreglo": ("net.ipv6.conf.all.forwarding = 0 en "
                    "/etc/sysctl.d/99-gateway.conf, o escribí las reglas v6"),
    }


# ------------------------------ fase 2: probarlo con UN equipo

def clientes(rutas=RUTAS_LEASES) -> list:
    """Quién está conectado a través de este gateway, según el DHCP.

    Cada línea de un archivo de leases es:
        <vence epoch> <mac> <ip> <nombre> <client-id>

    Se lee el archivo y no se escanea la red a propósito. Un escaneo activo en
    una fase donde justamente estás probando si la red anda es meter una
    variable más; el archivo de leases es lo que el propio DHCP anotó.
    """
    for ruta in rutas:
        archivo = Path(ruta)
        try:
            crudo = archivo.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        equipos = []
        for linea in crudo.splitlines():
            partes = linea.split()
            if len(partes) < 4:
                continue
            equipos.append({"vence": partes[0], "mac": partes[1].lower(),
                            "ip": partes[2],
                            "nombre": partes[3] if partes[3] != "*" else ""})
        return equipos
    return []


def contadores() -> tuple[dict, str]:
    """Los contadores con nombre de la tabla `gateway`.

    Son la única forma de contestar "¿está pasando algo por acá?" con un
    número. Si `reenviados` no se mueve mientras el equipo de prueba navega,
    el tráfico no está pasando por este router: está saliendo por el viejo, y
    vos estarías mirando un panel vacío creyendo que la prueba salió bien.
    """
    if platform.system() != "Linux":
        return {}, "solo aplica en Linux"
    from . import procutil

    try:
        salida = procutil.run_quiet(
            ["nft", "list", "counters", "table", "inet", TABLA_GATEWAY],
            timeout=10)
    except (OSError, ValueError) as exc:
        return {}, f"no pude correr nft: {exc}"
    if salida.returncode != 0:
        return {}, "no pude leer los contadores"

    valores, nombre = {}, ""
    for linea in (salida.stdout or "").splitlines():
        partes = linea.split()
        if len(partes) >= 2 and partes[0] == "counter":
            nombre = partes[1]
        if nombre and "packets" in partes:
            try:
                valores[nombre] = int(partes[partes.index("packets") + 1])
            except (IndexError, ValueError):
                pass
            nombre = ""
    return valores, ""


def revisar_cuantos_equipos(equipos: list) -> dict:
    """La fase 2 en una fila: ¿esto sigue siendo una prueba o ya es la casa?

    "Probalo con UN dispositivo, no con la casa entera" no es una recomendación
    de estilo: es lo que hace que, si algo sale mal, el que se queda sin
    internet sea un celular y no todos. Y hay un momento exacto en que deja de
    ser cierto sin que nadie lo decida, que es cuando alguien apaga el DHCP del
    router viejo o enchufa el switch entero.

    Por eso esto se cuenta y se dice, en vez de confiar en que te acordaste.
    """
    if not equipos:
        return {"nombre": "Gateway: equipos conectados", "estado": AVISO,
                "detalle": ("no hay ningún equipo con IP dada por este gateway. "
                            "Si estás en la prueba, el equipo todavía no la pidió"),
                "arreglo": ("desconectá y reconectá el equipo de prueba, o "
                            "renová la IP a mano")}
    if len(equipos) <= EQUIPOS_EN_PRUEBA:
        nombre = equipos[0].get("nombre") or equipos[0]["ip"]
        return {"nombre": "Gateway: equipos conectados", "estado": OK,
                "detalle": f"uno solo ({nombre}): esto todavía es una prueba",
                "arreglo": ""}
    return {
        "nombre": "Gateway: equipos conectados", "estado": AVISO,
        "detalle": (f"hay {len(equipos)} equipos pasando por este router. Ya no "
                    "es una prueba: si algo se rompe, se queda sin internet la "
                    "casa entera y no un celular"),
        "arreglo": ("está bien si fue a propósito. Si no, apagá el DHCP de acá y "
                    "volvé a prenderlo en el router del proveedor"),
    }


def revisar_trafico(valores: dict, motivo: str) -> dict:
    """Que el tráfico esté pasando de verdad por acá.

    Es el chequeo que separa "el equipo de prueba navega" de "el equipo de
    prueba navega POR ACÁ". Las dos cosas se ven igual desde el celular, y son
    completamente distintas: en la segunda estás filtrando, en la primera
    tenés un router configurado que nadie usa.
    """
    if motivo:
        return {"nombre": "Gateway: tráfico reenviado", "estado": AVISO,
                "detalle": f"no pude leer los contadores ({motivo})",
                "arreglo": "sudo nft list counters table inet gateway"}
    reenviados = valores.get("reenviados", 0)
    descartados = valores.get("descartados", 0)
    if not reenviados:
        return {
            "nombre": "Gateway: tráfico reenviado", "estado": MAL,
            "detalle": ("el contador está en cero: no pasó NI UN paquete por "
                        "este router. El equipo de prueba puede estar navegando "
                        "igual, pero por el router viejo, y vos estarías mirando "
                        "un panel vacío creyendo que la prueba salió bien"),
            "arreglo": ("revisá que el equipo tenga a este servidor como puerta "
                        "de enlace: en el equipo, `ip route` o la pantalla de wifi"),
        }
    if descartados > reenviados:
        return {
            "nombre": "Gateway: tráfico reenviado", "estado": AVISO,
            "detalle": (f"se descartaron más paquetes ({descartados:,}) de los que "
                        f"se reenviaron ({reenviados:,}). Algo que querés está "
                        "siendo cortado por la cadena de forward"),
            "arreglo": ("suele faltar `ct state established,related accept` como "
                        "primera regla, o el tráfico entra por una interfaz que "
                        "no es la que dice $LAN"),
        }
    return {"nombre": "Gateway: tráfico reenviado", "estado": OK,
            "detalle": f"{reenviados:,} paquetes reenviados, {descartados:,} descartados",
            "arreglo": ""}


def revisar_dns_de_los_equipos(equipos: list, pihole_db: str,
                               horas: float = 6) -> dict:
    """Que el DNS del equipo de prueba pase por Pi-hole, y no por afuera.

    ESTE ES EL FALLO SILENCIOSO DE LA FASE 2.

    Un celular puede estar navegando perfecto a través de este router y aun así
    no pasar una sola consulta por Pi-hole: alcanza con que tenga un DNS fijo
    escrito a mano, o con que el navegador tenga DNS-sobre-HTTPS prendido, que
    en Chrome y en Firefox viene activado solo en varios países.

    Desde el equipo no se ve ninguna diferencia. La navegación anda, el
    gateway reenvía, los contadores suben. Lo único que lo delata es que
    Pi-hole no tiene ni una consulta de esa IP, y eso se puede mirar acá.
    """
    if not pihole_db:
        return {"nombre": "Gateway: el DNS pasa por Pi-hole", "estado": NA,
                "detalle": "no está configurado externos.pihole_db",
                "arreglo": "poné la ruta en config/config.yaml"}
    if not equipos:
        return {"nombre": "Gateway: el DNS pasa por Pi-hole", "estado": NA,
                "detalle": "no hay equipos conectados para revisar", "arreglo": ""}

    import sqlite3
    import time

    desde = time.time() - horas * 3600
    ips = {e["ip"] for e in equipos if e.get("ip")}
    try:
        con = sqlite3.connect(f"file:{pihole_db}?mode=ro", uri=True, timeout=2.0)
        marcas = ",".join("?" * len(ips))
        filas = con.execute(
            f"SELECT DISTINCT client FROM queries WHERE timestamp >= ? "
            f"AND client IN ({marcas})", (desde, *sorted(ips))).fetchall()
        con.close()
    except sqlite3.Error as exc:
        return {"nombre": "Gateway: el DNS pasa por Pi-hole", "estado": AVISO,
                "detalle": f"no pude leer la base de Pi-hole: {exc}", "arreglo": ""}

    consultaron = {f[0] for f in filas}
    mudos = sorted(ips - consultaron)
    if not mudos:
        return {"nombre": "Gateway: el DNS pasa por Pi-hole", "estado": OK,
                "detalle": f"los {len(ips)} equipo(s) consultan por Pi-hole",
                "arreglo": ""}
    return {
        "nombre": "Gateway: el DNS pasa por Pi-hole", "estado": MAL,
        "detalle": (f"{', '.join(mudos)} pasa(n) por este router pero NO hicieron "
                    f"ninguna consulta a Pi-hole en {int(horas)} horas. O tienen "
                    "un DNS fijo escrito a mano, o el navegador está usando "
                    "DNS-sobre-HTTPS, que viene prendido solo en Chrome y "
                    "Firefox. Navegan igual y el filtrado no los toca"),
        "arreglo": ("en el equipo, sacá el DNS manual y apagá el DNS seguro del "
                    "navegador; o bloqueá el 853 y los resolutores conocidos "
                    "desde la cadena de forward"),
    }


# ------------------------- fase 3: el plan de salida, probado

def ultimo_simulacro(ruta: str = RUTA_SIMULACRO) -> float:
    """Cuándo se probó por última vez la vuelta atrás. 0 = nunca.

    Lo escribe `gateway/salir-del-gateway.sh` cuando termina. Que lo escriba el
    script y no este módulo es a propósito: la marca tiene que ser prueba de que
    el camino de vuelta CORRIÓ, no de que alguien apretó un botón que dice
    "ya lo probé".
    """
    try:
        crudo = Path(ruta).read_text(encoding="utf-8").strip().split()[0]
        return float(crudo)
    except (OSError, ValueError, IndexError):
        return 0.0


def revisar_plan_de_salida(ruta: str = RUTA_SIMULACRO) -> dict:
    """"Si no lo probaste, no lo tenés". Eso, verificado.

    Un plan de salida escrito y nunca corrido es una hoja de papel. Las cosas
    que fallan al volver atrás son siempre las mismas y ninguna se ve leyendo:
    el router del proveedor con el DHCP apagado hace seis meses y nadie se
    acuerda de la clave del panel, el cable que no alcanza porque el servidor
    se movió de lugar, el `systemctl` que no arranca porque se le sacó el
    enable.

    Por eso esto es una fila del diagnóstico y no una línea del README.
    """
    import time

    cuando = ultimo_simulacro(ruta)
    if not cuando:
        return {
            "nombre": "Gateway: plan de salida probado", "estado": MAL,
            "detalle": ("nunca se probó volver atrás. El plan está escrito, y un "
                        "plan escrito y nunca corrido es una hoja de papel: lo "
                        "que falla al volver son cosas que no se ven leyendo"),
            "arreglo": "bash gateway/salir-del-gateway.sh --simulacro",
        }
    dias = (time.time() - cuando) / 86400
    fecha = time.strftime("%d/%m/%Y", time.localtime(cuando))
    if dias > DIAS_ENTRE_SIMULACROS:
        return {
            "nombre": "Gateway: plan de salida probado", "estado": AVISO,
            "detalle": (f"la última vez fue el {fecha}, hace {int(dias)} días. En "
                        "ese plazo cambian las interfaces, cambia el módem del "
                        "proveedor y cambia quién se acuerda"),
            "arreglo": "bash gateway/salir-del-gateway.sh --simulacro",
        }
    return {"nombre": "Gateway: plan de salida probado", "estado": OK,
            "detalle": f"probado el {fecha}", "arreglo": ""}


def revisar_punto_unico() -> dict:
    """Lo que cambia de verdad cuando esta máquina es el router.

    No es una falla y no resta puntaje: es un dato que hay que tener escrito
    en algún lado antes de que pase. Si el servidor se apaga, se cuelga o se
    queda sin disco, la casa entera se queda sin internet, y el que lo vaya a
    arreglar puede no ser el que lo configuró.
    """
    return {
        "nombre": "Gateway: punto único de falla", "estado": AVISO,
        "detalle": ("con esta máquina de router, si se apaga o se cuelga la casa "
                    "entera se queda sin internet. Antes era solo este equipo"),
        "arreglo": ("tené a mano el plan de salida (docs/gateway.md): volver el "
                    "DHCP al router del proveedor es un cable y dos clicks, y "
                    "conviene haberlo probado ANTES de necesitarlo"),
    }


def revisar(pihole_db: str = "", ruta_simulacro: str = RUTA_SIMULACRO) -> list:
    """Todo, en el formato de `diagnostico.py`.

    Cuando la máquina no reenvía sale UNA fila que lo dice. No es una falla ni
    algo que falte: la mayoría de las instalaciones no son el router de nadie,
    y llenarles la pantalla de renglones sobre un gateway que no tienen es el
    ruido que hace que se deje de mirar el diagnóstico.
    """
    fila = revisar_reenvio()
    if fila["estado"] != OK:
        return [fila]

    tablas, motivo = listar_tablas()
    equipos = clientes()
    valores, motivo_contadores = contadores()
    return [
        fila,
        revisar_nat(tablas, motivo),
        revisar_convivencia(tablas, motivo),
        revisar_bloqueos_en_reenvio(tablas, motivo),
        revisar_ipv6(tablas),
        # Fase 2: que siga siendo una prueba, y que la prueba sea real.
        revisar_cuantos_equipos(equipos),
        revisar_trafico(valores, motivo_contadores),
        revisar_dns_de_los_equipos(equipos, pihole_db),
        # Fase 3: que el camino de vuelta esté probado.
        revisar_plan_de_salida(ruta_simulacro),
        revisar_punto_unico(),
    ]
