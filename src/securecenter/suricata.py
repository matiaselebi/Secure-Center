"""Suricata: el motor que mira los paquetes. Acá solo se lo lee.

QUÉ VE SURICATA QUE NINGUNA OTRA PIEZA VE

Toda la suite mira la red desde arriba. SecureDNS ve el nombre que se
consultó. SecureProxy ve la conexión que abrió un proceso. SecureHIPS ve
quién golpea la puerta. Ninguno ve el paquete.

Suricata sí. Ve el handshake de TLS y puede decir que el certificado es de
una familia de malware conocida. Ve el User-Agent crudo de un pedido HTTP.
Ve un patrón de bytes que corresponde a un exploit conocido, en un puerto
donde no debería estar pasando eso. Son cosas que no se pueden deducir de un
nombre ni de un par de IPs.

POR QUÉ ESTO VIVE EN SECURECENTER Y NO ES UN PROYECTO NUEVO

Suricata tiene la misma forma que Pi-hole: es un motor instalado en el
sistema, sin carpeta hermana, sin venv, sin script de arranque. Ya existe un
lugar para eso y es `Externos` en la configuración, con la ruta absoluta a su
archivo de salida.

Un `secure-ids` propio sería una carpeta más para mantener toda la vida, y no
tendría nada adentro: Suricata detecta, y lo único que hace falta de este lado
es traducir lo que escribe al modelo común. Eso son doscientas líneas, no un
proyecto.

Y no va adentro de SecureHIPS, que sería la otra opción razonable (ya tiene
CrowdSec abajo), por una razón concreta: el archivo `eve.json` de un gateway
con tráfico real crece a cientos de megas por día, y meter ese parseo en el
proceso que tiene el firewall en la mano es cargarlo de trabajo que no es
suyo. SecureHIPS aplica. Detect lee y correlaciona.

LO QUE ESTE ARCHIVO NO HACE, A PROPÓSITO

No bloquea nada, no le pide nada a nadie, y no configura a Suricata. Es la
fase 1 del punto 9: solo detección. Que Detect pueda pedirle un bloqueo a
SecureHIPS a partir de una alerta de red es la fase 4, y llega recién cuando
todo esto esté estable, porque una regla de red mal escrita bloqueando sola
es la forma más rápida de quedarse sin internet en tu propia casa.
"""

import json
import os
import platform
import shutil
from pathlib import Path

from .evento import ALTA, BAJA, MEDIA

OK, AVISO, MAL, NA = "ok", "aviso", "mal", "na"

RUTA_EVE_POR_DEFECTO = "/var/log/suricata/eve.json"
RUTA_YAML_POR_DEFECTO = "/etc/suricata/suricata.yaml"

# Cuántos bytes del FINAL de eve.json se leen por vez. No hay marca de agua a
# propósito: es la misma semántica que tienen todos los otros adaptadores
# ("los últimos N eventos"), y una marca de agua acá sería peor, porque el
# archivo rota. Con rotación, un offset guardado apunta a cualquier lado.
#
# Dos megas alcanzan para varios miles de alertas y se leen en milisegundos
# incluso si el archivo pesa un giga, porque se busca desde el final.
TOPE_DE_LECTURA = 2 * 1024 * 1024

# Lo que pide Suricata con el ruleset abierto de Emerging Threats (~40.000
# reglas). El árbol de reglas solo se come más de un giga, y encima están las
# tablas de flujos, que crecen con el tráfico.
#
# ESTOS NÚMEROS NO REEMPLAZAN LA MEDICIÓN. Son el piso por debajo del cual ni
# vale la pena intentar; el número que importa es el que sale de medir TU
# equipo con TU tráfico, que es de lo que se trata la fase 4 del punto 1. Por
# eso `revisar_hardware` reporta lo que esta máquina tiene, y no dice "sí" ni
# "no" con más seguridad de la que hay.
RAM_MINIMA_GB = 2.0
RAM_COMODA_GB = 4.0
NUCLEOS_MINIMOS = 2

# El campo `severity` de una alerta de Suricata está INVERTIDO respecto de lo
# que uno esperaría: 1 es lo más grave y 3 lo menos. Es la convención de Snort
# que Suricata heredó, y confundirla haría que todo un troyano entre como bajo
# y una política de navegación entre como alta.
GRAVEDAD_DE_SEVERIDAD = {1: ALTA, 2: MEDIA, 3: BAJA}

# Categorías que valen alta sin importar el número, porque describen algo que
# YA pasó y no algo que podría estar por pasar.
CATEGORIAS_GRAVES = (
    "a network trojan was detected",
    "malware command and control activity detected",
    "successful administrator privilege gain",
    "successful user privilege gain",
    "executable code was detected",
)

# LOS ÚNICOS CAMPOS QUE SE COPIAN DE UNA ALERTA.
#
# Es una lista blanca y no una lista negra, y esa es toda la diferencia. Una
# alerta de `eve.json` puede traer `payload` y `payload_printable` (el
# contenido crudo del paquete, en base64 y en texto), `packet` (el paquete
# entero), y el cuerpo de un pedido HTTP. Eso es la captura completa que el
# punto 9 dice explícitamente que no se guarda: adentro va la contraseña que
# alguien escribió en un formulario, el token de sesión de su banco, el
# contenido de un mail.
#
# Con lista negra, el día que Suricata agregue un campo nuevo con contenido,
# entraría solo y nadie se enteraría. Con lista blanca, no entra nada que no
# esté acá escrito.
CAMPOS_DEL_FLUJO = ("timestamp", "src_ip", "src_port", "dest_ip", "dest_port",
                    "proto", "app_proto", "flow_id", "in_iface", "community_id")
CAMPOS_DE_LA_ALERTA = ("signature", "signature_id", "category", "severity",
                       "action", "gid", "rev")

# Los campos con contenido que NUNCA se copian. No se usan para filtrar (para
# eso está la lista blanca de arriba): están acá para que el test pueda
# afirmar que ninguno aparece nunca, y para que se lea qué se está evitando.
CAMPOS_PROHIBIDOS = ("payload", "payload_printable", "packet", "packet_info",
                     "http_request_body", "http_response_body", "email")


# ------------------------------------------------- fase 1: está y cómo está

def hay_suricata() -> bool:
    return shutil.which("suricata") is not None


def _linea_de_comando() -> str:
    """La línea de comando del Suricata que está corriendo AHORA.

    Se lee de `/proc` y no se deduce del archivo de configuración, y el motivo
    es concreto: el `suricata.yaml` que viene con el paquete trae la sección
    de NFQUEUE escrita y comentada, con ejemplos. Buscar la palabra "nfqueue"
    en ese archivo diría "está en modo IPS" en una instalación recién hecha
    que no está en modo IPS. Ya cometí ese error una vez con `pgrep -f`, que
    encontraba el propio comando que lo invocaba.

    Lo que está corriendo es un hecho. Lo que dice un archivo de configuración
    es una intención, y encima puede estar comentada.
    """
    if platform.system() != "Linux":
        return ""
    proc = Path("/proc")
    if not proc.is_dir():
        return ""
    for entrada in proc.iterdir():
        if not entrada.name.isdigit():
            continue
        try:
            exe = os.readlink(entrada / "exe")
        except OSError:
            # Sin permisos, o el proceso se murió entre el listado y esto.
            continue
        if os.path.basename(exe) != "suricata":
            continue
        try:
            crudo = (entrada / "cmdline").read_bytes()
        except OSError:
            return "suricata"
        return crudo.replace(b"\x00", b" ").decode("utf-8", "replace").strip()
    return ""


def corriendo() -> bool:
    return bool(_linea_de_comando())


def leer_yaml(ruta_yaml: str) -> dict:
    """El `suricata.yaml` PARSEADO. Vacío si no se puede leer.

    Se parsea y no se busca texto, y es la decisión más importante de este
    archivo. El `suricata.yaml` que trae el paquete viene con casi todo escrito
    y comentado, como ejemplos: NFQUEUE, copy-mode, pcap-log. Buscar esas
    palabras en el texto diría que están activadas en una instalación recién
    hecha donde no lo están. Un parser ignora los comentarios.
    """
    try:
        import yaml
    except ImportError:
        return {}
    try:
        crudo = Path(ruta_yaml).read_text(encoding="utf-8", errors="replace")
        datos = yaml.safe_load(crudo) or {}
    except Exception:  # noqa: BLE001 - un yaml roto no puede romper el panel
        return {}
    return datos if isinstance(datos, dict) else {}


def _copy_mode_del_yaml(ruta_yaml: str) -> str:
    """Si alguna interfaz de af-packet está en `copy-mode: ips`."""
    for entrada in leer_yaml(ruta_yaml).get("af-packet") or []:
        if isinstance(entrada, dict) and str(entrada.get("copy-mode", "")).lower() == "ips":
            return "ips"
    return ""


def modo(ruta_yaml: str = RUTA_YAML_POR_DEFECTO) -> tuple[str, str]:
    """('ids' | 'ips' | 'desconocido', por qué).

    La fase 1 del punto 9 es solo detección, y esto es lo que lo verifica. No
    es una preferencia estética: en modo IPS, una regla mal escrita del
    ruleset abierto te corta internet en tu propia casa, y el que la escribió
    no te conoce ni sabe qué usás.
    """
    linea = _linea_de_comando()
    if not linea:
        return "desconocido", "Suricata no está corriendo"

    partes = linea.split()
    if any(p in ("-q", "--queue", "-d", "--nfqueue") or p.startswith("--queue=")
           for p in partes):
        return "ips", "está enganchado a NFQUEUE: los paquetes pasan POR él"
    if _copy_mode_del_yaml(ruta_yaml) == "ips":
        return "ips", f"hay una interfaz con copy-mode: ips en {ruta_yaml}"
    if any(p in ("-i", "--af-packet", "--pcap") or p.startswith("--af-packet=")
           for p in partes):
        return "ids", "escucha una copia del tráfico, no está en el camino"
    return "desconocido", f"no reconozco cómo lo levantaron: {linea[:120]}"


def revisar_instalacion() -> dict:
    if not hay_suricata():
        return {"nombre": "Suricata", "estado": NA,
                "detalle": ("no está instalado. Es opcional: la suite funciona "
                            "entera sin él, con menos visibilidad de red"),
                "arreglo": "sudo apt install suricata (mirá antes si tu equipo da)"}
    if not corriendo():
        return {"nombre": "Suricata", "estado": AVISO,
                "detalle": "está instalado pero no está corriendo",
                "arreglo": "sudo systemctl start suricata"}
    return {"nombre": "Suricata", "estado": OK, "detalle": "corriendo",
            "arreglo": ""}


def revisar_modo(ruta_yaml: str = RUTA_YAML_POR_DEFECTO) -> dict:
    """Que esté mirando y no cortando. Es LA verificación de la fase 1."""
    if not hay_suricata():
        return {"nombre": "Suricata: modo", "estado": NA,
                "detalle": "no está instalado", "arreglo": ""}
    cual, porque = modo(ruta_yaml)
    if cual == "ids":
        return {"nombre": "Suricata: modo", "estado": OK,
                "detalle": f"solo detección ({porque})", "arreglo": ""}
    if cual == "ips":
        return {
            "nombre": "Suricata: modo", "estado": MAL,
            "detalle": (f"está en modo IPS y {porque}. Acá se lo quiere solo "
                        "mirando: una regla mal escrita del ruleset abierto "
                        "corta internet en tu casa, y el que la escribió no "
                        "sabe qué usás. El que bloquea es SecureHIPS, que "
                        "tiene vencimiento, lista blanca y un botón para "
                        "levantar el bloqueo"),
            "arreglo": ("sacá el enganche a NFQUEUE (o el copy-mode: ips) y "
                        "levantalo con af-packet"),
        }
    return {"nombre": "Suricata: modo", "estado": AVISO,
            "detalle": porque,
            "arreglo": "revisá cómo lo levanta tu unidad de systemd"}


def revisar_salida(ruta_eve: str) -> dict:
    """Que `eve.json` exista, se pueda leer y no esté congelado."""
    import time

    if not ruta_eve:
        return {"nombre": "Suricata: eve.json", "estado": NA,
                "detalle": "no está configurada la ruta en config.yaml",
                "arreglo": "poné externos.suricata_eve en config/config.yaml"}
    archivo = Path(ruta_eve)
    if not archivo.exists():
        return {"nombre": "Suricata: eve.json", "estado": MAL,
                "detalle": f"no existe {ruta_eve}",
                "arreglo": "revisá la sección outputs → eve-log de suricata.yaml"}
    if not os.access(archivo, os.R_OK):
        return {
            "nombre": "Suricata: eve.json", "estado": MAL,
            "detalle": ("existe pero no lo puedo leer. Suele ser de root y "
                        "SecureCenter no corre como root, que está bien"),
            "arreglo": "sudo usermod -aG adm $USER (y volvé a entrar)",
        }
    try:
        edad = time.time() - archivo.stat().st_mtime
    except OSError:
        edad = 0
    if edad > 3600:
        # Congelado NO es "vacío". Un eve.json que no se toca hace horas
        # significa que Suricata dejó de escribir, y el panel seguiría
        # mostrando las alertas viejas como si fueran el estado actual.
        return {"nombre": "Suricata: eve.json", "estado": AVISO,
                "detalle": f"no se escribe hace {int(edad / 3600)} hora(s)",
                "arreglo": "sudo systemctl status suricata"}
    return {"nombre": "Suricata: eve.json", "estado": OK,
            "detalle": f"{archivo.stat().st_size / 1024 ** 2:.0f} MB, al día",
            "arreglo": ""}


def revisar_hardware() -> dict:
    """¿Este equipo aguanta Suricata? Se dice lo que hay, no lo que conviene.

    "Solo si el hardware aguanta" es el título del punto 9, y es la clase de
    cosa que se decide con un número y no con una impresión. Acá se reporta lo
    que tiene la máquina contra el piso conocido, y se aclara que el número que
    manda es el que sale de medir con tráfico real.
    """
    from . import sistema

    datos = sistema.snapshot()
    if not datos.get("disponible") or datos.get("ram_total_gb") is None:
        return {"nombre": "Suricata: hardware", "estado": NA,
                "detalle": "no lo puedo medir sin psutil", "arreglo": ""}

    ram = float(datos["ram_total_gb"])
    nucleos = int(datos.get("cpu_nucleos") or 0)
    tiene = f"{ram:.0f} GB de RAM y {nucleos} núcleo(s)"

    if ram < RAM_MINIMA_GB:
        return {
            "nombre": "Suricata: hardware", "estado": MAL,
            "detalle": (f"este equipo tiene {tiene}. Suricata con el ruleset "
                        f"abierto necesita al menos {RAM_MINIMA_GB:.0f} GB solo "
                        "para el árbol de reglas: acá se va a quedar sin "
                        "memoria y el que va a morir es el que esté más gordo, "
                        "que puede ser Pi-hole"),
            "arreglo": ("no lo instales en este equipo, o corré Suricata con un "
                        "ruleset recortado"),
        }
    if ram < RAM_COMODA_GB or nucleos < NUCLEOS_MINIMOS:
        return {
            "nombre": "Suricata: hardware", "estado": AVISO,
            "detalle": (f"este equipo tiene {tiene}: entra justo. Va a andar en "
                        "un enlace hogareño y va a empezar a descartar paquetes "
                        "si el tráfico sube"),
            "arreglo": ("mirá el contador de `capture.kernel_drops` en las "
                        "estadísticas de Suricata antes de confiar en lo que ves"),
        }
    return {"nombre": "Suricata: hardware", "estado": OK,
            "detalle": f"{tiene}: alcanza", "arreglo": ""}


# ------------------- fase 3: metadata sí, captura completa nunca

# Las opciones de `outputs → eve-log → types → alert` que escriben CONTENIDO
# del paquete adentro del JSON, con la frase que explica qué se está guardando.
#
# La lista blanca de `a_evento` ya impide que esto llegue a un evento. Esto es
# la otra mitad, y hace falta igual: mientras la opción esté prendida, el dato
# se escribe en `eve.json`, que queda en el disco del gateway, entra en los
# backups y lo puede leer cualquiera que tenga una shell ahí. Filtrarlo al
# leerlo no lo borra del disco.
OPCIONES_CON_CONTENIDO = {
    "payload": "el contenido del paquete en base64",
    "payload-printable": "el contenido del paquete en texto plano",
    "packet": "el paquete entero",
    "http-body": "el cuerpo de los pedidos y respuestas HTTP",
    "http-body-printable": "el cuerpo HTTP en texto plano",
    "tagged-packets": "todos los paquetes de un flujo marcado",
}


def _salidas_del_yaml(datos: dict) -> dict:
    """`outputs` viene como una lista de diccionarios de una sola clave.

    Se aplana a {nombre: config} para poder preguntar por una sin recorrer.
    """
    salidas = {}
    for entrada in datos.get("outputs") or []:
        if isinstance(entrada, dict):
            for nombre, config in entrada.items():
                salidas[str(nombre)] = config if isinstance(config, dict) else {}
        elif isinstance(entrada, str):
            salidas[entrada] = {}
    return salidas


def _tipos_del_eve(eve: dict) -> dict:
    """Lo mismo con `types`, que además puede traer entradas sin opciones.

    `- alert:` con hijos y `- dns` pelado conviven en el mismo archivo.
    """
    tipos = {}
    for entrada in eve.get("types") or []:
        if isinstance(entrada, dict):
            for nombre, config in entrada.items():
                tipos[str(nombre)] = config if isinstance(config, dict) else {}
        elif isinstance(entrada, str):
            tipos[entrada] = {}
    return tipos


def revisar_privacidad(ruta_yaml: str = RUTA_YAML_POR_DEFECTO) -> list:
    """Que Suricata no esté guardando el contenido de tu tráfico en el disco.

    ESTA ES LA FASE 3 DEL PUNTO 9, Y ES LA MITAD QUE FALTABA.

    La lista blanca de campos de `a_evento` ya impide que el contenido de un
    paquete llegue a un evento de la suite. Pero mientras la opción esté
    prendida del lado de Suricata, el dato **igual se escribe** en `eve.json`:
    la contraseña que alguien tipeó en un formulario sin HTTPS, el cuerpo de
    un pedido, el paquete entero en base64. Ese archivo queda en el disco del
    gateway, entra en los backups y lo lee cualquiera que tenga una shell ahí.

    Filtrarlo al leerlo no lo borra del disco. La única forma de que ese dato
    no exista es que no se escriba.

    Y hay algo peor que `eve.json`, que es `pcap-log`: eso guarda los paquetes
    crudos, tal cual pasaron. Es literalmente la captura completa que el punto
    9 dice que no.

    SecureCenter no toca `suricata.yaml`: no es su archivo y necesita root.
    Reporta y dice exactamente qué cambiar.
    """
    datos = leer_yaml(ruta_yaml)
    if not datos:
        return [{"nombre": "Suricata: privacidad", "estado": AVISO,
                 "detalle": f"no pude leer {ruta_yaml} (suele necesitar sudo)",
                 "arreglo": "sudo cat el archivo y revisalo a mano, o dame permiso de lectura"}]

    filas = []
    salidas = _salidas_del_yaml(datos)

    # 1. La captura completa, que es la peor.
    pcap = salidas.get("pcap-log") or {}
    if pcap.get("enabled"):
        filas.append({
            "nombre": "Suricata: pcap-log", "estado": MAL,
            "detalle": ("está guardando los paquetes crudos en disco. Eso es la "
                        "captura completa: todo lo que pasa por la red de tu "
                        "casa, tal cual pasó, en un archivo"),
            "arreglo": "en suricata.yaml, outputs → pcap-log → enabled: no",
        })

    # 2. Los archivos extraídos del tráfico, que es la otra forma de lo mismo.
    almacen = salidas.get("file-store") or {}
    if almacen.get("enabled"):
        filas.append({
            "nombre": "Suricata: file-store", "estado": MAL,
            "detalle": ("está guardando en disco los archivos que ve pasar. Un "
                        "adjunto de mail o un PDF que alguien bajó terminan "
                        "ahí, completos"),
            "arreglo": "en suricata.yaml, outputs → file-store → enabled: no",
        })

    # 3. El contenido adentro del propio eve.json.
    eve = salidas.get("eve-log") or {}
    if not eve.get("enabled", True):
        filas.append({
            "nombre": "Suricata: eve-log", "estado": MAL,
            "detalle": "está apagado: no escribe nada que SecureCenter pueda leer",
            "arreglo": "en suricata.yaml, outputs → eve-log → enabled: yes",
        })
        return filas

    tipos = _tipos_del_eve(eve)
    if tipos and "alert" not in tipos:
        filas.append({
            "nombre": "Suricata: eve-log", "estado": MAL,
            "detalle": "no está registrando alertas, que es lo único que se lee de acá",
            "arreglo": "agregá `- alert:` en outputs → eve-log → types",
        })

    alerta = tipos.get("alert") or {}
    prendidas = [(clave, que) for clave, que in OPCIONES_CON_CONTENIDO.items()
                 if alerta.get(clave)]
    if prendidas:
        filas.append({
            "nombre": "Suricata: contenido en eve.json", "estado": MAL,
            "detalle": ("está escribiendo " + ", ".join(q for _c, q in prendidas)
                        + ". Adentro va la contraseña que alguien escribió en un "
                          "formulario o el contenido de un mail, y ese archivo "
                          "queda en el disco y entra en los backups"),
            "arreglo": ("poné en no estas opciones de outputs → eve-log → types → "
                        "alert: " + ", ".join(c for c, _q in prendidas)),
        })
    else:
        filas.append({"nombre": "Suricata: contenido en eve.json", "estado": OK,
                      "detalle": "no guarda payload ni cuerpos HTTP", "arreglo": ""})

    # 4. Lo único que se quiere que SÍ esté.
    if alerta and not alerta.get("metadata", True):
        filas.append({
            "nombre": "Suricata: metadata", "estado": AVISO,
            "detalle": ("está apagada. Es lo que dice de qué familia de malware "
                        "es la firma; sin eso queda el número de regla pelado"),
            "arreglo": "outputs → eve-log → types → alert → metadata: yes",
        })
    return filas


def revisar(ruta_eve: str = "", ruta_yaml: str = RUTA_YAML_POR_DEFECTO) -> list:
    """Todas las verificaciones, en el formato de `diagnostico.py`.

    Si no está instalado, sale UNA fila que dice que es opcional y no cuatro
    filas de "no aplica": llenar la pantalla de renglones grises sobre algo que
    elegiste no instalar es ruido.
    """
    if not hay_suricata():
        return [revisar_instalacion()]
    return ([revisar_instalacion(), revisar_modo(ruta_yaml),
             revisar_salida(ruta_eve), revisar_hardware()]
            + revisar_privacidad(ruta_yaml))


# --------------------------------------------- fase 2: leer y traducir

def leer_cola(ruta_eve: str, tope_bytes: int = TOPE_DE_LECTURA) -> list:
    """Las últimas alertas de `eve.json`, ya parseadas.

    Se lee desde el FINAL y no desde el principio. Un `eve.json` de un gateway
    con tráfico real pesa cientos de megas, y el panel se repinta cada pocos
    segundos: leerlo entero cada vez sería colgar la máquina para mostrar una
    tabla.

    La primera línea del pedazo leído se descarta siempre, porque el corte cae
    en cualquier lado y esa línea está partida al medio. Es una alerta perdida
    de miles, y la alternativa (adivinar dónde empieza una línea) es peor.

    Solo se devuelven las de `event_type: alert`. `eve.json` trae además todos
    los flujos, todas las consultas DNS y todos los handshakes TLS que ve, y
    eso es un volumen enorme de cosas que la suite ya sabe por otro lado.
    """
    if not ruta_eve:
        return []
    archivo = Path(ruta_eve)
    try:
        tamano = archivo.stat().st_size
        with archivo.open("rb") as f:
            if tamano > tope_bytes:
                f.seek(tamano - tope_bytes)
                f.readline()  # la línea partida al medio
            crudo = f.read()
    except OSError:
        # No existe, no hay permisos, o rotó justo ahora. Ninguna de las tres
        # es motivo para tirar abajo el resto de las fuentes.
        return []

    alertas = []
    for linea in crudo.decode("utf-8", "replace").splitlines():
        linea = linea.strip()
        if not linea or '"alert"' not in linea:
            # El descarte por texto antes de parsear es lo que hace esto
            # barato: en un eve.json típico, las alertas son menos del 1% de
            # las líneas, y parsear el otro 99% para tirarlo es el gasto.
            continue
        try:
            dato = json.loads(linea)
        except (ValueError, TypeError):
            continue
        if isinstance(dato, dict) and dato.get("event_type") == "alert":
            alertas.append(dato)
    return alertas


def _dominio_de(dato: dict) -> str:
    """El nombre, cuando la alerta lo trae. Es lo que cruza con SecureDNS.

    Una alerta con IP sola se puede cruzar con SecureHIPS y con Intel. Una que
    además trae el SNI del certificado o el Host del pedido se cruza también
    con SecureDNS y con Pi-hole, y ahí el incidente pasa de "una IP rara" a
    "este nombre, que además tu DNS ya había bloqueado".
    """
    tls = dato.get("tls") or {}
    http = dato.get("http") or {}
    dns = (dato.get("dns") or {}).get("rrname") or ""
    for valor in (tls.get("sni"), http.get("hostname"), dns):
        if valor:
            return str(valor).strip().lower()[:255]
    return ""


def gravedad_de(alerta: dict) -> str:
    categoria = str(alerta.get("category") or "").strip().lower()
    if categoria in CATEGORIAS_GRAVES:
        return ALTA
    return GRAVEDAD_DE_SEVERIDAD.get(alerta.get("severity"), BAJA)


def a_evento(dato: dict):
    """Una alerta de Suricata al modelo común. Devuelve None si no sirve.

    LO QUE SE COPIA ES UNA LISTA BLANCA. Ver `CAMPOS_DEL_FLUJO` y
    `CAMPOS_DE_LA_ALERTA` arriba: el contenido del paquete no entra nunca, ni
    ahora ni cuando Suricata agregue un campo nuevo.
    """
    from .evento import ALERTA_RED, Evento

    alerta = dato.get("alert")
    if not isinstance(alerta, dict):
        return None
    firma = str(alerta.get("signature") or "").strip()
    if not firma:
        return None

    origen = str(dato.get("src_ip") or "")
    destino = str(dato.get("dest_ip") or "")
    dominio = _dominio_de(dato)

    datos = {c: dato[c] for c in CAMPOS_DEL_FLUJO if c in dato}
    datos.update({c: alerta[c] for c in CAMPOS_DE_LA_ALERTA if c in alerta})
    if dominio:
        datos["dominio"] = dominio

    puerto = dato.get("dest_port")
    hacia = f"{destino}:{puerto}" if puerto else destino
    detalle = f"{firma} ({origen} → {hacia})"
    if dominio:
        detalle += f", nombre {dominio}"

    return Evento(
        ts=dato.get("timestamp"), fuente="Suricata", tipo=ALERTA_RED,
        gravedad=gravedad_de(alerta),
        # Los dos, siempre. Suricata dice quién ABRIÓ el flujo, no quién es la
        # víctima: en una alerta de C2 saliente el origen es tu propia máquina
        # y el que interesa es el destino, y en un escaneo entrante es al
        # revés. Poniendo los dos, la correlación cruza por el que sirva.
        origen=origen, destino=destino, dominio=dominio,
        detalle=detalle,
        # `action` es "allowed" en modo IDS SIEMPRE. Si alguna vez llega
        # "blocked", significa que Suricata está en línea cortando tráfico, que
        # es justo lo que la fase 1 dice que no.
        ok=str(alerta.get("action") or "allowed") != "blocked",
        datos=datos,
    )


def traducir(alertas: list) -> list:
    """De la lista cruda a eventos. Una alerta rota no tumba a las demás."""
    eventos = []
    for dato in alertas:
        try:
            evento = a_evento(dato)
        except Exception:  # noqa: BLE001
            continue
        if evento is not None:
            eventos.append(evento)
    return eventos


def eventos(ruta_eve: str, limite: int = 200) -> list:
    """Lo que usa el adaptador: leer la cola y traducir, los últimos `limite`."""
    return traducir(leer_cola(ruta_eve))[-limite:]
