"""Pedirle un bloqueo a SecureHIPS a partir de un incidente. Fase 4 del punto 9.

QUÉ CAMBIA ACÁ Y POR QUÉ ES EL ÚLTIMO PASO DE TODO

Hasta este archivo, SecureCenter solamente miraba. Leía las bases de los
proyectos, cruzaba indicadores y armaba incidentes. No tocaba nada. Este es el
primer lugar donde una lectura puede terminar en una regla de firewall, y por
eso llega recién cuando lo demás está estable: es el punto donde una
equivocación deja de ser un renglón feo en una pantalla y pasa a ser tu casa
sin internet.

ES UN BOTÓN, NO UNA AUTOMATIZACIÓN

La hoja de ruta dice "que Detect **pueda** pedirle un bloqueo a SecureHIPS", y
la palabra es esa. Una alerta de red que bloquea sola es exactamente lo que la
fase 1 evitó al no dejar a Suricata en modo IPS: una regla escrita por alguien
que no te conoce, cortando tráfico tuyo a las tres de la mañana, sin que nadie
pueda relacionar el corte con la causa.

Con un botón hay una persona que miró la evidencia y decidió. Es más lento y
es la diferencia entre una herramienta y una trampa.

LA TRAMPA QUE ESTE ARCHIVO EXISTE PARA EVITAR

Una alerta de Suricata trae DOS IPs, y una de las dos es tuya. En una alerta
de comando-y-control saliente, el origen es tu propia PC: es tu máquina la que
está infectada y le habla al servidor de afuera. Bloquear el origen ahí sería
dejar sin internet al equipo que quisiste proteger, y encima el implante
seguiría adentro.

Por eso el trabajo real de este módulo no es mandar el pedido (eso son diez
líneas) sino **elegir bien qué IP** y negarse cuando no hay una buena.
"""

import ipaddress

# Lo que hace falta para que un incidente habilite el botón.
#
# No es una restricción técnica: SecureHIPS bloquearía lo que se le pida. Es
# una restricción de criterio. Un incidente de gravedad baja armado por una
# sola coincidencia es justamente el que suele estar equivocado, y bloquear
# por uno de esos es cómo se aprende a desconfiar del propio panel.
GRAVEDADES_QUE_HABILITAN = ("alta", "media")
FUENTES_MINIMAS = 2

# Cuánto dura el bloqueo pedido desde acá, en segundos. Cuatro horas.
#
# Corto a propósito, y bastante más corto que la escalera propia de SecureHIPS.
# Esto lo pidió una persona mirando una pantalla, no un detector que vio cinco
# intentos fallidos de login. Si la IP es realmente mala, va a volver y el
# bloqueo se va a poder repetir; si fue un error, se cae solo antes de que
# alguien tenga que acordarse de sacarlo.
DURACION_SEGUNDOS = 4 * 3600


def es_de_afuera(valor: str) -> bool:
    """¿Es una IP pública, o sea algo que tiene sentido bloquear?

    Se rechaza todo lo privado, y no por prolijidad: en una alerta de C2
    saliente la IP privada es TU máquina. Bloquearla en el firewall del
    gateway deja sin internet al equipo infectado, que es el que más necesita
    poder actualizarse y del que igual hay que sacar el implante a mano.

    También se rechazan loopback (127.x, que sería bloquearte a vos mismo),
    link-local (169.254.x, que aparece cuando el DHCP falla), multicast y
    reservadas. Ninguna de esas es un atacante.
    """
    try:
        ip = ipaddress.ip_address(str(valor).strip())
    except ValueError:
        return False
    return not (ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_multicast or ip.is_reserved or ip.is_unspecified)


def _fuentes(incidente) -> set:
    return {getattr(e, "fuente", "") for e in getattr(incidente, "evidencias", [])
            if getattr(e, "fuente", "")}


def candidata(incidente) -> tuple[str, str]:
    """Qué IP se puede pedir bloquear de este incidente. ('', motivo) si ninguna.

    Devuelve SIEMPRE un motivo cuando dice que no. Un botón que aparece
    apagado sin explicación hace que la gente crea que el programa está roto;
    uno que dice "esto no se bloquea en el firewall, se bloquea en el DNS"
    enseña algo.
    """
    if incidente is None:
        return "", "no existe ese incidente"

    gravedad = getattr(incidente, "gravedad", "")
    if gravedad not in GRAVEDADES_QUE_HABILITAN:
        return "", (f"la gravedad es {gravedad or 'desconocida'}: desde acá solo "
                    "se piden bloqueos de lo que ya está señalado como serio")

    fuentes = _fuentes(incidente)
    if len(fuentes) < FUENTES_MINIMAS:
        return "", (f"lo señaló una sola herramienta ({', '.join(fuentes) or '-'}). "
                    "Una sola repitiéndose es la que suele estar equivocada")

    entidad = str(getattr(incidente, "entidad", "") or "").strip()
    if not es_de_afuera(entidad):
        # Los dos casos que caen acá son distintos y merecen frases distintas,
        # porque llevan a lugares distintos.
        try:
            ipaddress.ip_address(entidad)
            es_ip = True
        except ValueError:
            es_ip = False
        if es_ip:
            return "", (f"{entidad} es una dirección de tu propia red. En una "
                        "alerta de salida esa IP es TU máquina: bloquearla te "
                        "deja sin internet el equipo que querías proteger, y el "
                        "problema sigue adentro")
        return "", (f"{entidad} es un nombre, no una IP, y el firewall bloquea "
                    "direcciones. Los nombres los bloquea SecureDNS, que es "
                    "donde esto se corta bien")
    return entidad, ""


def motivo_para(incidente) -> str:
    """El texto que va a quedar guardado en SecureHIPS.

    Importa más de lo que parece. Dentro de tres semanas, cuando alguien mire
    la lista de bloqueos del HIPS, esta frase es todo lo que va a haber para
    entender por qué esa IP está ahí. "bloqueo manual" no sirve; el nombre de
    la regla y las herramientas que coincidieron, sí.
    """
    regla = getattr(incidente, "regla", "") or "incidente"
    fuentes = ", ".join(sorted(_fuentes(incidente))) or "sin fuente"
    return f"Detect: {regla} ({fuentes})"


def pedir(incidente, cliente) -> tuple[bool, str]:
    """Pide el bloqueo. Devuelve (se hizo algo, la frase para mostrar).

    Nunca lanza. El peor resultado posible es un "no lo bloqueé porque...",
    que es una respuesta y no un silencio.
    """
    ip, porque = candidata(incidente)
    if not ip:
        return False, f"no pedí ningún bloqueo: {porque}"
    if cliente is None or not cliente.configurado():
        detalle = cliente.por_que_no() if cliente is not None else "no hay cliente"
        return False, (f"no pedí ningún bloqueo: SecureHIPS {detalle}. Es el único "
                       "que escribe en el firewall")

    tomado, detalle = cliente.bloquear(
        ip, motivo=motivo_para(incidente), duracion=DURACION_SEGUNDOS)
    return tomado, detalle
