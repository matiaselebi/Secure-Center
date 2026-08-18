"""El botón que revisa todo y te da un número.

POR QUÉ UN PUNTAJE Y NO UNA LISTA DE TILDES

Porque una lista de veinte verificaciones se lee cuando ya sospechás algo. Un
número se mira todos los días, y es lo que hace que alguien note que pasó de
98 a 71 sin haber tocado nada. El número no reemplaza a la lista: está arriba
de ella, y cada punto que se pierde tiene su fila explicando por qué.

QUÉ ES UN PROBLEMA Y QUÉ NO

La distinción más importante de este módulo. Un servicio apagado **no es un
problema**: apagarlo puede ser exactamente lo que quisiste. Un servicio que
figura como corriendo pero no contesta, sí. Un feed sin actualizar hace dos
horas no es nada; hace tres semanas es grave. Si el diagnóstico marcara en
rojo todo lo que no es el estado ideal, la gente aprendería a ignorarlo, que
es la única forma de que una herramienta así deje de servir.

Por eso hay cuatro estados y no dos: `ok`, `aviso` (algo para mirar), `mal`
(algo roto) y `na` (no aplica acá, no cuenta para el puntaje).

CADA HALLAZGO TRAE EL ARREGLO

Igual que en SecureHIPS. Decir "el puerto 8890 no responde" sin decir qué
hacer al respecto obliga a googlear tu propia herramienta.
"""

import shutil
import socket
import time

from . import procesos, sistema
from .health import ACTIVO, APAGADO, PARCIAL, state_snapshot
from .projects import PROJECT_SPECS

OK, AVISO, MAL, NA = "ok", "aviso", "mal", "na"

# Cuánto resta cada cosa que sale mal. Los pesos están acá, juntos y a la
# vista, para que se puedan discutir: un servicio caído duele más que una
# librería opcional que falta, y eso tiene que ser una decisión visible y no
# algo enterrado en un `if`.
PESOS = {MAL: 15, AVISO: 5}

# Servicios de afuera que la suite necesita de verdad, con por qué. No es una
# lista de "webs conocidas": si alguno de estos no se alcanza, algo concreto
# de la suite deja de funcionar.
INTERNET = (
    ("Cloudflare DNS", "1.1.1.1", 853,
     "SecureDNS resuelve por DNS-over-TLS contra acá"),
    ("Quad9", "9.9.9.9", 853,
     "el otro upstream de SecureDNS, el que se usa si Cloudflare falla"),
    ("abuse.ch", "urlhaus.abuse.ch", 443,
     "de acá bajan URLhaus y Feodo Tracker"),
    ("AbuseIPDB", "api.abuseipdb.com", 443,
     "SecureProxy consulta la reputación de las IPs acá"),
    ("GitHub", "raw.githubusercontent.com", 443,
     "de acá baja FireHOL"),
)

# Cuánto se espera a cada uno. Corto: son cinco, y el diagnóstico entero no
# puede tardar medio minuto o nadie lo va a apretar dos veces.
TIMEOUT = 2.0


def _alcanzable(host: str, port: int, timeout: float = TIMEOUT) -> bool:
    """¿Se puede abrir un TCP hasta ahí?

    A propósito NO se usa HTTP ni se valida el certificado: lo que se está
    preguntando es "¿la red me deja llegar?", no "¿el servicio anda bien?".
    Un 403 de AbuseIPDB por falta de clave sigue siendo una red que funciona.
    """
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (OSError, socket.timeout):
        return False


def estado_de_internet(timeout: float = TIMEOUT) -> list[dict]:
    """A cuáles de los servicios de afuera se llega."""
    salida = []
    for nombre, host, port, para_que in INTERNET:
        salida.append({
            "nombre": nombre, "destino": f"{host}:{port}", "para_que": para_que,
            "ok": _alcanzable(host, port, timeout),
        })
    return salida


def _revisar_proyectos(projects, health) -> list[dict]:
    revisiones = []
    for spec in PROJECT_SPECS:
        project = projects.get(spec.key)
        if project is None or not project.found:
            revisiones.append({
                "nombre": spec.display_name, "estado": AVISO,
                "detalle": "no está en el disco",
                "arreglo": "clonalo al lado de los demás, o poné su ruta en "
                           "config/config.yaml",
            })
            continue
        if project.falta_el_venv():
            revisiones.append({
                "nombre": spec.display_name, "estado": MAL,
                "detalle": "está en el disco pero sin entorno virtual",
                "arreglo": f"en {project.folder}: python -m venv venv && "
                           "venv\\Scripts\\pip install -r requirements.txt",
            })
            continue
        estado = health.get(spec.key, APAGADO)
        if estado == ACTIVO:
            revisiones.append({
                "nombre": spec.display_name, "estado": OK,
                "detalle": "corriendo y contestando", "arreglo": "",
            })
        elif estado == PARCIAL:
            revisiones.append({
                "nombre": spec.display_name, "estado": MAL,
                "detalle": "el proceso está arriba pero no contesta como debería",
                "arreglo": "reinicialo desde su tarjeta y mirá la consola",
            })
        else:
            # Apagado NO es un problema. Puede ser exactamente lo que quisiste.
            revisiones.append({
                "nombre": spec.display_name, "estado": NA,
                "detalle": "apagado", "arreglo": "",
            })
    return revisiones


def _revisar_puertos(cfg) -> dict:
    """Que no haya dos servicios configurados en el mismo puerto.

    Es un error de configuración que se manifiesta como "uno de los dos no
    arranca y no se entiende por qué", y que nadie va a buscar en el YAML.
    """
    puertos = {
        "SecureProxy (servicio)": cfg.ports.proxy_service,
        "SecureProxy (panel)": cfg.ports.proxy_dashboard,
        "SecureDNS": cfg.ports.dns_dashboard,
        "SecureVPN": cfg.ports.vpn_dashboard,
        "SecureHIPS": cfg.ports.hips_dashboard,
        "Secure-Intel": cfg.ports.intel_dashboard,
        "SecureCenter": cfg.ports.center_dashboard,
    }
    repetidos = {}
    for nombre, port in puertos.items():
        repetidos.setdefault(port, []).append(nombre)
    choques = {p: n for p, n in repetidos.items() if len(n) > 1}
    if choques:
        detalle = "; ".join(f"{p}: {' y '.join(n)}" for p, n in choques.items())
        return {"nombre": "Puertos", "estado": MAL,
                "detalle": f"hay puertos repetidos ({detalle})",
                "arreglo": "cambiá uno de los dos en config/config.yaml"}
    return {"nombre": "Puertos", "estado": OK,
            "detalle": f"{len(puertos)} puertos, ninguno repetido", "arreglo": ""}


def _revisar_disco() -> dict:
    try:
        uso = shutil.disk_usage(".")
    except OSError:
        return {"nombre": "Disco", "estado": NA, "detalle": "no pude medirlo",
                "arreglo": ""}
    pct = uso.used * 100 / uso.total if uso.total else 0
    libres_gb = round(uso.free / 1024 ** 3, 1)
    if pct >= 95 or libres_gb < 1:
        return {"nombre": "Disco", "estado": MAL,
                "detalle": f"{pct:.0f}% usado, quedan {libres_gb} GB",
                "arreglo": "las bases de los proyectos crecen solas: bajales "
                           "logging.max_rows o retener_dias"}
    if pct >= 85:
        return {"nombre": "Disco", "estado": AVISO,
                "detalle": f"{pct:.0f}% usado, quedan {libres_gb} GB",
                "arreglo": "todavía alcanza, pero conviene mirarlo"}
    return {"nombre": "Disco", "estado": OK,
            "detalle": f"{pct:.0f}% usado, quedan {libres_gb} GB", "arreglo": ""}


def _revisar_memoria() -> dict:
    datos = sistema.snapshot()
    if not datos.get("disponible") or datos.get("ram_pct") is None:
        return {"nombre": "Memoria", "estado": NA,
                "detalle": "no la puedo medir sin psutil", "arreglo": ""}
    pct = datos["ram_pct"]
    if pct >= 92:
        return {"nombre": "Memoria", "estado": MAL,
                "detalle": f"{pct}% usada",
                "arreglo": "fijate en las fichas de los servicios cuál se la "
                           "está comiendo, y reinicialo"}
    if pct >= 80:
        return {"nombre": "Memoria", "estado": AVISO,
                "detalle": f"{pct}% usada", "arreglo": ""}
    return {"nombre": "Memoria", "estado": OK, "detalle": f"{pct}% usada",
            "arreglo": ""}


def _revisar_psutil() -> dict:
    if procesos.disponible():
        return {"nombre": "Medición de procesos", "estado": OK,
                "detalle": "psutil instalado", "arreglo": ""}
    return {"nombre": "Medición de procesos", "estado": AVISO,
            "detalle": "sin psutil no puedo mostrar PID, RAM ni CPU",
            "arreglo": "venv\\Scripts\\pip install psutil"}


def _revisar_feeds(projects) -> dict:
    """Hace cuánto que Secure-Intel no puede actualizar.

    Es el modo de falla más silencioso de toda la suite: las listas siguen
    ahí, los bloqueos siguen funcionando, y todo dice que te protege con datos
    de hace tres semanas.
    """
    import sqlite3

    project = projects.get("intel")
    if project is None or not project.found:
        return {"nombre": "Feeds de amenazas", "estado": AVISO,
                "detalle": "Secure-Intel no está instalado",
                "arreglo": "instalá o configurá Secure-Intel; los consumidores "
                           "solo pueden usar el último dataset que ya tengan"}
    db_file = project.db_path("data/intel.db")
    if db_file is None or not db_file.exists():
        return {"nombre": "Feeds de amenazas", "estado": AVISO,
                "detalle": "todavía no se bajó ningún feed",
                "arreglo": "encendé Secure-Intel, o corré su "
                           "scripts/actualizar.py --forzar"}
    try:
        con = sqlite3.connect(f"file:{db_file}?mode=ro", uri=True, timeout=1.0)
        filas = con.execute("SELECT nombre, ultima, ok FROM fuentes").fetchall()
        con.close()
    except sqlite3.Error:
        return {"nombre": "Feeds de amenazas", "estado": AVISO,
                "detalle": "no pude leer la base de Secure-Intel", "arreglo": ""}
    if not filas:
        return {"nombre": "Feeds de amenazas", "estado": AVISO,
                "detalle": "la base está vacía",
                "arreglo": "corré scripts/actualizar.py --forzar en Secure-Intel"}
    ahora = time.time()
    viejas = []
    for nombre, ultima, ok in filas:
        try:
            ultima_ts = float(ultima)
        except (TypeError, ValueError):
            ultima_ts = 0.0
        if not ok or ultima_ts <= 0 or (ahora - ultima_ts) > 24 * 3600:
            viejas.append(str(nombre or "fuente sin nombre"))
    if viejas:
        return {"nombre": "Feeds de amenazas", "estado": AVISO,
                "detalle": f"sin actualizar hace más de un día: {', '.join(viejas)}",
                "arreglo": "encendé Secure-Intel; si ya está prendido, mirá su "
                           "panel para ver qué error da"}
    return {"nombre": "Feeds de amenazas", "estado": OK,
            "detalle": f"{len(filas)} fuentes al día", "arreglo": ""}


def _revisar_internet(timeout: float, servicios: list[dict] | None = None) -> dict:
    servicios = estado_de_internet(timeout) if servicios is None else servicios
    caidos = [s["nombre"] for s in servicios if not s["ok"]]
    if not caidos:
        return {"nombre": "Internet", "estado": OK,
                "detalle": f"los {len(servicios)} servicios son alcanzables",
                "arreglo": ""}
    if len(caidos) == len(servicios):
        return {"nombre": "Internet", "estado": MAL,
                "detalle": "ningún servicio es alcanzable",
                "arreglo": "¿estás sin internet? Si el proxy está prendido, "
                           "fijate que no se esté bloqueando a sí mismo"}
    return {"nombre": "Internet", "estado": AVISO,
            "detalle": f"sin acceso a: {', '.join(caidos)}",
            "arreglo": "puede ser algo puntual de ese servicio, o tu red "
                       "bloqueando ese puerto"}


def _revisar_suricata(cfg) -> list[dict]:
    """Que esté MIRANDO y no cortando, y que el equipo lo aguante.

    Fase 1 del punto 9. Suricata es opcional y por eso, cuando no está, sale
    una sola fila que lo dice en vez de cuatro renglones grises sobre algo que
    elegiste no instalar.
    """
    from . import suricata

    externos = getattr(cfg, "externos", None)
    return suricata.revisar(
        getattr(externos, "suricata_eve", "") or "",
        getattr(externos, "suricata_yaml", "") or suricata.RUTA_YAML_POR_DEFECTO)


def _revisar_gateway(cfg=None) -> list[dict]:
    """Si esta máquina es el router de la casa, que lo sea bien.

    Punto 10. Cuando no reenvía sale una sola fila que lo dice: la mayoría de
    las instalaciones no son el router de nadie.
    """
    from . import gateway

    externos = getattr(cfg, "externos", None)
    try:
        return gateway.revisar(getattr(externos, "pihole_db", "") or "")
    except Exception as exc:  # noqa: BLE001 - el diagnóstico no se cae por esto
        return [{"nombre": "Gateway", "estado": AVISO,
                 "detalle": f"no pude revisarlo: {exc}", "arreglo": ""}]


def revisar(cfg, projects, timeout: float = TIMEOUT,
            internet: list[dict] | None = None) -> list[dict]:
    """Todas las verificaciones. Nunca lanza."""
    health = state_snapshot(cfg)
    revisiones = _revisar_proyectos(projects, health)
    revisiones.append(_revisar_puertos(cfg))
    revisiones.append(_revisar_feeds(projects))
    revisiones.append(_revisar_internet(timeout, internet))
    revisiones.append(_revisar_disco())
    revisiones.append(_revisar_memoria())
    revisiones.append(_revisar_psutil())
    revisiones.extend(_revisar_suricata(cfg))
    revisiones.extend(_revisar_gateway(cfg))
    # Las capacidades del sistema van al final, con el mismo formato, así que
    # se muestran solas en la pestaña. Las que no aplican entran con estado NA
    # y no restan puntaje: no aplicar no es una falla, es un dato.
    from . import capacidades as mod_cap

    revisiones.extend(mod_cap.todas(cfg, projects))
    return revisiones


def puntaje(revisiones: list[dict]) -> int:
    """De 100 para abajo. Lo que no aplica no resta."""
    total = 100
    for r in revisiones:
        total -= PESOS.get(r["estado"], 0)
    return max(0, total)


def resumen(revisiones: list[dict]) -> str:
    """Una frase que diga qué hacer, no cuántas cosas fallaron."""
    malas = [r for r in revisiones if r["estado"] == MAL]
    avisos = [r for r in revisiones if r["estado"] == AVISO]
    if malas:
        cantidad = "1 problema" if len(malas) == 1 else f"{len(malas)} problemas"
        return f"Hay {cantidad}: {', '.join(r['nombre'] for r in malas)}."
    if avisos:
        cantidad = "1 aviso" if len(avisos) == 1 else f"{len(avisos)} avisos"
        return (f"Nada roto. Hay {cantidad} para revisar cuando puedas: "
                f"{', '.join(r['nombre'] for r in avisos)}.")
    return "Todo en orden."
