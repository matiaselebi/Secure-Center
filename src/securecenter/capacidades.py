"""Qué puede hacer la suite EN ESTA máquina, y qué no.

POR QUÉ EXISTE

Porque la mitad de lo que hace SecureCenter depende del sistema, y hasta ahora
lo que no aplicaba simplemente no pasaba: `if not _is_windows(): return []`.
El plan salía todo en verde y el panel mostraba los mismos botones de siempre.
Alguien en un Debian sin pantalla apretaba "encender núcleo", veía todo OK, y
creía que su proxy del sistema estaba configurado. No lo estaba.

La regla 10 de la hoja de ruta dice justo esto: nada dice que está protegiendo
si no lo está. Una capacidad que no existe acá tiene que aparecer escrita como
"no aplica", con el motivo, y sin restar puntaje. No mostrar un botón muerto y
tampoco esconder el tema.

CÓMO SE ENGANCHA

Cada capacidad se devuelve con la misma forma que usa `diagnostico.py`
(nombre, estado, detalle, arreglo). Así entran solas en la pestaña de
diagnóstico, se muestran con el mismo formato que el resto, y el estado `NA`
ya está contemplado en el puntaje: lo que no aplica no resta.
"""

import os
import platform
import shutil
from pathlib import Path

OK, AVISO, NA = "ok", "aviso", "na"


def _es_windows() -> bool:
    return platform.system() == "Windows"


def _hay_escritorio() -> bool:
    """¿Hay una sesión gráfica donde mostrar algo?

    En Windows se asume que sí. En Linux se mira si hay servidor gráfico: en
    un servidor headless no lo hay, y ahí una notificación de escritorio no es
    que falle, es que no tiene a dónde ir.
    """
    if _es_windows():
        return True
    return bool(os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"))


def alcance_del_proxy() -> dict:
    """Dónde tiene sentido prender SecureProxy.

    Es un proxy EXPLÍCITO: cubre a los programas configurados para pasar por
    él. En una PC eso funciona porque acá se pone el proxy del sistema y el
    navegador lo hereda. En un servidor no hay a quién configurar: el celular,
    la consola y el televisor no tienen dónde ponerle un proxy, y prenderlo
    igual da un panel con números que parecen de toda la casa y son del propio
    servidor.

    La decisión está escrita en `alcance.py` de SecureProxy, que es quien la
    imprime al arrancar. Acá se responde la misma pregunta con la misma señal
    (¿hay sesión gráfica?) porque SecureCenter tiene que poder armar el plan
    sin importar código del otro proyecto, y esa señal es una línea. Lo que no
    se duplica es la lógica: si algún día cambia el criterio, el que manda es
    el archivo de SecureProxy y esto lo sigue.
    """
    if _hay_escritorio():
        return {"nombre": "Alcance de SecureProxy", "estado": OK,
                "detalle": ("equipo de escritorio: el proxy del sistema hace "
                            "que el navegador pase por SecureProxy"),
                "arreglo": ""}
    return {
        "nombre": "Alcance de SecureProxy", "estado": NA,
        "detalle": ("este equipo no tiene escritorio. SecureProxy solo cubre "
                    "programas configurados para pasar por él, y a un celular "
                    "o una consola no hay dónde configurárselo. Acá no lo "
                    "prendo: el que cubre a toda la casa es SecureDNS sobre "
                    "Pi-hole, que los equipos agarran del router"),
        "arreglo": "corré SecureProxy en tu PC de escritorio",
    }


def proxy_del_sistema() -> dict:
    """Poner SecureProxy como proxy de todo el sistema."""
    if _es_windows():
        return {"nombre": "Proxy del sistema", "estado": OK,
                "detalle": "se configura por el registro de Windows (HKCU)",
                "arreglo": ""}
    return {
        "nombre": "Proxy del sistema", "estado": NA,
        "detalle": ("no lo configuro en Linux: no hay un lugar único como el "
                    "registro de Windows. El proxy sigue funcionando, pero hay "
                    "que apuntarle las aplicaciones a mano"),
        "arreglo": ("exportá http_proxy y https_proxy apuntando a "
                    "127.0.0.1:8888, o configuralo en el navegador"),
    }


def dns_del_sistema(cfg=None, projects=None) -> dict:
    """Apuntar el DNS de la máquina a SecureDNS.

    Tiene DOS motivos para no aplicar y los dos importan. Uno es el sistema.
    El otro es el modo de SecureDNS: desde que puede correr sobre Pi-hole, el
    que tiene que estar en el adaptador es Pi-hole, y ponerse 127.0.0.1 sería
    apuntar a un puerto donde no escucha nadie.
    """
    if not _es_windows():
        return {"nombre": "DNS del sistema", "estado": NA,
                "detalle": ("no lo configuro en Linux; lo maneja el sistema "
                            "(resolv.conf / systemd-resolved) o Pi-hole"),
                "arreglo": ""}
    return {"nombre": "DNS del sistema", "estado": OK,
            "detalle": "lo configura SecureDNS, que es el único que lo toca",
            "arreglo": ""}


def arranque_automatico(cfg=None) -> dict:
    """Que el núcleo levante solo con la máquina."""
    from . import arranque

    backend = arranque.elegir(cfg)
    if not backend.disponible:
        return {"nombre": "Arranque automático", "estado": NA,
                "detalle": "; ".join(backend.avisos()) or "no disponible acá",
                "arreglo": ""}
    avisos = backend.avisos()
    if avisos:
        # El caso del linger: se puede instalar Y no va a arrancar. Es un
        # aviso, no un "no aplica": la capacidad existe, le falta un paso.
        return {"nombre": "Arranque automático", "estado": AVISO,
                "detalle": avisos[0], "arreglo": ""}
    como = ("tarea programada al iniciar sesión" if backend.sistema == "Windows"
            else "unidad de systemd")
    return {"nombre": "Arranque automático", "estado": OK,
            "detalle": como, "arreglo": ""}


def notificaciones_escritorio() -> dict:
    """Los avisos que aparecen en una esquina de la pantalla."""
    if _hay_escritorio():
        return {"nombre": "Avisos de escritorio", "estado": OK,
                "detalle": "hay sesión gráfica", "arreglo": ""}
    return {
        "nombre": "Avisos de escritorio", "estado": NA,
        "detalle": ("este equipo no tiene pantalla, así que un aviso de "
                    "escritorio no tiene a dónde ir. Los avisos igual quedan "
                    "en el historial y en el panel"),
        "arreglo": "para que te lleguen afuera, activá Telegram en SecureDNS",
    }


def elevacion() -> dict:
    """Poder pedir permisos de administrador cuando hace falta."""
    if _es_windows():
        return {"nombre": "Permisos de administrador", "estado": OK,
                "detalle": "se piden con UAC cuando hacen falta", "arreglo": ""}
    if os.geteuid() == 0 if hasattr(os, "geteuid") else False:
        return {"nombre": "Permisos de administrador", "estado": OK,
                "detalle": "ya corrés como root", "arreglo": ""}
    if shutil.which("sudo"):
        return {"nombre": "Permisos de administrador", "estado": OK,
                "detalle": "hay sudo para lo que lo necesite", "arreglo": ""}
    return {"nombre": "Permisos de administrador", "estado": AVISO,
            "detalle": "no sos root y no hay sudo: el firewall no se va a poder tocar",
            "arreglo": "instalá sudo o corré la suite como root"}


def vpn() -> dict:
    """El túnel de SecureVPN."""
    if _es_windows():
        if Path(r"C:\Program Files\WireGuard\wireguard.exe").exists():
            return {"nombre": "VPN", "estado": OK,
                    "detalle": "WireGuard instalado", "arreglo": ""}
        return {"nombre": "VPN", "estado": AVISO,
                "detalle": "falta la app oficial de WireGuard",
                "arreglo": "instalala desde wireguard.com/install"}
    return {
        "nombre": "VPN", "estado": NA,
        "detalle": ("SecureVPN está hecha contra la app de WireGuard de "
                    "Windows y el kill switch de su firewall: en Linux no "
                    "corre. Es una decisión, no algo que falte"),
        "arreglo": "",
    }


def abrir_navegador() -> dict:
    if _hay_escritorio():
        return {"nombre": "Abrir el panel solo", "estado": OK,
                "detalle": "hay navegador", "arreglo": ""}
    return {"nombre": "Abrir el panel solo", "estado": NA,
            "detalle": "sin escritorio no hay navegador que abrir",
            "arreglo": "entrá desde otra máquina por SSH con reenvío de puerto"}


def todas(cfg=None, projects=None) -> list:
    """Todas las capacidades, en el formato de `diagnostico.py`."""
    return [
        alcance_del_proxy(),
        proxy_del_sistema(),
        dns_del_sistema(cfg, projects),
        arranque_automatico(cfg),
        notificaciones_escritorio(),
        elevacion(),
        vpn(),
        abrir_navegador(),
    ]


def resumen(cfg=None, projects=None) -> dict:
    """Un renglón para la consola y para el encabezado del panel."""
    lista = todas(cfg, projects)
    no_aplican = [c["nombre"] for c in lista if c["estado"] == NA]
    return {
        "sistema": f"{platform.system()} {platform.release()}".strip(),
        "escritorio": _hay_escritorio(),
        "capacidades": lista,
        "no_aplican": no_aplican,
        "texto": ("todo aplica en este equipo" if not no_aplican else
                  "acá no aplica: " + ", ".join(no_aplican)),
    }
