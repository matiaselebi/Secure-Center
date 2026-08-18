#!/usr/bin/env python3
"""Relanza el núcleo en cada inicio de la máquina.

Lo ejecuta la tarea programada `SecureCenterCoreAutostart` (o la unidad de
systemd, en Linux).

EL BUG QUE ESTE ARCHIVO TENÍA, Y QUE COSTÓ CARO

Tenía la lista del núcleo escrita a mano, y decía "proxy y dns". Se escribió
así el día uno, cuando el núcleo eran esos dos, y ahí se quedó: entró
SecureHIPS y no se tocó, entró Secure-Intel y no se tocó, entraron
Secure-Scanner y Secure-Agent y tampoco.

El resultado es la peor forma de fallar que puede tener esto. Encendías el
núcleo, arrancaban los seis, el panel te lo confirmaba. Apagabas la máquina.
La prendías al otro día y volvían DOS. Sin un error, sin un aviso, y con un
panel que decía la verdad sobre un estado que ya no era el que habías dejado:
cuatro de los seis servicios te estaban protegiendo hasta que reiniciaste, que
es justo cuando dejás de mirar.

Ahora la lista sale de `SERVICIOS_DEL_NUCLEO`, que es la MISMA que usan el
plan de encendido y el de apagado. Hay un test que lo ata.

POR QUÉ NO SE USA `plan_start_core()` DIRECTAMENTE

Porque ese plan además libera puertos, toca el registro de Windows para el
proxy del sistema y vuelve a registrar la tarea programada. En un arranque
todo eso ya está hecho, y hacerlo de nuevo es pedir problemas justo cuando
nadie está mirando. Acá se levanta lo que falta y nada más.

POR QUÉ HAY UN SEGUNDO INTENTO

Porque un arranque de Windows es una carrera. La red puede no estar lista,
OneDrive puede estar todavía bajando los archivos del proyecto, el antivirus
puede estar revisando el disco. Un servicio que falla por eso a los diez
segundos arranca perfecto a los cuarenta, y reintentar una vez sale mucho más
barato que descubrir tres días después que quedaste con la mitad del stack.
"""

import sys
import time

from _common import build_orchestrator

from securecenter.orchestrator import SERVICIOS_DEL_NUCLEO  # noqa: E402
from securecenter.procutil import (  # noqa: E402
    popen_quiet,
    port_in_use,
    windows_service_running,
)

# Cuánto se espera antes del segundo intento. Cuarenta segundos alcanzan para
# que termine de levantar la red y para que OneDrive deje de pelear con los
# archivos, sin que el arranque se sienta lento.
ESPERA_ANTES_DE_REINTENTAR = 40

# Cuánto se le da al conjunto para abrir sus puertos antes de darlo por caído.
# Los de esta suite abren en menos de dos segundos cuando pueden.
ESPERA_POR_SERVICIO = 12


def _puerto_de(orquestador, clave: str):
    return orquestador._puertos_del_nucleo().get(clave)


def _lanzar(orquestador, clave: str, run: str) -> bool:
    project = orquestador.projects.get(clave)
    if project is None or not project.found:
        return False
    python = project.venv_python(windowless=True)
    script = project.script(run)
    if python is None or script is None:
        return False
    # Con log: sin esto, un servicio que arranca, dice por qué no puede seguir
    # y se muere deja el mismo rastro que uno que arrancó bien. Y en el
    # arranque de la máquina no hay nadie mirando una consola.
    popen_quiet([str(python), "-u", str(script)], cwd=str(project.folder),
                log=str(orquestador.ruta_de_arranque(clave)))
    return True


def faltantes(orquestador) -> list:
    """Los del núcleo que están instalados y NO están escuchando."""
    pendientes = []
    for clave, nombre, run, _stop in SERVICIOS_DEL_NUCLEO:
        project = orquestador.projects.get(clave)
        if project is None or not project.found:
            continue
        puerto = _puerto_de(orquestador, clave)
        if puerto is None or port_in_use(puerto):
            continue
        pendientes.append((clave, nombre, run, puerto))
    return pendientes


def una_vuelta(orquestador, intento: int) -> list:
    pendientes = faltantes(orquestador)
    for clave, nombre, run, _puerto in pendientes:
        if _lanzar(orquestador, clave, run):
            print(f"[SecureCenter] intento {intento}: lanzando {nombre}")
    if pendientes:
        # Se espera una sola vez para todos y no por cada uno: arrancan en
        # paralelo, y sumar las esperas alargaría el arranque sin motivo.
        time.sleep(min(ESPERA_POR_SERVICIO, 3 + len(pendientes)))
    return faltantes(orquestador)


def main() -> int:
    o = build_orchestrator()

    quedan = una_vuelta(o, 1)
    if quedan:
        print("[SecureCenter] no arrancaron: "
              + ", ".join(n for _c, n, _r, _p in quedan)
              + ". Espero y reintento.")
        time.sleep(ESPERA_ANTES_DE_REINTENTAR)
        quedan = una_vuelta(o, 2)

    # El dashboard de la VPN, solo si el túnel quedó instalado y corriendo. La
    # VPN nunca se enciende sola (ADR 0001 de SecureVPN); lo que se relanza es
    # su panel, que es un proceso aparte y no sobrevive al reinicio.
    vpn = o.projects.get("vpn")
    if vpn is not None and vpn.found and not port_in_use(o.cfg.ports.vpn_dashboard):
        if windows_service_running("WireGuardTunnel$securevpn"):
            _lanzar(o, "vpn", "scripts/run_dashboard.py")

    if not quedan:
        print("[SecureCenter] núcleo arriba.")
        return 0

    # Queda escrito en el historial de SecureCenter, que es lo que se mira
    # después. Un arranque que falló y no dejó rastro es indistinguible de uno
    # que nunca corrió.
    detalle = ", ".join(f"{n} (mirá data/arranque-{c}.log)"
                        for c, n, _r, _p in quedan)
    print(f"[SecureCenter] NO arrancaron: {detalle}")
    try:
        o.logger_db.log_event("arranque automático incompleto", detalle, ok=False)
    except Exception:  # noqa: BLE001 - el arranque no se cae por el log
        pass
    return 1


if __name__ == "__main__":
    sys.exit(main())
