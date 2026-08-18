#!/usr/bin/env python3
"""Prender o apagar UN servicio, por nombre.

    python scripts/servicio.py encender scanner
    python scripts/servicio.py apagar agente

POR QUÉ EXISTE

Porque Secure-Scanner y Secure-Agent no están en el núcleo, y hasta ahora la
única forma de prenderlos era el panel web. Eso está bien mientras el panel
esté arriba; el problema es justo cuando no lo está, o cuando estás por SSH
sin reenvío de puertos, que es exactamente el caso del servidor.

El menú (`.bat` y `.sh`) llama a esto.

POR QUÉ NO ESTÁN EN EL NÚCLEO

Escanear la red y recibir telemetría de otras máquinas son cosas que se
prenden cuando las querés, no todo el día. El scanner manda paquetes a
equipos que no son tuyos (la impresora, el televisor de otro) y el servidor
de agentes es la única pieza de la suite que escucha fuera de esta máquina.
Ninguna de las dos tiene que arrancar sola porque sí.

Lo que sí hace "apagar TODO" es apagarlos: un botón que dice TODO y deja dos
servicios corriendo es la clase de mentira que hace que después nadie confíe
en el panel.
"""

import sys

from _common import build_orchestrator, esperar_estado, print_result

from securecenter.projects import PROJECT_SPECS  # noqa: E402

NOMBRES = {s.key: s.display_name for s in PROJECT_SPECS}
VERBOS = ("encender", "apagar", "reiniciar")


def _uso() -> int:
    print("Uso: python scripts/servicio.py <encender|apagar|reiniciar> <servicio>")
    print(f"Servicios: {', '.join(sorted(NOMBRES))}")
    return 2


def main(argv: list) -> int:
    if len(argv) != 2:
        return _uso()
    verbo, clave = argv[0].strip().lower(), argv[1].strip().lower()
    if verbo not in VERBOS or clave not in NOMBRES:
        return _uso()

    o = build_orchestrator()
    project = o.projects.get(clave)
    if project is None or not project.found:
        # No es un error del programa: es un proyecto que no está instalado, y
        # decirlo así evita que alguien busque el problema en otro lado.
        print(f"[SecureCenter] No encontré {NOMBRES[clave]} en el disco. "
              "Revisá config/config.yaml o clonalo como carpeta hermana.")
        return 1

    nombre = NOMBRES[clave]
    if verbo == "apagar":
        pasos = o.plan_stop_one(clave)
    elif verbo == "reiniciar":
        # Apagar y encender en una sola operación, no dos comandos: entre uno
        # y otro el usuario se puede ir, y quedaría todo apagado creyendo que
        # reinició.
        pasos = o.plan_stop_one(clave) + o.plan_start_one(clave)
    else:
        pasos = o.plan_start_one(clave)

    if not pasos:
        print(f"[SecureCenter] No hay nada que hacer con {nombre}.")
        return 1

    print(f"[SecureCenter] {verbo.capitalize()} {nombre}...")
    codigo = print_result(o.execute(pasos, f"{verbo}_{clave}"))

    # Y se dice cómo quedó, que no es lo mismo que si el plan salió bien: un
    # servicio puede arrancar, imprimir un error y morirse al segundo.
    estado = esperar_estado(o, arriba=(verbo != "apagar"), keys=[clave])
    vivo = bool(estado.get(clave))
    if verbo == "apagar":
        print(f"[SecureCenter] {nombre}: {'apagado' if not vivo else 'SIGUE CORRIENDO'}")
        return 0 if not vivo else 1
    if vivo:
        print(f"[SecureCenter] {nombre}: corriendo.")
        return 0
    print(f"[SecureCenter] {nombre} NO quedó arriba. Corré su run_*.py a mano "
          "en una consola para ver el error.")
    return codigo or 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
