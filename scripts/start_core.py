#!/usr/bin/env python3
"""Enciende el núcleo y le activa el inicio automático con Windows.

Idempotente: si ya estaba corriendo, lo reinicia para dejar un estado limpio
y lo avisa.

Qué es "el núcleo" NO se escribe acá: sale de `CLAVES_DEL_NUCLEO`. Antes
estaba puesto a mano ("SecureProxy + SecureDNS") y quedó viejo dos veces
seguidas, cuando entraron SecureHIPS y Secure-Intel: el mensaje decía que
todo estaba listo nombrando dos de cuatro.
"""

import sys

from _common import build_orchestrator, esperar_estado, estado, print_result

from securecenter.orchestrator import CLAVES_DEL_NUCLEO  # noqa: E402
from securecenter.projects import PROJECT_SPECS  # noqa: E402

NOMBRES = {s.key: s.display_name for s in PROJECT_SPECS}


def _lista(claves) -> str:
    """«SecureProxy, SecureDNS y SecureHIPS», con la «y» donde va."""
    nombres = [NOMBRES.get(k, k) for k in claves]
    if len(nombres) <= 1:
        return "".join(nombres)
    return ", ".join(nombres[:-1]) + " y " + nombres[-1]


def main() -> int:
    o = build_orchestrator()
    # Solo los que están instalados: pedirle a alguien que instale
    # Secure-Intel para poder encender el núcleo sería absurdo.
    claves = [k for k in CLAVES_DEL_NUCLEO
              if (p := o.projects.get(k)) is not None and p.found]
    if not claves:
        print("[SecureCenter] No encontré ningún proyecto del núcleo. "
              "Revisá config/config.yaml.")
        return 1

    antes = estado(o)
    if all(antes.get(k) for k in claves):
        print("[SecureCenter] El núcleo ya estaba corriendo; lo reinicio para "
              "dejar el estado limpio.")
    else:
        print(f"[SecureCenter] Encendiendo el núcleo ({_lista(claves)})...")

    faltan_venv = [NOMBRES.get(k, k) for k in claves
                   if o.projects[k].falta_el_venv()]
    if faltan_venv:
        # Antes de arrancar y no después: así se ve arriba de todo y no
        # perdido entre veinte líneas de salida.
        print(f"[SecureCenter] AVISO: sin entorno virtual: {', '.join(faltan_venv)}. "
              "Van a fallar hasta que les corras: python -m venv venv")

    result = o.execute(o.plan_start_core(), "start_core")
    print_result(result)

    despues = esperar_estado(o, arriba=True, keys=claves)
    arriba = [k for k in claves if despues.get(k)]
    faltan = [NOMBRES.get(k, k) for k in claves if not despues.get(k)]
    if not faltan:
        print(f"[SecureCenter] NÚCLEO ACTIVO: {_lista(arriba)} corriendo. Todo listo.")
        return 0
    print(f"[SecureCenter] AVISO: el núcleo no quedó del todo arriba "
          f"(falta: {', '.join(faltan)}).")
    print("[SecureCenter] Probá el run de ese proyecto a mano para ver el error, "
          "o revisá que tenga su venv creado.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
