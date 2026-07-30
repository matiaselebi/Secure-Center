#!/usr/bin/env python3
"""Enciende el núcleo (SecureProxy + SecureDNS) y les activa el inicio
automático con Windows. Idempotente: si ya estaba corriendo, lo reinicia
para dejar un estado limpio y lo avisa."""

import sys

from _common import build_orchestrator, esperar_estado, estado, print_result


def main() -> int:
    o = build_orchestrator()
    antes = estado(o)
    if antes["proxy"] and antes["dns"]:
        print("[SecureCenter] El núcleo ya estaba corriendo; lo reinicio para dejar el estado limpio.")
    else:
        print("[SecureCenter] Encendiendo el núcleo (SecureProxy + SecureDNS)...")

    result = o.execute(o.plan_start_core(), "start_core")
    print_result(result)

    despues = esperar_estado(o, arriba=True, keys=["proxy", "dns"])
    if despues["proxy"] and despues["dns"]:
        print("[SecureCenter] NÚCLEO ACTIVO: SecureProxy y SecureDNS corriendo. Todo listo.")
        return 0
    faltan = [n for n, k in (("SecureProxy", "proxy"), ("SecureDNS", "dns")) if not despues[k]]
    print(f"[SecureCenter] AVISO: el núcleo no quedó del todo arriba (falta: {', '.join(faltan)}).")
    print("[SecureCenter] Probá 'python scripts/run_dashboard.py' o el run de ese proyecto a mano para ver el error.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
