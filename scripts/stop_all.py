#!/usr/bin/env python3
"""Apaga TODO: núcleo y, si estaba corriendo, también la VPN. Si no había
nada corriendo, igual limpia tareas y ajustes del sistema y lo avisa, sin
quedarse colgado."""

import sys

from _common import build_orchestrator, esperar_estado, estado, print_result


def main() -> int:
    o = build_orchestrator()
    antes = estado(o)
    if not any(antes.values()):
        print("[SecureCenter] No había nada corriendo; igual limpio tareas y ajustes del sistema por las dudas...")
    else:
        print("[SecureCenter] Apagando todo...")

    result = o.execute(o.plan_stop_all(), "stop_all")
    print_result(result)

    despues = esperar_estado(o, arriba=False, keys=["proxy", "dns", "vpn"], timeout=2.0)
    if not any(despues.values()):
        print("[SecureCenter] TODO APAGADO y verificado (proxy, DNS y VPN abajo).")
        return 0
    quedan = [n for n, k in (("SecureProxy", "proxy"), ("SecureDNS", "dns"), ("SecureVPN", "vpn")) if despues[k]]
    print(f"[SecureCenter] AVISO: sigue arriba: {', '.join(quedan)}. Reintentá 'Apagar todo' o usá PÁNICO (opción 7).")
    return 1


if __name__ == "__main__":
    sys.exit(main())
