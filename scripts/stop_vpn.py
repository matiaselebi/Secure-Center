#!/usr/bin/env python3
"""Apaga solo la VPN: desconecta el túnel (revirtiendo el kill switch), baja
el laboratorio y detiene su dashboard. Si no estaba corriendo, igual limpia
por las dudas y lo avisa, sin colgarse."""

import sys

from _common import build_orchestrator, esperar_estado, estado, print_result


def main() -> int:
    o = build_orchestrator()
    if not estado(o)["vpn"]:
        print("[SecureCenter] La VPN no parecía estar corriendo; igual limpio túnel/kill switch/laboratorio por las dudas...")
    else:
        print("[SecureCenter] Apagando la VPN...")

    result = o.execute(o.plan_stop_vpn(), "stop_vpn")
    print_result(result)

    if not esperar_estado(o, arriba=False, keys=["vpn"], timeout=2.0)["vpn"]:
        print("[SecureCenter] VPN APAGADA y verificada.")
        return 0
    print("[SecureCenter] AVISO: la VPN sigue arriba. Reintentá, o usá PÁNICO (opción 7).")
    return 1


if __name__ == "__main__":
    sys.exit(main())
