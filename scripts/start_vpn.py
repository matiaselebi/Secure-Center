#!/usr/bin/env python3
"""Enciende la VPN en un solo paso: levanta el laboratorio, aprovisiona el
servidor y conecta el túnel. Idempotente: si ya estaba, lo avisa y reintenta
para dejar el estado consistente."""

import sys

from _common import build_orchestrator, esperar_estado, estado, print_result


def main() -> int:
    o = build_orchestrator()
    if estado(o)["vpn"]:
        print("[SecureCenter] La VPN ya estaba encendida; reintento para asegurar el estado.")
    else:
        print("[SecureCenter] Encendiendo la VPN (laboratorio -> aprovisionar -> conectar)...")
    print("[SecureCenter] La primera vez tarda unos minutos; no cierres la ventana.")

    result = o.execute(o.plan_start_vpn(), "start_vpn")
    print_result(result)

    if esperar_estado(o, arriba=True, keys=["vpn"], timeout=3.0)["vpn"]:
        print("[SecureCenter] VPN ACTIVA: dashboard arriba. Mirá el handshake en http://127.0.0.1:8891/")
        return 0
    print("[SecureCenter] AVISO: la VPN no quedó arriba (¿handshake? ¿laboratorio? ¿WireGuard instalado?).")
    return 1


if __name__ == "__main__":
    sys.exit(main())
