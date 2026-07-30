#!/usr/bin/env python3
"""Apaga los dashboards que son procesos aparte, sin tocar los servicios.

Cuáles son "aparte" y cuáles no:

- **SecureCenter (8899)** y **SecureVPN (8891)**: procesos independientes. Se
  pueden apagar dejando el resto funcionando.
- **SecureProxy (8888)** y **SecureDNS (8890)**: su dashboard vive DENTRO del
  mismo proceso que hace el trabajo. Apagar ese dashboard sería apagar el
  filtrado, así que no se tocan acá; para eso está "Apagar todo".

Útil para liberar las páginas web y las ventanas del navegador sin perder la
protección del núcleo ni el túnel.
"""

import sys

from _common import build_orchestrator

from securecenter.procutil import free_port, port_in_use  # noqa: E402


def main() -> int:
    o = build_orchestrator()
    objetivos = [
        ("SecureCenter", o.cfg.ports.center_dashboard),
        ("SecureVPN", o.cfg.ports.vpn_dashboard),
    ]

    apagados = []
    problemas = []
    for nombre, port in objetivos:
        if not port_in_use(port):
            print(f"[SecureCenter] {nombre} ({port}): su dashboard no estaba corriendo.")
            continue
        ok, detalle = free_port(port)
        if ok:
            apagados.append(f"{nombre} ({port})")
            print(f"[SecureCenter] {nombre} ({port}): dashboard apagado.")
        else:
            problemas.append(f"{nombre}: {detalle}")
            print(f"[SecureCenter] ERROR con {nombre} ({port}): {detalle}")

    print()
    if apagados:
        print(f"[SecureCenter] Dashboards apagados: {', '.join(apagados)}.")
    if problemas:
        print("[SecureCenter] Quedaron problemas; probá de nuevo o usá PANICO.")
    print(
        "[SecureCenter] Los dashboards de SecureProxy y SecureDNS NO se tocan: "
        "viven dentro del mismo proceso que filtra, así que apagarlos sería "
        "apagar la protección (para eso está 'Apagar TODO')."
    )
    o.logger_db.log_event(
        "stop_dashboards",
        f"apagados: {', '.join(apagados) or 'ninguno'}",
        ok=not problemas,
    )
    return 1 if problemas else 0


if __name__ == "__main__":
    sys.exit(main())
