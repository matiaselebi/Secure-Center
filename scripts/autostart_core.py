#!/usr/bin/env python3
"""Relanza el stack en cada inicio de Windows.

Lo ejecuta la tarea programada 'SecureCenterCoreAutostart'. Levanta:

- **SecureProxy y SecureDNS** (el núcleo "siempre prendido"). Sus dashboards
  viven dentro del mismo proceso, así que vuelven solos con ellos. El proxy y
  el DNS del sistema (registro / adaptadores) ya quedaron configurados cuando
  encendiste el núcleo, y Windows los recuerda entre reinicios.
- **El dashboard de SecureVPN, pero SOLO si la VPN quedó encendida.** El túnel
  se instala como servicio de Windows, así que sobrevive al reinicio; su
  dashboard, en cambio, es un proceso aparte que hay que relanzar. Si el túnel
  no está, no se levanta nada: la VPN nunca se enciende sola (ADR 0001 de
  SecureVPN y decisión de diseño de SecureCenter).

El dashboard de SecureCenter tiene su propia tarea programada, registrada por
SecureCenter.bat.
"""

import sys

from _common import PROJECT_ROOT  # noqa: F401  (fija el sys.path)
from _common import build_orchestrator

from securecenter.procutil import popen_quiet, port_in_use, windows_service_running  # noqa: E402


def _lanzar(project, script_rel: str) -> bool:
    python = project.venv_python(windowless=True)
    script = project.script(script_rel)
    if python is None or script is None:
        return False
    popen_quiet([str(python), str(script)], cwd=str(project.folder))
    return True


def main() -> int:
    o = build_orchestrator()

    # 1) Núcleo: proxy + DNS (con sus dashboards adentro).
    for key, script, port in (
        ("proxy", "scripts/run_proxy.py", o.cfg.ports.proxy_service),
        ("dns", "scripts/run_dns.py", o.cfg.ports.dns_dashboard),
    ):
        project = o.projects.get(key)
        if project is None or not project.found:
            continue
        if port_in_use(port):
            continue  # ya está corriendo: no duplicar
        _lanzar(project, script)

    # 2) Dashboard de la VPN, solo si el túnel quedó instalado y corriendo.
    vpn = o.projects.get("vpn")
    if vpn is not None and vpn.found and not port_in_use(o.cfg.ports.vpn_dashboard):
        interfaz = "securevpn"  # nombre por defecto de la interfaz del túnel
        if windows_service_running(f"WireGuardTunnel${interfaz}"):
            _lanzar(vpn, "scripts/run_dashboard.py")

    return 0


if __name__ == "__main__":
    sys.exit(main())
