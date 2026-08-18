#!/usr/bin/env python3
"""Apaga los dashboards que son procesos aparte, sin tocar los servicios.

Cuáles son "aparte" y cuáles no:

- **SecureCenter (8899)** y **SecureVPN (8891)**: procesos independientes. Se
  pueden apagar dejando el resto funcionando.
- **Secure-Intel (8893)**: acá el panel ES casi todo el proceso, así que
  apagarlo apaga Secure-Intel entero. Y está bien: no deja a nadie sin
  protección, porque los feeds que ya bajó siguen en la base y en los archivos
  exportados, y los otros tres los leen igual. Lo único que se pierde es que
  se pongan al día solos. Se apaga con su `stop_intel.py` y no matando el
  puerto, para que si justo estaba actualizando termine la transacción en vez
  de dejar el WAL a medias.
- **SecureProxy (8888)**, **SecureDNS (8890)** y **SecureHIPS (8892)**: su
  dashboard vive DENTRO del mismo proceso que hace el trabajo. Apagar ese
  dashboard sería apagar el filtrado o la vigilancia, así que no se tocan acá;
  para eso está "Apagar todo".

  En el caso del HIPS hay una razón extra y peor: matarlo por puerto le deja
  las reglas puestas en el firewall, y sin nadie corriendo que las levante
  cuando venzan. O sea alguien bloqueado para siempre por un programa que ya
  no existe. Por eso el HIPS se apaga solo con su `stop_hips.py`, que le pide
  el apagado ordenado.

Útil para liberar las páginas web y las ventanas del navegador sin perder la
protección del núcleo ni el túnel.
"""

import subprocess
import sys

from _common import build_orchestrator

from securecenter.procutil import free_port, port_in_use  # noqa: E402


def _apagar_intel(o) -> None:
    """Apagado ordenado de Secure-Intel, con el kill por puerto de respaldo."""
    puerto = o.cfg.ports.intel_dashboard
    intel = o.projects.get("intel")
    if intel is None or not intel.found or not port_in_use(puerto):
        return
    script = intel.script("scripts/stop_intel.py")
    python = intel.venv_python()
    if script is not None and python is not None:
        try:
            subprocess.run([str(python), str(script)], timeout=20,
                           capture_output=True, check=False)
        except (OSError, subprocess.SubprocessError) as exc:
            print(f"[SecureCenter] Secure-Intel: no pude pedirle el apagado ({exc})")
    if port_in_use(puerto):
        # No contestó: se libera el puerto igual. Acá se puede, porque
        # Secure-Intel no deja nada puesto en el sistema al morir de golpe.
        free_port(puerto)
    print(f"[SecureCenter] Secure-Intel ({puerto}): dashboard apagado.")


def main() -> int:
    o = build_orchestrator()
    # Secure-Intel primero y por su propio script: el apagado ordenado deja
    # terminar una actualización en curso. Los otros dos se liberan por puerto.
    _apagar_intel(o)

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
        "[SecureCenter] Los dashboards de SecureProxy, SecureDNS y SecureHIPS "
        "NO se tocan: viven dentro del mismo proceso que hace el trabajo, así "
        "que apagarlos sería apagar la protección (para eso está 'Apagar "
        "TODO'). El del HIPS además le dejaría las reglas puestas en el "
        "firewall sin nadie que las levante."
    )
    o.logger_db.log_event(
        "stop_dashboards",
        f"apagados: {', '.join(apagados) or 'ninguno'}",
        ok=not problemas,
    )
    return 1 if problemas else 0


if __name__ == "__main__":
    sys.exit(main())
