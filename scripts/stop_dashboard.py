#!/usr/bin/env python3
"""Detiene el dashboard de SecureCenter usando el PID guardado.

El PID se valida antes de terminarlo. Un archivo PID que quedó de un cierre
brusco puede apuntar, después de un reinicio o con el paso del tiempo, a un
proceso completamente distinto. Matarlo a ciegas es peor que dejar el panel
encendido.
"""

import json
import platform
import subprocess
import sys
from pathlib import Path

import psutil

PROJECT_ROOT = Path(__file__).resolve().parent.parent
PID_FILE = PROJECT_ROOT / "data" / "dashboard.pid"
EXPECTED_SCRIPT = (PROJECT_ROOT / "scripts" / "run_dashboard.py").resolve()


def _es_nuestro_dashboard(
        pid: int, script: str, create_time: float) -> tuple[bool, str]:
    try:
        if Path(script).resolve() != EXPECTED_SCRIPT:
            return False, "la ruta guardada pertenece a otro dashboard"
    except (OSError, TypeError, ValueError):
        return False, "la ruta guardada no es válida"

    try:
        proc = psutil.Process(pid)
        cmdline = proc.cmdline()
        if abs(proc.create_time() - create_time) > 0.001:
            return False, "el PID fue reutilizado por otro proceso"
    except psutil.NoSuchProcess:
        return False, "el proceso ya no existe"
    except (psutil.AccessDenied, OSError) as exc:
        return False, f"no pude verificar el proceso {pid}: {exc}"

    for argumento in cmdline:
        try:
            ruta = Path(argumento)
            if not ruta.is_absolute():
                ruta = Path(proc.cwd()) / ruta
            if ruta.resolve() == EXPECTED_SCRIPT:
                return True, "PID verificado"
        except (OSError, TypeError, ValueError):
            continue
    return False, "el PID guardado pertenece a otro proceso"


def main() -> int:
    if not PID_FILE.exists():
        print("[SecureCenter] No hay PID: ¿está corriendo el dashboard?")
        return 1
    try:
        registro = json.loads(PID_FILE.read_text(encoding="utf-8"))
        pid = registro["pid"]
        create_time = registro["create_time"]
        script = registro["script"]
        if type(pid) is not int or pid <= 0:
            raise ValueError
        if not isinstance(create_time, (int, float)) or isinstance(create_time, bool):
            raise ValueError
        if not isinstance(script, str):
            raise ValueError
    except (KeyError, OSError, TypeError, ValueError, json.JSONDecodeError):
        print("[SecureCenter] El archivo PID está roto; no termino ningún proceso.")
        return 1

    es_nuestro, detalle = _es_nuestro_dashboard(pid, script, float(create_time))
    if not es_nuestro:
        if detalle == "el proceso ya no existe":
            PID_FILE.unlink(missing_ok=True)
            print(f"[SecureCenter] PID viejo eliminado ({pid} ya no existe).")
            return 0
        print(f"[SecureCenter] Me niego a terminar PID {pid}: {detalle}.")
        return 1

    if platform.system() == "Windows":
        resultado = subprocess.run(
            ["taskkill", "/PID", str(pid), "/F"], capture_output=True, text=True)
        if resultado.returncode != 0:
            detalle_kill = (resultado.stderr or resultado.stdout or "").strip()
            print(f"[SecureCenter] No pude detener PID {pid}: {detalle_kill}")
            return 1
    else:
        try:
            psutil.Process(pid).terminate()
            psutil.Process(pid).wait(timeout=10)
        except psutil.NoSuchProcess:
            pass
        except (psutil.AccessDenied, psutil.TimeoutExpired) as exc:
            print(f"[SecureCenter] No pude detener PID {pid}: {exc}")
            return 1

    PID_FILE.unlink(missing_ok=True)
    print(f"[SecureCenter] dashboard detenido (PID {pid}).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
