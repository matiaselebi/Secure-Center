#!/usr/bin/env python3
"""Detiene el dashboard de SecureCenter usando el PID guardado."""

import platform
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
PID_FILE = PROJECT_ROOT / "data" / "dashboard.pid"


def main() -> None:
    if not PID_FILE.exists():
        print("[SecureCenter] No hay PID: ¿está corriendo el dashboard?")
        sys.exit(1)
    pid = int(PID_FILE.read_text().strip())
    if platform.system() == "Windows":
        subprocess.run(["taskkill", "/PID", str(pid), "/F"], capture_output=True, text=True)
    else:
        import os
        import signal

        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
    PID_FILE.unlink(missing_ok=True)
    print(f"[SecureCenter] dashboard detenido (PID {pid}).")


if __name__ == "__main__":
    main()
