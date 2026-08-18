#!/usr/bin/env python3
"""Deja a los proyectos listos para arrancar: venv, dependencias y el token.

    python scripts/preparar.py            # ve qué falta, no toca nada
    python scripts/preparar.py --hacelo   # lo hace

POR QUÉ EXISTE

Porque el diagnóstico y los planes ya decían perfecto qué faltaba ("Secure-
Scanner no tiene su entorno virtual creado todavía, creálo así: ...") y esa
frase igual es un comando largo con comillas que hay que copiar bien, por cada
proyecto, en una consola aparte. Decir qué hacer es mejor que fallar callado,
pero hacerlo es mejor que decirlo.

QUÉ HACE Y QUÉ NO

Hace dos cosas, las dos aburridas y reversibles:

- Crea el `venv/` del proyecto que no lo tenga e instala su `requirements.txt`.
- Le genera a Secure-Agent su `.env` con un token nuevo, si no lo tiene.

No toca configuración, no prende nada, no borra nada. Si un proyecto ya está
listo, no lo toca: se puede correr todas las veces que quieras.

EL TOKEN

Se genera con `secrets.token_urlsafe`, que es el generador criptográfico de la
biblioteca estándar, y se escribe SOLO si el archivo no existe: pisar un `.env`
que ya tenía un token dejaría al servidor sin poder hablar con los agentes que
ya lo tienen configurado.

Ese mismo string va en el `.env` de cada equipo vigilado. Se imprime una vez
acá y no se vuelve a mostrar en ningún panel.
"""

import subprocess
import sys
from pathlib import Path

from _common import build_orchestrator

from securecenter.projects import PROJECT_SPECS  # noqa: E402

NOMBRES = {s.key: s.display_name for s in PROJECT_SPECS}


def _python_del_sistema() -> str:
    """Con qué se crea el venv de OTRO proyecto.

    El intérprete de ESTE venv sirve: `python -m venv` crea un entorno nuevo y
    limpio, no una copia del que lo invoca.
    """
    return sys.executable


def _venv_python(carpeta: Path) -> Path:
    windows = carpeta / "venv" / "Scripts" / "python.exe"
    return windows if windows.exists() else carpeta / "venv" / "bin" / "python"


def _preparar_venv(nombre: str, carpeta: Path, hacelo: bool) -> bool:
    """Devuelve True si hizo algo."""
    if _venv_python(carpeta).exists():
        return False
    if not hacelo:
        print(f"  [falta] {nombre}: no tiene entorno virtual")
        return True

    print(f"  {nombre}: creando el entorno virtual...")
    salida = subprocess.run([_python_del_sistema(), "-m", "venv", "venv"],
                            cwd=str(carpeta), capture_output=True, text=True)
    if salida.returncode != 0:
        print(f"  {nombre}: NO pude crear el venv: {salida.stderr.strip()[:200]}")
        return True

    requisitos = carpeta / "requirements.txt"
    if not requisitos.exists():
        print(f"  {nombre}: venv creado (no tiene requirements.txt)")
        return True

    print(f"  {nombre}: instalando dependencias (esto tarda)...")
    salida = subprocess.run(
        [str(_venv_python(carpeta)), "-m", "pip", "install", "-q",
         "-r", "requirements.txt"],
        cwd=str(carpeta), capture_output=True, text=True)
    if salida.returncode != 0:
        # El venv queda creado igual. Se dice qué pasó y no se borra nada:
        # borrar el venv a medio hacer obliga a bajar todo de nuevo.
        print(f"  {nombre}: el venv quedó, pero pip falló: "
              f"{salida.stderr.strip()[:200]}")
        return True
    print(f"  {nombre}: listo.")
    return True


def _preparar_token(carpeta: Path, hacelo: bool) -> bool:
    """El .env de Secure-Agent, con un token nuevo. True si hizo algo."""
    env = carpeta / ".env"
    if env.exists() and "SECUREAGENT_TOKEN" in env.read_text(
            encoding="utf-8", errors="replace"):
        return False
    if not hacelo:
        print("  [falta] Secure-Agent: no tiene SECUREAGENT_TOKEN en su .env")
        return True

    import secrets

    token = secrets.token_urlsafe(32)
    # 'a' y no 'w': si el archivo ya existía con otras claves, no se pisan.
    with env.open("a", encoding="utf-8") as f:
        f.write(f"\nSECUREAGENT_TOKEN={token}\n")
    print(f"  Secure-Agent: token generado en {env}")
    print("")
    print("  ESTE MISMO STRING va en el .env de cada equipo vigilado:")
    print(f"      SECUREAGENT_TOKEN={token}")
    print("")
    print("  No se vuelve a mostrar en ningún panel. Guardalo ahora.")
    return True


def main(argv: list) -> int:
    hacelo = "--hacelo" in argv
    o = build_orchestrator()

    if not hacelo:
        print("[SecureCenter] Revisando qué falta (no toco nada):")
    algo = False
    for spec in PROJECT_SPECS:
        project = o.projects.get(spec.key)
        if project is None or not project.found:
            continue
        carpeta = Path(project.folder)
        algo |= _preparar_venv(NOMBRES[spec.key], carpeta, hacelo)
        if spec.key == "agente":
            algo |= _preparar_token(carpeta, hacelo)

    if not algo:
        print("[SecureCenter] Está todo listo: no falta ningún venv ni el token.")
        return 0
    if not hacelo:
        print("")
        print("[SecureCenter] Para que lo haga:  python scripts/preparar.py --hacelo")
    else:
        print("")
        print("[SecureCenter] Listo. Encendé el núcleo (opción 1 del menú).")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
