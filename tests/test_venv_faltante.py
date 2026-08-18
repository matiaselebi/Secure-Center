"""Cuando a un proyecto le falta el venv o el script.

El bug real: al agregar Secure-Intel, la carpeta existía pero todavía no
tenía su entorno virtual. SecureCenter armaba el comando igual y salía
«[WinError 2] El sistema no puede encontrar el archivo especificado», que no
dice qué archivo falta ni qué hacer. Y encima el mensaje final del núcleo
decía «SecureProxy y SecureDNS corriendo. Todo listo» nombrando dos de cuatro.
"""

import sys
from pathlib import Path

import pytest

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ / "src"))

from securecenter.config_loader import load_config  # noqa: E402
from securecenter.logger_db import LoggerDB  # noqa: E402
from securecenter.orchestrator import Orchestrator  # noqa: E402
from securecenter.projects import PROJECT_SPECS, ManagedProject  # noqa: E402


def _carpeta(tmp_path, paquete, con_venv=True, scripts=("run_intel.py",)):
    carpeta = tmp_path / paquete
    (carpeta / "src" / paquete).mkdir(parents=True, exist_ok=True)
    (carpeta / "scripts").mkdir(exist_ok=True)
    for s in scripts:
        (carpeta / "scripts" / s).write_text("", encoding="utf-8")
    if con_venv:
        binario = carpeta / "venv" / ("Scripts" if sys.platform == "win32" else "bin")
        binario.mkdir(parents=True, exist_ok=True)
        (binario / ("python.exe" if sys.platform == "win32" else "python")).write_text("")
    return carpeta


def _proyecto(tmp_path, key, con_venv=True, scripts=("run_intel.py",)):
    spec = next(s for s in PROJECT_SPECS if s.key == key)
    return ManagedProject(spec, _carpeta(tmp_path, spec.package, con_venv, scripts))


def test_sin_venv_no_se_inventa_una_ruta(tmp_path):
    """Devolver la ruta igual es lo que producía el WinError 2."""
    p = _proyecto(tmp_path, "intel", con_venv=False)
    assert p.found
    assert p.venv_python() is None
    assert p.falta_el_venv()


def test_con_venv_se_encuentra(tmp_path):
    p = _proyecto(tmp_path, "intel", con_venv=True)
    assert p.venv_python() is not None
    assert not p.falta_el_venv()


def test_el_paso_explica_que_falta_el_venv(tmp_path):
    o = Orchestrator(
        load_config(str(tmp_path / "no.yaml")),
        {"intel": _proyecto(tmp_path, "intel", con_venv=False)},
        LoggerDB(str(tmp_path / "c.db")), dry_run=True,
    )
    pasos = o.plan_start_one("intel")
    paso = next(s for s in pasos if s.label == "iniciar Secure-Intel")
    ok, detalle = paso.func()
    assert not ok
    assert "entorno virtual" in detalle
    assert "venv" in detalle
    assert "WinError" not in detalle


def test_que_le_falte_el_venv_a_uno_no_frena_a_los_demas(tmp_path):
    """Secure-Intel sin instalar no puede impedir que arranque el proxy."""
    o = Orchestrator(
        load_config(str(tmp_path / "no.yaml")),
        {"intel": _proyecto(tmp_path, "intel", con_venv=False)},
        LoggerDB(str(tmp_path / "c.db")), dry_run=True,
    )
    paso = next(s for s in o.plan_start_one("intel") if s.label == "iniciar Secure-Intel")
    assert paso.optional, "un proyecto sin instalar no puede cortar el arranque"


def test_si_falta_el_script_tambien_se_explica(tmp_path):
    o = Orchestrator(
        load_config(str(tmp_path / "no.yaml")),
        {"intel": _proyecto(tmp_path, "intel", con_venv=True, scripts=())},
        LoggerDB(str(tmp_path / "c.db")), dry_run=True,
    )
    paso = next(s for s in o.plan_start_one("intel") if s.label == "iniciar Secure-Intel")
    ok, detalle = paso.func()
    assert not ok and "run_intel.py" in detalle


def test_el_mensaje_del_nucleo_no_tiene_nombres_escritos_a_mano():
    """Quedó viejo dos veces: cuando entró el HIPS y cuando entró Intel."""
    texto = (RAIZ / "scripts" / "start_core.py").read_text(encoding="utf-8")
    cuerpo = texto.split('"""', 2)[-1]  # sin el docstring, que sí los nombra
    for nombre in ("SecureProxy", "SecureDNS", "SecureHIPS", "Secure-Intel"):
        assert f'"{nombre}' not in cuerpo and f"'{nombre}" not in cuerpo, nombre
