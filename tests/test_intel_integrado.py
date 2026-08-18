"""Secure-Intel dentro de SecureCenter.

Lo que se prueba acá no es que Intel funcione (para eso están sus propios
tests) sino que SecureCenter lo trate como a los demás: que el núcleo lo
encienda y lo apague, que aparezca en el estado, y que su puerto no choque.
"""

import sqlite3
import sys
import time
from pathlib import Path

import pytest

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ / "src"))

from securecenter.config_loader import Ports, load_config  # noqa: E402
from securecenter.logger_db import LoggerDB  # noqa: E402
from securecenter.logs import collect_logs  # noqa: E402
from securecenter.orchestrator import CLAVES_DEL_NUCLEO, Orchestrator  # noqa: E402
from securecenter.projects import PROJECT_SPECS, ManagedProject  # noqa: E402

from tests.test_hips_integrado import _proyecto_falso  # noqa: E402

CARPETAS = {
    "proxy": ("secureproxy", ["run_proxy.py", "stop_proxy.py"]),
    "dns": ("securedns", ["run_dns.py", "stop_dns.py"]),
    "vpn": ("securevpn", ["run_dashboard.py"]),
    "hips": ("securehips", ["run_hips.py", "stop_hips.py"]),
    "intel": ("secureintel", ["run_intel.py", "stop_intel.py"]),
    "scanner": ("securescanner", ["run_scanner.py", "stop_scanner.py"]),
    "agente": ("secureagent", ["run_servidor.py", "stop_servidor.py"]),
}


@pytest.fixture()
def orquestador(tmp_path):
    cfg = load_config(str(tmp_path / "no.yaml"))
    proyectos = {}
    for spec in PROJECT_SPECS:
        paquete, scripts = CARPETAS[spec.key]
        proyectos[spec.key] = ManagedProject(
            spec, _proyecto_falso(tmp_path, paquete, scripts))
    db = LoggerDB(str(tmp_path / "center.db"))
    return Orchestrator(cfg, proyectos, db, dry_run=True), proyectos, cfg


def _textos(steps):
    return " ".join(f"{s.label} {' '.join(map(str, s.argv or []))}" for s in steps)


# ------------------------------------------------------------ lo básico


def test_intel_esta_entre_los_proyectos():
    assert "intel" in [s.key for s in PROJECT_SPECS]


def test_el_puerto_no_choca_con_ninguno():
    p = Ports()
    puertos = [p.proxy_service, p.proxy_dashboard, p.dns_dashboard,
               p.vpn_dashboard, p.hips_dashboard, p.intel_dashboard,
               p.center_dashboard]
    assert p.intel_dashboard == 8893
    assert len(puertos) == len(set(puertos)), "hay dos proyectos en el mismo puerto"


def test_intel_forma_parte_del_nucleo():
    assert "intel" in CLAVES_DEL_NUCLEO


# ------------------------------------------------------ encender y apagar


def test_encender_el_nucleo_tambien_enciende_intel(orquestador):
    o, _, _ = orquestador
    assert "run_intel.py" in _textos(o.plan_start_core())


def test_intel_arranca_ultimo(orquestador):
    """No está en el camino de ninguna conexión: que los otros protejan antes."""
    o, _, _ = orquestador
    texto = _textos(o.plan_start_core())
    assert texto.index("run_intel.py") > texto.index("run_hips.py")
    assert texto.index("run_intel.py") > texto.index("run_proxy.py")


def test_apagar_el_nucleo_usa_el_apagado_ordenado_de_intel(orquestador):
    """Un kill en el medio de una actualización deja el WAL a medias."""
    o, _, _ = orquestador
    assert "stop_intel.py" in _textos(o.plan_stop_core())


def test_apagar_todo_incluye_a_intel(orquestador):
    o, _, cfg = orquestador
    texto = _textos(o.plan_stop_all())
    assert "stop_intel.py" in texto or str(cfg.ports.intel_dashboard) in texto


def test_se_puede_encender_y_apagar_intel_solo(orquestador):
    """Como cualquier otro: su propio botón, sin tocar al resto."""
    o, _, _ = orquestador
    assert "run_intel.py" in _textos(o.plan_start_one("intel"))
    assert "stop_intel.py" in _textos(o.plan_stop_one("intel"))


def test_encender_intel_solo_no_toca_a_los_demas(orquestador):
    o, _, _ = orquestador
    texto = _textos(o.plan_start_one("intel"))
    assert "run_proxy.py" not in texto and "run_hips.py" not in texto


# ------------------------------------------------------- línea de tiempo


def test_las_actualizaciones_de_intel_entran_en_la_linea_de_tiempo(tmp_path):
    """Un feed que hace tres semanas que no baja se parece a uno que anda."""
    carpeta = _proyecto_falso(tmp_path, "secureintel", ["run_intel.py"])
    (carpeta / "data").mkdir(exist_ok=True)
    # La base se arma con sqlite3 pelado y NO importando `secureintel`: los
    # tests de SecureCenter no pueden depender de que el repo hermano esté
    # clonado al lado. Andaba en mi máquina y fallaba en cualquier otra, que
    # es el peor tipo de test.
    con = sqlite3.connect(str(carpeta / "data" / "intel.db"))
    con.execute("CREATE TABLE fuentes (nombre TEXT PRIMARY KEY, ultima REAL, "
                "ok INTEGER, total INTEGER, error TEXT)")
    con.executemany("INSERT INTO fuentes VALUES (?,?,?,?,?)", [
        ("URLhaus", time.time(), 1, 40000, ""),
        ("OpenPhish", time.time() - 60, 0, 0, "sin internet"),
    ])
    con.commit()
    con.close()

    spec = next(s for s in PROJECT_SPECS if s.key == "intel")
    cfg = load_config(str(tmp_path / "no.yaml"))
    filas = collect_logs(cfg, {"intel": ManagedProject(spec, carpeta)}, per_source=10)
    eventos = {f.kind for f in filas}
    assert "feed actualizado" in eventos
    assert "feed con problemas" in eventos
    assert any("sin internet" in f.detail for f in filas)
    # La hora tiene que venir convertida a ISO, no como epoch: si entrara
    # cruda, "1785..." ordenaría antes que "2026-..." y la línea de tiempo
    # quedaría desordenada justo donde más se la mira.
    assert all(f.timestamp.startswith("2") for f in filas), filas


def test_sin_base_de_intel_no_se_rompe_nada(tmp_path):
    carpeta = _proyecto_falso(tmp_path, "secureintel", ["run_intel.py"])
    spec = next(s for s in PROJECT_SPECS if s.key == "intel")
    cfg = load_config(str(tmp_path / "no.yaml"))
    assert collect_logs(cfg, {"intel": ManagedProject(spec, carpeta)}, per_source=10) == []
