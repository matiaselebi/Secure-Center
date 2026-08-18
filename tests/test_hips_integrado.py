"""SecureHIPS dentro de SecureCenter.

Cubre las tres cosas que se rompen al sumar un proyecto y que no se notan
hasta que estás delante de la máquina: que el núcleo lo encienda, que lo
apague ORDENADAMENTE (y no matándolo por puerto, que le dejaría las reglas
puestas en el firewall), y que sus eventos entren bien en la línea de tiempo,
que es donde tiene un formato de fecha distinto al de los otros tres.
"""

import sqlite3
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from securecenter.config_loader import load_config  # noqa: E402
from securecenter.logger_db import LoggerDB  # noqa: E402
from securecenter.logs import _epoch_a_iso, collect_logs  # noqa: E402
from securecenter.orchestrator import CLAVES_DEL_NUCLEO, Orchestrator  # noqa: E402
from securecenter.projects import PROJECT_SPECS, ManagedProject  # noqa: E402


def _proyecto_falso(raiz: Path, paquete: str, scripts: list[str]) -> Path:
    """Una carpeta con la forma que SecureCenter espera de un proyecto."""
    carpeta = raiz / paquete
    (carpeta / "src" / paquete).mkdir(parents=True, exist_ok=True)
    (carpeta / "scripts").mkdir(parents=True, exist_ok=True)
    (carpeta / "data").mkdir(parents=True, exist_ok=True)
    for script in scripts:
        (carpeta / "scripts" / script).write_text("", encoding="utf-8")
    for directorio, ejecutables in (
        ("bin", ("python",)),
        ("Scripts", ("python.exe", "pythonw.exe")),
    ):
        venv = carpeta / "venv" / directorio
        venv.mkdir(parents=True, exist_ok=True)
        for ejecutable in ejecutables:
            (venv / ejecutable).write_text("", encoding="utf-8")
    return carpeta


@pytest.fixture()
def orquestador(tmp_path):
    cfg = load_config(str(tmp_path / "no.yaml"))
    carpetas = {
        "proxy": ("secureproxy", ["run_proxy.py", "stop_proxy.py"]),
        "dns": ("securedns", ["run_dns.py", "stop_dns.py"]),
        "vpn": ("securevpn", ["run_dashboard.py"]),
        "hips": ("securehips", ["run_hips.py", "stop_hips.py"]),
        "intel": ("secureintel", ["run_intel.py", "stop_intel.py"]),
        "scanner": ("securescanner", ["run_scanner.py", "stop_scanner.py"]),
        "agente": ("secureagent", ["run_servidor.py", "stop_servidor.py"]),
    }
    proyectos = {}
    for spec in PROJECT_SPECS:
        paquete, scripts = carpetas[spec.key]
        carpeta = _proyecto_falso(tmp_path, paquete, scripts)
        proyectos[spec.key] = ManagedProject(spec, carpeta)
    logger_db = LoggerDB(str(tmp_path / "center.db"))
    return Orchestrator(cfg, proyectos, logger_db, dry_run=True), proyectos, cfg


# ------------------------------------------------------------ el registro


def test_el_hips_esta_registrado():
    claves = {s.key for s in PROJECT_SPECS}
    assert "hips" in claves


def test_el_hips_forma_parte_del_nucleo():
    """El núcleo es lo que se prende con un botón y arranca con Windows. La
    VPN queda afuera a propósito; el HIPS no molesta en el uso diario."""
    assert "hips" in CLAVES_DEL_NUCLEO
    assert "vpn" not in CLAVES_DEL_NUCLEO


def test_el_puerto_no_choca_con_los_otros(orquestador):
    _orq, _proyectos, cfg = orquestador
    puertos = [
        cfg.ports.proxy_service, cfg.ports.proxy_dashboard,
        cfg.ports.dns_dashboard, cfg.ports.vpn_dashboard,
        cfg.ports.hips_dashboard, cfg.ports.center_dashboard,
    ]
    assert len(puertos) == len(set(puertos))


# ----------------------------------------------------------- el encendido


def test_encender_el_nucleo_tambien_enciende_el_hips(orquestador):
    orq, _proyectos, _cfg = orquestador
    etiquetas = [s.label for s in orq.plan_start_core()]
    assert any("iniciar SecureHIPS" in e for e in etiquetas)
    assert any("iniciar SecureProxy" in e for e in etiquetas)
    assert any("iniciar SecureDNS" in e for e in etiquetas)


def test_encender_el_nucleo_no_enciende_la_vpn(orquestador):
    """La VPN sigue con su botón aparte: no se prende sola para que nunca te
    corte una partida sin querer."""
    orq, _proyectos, _cfg = orquestador
    etiquetas = " ".join(s.label for s in orq.plan_start_core())
    assert "SecureVPN" not in etiquetas


def test_el_hips_no_pide_cambiar_nada_del_sistema(orquestador):
    """A diferencia del proxy y del DNS, no hay que apuntarle nada. Si algún
    día aparece un paso de configuración del sistema para el HIPS, este test
    obliga a justificarlo."""
    orq, _proyectos, _cfg = orquestador
    pasos = orq.plan_start_one("hips")
    assert pasos
    assert not any("proxy del sistema" in s.label or "DNS del sistema" in s.label
                   for s in pasos)


# -------------------------------------------------------------- el apagado


def test_apagar_el_nucleo_usa_el_apagado_ordenado_del_hips(orquestador):
    """Es lo más importante de este archivo. Matar el HIPS por puerto le
    dejaría las reglas puestas en el firewall, y sin nadie corriendo que las
    levante cuando venzan: alguien bloqueado para siempre por un programa que
    ya no existe."""
    orq, _proyectos, _cfg = orquestador
    pasos = orq.plan_stop_core()
    etiquetas = [s.label for s in pasos]
    assert any("detener SecureHIPS (prolijo)" in e for e in etiquetas)

    indice_prolijo = next(i for i, e in enumerate(etiquetas) if "SecureHIPS (prolijo)" in e)
    # El apagado ordenado va ANTES del kill por puerto, que es la red de
    # contención. Al revés, el kill lo mataría antes de que pueda limpiar.
    # (El paso de kill solo existe en Windows, así que se chequea si está.)
    matadores = [i for i, e in enumerate(etiquetas) if "puertos del núcleo cerrados" in e]
    if matadores:
        assert indice_prolijo < matadores[0]


def test_apagar_todo_incluye_al_hips(orquestador):
    orq, _proyectos, _cfg = orquestador
    etiquetas = " ".join(s.label for s in orq.plan_stop_all(vpn_was_running=False))
    assert "SecureHIPS" in etiquetas


def test_panico_incluye_al_hips(orquestador):
    """El botón de pánico tiene que dejar la máquina como estaba, y eso
    incluye sacar las reglas de entrada que puso el HIPS."""
    orq, _proyectos, _cfg = orquestador
    etiquetas = " ".join(s.label for s in orq.plan_panic())
    assert "SecureHIPS" in etiquetas


# --------------------------------------------------- la línea de tiempo


def test_la_fecha_del_hips_se_convierte(tmp_path):
    """SecureHIPS guarda la hora como epoch (un número) y los otros tres como
    texto ISO. Si entrara cruda, el orden por texto pondría todos sus eventos
    juntos al final ("1785..." ordena antes que "2026-..."), y la línea de
    tiempo dejaría de estar ordenada justo cuando aparece un bloqueo, que es
    cuando más se la mira."""
    iso = _epoch_a_iso(1785866294.97)
    assert iso.startswith("2026-")
    assert "T" in iso


def test_una_fecha_rota_no_rompe_la_linea_de_tiempo():
    assert _epoch_a_iso("no es una fecha") == ""
    assert _epoch_a_iso(None) == ""


def test_los_bans_del_hips_entran_ordenados(tmp_path, orquestador):
    orq, proyectos, cfg = orquestador

    # Base del HIPS con un ban.
    db_hips = proyectos["hips"].folder / "data" / "hips_logs.db"
    con = sqlite3.connect(db_hips)
    con.execute(
        "CREATE TABLE bans (ip TEXT PRIMARY KEY, desde REAL, hasta REAL, "
        "motivo TEXT, intentos INTEGER, aplicado INTEGER, detalle TEXT, veces INTEGER)"
    )
    con.execute(
        "INSERT INTO bans VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        ("200.1.2.3", time.time(), time.time() + 3600,
         "5 intentos fallidos", 5, 1, "", 1),
    )
    con.commit()
    con.close()

    filas = collect_logs(cfg, proyectos)

    del_hips = [f for f in filas if f.project == "SecureHIPS"]
    assert len(del_hips) == 1
    assert "200.1.2.3" in del_hips[0].detail
    assert del_hips[0].kind == "bloqueo"
    assert del_hips[0].timestamp.startswith("20")


def test_un_ban_en_audit_se_distingue(tmp_path, orquestador):
    """Mostrar igual un bloqueo aplicado y uno que solo se registró sería la
    peor forma de mentir: el panel diría que estás protegido y no."""
    orq, proyectos, cfg = orquestador
    db_hips = proyectos["hips"].folder / "data" / "hips_logs.db"
    con = sqlite3.connect(db_hips)
    con.execute(
        "CREATE TABLE bans (ip TEXT PRIMARY KEY, desde REAL, hasta REAL, "
        "motivo TEXT, intentos INTEGER, aplicado INTEGER, detalle TEXT, veces INTEGER)"
    )
    con.execute(
        "INSERT INTO bans VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        ("200.1.2.9", time.time(), time.time() + 3600, "5 intentos", 5, 0, "", 1),
    )
    con.commit()
    con.close()

    filas = [f for f in collect_logs(cfg, proyectos) if f.project == "SecureHIPS"]

    assert filas[0].kind == "bloqueo (audit)"


def test_sin_base_del_hips_no_se_rompe_nada(orquestador):
    """El proyecto puede estar instalado y no haber corrido nunca."""
    orq, proyectos, cfg = orquestador
    assert collect_logs(cfg, proyectos) == []
