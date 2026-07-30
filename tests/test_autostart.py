"""Tests del arranque con Windows: qué se levanta solo y qué NO.

Regla del stack: el núcleo (proxy + DNS) arranca siempre; la VPN nunca se
conecta sola, pero SI el túnel quedó instalado (sobrevive al reinicio como
servicio de Windows), su dashboard debe volver para poder verla.
"""

import runpy
import socket
import sys
from pathlib import Path

import pytest

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ / "src"))
sys.path.insert(0, str(RAIZ / "scripts"))

import securecenter.procutil as procutil  # noqa: E402


@pytest.fixture
def autostart_env(fake_stack, tmp_path, monkeypatch):
    """Prepara autostart_core con proyectos falsos y captura qué lanza."""
    root, _ = fake_stack
    lanzados = []

    import securecenter.config_loader as cl
    from securecenter.config_loader import load_config
    from securecenter.logger_db import LoggerDB
    from securecenter.orchestrator import Orchestrator
    from securecenter.projects import discover_projects

    cfg = load_config(str(tmp_path / "no.yaml"))
    projects = discover_projects(cfg, search_root=root)
    orch = Orchestrator(cfg, projects, LoggerDB(str(tmp_path / "c.db")))

    import _common

    monkeypatch.setattr(_common, "build_orchestrator", lambda: orch)
    monkeypatch.setattr(procutil, "popen_quiet", lambda argv, cwd=None: lanzados.append(" ".join(argv)))
    return orch, lanzados, monkeypatch


def _correr_autostart(monkeypatch, lanzados, puertos_ocupados=(), servicio_vpn=False):
    import autostart_core

    monkeypatch.setattr(autostart_core, "popen_quiet", lambda argv, cwd=None: lanzados.append(" ".join(argv)))
    monkeypatch.setattr(autostart_core, "port_in_use", lambda p: p in puertos_ocupados)
    monkeypatch.setattr(autostart_core, "windows_service_running", lambda s: servicio_vpn)
    autostart_core.main()


def test_arranca_proxy_y_dns(autostart_env):
    orch, lanzados, monkeypatch = autostart_env
    _correr_autostart(monkeypatch, lanzados)
    texto = " || ".join(lanzados)
    assert "run_proxy.py" in texto
    assert "run_dns.py" in texto


def test_no_duplica_lo_que_ya_esta_corriendo(autostart_env):
    """Si el proxy ya está escuchando (por ejemplo, porque el usuario lo dejó
    prendido), no se lanza una segunda instancia que pelearía por el puerto."""
    orch, lanzados, monkeypatch = autostart_env
    _correr_autostart(monkeypatch, lanzados, puertos_ocupados=(8888,))
    texto = " || ".join(lanzados)
    assert "run_proxy.py" not in texto
    assert "run_dns.py" in texto


def test_no_levanta_el_dashboard_de_la_vpn_si_el_tunel_no_quedo_instalado(autostart_env):
    """La VPN no se enciende sola: sin túnel instalado, ni su dashboard sube."""
    orch, lanzados, monkeypatch = autostart_env
    _correr_autostart(monkeypatch, lanzados, servicio_vpn=False)
    assert "run_dashboard.py" not in " || ".join(lanzados)


def test_levanta_el_dashboard_de_la_vpn_si_el_tunel_sigue_activo(autostart_env):
    """Si el túnel quedó instalado (sobrevive al reinicio), su dashboard vuelve
    para que se pueda ver y manejar."""
    orch, lanzados, monkeypatch = autostart_env
    _correr_autostart(monkeypatch, lanzados, servicio_vpn=True)
    assert "run_dashboard.py" in " || ".join(lanzados)


def test_nunca_conecta_la_vpn_sola(autostart_env):
    """Ni connect_vpn ni lab_up: encender la VPN es siempre decisión del
    usuario (para no cortarle juegos/streaming sin aviso)."""
    orch, lanzados, monkeypatch = autostart_env
    _correr_autostart(monkeypatch, lanzados, servicio_vpn=True)
    texto = " || ".join(lanzados)
    assert "connect_vpn.py" not in texto
    assert "lab_up.py" not in texto
    assert "provision_server.py" not in texto
