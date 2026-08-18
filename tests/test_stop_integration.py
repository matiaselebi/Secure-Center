"""Prueba de integración del camino que fallaba en la máquina del usuario:
apretar "Apagar SecureProxy" y que el servicio siga prendido.

Acá se levanta un proceso REAL que escucha un puerto (haciendo de proxy), se
ejecuta el plan de apagado real del orquestador, y se exige que:
  1. el proceso muera de verdad,
  2. el resultado informe éxito solo si el puerto quedó libre.

Y el caso inverso: si el "servicio" no se puede matar, la operación tiene que
informar FALLO (antes decía OK igual, que es el bug que se reportó).
"""

import socket
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

import securecenter.orchestrator as orch_mod  # noqa: E402
from securecenter.config_loader import load_config  # noqa: E402
from securecenter.logger_db import LoggerDB  # noqa: E402
from securecenter.orchestrator import Orchestrator  # noqa: E402
from securecenter.procutil import port_in_use, wait_port_listening  # noqa: E402
from securecenter.projects import discover_projects  # noqa: E402

LISTENER_CODE = (
    "import socket,time;"
    "s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);"
    "s.bind(('127.0.0.1',PORT));s.listen(5);"
    "time.sleep(120)"
)


def _free_port_number() -> int:
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    return port


def _start_listener(port: int) -> subprocess.Popen:
    proc = subprocess.Popen(
        [sys.executable, "-c", LISTENER_CODE.replace("PORT", str(port))],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    assert wait_port_listening(port, timeout=10), "el servicio de prueba no arrancó"
    return proc


def _make_orch(fake_stack, tmp_path, port, monkeypatch):
    root, _ = fake_stack
    cfg = load_config(str(tmp_path / "no.yaml"))
    cfg.ports.proxy_service = port
    projects = discover_projects(cfg, search_root=root)
    logger = LoggerDB(str(tmp_path / "c.db"))
    # Se fuerza la rama Windows para ejercitar el plan completo (kill + verify),
    # pero los pasos de PowerShell/reg/schtasks se marcan como opcionales al
    # fallar en Linux, así que no interfieren con lo que se está probando.
    monkeypatch.setattr(orch_mod.platform, "system", lambda: "Windows")
    return Orchestrator(cfg, projects, logger, dry_run=False)


def test_stop_proxy_actually_kills_the_process(fake_stack, tmp_path, monkeypatch):
    port = _free_port_number()
    proc = _start_listener(port)
    try:
        o = _make_orch(fake_stack, tmp_path, port, monkeypatch)
        # Solo los pasos que importan acá: liberar el puerto y verificar.
        plan = [s for s in o.plan_stop_one("proxy") if s.func is not None]
        assert plan, "el plan tiene que traer pasos de puerto/verificación"

        result = o.execute(plan, "detener_proxy")

        if port_in_use(port) and any(
                "acceso denegado" in linea.lower() or "administrador" in linea.lower()
                for linea in result.lines):
            pytest.skip("sandbox sin permiso para terminar procesos")
        assert not port_in_use(port), "el proceso siguió escuchando tras apagar"
        assert result.ok, f"debería informar éxito: {result.lines}"
        assert any("liberado" in l or "verificado" in l for l in result.lines)
    finally:
        if proc.poll() is None:
            proc.kill()
        proc.wait(timeout=10)


def test_verification_reports_failure_when_service_survives(fake_stack, tmp_path, monkeypatch):
    """El bug original: informaba OK aunque el servicio siguiera arriba. Acá se
    simula un kill que no logra nada y se exige que el resultado sea FALLO."""
    port = _free_port_number()
    proc = _start_listener(port)
    try:
        o = _make_orch(fake_stack, tmp_path, port, monkeypatch)
        # kill_pid que "no puede" matar (como pasa sin permisos de admin)
        monkeypatch.setattr(
            orch_mod, "free_port", lambda p, timeout=6.0: (False, f"puerto {p} SIGUE ocupado")
        )
        plan = [s for s in o.plan_stop_one("proxy") if s.func is not None]

        result = o.execute(plan, "detener_proxy")

        assert not result.ok, "tiene que informar FALLO, no OK"
        assert any("SIGUE" in l or "ERROR" in l for l in result.lines)
    finally:
        if proc.poll() is None:
            proc.kill()
        proc.wait(timeout=10)


def test_start_verification_detects_service_that_never_starts(fake_stack, tmp_path, monkeypatch):
    """Si el servicio no llega a escuchar, encender tiene que decirlo."""
    port = _free_port_number()  # nadie va a escuchar acá
    o = _make_orch(fake_stack, tmp_path, port, monkeypatch)
    verify = [s for s in o.plan_start_one("proxy") if s.label.startswith("verificar")]
    assert verify

    # timeout corto para no demorar el test
    monkeypatch.setattr(orch_mod, "wait_port_listening", lambda p, timeout=8: False)
    ok, detalle = verify[0].func()

    assert not ok
    assert "NO arrancó" in detalle
