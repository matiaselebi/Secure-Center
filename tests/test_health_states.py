"""Tests del bug visual: la VPN mostraba "activo" con el túnel caído.

La causa: se medía "¿el dashboard responde?" y para la VPN eso NO implica que
el túnel esté conectado (son procesos distintos). Acá se levanta un dashboard
de mentira que responde /state como lo hace SecureVPN, y se verifica que cada
respuesta se traduzca al estado correcto.
"""

import socket
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from securecenter.config_loader import load_config  # noqa: E402
from securecenter.health import (  # noqa: E402
    ACTIVO,
    APAGADO,
    PARCIAL,
    project_alive,
    project_state,
    state_snapshot,
)
from securecenter.projects import PROJECT_SPECS  # noqa: E402


def _fake_vpn_dashboard(state_body: str | None):
    """Servidor mínimo que imita el dashboard de SecureVPN. Si state_body es
    None, no expone /state (simula una versión vieja)."""

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):  # noqa: N802
            if self.path.rstrip("/") == "/state" and state_body is not None:
                body = state_body.encode()
                self.send_response(200)
            elif self.path.rstrip("/") == "/state":
                self.send_error(404)
                return
            else:
                body = b"<html>dashboard</html>"
                self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


@pytest.fixture
def cfg(tmp_path):
    c = load_config(str(tmp_path / "no.yaml"))
    # puertos donde no hay nadie, salvo el que se sobrescriba en cada test
    c.ports.proxy_dashboard = 1
    c.ports.dns_dashboard = 1
    c.ports.vpn_dashboard = 1
    return c


def test_vpn_connected_is_activo(cfg):
    server = _fake_vpn_dashboard("tunnel=connected killswitch=on")
    cfg.ports.vpn_dashboard = server.server_address[1]
    try:
        assert project_state("vpn", cfg) == ACTIVO
    finally:
        server.shutdown()


def test_vpn_dashboard_up_but_tunnel_down_is_parcial(cfg):
    """EL bug: antes esto se mostraba como 'activo'. El dashboard responde,
    pero el túnel no conectó (por ejemplo, porque falló el laboratorio)."""
    server = _fake_vpn_dashboard("tunnel=down killswitch=off")
    cfg.ports.vpn_dashboard = server.server_address[1]
    try:
        assert project_state("vpn", cfg) == PARCIAL
        # y el proceso SÍ está corriendo: por eso hacen falta tres estados
        assert project_alive("vpn", cfg) is True
    finally:
        server.shutdown()


def test_vpn_interface_up_without_handshake_is_parcial(cfg):
    server = _fake_vpn_dashboard("tunnel=up killswitch=off")
    cfg.ports.vpn_dashboard = server.server_address[1]
    try:
        assert project_state("vpn", cfg) == PARCIAL
    finally:
        server.shutdown()


def test_vpn_without_state_endpoint_degrades_to_parcial(cfg):
    """Compatibilidad con una SecureVPN vieja: sin /state no se puede afirmar
    que el túnel esté conectado, así que se informa 'parcial', nunca activo."""
    server = _fake_vpn_dashboard(None)
    cfg.ports.vpn_dashboard = server.server_address[1]
    try:
        assert project_state("vpn", cfg) == PARCIAL
    finally:
        server.shutdown()


def test_vpn_off_is_apagado(cfg):
    assert project_state("vpn", cfg) == APAGADO


def test_proxy_state_is_direct_port_check(cfg):
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    cfg.ports.proxy_service = listener.getsockname()[1]
    try:
        # Para el proxy, el puerto ES el servicio: escuchar = activo.
        assert project_state("proxy", cfg) == ACTIVO
    finally:
        listener.close()


def test_el_snapshot_tiene_una_clave_por_proyecto(cfg, monkeypatch):
    monkeypatch.setattr("securecenter.health._tcp_open", lambda *_args, **_kwargs: False)
    snap = state_snapshot(cfg)
    assert set(snap) == {s.key for s in PROJECT_SPECS}
    assert "hips" in snap
    assert all(v == APAGADO for v in snap.values())
