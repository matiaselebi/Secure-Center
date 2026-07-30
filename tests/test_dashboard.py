import sys
import threading
import time
import urllib.request
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from securecenter.config_loader import load_config  # noqa: E402
from securecenter.dashboard import build_dashboard_server  # noqa: E402
from securecenter.logger_db import LoggerDB  # noqa: E402
from securecenter.orchestrator import Orchestrator  # noqa: E402
from securecenter.projects import discover_projects  # noqa: E402


@pytest.fixture
def dashboard(fake_stack, tmp_path):
    root, _ = fake_stack
    cfg = load_config(str(tmp_path / "no.yaml"))
    # puertos donde nadie escucha, para que la salud dé "apagado"
    cfg.ports.proxy_service = 1
    cfg.ports.dns_dashboard = 1
    cfg.ports.vpn_dashboard = 1
    projects = discover_projects(cfg, search_root=root)
    logger = LoggerDB(str(tmp_path / "c.db"))
    orch = Orchestrator(cfg, projects, logger, dry_run=True)
    server = build_dashboard_server("127.0.0.1", 0, orch, logger)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    port = server.server_address[1]
    yield f"http://127.0.0.1:{port}", orch, logger
    server.shutdown()


def get(url):
    with urllib.request.urlopen(url, timeout=5) as resp:
        return resp.status, resp.read().decode("utf-8", "replace")


def test_dashboard_shows_three_projects_and_globalbar(dashboard):
    base, _, _ = dashboard
    status, body = get(base + "/")
    assert status == 200
    for name in ("SecureProxy", "SecureDNS", "SecureVPN", "SecureCenter"):
        assert name in body
    assert "Encender núcleo" in body
    assert "PÁNICO" in body
    assert "Línea de tiempo" in body


def test_health_endpoint(dashboard):
    base, _, _ = dashboard
    status, body = get(base + "/health")
    assert status == 200 and body == "ok"


def test_start_core_runs_in_background_and_logs(dashboard):
    base, _, logger = dashboard
    get(base + "/start-core")
    # la operación corre en un hilo; esperamos a que loguee
    for _ in range(50):
        events = [e[1] for e in logger.recent_events(10)]
        if "start_core" in events:
            break
        time.sleep(0.05)
    assert "start_core" in [e[1] for e in logger.recent_events(10)]


def test_only_one_background_op_at_a_time(dashboard, monkeypatch):
    import securecenter.dashboard as dash_mod

    base, orch, logger = dashboard
    release = threading.Event()
    started = threading.Event()

    def slow_plan_start_vpn():
        started.set()
        release.wait(timeout=10)
        return []

    monkeypatch.setattr(orch, "plan_start_vpn", slow_plan_start_vpn)
    get(base + "/start-vpn")
    assert started.wait(timeout=5)
    get(base + "/start-vpn")  # segunda mientras corre la primera
    release.set()
    time.sleep(0.3)
    assert any("ya hay una operación en curso" in str(e[2]) for e in logger.recent_events(10))


def test_individual_buttons_use_hidden_input_not_query_string(dashboard):
    """Regresión: un form GET descarta la query string del action, así que
    '/stop-one?p=proxy' nunca mandaba el p y el botón 'no hacía nada'. El
    parámetro tiene que ir en un input oculto."""
    base, _, _ = dashboard
    _, body = get(base + "/")
    assert "action='/stop-one'" in body
    assert "action='/start-one'" in body
    assert "name='p' value='proxy'" in body
    assert "name='p' value='dns'" in body
    # y NO la forma vieja rota:
    assert "/stop-one?p=" not in body
    assert "/start-one?p=" not in body


def test_stop_button_asks_confirmation(dashboard):
    base, _, _ = dashboard
    _, body = get(base + "/")
    assert "querés apagar SecureProxy" in body
    assert "querés apagar SecureDNS" in body


def test_individual_start_endpoint(dashboard):
    base, _, logger = dashboard
    get(base + "/start-one?p=dns")
    for _ in range(50):
        if any("iniciar_dns" in str(e[1]) for e in logger.recent_events(10)):
            break
        time.sleep(0.05)
    assert any("iniciar_dns" in str(e[1]) for e in logger.recent_events(10))


# ---------------- consola en vivo ----------------


def _resetear_consola():
    from securecenter.dashboard import DashboardRequestHandler as H

    with H._bg_lock:
        H._bg_running = None
        H._last_result = None
        H._live_lines = []
    return H


def test_la_salida_se_ve_mientras_la_operacion_corre(dashboard):
    """Lo que se pidio: consola en tiempo real, no un silencio de varios
    minutos y despues todo el texto junto."""
    base, _, _ = dashboard
    H = _resetear_consola()
    with H._bg_lock:
        H._bg_running = "encender VPN"
        H._live_lines = [
            "> VPN: encendido completo...",
            "   [SecureVPN] Docker: Docker ya estaba corriendo",
        ]

    _status, body = get(base + "/")

    assert "EN CURSO: encender VPN" in body
    assert "resultado run" in body, "mientras corre va en ambar, ni verde ni rojo"
    assert "Docker ya estaba corriendo" in body, "la salida en vivo tiene que verse"
    _resetear_consola()


def test_al_terminar_bien_queda_en_verde(dashboard):
    base, _, _ = dashboard
    H = _resetear_consola()
    with H._bg_lock:
        H._last_result = ("apagar todo", True, ["OK: puerto 8888 liberado"])

    _status, body = get(base + "/")

    assert "resultado ok" in body
    assert "OK: apagar todo" in body
    assert "puerto 8888 liberado" in body, "el detalle no se pierde al terminar"
    _resetear_consola()


def test_al_fallar_queda_en_rojo(dashboard):
    base, _, _ = dashboard
    H = _resetear_consola()
    with H._bg_lock:
        H._last_result = ("encender VPN", False, ["ERROR: Docker no arrancó"])

    _status, body = get(base + "/")

    assert "resultado err" in body
    assert "FALLÓ: encender VPN" in body
    assert "Docker no arrancó" in body
    _resetear_consola()


def test_ya_no_manda_a_mirar_la_linea_de_tiempo(dashboard):
    """La consola esta arriba: mandar a otro lado a ver el progreso sobraba.
    La linea de tiempo se queda igual, como registro historico."""
    base, _, _ = dashboard
    H = _resetear_consola()
    with H._bg_lock:
        H._bg_running = "encender núcleo"

    _status, body = get(base + "/")

    assert "mirá la línea de tiempo" not in body
    assert "Línea de tiempo" in body, "la pestaña de registro sigue estando"
    _resetear_consola()


def test_la_consola_se_muestra_como_consola(dashboard):
    """Monoespaciada y con scroll propio: si no, un encendido largo empuja
    toda la pagina hacia abajo."""
    base, _, _ = dashboard
    H = _resetear_consola()
    with H._bg_lock:
        H._bg_running = "encender VPN"
        H._live_lines = ["linea"]

    _status, body = get(base + "/")

    assert "class='consola'" in body or 'class="consola"' in body
    assert "monospace" in body
    assert "overflow-y:auto" in body
    _resetear_consola()
