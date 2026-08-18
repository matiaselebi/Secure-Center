import http.client
import sys
import threading
import time
import urllib.error
import urllib.parse
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
def dashboard(fake_stack, tmp_path, monkeypatch):
    import securecenter.health as health

    monkeypatch.setattr(health, "_tcp_open", lambda _host, _port, timeout=0.4: False)
    root, _ = fake_stack
    cfg = load_config(str(tmp_path / "no.yaml"))
    # puertos donde nadie escucha, para que la salud dé "apagado"
    for campo in vars(cfg.ports):
        setattr(cfg.ports, campo, 1)
    projects = discover_projects(cfg, search_root=root)
    logger = LoggerDB(str(tmp_path / "c.db"))
    orch = Orchestrator(cfg, projects, logger, dry_run=True)
    server = build_dashboard_server("127.0.0.1", 0, orch, logger)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    port = server.server_address[1]
    yield f"http://127.0.0.1:{port}", orch, logger
    server.shutdown()
    server.server_close()


def get(url):
    with urllib.request.urlopen(url, timeout=5) as resp:
        return resp.status, resp.read().decode("utf-8", "replace")


def post(url, datos=None, cabeceras=None):
    """Las acciones son POST, no GET.

    Un GET lo dispara un `<img src="http://127.0.0.1:8899/panic">` con solo
    cargar cualquier página. Un POST no, y encima acá se valida de dónde vino.
    """
    # El dashboard entrega un token CSRF HttpOnly/SameSite en su GET. Un
    # navegador lo manda solo en el POST; urllib no mantiene cookies solo, así
    # que el helper reproduce ese flujo explícitamente.
    partes = urllib.parse.urlsplit(url)
    base = f"{partes.scheme}://{partes.netloc}/"
    with urllib.request.urlopen(base, timeout=5) as inicial:
        set_cookie = inicial.headers.get("Set-Cookie", "")
    cookie = set_cookie.split(";", 1)[0]
    headers = {"Cookie": cookie}
    headers.update(cabeceras or {})
    cuerpo = urllib.parse.urlencode(datos or {}).encode()
    pedido = urllib.request.Request(url, data=cuerpo, method="POST",
                                    headers=headers)
    with urllib.request.urlopen(pedido, timeout=5) as resp:
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
    post(base + "/start-core")
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
    post(base + "/start-vpn")
    assert started.wait(timeout=5)
    post(base + "/start-vpn")  # segunda mientras corre la primera
    release.set()
    time.sleep(0.3)
    assert any("ya hay una operación en curso" in str(e[2]) for e in logger.recent_events(10))


def test_individual_buttons_match_state_and_use_hidden_input(tmp_path):
    """Regresión: un form GET descarta la query string del action, así que
    '/stop-one?p=proxy' nunca mandaba el p y el botón 'no hacía nada'. El
    parámetro tiene que ir en un input oculto."""
    from securecenter.health import ACTIVO, APAGADO

    apagado = _tarjeta_de(tmp_path, "proxy", APAGADO)
    activo = _tarjeta_de(tmp_path, "proxy", ACTIVO)
    assert "action='/start-one'" in apagado
    assert "action='/stop-one'" not in apagado
    assert "action='/restart-one'" not in apagado
    assert "action='/start-one'" not in activo
    assert "action='/stop-one'" in activo
    assert "action='/restart-one'" in activo
    assert "name='p' value='proxy'" in apagado
    assert "name='p' value='proxy'" in activo
    # y NO la forma vieja rota:
    assert "/stop-one?p=" not in activo
    assert "/start-one?p=" not in apagado


def test_stop_button_asks_confirmation(tmp_path):
    from securecenter.health import ACTIVO

    body = _tarjeta_de(tmp_path, "proxy", ACTIVO)
    assert "querés apagar SecureProxy" in body


def test_panic_is_separate_and_explains_its_effect(dashboard):
    base, _, _ = dashboard
    _, body = get(base + "/")
    assert "class='emergencybar'" in body
    assert "intenta restaurar Internet" in body
    assert "elimina sus inicios automáticos" in body


def test_status_words_are_consistent(tmp_path):
    from securecenter.health import ACTIVO, APAGADO, PARCIAL

    assert "operativo" in _tarjeta_de(tmp_path, "proxy", ACTIVO)
    assert "degradado" in _tarjeta_de(tmp_path, "vpn", PARCIAL)
    assert "detenido" in _tarjeta_de(tmp_path, "dns", APAGADO)


def test_individual_start_endpoint(dashboard):
    base, _, logger = dashboard
    post(base + "/start-one", {"p": "dns"})
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


# ------------------------------------------------------ defensas del panel


def test_una_web_cualquiera_no_puede_apagarte_todo(dashboard):
    """CSRF. Es el panel más peligroso de la suite: desde acá se apaga TODO.

    Pasar los botones de GET a POST fue el primer paso y estuvo bien, pero no
    alcanza: un formulario `application/x-www-form-urlencoded` se puede mandar
    a otro origen sin que el navegador pida permiso. Cualquier web podía
    autoenviarte un POST a /panic.
    """
    base, _, logger = dashboard
    for ruta in ("/panic", "/stop-all", "/start-core", "/stop-one"):
        try:
            post(base + ruta, {"p": "dns"},
                 {"Origin": "https://sitio-malicioso.com",
                  "Sec-Fetch-Site": "cross-site"})
            raise AssertionError(f"{ruta} aceptó un pedido de otro origen")
        except urllib.error.HTTPError as exc:
            assert exc.code == 403, ruta
    time.sleep(0.3)
    assert not logger.recent_events(10), "algo se ejecutó igual"


def test_tambien_se_frena_por_referer(dashboard):
    """Los navegadores viejos no mandan Sec-Fetch-Site."""
    base, _, _ = dashboard
    try:
        post(base + "/panic", None, {"Referer": "https://sitio-malicioso.com/x"})
        raise AssertionError("se aceptó un pedido con Referer ajeno")
    except urllib.error.HTTPError as exc:
        assert exc.code == 403


def test_un_host_inventado_se_rechaza(dashboard):
    """DNS rebinding: sin esto, el JS de otro puede LEER lo que hay acá."""
    base, _, _ = dashboard
    pedido = urllib.request.Request(base + "/", headers={"Host": "malicioso.com"})
    try:
        urllib.request.urlopen(pedido, timeout=5)
        raise AssertionError("se aceptó un Host inventado")
    except urllib.error.HTTPError as exc:
        assert exc.code == 403


def test_health_contesta_aunque_el_host_sea_raro(dashboard):
    """SecureCenter se chequea a sí mismo por IP; /health no puede depender de eso."""
    base, _, _ = dashboard
    pedido = urllib.request.Request(base + "/health", headers={"Host": "loquesea"})
    with urllib.request.urlopen(pedido, timeout=5) as r:
        assert r.status == 200


def test_un_post_directo_sin_cookie_csrf_se_rechaza(dashboard):
    base, _, logger = dashboard
    pedido = urllib.request.Request(base + "/panic", data=b"", method="POST")
    try:
        urllib.request.urlopen(pedido, timeout=5)
        raise AssertionError("se aceptó un POST sin el token CSRF")
    except urllib.error.HTTPError as exc:
        assert exc.code == 403
    assert not logger.recent_events(5)


def test_el_panel_manda_cabeceras_de_endurecimiento(dashboard):
    base, _, _ = dashboard
    with urllib.request.urlopen(base + "/", timeout=5) as resp:
        assert resp.headers.get("X-Content-Type-Options") == "nosniff"
        assert resp.headers.get("X-Frame-Options") == "DENY"
        assert "frame-ancestors 'none'" in resp.headers.get("Content-Security-Policy", "")
        assert "SameSite=Strict" in resp.headers.get("Set-Cookie", "")


def test_otro_servicio_local_no_cuenta_como_mismo_origen(dashboard):
    """127.0.0.1:8000 y 127.0.0.1:8899 son hosts iguales, pero orígenes distintos."""
    base, _, logger = dashboard
    try:
        post(base + "/panic", None, {
            "Origin": "http://127.0.0.1:8000",
            "Sec-Fetch-Site": "same-site",
        })
        raise AssertionError("se aceptó un POST de otro puerto local")
    except urllib.error.HTTPError as exc:
        assert exc.code == 403
    assert not logger.recent_events(5)


def test_post_demasiado_grande_se_rechaza_antes_de_procesarlo(dashboard):
    base, _, logger = dashboard
    partes = urllib.parse.urlsplit(base)
    with urllib.request.urlopen(base + "/", timeout=5) as inicial:
        cookie = inicial.headers.get("Set-Cookie", "").split(";", 1)[0]
    conexion = http.client.HTTPConnection(partes.hostname, partes.port, timeout=5)
    conexion.putrequest("POST", "/panic")
    conexion.putheader("Content-Length", 64 * 1024 + 1)
    conexion.putheader("Cookie", cookie)
    conexion.putheader("Origin", f"{partes.scheme}://{partes.netloc}")
    conexion.endheaders()
    respuesta = conexion.getresponse()
    assert respuesta.status == 413
    respuesta.read()
    conexion.close()
    assert not logger.recent_events(5)


# ---------------- punto 9, fase 4: el botón de pedir bloqueo

def test_bloquear_esta_detras_del_csrf_como_todo_lo_demas(dashboard):
    """Es el único endpoint que puede terminar en una regla de firewall. Que
    esté en la misma puerta que el resto no es opcional: sin el token, una
    página cualquiera abierta en otra pestaña podría hacer que tu SecureCenter
    bloquee una IP."""
    base, _, _ = dashboard
    pedido = urllib.request.Request(base + "/bloquear", data=b"h=x", method="POST")
    try:
        urllib.request.urlopen(pedido, timeout=5)
        raise AssertionError("se aceptó un POST sin el token CSRF")
    except urllib.error.HTTPError as exc:
        assert exc.code == 403


def test_bloquear_con_una_huella_que_no_existe_no_rompe_nada(dashboard):
    """No hay incidente, así que no hay IP, así que no se pide nada. El panel
    tiene que seguir contestando igual."""
    base, _, _ = dashboard
    status, _cuerpo = post(base + "/bloquear", {"h": "no-existe-0"})
    assert status in (200, 302, 303)


# ---------------- las tarjetas de Secure-Scanner y Secure-Agent

def _tarjeta_de(tmp_path, clave, estado=None, operacion_en_curso=False):
    """El HTML de una tarjeta, llamando al método directo.

    Se prueba así y no pidiendo la página entera porque la fixture del panel
    arma solo tres proyectos y con puertos de prueba; los que interesan acá
    son el sexto y el séptimo, con los puertos reales.
    """
    from securecenter.config_loader import Config
    from securecenter.dashboard import DashboardRequestHandler
    from securecenter.health import APAGADO
    from securecenter.logger_db import LoggerDB
    from securecenter.orchestrator import Orchestrator
    from securecenter.projects import PROJECT_SPECS

    orquestador = Orchestrator(Config(), {}, LoggerDB(str(tmp_path / "c.db")))
    spec = next(s for s in PROJECT_SPECS if s.key == clave)
    handler = object.__new__(DashboardRequestHandler)
    handler.orchestrator = orquestador

    class Presente:
        found = True

        def __init__(self, spec):
            self.spec = spec

    return DashboardRequestHandler._project_section(
        handler, spec, {clave: Presente(spec)},
        APAGADO if estado is None else estado,
        operacion_en_curso=operacion_en_curso,
    )


def test_la_tarjeta_del_agente_muestra_el_puerto_que_dice_si_esta_vivo(tmp_path):
    """Mostraba el 8896, que es un panel que Secure-Agent no tiene. La tarjeta
    apuntaba a un puerto donde no escucha nadie."""
    html = _tarjeta_de(tmp_path, "agente")
    assert "8895" in html
    assert "8896" not in html


def test_no_se_ofrece_un_panel_que_no_existe(tmp_path):
    """Un link que da 405 es peor que no dar ninguno: hace pensar que el
    servicio está roto cuando está perfecto."""
    html = _tarjeta_de(tmp_path, "agente")
    assert "servidor receptor" in html
    assert "detección de incidentes" in html
    assert "línea de tiempo" not in html
    assert "abrir su dashboard" not in html


def test_una_operacion_en_curso_deshabilita_las_acciones(tmp_path):
    from securecenter.health import ACTIVO

    html = _tarjeta_de(tmp_path, "proxy", ACTIVO, operacion_en_curso=True)
    assert "disabled aria-disabled='true'" in html


def test_el_scanner_si_ofrece_su_panel(tmp_path):
    html = _tarjeta_de(tmp_path, "scanner")
    assert "8894" in html
    assert "dashboard" in html
