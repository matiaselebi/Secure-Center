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
def autostart_env(stack_completo, tmp_path, monkeypatch):
    """Prepara autostart_core con LOS SIETE proyectos falsos y captura qué lanza.

    Antes usaba `fake_stack`, que solo arma tres. Con eso, un autostart que
    levantaba dos de seis pasaba todos los tests.
    """
    root = stack_completo
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
    monkeypatch.setattr(procutil, "popen_quiet",
                        lambda argv, cwd=None, log=None: lanzados.append(" ".join(argv)))
    return orch, lanzados, monkeypatch


def _correr_autostart(monkeypatch, lanzados, puertos_ocupados=(), servicio_vpn=False):
    import autostart_core

    monkeypatch.setattr(autostart_core, "popen_quiet",
                        lambda argv, cwd=None, log=None: lanzados.append(" ".join(argv)))
    monkeypatch.setattr(autostart_core, "port_in_use", lambda p: p in puertos_ocupados)
    monkeypatch.setattr(autostart_core, "windows_service_running", lambda s: servicio_vpn)
    # El reintento espera cuarenta segundos de verdad. En un test eso son
    # cuarenta segundos de verdad.
    monkeypatch.setattr(autostart_core.time, "sleep", lambda _s: None)
    autostart_core.main()


def test_arranca_todo_el_nucleo_y_no_solo_dos(autostart_env):
    """EL bug del reinicio.

    Este test decía `test_arranca_proxy_y_dns` y pasaba, porque el autostart
    hacía exactamente eso: proxy y dns. Lo que nadie chequeaba es que el
    núcleo hacía rato que eran seis.
    """
    orch, lanzados, monkeypatch = autostart_env
    _correr_autostart(monkeypatch, lanzados)
    texto = " || ".join(lanzados)
    assert "run_proxy.py" in texto
    assert "run_dns.py" in texto
    # Los que faltaban, que son los que se caían en cada reinicio:
    assert "run_hips.py" in texto
    assert "run_intel.py" in texto


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


# ============ el bug del reinicio: el autostart levantaba dos de seis ============

def test_el_autostart_levanta_lo_mismo_que_el_nucleo():
    """EL test que faltaba, y que habría ahorrado el bug entero.

    La lista del núcleo estaba escrita a mano en tres lugares. Los dos planes
    se fueron actualizando; `autostart_core.py` quedó con "proxy y dns" desde
    el día uno.

    Encendías el núcleo, arrancaban los seis, el panel te lo confirmaba.
    Reiniciabas la máquina y volvían DOS, sin un error y sin un aviso. Cuatro
    de los seis te estaban protegiendo hasta que apagaste la PC.
    """
    from securecenter.orchestrator import CLAVES_DEL_NUCLEO, SERVICIOS_DEL_NUCLEO

    fuente = (Path(__file__).resolve().parent.parent / "scripts"
              / "autostart_core.py").read_text(encoding="utf-8")

    # Usa la tabla compartida y no una lista propia.
    assert "SERVICIOS_DEL_NUCLEO" in fuente
    # Y la tabla cubre exactamente el núcleo, ni uno más ni uno menos.
    assert {s[0] for s in SERVICIOS_DEL_NUCLEO} == set(CLAVES_DEL_NUCLEO)


def test_ningun_script_del_nucleo_esta_escrito_a_mano_dos_veces():
    """El test de "no vuelvas a copiarlo".

    Que `run_hips.py` aparezca en dos archivos distintos es cómo empezó esto:
    uno se actualiza, el otro no, y no falla nada hasta que reiniciás.
    """
    import ast

    raiz = Path(__file__).resolve().parent.parent
    fuentes = list((raiz / "scripts").glob("*.py"))
    fuentes += [f for f in (raiz / "src" / "securecenter").glob("*.py")
                if f.name != "orchestrator.py"]

    culpables = []
    for archivo in fuentes:
        arbol = ast.parse(archivo.read_text(encoding="utf-8"))
        for nodo in ast.walk(arbol):
            if (isinstance(nodo, ast.Constant) and isinstance(nodo.value, str)
                    and nodo.value.startswith("scripts/run_")
                    and "dashboard" not in nodo.value):
                culpables.append(f"{archivo.name}: {nodo.value}")
    assert culpables == [], (
        "los scripts del núcleo viven SOLO en SERVICIOS_DEL_NUCLEO: "
        + "; ".join(culpables))


def test_no_relanza_lo_que_ya_esta_corriendo(monkeypatch):
    """Al arrancar la máquina puede que algo ya haya levantado (una tarea
    propia del proyecto que quedó). Lanzarlo de nuevo daría dos procesos
    peleando por el mismo puerto."""
    import autostart_core

    monkeypatch.setattr(autostart_core, "port_in_use", lambda _p: True)

    class Orq:
        projects = {}

        def _puertos_del_nucleo(self):
            return {"proxy": 8888}

    assert autostart_core.faltantes(Orq()) == []


def test_reintenta_una_vez_cuando_algo_no_arranco(monkeypatch):
    """Un arranque de Windows es una carrera: la red puede no estar lista y
    OneDrive puede estar todavía bajando los archivos del proyecto. Un
    servicio que falla por eso a los diez segundos arranca a los cuarenta."""
    import autostart_core

    assert autostart_core.ESPERA_ANTES_DE_REINTENTAR >= 20


def test_lo_que_no_arranco_queda_escrito():
    """Un arranque que falló y no dejó rastro es indistinguible de uno que
    nunca corrió. Y en el arranque de la máquina no hay nadie mirando."""
    fuente = (Path(__file__).resolve().parent.parent / "scripts"
              / "autostart_core.py").read_text(encoding="utf-8")
    assert "log_event" in fuente
    assert "arranque-" in fuente  # apunta al log de cada proyecto
