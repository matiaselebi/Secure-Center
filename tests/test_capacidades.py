"""Fase 3 del punto 4: cada capacidad dice si aplica en esta máquina.

El bug que esto cierra no era un error: era un SILENCIO. `if not
_is_windows(): return []` hacía que el plan saliera todo en verde sin haber
configurado nada, y quien lo miraba creía que su proxy del sistema estaba
puesto. Un botón muerto es malo; un botón que dice que funcionó sin funcionar
es peor.
"""

import platform

import pytest

from securecenter import capacidades as cap
from securecenter import diagnostico


def _es(monkeypatch, sistema: str, escritorio: bool = True):
    monkeypatch.setattr(cap.platform, "system", lambda: sistema)
    monkeypatch.setattr(cap, "_hay_escritorio", lambda: escritorio)


# ------------------------------------------------------- lo que no aplica

def test_el_proxy_del_sistema_no_aplica_en_linux(monkeypatch):
    _es(monkeypatch, "Linux")
    c = cap.proxy_del_sistema()
    assert c["estado"] == cap.NA
    # No alcanza con decir que no: hay que decir qué hacer en su lugar.
    assert "http_proxy" in c["arreglo"]


def test_el_proxy_del_sistema_si_aplica_en_windows(monkeypatch):
    _es(monkeypatch, "Windows")
    assert cap.proxy_del_sistema()["estado"] == cap.OK


def test_los_avisos_de_escritorio_no_aplican_sin_pantalla(monkeypatch):
    _es(monkeypatch, "Linux", escritorio=False)
    c = cap.notificaciones_escritorio()
    assert c["estado"] == cap.NA
    assert "Telegram" in c["arreglo"]


def test_los_avisos_de_escritorio_aplican_con_pantalla(monkeypatch):
    _es(monkeypatch, "Linux", escritorio=True)
    assert cap.notificaciones_escritorio()["estado"] == cap.OK


def test_la_vpn_no_aplica_en_linux_y_se_dice_que_es_a_proposito(monkeypatch):
    """No es algo que falte: SecureVPN está hecha contra la app de WireGuard
    de Windows. Decir 'falta' invitaría a alguien a intentar instalarla."""
    _es(monkeypatch, "Linux")
    c = cap.vpn()
    assert c["estado"] == cap.NA
    assert "decisión" in c["detalle"]


def test_el_escritorio_se_detecta_por_las_variables(monkeypatch):
    monkeypatch.setattr(cap.platform, "system", lambda: "Linux")
    monkeypatch.delenv("DISPLAY", raising=False)
    monkeypatch.delenv("WAYLAND_DISPLAY", raising=False)
    assert cap._hay_escritorio() is False
    monkeypatch.setenv("DISPLAY", ":0")
    assert cap._hay_escritorio() is True


def test_en_windows_siempre_hay_escritorio(monkeypatch):
    monkeypatch.setattr(cap.platform, "system", lambda: "Windows")
    monkeypatch.delenv("DISPLAY", raising=False)
    assert cap._hay_escritorio() is True


# --------------------------------------------------- forma y consecuencias

def test_todas_las_capacidades_tienen_la_forma_del_diagnostico():
    """Entran solas en la pestaña porque tienen las mismas claves. Si a una le
    faltara alguna, el panel se rompería al pintarla."""
    for c in cap.todas():
        assert set(c) == {"nombre", "estado", "detalle", "arreglo"}
        assert c["estado"] in (cap.OK, cap.AVISO, cap.NA)
        assert c["detalle"], f"{c['nombre']} no explica nada"


def test_lo_que_no_aplica_no_resta_puntaje():
    """No aplicar no es una falla. Si restara, un servidor headless tendría un
    puntaje bajo por no tener pantalla, que no es un problema de seguridad."""
    solo_na = [c for c in cap.todas() if c["estado"] == cap.NA]
    assert diagnostico.puntaje(solo_na) == 100


def test_las_capacidades_entran_al_diagnostico(monkeypatch):
    """Sin esto habría que dibujarlas aparte en el panel."""
    from securecenter.config_loader import Config

    monkeypatch.setattr(diagnostico, "state_snapshot", lambda cfg: {})
    revisiones = diagnostico.revisar(Config(), {})
    nombres = [r["nombre"] for r in revisiones]
    assert "Proxy del sistema" in nombres
    assert "Avisos de escritorio" in nombres


def test_el_resumen_lista_lo_que_no_aplica(monkeypatch):
    _es(monkeypatch, "Linux", escritorio=False)
    r = cap.resumen()
    assert "Proxy del sistema" in r["no_aplican"]
    assert "acá no aplica" in r["texto"]


# ------------------------------------------------ el orquestador lo dice

def _orq(tmp_path):
    import securecenter.orchestrator as orch_mod
    from securecenter.config_loader import load_config
    from securecenter.logger_db import LoggerDB

    cfg = load_config(str(tmp_path / "no.yaml"))
    return orch_mod.Orchestrator(cfg, {}, LoggerDB(str(tmp_path / "c.db")), dry_run=True)


@pytest.mark.skipif(platform.system() == "Windows",
                    reason="acá se prueba justamente el camino de NO Windows")
def test_encender_en_linux_avisa_del_proxy_en_vez_de_saltearlo(tmp_path):
    pasos = _orq(tmp_path)._set_system_proxy_steps(True)
    assert len(pasos) == 1
    ok, detalle = pasos[0].func()
    assert ok                       # no rompe el encendido...
    assert "Proxy del sistema" in detalle   # ...pero queda dicho


@pytest.mark.skipif(platform.system() == "Windows", reason="camino de NO Windows")
def test_apagar_no_repite_el_aviso(tmp_path):
    """Al apagar no hay nada que aclarar; repetirlo en cada apagado es ruido."""
    assert _orq(tmp_path)._set_system_proxy_steps(False) == []
    assert _orq(tmp_path)._set_system_dns_steps(False) == []


# ------------------------------- fase 1 del punto 8: el alcance del proxy

def test_el_proxy_no_se_prende_en_un_equipo_sin_escritorio(monkeypatch):
    """No es que "falle en Linux": es que un proxy explícito no cubre a un
    celular ni a una consola, porque a esos no hay dónde configurárselo."""
    _es(monkeypatch, "Linux", escritorio=False)
    c = cap.alcance_del_proxy()
    assert c["estado"] == cap.NA
    assert "celular" in c["detalle"]
    # Y dice cuál es la pieza que sí cubre la casa entera.
    assert "SecureDNS" in c["detalle"]


def test_el_proxy_si_aplica_en_una_pc(monkeypatch):
    _es(monkeypatch, "Linux", escritorio=True)
    assert cap.alcance_del_proxy()["estado"] == cap.OK


def test_el_alcance_del_proxy_esta_en_el_diagnostico(monkeypatch):
    _es(monkeypatch, "Linux", escritorio=False)
    nombres = [c["nombre"] for c in cap.todas()]
    assert "Alcance de SecureProxy" in nombres
