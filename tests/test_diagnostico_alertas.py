"""Fase 3 y 4: el diagnóstico con puntaje, y el centro de alertas.

Lo que más se prueba: que apagado NO cuente como problema, y que silenciar
una alerta no signifique "no me avises nunca más de esto".
"""

import sqlite3
import sys
import time
from pathlib import Path

import pytest

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ / "src"))

from securecenter import alertas, diagnostico  # noqa: E402

from securecenter.config_loader import Ports, load_config  # noqa: E402
from securecenter.health import ACTIVO, APAGADO, PARCIAL  # noqa: E402
from securecenter.projects import PROJECT_SPECS, ManagedProject  # noqa: E402


def _revision_de(revisiones, nombre):
    """`_revisar_proyectos` recorre los cinco: hay que buscar el que importa."""
    return next(r for r in revisiones if r["nombre"] == nombre)


def _proyecto(tmp_path, key, con_venv=True):
    spec = next(s for s in PROJECT_SPECS if s.key == key)
    carpeta = tmp_path / spec.package
    (carpeta / "src" / spec.package).mkdir(parents=True)
    (carpeta / "data").mkdir()
    if con_venv:
        binario = carpeta / "venv" / ("Scripts" if sys.platform == "win32" else "bin")
        binario.mkdir(parents=True)
        (binario / ("python.exe" if sys.platform == "win32" else "python")).write_text("")
    return ManagedProject(spec, carpeta)


# ------------------------------------------------------------ el puntaje


def test_todo_bien_da_cien():
    assert diagnostico.puntaje([{"estado": diagnostico.OK}] * 8) == 100


def test_lo_que_no_aplica_no_resta():
    """Un servicio apagado a propósito no puede bajarte el puntaje."""
    revisiones = [{"estado": diagnostico.NA}] * 5 + [{"estado": diagnostico.OK}]
    assert diagnostico.puntaje(revisiones) == 100


def test_algo_roto_pesa_mas_que_un_aviso():
    roto = diagnostico.puntaje([{"estado": diagnostico.MAL}])
    aviso = diagnostico.puntaje([{"estado": diagnostico.AVISO}])
    assert roto < aviso < 100


def test_el_puntaje_no_baja_de_cero():
    assert diagnostico.puntaje([{"estado": diagnostico.MAL}] * 50) == 0


# ------------------------------------------------------- las revisiones


def test_un_servicio_apagado_no_es_un_problema(tmp_path, monkeypatch):
    """Apagarlo puede ser exactamente lo que quisiste.

    Si el diagnóstico marcara en rojo todo lo que no es el estado ideal, la
    gente aprendería a ignorarlo.
    """
    projects = {"dns": _proyecto(tmp_path, "dns")}
    revisiones = diagnostico._revisar_proyectos(projects, {"dns": APAGADO})
    assert _revision_de(revisiones, "SecureDNS")["estado"] == diagnostico.NA


def test_un_servicio_que_no_contesta_si_es_un_problema(tmp_path):
    """Peor que apagado: el panel diría «arriba» y no está protegiendo."""
    projects = {"dns": _proyecto(tmp_path, "dns")}
    revisiones = diagnostico._revisar_proyectos(projects, {"dns": PARCIAL})
    revision = _revision_de(revisiones, "SecureDNS")
    assert revision["estado"] == diagnostico.MAL
    assert revision["arreglo"]


def test_sin_venv_se_marca_y_se_dice_como_arreglarlo(tmp_path):
    projects = {"dns": _proyecto(tmp_path, "dns", con_venv=False)}
    revisiones = diagnostico._revisar_proyectos(projects, {"dns": APAGADO})
    revision = _revision_de(revisiones, "SecureDNS")
    assert revision["estado"] == diagnostico.MAL
    assert "venv" in revision["arreglo"]


def test_se_detectan_dos_servicios_en_el_mismo_puerto(tmp_path):
    """Se manifiesta como «uno no arranca y no se entiende por qué»."""
    cfg = load_config(str(tmp_path / "no.yaml"))
    cfg.ports.dns_dashboard = cfg.ports.hips_dashboard
    revision = diagnostico._revisar_puertos(cfg)
    assert revision["estado"] == diagnostico.MAL
    assert "SecureDNS" in revision["detalle"] and "SecureHIPS" in revision["detalle"]


def test_con_los_puertos_de_fabrica_no_hay_choques(tmp_path):
    cfg = load_config(str(tmp_path / "no.yaml"))
    assert diagnostico._revisar_puertos(cfg)["estado"] == diagnostico.OK


def test_los_feeds_viejos_se_avisan(tmp_path):
    """El modo de falla más silencioso: datos de hace tres semanas."""
    p = _proyecto(tmp_path, "intel")
    con = sqlite3.connect(str(p.folder / "data" / "intel.db"))
    con.execute("CREATE TABLE fuentes (nombre TEXT PRIMARY KEY, ultima REAL, "
                "ok INT, total INT, error TEXT)")
    con.executemany("INSERT INTO fuentes VALUES (?,?,?,?,?)", [
        ("URLhaus", time.time(), 1, 100, ""),
        ("OpenPhish", time.time() - 30 * 86400, 1, 50, ""),
    ])
    con.commit()
    con.close()
    revision = diagnostico._revisar_feeds({"intel": p})
    assert revision["estado"] == diagnostico.AVISO
    assert "OpenPhish" in revision["detalle"]
    assert "URLhaus" not in revision["detalle"]


def test_feeds_al_dia_dan_ok(tmp_path):
    p = _proyecto(tmp_path, "intel")
    con = sqlite3.connect(str(p.folder / "data" / "intel.db"))
    con.execute("CREATE TABLE fuentes (nombre TEXT PRIMARY KEY, ultima REAL, "
                "ok INT, total INT, error TEXT)")
    con.execute("INSERT INTO fuentes VALUES ('URLhaus', ?, 1, 100, '')", (time.time(),))
    con.commit()
    con.close()
    assert diagnostico._revisar_feeds({"intel": p})["estado"] == diagnostico.OK


def test_sin_internet_se_dice_y_no_se_rompe(monkeypatch):
    monkeypatch.setattr(diagnostico, "_alcanzable", lambda *a, **k: False)
    revision = diagnostico._revisar_internet(0.1)
    assert revision["estado"] == diagnostico.MAL
    assert revision["arreglo"]


def test_si_falla_uno_solo_es_un_aviso_y_no_un_error(monkeypatch):
    llamadas = {"n": 0}

    def uno_falla(host, port, timeout=1):
        llamadas["n"] += 1
        return llamadas["n"] != 1

    monkeypatch.setattr(diagnostico, "_alcanzable", uno_falla)
    assert diagnostico._revisar_internet(0.1)["estado"] == diagnostico.AVISO


def test_la_revision_reutiliza_la_medicion_que_muestra_el_panel(monkeypatch):
    servicios = [
        {"nombre": "Cloudflare DNS", "ok": True},
        {"nombre": "AbuseIPDB", "ok": False},
    ]
    monkeypatch.setattr(
        diagnostico, "estado_de_internet",
        lambda _timeout: pytest.fail("no debe medir Internet dos veces"),
    )
    revision = diagnostico._revisar_internet(0.1, servicios)
    assert revision["estado"] == diagnostico.AVISO
    assert revision["detalle"] == "sin acceso a: AbuseIPDB"


def test_el_resumen_dice_que_hacer_y_no_cuantos_fallaron():
    revisiones = [{"nombre": "Disco", "estado": diagnostico.MAL},
                  {"nombre": "Internet", "estado": diagnostico.OK}]
    assert diagnostico.resumen(revisiones) == "Hay 1 problema: Disco."


def test_el_resumen_escribe_el_plural_naturalmente():
    revisiones = [{"nombre": "Internet", "estado": diagnostico.AVISO},
                  {"nombre": "Disco", "estado": diagnostico.AVISO}]
    assert diagnostico.resumen(revisiones) == (
        "Nada roto. Hay 2 avisos para revisar cuando puedas: Internet, Disco."
    )


# --------------------------------------------------------------- alertas


@pytest.fixture()
def registro(tmp_path):
    con = sqlite3.connect(str(tmp_path / "c.db"))
    return alertas.RegistroDeAlertas(con)


def test_un_servicio_que_no_responde_genera_alerta_alta(tmp_path):
    projects = {"dns": _proyecto(tmp_path, "dns")}
    encontradas = alertas.detectar(None, projects, {"dns": PARCIAL})
    assert len(encontradas) == 1
    assert encontradas[0]["gravedad"] == alertas.ALTA


def test_un_servicio_apagado_a_proposito_no_genera_alerta(tmp_path):
    projects = {"dns": _proyecto(tmp_path, "dns")}
    assert alertas.detectar(None, projects, {"dns": APAGADO}) == []
    assert alertas.detectar(None, projects, {"dns": ACTIVO}) == []


def test_lo_que_no_aplica_no_genera_una_alerta():
    revisiones = [
        {"nombre": "Suricata", "estado": diagnostico.NA, "detalle": "opcional"},
        {"nombre": "Gateway reenvío", "estado": diagnostico.NA,
         "detalle": "no aplica"},
        {"nombre": "Disco", "estado": diagnostico.AVISO, "detalle": "90%"},
    ]
    encontradas = alertas.detectar(None, {}, {}, revisiones)
    assert [a["titulo"] for a in encontradas] == ["Disco"]


def test_la_misma_condicion_es_la_misma_alerta(tmp_path, registro):
    """Sin huella estable, silenciar no serviría para nada."""
    projects = {"dns": _proyecto(tmp_path, "dns")}
    primera = alertas.detectar(None, projects, {"dns": PARCIAL})
    segunda = alertas.detectar(None, projects, {"dns": PARCIAL})
    assert primera[0]["huella"] == segunda[0]["huella"]
    registro.sincronizar(primera, ahora=1000)
    registro.sincronizar(segunda, ahora=2000)
    total = registro._con.execute("SELECT COUNT(*) FROM alertas").fetchone()[0]
    assert total == 1


def test_marcar_leida_se_recuerda(tmp_path, registro):
    projects = {"dns": _proyecto(tmp_path, "dns")}
    detectadas = alertas.detectar(None, projects, {"dns": PARCIAL})
    registro.sincronizar(detectadas, ahora=1000)
    assert registro.marcar(detectadas[0]["huella"], alertas.LEIDA)
    salida = registro.sincronizar(detectadas, ahora=2000)
    assert salida[0]["estado"] == alertas.LEIDA


def test_una_alerta_silenciada_que_vuelve_a_pasar_se_despierta(tmp_path, registro):
    """Silenciar no puede significar «no me avises nunca más de esto».

    Si silenciás «SecureDNS caído» y mañana se cae de nuevo después de haber
    estado bien, te tenés que enterar.
    """
    projects = {"dns": _proyecto(tmp_path, "dns")}
    detectadas = alertas.detectar(None, projects, {"dns": PARCIAL})
    registro.sincronizar(detectadas, ahora=1000)
    registro.marcar(detectadas[0]["huella"], alertas.SILENCIADA)

    registro.sincronizar([], ahora=2000)          # se arregló
    vuelta = registro.sincronizar(detectadas, ahora=3000)  # se rompió de nuevo
    assert vuelta[0]["estado"] == alertas.NUEVA


def test_mientras_la_condicion_sigue_el_silencio_se_respeta(tmp_path, registro):
    projects = {"dns": _proyecto(tmp_path, "dns")}
    detectadas = alertas.detectar(None, projects, {"dns": PARCIAL})
    registro.sincronizar(detectadas, ahora=1000)
    registro.marcar(detectadas[0]["huella"], alertas.SILENCIADA)
    salida = registro.sincronizar(detectadas, ahora=2000)
    assert salida[0]["estado"] == alertas.SILENCIADA


def test_una_alerta_que_deja_de_pasar_no_se_borra(tmp_path, registro):
    """Que desaparezca sin rastro es perder que ocurrió."""
    projects = {"dns": _proyecto(tmp_path, "dns")}
    detectadas = alertas.detectar(None, projects, {"dns": PARCIAL})
    registro.sincronizar(detectadas, ahora=1000)
    assert registro.sincronizar([], ahora=2000) == []
    fila = registro._con.execute("SELECT vigente FROM alertas").fetchone()
    assert fila[0] == 0


def test_las_graves_van_primero(tmp_path, registro):
    detectadas = [
        alertas._alerta("b", alertas.BAJA, "algo menor", ""),
        alertas._alerta("a", alertas.ALTA, "algo grave", ""),
        alertas._alerta("m", alertas.MEDIA, "algo medio", ""),
    ]
    salida = registro.sincronizar(detectadas, ahora=1000)
    assert [a["gravedad"] for a in salida] == [alertas.ALTA, alertas.MEDIA, alertas.BAJA]


def test_el_contador_solo_cuenta_las_que_nadie_miro(tmp_path, registro):
    detectadas = [alertas._alerta("x", alertas.ALTA, "algo", "")]
    registro.sincronizar(detectadas, ahora=1000)
    assert registro.sin_atender() == 1
    registro.marcar(detectadas[0]["huella"], alertas.LEIDA)
    assert registro.sin_atender() == 0


def test_un_estado_inventado_se_rechaza(registro):
    assert not registro.marcar("loquesea", "explotar")


# -------------------------------------------------- lo que se ve en el panel


def _fragmentos(tmp_path):
    from securecenter.dashboard import DashboardRequestHandler
    from securecenter.logger_db import LoggerDB
    from securecenter.orchestrator import Orchestrator

    proyectos = {}
    for spec in PROJECT_SPECS:
        carpeta = tmp_path / spec.package
        (carpeta / "src" / spec.package).mkdir(parents=True)
        (carpeta / "src" / spec.package / "__init__.py").write_text("", encoding="utf-8")
        (carpeta / "scripts").mkdir()
        (carpeta / "data").mkdir()
        proyectos[spec.key] = ManagedProject(spec, carpeta)
    o = Orchestrator(load_config(str(tmp_path / "no.yaml")), proyectos,
                     LoggerDB(str(tmp_path / "c.db")), dry_run=True)
    DashboardRequestHandler._alertas = None
    DashboardRequestHandler._ultimo_diagnostico = None
    handler = type("H", (DashboardRequestHandler,),
                   {"orchestrator": o, "logger_db": o.logger_db})
    return handler.__new__(handler)._fragmentos()


def test_el_diagnostico_va_por_el_canal_de_eventos(tmp_path):
    """Sin esto, corrías la revisión, terminaba, y la pestaña seguía diciendo
    «todavía no lo corriste» hasta recargar la página a mano."""
    frag = _fragmentos(tmp_path)
    assert "diagnostico" in frag
    assert str(hash(frag["diagnostico"])) in frag["revision"]


def test_las_alertas_van_por_el_canal_con_su_contador(tmp_path):
    frag = _fragmentos(tmp_path)
    assert "alertas" in frag and "chapa" in frag
    assert "Última evaluación:" in frag["alertas"]


def test_la_timeline_trae_los_datos_para_filtrar(tmp_path):
    """El filtro del navegador mira estos data-*: si no están, no filtra."""
    frag = _fragmentos(tmp_path)
    assert "opciones_proyecto" in frag and "opciones_tipo" in frag


def test_un_timestamp_roto_en_intel_se_marca_como_feed_viejo(tmp_path):
    p = _proyecto(tmp_path, "intel")
    con = sqlite3.connect(str(p.folder / "data" / "intel.db"))
    con.execute("CREATE TABLE fuentes (nombre TEXT PRIMARY KEY, ultima, ok INT)")
    con.execute("INSERT INTO fuentes VALUES (?,?,?)", ("URLhaus", None, 1))
    con.commit()
    con.close()

    revision = diagnostico._revisar_feeds({"intel": p})
    assert revision["estado"] == diagnostico.AVISO
    assert "URLhaus" in revision["detalle"]
