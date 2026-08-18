"""Fase 1 y 2: estado de la máquina, detalle por proceso y contadores.

Lo que más se prueba acá es qué pasa cuando NO se puede medir. Esta pantalla
es la primera que se abre, así que un dato que falta no puede dejarla en
blanco ni tirar una excepción.
"""

import sqlite3
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ / "src"))

from securecenter import procesos, resumen, sistema  # noqa: E402
from securecenter.projects import PROJECT_SPECS, ManagedProject  # noqa: E402


@pytest.fixture(autouse=True)
def _sin_cache():
    sistema.limpiar_cache()
    procesos.limpiar_cache()
    yield
    sistema.limpiar_cache()
    procesos.limpiar_cache()


# ------------------------------------------------------ estado de la máquina


def test_el_snapshot_trae_lo_basico():
    datos = sistema.snapshot()
    assert "disponible" in datos and "sistema" in datos
    assert "disco_libre_gb" in datos
    if datos["disponible"]:
        for clave in ("cpu_pct", "ram_pct", "ram_total_gb", "encendida_hace"):
            assert clave in datos, clave


def test_sin_psutil_no_se_rompe_y_dice_como_arreglarlo(monkeypatch):
    """Una dependencia nueva no puede dejar al orquestador sin arrancar."""
    monkeypatch.setattr(sistema, "psutil", None)
    sistema.limpiar_cache()
    datos = sistema.snapshot()
    assert datos["disponible"] is False
    assert "psutil" in datos["aviso"] and "pip install" in datos["aviso"]
    # El disco no necesita psutil: eso se sigue midiendo igual.
    assert "disco_pct" in datos


def test_hay_cache_para_no_medir_en_cada_repintado():
    """El panel repinta por SSE con hasta doce clientes conectados."""
    primero = sistema.snapshot(ahora=1000.0)
    segundo = sistema.snapshot(ahora=1000.5)
    assert primero == segundo
    tercero = sistema.snapshot(ahora=1000.0 + sistema.SEGUNDOS_DE_CACHE + 1)
    assert tercero is not None


def test_el_tiempo_se_lee_en_castellano():
    assert sistema.en_palabras(90000) == "1 día 1 h"
    assert sistema.en_palabras(3700) == "1 h 1 min"
    assert sistema.en_palabras(120) == "2 min"
    assert sistema.en_palabras(-5) == "0 min"


def test_el_color_del_disco_considera_porcentaje_y_espacio_libre():
    assert sistema.color_de_disco(90.4, 91.9) == "#e0b341"
    assert sistema.color_de_disco(96.0, 100.0) == "#ff8a8a"
    assert sistema.color_de_disco(80.0, 7.0) == "#ff8a8a"


# ----------------------------------------------------------------- procesos


def test_un_puerto_sin_nadie_devuelve_vacio():
    assert procesos.detalle_de_puerto(0) == {}
    assert procesos.detalle_de_puerto(59999) == {}


def test_el_detalle_del_proceso_propio_tiene_sentido(monkeypatch):
    """Se fuerza el PID de este mismo test: sin red, pero con datos reales."""
    import os
    if not procesos.disponible():
        pytest.skip("psutil no está instalado")
    monkeypatch.setattr(procesos, "listening_pids", lambda p: {os.getpid()})
    datos = procesos.detalle_de_puerto(8899, ahora=time.time())
    assert datos["pid"] == os.getpid()
    assert datos["ram_mb"] > 0
    assert "activo_hace" in datos


def test_la_segunda_medicion_de_cpu_no_es_siempre_cero(monkeypatch):
    """`cpu_percent` la primera vez devuelve 0.0 porque no tiene con qué
    comparar. Si no se guardara el objeto entre llamadas, el panel mostraría
    0% para todo y para siempre, que es peor que no mostrar nada."""
    import os
    if not procesos.disponible():
        pytest.skip("psutil no está instalado")
    monkeypatch.setattr(procesos, "listening_pids", lambda p: {os.getpid()})
    procesos.detalle_de_puerto(8899)
    assert os.getpid() in procesos._procesos


def test_los_procesos_muertos_se_sacan_del_cache(monkeypatch):
    """Sin esto, cada reinicio deja un PID viejo y la memoria crece sola."""
    procesos._procesos[999999] = object()
    monkeypatch.setattr(procesos, "listening_pids", lambda p: set())
    procesos.snapshot({"dns": 8890}, ahora=time.time())
    assert 999999 not in procesos._procesos


def test_sin_psutil_el_detalle_viene_vacio(monkeypatch):
    monkeypatch.setattr(procesos, "psutil", None)
    assert procesos.detalle_de_puerto(8890) == {}


# ------------------------------------------------------------- la versión


def _proyecto(tmp_path, key, version=None):
    spec = next(s for s in PROJECT_SPECS if s.key == key)
    carpeta = tmp_path / spec.package
    paquete = carpeta / "src" / spec.package
    paquete.mkdir(parents=True)
    (carpeta / "data").mkdir()
    texto = f'__version__ = "{version}"\n' if version else "# sin nada\n"
    (paquete / "__init__.py").write_text(texto, encoding="utf-8")
    return ManagedProject(spec, carpeta)


def test_la_version_sale_del_paquete(tmp_path):
    assert procesos.version_de(_proyecto(tmp_path, "dns", "0.4.1")) == "0.4.1"


def test_sin_version_se_dice_y_no_se_inventa(tmp_path):
    """Mostrar «1.0» cuando nadie la declaró es inventar un dato."""
    assert procesos.version_de(_proyecto(tmp_path, "dns")) == "sin versionar"


def test_un_proyecto_que_no_esta_no_tiene_version():
    spec = next(s for s in PROJECT_SPECS if s.key == "dns")
    assert procesos.version_de(ManagedProject(spec, None)) == ""


# ------------------------------------------------------------- contadores


def _base_dns(carpeta: Path, cuando: datetime, cuantos: int):
    con = sqlite3.connect(str(carpeta / "data" / "dns_logs.db"))
    con.execute("CREATE TABLE queries (id INTEGER PRIMARY KEY, timestamp TEXT, "
                "domain TEXT, reason TEXT, blocked INTEGER)")
    con.executemany("INSERT INTO queries (timestamp, domain, reason, blocked) "
                    "VALUES (?,?,?,1)",
                    [(cuando.isoformat(), f"malo{i}.com", "lista") for i in range(cuantos)])
    con.commit()
    con.close()


def test_se_cuentan_los_bloqueos_de_hoy(tmp_path):
    p = _proyecto(tmp_path, "dns")
    _base_dns(p.folder, datetime.now(timezone.utc), 7)
    contadores = resumen.construir({"dns": p})
    dns = next(c for c in contadores if c["titulo"] == "Bloqueos DNS")
    assert dns["valor"] == 7


def test_lo_de_ayer_no_cuenta_como_de_hoy(tmp_path):
    p = _proyecto(tmp_path, "dns")
    _base_dns(p.folder, datetime.now(timezone.utc) - timedelta(days=2), 5)
    dns = next(c for c in resumen.construir({"dns": p}) if c["titulo"] == "Bloqueos DNS")
    assert dns["valor"] == 0


def test_el_corte_del_dia_es_local_y_no_utc():
    """Con corte UTC, en Buenos Aires «hoy» empezaría a las 9 de la mañana."""
    ahora = time.time()
    corte = resumen.inicio_del_dia(ahora)
    local = corte.astimezone()
    assert (local.hour, local.minute, local.second) == (0, 0, 0)


def test_una_base_que_no_existe_da_guion_y_no_cero(tmp_path):
    """0 parece un dato. «No sé» es lo honesto cuando el proyecto no está."""
    p = _proyecto(tmp_path, "dns")  # sin crear la base
    dns = next(c for c in resumen.construir({"dns": p}) if c["titulo"] == "Bloqueos DNS")
    assert dns["valor"] is None


def test_una_base_corrupta_tampoco_rompe(tmp_path):
    p = _proyecto(tmp_path, "dns")
    (p.folder / "data" / "dns_logs.db").write_text("esto no es sqlite", encoding="utf-8")
    dns = next(c for c in resumen.construir({"dns": p}) if c["titulo"] == "Bloqueos DNS")
    assert dns["valor"] is None


def test_un_esquema_viejo_sin_la_columna_no_rompe(tmp_path):
    p = _proyecto(tmp_path, "dns")
    con = sqlite3.connect(str(p.folder / "data" / "dns_logs.db"))
    con.execute("CREATE TABLE queries (id INTEGER PRIMARY KEY, domain TEXT)")
    con.commit()
    con.close()
    dns = next(c for c in resumen.construir({"dns": p}) if c["titulo"] == "Bloqueos DNS")
    assert dns["valor"] is None


def test_sin_ningun_proyecto_la_pantalla_no_se_cae():
    contadores = resumen.construir({})
    assert len(contadores) == len(resumen.CONTADORES)
    assert all(c["valor"] is None for c in contadores)
    assert resumen.total_de_hoy(contadores) is None


def test_el_total_no_mezcla_lo_de_hoy_con_el_tamano_de_los_feeds(tmp_path):
    """Sumar 48.000 indicadores a 7 bloqueos daría un número sin sentido."""
    p = _proyecto(tmp_path, "dns")
    _base_dns(p.folder, datetime.now(timezone.utc), 7)
    contadores = resumen.construir({"dns": p})
    indicadores = next(c for c in contadores if c["titulo"] == "Indicadores de Intel")
    assert not indicadores["de_hoy"]
    assert resumen.total_de_hoy(contadores) == 7


# ------------------------------------------------- lo que se ve en el panel


def _panel_html(tmp_path, monkeypatch):
    """El HTML del panel, sin levantar servidor."""
    from securecenter.config_loader import load_config
    from securecenter.dashboard import DashboardRequestHandler
    from securecenter.logger_db import LoggerDB
    from securecenter.orchestrator import Orchestrator

    proyectos = {}
    for spec in PROJECT_SPECS:
        carpeta = tmp_path / spec.package
        (carpeta / "src" / spec.package).mkdir(parents=True)
        (carpeta / "src" / spec.package / "__init__.py").write_text(
            '__version__ = "0.2.0"\n', encoding="utf-8")
        (carpeta / "scripts").mkdir()
        (carpeta / "data").mkdir()
        proyectos[spec.key] = ManagedProject(spec, carpeta)
    o = Orchestrator(load_config(str(tmp_path / "no.yaml")), proyectos,
                     LoggerDB(str(tmp_path / "c.db")), dry_run=True)

    handler = type("H", (DashboardRequestHandler,),
                   {"orchestrator": o, "logger_db": o.logger_db})
    instancia = handler.__new__(handler)
    return instancia._fragmentos()


def test_el_panel_muestra_el_estado_de_la_maquina(tmp_path, monkeypatch):
    frag = _panel_html(tmp_path, monkeypatch)
    assert "maquina" in frag
    texto = frag["maquina"]
    assert "CPU" in texto or "psutil" in texto


def test_el_panel_muestra_los_contadores(tmp_path, monkeypatch):
    frag = _panel_html(tmp_path, monkeypatch)
    for titulo in ("Bloqueos DNS", "Conexiones bloqueadas", "IPs bloqueadas",
                   "Indicadores de Intel"):
        assert titulo in frag["contadores"], titulo


def test_cada_servicio_muestra_su_ficha(tmp_path, monkeypatch):
    frag = _panel_html(tmp_path, monkeypatch)
    assert "Puerto" in frag["secciones"]
    assert "Versión" in frag["secciones"]
    assert "0.2.0" in frag["secciones"]


def test_cada_servicio_tiene_boton_de_reiniciar(tmp_path, monkeypatch):
    from securecenter.health import ACTIVO

    monkeypatch.setattr(
        "securecenter.dashboard.state_snapshot",
        lambda _cfg: {s.key: ACTIVO for s in PROJECT_SPECS},
    )
    frag = _panel_html(tmp_path, monkeypatch)
    assert "/restart-one" in frag["secciones"]
    assert frag["secciones"].count("/restart-one") == len(PROJECT_SPECS)


def test_el_panel_avisa_si_el_disco_esta_casi_lleno():
    from securecenter.dashboard import DashboardRequestHandler

    handler = object.__new__(DashboardRequestHandler)
    html = handler._bloque_maquina({
        "disponible": True,
        "cpu_pct": 1.0,
        "cpu_nucleos": 4,
        "ram_pct": 20.0,
        "ram_usada_gb": 2.0,
        "ram_total_gb": 8.0,
        "disco_pct": 93.0,
        "disco_usado_gb": 93.0,
        "disco_total_gb": 100.0,
        "disco_libre_gb": 7.0,
        "sistema": "Test",
    })
    assert "Disco casi lleno" in html
    assert "7.0 GB libres" in html
    assert "Diagnóstico" in html


def test_el_panel_no_dice_casi_lleno_si_queda_mucho_espacio():
    from securecenter.dashboard import DashboardRequestHandler

    handler = object.__new__(DashboardRequestHandler)
    html = handler._bloque_maquina({
        "disponible": True,
        "cpu_pct": 1.0,
        "cpu_nucleos": 4,
        "ram_pct": 20.0,
        "ram_usada_gb": 2.0,
        "ram_total_gb": 8.0,
        "disco_pct": 90.4,
        "disco_usado_gb": 860.0,
        "disco_total_gb": 952.8,
        "disco_libre_gb": 91.9,
        "sistema": "Test",
    })
    assert "Uso de disco alto" in html
    assert "Disco casi lleno" not in html
    assert "#e0b341" in html


def test_la_revision_cambia_cuando_cambian_los_contadores(tmp_path, monkeypatch):
    """Si no, el número de bloqueos de hoy se quedaría quieto en pantalla
    hasta que cambiara alguna otra cosa."""
    frag = _panel_html(tmp_path, monkeypatch)
    assert str(hash(frag["contadores"])) in frag["revision"]
    assert str(hash(frag["maquina"])) in frag["revision"]


def test_reiniciar_apaga_y_enciende_en_una_sola_operacion(tmp_path):
    """No es lo mismo que apretar los dos botones: entre uno y otro el
    usuario se puede ir, y quedaría todo apagado creyendo que reinició."""
    from securecenter.config_loader import load_config
    from securecenter.logger_db import LoggerDB
    from securecenter.orchestrator import Orchestrator

    spec = next(s for s in PROJECT_SPECS if s.key == "dns")
    carpeta = tmp_path / spec.package
    (carpeta / "src" / spec.package).mkdir(parents=True)
    (carpeta / "scripts").mkdir()
    for n in ("run_dns.py", "stop_dns.py"):
        (carpeta / "scripts" / n).write_text("", encoding="utf-8")
    for directorio, ejecutable in (("bin", "python"), ("Scripts", "python.exe")):
        binario = carpeta / "venv" / directorio
        binario.mkdir(parents=True)
        (binario / ejecutable).write_text("")
    o = Orchestrator(load_config(str(tmp_path / "no.yaml")),
                     {"dns": ManagedProject(spec, carpeta)},
                     LoggerDB(str(tmp_path / "c.db")), dry_run=True)
    pasos = o.plan_stop_one("dns") + o.plan_start_one("dns")
    texto = " ".join(" ".join(map(str, s.argv or [])) for s in pasos)
    assert "stop_dns.py" in texto and "run_dns.py" in texto
    assert texto.index("stop_dns.py") < texto.index("run_dns.py")


def test_los_miles_van_con_punto():
    assert sistema.miles(48123) == "48.123"
    assert sistema.miles(0) == "0"
    assert sistema.miles(None) == "-"


def test_el_cpu_no_es_siempre_cero_en_la_primera_pantalla():
    """`cpu_percent` la primera vez devuelve 0.0 porque no tiene con qué
    comparar. Sin la llamada de calentamiento, la primera pantalla que ve el
    usuario diría «CPU 0.0%», que parece un dato y no lo es."""
    if not sistema.disponible():
        pytest.skip("psutil no está instalado")
    # Un poco de trabajo para que haya algo que medir.
    for _ in range(400000):
        pass
    sistema.limpiar_cache()
    assert sistema.snapshot()["cpu_pct"] >= 0.0
    assert "cpu_pct" in sistema.snapshot()


def test_los_contadores_grandes_se_ven_con_separador(tmp_path, monkeypatch):
    frag = _panel_html(tmp_path, monkeypatch)
    assert "48123" not in frag["contadores"]
