"""Fase 6: historial con gráficos, y el motor de reglas.

De las automatizaciones lo que más se prueba son los frenos. «Si un servicio
no responde, reinicialo» es la regla más obvia y la más peligrosa: si el
servicio no puede arrancar, se reinicia para siempre.
"""

import sqlite3
import sys
import time
from pathlib import Path

import pytest

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ / "src"))

from securecenter import automatizaciones as auto  # noqa: E402
from securecenter import metricas  # noqa: E402
from securecenter.health import ACTIVO, APAGADO, PARCIAL  # noqa: E402


@pytest.fixture()
def historial(tmp_path):
    return metricas.Historial(sqlite3.connect(str(tmp_path / "c.db")))


# -------------------------------------------------------------- historial


def test_se_guardan_y_se_leen_las_muestras(historial):
    for i in range(5):
        historial.guardar({"disponible": True, "cpu_pct": 10 + i,
                           "ram_pct": 50, "disco_pct": 30}, ahora=1000 + i)
    assert len(historial.serie(horas=1, ahora=1010)) == 5


def test_sin_psutil_no_se_guardan_filas_vacias(historial):
    """Filas con nulos ensucian el gráfico con huecos que parecen caídas."""
    assert not historial.guardar({"disponible": False}, ahora=1000)
    assert historial.serie(horas=1, ahora=1000) == []


def test_lo_viejo_se_borra(historial):
    historial.guardar({"disponible": True, "cpu_pct": 1, "ram_pct": 1,
                       "disco_pct": 1}, ahora=1000)
    historial.guardar({"disponible": True, "cpu_pct": 2, "ram_pct": 2,
                       "disco_pct": 2}, ahora=1000 + 8 * 86400)
    assert historial.podar(dias=7, ahora=1000 + 8 * 86400) == 1
    assert len(historial.serie(horas=24 * 30, ahora=1000 + 8 * 86400)) == 1


def test_el_rango_deja_afuera_lo_de_antes(historial):
    historial.guardar({"disponible": True, "cpu_pct": 5, "ram_pct": 5,
                       "disco_pct": 5}, ahora=1000)
    historial.guardar({"disponible": True, "cpu_pct": 6, "ram_pct": 6,
                       "disco_pct": 6}, ahora=10000)
    assert len(historial.serie(horas=1, ahora=10000)) == 1


# ---------------------------------------------------------------- gráfico


def test_el_grafico_es_un_svg_sin_librerias():
    """El panel tiene que andar sin internet: es una herramienta de seguridad
    y puede estar corriendo justo cuando la red no anda."""
    svg = metricas.grafico("CPU", [10, 50, 90], "#fff")
    assert "<svg" in svg and "<polyline" in svg
    assert "http" not in svg and "script" not in svg


def test_el_grafico_muestra_ultimo_maximo_y_promedio():
    svg = metricas.grafico("CPU", [10, 90, 20], "#fff")
    assert "20%" in svg and "máximo 90%" in svg and "promedio 40%" in svg


def test_una_sola_muestra_no_rompe_el_dibujo():
    assert "<polyline" in metricas.grafico("CPU", [42], "#fff")


def test_sin_muestras_se_dice_y_no_se_dibuja_una_linea_falsa():
    assert "todavía no hay muestras" in metricas.grafico("CPU", [], "#fff")


def test_los_valores_se_recortan_al_rango_del_dibujo():
    """Un valor fuera de 0-100 dibujaría la línea afuera del recuadro."""
    puntos = metricas._puntos([-20, 500], 100, 50)
    for par in puntos.split():
        y = float(par.split(",")[1])
        assert 0 <= y <= 50


def test_el_bloque_avisa_cuando_no_hay_nada(historial):
    assert "Todavía no hay muestras" in metricas.bloque(historial, 1, ahora=1000)


def test_el_disco_al_noventa_se_muestra_en_ambar(historial):
    historial.guardar({"disponible": True, "cpu_pct": 5, "ram_pct": 40,
                       "disco_pct": 90.4}, ahora=1000)
    html = metricas.bloque(historial, 1, ahora=1000)
    assert "#e0b341" in html


# ------------------------------------------------------------ disparadores


def _ctx(**kw):
    base = {"health": {}, "alertas": [], "revisiones": [], "maquina": {},
            "puntaje": None}
    base.update(kw)
    return base


def test_se_dispara_con_un_servicio_que_no_responde():
    objetivos = auto._servicio_no_responde(_ctx(health={"dns": PARCIAL, "proxy": ACTIVO}))
    assert objetivos == ["dns"]


def test_un_servicio_apagado_no_dispara_nada():
    """Apagarlo puede ser exactamente lo que quisiste."""
    assert auto._servicio_no_responde(_ctx(health={"dns": APAGADO})) == []


def test_el_disco_lleno_dispara():
    assert auto._disco_lleno(_ctx(maquina={"disco_pct": 95})) == ["*"]
    assert auto._disco_lleno(_ctx(maquina={"disco_pct": 40})) == []


def test_el_diagnostico_bajo_dispara():
    assert auto._diagnostico_bajo(_ctx(puntaje=55)) == ["*"]
    assert auto._diagnostico_bajo(_ctx(puntaje=95)) == []
    assert auto._diagnostico_bajo(_ctx()) == [], "sin diagnóstico corrido, nada"


# ------------------------------------------------------------- los frenos


def _motor(sirve=True):
    hechas = []

    def ejecutor(accion, objetivo):
        hechas.append((accion, objetivo))
        return sirve, "listo"

    regla = auto.Regla("servicio_no_responde", "reiniciar", habilitado=True)
    return auto.Motor([regla], ejecutor), regla, hechas


def test_todo_viene_apagado_por_defecto():
    """Reiniciar servicios solo es algo que se prende a propósito."""
    assert all(not r.habilitado for r in auto.reglas_por_defecto())


def test_una_regla_apagada_no_hace_nada_ni_ensucia_la_pantalla():
    """Antes devolvía «se cumplió pero no corrió: desactivada», y eso llenaba
    la pantalla de líneas sobre reglas que apagaste para no verlas."""
    motor = auto.Motor([auto.Regla("disco_lleno", "avisar")], lambda a, o: (True, ""))
    assert motor.evaluar(_ctx(maquina={"disco_pct": 99}), ahora=1000) == []


def test_la_regla_prendida_ejecuta_la_accion():
    motor, _, hechas = _motor()
    motor.evaluar(_ctx(health={"dns": PARCIAL}), ahora=1000)
    assert hechas == [("reiniciar", "dns")]


def test_no_se_repite_antes_de_la_espera():
    """Sin esto, un servicio que no puede arrancar se reinicia cada vuelta."""
    motor, _, hechas = _motor()
    motor.evaluar(_ctx(health={"dns": PARCIAL}), ahora=1000)
    motor.evaluar(_ctx(health={"dns": PARCIAL}), ahora=1060)
    assert len(hechas) == 1


def test_pasada_la_espera_vuelve_a_correr():
    motor, _, hechas = _motor()
    motor.evaluar(_ctx(health={"dns": PARCIAL}), ahora=1000)
    motor.evaluar(_ctx(health={"dns": PARCIAL}), ahora=1000 + 700)
    assert len(hechas) == 2


def test_hay_un_tope_por_hora():
    motor, regla, hechas = _motor()
    regla.espera = 60
    for i in range(10):
        motor.evaluar(_ctx(health={"dns": PARCIAL}), ahora=1000 + i * 100)
    assert len(hechas) == regla.maximo_por_hora


def test_si_no_arregla_nada_la_regla_se_apaga_sola():
    """Una automatización que no funciona tiene que pedir ayuda, no insistir."""
    motor, regla, hechas = _motor(sirve=False)
    regla.espera = 60
    regla.maximo_por_hora = 99
    for i in range(5):
        motor.evaluar(_ctx(health={"dns": PARCIAL}), ahora=1000 + i * 100)
    assert regla.apagada_por_fallas
    assert len(hechas) == 3


def test_si_arregla_el_contador_de_fallas_se_reinicia():
    motor, regla, _ = _motor(sirve=True)
    regla.fallas_seguidas = 2
    motor.evaluar(_ctx(health={"dns": PARCIAL}), ahora=1000)
    assert regla.fallas_seguidas == 0
    assert not regla.apagada_por_fallas


def test_cuando_no_corre_se_explica_por_que():
    """«No pasó nada» sin motivo es lo peor que puede mostrar un panel."""
    motor, _, _ = _motor()
    motor.evaluar(_ctx(health={"dns": PARCIAL}), ahora=1000)
    hechos = motor.evaluar(_ctx(health={"dns": PARCIAL}), ahora=1060)
    assert hechos and not hechos[0]["corrio"]
    assert "esperando" in hechos[0]["detalle"]


def test_una_accion_que_explota_no_frena_las_demas_reglas():
    def ejecutor(accion, objetivo):
        raise RuntimeError("boom")

    motor = auto.Motor(
        [auto.Regla("servicio_no_responde", "reiniciar", habilitado=True),
         auto.Regla("disco_lleno", "avisar", habilitado=True)], ejecutor)
    hechos = motor.evaluar(_ctx(health={"dns": PARCIAL},
                                maquina={"disco_pct": 99}), ahora=1000)
    assert len(hechos) == 2
    assert all("boom" in h["detalle"] for h in hechos)


def test_queda_historial_de_lo_que_hizo():
    motor, _, _ = _motor()
    motor.evaluar(_ctx(health={"dns": PARCIAL}), ahora=1000)
    assert motor.historial and motor.historial[0]["objetivo"] == "dns"


def test_el_titulo_de_la_regla_se_lee_en_castellano():
    regla = auto.Regla("servicio_no_responde", "reiniciar")
    assert regla.titulo().startswith("Si un servicio no responde")
