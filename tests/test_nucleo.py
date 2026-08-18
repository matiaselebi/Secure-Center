"""Quiénes entran al núcleo, y por qué los dos últimos son un caso aparte.

El núcleo siempre fue "lo que no molesta prendido todo el día". Secure-Scanner
y Secure-Agent habían quedado afuera por la misma clase de razón que la VPN, y
mirándolo de nuevo esa razón solo era buena para uno de los dos.
"""

import sys
from pathlib import Path

import pytest
import yaml

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ / "src"))

from securecenter import nucleo  # noqa: E402
from securecenter.config_loader import NucleoConfig  # noqa: E402


class Falso:
    """Un proyecto en disco, con lo mínimo que mira `nucleo.py`."""

    found = True

    def __init__(self, carpeta):
        self.folder = carpeta


@pytest.fixture
def proyectos(tmp_path, monkeypatch):
    monkeypatch.delenv("SECUREAGENT_TOKEN", raising=False)
    salida = {}
    for clave in ("scanner", "agente"):
        carpeta = tmp_path / clave
        (carpeta / "config").mkdir(parents=True)
        salida[clave] = Falso(carpeta)
    return salida


def _config(project, datos):
    (Path(project.folder) / "config" / "config.yaml").write_text(
        yaml.safe_dump(datos), encoding="utf-8")


def _env(project, texto):
    (Path(project.folder) / ".env").write_text(texto, encoding="utf-8")


# ----------------------------------------------------- Secure-Agent

def test_el_agente_configurado_entra(proyectos):
    """Tenerlo apagado pierde datos para siempre: los agentes empujan y no
    guardan cola en disco, así que cada minuto que el servidor está abajo es
    telemetría que no se recupera."""
    _env(proyectos["agente"], "SECUREAGENT_TOKEN=abc123\n")
    _config(proyectos["agente"], {"servidor": {"habilitado": True}})
    entra, _motivo = nucleo.evaluar(proyectos)["agente"]
    assert entra


def test_sin_token_el_agente_no_entra_y_se_dice_por_que(proyectos):
    """Sin token no arranca (un token por defecto es un token público), así
    que tampoco tiene sentido prenderlo con el núcleo."""
    entra, motivo = nucleo.evaluar(proyectos)["agente"]
    assert not entra
    assert "SECUREAGENT_TOKEN" in motivo


def test_si_su_config_lo_apaga_no_entra(proyectos):
    """El mismo repositorio corre de dos formas. En una máquina que solo es
    agente, el servidor está apagado a propósito."""
    _env(proyectos["agente"], "SECUREAGENT_TOKEN=abc123\n")
    _config(proyectos["agente"], {"servidor": {"habilitado": False}})
    entra, motivo = nucleo.evaluar(proyectos)["agente"]
    assert not entra
    assert "habilitado" in motivo


def test_el_token_del_entorno_tambien_vale(proyectos, monkeypatch):
    monkeypatch.setenv("SECUREAGENT_TOKEN", "abc123")
    assert nucleo.evaluar(proyectos)["agente"][0]


def test_una_clave_vacia_cuenta_como_que_falta(proyectos):
    """`SECUREAGENT_TOKEN=` es el caso más fácil de dejar a medias: copiaste
    el .env.example y no lo completaste."""
    _env(proyectos["agente"], "SECUREAGENT_TOKEN=\n")
    assert not nucleo.evaluar(proyectos)["agente"][0]


# ---------------------------------------------------- Secure-Scanner

def test_con_el_rango_fijado_el_scanner_entra(proyectos):
    """La tabla de novedades ("apareció un equipo nuevo", "este se fue") solo
    significa algo si se mira seguido. Un escaneo cuando te acordás no detecta
    que apareció algo el martes."""
    _config(proyectos["scanner"], {"red": {"rango": "192.168.1.0/24"}})
    entra, motivo = nucleo.evaluar(proyectos)["scanner"]
    assert entra
    assert "192.168.1.0/24" in motivo


def test_sin_rango_fijado_no_entra(proyectos):
    """El argumento en contra es real: manda paquetes a equipos que no son
    tuyos. Si el rango se autodetecta puede agarrar la red equivocada en una
    máquina con VPN, Docker o dos placas."""
    _config(proyectos["scanner"], {"red": {"rango": ""}})
    entra, motivo = nucleo.evaluar(proyectos)["scanner"]
    assert not entra
    assert "autodetecta" in motivo
    assert "no son tuyos" in motivo


def test_sin_config_tampoco_entra(proyectos):
    """No poder leer su configuración no es lo mismo que estar configurado."""
    assert not nucleo.evaluar(proyectos)["scanner"][0]


def test_un_yaml_roto_no_rompe_nada(proyectos):
    (Path(proyectos["scanner"].folder) / "config" / "config.yaml").write_text(
        "esto: no es: yaml: valido:\n", encoding="utf-8")
    assert not nucleo.evaluar(proyectos)["scanner"][0]


# ------------------------------------------------- forzar a mano

def test_se_puede_forzar_que_entre(proyectos):
    """Es una decisión de quien lo usa. Lo que no se puede es que sea
    invisible."""
    entra, motivo = nucleo.evaluar(
        proyectos, NucleoConfig(scanner="si"))["scanner"]
    assert entra
    assert "forzado" in motivo


def test_se_puede_forzar_que_no_entre(proyectos):
    _config(proyectos["scanner"], {"red": {"rango": "192.168.1.0/24"}})
    entra, motivo = nucleo.evaluar(
        proyectos, NucleoConfig(scanner="no"))["scanner"]
    assert not entra
    assert "config.yaml" in motivo


def test_un_valor_raro_se_trata_como_auto(proyectos):
    _config(proyectos["scanner"], {"red": {"rango": "192.168.1.0/24"}})
    assert nucleo.evaluar(proyectos, NucleoConfig(scanner="cualquier cosa"))["scanner"][0]


# ----------------------------------------- lo que NO está instalado

def test_un_proyecto_que_no_esta_ni_se_menciona(proyectos):
    """Nadie tiene que enterarse de que no tiene un proyecto que nunca clonó.
    No es una decisión, es un dato, y no genera ningún paso."""
    class Ausente:
        found = False
        folder = Path("/no/existe")

    evaluacion = nucleo.evaluar({"scanner": Ausente(), "agente": Ausente()})
    assert evaluacion == {}


def test_los_que_entran_devuelve_solo_las_claves(proyectos):
    _config(proyectos["scanner"], {"red": {"rango": "10.0.0.0/24"}})
    assert nucleo.los_que_entran(proyectos) == ["scanner"]
