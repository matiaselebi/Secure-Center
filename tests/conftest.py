"""Fixtures compartidas: un trío falso de proyectos en disco.

Para probar la orquestación sin los proyectos reales, se arma una carpeta
'proyectos/' con tres subcarpetas que tienen la estructura mínima que
SecureCenter reconoce: src/<paquete>, venv/bin/python y scripts/. Los nombres
de carpeta son distintos a propósito, para probar que la autodetección no
depende del nombre sino del paquete.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))


@pytest.fixture(autouse=True)
def _equipo_de_escritorio(monkeypatch):
    """Por defecto, los tests corren como si hubiera pantalla.

    Hace falta desde que SecureProxy no se prende en equipos sin escritorio
    (fase 1 del punto 8): sin esto, el plan del núcleo salía distinto en una
    PC que en el runner de CI, que es headless. Un test que depende de si
    quien lo corre tiene monitor no prueba el código, prueba la máquina.

    Los tests que quieren el caso servidor borran DISPLAY ellos mismos, que
    es donde se ve de qué se trata cada uno.
    """
    monkeypatch.setenv("DISPLAY", ":0")


def _make_project(root: Path, folder_name: str, package: str, scripts: list[str]) -> Path:
    folder = root / folder_name
    (folder / "src" / package).mkdir(parents=True)
    # Los DOS layouts de venv, porque hay tests que simulan Windows con
    # monkeypatch corriendo en Linux. Con uno solo, al simular el otro sistema
    # el intérprete "no existe" y los planes salen distintos.
    (folder / "venv" / "bin").mkdir(parents=True)
    (folder / "venv" / "bin" / "python").write_text("#!fake")
    (folder / "venv" / "Scripts").mkdir(parents=True)
    for exe in ("python.exe", "pythonw.exe"):
        (folder / "venv" / "Scripts" / exe).write_text("fake")
    (folder / "scripts").mkdir()
    (folder / "data").mkdir()
    for s in scripts:
        (folder / "scripts" / s).write_text("# fake script")
    return folder


@pytest.fixture
def fake_stack(tmp_path):
    """Devuelve (search_root, {key: folder}) con los tres proyectos falsos."""
    root = tmp_path / "Proyectos Github"
    root.mkdir()
    proxy = _make_project(root, "mi-proxy", "secureproxy", ["run_proxy.py", "stop_proxy.py"])
    dns = _make_project(root, "carpeta-dns", "securedns", ["run_dns.py", "stop_dns.py"])
    vpn = _make_project(
        root, "vpn-final", "securevpn",
        # La lista tiene que incluir TODOS los scripts que el orquestador
        # nombra, no solo algunos. Faltaban `start_vpn.py` y
        # `run_dashboard.py`, que en el proyecto real existen: mientras el
        # código no chequeaba si el archivo estaba, la fixture incompleta no
        # se notaba.
        ["lab_up.py", "provision_server.py", "connect_vpn.py",
         "disconnect_vpn.py", "lab_down.py", "stop_dashboard.py",
         "restore_internet.py", "start_vpn.py", "run_dashboard.py"],
    )
    return root, {"proxy": proxy, "dns": dns, "vpn": vpn}


# Los scripts que el orquestador le pide a cada proyecto. La tabla está acá y
# no se importa del código porque es lo que los tests verifican: que para cada
# clave de PROJECT_SPECS exista un plan de encendido y uno de apagado.
SCRIPTS_POR_PROYECTO = {
    "proxy": ["run_proxy.py", "stop_proxy.py"],
    "dns": ["run_dns.py", "stop_dns.py"],
    "hips": ["run_hips.py", "stop_hips.py"],
    "intel": ["run_intel.py", "stop_intel.py"],
    "scanner": ["run_scanner.py", "stop_scanner.py"],
    "agente": ["run_servidor.py", "stop_servidor.py"],
    "vpn": ["lab_up.py", "provision_server.py", "connect_vpn.py",
            "disconnect_vpn.py", "lab_down.py", "stop_dashboard.py",
            "restore_internet.py", "start_vpn.py", "run_dashboard.py"],
}


@pytest.fixture
def stack_completo(tmp_path, monkeypatch):
    """Los SIETE proyectos en disco, no tres.

    `fake_stack` arma proxy, dns y vpn. Con eso se escondieron dos bugs: el
    KeyError que hacía que los botones de Secure-Scanner y Secure-Agent no
    hicieran nada, y el arranque automático que levantaba dos de seis y nadie
    lo notaba hasta reiniciar la máquina.
    """
    from securecenter.projects import PROJECT_SPECS

    monkeypatch.setenv("SECUREAGENT_TOKEN", "un-token-de-prueba")
    raiz = tmp_path / "Proyectos Github"
    raiz.mkdir()
    for spec in PROJECT_SPECS:
        carpeta = raiz / f"carpeta-{spec.key}"
        (carpeta / "src" / spec.package).mkdir(parents=True)
        (carpeta / "venv" / "bin").mkdir(parents=True)
        (carpeta / "venv" / "bin" / "python").write_text("#!fake")
        (carpeta / "venv" / "Scripts").mkdir(parents=True)
        for exe in ("python.exe", "pythonw.exe"):
            (carpeta / "venv" / "Scripts" / exe).write_text("fake")
        (carpeta / "scripts").mkdir()
        (carpeta / "data").mkdir()
        for script in SCRIPTS_POR_PROYECTO[spec.key]:
            (carpeta / "scripts" / script).write_text("# fake")
    return raiz


