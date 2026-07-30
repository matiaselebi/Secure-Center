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


def _make_project(root: Path, folder_name: str, package: str, scripts: list[str]) -> Path:
    folder = root / folder_name
    (folder / "src" / package).mkdir(parents=True)
    (folder / "venv" / "bin").mkdir(parents=True)
    (folder / "venv" / "bin" / "python").write_text("#!fake")
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
        ["lab_up.py", "provision_server.py", "connect_vpn.py",
         "disconnect_vpn.py", "lab_down.py", "stop_dashboard.py", "restore_internet.py"],
    )
    return root, {"proxy": proxy, "dns": dns, "vpn": vpn}
