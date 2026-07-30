import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from securecenter.config_loader import load_config  # noqa: E402
from securecenter.projects import autodetect_project, discover_projects  # noqa: E402


def test_autodetect_finds_project_by_package_not_by_name(fake_stack):
    root, folders = fake_stack
    # Los nombres de carpeta son cualquier cosa; se detecta por el paquete.
    assert autodetect_project("secureproxy", root) == folders["proxy"]
    assert autodetect_project("securedns", root) == folders["dns"]
    assert autodetect_project("securevpn", root) == folders["vpn"]


def test_autodetect_returns_none_when_absent(tmp_path):
    (tmp_path / "vacio").mkdir()
    assert autodetect_project("secureproxy", tmp_path) is None


def test_discover_all_three(fake_stack, tmp_path):
    root, folders = fake_stack
    cfg = load_config(str(tmp_path / "no.yaml"))
    projects = discover_projects(cfg, search_root=root)
    assert all(projects[k].found for k in ("proxy", "dns", "vpn"))
    assert projects["dns"].folder == folders["dns"]


def test_explicit_path_overrides_autodetect(fake_stack, tmp_path):
    root, folders = fake_stack
    cfg = load_config(str(tmp_path / "no.yaml"))
    cfg.paths.proxy = str(folders["proxy"])
    projects = discover_projects(cfg, search_root=root)
    assert projects["proxy"].folder == folders["proxy"]


def test_missing_project_is_marked_not_found(tmp_path):
    empty = tmp_path / "vacia"
    empty.mkdir()
    cfg = load_config(str(tmp_path / "no.yaml"))
    projects = discover_projects(cfg, search_root=empty)
    assert not projects["proxy"].found
    assert projects["proxy"].venv_python() is None


def test_venv_python_path_shape(fake_stack, tmp_path):
    root, _ = fake_stack
    cfg = load_config(str(tmp_path / "no.yaml"))
    projects = discover_projects(cfg, search_root=root)
    python = projects["proxy"].venv_python()
    assert python is not None
    assert python.name in ("python", "python.exe")
