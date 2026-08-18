import importlib.util
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "stop_dashboard.py"
SPEC = importlib.util.spec_from_file_location("stop_dashboard", SCRIPT)
stop_dashboard = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(stop_dashboard)


class FakeProcess:
    def __init__(self, script: Path, created: float = 123.5):
        self.script = script
        self.created = created

    def cmdline(self):
        return ["python.exe", str(self.script)]

    def create_time(self):
        return self.created

    def cwd(self):
        return str(self.script.parent)


def test_rechaza_mismo_nombre_en_otra_carpeta(monkeypatch, tmp_path):
    ajeno = tmp_path / "run_dashboard.py"
    monkeypatch.setattr(stop_dashboard.psutil, "Process", lambda _pid: FakeProcess(ajeno))

    valido, _ = stop_dashboard._es_nuestro_dashboard(
        42, str(stop_dashboard.EXPECTED_SCRIPT), 123.5)

    assert not valido


def test_rechaza_pid_reutilizado_por_hora_de_creacion(monkeypatch):
    monkeypatch.setattr(
        stop_dashboard.psutil, "Process",
        lambda _pid: FakeProcess(stop_dashboard.EXPECTED_SCRIPT, created=999.0),
    )

    valido, _ = stop_dashboard._es_nuestro_dashboard(
        42, str(stop_dashboard.EXPECTED_SCRIPT), 123.5)

    assert not valido


def test_acepta_dashboard_exacto(monkeypatch):
    monkeypatch.setattr(
        stop_dashboard.psutil, "Process",
        lambda _pid: FakeProcess(stop_dashboard.EXPECTED_SCRIPT),
    )

    valido, _ = stop_dashboard._es_nuestro_dashboard(
        42, str(stop_dashboard.EXPECTED_SCRIPT), 123.5)

    assert valido
