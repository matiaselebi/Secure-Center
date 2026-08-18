import socket
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from securecenter.config_loader import load_config  # noqa: E402
from securecenter.health import health_snapshot, project_alive  # noqa: E402
from securecenter.projects import PROJECT_SPECS  # noqa: E402


def test_alive_true_with_listener(tmp_path):
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]

    cfg = load_config(str(tmp_path / "no.yaml"))
    cfg.ports.proxy_service = port
    assert project_alive("proxy", cfg) is True
    listener.close()


def test_alive_false_when_nothing_listens(tmp_path):
    cfg = load_config(str(tmp_path / "no.yaml"))
    cfg.ports.dns_dashboard = 1  # nadie escucha
    assert project_alive("dns", cfg) is False


def test_snapshot_tiene_una_clave_por_proyecto(tmp_path, monkeypatch):
    """Se compara contra PROJECT_SPECS y no contra una lista escrita a mano:
    así, sumar un proyecto al registro no obliga a acordarse de este test.
    Esa lista escrita a mano era parte de lo que hacía que agregar una
    herramienta significara tocar seis archivos."""
    cfg = load_config(str(tmp_path / "no.yaml"))
    cfg.ports.proxy_service = 1
    cfg.ports.dns_dashboard = 1
    cfg.ports.vpn_dashboard = 1
    cfg.ports.hips_dashboard = 1
    monkeypatch.setattr("securecenter.health._tcp_open", lambda *_args, **_kwargs: False)
    snap = health_snapshot(cfg)
    assert set(snap.keys()) == {s.key for s in PROJECT_SPECS}
    assert "hips" in snap
    assert all(v is False for v in snap.values())
