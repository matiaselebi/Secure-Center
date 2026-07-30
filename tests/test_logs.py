import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from securecenter.config_loader import load_config  # noqa: E402
from securecenter.logs import collect_logs  # noqa: E402
from securecenter.projects import discover_projects  # noqa: E402


def _seed_proxy(db: Path):
    conn = sqlite3.connect(db)
    conn.execute(
        "CREATE TABLE requests (id INTEGER PRIMARY KEY, timestamp TEXT, client_ip TEXT, "
        "method TEXT, host TEXT, port INTEGER, path TEXT, blocked INTEGER, reason TEXT, duration_ms REAL)"
    )
    conn.execute(
        "INSERT INTO requests (timestamp, host, blocked, reason) VALUES (?,?,?,?)",
        ("2026-07-26T10:00:00+00:00", "malo.com", 1, "IP en blocklist"),
    )
    conn.commit()
    conn.close()


def _seed_dns(db: Path):
    conn = sqlite3.connect(db)
    conn.execute(
        "CREATE TABLE queries (id INTEGER PRIMARY KEY, timestamp TEXT, client_ip TEXT, "
        "domain TEXT, qtype TEXT, blocked INTEGER, reason TEXT, source TEXT, duration_ms REAL)"
    )
    conn.execute(
        "INSERT INTO queries (timestamp, domain, blocked, reason) VALUES (?,?,?,?)",
        ("2026-07-26T11:00:00+00:00", "phishing.net", 1, "dominio en blocklist"),
    )
    conn.commit()
    conn.close()


def _seed_vpn(db: Path):
    conn = sqlite3.connect(db)
    conn.execute(
        "CREATE TABLE events (id INTEGER PRIMARY KEY, timestamp TEXT, event TEXT, detail TEXT, ok INTEGER)"
    )
    conn.execute(
        "INSERT INTO events (timestamp, event, detail, ok) VALUES (?,?,?,?)",
        ("2026-07-26T12:00:00+00:00", "connect", "peer pc", 1),
    )
    conn.commit()
    conn.close()


def test_collect_merges_and_sorts_desc(fake_stack, tmp_path):
    root, folders = fake_stack
    _seed_proxy(folders["proxy"] / "data" / "proxy_logs.db")
    _seed_dns(folders["dns"] / "data" / "dns_logs.db")
    _seed_vpn(folders["vpn"] / "data" / "vpn_logs.db")

    cfg = load_config(str(tmp_path / "no.yaml"))
    projects = discover_projects(cfg, search_root=root)
    rows = collect_logs(cfg, projects)

    assert len(rows) == 3
    # Más nuevo primero: la VPN (12:00), después DNS (11:00), después proxy (10:00).
    assert [r.project for r in rows] == ["SecureVPN", "SecureDNS", "SecureProxy"]
    assert "phishing.net" in rows[1].detail


def test_collect_handles_missing_dbs(fake_stack, tmp_path):
    """Si un proyecto nunca corrió (sin DB), no rompe: se saltea."""
    root, folders = fake_stack
    _seed_vpn(folders["vpn"] / "data" / "vpn_logs.db")
    cfg = load_config(str(tmp_path / "no.yaml"))
    projects = discover_projects(cfg, search_root=root)
    rows = collect_logs(cfg, projects)
    assert len(rows) == 1
    assert rows[0].project == "SecureVPN"


def test_collect_empty_when_nothing_ran(fake_stack, tmp_path):
    root, _ = fake_stack
    cfg = load_config(str(tmp_path / "no.yaml"))
    projects = discover_projects(cfg, search_root=root)
    assert collect_logs(cfg, projects) == []
