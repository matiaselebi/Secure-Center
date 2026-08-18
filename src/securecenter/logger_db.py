"""Eventos de orquestación de SecureCenter en SQLite (encendidos, apagados,
arranque de la VPN, pánico). Mismo patrón que los otros proyectos."""

import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path


class LoggerDB:
    def __init__(self, db_path: str):
        self.db_path = db_path
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, check_same_thread=False, timeout=5.0)
        conn.execute("PRAGMA busy_timeout=5000")
        return conn

    def _init_schema(self) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    event TEXT NOT NULL,
                    detail TEXT,
                    ok INTEGER NOT NULL
                )
                """
            )
            conn.commit()

    def log_event(self, event: str, detail: str = "", ok: bool = True) -> None:
        timestamp = datetime.now(timezone.utc).isoformat()
        with self._lock, self._connect() as conn:
            conn.execute(
                "INSERT INTO events (timestamp, event, detail, ok) VALUES (?, ?, ?, ?)",
                (timestamp, event, detail, int(ok)),
            )
            conn.commit()

    def recent_events(self, limit: int = 25) -> list[tuple]:
        with self._lock, self._connect() as conn:
            return conn.execute(
                "SELECT timestamp, event, detail, ok FROM events ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()
