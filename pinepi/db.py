from __future__ import annotations

import json
import sqlite3
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

SCHEMA_VERSION = 1


class Database:
    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()

    @contextmanager
    def connection(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.path, timeout=10)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 10000")
        try:
            yield connection
            connection.commit()
        finally:
            connection.close()

    def migrate(self) -> None:
        with self._lock, self.connection() as db:
            db.execute("PRAGMA journal_mode = WAL")
            db.executescript(
                """
                CREATE TABLE IF NOT EXISTS schema_meta (
                    version INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS recon_sessions (
                    id TEXT PRIMARY KEY, interface TEXT NOT NULL, mode TEXT NOT NULL,
                    started_at TEXT NOT NULL, ended_at TEXT, status TEXT NOT NULL,
                    stop_reason TEXT, output_path TEXT
                );
                CREATE TABLE IF NOT EXISTS access_points (
                    session_id TEXT NOT NULL REFERENCES recon_sessions(id) ON DELETE CASCADE,
                    bssid TEXT NOT NULL, ssid TEXT, channel INTEGER, signal INTEGER,
                    security TEXT, first_seen TEXT, last_seen TEXT,
                    PRIMARY KEY(session_id, bssid)
                );
                CREATE TABLE IF NOT EXISTS recon_clients (
                    session_id TEXT NOT NULL REFERENCES recon_sessions(id) ON DELETE CASCADE,
                    mac TEXT NOT NULL, bssid TEXT, signal INTEGER, first_seen TEXT, last_seen TEXT,
                    PRIMARY KEY(session_id, mac)
                );
                CREATE TABLE IF NOT EXISTS ap_sessions (
                    id TEXT PRIMARY KEY, ssid TEXT NOT NULL, interface TEXT NOT NULL,
                    requested_uplink TEXT, effective_uplink TEXT, security TEXT NOT NULL,
                    channel INTEGER NOT NULL, started_at TEXT NOT NULL, ended_at TEXT,
                    status TEXT NOT NULL, log_clients INTEGER NOT NULL,
                    capture_traffic INTEGER NOT NULL, capture_path TEXT, stop_reason TEXT
                );
                CREATE TABLE IF NOT EXISTS ap_clients (
                    session_id TEXT NOT NULL REFERENCES ap_sessions(id) ON DELETE CASCADE,
                    mac TEXT NOT NULL, ip TEXT, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
                    rx_bytes INTEGER, tx_bytes INTEGER,
                    PRIMARY KEY(session_id, mac)
                );
                CREATE TABLE IF NOT EXISTS captures (
                    id TEXT PRIMARY KEY, name TEXT NOT NULL, interface TEXT NOT NULL,
                    channel INTEGER NOT NULL, started_at TEXT NOT NULL, ended_at TEXT,
                    status TEXT NOT NULL, path TEXT NOT NULL, packet_count INTEGER,
                    size_bytes INTEGER NOT NULL DEFAULT 0, stop_reason TEXT
                );
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT NOT NULL,
                    level TEXT NOT NULL, component TEXT NOT NULL, event TEXT NOT NULL,
                    message TEXT NOT NULL, context_json TEXT NOT NULL DEFAULT '{}'
                );
                CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp DESC);
                CREATE INDEX IF NOT EXISTS idx_events_component ON events(component);
                """
            )
            row = db.execute("SELECT version FROM schema_meta LIMIT 1").fetchone()
            if row is None:
                db.execute("INSERT INTO schema_meta(version) VALUES (?)", (SCHEMA_VERSION,))
            elif row["version"] < SCHEMA_VERSION:
                db.execute("UPDATE schema_meta SET version = ?", (SCHEMA_VERSION,))

    def execute(self, sql: str, params: tuple = ()) -> None:
        with self._lock, self.connection() as db:
            db.execute(sql, params)

    def fetchone(self, sql: str, params: tuple = ()) -> dict | None:
        with self.connection() as db:
            row = db.execute(sql, params).fetchone()
            return dict(row) if row else None

    def fetchall(self, sql: str, params: tuple = ()) -> list[dict]:
        with self.connection() as db:
            return [dict(row) for row in db.execute(sql, params).fetchall()]

    def insert_event(self, timestamp: str, level: str, component: str, event: str, message: str, context: dict) -> None:
        with self._lock, self.connection() as db:
            db.execute(
                "INSERT INTO events(timestamp, level, component, event, message, context_json) VALUES(?,?,?,?,?,?)",
                (timestamp, level, component, event, message, json.dumps(context, separators=(",", ":"))),
            )
            # Keep the appliance log bounded without touching session/capture data.
            db.execute("DELETE FROM events WHERE id <= (SELECT COALESCE(MAX(id),0)-50000 FROM events)")
