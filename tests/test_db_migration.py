from __future__ import annotations

import sqlite3

from pinepi.db import SCHEMA_VERSION, Database


def test_version_one_database_migrates_without_losing_sessions(tmp_path):
    path = tmp_path / "pinepi-v1.db"
    with sqlite3.connect(path) as connection:
        connection.executescript(
            """
            CREATE TABLE schema_meta (version INTEGER NOT NULL);
            INSERT INTO schema_meta(version) VALUES (1);
            CREATE TABLE ap_sessions (
                id TEXT PRIMARY KEY, ssid TEXT NOT NULL, interface TEXT NOT NULL,
                requested_uplink TEXT, effective_uplink TEXT, security TEXT NOT NULL,
                channel INTEGER NOT NULL, started_at TEXT NOT NULL, ended_at TEXT,
                status TEXT NOT NULL, log_clients INTEGER NOT NULL,
                capture_traffic INTEGER NOT NULL, capture_path TEXT, stop_reason TEXT
            );
            CREATE TABLE captures (
                id TEXT PRIMARY KEY, name TEXT NOT NULL, interface TEXT NOT NULL,
                channel INTEGER NOT NULL, started_at TEXT NOT NULL, ended_at TEXT,
                status TEXT NOT NULL, path TEXT NOT NULL, packet_count INTEGER,
                size_bytes INTEGER NOT NULL DEFAULT 0, stop_reason TEXT
            );
            INSERT INTO ap_sessions(
                id,ssid,interface,security,channel,started_at,status,log_clients,capture_traffic
            ) VALUES ('ap-old','Existing AP','wlan1','open',6,'2026-01-01T00:00:00+00:00','COMPLETED',1,0);
            INSERT INTO captures(
                id,name,interface,channel,started_at,status,path
            ) VALUES ('capture-old','Existing capture','wlan1',6,'2026-01-01T00:00:00+00:00','COMPLETED','/tmp/existing.pcapng');
            """
        )

    database = Database(path)
    database.migrate()

    assert database.fetchone("SELECT version FROM schema_meta")["version"] == SCHEMA_VERSION
    ap = database.fetchone("SELECT * FROM ap_sessions WHERE id='ap-old'")
    capture = database.fetchone("SELECT * FROM captures WHERE id='capture-old'")
    assert ap["ssid"] == "Existing AP"
    assert "resolved_channel" in ap
    assert capture["name"] == "Existing capture"
    assert capture["capture_mode"] == "raw"
    assert database.fetchone("SELECT COUNT(*) AS count FROM current_target")["count"] == 0
