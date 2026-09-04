from __future__ import annotations

import csv
import io
import json
import shutil
import uuid
import zipfile
from pathlib import Path

from .db import Database
from .errors import PinePiError
from .events import EventLog
from .operations import OperationService, safe_name


class ExportService:
    """Builds exports from persisted data and known PinePi-owned paths only."""

    def __init__(self, database: Database, events: EventLog, operations: OperationService):
        self.db = database
        self.events = events
        self.operations = operations

    def recon(self, session_id: str, kind: str) -> tuple[bytes, str, str]:
        result = self.operations.recon_results(session_id)
        session = result["session"]
        base = f"recon_{safe_name(session['id'])}"
        if kind == "json":
            payload = {**result, "session": {key: value for key, value in session.items() if key != "output_path"}}
            return self._json(payload), base + ".json", "application/json"
        if kind != "csv":
            raise PinePiError("INVALID_EXPORT_FORMAT", "Recon export must be CSV or JSON.")
        stream = io.StringIO(newline="")
        writer = csv.writer(stream)
        writer.writerow(["record_type", "ssid_or_mac", "bssid", "channel", "signal", "security", "first_seen", "last_seen"])
        for ap in result["access_points"]:
            writer.writerow(["access_point", ap.get("ssid"), ap.get("bssid"), ap.get("channel"), ap.get("signal"), ap.get("security"), ap.get("first_seen"), ap.get("last_seen")])
        for client in result["clients"]:
            writer.writerow(["client", client.get("mac"), client.get("bssid"), "", client.get("signal"), "", client.get("first_seen"), client.get("last_seen")])
        return stream.getvalue().encode("utf-8"), base + ".csv", "text/csv; charset=utf-8"

    def logs(self, kind: str, level: str | None, component: str | None, search: str | None) -> tuple[bytes, str, str]:
        rows = self.events.list(level, component, search, 1000)
        if kind == "json":
            payload = []
            for row in rows:
                item = dict(row)
                try:
                    item["context"] = json.loads(item.pop("context_json"))
                except json.JSONDecodeError:
                    item["context"] = {}
                payload.append(item)
            return self._json(payload), "pinepi_logs.json", "application/json"
        if kind == "csv":
            stream = io.StringIO(newline="")
            writer = csv.DictWriter(stream, fieldnames=["timestamp", "level", "component", "event", "message", "context_json"])
            writer.writeheader()
            writer.writerows({key: row.get(key) for key in writer.fieldnames} for row in rows)
            return stream.getvalue().encode("utf-8"), "pinepi_logs.csv", "text/csv; charset=utf-8"
        if kind == "txt":
            lines = [f"{row['timestamp']} {row['level']:<7} {row['component']:<16} {row['event']} - {row['message']}" for row in rows]
            return ("\n".join(lines) + ("\n" if lines else "")).encode("utf-8"), "pinepi_logs.txt", "text/plain; charset=utf-8"
        raise PinePiError("INVALID_EXPORT_FORMAT", "Log export must be TXT, CSV or JSON.")

    def capture_summary(self, capture_id: str) -> tuple[bytes, str, str]:
        row = self.db.fetchone("SELECT * FROM captures WHERE id=?", (capture_id,))
        if not row:
            raise PinePiError("CAPTURE_NOT_FOUND", "Capture not found.", 404)
        path = self.operations.authorized_path(row["path"], self.operations.data_dir / "captures")
        data = {"capture": row, "analysis": self.operations.analyze_pcap(path)}
        data["capture"].pop("path", None)
        return self._json(data), f"{safe_name(row['name'])}_{capture_id[:8]}.json", "application/json"

    def ap_zip(self, session_id: str) -> tuple[Path, str]:
        session = self.db.fetchone("SELECT * FROM ap_sessions WHERE id=?", (session_id,))
        if not session:
            raise PinePiError("SESSION_NOT_FOUND", "Access Point session not found.", 404)
        clients = self.db.fetchall("SELECT mac,ip,first_seen,last_seen,rx_bytes,tx_bytes FROM ap_clients WHERE session_id=? ORDER BY first_seen", (session_id,))
        export_dir = self.operations.data_dir / "exports"
        zip_path = self.operations.authorized_path(
            export_dir / f"ap_session_{safe_name(session_id)}_{uuid.uuid4().hex[:8]}.zip", export_dir
        )
        metadata = {key: value for key, value in session.items() if key not in {"capture_path"}}
        event_rows = self.db.fetchall(
            "SELECT timestamp,level,component,event,message FROM events WHERE context_json LIKE ? ORDER BY id",
            (f'%"session_id":"{session_id}"%',),
        )
        capture = None
        if session.get("capture_path"):
            candidate = self.operations.authorized_path(session["capture_path"], self.operations.data_dir / "ap_sessions")
            capture = candidate if candidate.is_file() else None
        capture_size = capture.stat().st_size if capture else 0
        metadata["traffic_totals"] = {
            "rx_bytes": sum(item.get("rx_bytes") or 0 for item in clients),
            "tx_bytes": sum(item.get("tx_bytes") or 0 for item in clients),
        }
        metadata["capture_file"] = "traffic" + capture.suffix if capture else None
        if shutil.disk_usage(export_dir).free < capture_size + self.operations.min_free_bytes:
            raise PinePiError("INSUFFICIENT_STORAGE", "Not enough free storage to create the AP session export.", 507)
        try:
            with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=4) as archive:
                archive.writestr("metadata.json", json.dumps(metadata, indent=2, ensure_ascii=False) + "\n")
                if clients:
                    stream = io.StringIO(newline="")
                    writer = csv.DictWriter(stream, fieldnames=list(clients[0].keys()))
                    writer.writeheader()
                    writer.writerows(clients)
                    archive.writestr("clients.csv", stream.getvalue())
                if event_rows:
                    archive.writestr(
                        "events.log",
                        "\n".join(f"{item['timestamp']} {item['level']} {item['component']} {item['event']} - {item['message']}" for item in event_rows) + "\n",
                    )
                if capture:
                    archive.write(capture, "traffic" + capture.suffix, compress_type=zipfile.ZIP_STORED)
        except OSError as exc:
            zip_path.unlink(missing_ok=True)
            raise PinePiError("EXPORT_FAILED", "The AP session export could not be created.", 507) from exc
        return zip_path, f"ap_session_{safe_name(session_id)}.zip"

    @staticmethod
    def _json(value) -> bytes:
        return (json.dumps(value, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
