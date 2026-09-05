from __future__ import annotations

import csv
import json
import re
import shutil
import threading
import time
import uuid
from collections import Counter
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

import psutil

from .adapters import AdapterService, Reservation, ReservationRegistry
from .db import Database
from .errors import PinePiError, require
from .events import EventLog
from .privileged import OwnedProcess, PrivilegedService

BSSID_PATTERN = re.compile(r"^(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")
AP_AUTO_24_CHANNELS = (1, 6, 11)
AP_AUTO_5_CHANNELS = (36, 40, 44, 48, 149, 153, 157, 161, 165)
RECON_RECOMMENDATION_MAX_AGE = 15 * 60
TARGET_RECENT_MAX_AGE = 30 * 60
NOTE_LABELS = {"test target", "trusted", "investigate", "lab ap"}


def utcnow() -> str:
    return datetime.now(UTC).isoformat()


def safe_name(value: str, fallback: str = "capture") -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_-]+", "_", str(value)).strip("_-")[:64]
    return cleaned or fallback


def elapsed_seconds(started_at: str | None) -> int:
    if not started_at:
        return 0
    try:
        started = datetime.fromisoformat(started_at)
        end = datetime.now(UTC)
        return max(0, int((end - started).total_seconds()))
    except ValueError:
        return 0


def channel_band(channel: int) -> str | None:
    if 1 <= channel <= 14:
        return "2.4"
    if 32 <= channel <= 177:
        return "5"
    return None


def channel_frequency(channel: int) -> int | None:
    band = channel_band(channel)
    if band == "2.4":
        return 2484 if channel == 14 else 2407 + channel * 5
    if band == "5":
        return 5000 + channel * 5
    return None


@dataclass
class ActiveRecon:
    id: str
    interface: str
    mode: str
    started_at: str
    prefix: Path
    reservation: Reservation
    process: OwnedProcess
    state: str = "RUNNING"


@dataclass
class ActiveCapture:
    id: str
    name: str
    interface: str
    channel: int
    started_at: str
    path: Path
    reservation: Reservation
    process: OwnedProcess
    capture_mode: str = "raw"
    target: dict | None = None
    state: str = "RUNNING"


@dataclass
class ActiveAP:
    id: str
    interface: str
    ssid: str
    channel: int
    security: str
    requested_uplink: str
    effective_uplink: str | None
    started_at: str
    session_dir: Path
    reservation: Reservation
    uplink_reservation: Reservation | None
    hostapd: OwnedProcess
    dnsmasq: OwnedProcess
    routing: dict | None
    capture: OwnedProcess | None
    capture_path: Path | None
    log_clients: bool
    capture_traffic: bool
    requested_band: str = "auto"
    resolved_band: str = "2.4"
    requested_channel: str = "auto"
    channel_score: float | None = None
    recommendation_reason: str = ""
    state: str = "RUNNING"
    connected_macs: set[str] = field(default_factory=set)


class OperationService:
    def __init__(
        self,
        database: Database,
        events: EventLog,
        adapters: AdapterService,
        registry: ReservationRegistry,
        privileged: PrivilegedService,
        data_dir: Path,
        max_capture_bytes: int,
        min_free_bytes: int,
        reconcile: bool = True,
    ):
        self.db = database
        self.events = events
        self.adapters = adapters
        self.registry = registry
        self.privileged = privileged
        self.data_dir = data_dir.resolve()
        self.max_capture_bytes = max_capture_bytes
        self.min_free_bytes = min_free_bytes
        self._recon_lock = threading.RLock()
        self._capture_lock = threading.RLock()
        self._ap_lock = threading.RLock()
        self._recon: ActiveRecon | None = None
        self._capture: ActiveCapture | None = None
        self._ap: ActiveAP | None = None
        if reconcile:
            self.reconcile_startup()

    def reconcile_startup(self) -> None:
        restored = self.privileged.reconcile_runtime()
        for export in (self.data_dir / "exports").glob("*.zip"):
            export.unlink(missing_ok=True)
        now = utcnow()
        for table in ("recon_sessions", "captures", "ap_sessions"):
            self.db.execute(
                f"UPDATE {table} SET status='INTERRUPTED', ended_at=?, stop_reason='service_restart' "
                "WHERE status IN ('STARTING','RUNNING','STOPPING')",
                (now,),
            )
        self.db.execute("DELETE FROM current_target")
        self.db.execute("DELETE FROM network_monitor")
        self.registry.clear()
        self.events.write("INFO", "system", "startup_reconciled", "Startup reconciliation completed.", restored=restored)

    def check_storage(self, expected_bytes: int | None = None) -> dict:
        usage = shutil.disk_usage(self.data_dir)
        expected = min(expected_bytes or self.max_capture_bytes, self.max_capture_bytes)
        required = self.min_free_bytes + min(expected, 64 * 1024 * 1024)
        if usage.free < required:
            self.events.write(
                "WARNING", "storage", "insufficient_space", "Capture start blocked by the free-space guard.",
                free_bytes=usage.free, required_bytes=required,
            )
            raise PinePiError(
                "INSUFFICIENT_STORAGE",
                "Not enough free storage to begin capture safely.",
                507,
                {"free_bytes": usage.free, "required_bytes": required},
            )
        return {"total": usage.total, "used": usage.used, "free": usage.free}

    def _cleanup_call(self, component: str, operation_id: str, action: str, callback) -> bool:
        try:
            callback()
            return True
        except Exception as exc:  # noqa: BLE001
            try:
                context = self._failure_context(exc, "failed")
                context.update({"operation_id": operation_id, "action": action})
                self.events.write(
                    "ERROR", component, "cleanup_failed", "A lifecycle cleanup step failed.", **context,
                )
            except Exception:  # noqa: BLE001
                return False
            return False

    @staticmethod
    def _failure_context(exc: Exception, cleanup_result: str) -> dict:
        context = {
            "error": getattr(exc, "message", str(exc)) or type(exc).__name__,
            "error_code": getattr(exc, "code", type(exc).__name__),
            "cleanup_result": cleanup_result,
        }
        if isinstance(exc, PinePiError):
            context.update(exc.details)
            context["cleanup_result"] = cleanup_result
        return context

    @staticmethod
    def _age_seconds(value: str | None) -> float | None:
        if not value:
            return None
        try:
            observed = datetime.fromisoformat(value)
            if observed.tzinfo is None:
                observed = observed.astimezone()
            now = datetime.now(observed.tzinfo)
            return max(0.0, (now - observed).total_seconds())
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _validate_bssid(value: str) -> str:
        bssid = str(value or "").upper()
        require(bool(BSSID_PATTERN.fullmatch(bssid)), "INVALID_BSSID", "BSSID must be a valid MAC address.")
        return bssid

    @staticmethod
    def _network_payload(network: dict) -> dict:
        channel = int(network["channel"]) if network.get("channel") is not None else None
        band = channel_band(channel) if channel is not None else None
        return {
            "ssid": network.get("ssid") or "<hidden>",
            "bssid": str(network.get("bssid") or "").upper(),
            "channel": channel,
            "frequency": channel_frequency(channel) if channel is not None else None,
            "band": band,
            "security": network.get("security") or "Unknown",
            "signal": network.get("signal"),
            "first_seen": network.get("first_seen"),
            "last_seen": network.get("last_seen"),
        }

    def _recon_snapshot(self) -> tuple[list[dict], list[dict], dict | None]:
        if self._recon:
            session = self.db.fetchone("SELECT * FROM recon_sessions WHERE id=?", (self._recon.id,))
            aps, clients = self._parse_airodump(self._recon.prefix)
            return aps, clients, session
        session = self.db.fetchone("SELECT * FROM recon_sessions ORDER BY started_at DESC LIMIT 1")
        if not session:
            return [], [], None
        aps = self.db.fetchall(
            "SELECT * FROM access_points WHERE session_id=? ORDER BY signal DESC", (session["id"],)
        )
        clients = self.db.fetchall(
            "SELECT * FROM recon_clients WHERE session_id=? ORDER BY signal DESC", (session["id"],)
        )
        return aps, clients, session

    def _latest_network(self, bssid: str) -> dict | None:
        bssid = self._validate_bssid(bssid)
        if self._recon:
            aps, _clients = self._parse_airodump(self._recon.prefix)
            live = next((item for item in aps if item.get("bssid") == bssid), None)
            if live:
                return self._network_payload(live)
        row = self.db.fetchone(
            "SELECT ap.* FROM access_points ap "
            "JOIN recon_sessions rs ON rs.id=ap.session_id "
            "WHERE ap.bssid=? ORDER BY rs.started_at DESC LIMIT 1",
            (bssid,),
        )
        return self._network_payload(row) if row else None

    # Current network target. It is persisted for page reloads and cleared when
    # the PinePi service performs startup reconciliation.
    def current_target(self) -> dict:
        row = self.db.fetchone("SELECT * FROM current_target WHERE id=1")
        if not row:
            return {"selected": False, "currently_observed": False}
        latest = self._latest_network(row["bssid"])
        target = {key: value for key, value in row.items() if key != "id"}
        if latest:
            for key in ("ssid", "channel", "frequency", "band", "security", "signal", "last_seen"):
                if latest.get(key) is not None:
                    target[key] = latest[key]
        live_match = False
        if self._recon:
            aps, _clients = self._parse_airodump(self._recon.prefix)
            live_match = any(
                item.get("bssid") == row["bssid"]
                and (self._age_seconds(item.get("last_seen")) or 0) <= 90
                for item in aps
            )
        age = self._age_seconds(target.get("last_seen"))
        return {
            "selected": True,
            **target,
            "currently_observed": live_match,
            "last_seen_age_seconds": int(age) if age is not None else None,
        }

    def set_current_target(self, data: dict) -> dict:
        bssid = self._validate_bssid(data.get("bssid", ""))
        network = self._latest_network(bssid)
        if not network or network.get("channel") is None or not network.get("band"):
            raise PinePiError(
                "TARGET_NOT_OBSERVED",
                "The requested BSSID is not available in Recon observations.",
                404,
                {"bssid": bssid},
            )
        selected_at = utcnow()
        self.db.execute(
            "INSERT INTO current_target(id,bssid,ssid,channel,frequency,band,security,signal,last_seen,selected_at) "
            "VALUES(1,?,?,?,?,?,?,?,?,?) "
            "ON CONFLICT(id) DO UPDATE SET bssid=excluded.bssid,ssid=excluded.ssid,"
            "channel=excluded.channel,frequency=excluded.frequency,band=excluded.band,"
            "security=excluded.security,signal=excluded.signal,last_seen=excluded.last_seen,"
            "selected_at=excluded.selected_at",
            (
                bssid, network["ssid"], network["channel"], network["frequency"], network["band"],
                network["security"], network["signal"], network["last_seen"], selected_at,
            ),
        )
        self.events.write(
            "INFO", "target", "selected", "Current network target selected.",
            bssid=bssid, ssid=network["ssid"], channel=network["channel"], band=network["band"],
        )
        return self.current_target()

    def clear_current_target(self) -> dict:
        previous = self.db.fetchone("SELECT bssid,ssid FROM current_target WHERE id=1")
        self.db.execute("DELETE FROM current_target")
        if previous:
            self.events.write(
                "INFO", "target", "cleared", "Current network target cleared.", **previous,
            )
        return {"selected": False, "currently_observed": False}

    def _target_for_capture(self, supplied_bssid: str | None = None) -> dict:
        target = self.current_target()
        if supplied_bssid:
            bssid = self._validate_bssid(supplied_bssid)
            if not target.get("selected") or target.get("bssid") != bssid:
                target = self.set_current_target({"bssid": bssid})
        if not target.get("selected"):
            raise PinePiError("TARGET_REQUIRED", "Select a Recon network before starting targeted capture.", 409)
        age = target.get("last_seen_age_seconds")
        if age is None or age > TARGET_RECENT_MAX_AGE:
            raise PinePiError(
                "TARGET_NOT_RECENT",
                "The selected target has not been observed recently enough for targeted capture.",
                409,
                {"bssid": target.get("bssid"), "last_seen": target.get("last_seen")},
            )
        return target

    def network_note(self, bssid: str) -> dict:
        bssid = self._validate_bssid(bssid)
        row = self.db.fetchone("SELECT * FROM network_notes WHERE bssid=?", (bssid,))
        return row or {"bssid": bssid, "bookmarked": 0, "note": "", "label": None}

    def update_network_note(self, bssid: str, data: dict) -> dict:
        bssid = self._validate_bssid(bssid)
        network = self._latest_network(bssid)
        if not network:
            raise PinePiError("TARGET_NOT_OBSERVED", "Network is not available in Recon history.", 404)
        note = str(data.get("note", "")).strip()
        require(len(note) <= 500 and not any(ord(char) < 9 for char in note), "INVALID_NOTE", "Note must be at most 500 characters.")
        label = str(data.get("label", "")).strip().lower() or None
        require(label is None or label in NOTE_LABELS, "INVALID_LABEL", "Unsupported network label.")
        bookmarked = bool(data.get("bookmarked", False))
        self.db.execute(
            "INSERT INTO network_notes(bssid,ssid,bookmarked,note,label,updated_at) VALUES(?,?,?,?,?,?) "
            "ON CONFLICT(bssid) DO UPDATE SET ssid=excluded.ssid,bookmarked=excluded.bookmarked,"
            "note=excluded.note,label=excluded.label,updated_at=excluded.updated_at",
            (bssid, network["ssid"], int(bookmarked), note, label, utcnow()),
        )
        return self.network_note(bssid)

    def delete_network_note(self, bssid: str) -> dict:
        bssid = self._validate_bssid(bssid)
        self.db.execute("DELETE FROM network_notes WHERE bssid=?", (bssid,))
        return {"bssid": bssid, "bookmarked": 0, "note": "", "label": None}

    def observed_clients(self, bssid: str) -> list[dict]:
        bssid = self._validate_bssid(bssid)
        _aps, clients, _session = self._recon_snapshot()
        matches = [item for item in clients if item.get("bssid") == bssid]
        if not matches:
            matches = self.db.fetchall(
                "SELECT * FROM recon_clients WHERE bssid=? ORDER BY last_seen DESC", (bssid,)
            )
        unique = {}
        for item in matches:
            unique.setdefault(item["mac"], item)
        return [
            {
                **item,
                "relationship": "Observed client/station",
                "association": "observed, not independently confirmed",
                "vendor": None,
            }
            for item in unique.values()
        ]

    def passive_audit(self, bssid: str) -> dict:
        bssid = self._validate_bssid(bssid)
        network = self._latest_network(bssid)
        if not network:
            raise PinePiError("TARGET_NOT_OBSERVED", "Network is not available in Recon history.", 404)
        aps, _clients, _session = self._recon_snapshot()
        duplicates = [
            item for item in aps
            if item.get("bssid") != bssid and item.get("ssid") == network.get("ssid")
            and network.get("ssid") not in {None, "", "<hidden>"}
        ]
        same_channel = sum(
            1 for item in aps
            if item.get("bssid") != bssid and item.get("channel") == network.get("channel")
        )
        security = str(network.get("security") or "Unknown").upper()
        rating = "Good"
        reasons: list[str] = []
        if security in {"OPEN", "OPN"}:
            rating = "Risk"
            reasons.append("Open network traffic is not protected by link-layer encryption.")
        elif "WEP" in security or security == "WPA":
            rating = "Risk"
            reasons.append("Legacy wireless security was observed.")
        elif "WPA3" in security and "WPA2" in security:
            rating = "Warning"
            reasons.append("Mixed WPA2/WPA3 transition security was observed.")
        elif "WPA3" in security:
            reasons.append("WPA3 was observed; configuration and client behavior still require verification.")
        elif "WPA2" in security:
            rating = "Warning"
            reasons.append("WPA2-only security was observed.")
        else:
            rating = "Warning"
            reasons.append("Security capabilities could not be classified confidently.")
        if same_channel >= 3:
            rating = "Warning" if rating == "Good" else rating
            reasons.append(f"High same-channel occupancy: {same_channel} other access points observed.")
        elif same_channel:
            reasons.append(f"{same_channel} other access point(s) observed on this channel.")
        if duplicates:
            rating = "Warning" if rating == "Good" else rating
            reasons.append(f"{len(duplicates)} additional BSSID(s) use the same SSID; verify intended deployment.")
        return {
            "assessment": rating,
            "reasons": reasons,
            "network": network,
            "vendor": None,
            "wps": "not available from current passive data",
            "same_channel_access_points": same_channel,
            "duplicate_ssid_count": len(duplicates),
            "observed_client_count": len(self.observed_clients(bssid)),
            "method": "passive Recon observations only; no frames were transmitted",
        }

    def duplicate_check(self, bssid: str) -> dict:
        bssid = self._validate_bssid(bssid)
        selected = self._latest_network(bssid)
        if not selected:
            raise PinePiError("TARGET_NOT_OBSERVED", "Network is not available in Recon history.", 404)
        aps, _clients, _session = self._recon_snapshot()
        matches = []
        for item in aps:
            if item.get("bssid") == bssid or item.get("ssid") != selected.get("ssid"):
                continue
            candidate = self._network_payload(item)
            differences = []
            for field_name in ("security", "channel", "band"):
                if candidate.get(field_name) != selected.get(field_name):
                    differences.append({
                        "field": field_name,
                        "selected": selected.get(field_name),
                        "candidate": candidate.get(field_name),
                    })
            signal_difference = None
            if selected.get("signal") is not None and candidate.get("signal") is not None:
                signal_difference = candidate["signal"] - selected["signal"]
            inconsistent = any(item["field"] == "security" for item in differences)
            matches.append({
                "network": candidate,
                "differences": differences,
                "signal_difference_db": signal_difference,
                "assessment": "Potentially inconsistent AP" if inconsistent else "Additional AP using same SSID",
                "guidance": "Requires verification; passive observations do not prove a rogue access point.",
            })
        return {
            "selected": selected,
            "matches": matches,
            "conclusion": "Requires verification" if matches else "No duplicate SSID observed in this Recon snapshot.",
            "confirmed_rogue": False,
        }

    @staticmethod
    def _monitor_snapshot(network: dict | None, clients: list[dict], aps: list[dict] | None = None) -> dict:
        if not network:
            return {"present": False}
        age = OperationService._age_seconds(network.get("last_seen"))
        return {
            "present": age is None or age <= 90,
            "signal": network.get("signal"),
            "channel": network.get("channel"),
            "security": network.get("security"),
            "client_count": sum(1 for item in clients if item.get("bssid") == network.get("bssid")),
            "duplicate_ssid_count": sum(
                1 for item in (aps or [])
                if item.get("bssid") != network.get("bssid")
                and item.get("ssid") == network.get("ssid")
                and network.get("ssid") not in {None, "", "<hidden>"}
            ),
            "first_seen": network.get("first_seen"),
            "last_seen": network.get("last_seen"),
        }

    def start_network_monitor(self, data: dict) -> dict:
        if not self._recon:
            raise PinePiError(
                "MONITOR_RECON_REQUIRED",
                "Start Recon before monitoring a network so PinePi has a live passive observation source.",
                409,
            )
        bssid = self._validate_bssid(data.get("bssid") or self.current_target().get("bssid") or "")
        aps, clients = self._parse_airodump(self._recon.prefix)
        network = next((item for item in aps if item.get("bssid") == bssid), None)
        if not network:
            raise PinePiError("TARGET_NOT_OBSERVED", "The target is not currently visible to Recon.", 409)
        snapshot = self._monitor_snapshot(network, clients, aps)
        self.db.execute(
            "INSERT INTO network_monitor(id,bssid,ssid,started_at,status,snapshot_json,changes_json,observation_count,last_observed_at) "
            "VALUES(1,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET bssid=excluded.bssid,"
            "ssid=excluded.ssid,started_at=excluded.started_at,status=excluded.status,"
            "snapshot_json=excluded.snapshot_json,changes_json=excluded.changes_json,"
            "observation_count=excluded.observation_count,last_observed_at=excluded.last_observed_at",
            (bssid, network.get("ssid"), utcnow(), "RUNNING", json.dumps(snapshot), "[]", 1, utcnow()),
        )
        self.events.write("INFO", "monitor", "started", "Passive network monitor started.", bssid=bssid)
        return self.network_monitor_status()

    def _refresh_network_monitor(self, aps: list[dict], clients: list[dict]) -> None:
        row = self.db.fetchone("SELECT * FROM network_monitor WHERE id=1 AND status='RUNNING'")
        if not row:
            return
        network = next((item for item in aps if item.get("bssid") == row["bssid"]), None)
        current = self._monitor_snapshot(network, clients, aps)
        try:
            previous = json.loads(row.get("snapshot_json") or "{}")
            changes = json.loads(row.get("changes_json") or "[]")
        except (TypeError, json.JSONDecodeError):
            previous, changes = {}, []
        labels = {
            "present": "presence", "signal": "signal", "channel": "channel",
            "security": "security", "client_count": "observed client count",
            "duplicate_ssid_count": "duplicate SSID count",
        }
        timestamp = utcnow()
        for field_name, label in labels.items():
            if field_name in previous and previous.get(field_name) != current.get(field_name):
                changes.append({
                    "timestamp": timestamp, "field": field_name, "label": label,
                    "before": previous.get(field_name), "after": current.get(field_name),
                })
        changes = changes[-100:]
        self.db.execute(
            "UPDATE network_monitor SET snapshot_json=?,changes_json=?,observation_count=observation_count+1,"
            "last_observed_at=? WHERE id=1",
            (json.dumps(current), json.dumps(changes), timestamp),
        )

    def network_monitor_status(self) -> dict:
        row = self.db.fetchone("SELECT * FROM network_monitor WHERE id=1")
        if not row:
            return {"active": False, "state": "IDLE"}
        try:
            snapshot = json.loads(row.pop("snapshot_json") or "{}")
            changes = json.loads(row.pop("changes_json") or "[]")
        except (TypeError, json.JSONDecodeError):
            snapshot, changes = {}, []
        return {"active": row["status"] == "RUNNING", "state": row["status"], **row, "snapshot": snapshot, "changes": changes}

    def stop_network_monitor(self) -> dict:
        row = self.db.fetchone("SELECT bssid FROM network_monitor WHERE id=1")
        self.db.execute("DELETE FROM network_monitor")
        if row:
            self.events.write("INFO", "monitor", "stopped", "Passive network monitor stopped.", **row)
        return {"active": False, "state": "IDLE"}

    def _recent_recon_networks(self) -> list[dict]:
        aps, _clients, session = self._recon_snapshot()
        if not session:
            return []
        session_age = self._age_seconds(session.get("ended_at") or session.get("started_at"))
        if not self._recon and (session_age is None or session_age > RECON_RECOMMENDATION_MAX_AGE):
            return []
        recent = []
        for network in aps:
            age = self._age_seconds(network.get("last_seen"))
            if age is None or age <= RECON_RECOMMENDATION_MAX_AGE:
                recent.append(network)
        return recent

    @staticmethod
    def _channel_congestion_score(channel: int, band: str, networks: list[dict]) -> float:
        score = 0.0
        for network in networks:
            observed_channel = network.get("channel")
            if not isinstance(observed_channel, int):
                continue
            signal = network.get("signal")
            strength = max(1.0, min(100.0, 100.0 + float(signal))) if isinstance(signal, (int, float)) else 10.0
            if band == "2.4":
                distance = abs(channel - observed_channel)
                overlap = max(0.0, 1.0 - distance / 5.0)
                score += strength * overlap
            elif observed_channel == channel:
                score += strength
        return round(score, 2)

    def ap_recommendation(self, interface: str, requested_band: str = "auto") -> dict:
        band = str(requested_band or "auto").lower()
        require(band in {"auto", "2.4", "5"}, "INVALID_BAND", "Band must be auto, 2.4, or 5.")
        adapter = self.adapters.require_wireless(interface, "ap")
        capabilities = adapter.get("capabilities", {})
        channels = sorted({int(value) for value in capabilities.get("ap_channels", [])})
        if not channels:
            raise PinePiError("AP_CHANNELS_UNKNOWN", "Unable to determine supported AP channels.", 409)
        reported_by_band = capabilities.get("ap_channels_by_band") or {}
        manual_by_band = {
            "2.4": sorted({int(value) for value in reported_by_band.get("2.4", [])})
            if "2.4" in reported_by_band else [channel for channel in channels if channel_band(channel) == "2.4"],
            "5": sorted({int(value) for value in reported_by_band.get("5", [])})
            if "5" in reported_by_band else [channel for channel in channels if channel_band(channel) == "5"],
        }
        available_bands = [name for name in ("2.4", "5") if manual_by_band[name]]
        if band != "auto" and band not in available_bands:
            raise PinePiError(
                "BAND_UNSUPPORTED", f"{interface} does not support {band} GHz AP channels.", 409,
                {"interface": interface, "requested_band": band, "available_bands": available_bands},
            )
        candidates = {
            "2.4": [channel for channel in AP_AUTO_24_CHANNELS if channel in manual_by_band["2.4"]],
            "5": [channel for channel in AP_AUTO_5_CHANNELS if channel in manual_by_band["5"]],
        }
        resolved_band = "5" if band == "auto" and candidates["5"] else ("2.4" if band == "auto" else band)
        if not candidates.get(resolved_band):
            if band == "auto" and candidates["2.4"]:
                resolved_band = "2.4"
            else:
                raise PinePiError(
                    "NO_SAFE_AUTO_CHANNEL",
                    f"No safe non-DFS automatic channel is available for {resolved_band} GHz.",
                    409,
                    {"interface": interface, "band": resolved_band, "supported_channels": channels},
                )
        recent = self._recent_recon_networks()
        scored = [
            {
                "channel": channel,
                "score": self._channel_congestion_score(channel, resolved_band, recent),
            }
            for channel in candidates[resolved_band]
        ]
        chosen = min(scored, key=lambda item: (item["score"], candidates[resolved_band].index(item["channel"])))
        fallback = not recent
        reason = (
            "Fallback selection used because no recent Recon data was available."
            if fallback else
            "Lowest observed nearby channel occupancy from recent Recon data."
        )
        return {
            "interface": interface,
            "requested_band": band,
            "resolved_band": resolved_band,
            "resolved_channel": chosen["channel"],
            "channel_score": chosen["score"],
            "recommendation_reason": reason,
            "fallback_used": fallback,
            "recent_network_count": len(recent),
            "available_bands": available_bands,
            "manual_channels": manual_by_band,
            "candidate_scores": scored,
        }

    def resolve_ap_configuration(self, interface: str, requested_band: str, requested_channel) -> dict:
        band = str(requested_band or "auto").lower()
        require(band in {"auto", "2.4", "5"}, "INVALID_BAND", "Band must be auto, 2.4, or 5.")
        if isinstance(requested_channel, str) and requested_channel.lower() == "auto":
            return {"requested_channel": "auto", **self.ap_recommendation(interface, band)}
        try:
            channel = int(requested_channel)
        except (TypeError, ValueError) as exc:
            raise PinePiError("INVALID_CHANNEL", "Channel must be auto or a number.") from exc
        require(1 <= channel <= 196, "INVALID_CHANNEL", "Channel is out of range.")
        resolved_band = channel_band(channel)
        require(resolved_band is not None, "UNSUPPORTED_BAND", "6 GHz channels are not supported by this workflow.")
        if band != "auto" and band != resolved_band:
            raise PinePiError(
                "CHANNEL_BAND_MISMATCH",
                f"Channel {channel} does not belong to the requested {band} GHz band.",
                409,
                {"requested_band": band, "channel": channel, "resolved_band": resolved_band},
            )
        adapter = self.adapters.require_wireless(interface, "ap")
        by_band = adapter.get("capabilities", {}).get("ap_channels_by_band") or {}
        if resolved_band in by_band and channel not in by_band[resolved_band]:
            raise PinePiError(
                "CHANNEL_BAND_MISMATCH",
                f"Channel {channel} is not advertised in the requested {resolved_band} GHz band.",
                409,
                {"channel": channel, "resolved_band": resolved_band},
            )
        self.adapters.require_ap_channel(interface, channel)
        return {
            "interface": interface,
            "requested_band": band,
            "resolved_band": resolved_band,
            "requested_channel": str(channel),
            "resolved_channel": channel,
            "channel_score": None,
            "recommendation_reason": "Manual regulatory-valid channel selected.",
            "fallback_used": False,
        }

    # Recon
    def start_recon(self, interface: str, mode: str = "normal") -> dict:
        mode = str(mode).lower()
        require(mode in {"normal", "passive"}, "INVALID_SCAN_MODE", "Scan mode must be normal or passive.")
        self.adapters.require_wireless(interface, "monitor")
        with self._recon_lock:
            if self._recon:
                raise PinePiError("OPERATION_ACTIVE", "A Recon session is already active.", 409)
            operation_id = uuid.uuid4().hex
            started = utcnow()
            reservation = self.registry.reserve(interface, "recon", operation_id)
            session_dir = self.data_dir / "recon" / operation_id
            prefix = session_dir / "recon"
            process: OwnedProcess | None = None
            try:
                session_dir.mkdir(parents=True, exist_ok=False)
                self.db.execute(
                    "INSERT INTO recon_sessions(id,interface,mode,started_at,status,output_path) VALUES(?,?,?,?,?,?)",
                    (operation_id, interface, mode, started, "STARTING", str(prefix)),
                )
                self.privileged.record_restore(interface, operation_id)
                self.privileged.set_monitor(interface)
                process = self.privileged.start_recon(interface, prefix, operation_id)
                time.sleep(0.2)
                if not process.alive():
                    raise PinePiError(
                        "RECON_START_FAILED", "Recon process exited during startup.", 500,
                        {"stage": "recon_process_start", "interface": interface, "process_exit": True},
                    )
                self._recon = ActiveRecon(operation_id, interface, mode, started, prefix, reservation, process)
                self.db.execute("UPDATE recon_sessions SET status='RUNNING' WHERE id=?", (operation_id,))
                self.events.write("INFO", "recon", "started", "Recon started.", interface=interface, session_id=operation_id)
                self._watch("recon", operation_id)
                return self.recon_status()
            except Exception as exc:
                cleanup_ok = self._cleanup_call("recon", operation_id, "stop_process", lambda: self.privileged.stop_process(process))
                cleanup_ok &= self._cleanup_call("recon", operation_id, "restore_interface", lambda: self.privileged.restore_interface(interface))
                cleanup_ok &= self._cleanup_call("recon", operation_id, "forget_restore", lambda: self.privileged.forget_restore(operation_id))
                self.registry.release(reservation)
                self.db.execute(
                    "UPDATE recon_sessions SET status='ERROR',ended_at=?,stop_reason='startup_failed' WHERE id=?",
                    (utcnow(), operation_id),
                )
                context = self._failure_context(exc, "complete" if cleanup_ok else "incomplete")
                context.update({"interface": interface, "session_id": operation_id})
                self.events.write(
                    "ERROR", "recon", "start_failed", f"Recon failed to start: {context['error']}", **context,
                )
                raise

    def stop_recon(self, reason: str = "user") -> dict:
        with self._recon_lock:
            active = self._recon
            if not active:
                return self.recon_status()
            if active.state == "STOPPING":
                return self.recon_status()
            active.state = "STOPPING"
            self.db.execute("UPDATE recon_sessions SET status='STOPPING' WHERE id=?", (active.id,))
            cleanup_ok = True
            try:
                cleanup_ok &= self._cleanup_call("recon", active.id, "stop_process", lambda: self.privileged.stop_process(active.process))
                self._persist_recon(active)
            finally:
                cleanup_ok &= self._cleanup_call("recon", active.id, "restore_interface", lambda: self.privileged.restore_interface(active.interface))
                cleanup_ok &= self._cleanup_call("recon", active.id, "forget_restore", lambda: self.privileged.forget_restore(active.id))
                self.registry.release(active.reservation)
                ended = utcnow()
                final_reason = reason if cleanup_ok else "cleanup_failed"
                self.db.execute(
                    "UPDATE recon_sessions SET status=?,ended_at=?,stop_reason=? WHERE id=?",
                    ("COMPLETED" if final_reason == "user" else "ERROR", ended, final_reason, active.id),
                )
                self.events.write(
                    "INFO" if reason == "user" else "WARNING", "recon", "stopped", "Recon stopped.",
                    interface=active.interface, session_id=active.id, reason=reason,
                )
                self._recon = None
                # The minimal monitor consumes the live Recon observation stream;
                # it cannot remain active once that stream has stopped.
                self.stop_network_monitor()
            if not cleanup_ok:
                raise PinePiError("CLEANUP_FAILED", "Recon stopped locally, but hardware cleanup could not be confirmed.", 500)
            return {"state": "IDLE", "active": False, "reason": reason}

    def recon_status(self) -> dict:
        active = self._recon
        if not active:
            return {"state": "IDLE", "active": False, "elapsed_seconds": 0}
        # This endpoint observes process state only; cleanup belongs to the watcher.
        return {
            "state": active.state,
            "active": True,
            "session_id": active.id,
            "interface": active.interface,
            "mode": active.mode,
            "started_at": active.started_at,
            "elapsed_seconds": elapsed_seconds(active.started_at),
            "process_alive": active.process.alive(),
        }

    def recon_results(self, session_id: str | None = None) -> dict:
        if session_id and self._recon and session_id == self._recon.id:
            session = self.db.fetchone("SELECT * FROM recon_sessions WHERE id=?", (session_id,))
            aps, clients = self._parse_airodump(self._recon.prefix)
        elif session_id:
            session = self.db.fetchone("SELECT * FROM recon_sessions WHERE id=?", (session_id,))
            if not session:
                raise PinePiError("SESSION_NOT_FOUND", "Recon session not found.", 404)
            aps = self.db.fetchall("SELECT * FROM access_points WHERE session_id=? ORDER BY signal DESC", (session_id,))
            clients = self.db.fetchall("SELECT * FROM recon_clients WHERE session_id=? ORDER BY signal DESC", (session_id,))
        elif self._recon:
            session = self.db.fetchone("SELECT * FROM recon_sessions WHERE id=?", (self._recon.id,))
            aps, clients = self._parse_airodump(self._recon.prefix)
        else:
            session = self.db.fetchone("SELECT * FROM recon_sessions ORDER BY started_at DESC LIMIT 1")
            if session:
                aps = self.db.fetchall("SELECT * FROM access_points WHERE session_id=? ORDER BY signal DESC", (session["id"],))
                clients = self.db.fetchall("SELECT * FROM recon_clients WHERE session_id=? ORDER BY signal DESC", (session["id"],))
            else:
                aps, clients = [], []
        channel_counts = Counter(str(ap["channel"]) for ap in aps if ap.get("channel"))
        security_counts = Counter(ap.get("security") or "Unknown" for ap in aps)
        client_counts = Counter(client.get("bssid") for client in clients if client.get("bssid"))
        notes = {
            item["bssid"]: item
            for item in self.db.fetchall("SELECT bssid,bookmarked,note,label,updated_at FROM network_notes")
        }
        target = self.db.fetchone("SELECT bssid FROM current_target WHERE id=1")
        for ap in aps:
            ap["client_count"] = client_counts.get(ap["bssid"], 0)
            ap["frequency"] = channel_frequency(ap["channel"]) if ap.get("channel") else None
            ap["band"] = channel_band(ap["channel"]) if ap.get("channel") else None
            note = notes.get(ap["bssid"], {})
            ap["bookmarked"] = bool(note.get("bookmarked", False))
            ap["note"] = note.get("note") or ""
            ap["label"] = note.get("label")
            ap["is_current_target"] = bool(target and target["bssid"] == ap["bssid"])
        return {
            "session": session,
            "access_points": aps,
            "clients": clients,
            "channel_usage": dict(sorted(channel_counts.items(), key=lambda item: int(item[0]))),
            "security_distribution": dict(security_counts),
        }

    def recon_history(self) -> list[dict]:
        return self.db.fetchall("SELECT * FROM recon_sessions ORDER BY started_at DESC LIMIT 100")

    def _airodump_path(self, prefix: Path) -> Path | None:
        candidates = sorted(prefix.parent.glob(prefix.name + "-*.csv"))
        return candidates[-1] if candidates else None

    def _parse_airodump(self, prefix: Path) -> tuple[list[dict], list[dict]]:
        path = self._airodump_path(prefix)
        if not path or not path.is_file() or path.stat().st_size > 50 * 1024 * 1024:
            return [], []
        aps: list[dict] = []
        clients: list[dict] = []
        section = "aps"
        try:
            with path.open("r", encoding="utf-8", errors="replace", newline="") as handle:
                for row in csv.reader(handle):
                    if not row:
                        continue
                    first = row[0].strip()
                    if first == "Station MAC":
                        section = "clients"
                        continue
                    if first in {"BSSID", "Station MAC"} or not re.fullmatch(r"[0-9A-Fa-f:]{17}", first):
                        continue
                    values = [value.strip() for value in row]
                    if section == "aps" and len(values) >= 14:
                        privacy = values[5] or "Open"
                        aps.append({
                            "bssid": first.upper(), "first_seen": values[1], "last_seen": values[2],
                            "channel": self._int(values[3]), "signal": self._int(values[8]),
                            "security": "Open" if privacy in {"", "OPN"} else privacy,
                            "ssid": values[13] or "<hidden>",
                        })
                    elif section == "clients" and len(values) >= 6:
                        bssid = values[5].upper() if re.fullmatch(r"[0-9A-Fa-f:]{17}", values[5]) else None
                        clients.append({
                            "mac": first.upper(), "first_seen": values[1], "last_seen": values[2],
                            "signal": self._int(values[3]), "bssid": bssid,
                        })
        except (OSError, csv.Error):
            return [], []
        return aps, clients

    @staticmethod
    def _int(value: str) -> int | None:
        try:
            return int(value)
        except (TypeError, ValueError):
            return None

    def _persist_recon(self, active: ActiveRecon) -> None:
        aps, clients = self._parse_airodump(active.prefix)
        for ap in aps:
            self.db.execute(
                "INSERT OR REPLACE INTO access_points(session_id,bssid,ssid,channel,signal,security,first_seen,last_seen) VALUES(?,?,?,?,?,?,?,?)",
                (active.id, ap["bssid"], ap["ssid"], ap["channel"], ap["signal"], ap["security"], ap["first_seen"], ap["last_seen"]),
            )
        for client in clients:
            self.db.execute(
                "INSERT OR REPLACE INTO recon_clients(session_id,mac,bssid,signal,first_seen,last_seen) VALUES(?,?,?,?,?,?)",
                (active.id, client["mac"], client["bssid"], client["signal"], client["first_seen"], client["last_seen"]),
            )

    # Standalone Capture. Targeted mode still receives every frame visible to
    # the monitor adapter on the selected channel; target metadata provides
    # association and filtering context rather than a hardware BSSID filter.
    def start_capture(
        self,
        interface: str,
        channel: int,
        name: str,
        capture_mode: str = "raw",
        target: dict | None = None,
    ) -> dict:
        capture_mode = str(capture_mode or "raw").lower()
        require(capture_mode in {"raw", "targeted"}, "INVALID_CAPTURE_MODE", "Capture mode must be raw or targeted.")
        target_data = None
        if capture_mode == "targeted":
            supplied_bssid = target.get("bssid") if isinstance(target, dict) else None
            target_data = self._target_for_capture(supplied_bssid)
            channel = int(target_data["channel"])
        else:
            try:
                channel = int(channel)
            except (TypeError, ValueError) as exc:
                raise PinePiError("INVALID_CHANNEL", "Channel must be a number.") from exc
        require(1 <= channel <= 196, "INVALID_CHANNEL", "Channel is out of range.")
        adapter = self.adapters.require_wireless(interface, "monitor")
        supported = adapter.get("capabilities", {}).get("ap_channels") or []
        if capture_mode == "targeted" and supported and channel not in supported:
            raise PinePiError(
                "ADAPTER_CHANNEL_UNSUPPORTED",
                f"{interface} does not advertise channel {channel} for the selected target.",
                409,
                {"interface": interface, "channel": channel, "supported_channels": supported},
            )
        self.check_storage(self.max_capture_bytes)
        with self._capture_lock:
            if self._capture:
                raise PinePiError("OPERATION_ACTIVE", "A standalone capture is already active.", 409)
            operation_id = uuid.uuid4().hex
            capture_name = safe_name(name)
            started = utcnow()
            reservation = self.registry.reserve(interface, "capture", operation_id)
            path = self.data_dir / "captures" / f"{operation_id}_{capture_name}.pcapng"
            process: OwnedProcess | None = None
            try:
                self.db.execute(
                    "INSERT INTO captures(id,name,interface,channel,started_at,status,path,capture_mode,"
                    "target_bssid,target_ssid,target_frequency,target_band,target_security,target_last_seen) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        operation_id, capture_name, interface, channel, started, "STARTING", str(path),
                        capture_mode, target_data.get("bssid") if target_data else None,
                        target_data.get("ssid") if target_data else None,
                        target_data.get("frequency") if target_data else None,
                        target_data.get("band") if target_data else None,
                        target_data.get("security") if target_data else None,
                        target_data.get("last_seen") if target_data else None,
                    ),
                )
                self.privileged.record_restore(interface, operation_id)
                self.privileged.set_monitor(interface, channel)
                process = self.privileged.start_capture(interface, path, self.max_capture_bytes, operation_id)
                time.sleep(0.2)
                if not process.alive():
                    raise PinePiError(
                        "CAPTURE_START_FAILED", "Capture process exited during startup.", 500,
                        {"stage": "capture_process_start", "interface": interface, "process_exit": True},
                    )
                self._capture = ActiveCapture(
                    operation_id, capture_name, interface, channel, started, path, reservation, process,
                    capture_mode=capture_mode, target=target_data,
                )
                self.db.execute("UPDATE captures SET status='RUNNING' WHERE id=?", (operation_id,))
                self.events.write(
                    "INFO", "capture", "started", "Standalone capture started.",
                    interface=interface, capture_id=operation_id, capture_mode=capture_mode,
                    target_bssid=target_data.get("bssid") if target_data else None,
                    channel=channel,
                )
                self._watch("capture", operation_id)
                return self.capture_status()
            except Exception as exc:
                cleanup_ok = self._cleanup_call("capture", operation_id, "stop_process", lambda: self.privileged.stop_process(process))
                cleanup_ok &= self._cleanup_call("capture", operation_id, "restore_interface", lambda: self.privileged.restore_interface(interface))
                cleanup_ok &= self._cleanup_call("capture", operation_id, "forget_restore", lambda: self.privileged.forget_restore(operation_id))
                self.registry.release(reservation)
                self.db.execute("UPDATE captures SET status='ERROR',ended_at=?,stop_reason='startup_failed' WHERE id=?", (utcnow(), operation_id))
                context = self._failure_context(exc, "complete" if cleanup_ok else "incomplete")
                context.update({"interface": interface, "capture_id": operation_id})
                self.events.write(
                    "ERROR", "capture", "start_failed", f"Capture failed to start: {context['error']}", **context,
                )
                raise

    def stop_capture(self, reason: str = "user") -> dict:
        with self._capture_lock:
            active = self._capture
            if not active:
                return self.capture_status()
            if active.state == "STOPPING":
                return self.capture_status()
            active.state = "STOPPING"
            self.db.execute("UPDATE captures SET status='STOPPING' WHERE id=?", (active.id,))
            cleanup_ok = True
            try:
                cleanup_ok &= self._cleanup_call("capture", active.id, "stop_process", lambda: self.privileged.stop_process(active.process))
            finally:
                cleanup_ok &= self._cleanup_call("capture", active.id, "restore_interface", lambda: self.privileged.restore_interface(active.interface))
                cleanup_ok &= self._cleanup_call("capture", active.id, "forget_restore", lambda: self.privileged.forget_restore(active.id))
                self.registry.release(active.reservation)
                size = active.path.stat().st_size if active.path.exists() else 0
                summary = self.analyze_pcap(active.path)
                final_reason = reason if cleanup_ok else "cleanup_failed"
                status = "COMPLETED" if final_reason == "user" else ("LIMIT_REACHED" if final_reason in {"size_limit", "low_space"} else "ERROR")
                self.db.execute(
                    "UPDATE captures SET status=?,ended_at=?,size_bytes=?,packet_count=?,stop_reason=? WHERE id=?",
                    (status, utcnow(), size, summary.get("packet_count"), final_reason, active.id),
                )
                self.events.write(
                    "WARNING" if reason != "user" else "INFO", "capture", "stopped", "Standalone capture stopped.",
                    interface=active.interface, capture_id=active.id, reason=reason, size_bytes=size,
                )
                if reason in {"size_limit", "low_space"}:
                    self.events.write(
                        "WARNING", "storage", "capture_limit", "Capture stopped by a storage protection limit.",
                        capture_id=active.id, reason=reason, size_bytes=size,
                    )
                self._capture = None
            if not cleanup_ok:
                raise PinePiError("CLEANUP_FAILED", "Capture stopped locally, but hardware cleanup could not be confirmed.", 500)
            return {"state": "IDLE", "active": False, "reason": reason}

    def capture_status(self) -> dict:
        active = self._capture
        if not active:
            return {"state": "IDLE", "active": False, "elapsed_seconds": 0}
        size = active.path.stat().st_size if active.path.exists() else 0
        return {
            "state": active.state, "active": True, "capture_id": active.id, "name": active.name,
            "interface": active.interface, "channel": active.channel, "started_at": active.started_at,
            "elapsed_seconds": elapsed_seconds(active.started_at), "size_bytes": size,
            "packet_count": None, "process_alive": active.process.alive(),
            "capture_mode": active.capture_mode, "target": active.target,
        }

    def capture_history(self) -> list[dict]:
        return self.db.fetchall("SELECT * FROM captures ORDER BY started_at DESC LIMIT 100")

    def delete_capture(self, capture_id: str) -> None:
        row = self.db.fetchone("SELECT * FROM captures WHERE id=?", (capture_id,))
        if not row:
            raise PinePiError("CAPTURE_NOT_FOUND", "Capture not found.", 404)
        if self._capture and self._capture.id == capture_id:
            raise PinePiError("CAPTURE_ACTIVE", "Stop the capture before deleting it.", 409)
        path = self.authorized_path(row["path"], self.data_dir / "captures")
        path.unlink(missing_ok=True)
        path.with_suffix(".log").unlink(missing_ok=True)
        self.db.execute("DELETE FROM captures WHERE id=?", (capture_id,))
        self.events.write("INFO", "capture", "deleted", "Capture deleted.", capture_id=capture_id)

    def analyze_pcap(self, path: Path) -> dict:
        result = {"valid": False, "packet_count": None, "size_bytes": 0, "format": None}
        try:
            path = path.resolve(strict=True)
            size = path.stat().st_size
            result["size_bytes"] = size
            if size < 4 or size > self.max_capture_bytes + 1024 * 1024:
                return result
            with path.open("rb") as handle:
                magic = handle.read(4)
            formats = {
                b"\x0a\x0d\x0d\x0a": "pcapng", b"\xd4\xc3\xb2\xa1": "pcap",
                b"\xa1\xb2\xc3\xd4": "pcap", b"\x4d\x3c\xb2\xa1": "pcap-ns", b"\xa1\xb2\x3c\x4d": "pcap-ns",
            }
            result["format"] = formats.get(magic)
            if not result["format"]:
                return result
            command = self.privileged.inspect_capture(path)
            match = re.search(r"Number of packets:\s*([0-9,]+)", command.stdout)
            result["packet_count"] = int(match.group(1).replace(",", "")) if match else None
            result["valid"] = command.returncode == 0
            return result
        except (OSError, ValueError, PinePiError):
            return result

    # Test Access Point
    def start_ap(self, data: dict) -> dict:
        interface = str(data.get("interface", ""))
        ssid = str(data.get("ssid", "")).strip()
        requested_band = str(data.get("band", "auto")).lower()
        requested_channel = data.get("channel", "auto")
        security = str(data.get("security", "open")).lower()
        password = str(data.get("password", "")) if security == "wpa2" else None
        requested_value = str(data.get("uplink", "auto"))
        requested_uplink = requested_value.lower() if requested_value.lower() in {"auto", "none"} else requested_value
        forwarding = bool(data.get("forwarding", True))
        log_clients = bool(data.get("log_clients", True))
        capture_traffic = bool(data.get("capture_traffic", False))
        require(1 <= len(ssid.encode("utf-8")) <= 32 and not {"\n", "\r"} & set(ssid), "INVALID_SSID", "SSID must be 1–32 bytes.")
        require(security in {"open", "wpa2"}, "INVALID_SECURITY", "Security must be Open or WPA2-PSK.")
        if security == "wpa2":
            require(8 <= len(password.encode("utf-8")) <= 63 and not {"\n", "\r"} & set(password), "INVALID_PASSPHRASE", "WPA2 passphrase must be 8–63 bytes.")
        try:
            resolution = self.resolve_ap_configuration(interface, requested_band, requested_channel)
            channel = resolution["resolved_channel"]
        except PinePiError as exc:
            context = self._failure_context(exc, "not_started")
            context.update({
                "interface": interface,
                "requested_band": requested_band,
                "requested_channel": str(requested_channel),
            })
            self.events.write(
                "WARNING", "access_point", "start_rejected", "Access Point start was rejected during preflight.",
                **context,
            )
            raise
        if capture_traffic:
            self.check_storage(self.max_capture_bytes)
        effective_uplink = self.adapters.choose_uplink(requested_uplink, interface) if forwarding else None
        if forwarding and not effective_uplink:
            raise PinePiError("NO_UPLINK", "No connected uplink is available; disable forwarding or select No uplink.", 409)
        with self._ap_lock:
            if self._ap:
                raise PinePiError("OPERATION_ACTIVE", "A test access point is already active.", 409)
            operation_id = uuid.uuid4().hex
            started = utcnow()
            reservation = self.registry.reserve(interface, "ap", operation_id)
            uplink_reservation: Reservation | None = None
            session_dir = self.data_dir / "ap_sessions" / operation_id
            capture_path = session_dir / "traffic.pcapng" if capture_traffic else None
            hostapd = dnsmasq = capture = None
            routing = None
            try:
                if effective_uplink:
                    uplink_reservation = self.registry.reserve(effective_uplink, "ap_uplink", operation_id)
                session_dir.mkdir(parents=True, exist_ok=False)
                self.db.execute(
                    "INSERT INTO ap_sessions(id,ssid,interface,requested_uplink,effective_uplink,security,channel,"
                    "started_at,status,log_clients,capture_traffic,capture_path,requested_band,resolved_band,"
                    "requested_channel,resolved_channel,channel_score,recommendation_reason) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        operation_id, ssid, interface, requested_uplink, effective_uplink, security, channel,
                        started, "STARTING", int(log_clients), int(capture_traffic),
                        str(capture_path) if capture_path else None,
                        resolution["requested_band"], resolution["resolved_band"],
                        resolution["requested_channel"], resolution["resolved_channel"],
                        resolution["channel_score"], resolution["recommendation_reason"],
                    ),
                )
                self.privileged.record_restore(interface, operation_id)
                hostapd, dnsmasq = self.privileged.start_ap(interface, ssid, channel, security, password, session_dir, operation_id)
                if effective_uplink:
                    routing = self.privileged.setup_routing(interface, effective_uplink, operation_id)
                    self.events.write(
                        "INFO", "networking", "routing_enabled", "AP forwarding route enabled.",
                        session_id=operation_id, ap_interface=interface, uplink=effective_uplink,
                    )
                if capture_traffic and capture_path:
                    capture = self.privileged.start_capture(interface, capture_path, self.max_capture_bytes, operation_id + "-traffic")
                    time.sleep(0.2)
                    if not capture.alive():
                        raise PinePiError(
                            "CAPTURE_START_FAILED", "AP traffic capture did not start.", 500,
                            {"stage": "ap_capture_start", "interface": interface, "process_exit": True},
                        )
                self._ap = ActiveAP(
                    operation_id, interface, ssid, channel, security, requested_uplink, effective_uplink,
                    started, session_dir, reservation, uplink_reservation, hostapd, dnsmasq, routing, capture, capture_path,
                    log_clients, capture_traffic,
                    requested_band=resolution["requested_band"], resolved_band=resolution["resolved_band"],
                    requested_channel=resolution["requested_channel"],
                    channel_score=resolution["channel_score"],
                    recommendation_reason=resolution["recommendation_reason"],
                )
                self.db.execute("UPDATE ap_sessions SET status='RUNNING' WHERE id=?", (operation_id,))
                self.events.write(
                    "INFO", "access_point", "started", "Test access point started.", interface=interface,
                    session_id=operation_id, ssid=ssid, effective_uplink=effective_uplink,
                    requested_band=resolution["requested_band"], resolved_band=resolution["resolved_band"],
                    requested_channel=resolution["requested_channel"], resolved_channel=channel,
                    channel_score=resolution["channel_score"],
                    recommendation_reason=resolution["recommendation_reason"],
                )
                self._watch("ap", operation_id)
                return self.ap_status()
            except Exception as exc:
                cleanup_ok = self._cleanup_call("access_point", operation_id, "stop_capture", lambda: self.privileged.stop_process(capture))
                cleanup_ok &= self._cleanup_call("access_point", operation_id, "teardown_routing", lambda: self.privileged.teardown_routing(routing))
                cleanup_ok &= self._cleanup_call("access_point", operation_id, "stop_dnsmasq", lambda: self.privileged.stop_process(dnsmasq))
                cleanup_ok &= self._cleanup_call("access_point", operation_id, "stop_hostapd", lambda: self.privileged.stop_process(hostapd))
                cleanup_ok &= self._cleanup_call("access_point", operation_id, "restore_interface", lambda: self.privileged.restore_interface(interface))
                cleanup_ok &= self._cleanup_call("access_point", operation_id, "forget_restore", lambda: self.privileged.forget_restore(operation_id))
                self.registry.release(uplink_reservation)
                self.registry.release(reservation)
                (session_dir / "hostapd.conf").unlink(missing_ok=True)
                self.db.execute("UPDATE ap_sessions SET status='ERROR',ended_at=?,stop_reason='startup_failed' WHERE id=?", (utcnow(), operation_id))
                context = self._failure_context(exc, "complete" if cleanup_ok else "incomplete")
                context.update({"interface": interface, "session_id": operation_id})
                self.events.write(
                    "ERROR", "access_point", "start_failed", f"Test access point failed to start: {context['error']}", **context,
                )
                raise

    def stop_ap(self, reason: str = "user") -> dict:
        with self._ap_lock:
            active = self._ap
            if not active:
                return self.ap_status()
            if active.state == "STOPPING":
                return self.ap_status()
            active.state = "STOPPING"
            self.db.execute("UPDATE ap_sessions SET status='STOPPING' WHERE id=?", (active.id,))
            cleanup_ok = True
            try:
                cleanup_ok &= self._cleanup_call("access_point", active.id, "save_clients", lambda: self._save_ap_clients(active))
                cleanup_ok &= self._cleanup_call("access_point", active.id, "stop_capture", lambda: self.privileged.stop_process(active.capture))
                routing_removed = self._cleanup_call("access_point", active.id, "teardown_routing", lambda: self.privileged.teardown_routing(active.routing))
                cleanup_ok &= routing_removed
                if active.routing and routing_removed:
                    self.events.write(
                        "INFO", "networking", "routing_removed", "AP forwarding route removed.",
                        session_id=active.id, ap_interface=active.interface, uplink=active.effective_uplink,
                    )
                cleanup_ok &= self._cleanup_call("access_point", active.id, "stop_dnsmasq", lambda: self.privileged.stop_process(active.dnsmasq))
                cleanup_ok &= self._cleanup_call("access_point", active.id, "stop_hostapd", lambda: self.privileged.stop_process(active.hostapd))
            finally:
                cleanup_ok &= self._cleanup_call("access_point", active.id, "restore_interface", lambda: self.privileged.restore_interface(active.interface))
                cleanup_ok &= self._cleanup_call("access_point", active.id, "forget_restore", lambda: self.privileged.forget_restore(active.id))
                self.registry.release(active.uplink_reservation)
                self.registry.release(active.reservation)
                (active.session_dir / "hostapd.conf").unlink(missing_ok=True)
                final_reason = reason if cleanup_ok else "cleanup_failed"
                status = "COMPLETED" if final_reason == "user" else ("LIMIT_REACHED" if final_reason in {"size_limit", "low_space"} else "ERROR")
                self.db.execute("UPDATE ap_sessions SET status=?,ended_at=?,stop_reason=? WHERE id=?", (status, utcnow(), final_reason, active.id))
                self.events.write(
                    "WARNING" if reason != "user" else "INFO", "access_point", "stopped", "Test access point stopped.",
                    interface=active.interface, session_id=active.id, reason=reason,
                )
                if reason in {"size_limit", "low_space"}:
                    self.events.write(
                        "WARNING", "storage", "ap_capture_limit", "AP traffic capture stopped by a storage protection limit.",
                        session_id=active.id, reason=reason,
                    )
                self._ap = None
            if not cleanup_ok:
                raise PinePiError("CLEANUP_FAILED", "Access Point stopped locally, but hardware cleanup could not be confirmed.", 500)
            return {"state": "IDLE", "active": False, "reason": reason}

    def ap_status(self) -> dict:
        active = self._ap
        if not active:
            return {"state": "IDLE", "active": False, "elapsed_seconds": 0, "clients": []}
        clients = self._read_ap_clients(active)
        capture_size = active.capture_path.stat().st_size if active.capture_path and active.capture_path.exists() else 0
        return {
            "state": active.state, "active": True, "session_id": active.id, "interface": active.interface,
            "ssid": active.ssid, "channel": active.channel, "security": active.security,
            "requested_band": active.requested_band, "resolved_band": active.resolved_band,
            "requested_channel": active.requested_channel, "resolved_channel": active.channel,
            "channel_score": active.channel_score,
            "recommendation_reason": active.recommendation_reason,
            "requested_uplink": active.requested_uplink, "effective_uplink": active.effective_uplink,
            "started_at": active.started_at, "elapsed_seconds": elapsed_seconds(active.started_at),
            "clients": clients, "capture_traffic": active.capture_traffic, "capture_size_bytes": capture_size,
            "hostapd_alive": active.hostapd.alive(), "dnsmasq_alive": active.dnsmasq.alive(),
        }

    def ap_history(self) -> list[dict]:
        return self.db.fetchall("SELECT * FROM ap_sessions ORDER BY started_at DESC LIMIT 100")

    def _read_ap_clients(self, active: ActiveAP) -> list[dict]:
        stations = {item["mac"]: item for item in self.privileged.station_dump(active.interface)}
        leases: dict[str, str] = {}
        path = active.session_dir / "dnsmasq-state" / "dnsmasq.leases"
        try:
            if path.stat().st_size <= 2 * 1024 * 1024:
                for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
                    parts = line.split()
                    if len(parts) >= 3 and re.fullmatch(r"[0-9A-Fa-f:]{17}", parts[1]):
                        leases[parts[1].upper()] = parts[2]
        except OSError:
            pass
        now = utcnow()
        known = {row["mac"]: row for row in self.db.fetchall("SELECT * FROM ap_clients WHERE session_id=?", (active.id,))}
        clients: list[dict] = []
        for mac, station in stations.items():
            previous = known.get(mac)
            first_seen = previous["first_seen"] if previous else now
            clients.append({
                "mac": mac, "ip": leases.get(mac), "first_seen": first_seen, "last_seen": now,
                "duration_seconds": elapsed_seconds(first_seen), "rx_bytes": station.get("rx_bytes"),
                "tx_bytes": station.get("tx_bytes"),
            })
        return clients

    def _save_ap_clients(self, active: ActiveAP) -> None:
        if not active.log_clients:
            return
        clients = self._read_ap_clients(active)
        current_macs = {client["mac"] for client in clients}
        for mac in sorted(current_macs - active.connected_macs):
            self.events.write(
                "INFO", "access_point", "client_connected", "Client connected to the test access point.",
                session_id=active.id, interface=active.interface, mac=mac,
            )
        for mac in sorted(active.connected_macs - current_macs):
            self.events.write(
                "INFO", "access_point", "client_disconnected", "Client disconnected from the test access point.",
                session_id=active.id, interface=active.interface, mac=mac,
            )
        active.connected_macs = current_macs
        for client in clients:
            self.db.execute(
                "INSERT INTO ap_clients(session_id,mac,ip,first_seen,last_seen,rx_bytes,tx_bytes) VALUES(?,?,?,?,?,?,?) "
                "ON CONFLICT(session_id,mac) DO UPDATE SET ip=excluded.ip,last_seen=excluded.last_seen,rx_bytes=excluded.rx_bytes,tx_bytes=excluded.tx_bytes",
                (active.id, client["mac"], client["ip"], client["first_seen"], client["last_seen"], client["rx_bytes"], client["tx_bytes"]),
            )

    # Background lifecycle monitoring. GET status calls deliberately never perform cleanup.
    def _watch(self, kind: str, operation_id: str) -> None:
        thread = threading.Thread(target=self._watch_loop, args=(kind, operation_id), daemon=True, name=f"pinepi-{kind}-{operation_id[:8]}")
        thread.start()

    def _watch_loop(self, kind: str, operation_id: str) -> None:
        consecutive_errors = 0
        while True:
            time.sleep(min(10, 1 + consecutive_errors))
            try:
                if kind == "recon":
                    active = self._recon
                    if not active or active.id != operation_id:
                        return
                    if not active.process.alive():
                        self.stop_recon("process_exit")
                        return
                    aps, clients = self._parse_airodump(active.prefix)
                    self._refresh_network_monitor(aps, clients)
                elif kind == "capture":
                    active = self._capture
                    if not active or active.id != operation_id:
                        return
                    reason = self._capture_guard(active.path, active.process)
                    if reason:
                        self.stop_capture(reason)
                        return
                elif kind == "ap":
                    active = self._ap
                    if not active or active.id != operation_id:
                        return
                    if active.log_clients:
                        self._save_ap_clients(active)
                    if not active.hostapd.alive() or not active.dnsmasq.alive():
                        self.stop_ap("process_exit")
                        return
                    if active.capture and active.capture_path:
                        reason = self._capture_guard(active.capture_path, active.capture)
                        if reason:
                            self.stop_ap(reason)
                            return
                consecutive_errors = 0
            # A monitor must survive any OS/parser/database exception long enough to log it.
            except Exception as exc:  # noqa: BLE001
                consecutive_errors += 1
                if consecutive_errors == 1 or consecutive_errors % 30 == 0:
                    self.events.write(
                        "ERROR", kind, "watcher_error", "Lifecycle monitor encountered an error.",
                        operation_id=operation_id, error=type(exc).__name__, consecutive_errors=consecutive_errors,
                    )

    def _capture_guard(self, path: Path, process: OwnedProcess) -> str | None:
        size = path.stat().st_size if path.exists() else 0
        if size >= self.max_capture_bytes:
            return "size_limit"
        if shutil.disk_usage(self.data_dir).free < self.min_free_bytes:
            return "low_space"
        if not process.alive():
            return "size_limit" if size >= self.max_capture_bytes * 0.98 else "process_exit"
        return None

    def landscape(self) -> dict:
        results = self.recon_results()
        aps = results["access_points"]
        return {
            "access_points": len(aps), "clients": len(results["clients"]),
            "open_networks": sum(1 for item in aps if (item.get("security") or "").lower() == "open"),
            "channels_used": len(results["channel_usage"]), "session": results["session"],
        }

    def active_operations(self) -> list[dict]:
        active = []
        for kind, status in (("Recon", self.recon_status()), ("Access Point", self.ap_status()), ("Capture", self.capture_status())):
            if status.get("active"):
                active.append({"type": kind, **status})
        return active

    def authorized_path(self, raw_path: str | Path, root: Path) -> Path:
        root = root.resolve()
        try:
            path = Path(raw_path).resolve(strict=False)
            path.relative_to(root)
        except (OSError, ValueError):
            raise PinePiError("INVALID_EXPORT_PATH", "Requested file is outside PinePi storage.", 403)
        return path

    def shutdown(self) -> None:
        if self._recon:
            self.stop_recon("service_stop")
        if self._capture:
            self.stop_capture("service_stop")
        if self._ap:
            self.stop_ap("service_stop")

    def system_metrics(self) -> dict:
        memory = psutil.virtual_memory()
        disk = shutil.disk_usage(self.data_dir)
        temperature = None
        try:
            temps = psutil.sensors_temperatures()
            values = next((items for key, items in temps.items() if key in {"cpu_thermal", "coretemp"}), [])
            if values:
                temperature = round(values[0].current, 1)
        except (AttributeError, OSError):
            pass
        return {
            "cpu_percent": psutil.cpu_percent(interval=None), "cpu_count": psutil.cpu_count(),
            "memory_percent": memory.percent, "memory_used": memory.used, "memory_total": memory.total,
            "storage_percent": round((disk.used / disk.total) * 100, 1) if disk.total else 0,
            "storage_used": disk.used, "storage_total": disk.total, "storage_free": disk.free,
            "temperature_c": temperature, "uptime_seconds": max(0, int(time.time() - psutil.boot_time())),
        }
