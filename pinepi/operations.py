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
from datetime import UTC, datetime, timedelta
from pathlib import Path

import psutil

from .adapters import AdapterService, Reservation, ReservationRegistry
from .db import Database
from .errors import PinePiError, require
from .events import EventLog
from .privileged import (
    DEAUTH_MAX_COUNT,
    DEAUTH_MAX_DURATION_SECONDS,
    OwnedProcess,
    PrivilegedService,
    normalize_bssid,
    normalize_client_mac,
)

AP_AUTO_24_CHANNELS = (1, 6, 11)
AP_AUTO_5_CHANNELS = (36, 40, 44, 48, 149, 153, 157, 161, 165)
RECON_RECOMMENDATION_MAX_AGE = 15 * 60
TARGET_RECENT_MAX_AGE = 30 * 60
NOTE_LABELS = {"test target", "trusted", "investigate", "lab ap"}
HANDSHAKE_STATES = {"not_captured": 0, "partial": 1, "full": 2}


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


def analyze_eapol_key_frames(frames: list[dict], target_bssid: str) -> dict:
    """Reduce EAPOL-Key observations to a per-client, target-scoped handshake state."""

    target_bssid = normalize_bssid(target_bssid)
    messages_by_client: dict[str, set[tuple[str, int | None]]] = {}
    for frame in frames:
        if not isinstance(frame, dict) or str(frame.get("bssid") or "").upper() != target_bssid:
            continue
        source = str(frame.get("source") or "").upper()
        destination = str(frame.get("destination") or "").upper()
        client_value = destination if source == target_bssid else source if destination == target_bssid else None
        if not client_value:
            continue
        try:
            client = normalize_client_mac(client_value)
        except PinePiError:
            continue
        if client == target_bssid:
            continue
        try:
            message_number = int(str(frame.get("message_number") or "").split(",", 1)[0], 0)
        except (TypeError, ValueError):
            message_number = 0
        if 1 <= message_number <= 4:
            message = f"m{message_number}"
        else:
            try:
                value = str(frame.get("key_info") or "").split(",", 1)[0].strip()
                key_info = int(value, 0)
            except (TypeError, ValueError):
                continue
            if not key_info & 0x0008:
                continue
            acknowledge = bool(key_info & 0x0080)
            mic = bool(key_info & 0x0100)
            secure = bool(key_info & 0x0200)
            if acknowledge and not mic:
                message = "m1"
            elif not acknowledge and mic and not secure:
                message = "m2"
            elif acknowledge and mic:
                message = "m3"
            elif not acknowledge and mic and secure:
                message = "m4"
            else:
                continue
        try:
            replay_counter = int(str(frame.get("replay_counter") or "").split(",", 1)[0], 0)
            if not 0 <= replay_counter < 2**64:
                replay_counter = None
        except (TypeError, ValueError):
            replay_counter = None
        messages_by_client.setdefault(client, set()).add((message, replay_counter))

    client_states = []
    for client, observations in messages_by_client.items():
        replay_by_message = {
            message: {replay for observed, replay in observations if observed == message and replay is not None}
            for message in ("m1", "m2", "m3", "m4")
        }
        m1_m2 = bool(replay_by_message["m1"] & replay_by_message["m2"])
        m2_m3 = any(
            replay in replay_by_message["m3"] or replay + 1 in replay_by_message["m3"]
            for replay in replay_by_message["m2"]
        )
        full = m1_m2 or m2_m3
        client_states.append({"mac": client, "state": "full" if full else "partial"})
    client_states.sort(key=lambda item: (-HANDSHAKE_STATES[item["state"]], item["mac"]))
    state = client_states[0]["state"] if client_states else "not_captured"
    return {
        "state": state,
        "client_mac": client_states[0]["mac"] if client_states else None,
        "clients": client_states,
        "unique_message_count": sum(len(messages) for messages in messages_by_client.values()),
    }


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
    handshake_state: str | None = None
    handshake_client_mac: str | None = None
    handshake_checked_at: float = 0.0
    handshake_client_macs: set[str] = field(default_factory=set)
    known_client_macs: set[str] = field(default_factory=set)
    handshake_error_code: str | None = None


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
    blocked_macs: set[str] = field(default_factory=set)


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
        return normalize_bssid(value)

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

    @staticmethod
    def _handshake_security_supported(value: str | None) -> bool:
        tokens = set(re.split(r"[^A-Z0-9]+", str(value or "").upper()))
        return bool(tokens & {"WPA", "WPA2"})

    def _capture_observed_clients(self, active: ActiveCapture) -> list[dict]:
        if active.capture_mode != "handshake" or not active.target:
            return []
        bssid = active.target["bssid"]
        clients: dict[str, dict] = {}
        for item in self.observed_clients(bssid):
            age = self._age_seconds(item.get("last_seen"))
            if age is None or age > TARGET_RECENT_MAX_AGE:
                continue
            try:
                mac = normalize_client_mac(item.get("mac", ""))
            except PinePiError:
                continue
            clients[mac] = {
                "mac": mac,
                "signal": item.get("signal"),
                "last_seen": item.get("last_seen"),
                "source": "recon",
            }
        for mac in active.handshake_client_macs:
            clients.setdefault(mac, {
                "mac": mac,
                "signal": None,
                "last_seen": None,
                "source": "captured_eapol",
            })
        newly_observed = set(clients) - active.known_client_macs
        for mac in sorted(newly_observed):
            self.events.write(
                "INFO", "capture", "client_detected",
                "Client associated with the handshake target was observed.",
                capture_id=active.id,
                target_bssid=bssid,
                client_mac=mac,
                source=clients[mac]["source"],
            )
        active.known_client_macs.update(clients)
        return sorted(clients.values(), key=lambda item: item["mac"])

    def _refresh_handshake(self, active: ActiveCapture, *, force: bool = False) -> None:
        if active.capture_mode != "handshake" or not active.target:
            return
        checked_at = time.monotonic()
        if not force and checked_at - active.handshake_checked_at < 2:
            return
        active.handshake_checked_at = checked_at
        try:
            frames = self.privileged.capture_handshake_frames(
                active.path,
                active.id,
                active.target["bssid"],
            )
            analysis = analyze_eapol_key_frames(frames, active.target["bssid"])
            active.handshake_error_code = None
        except Exception as exc:  # noqa: BLE001 - analysis failure must never interrupt capture cleanup
            error_code = getattr(exc, "code", type(exc).__name__)
            if active.handshake_error_code != error_code:
                self.events.write(
                    "WARNING", "capture", "handshake_analysis_failed",
                    "Handshake analysis is temporarily unavailable; capture continues.",
                    capture_id=active.id,
                    error_code=error_code,
                )
            active.handshake_error_code = error_code
            return

        active.handshake_client_macs.update(item["mac"] for item in analysis["clients"])
        old_state = active.handshake_state or "not_captured"
        new_state = analysis["state"]
        if HANDSHAKE_STATES[new_state] < HANDSHAKE_STATES[old_state]:
            new_state = old_state
            new_client = active.handshake_client_mac
        else:
            new_client = analysis["client_mac"] or active.handshake_client_mac
        if new_state == old_state and new_client == active.handshake_client_mac:
            return
        active.handshake_state = new_state
        active.handshake_client_mac = new_client
        updated_at = utcnow()
        self.db.execute(
            "UPDATE captures SET handshake_state=?,handshake_client_mac=?,handshake_updated_at=? WHERE id=?",
            (new_state, new_client, updated_at, active.id),
        )
        if HANDSHAKE_STATES[new_state] > HANDSHAKE_STATES[old_state]:
            event = "partial_handshake_detected" if new_state == "partial" else "full_handshake_detected"
            message = "Partial WPA/WPA2 handshake detected." if new_state == "partial" else "Full WPA/WPA2 handshake captured."
            self.events.write(
                "INFO", "capture", event, message,
                capture_id=active.id,
                target_bssid=active.target["bssid"],
                client_mac=new_client,
            )

    # Standalone Capture. Targeted and handshake modes still receive every
    # frame visible to the monitor adapter on the selected channel; target
    # metadata provides analysis context rather than a hardware BSSID filter.
    def start_capture(
        self,
        interface: str,
        channel: int,
        name: str,
        capture_mode: str = "raw",
        target: dict | None = None,
    ) -> dict:
        capture_mode = str(capture_mode or "raw").lower()
        require(
            capture_mode in {"raw", "targeted", "handshake"},
            "INVALID_CAPTURE_MODE",
            "Capture mode must be raw, targeted, or handshake.",
        )
        target_data = None
        if capture_mode in {"targeted", "handshake"}:
            supplied_bssid = target.get("bssid") if isinstance(target, dict) else None
            target_data = self._target_for_capture(supplied_bssid)
            channel = int(target_data["channel"])
            if capture_mode == "handshake" and not self._handshake_security_supported(target_data.get("security")):
                raise PinePiError(
                    "HANDSHAKE_SECURITY_UNSUPPORTED",
                    "Handshake capture requires a WPA or WPA2 target observed in Recon.",
                    409,
                    {"bssid": target_data["bssid"], "security": target_data.get("security")},
                )
        else:
            try:
                channel = int(channel)
            except (TypeError, ValueError) as exc:
                raise PinePiError("INVALID_CHANNEL", "Channel must be a number.") from exc
        require(1 <= channel <= 196, "INVALID_CHANNEL", "Channel is out of range.")
        adapter = self.adapters.require_wireless(interface, "monitor")
        supported = adapter.get("capabilities", {}).get("ap_channels") or []
        if capture_mode in {"targeted", "handshake"} and supported and channel not in supported:
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
                    "target_bssid,target_ssid,target_frequency,target_band,target_security,target_last_seen,"
                    "handshake_state,handshake_updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        operation_id, capture_name, interface, channel, started, "STARTING", str(path),
                        capture_mode, target_data.get("bssid") if target_data else None,
                        target_data.get("ssid") if target_data else None,
                        target_data.get("frequency") if target_data else None,
                        target_data.get("band") if target_data else None,
                        target_data.get("security") if target_data else None,
                        target_data.get("last_seen") if target_data else None,
                        "not_captured" if capture_mode == "handshake" else None,
                        started if capture_mode == "handshake" else None,
                    ),
                )
                self.privileged.record_restore(interface, operation_id)
                self.privileged.set_monitor(interface, channel)
                process = self.privileged.start_capture(
                    interface,
                    path,
                    self.max_capture_bytes,
                    operation_id,
                    channel,
                    target_data.get("bssid") if target_data else None,
                )
                time.sleep(0.2)
                if not process.alive():
                    raise PinePiError(
                        "CAPTURE_START_FAILED", "Capture process exited during startup.", 500,
                        {"stage": "capture_process_start", "interface": interface, "process_exit": True},
                    )
                self._capture = ActiveCapture(
                    operation_id, capture_name, interface, channel, started, path, reservation, process,
                    capture_mode=capture_mode, target=target_data,
                    handshake_state="not_captured" if capture_mode == "handshake" else None,
                )
                self.db.execute("UPDATE captures SET status='RUNNING' WHERE id=?", (operation_id,))
                self.events.write(
                    "INFO", "capture", "started", "Standalone capture started.",
                    interface=interface, capture_id=operation_id, capture_mode=capture_mode,
                    target_bssid=target_data.get("bssid") if target_data else None,
                    channel=channel,
                )
                if capture_mode == "handshake":
                    self.events.write(
                        "INFO", "capture", "handshake_capture_started",
                        "WPA/WPA2 handshake capture started.",
                        capture_id=operation_id,
                        interface=interface,
                        target_bssid=target_data["bssid"],
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
            restore_ok = False
            try:
                cleanup_ok &= self._cleanup_call("capture", active.id, "stop_process", lambda: self.privileged.stop_process(active.process))
            finally:
                self._refresh_handshake(active, force=True)
                restore_ok = self._cleanup_call(
                    "capture", active.id, "restore_interface",
                    lambda: self.privileged.restore_interface(active.interface),
                )
                cleanup_ok &= restore_ok
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
                    handshake_state=active.handshake_state,
                    handshake_client_mac=active.handshake_client_mac,
                )
                if restore_ok:
                    self.events.write(
                        "INFO", "capture", "adapter_restored",
                        "Capture adapter was restored after capture stopped.",
                        interface=active.interface, capture_id=active.id,
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
        with self._capture_lock:
            active = self._capture
            if not active:
                return {
                    "state": "IDLE", "active": False, "elapsed_seconds": 0,
                    "handshake_state": None, "observed_clients": [],
                }
            self._refresh_handshake(active)
            size = active.path.stat().st_size if active.path.exists() else 0
            return {
                "state": active.state, "active": True, "capture_id": active.id, "name": active.name,
                "interface": active.interface, "channel": active.channel, "started_at": active.started_at,
                "elapsed_seconds": elapsed_seconds(active.started_at), "size_bytes": size,
                "packet_count": None, "process_alive": active.process.alive(),
                "capture_mode": active.capture_mode, "target": active.target,
                "handshake_state": active.handshake_state,
                "handshake_client_mac": active.handshake_client_mac,
                "observed_clients": self._capture_observed_clients(active),
                "reconnect_limits": {
                    "max_count": DEAUTH_MAX_COUNT,
                    "max_duration_seconds": DEAUTH_MAX_DURATION_SECONDS,
                } if active.capture_mode == "handshake" else None,
            }

    def request_capture_reconnect(self, capture_id: str, data: dict) -> dict:
        with self._capture_lock:
            active = self._capture
            if not active or active.id != capture_id or active.state != "RUNNING":
                raise PinePiError(
                    "HANDSHAKE_CAPTURE_NOT_ACTIVE",
                    "Reconnect requests require the matching active handshake capture.",
                    409,
                )
            if active.capture_mode != "handshake" or not active.target:
                raise PinePiError(
                    "HANDSHAKE_CAPTURE_REQUIRED",
                    "Reconnect requests are available only inside a WPA/WPA2 handshake capture.",
                    409,
                )
            if not active.process.alive():
                raise PinePiError("CAPTURE_PROCESS_EXITED", "The capture process is no longer running.", 409)

            requested_bssid = normalize_bssid(data.get("bssid", active.target["bssid"]))
            if requested_bssid != active.target["bssid"]:
                raise PinePiError("CAPTURE_TARGET_MISMATCH", "BSSID does not match the active capture target.", 409)
            channel_value = data.get("channel", active.channel)
            if isinstance(channel_value, bool) or not isinstance(channel_value, int):
                raise PinePiError("INVALID_CHANNEL", "Channel is out of range.")
            requested_channel = channel_value
            require(1 <= requested_channel <= 196, "INVALID_CHANNEL", "Channel is out of range.")
            if requested_channel != active.channel:
                raise PinePiError("CAPTURE_TARGET_MISMATCH", "Channel does not match the active capture.", 409)

            client_mac = normalize_client_mac(data.get("client_mac", ""))
            allowed_clients = {item["mac"] for item in self._capture_observed_clients(active)}
            if client_mac not in allowed_clients:
                raise PinePiError(
                    "CLIENT_NOT_OBSERVED",
                    "The client was not recently observed with the active capture target.",
                    404,
                    {"client_mac": client_mac, "target_bssid": requested_bssid},
                )
            count = self._bounded_reconnect_value(data.get("count", DEAUTH_MAX_COUNT), "count")
            duration_seconds = self._bounded_reconnect_value(
                data.get("duration_seconds", 10), "duration_seconds",
            )
            if count > DEAUTH_MAX_COUNT or duration_seconds > DEAUTH_MAX_DURATION_SECONDS:
                raise PinePiError("DEAUTH_LIMIT_EXCEEDED", "Reconnect request exceeds the server safety limit.")

            self.events.write(
                "WARNING", "capture", "reconnect_requested",
                "Bounded client reconnect requested during handshake capture.",
                capture_id=active.id,
                target_bssid=requested_bssid,
                client_mac=client_mac,
                count=count,
                duration_seconds=duration_seconds,
            )
            try:
                result = self.privileged.capture_reconnect(
                    active.interface,
                    active.id,
                    requested_bssid,
                    requested_channel,
                    client_mac,
                    count,
                    duration_seconds,
                )
            except PinePiError as exc:
                self.events.write(
                    "ERROR", "capture", "reconnect_failed",
                    "Bounded client reconnect request failed; capture continues.",
                    capture_id=active.id,
                    target_bssid=requested_bssid,
                    client_mac=client_mac,
                    error_code=exc.code,
                )
                raise
            completed_at = utcnow()
            self.db.execute(
                "UPDATE captures SET reconnect_count=reconnect_count+1,last_reconnect_at=?,"
                "last_reconnect_client=? WHERE id=?",
                (completed_at, client_mac, active.id),
            )
            self.events.write(
                "INFO", "capture", "bounded_deauth_completed",
                "Bounded client reconnect request completed; handshake capture remains active.",
                capture_id=active.id,
                target_bssid=requested_bssid,
                client_mac=client_mac,
                count=count,
            )
            return {
                **result,
                "capture_active": bool(active.process.alive()),
                "handshake_state": active.handshake_state,
            }

    @staticmethod
    def _bounded_reconnect_value(value, field_name: str) -> int:
        if isinstance(value, bool) or not isinstance(value, int):
            raise PinePiError("DEAUTH_LIMIT_EXCEEDED", f"Reconnect {field_name} must be an integer.")
        if value < 1:
            raise PinePiError("DEAUTH_LIMIT_EXCEEDED", f"Reconnect {field_name} must be positive.")
        return value

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
                    capture = self.privileged.start_capture(
                        interface,
                        capture_path,
                        self.max_capture_bytes,
                        operation_id + "-traffic",
                        channel,
                        None,
                    )
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
                # Telemetry is best effort during shutdown. A dead hostapd makes
                # the helper intentionally reject a station snapshot, but that
                # must not misreport successful interface/routing cleanup.
                self._cleanup_call("access_point", active.id, "save_clients", lambda: self._save_ap_clients(active))
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
            return {
                "state": "IDLE", "active": False, "elapsed_seconds": 0, "clients": [],
                "traffic_totals": {"download_bytes": 0, "upload_bytes": 0},
                "client_counter_semantics": self._client_counter_semantics(),
            }
        clients = self._read_ap_clients(active)
        persisted = {
            item["mac"]: item
            for item in self.db.fetchall(
                "SELECT mac,download_bytes,upload_bytes FROM ap_clients WHERE session_id=?",
                (active.id,),
            )
        }
        for client in clients:
            persisted[client["mac"]] = client
        traffic_totals = {
            "download_bytes": sum(item.get("download_bytes") or 0 for item in persisted.values()),
            "upload_bytes": sum(item.get("upload_bytes") or 0 for item in persisted.values()),
        }
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
            "traffic_totals": traffic_totals,
            "client_counter_semantics": self._client_counter_semantics(),
            "hostapd_alive": active.hostapd.alive(), "dnsmasq_alive": active.dnsmasq.alive(),
        }

    def ap_history(self) -> list[dict]:
        return self.db.fetchall("SELECT * FROM ap_sessions ORDER BY started_at DESC LIMIT 100")

    @staticmethod
    def _nonnegative_counter(value) -> int | None:
        return value if isinstance(value, int) and value >= 0 else None

    @staticmethod
    def _client_counter_semantics() -> dict:
        return {
            "download_bytes": "Bytes transmitted by the AP to the client (AP TX / client RX).",
            "upload_bytes": "Bytes received by the AP from the client (AP RX / client TX).",
            "ap_rx_bytes": "Latest kernel per-association counter for bytes received by the AP.",
            "ap_tx_bytes": "Latest kernel per-association counter for bytes transmitted by the AP.",
            "scope": "Accumulated per MAC for this AP session across detected associations.",
        }

    @staticmethod
    def _association_reset(previous: dict | None, station: dict) -> bool:
        if not previous:
            return False
        current_connected = OperationService._nonnegative_counter(station.get("connected_seconds"))
        previous_connected = OperationService._nonnegative_counter(previous.get("last_connected_seconds"))
        if current_connected is not None and previous_connected is not None and current_connected < previous_connected:
            return True
        for key in ("ap_rx_bytes", "ap_tx_bytes"):
            current = OperationService._nonnegative_counter(station.get(key))
            old = OperationService._nonnegative_counter(previous.get(key))
            if current is not None and old is not None and current < old:
                return True
        return False

    @staticmethod
    def _accumulate_counter(previous: dict | None, total_key: str, raw_key: str, current, reset: bool) -> int:
        value = OperationService._nonnegative_counter(current)
        previous_total = int(previous.get(total_key) or 0) if previous else 0
        if value is None:
            return previous_total
        if not previous or reset:
            return previous_total + value
        previous_raw = OperationService._nonnegative_counter(previous.get(raw_key))
        return previous_total + (value if previous_raw is None else max(0, value - previous_raw))

    @staticmethod
    def _connected_at(now: datetime, station: dict, previous: dict | None, reset: bool) -> str:
        if previous and not reset and previous.get("connected_at"):
            return previous["connected_at"]
        connected_seconds = OperationService._nonnegative_counter(station.get("connected_seconds"))
        return (now - timedelta(seconds=connected_seconds or 0)).isoformat()

    def _merge_ap_clients(self, active: ActiveAP) -> tuple[list[dict], set[str]]:
        stations = self.privileged.ap_client_snapshot(active.interface, active.session_dir, active.id)
        known = {
            row["mac"]: row
            for row in self.db.fetchall("SELECT * FROM ap_clients WHERE session_id=?", (active.id,))
        }
        now_value = datetime.now(UTC)
        now = now_value.isoformat()
        clients: list[dict] = []
        associated_macs: set[str] = set()
        observed_macs: set[str] = set()
        for station in stations:
            mac = normalize_client_mac(station.get("mac", ""))
            observed_macs.add(mac)
            previous = known.get(mac)
            reset = self._association_reset(previous, station)
            ap_rx_bytes = self._nonnegative_counter(station.get("ap_rx_bytes"))
            ap_tx_bytes = self._nonnegative_counter(station.get("ap_tx_bytes"))
            association_count = max(1, int(previous.get("association_count") or 0)) if previous else 1
            if reset:
                association_count += 1
            blocked = mac in active.blocked_macs or bool(previous and previous.get("blocked"))
            if not blocked:
                associated_macs.add(mac)
            client = {
                "mac": mac,
                "ip_address": station.get("ip_address"),
                "hostname": station.get("hostname"),
                "ip_source": station.get("ip_source"),
                "first_seen": previous.get("first_seen") if previous else now,
                "last_seen": now,
                "connected_at": self._connected_at(now_value, station, previous, reset),
                "disconnected_at": None,
                "association_state": "blocked" if blocked else "associated",
                "association_count": association_count,
                "signal_dbm": station.get("signal_dbm"),
                "inactive_ms": self._nonnegative_counter(station.get("inactive_ms")),
                "authenticated": station.get("authenticated"),
                "authorized": station.get("authorized"),
                # Linux reports station counters from the local AP perspective:
                # AP TX is client download; AP RX is client upload.
                "download_bytes": self._accumulate_counter(
                    previous, "download_bytes", "ap_tx_bytes", ap_tx_bytes, reset,
                ),
                "upload_bytes": self._accumulate_counter(
                    previous, "upload_bytes", "ap_rx_bytes", ap_rx_bytes, reset,
                ),
                "ap_rx_bytes": ap_rx_bytes,
                "ap_tx_bytes": ap_tx_bytes,
                "last_connected_seconds": self._nonnegative_counter(station.get("connected_seconds")),
                "connection_duration_seconds": self._nonnegative_counter(station.get("connected_seconds")),
                "blocked": blocked,
                "blocked_at": previous.get("blocked_at") if previous else None,
                "ap_rx_packets": self._nonnegative_counter(station.get("ap_rx_packets")),
                "ap_tx_packets": self._nonnegative_counter(station.get("ap_tx_packets")),
            }
            clients.append(client)
        for mac in sorted(active.blocked_macs - observed_macs):
            previous = known.get(mac)
            if previous:
                clients.append({
                    **previous,
                    "association_state": "blocked",
                    "blocked": True,
                    "connection_duration_seconds": previous.get("last_connected_seconds"),
                    "ap_rx_packets": None,
                    "ap_tx_packets": None,
                })
        clients.sort(key=lambda item: (not item.get("blocked"), item["mac"]))
        return clients, associated_macs

    def _read_ap_clients(self, active: ActiveAP) -> list[dict]:
        clients, _associated = self._merge_ap_clients(active)
        return clients

    def _persist_ap_client(self, session_id: str, client: dict) -> None:
        self.db.execute(
            "INSERT INTO ap_clients(session_id,mac,ip_address,hostname,ip_source,first_seen,last_seen,"
            "connected_at,disconnected_at,association_state,association_count,signal_dbm,inactive_ms,"
            "authenticated,authorized,download_bytes,upload_bytes,ap_rx_bytes,ap_tx_bytes,"
            "last_connected_seconds,blocked,blocked_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) "
            "ON CONFLICT(session_id,mac) DO UPDATE SET ip_address=excluded.ip_address,"
            "hostname=excluded.hostname,ip_source=excluded.ip_source,last_seen=excluded.last_seen,"
            "connected_at=excluded.connected_at,disconnected_at=excluded.disconnected_at,"
            "association_state=excluded.association_state,association_count=excluded.association_count,"
            "signal_dbm=excluded.signal_dbm,inactive_ms=excluded.inactive_ms,"
            "authenticated=excluded.authenticated,authorized=excluded.authorized,"
            "download_bytes=excluded.download_bytes,upload_bytes=excluded.upload_bytes,"
            "ap_rx_bytes=excluded.ap_rx_bytes,ap_tx_bytes=excluded.ap_tx_bytes,"
            "last_connected_seconds=excluded.last_connected_seconds,blocked=excluded.blocked,"
            "blocked_at=excluded.blocked_at",
            (
                session_id, client["mac"], client.get("ip_address"), client.get("hostname"),
                client.get("ip_source"), client["first_seen"], client["last_seen"],
                client.get("connected_at"), client.get("disconnected_at"),
                client["association_state"], client["association_count"], client.get("signal_dbm"),
                client.get("inactive_ms"),
                None if client.get("authenticated") is None else int(client["authenticated"]),
                None if client.get("authorized") is None else int(client["authorized"]),
                client["download_bytes"], client["upload_bytes"], client.get("ap_rx_bytes"),
                client.get("ap_tx_bytes"), client.get("last_connected_seconds"),
                int(bool(client.get("blocked"))), client.get("blocked_at"),
            ),
        )

    def _save_ap_clients(self, active: ActiveAP) -> None:
        clients, current_macs = self._merge_ap_clients(active)
        if active.log_clients:
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
            self._persist_ap_client(active.id, client)
        disconnected_at = utcnow()
        for row in self.db.fetchall(
            "SELECT mac,blocked,association_state FROM ap_clients WHERE session_id=?", (active.id,),
        ):
            if row["mac"] in current_macs or row["mac"] in active.blocked_macs:
                continue
            if row["association_state"] == "associated":
                self.db.execute(
                    "UPDATE ap_clients SET association_state='disconnected',disconnected_at=? "
                    "WHERE session_id=? AND mac=?",
                    (disconnected_at, active.id, row["mac"]),
                )

    def manage_ap_client(self, mac: str, action: str) -> dict:
        mac = normalize_client_mac(mac)
        require(action in {"kick", "block", "unblock"}, "INVALID_CLIENT_ACTION", "Unsupported AP client action.")
        with self._ap_lock:
            active = self._ap
            if not active or active.state != "RUNNING":
                raise PinePiError(
                    "AP_NOT_ACTIVE", "Client management requires an active PinePi-hosted Access Point.", 409,
                )
            clients = {item["mac"]: item for item in self._read_ap_clients(active)}
            client = clients.get(mac)
            blocked = mac in active.blocked_macs or bool(client and client.get("blocked"))
            if action == "block" and blocked:
                return {"mac": mac, "action": action, "association_state": "blocked", "changed": False}
            if action == "unblock":
                if not blocked:
                    raise PinePiError("CLIENT_NOT_BLOCKED", "The client is not blocked on this AP.", 409)
            elif not client or client.get("association_state") != "associated":
                raise PinePiError(
                    "CLIENT_NOT_ASSOCIATED", "The client is not associated with the active PinePi AP.", 404,
                    {"mac": mac},
                )

            if client:
                self._persist_ap_client(active.id, client)
            self.privileged.ap_client_action(active.interface, active.session_dir, active.id, mac, action)
            changed_at = utcnow()
            if action == "block":
                active.blocked_macs.add(mac)
                active.connected_macs.discard(mac)
                self.db.execute(
                    "UPDATE ap_clients SET blocked=1,blocked_at=?,association_state='blocked',"
                    "disconnected_at=? WHERE session_id=? AND mac=?",
                    (changed_at, changed_at, active.id, mac),
                )
                association_state = "blocked"
            elif action == "unblock":
                active.blocked_macs.discard(mac)
                self.db.execute(
                    "UPDATE ap_clients SET blocked=0,blocked_at=NULL,association_state='disconnected' "
                    "WHERE session_id=? AND mac=?",
                    (active.id, mac),
                )
                association_state = "disconnected"
            else:
                active.connected_macs.discard(mac)
                self.db.execute(
                    "UPDATE ap_clients SET association_state='disconnected',disconnected_at=? "
                    "WHERE session_id=? AND mac=?",
                    (changed_at, active.id, mac),
                )
                association_state = "disconnected"
            self.events.write(
                "INFO", "access_point", f"client_{action}",
                f"AP client {action} completed.",
                session_id=active.id, interface=active.interface, mac=mac,
            )
            return {
                "mac": mac,
                "action": action,
                "association_state": association_state,
                "changed": True,
            }

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
                    with self._capture_lock:
                        active = self._capture
                        if not active or active.id != operation_id:
                            return
                        reason = self._capture_guard(active.path, active.process)
                        if reason:
                            self.stop_capture(reason)
                            return
                        self._refresh_handshake(active)
                elif kind == "ap":
                    with self._ap_lock:
                        active = self._ap
                        if not active or active.id != operation_id:
                            return
                        if not active.hostapd.alive() or not active.dnsmasq.alive():
                            self.stop_ap("process_exit")
                            return
                        self._save_ap_clients(active)
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
