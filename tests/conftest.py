from __future__ import annotations

from dataclasses import dataclass

import pytest

from pinepi.adapters import MANAGEMENT_INTERFACE, ReservationRegistry
from pinepi.db import Database
from pinepi.errors import PinePiError
from pinepi.events import EventLog
from pinepi.operations import OperationService


@dataclass
class FakeProcess:
    operation_id: str
    running: bool = True
    pid: int = 12345

    def alive(self):
        return self.running


class FakePrivileged:
    def __init__(self):
        self.calls = []
        self.fail_monitor = False
        self.fail_capture = False
        self.fail_ap = False
        self.fail_routing = False
        self.stations = []

    def reconcile_runtime(self):
        self.calls.append(("reconcile",))
        return []

    def record_restore(self, interface, operation_id): self.calls.append(("record_restore", interface, operation_id))
    def forget_restore(self, operation_id): self.calls.append(("forget_restore", operation_id))
    def set_monitor(self, interface, channel=None):
        self.calls.append(("set_monitor", interface, channel))
        if self.fail_monitor: raise PinePiError("MONITOR_MODE_FAILED", "failed", 500)
    def restore_interface(self, interface): self.calls.append(("restore", interface))
    def start_recon(self, interface, prefix, operation_id):
        self.calls.append(("start_recon", interface))
        return FakeProcess(operation_id, not self.fail_capture)
    def start_capture(self, interface, path, max_bytes, operation_id):
        self.calls.append(("start_capture", interface, path))
        process = FakeProcess(operation_id, not self.fail_capture)
        if not self.fail_capture:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"\x0a\x0d\x0d\x0a")
        return process
    def stop_process(self, process, grace=3):
        self.calls.append(("stop", getattr(process, "operation_id", None)))
        if process: process.running = False
    def start_ap(self, interface, ssid, channel, security, password, session_dir, operation_id):
        self.calls.append(("start_ap", interface, security, password))
        if self.fail_ap:
            raise PinePiError(
                "AP_VERIFICATION_FAILED", f"{interface} remained in managed mode instead of AP mode.", 500,
                {
                    "stage": "hostapd_verify", "expected_mode": "AP", "actual_mode": "managed",
                    "expected_ssid": "PinePi-Test", "actual_ssid": None, "hostapd_exit": None,
                    "hostapd_status": "state=STARTING", "hostapd_output": "nl80211: setup pending",
                },
            )
        return FakeProcess(operation_id + "-hostapd"), FakeProcess(operation_id + "-dnsmasq")
    def setup_routing(self, ap_interface, uplink, operation_id):
        self.calls.append(("setup_routing", ap_interface, uplink))
        if self.fail_routing: raise PinePiError("ROUTING_SETUP_FAILED", "failed", 500)
        return {"table": "pinepi_test", "previous_forwarding": "0"}
    def teardown_routing(self, routing): self.calls.append(("teardown_routing", routing))
    def station_dump(self, interface): return list(self.stations)
    def inspect_capture(self, _path):
        class Result:
            returncode = 1
            stdout = ""
        return Result()


class FakeAdapters:
    def __init__(self):
        self.names = {"wlan1", "wlan2"}

    def require_wireless(self, interface, capability):
        if interface == MANAGEMENT_INTERFACE:
            raise PinePiError("MANAGEMENT_INTERFACE_RESERVED", "reserved", 409)
        if interface not in self.names:
            raise PinePiError("ADAPTER_NOT_FOUND", "not found", 404)
        return {"name": interface, f"{capability}_capable": True}

    def require_ap_channel(self, interface, channel):
        if interface not in self.names:
            raise PinePiError("ADAPTER_NOT_FOUND", "not found", 404)
        if channel not in {1, 6, 11, 36, 40, 44, 48}:
            raise PinePiError("UNSUPPORTED_CHANNEL", "unsupported channel", 409)
        return {"name": interface, "channel": channel}

    def choose_uplink(self, requested, ap_interface):
        if requested in {"none", ""}: return None
        if requested == "auto": return "eth0"
        if requested == MANAGEMENT_INTERFACE: raise PinePiError("MANAGEMENT_INTERFACE_RESERVED", "reserved", 409)
        if requested == ap_interface or requested not in {"eth0", "usb0", "wlan1", "wlan2"}: raise PinePiError("NO_UPLINK", "unavailable", 409)
        return requested


@pytest.fixture
def service(tmp_path):
    for folder in ("captures", "ap_sessions", "exports", "runtime"):
        (tmp_path / folder).mkdir()
    database = Database(tmp_path / "pinepi.db")
    database.migrate()
    privileged = FakePrivileged()
    registry = ReservationRegistry()
    operations = OperationService(
        database, EventLog(database), FakeAdapters(), registry, privileged, tmp_path,
        max_capture_bytes=250 * 1024 * 1024, min_free_bytes=1, reconcile=False,
    )
    return operations, privileged, registry, database
