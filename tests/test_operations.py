from __future__ import annotations

import json
import zipfile
from pathlib import Path

import pytest

from pinepi.errors import PinePiError
from pinepi.exports import ExportService
from pinepi.helper import HelperState
from pinepi.privileged import PrivilegedService


@pytest.mark.parametrize("kind", ["recon", "capture", "ap"])
def test_wlan0_is_rejected_for_all_audit_operations(service, kind):
    operations, _privileged, registry, _db = service
    with pytest.raises(PinePiError) as error:
        if kind == "recon": operations.start_recon("wlan0")
        elif kind == "capture": operations.start_capture("wlan0", 6, "test")
        else: operations.start_ap({"interface": "wlan0", "ssid": "Test", "channel": 6, "security": "open", "forwarding": False})
    assert error.value.code == "MANAGEMENT_INTERFACE_RESERVED"
    assert registry.snapshot() == {}


def test_unavailable_adapter_is_rejected(service):
    operations, _privileged, registry, _db = service
    with pytest.raises(PinePiError) as error:
        operations.start_recon("wlan9")
    assert error.value.code == "ADAPTER_NOT_FOUND"
    assert registry.snapshot() == {}


def test_recon_and_ap_can_use_different_adapters(service):
    operations, _privileged, registry, _db = service
    operations.start_recon("wlan1")
    operations.start_ap({"interface": "wlan2", "ssid": "Test", "channel": 6, "security": "open", "forwarding": False})
    assert registry.role("wlan1") == "recon"
    assert registry.role("wlan2") == "ap"
    operations.stop_ap()
    operations.stop_recon()
    assert registry.snapshot() == {}


def test_failed_recon_start_releases_and_restores_adapter(service):
    operations, privileged, registry, _db = service
    privileged.fail_monitor = True
    with pytest.raises(PinePiError): operations.start_recon("wlan1")
    assert registry.snapshot() == {}
    assert ("restore", "wlan1") in privileged.calls


def test_helper_cleanup_failure_still_releases_local_ownership(service):
    operations, privileged, registry, database = service
    operations.start_recon("wlan1")

    def fail_restore(_interface):
        raise PinePiError("HELPER_UNAVAILABLE", "offline", 503)

    privileged.restore_interface = fail_restore
    with pytest.raises(PinePiError) as error:
        operations.stop_recon()
    assert error.value.code == "CLEANUP_FAILED"
    assert registry.snapshot() == {}
    assert operations.recon_status()["active"] is False
    row = database.fetchone("SELECT status,stop_reason FROM recon_sessions ORDER BY started_at DESC LIMIT 1")
    assert row == {"status": "ERROR", "stop_reason": "cleanup_failed"}


def test_failed_capture_start_releases_and_restores_adapter(service):
    operations, privileged, registry, _db = service
    privileged.fail_capture = True
    with pytest.raises(PinePiError) as error: operations.start_capture("wlan1", 6, "test")
    assert error.value.code == "CAPTURE_START_FAILED"
    assert registry.snapshot() == {}
    assert ("restore", "wlan1") in privileged.calls


def test_failed_ap_start_cleans_processes_interface_and_reservation(service):
    operations, privileged, registry, _db = service
    privileged.fail_routing = True
    with pytest.raises(PinePiError):
        operations.start_ap({"interface": "wlan1", "ssid": "Test", "channel": 6, "security": "open", "uplink": "eth0"})
    assert registry.snapshot() == {}
    assert ("teardown_routing", None) in privileged.calls
    assert ("restore", "wlan1") in privileged.calls
    assert any(call[0] == "stop" for call in privileged.calls)


def test_ap_failure_log_and_txt_export_include_structured_diagnostics(service):
    operations, privileged, registry, database = service
    privileged.fail_ap = True
    with pytest.raises(PinePiError) as error:
        operations.start_ap({"interface": "wlan1", "ssid": "PinePi-Test", "channel": 6, "security": "open", "forwarding": False})
    assert error.value.message == "wlan1 remained in managed mode instead of AP mode."
    assert registry.snapshot() == {}
    row = database.fetchone("SELECT context_json FROM events WHERE component='access_point' AND event='start_failed'")
    context = json.loads(row["context_json"])
    assert context["stage"] == "hostapd_verify"
    assert context["actual_mode"] == "managed"
    assert context["cleanup_result"] == "complete"
    exporter = ExportService(database, operations.events, operations)
    payload, _name, _mimetype = exporter.logs("txt", "ERROR", "access_point", None)
    text = payload.decode("utf-8")
    assert '"stage":"hostapd_verify"' in text
    assert '"hostapd_status":"state=STARTING"' in text


def test_ap_stop_removes_routing_and_restores_interface(service):
    operations, privileged, registry, _db = service
    operations.start_ap({"interface": "wlan1", "ssid": "Test", "channel": 6, "security": "open", "uplink": "eth0"})
    operations.stop_ap()
    assert any(call[0] == "teardown_routing" and call[1] for call in privileged.calls)
    assert ("restore", "wlan1") in privileged.calls
    assert registry.snapshot() == {}


@pytest.mark.parametrize("interface", ["wlan1", "wlan2"])
def test_repeated_ap_cycles_stop_only_temporary_processes_and_restore_adapter(service, interface):
    operations, privileged, registry, _db = service

    for _ in range(2):
        started = operations.start_ap({
            "interface": interface,
            "ssid": f"PinePi-{interface}",
            "channel": 6,
            "security": "open",
            "forwarding": False,
        })
        operation_id = started["session_id"]
        assert registry.role(interface) == "ap"

        operations.stop_ap()

        stopped_ids = [call[1] for call in privileged.calls if call[0] == "stop"]
        assert operation_id + "-dnsmasq" in stopped_ids
        assert operation_id + "-hostapd" in stopped_ids
        assert registry.snapshot() == {}

    assert privileged.calls.count(("restore", interface)) == 2
    assert all(
        call[1] is None or not call[1].startswith("pinepi-management")
        for call in privileged.calls
        if call[0] == "stop"
    )


def test_wlan0_cannot_be_an_uplink(service):
    operations, _privileged, registry, _db = service
    with pytest.raises(PinePiError) as error:
        operations.start_ap({"interface": "wlan1", "ssid": "Test", "channel": 6, "security": "open", "uplink": "wlan0"})
    assert error.value.code == "MANAGEMENT_INTERFACE_RESERVED"
    assert registry.snapshot() == {}


def test_wireless_ap_uplink_is_reserved_from_capture(service):
    operations, _privileged, registry, _db = service
    operations.start_ap({"interface": "wlan1", "ssid": "Test", "channel": 6, "security": "open", "uplink": "wlan2"})
    with pytest.raises(PinePiError) as error:
        operations.start_capture("wlan2", 6, "conflict")
    assert error.value.code == "ADAPTER_BUSY"
    assert registry.role("wlan2") == "ap_uplink"
    operations.stop_ap()


def test_password_is_not_persisted_in_events_or_ap_export(service):
    operations, _privileged, _registry, database = service
    secret = "teacher-demo-secret"
    started = operations.start_ap({"interface": "wlan1", "ssid": "Test", "channel": 6, "security": "wpa2", "password": secret, "forwarding": False})
    operations.stop_ap()
    raw = operations.data_dir.joinpath("pinepi.db").read_bytes()
    assert secret.encode() not in raw
    exporter = ExportService(database, operations.events, operations)
    path, _name = exporter.ap_zip(started["session_id"])
    with zipfile.ZipFile(path) as archive:
        assert secret not in archive.read("metadata.json").decode()


def test_startup_reconciliation_marks_interrupted_sessions(tmp_path, service):
    operations, privileged, registry, database = service
    operations.start_recon("wlan1")
    # Simulate a new service instance reconciling persisted state.
    from conftest import FakeAdapters

    from pinepi.events import EventLog
    from pinepi.operations import OperationService
    replacement_registry = type(registry)()
    OperationService(database, EventLog(database), FakeAdapters(), replacement_registry, privileged, operations.data_dir, operations.max_capture_bytes, 1, reconcile=True)
    row = database.fetchone("SELECT status FROM recon_sessions ORDER BY started_at DESC LIMIT 1")
    assert row["status"] == "INTERRUPTED"
    assert ("reconcile",) in privileged.calls
    operations.stop_recon()


def test_capture_storage_guard(service, monkeypatch):
    operations, _privileged, _registry, _db = service
    class Usage:
        total = 1000
        used = 999
        free = 1
    monkeypatch.setattr("pinepi.operations.shutil.disk_usage", lambda _path: Usage())
    operations.min_free_bytes = 10
    with pytest.raises(PinePiError) as error: operations.start_capture("wlan1", 6, "test")
    assert error.value.code == "INSUFFICIENT_STORAGE"


def test_path_traversal_is_rejected(service, tmp_path):
    operations, _privileged, _registry, _db = service
    with pytest.raises(PinePiError) as error:
        operations.authorized_path(tmp_path.parent / "secret", operations.data_dir / "captures")
    assert error.value.code == "INVALID_EXPORT_PATH"


def test_malformed_pcap_does_not_crash(service):
    operations, _privileged, _registry, _db = service
    path = operations.data_dir / "captures" / "bad.pcap"
    path.write_bytes(b"not a packet capture")
    summary = operations.analyze_pcap(path)
    assert summary["valid"] is False
    assert summary["packet_count"] is None


def test_status_methods_do_not_change_persistent_state(service):
    operations, privileged, _registry, database = service
    before = database.fetchall("SELECT * FROM events")
    calls = list(privileged.calls)
    for _ in range(3):
        operations.recon_status(); operations.capture_status(); operations.ap_status()
    assert database.fetchall("SELECT * FROM events") == before
    assert privileged.calls == calls


def test_privileged_routing_failure_rolls_back_only_owned_state(tmp_path, monkeypatch):
    calls = []

    class Result:
        def __init__(self, returncode=0):
            self.returncode = returncode
            self.stdout = ""
            self.stderr = "failed" if returncode else ""

    def runner(argv, **_kwargs):
        calls.append(argv)
        return Result(1 if argv[:3] == ["nft", "add", "rule"] else 0)

    original_read_text = Path.read_text

    def read_text(path, *args, **kwargs):
        if str(path).replace("\\", "/") == "/proc/sys/net/ipv4/ip_forward":
            return "0"
        return original_read_text(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", read_text)
    privileged = PrivilegedService(tmp_path / "runtime", runner=runner)
    with pytest.raises(PinePiError) as error:
        privileged.setup_routing("wlan1", "eth0", "a" * 32)
    assert error.value.code == "ROUTING_SETUP_FAILED"
    assert ["nft", "delete", "table", "inet", "pinepi_aaaaaaaaaaaa"] in calls
    assert ["sysctl", "-w", "net.ipv4.ip_forward=0"] in calls


def test_reconcile_restores_only_external_recorded_adapters(tmp_path, monkeypatch):
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    (runtime / "restore-one.json").write_text('{"interface":"wlan1"}')
    (runtime / "restore-management.json").write_text('{"interface":"wlan0"}')
    (runtime / "restore-bad.json").write_text("not-json")
    privileged = PrivilegedService(runtime, runner=lambda _argv, **_kwargs: type("Result", (), {"returncode": 0, "stdout": "", "stderr": ""})())
    restored = []
    monkeypatch.setattr(privileged, "restore_interface", restored.append)
    assert privileged.reconcile_runtime() == ["wlan1"]
    assert restored == ["wlan1"]
    assert not list(runtime.glob("restore-*.json"))


def test_oversized_capture_is_rejected_without_analysis_command(service):
    operations, privileged, _registry, _database = service
    operations.max_capture_bytes = 1024
    path = operations.data_dir / "captures" / "large.pcap"
    with path.open("wb") as handle:
        handle.seek(2 * 1024 * 1024)
        handle.write(b"\0")
    before = list(privileged.calls)
    assert operations.analyze_pcap(path)["valid"] is False
    assert privileged.calls == before


def test_privileged_helper_rejects_unknown_actions_paths_and_ids(tmp_path):
    state = HelperState(tmp_path / "data")
    with pytest.raises(PinePiError) as error:
        state.dispatch("run_arbitrary_command", {"command": "id"})
    assert error.value.code == "HELPER_ACTION_DENIED"
    with pytest.raises(PinePiError) as error:
        state.path(tmp_path / "outside")
    assert error.value.code == "INVALID_STORAGE_PATH"
    with pytest.raises(PinePiError) as error:
        state.operation_id("../../bad")
    assert error.value.code == "INVALID_OPERATION_ID"
