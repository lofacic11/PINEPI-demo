from __future__ import annotations

import csv
import io
import json
import zipfile

import pytest

from pinepi import create_app
from pinepi.errors import PinePiError
from pinepi.exports import ExportService
from pinepi.operations import OperationService

MAC_A = "02:11:22:33:44:55"
MAC_B = "06:66:77:88:99:AA"


def station(
    mac: str,
    *,
    ap_rx: int,
    ap_tx: int,
    connected: int = 30,
    ip: str | None = None,
    hostname: str | None = None,
) -> dict:
    return {
        "mac": mac,
        "ap_rx_bytes": ap_rx,
        "ap_tx_bytes": ap_tx,
        "ap_rx_packets": 10,
        "ap_tx_packets": 20,
        "signal_dbm": -48,
        "inactive_ms": 12,
        "connected_seconds": connected,
        "authenticated": True,
        "authorized": True,
        "ip_address": ip,
        "hostname": hostname,
        "ip_source": "dhcp_lease" if ip else None,
        "lease_expires_at": None,
    }


def start_ap(operations, **overrides):
    data = {
        "interface": "wlan1",
        "ssid": "Client-Lab",
        "channel": 6,
        "security": "open",
        "forwarding": False,
    }
    data.update(overrides)
    return operations.start_ap(data)


def save_clients(operations):
    with operations._ap_lock:
        operations._save_ap_clients(operations._ap)


def test_client_oriented_direction_and_metadata_are_explicit(service):
    operations, privileged, _registry, database = service
    started = start_ap(operations, log_clients=False)
    privileged.stations = [station(
        MAC_A, ap_rx=205599, ap_tx=1528305, connected=73,
        ip="10.77.0.25", hostname="laptop",
    )]

    save_clients(operations)
    status = operations.ap_status()
    client = status["clients"][0]

    assert client["upload_bytes"] == 205599
    assert client["download_bytes"] == 1528305
    assert client["ap_rx_bytes"] == 205599
    assert client["ap_tx_bytes"] == 1528305
    assert client["ip_address"] == "10.77.0.25"
    assert client["hostname"] == "laptop"
    assert client["signal_dbm"] == -48
    assert client["connection_duration_seconds"] == 73
    assert client["association_state"] == "associated"
    assert client["last_seen"]
    assert status["traffic_totals"] == {"download_bytes": 1528305, "upload_bytes": 205599}
    assert database.fetchone(
        "SELECT download_bytes,upload_bytes FROM ap_clients WHERE session_id=? AND mac=?",
        (started["session_id"], MAC_A),
    ) == {"download_bytes": 1528305, "upload_bytes": 205599}
    operations.stop_ap()


def test_two_clients_accumulate_independent_deltas(service):
    operations, privileged, _registry, database = service
    started = start_ap(operations)
    privileged.stations = [
        station(MAC_A, ap_rx=100, ap_tx=1000, connected=10),
        station(MAC_B, ap_rx=200, ap_tx=2000, connected=20),
    ]
    save_clients(operations)
    privileged.stations = [
        station(MAC_A, ap_rx=150, ap_tx=1300, connected=15),
        station(MAC_B, ap_rx=210, ap_tx=2020, connected=25),
    ]
    save_clients(operations)

    rows = {
        row["mac"]: row
        for row in database.fetchall(
            "SELECT mac,download_bytes,upload_bytes FROM ap_clients WHERE session_id=?",
            (started["session_id"],),
        )
    }
    assert rows[MAC_A] == {"mac": MAC_A, "download_bytes": 1300, "upload_bytes": 150}
    assert rows[MAC_B] == {"mac": MAC_B, "download_bytes": 2020, "upload_bytes": 210}
    assert operations.ap_status()["traffic_totals"] == {
        "download_bytes": 3320,
        "upload_bytes": 360,
    }
    operations.stop_ap()


def test_packet_capture_lifecycle_does_not_change_station_accounting(service):
    operations, privileged, _registry, _database = service
    start_ap(operations, capture_traffic=True)
    privileged.stations = [station(MAC_A, ap_rx=100, ap_tx=1000, connected=10)]
    save_clients(operations)
    operations._ap.capture_path.write_bytes(b"\x0a\x0d\x0d\x0a" + (b"x" * 512))

    status = operations.ap_status()

    assert status["capture_size_bytes"] == 516
    assert status["clients"][0]["download_bytes"] == 1000
    assert status["clients"][0]["upload_bytes"] == 100
    operations.stop_ap()


def test_current_valid_ip_replaces_prior_client_mapping(service):
    operations, privileged, _registry, database = service
    started = start_ap(operations)
    privileged.stations = [station(
        MAC_A, ap_rx=10, ap_tx=20, ip="10.77.0.25", hostname="laptop-old",
    )]
    save_clients(operations)
    privileged.stations = [station(
        MAC_A, ap_rx=15, ap_tx=30, connected=35, ip="10.77.0.31", hostname="laptop-new",
    )]
    save_clients(operations)

    row = database.fetchone(
        "SELECT ip_address,hostname,ip_source FROM ap_clients WHERE session_id=? AND mac=?",
        (started["session_id"], MAC_A),
    )
    assert row == {
        "ip_address": "10.77.0.31",
        "hostname": "laptop-new",
        "ip_source": "dhcp_lease",
    }
    operations.stop_ap()


def test_reconnect_counter_reset_preserves_prior_bytes_without_underflow(service):
    operations, privileged, _registry, database = service
    started = start_ap(operations)
    privileged.stations = [station(MAC_A, ap_rx=100, ap_tx=1000, connected=60)]
    save_clients(operations)
    privileged.stations = []
    save_clients(operations)
    disconnected = database.fetchone(
        "SELECT association_state,disconnected_at FROM ap_clients WHERE session_id=? AND mac=?",
        (started["session_id"], MAC_A),
    )
    assert disconnected["association_state"] == "disconnected"
    assert disconnected["disconnected_at"]

    privileged.stations = [station(MAC_A, ap_rx=5, ap_tx=20, connected=2)]
    save_clients(operations)
    reconnected = database.fetchone(
        "SELECT association_state,association_count,download_bytes,upload_bytes "
        "FROM ap_clients WHERE session_id=? AND mac=?",
        (started["session_id"], MAC_A),
    )

    assert reconnected == {
        "association_state": "associated",
        "association_count": 2,
        "download_bytes": 1020,
        "upload_bytes": 105,
    }
    operations.stop_ap()


def test_ap_restart_creates_new_session_counter_scope(service):
    operations, privileged, _registry, database = service
    first = start_ap(operations)
    privileged.stations = [station(MAC_A, ap_rx=90, ap_tx=900, connected=50)]
    save_clients(operations)
    operations.stop_ap()

    privileged.stations = [station(MAC_A, ap_rx=3, ap_tx=30, connected=1)]
    second = start_ap(operations)
    save_clients(operations)

    assert first["session_id"] != second["session_id"]
    rows = database.fetchall(
        "SELECT session_id,download_bytes,upload_bytes FROM ap_clients WHERE mac=? ORDER BY first_seen",
        (MAC_A,),
    )
    by_session = {row["session_id"]: row for row in rows}
    assert by_session[first["session_id"]]["download_bytes"] == 900
    assert by_session[second["session_id"]]["download_bytes"] == 30
    assert by_session[second["session_id"]]["upload_bytes"] == 3
    operations.stop_ap()


def test_pinepi_restart_preserves_client_history_and_ends_runtime_state(service):
    operations, privileged, registry, database = service
    started = start_ap(operations)
    privileged.stations = [station(MAC_A, ap_rx=90, ap_tx=900, connected=50)]
    save_clients(operations)

    operations._ap.hostapd.running = False
    operations._ap.dnsmasq.running = False
    operations._ap = None
    registry.clear()
    replacement = OperationService(
        database,
        operations.events,
        operations.adapters,
        registry,
        privileged,
        operations.data_dir,
        operations.max_capture_bytes,
        operations.min_free_bytes,
        reconcile=True,
    )

    session = database.fetchone(
        "SELECT status,stop_reason FROM ap_sessions WHERE id=?", (started["session_id"],),
    )
    client = database.fetchone(
        "SELECT download_bytes,upload_bytes FROM ap_clients WHERE session_id=? AND mac=?",
        (started["session_id"], MAC_A),
    )
    assert session == {"status": "INTERRUPTED", "stop_reason": "service_restart"}
    assert client == {"download_bytes": 900, "upload_bytes": 90}
    assert replacement.ap_status()["active"] is False


def test_kick_block_and_unblock_are_scoped_and_idempotent(service):
    operations, privileged, _registry, database = service
    started = start_ap(operations)
    privileged.stations = [station(MAC_A, ap_rx=10, ap_tx=20)]
    save_clients(operations)

    kicked = operations.manage_ap_client(MAC_A.lower(), "kick")
    blocked = operations.manage_ap_client(MAC_A, "block")
    repeated = operations.manage_ap_client(MAC_A, "block")
    blocked_status = operations.ap_status()["clients"][0]
    unblocked = operations.manage_ap_client(MAC_A, "unblock")

    assert kicked["association_state"] == "disconnected"
    assert blocked == {
        "mac": MAC_A, "action": "block", "association_state": "blocked", "changed": True,
    }
    assert repeated["changed"] is False
    assert blocked_status["blocked"] is True
    assert blocked_status["association_state"] == "blocked"
    assert unblocked["association_state"] == "disconnected"
    actions = [call[-1] for call in privileged.calls if call[0] == "ap_client_action"]
    assert actions == ["kick", "block", "unblock"]
    row = database.fetchone(
        "SELECT blocked,blocked_at FROM ap_clients WHERE session_id=? AND mac=?",
        (started["session_id"], MAC_A),
    )
    assert row == {"blocked": 0, "blocked_at": None}
    operations.stop_ap()


def test_client_actions_reject_malformed_unknown_and_helper_failure(service):
    operations, privileged, _registry, database = service
    started = start_ap(operations)

    with pytest.raises(PinePiError) as malformed:
        operations.manage_ap_client("not-a-mac", "kick")
    with pytest.raises(PinePiError) as unknown:
        operations.manage_ap_client(MAC_A, "kick")
    assert malformed.value.code == "INVALID_CLIENT_MAC"
    assert unknown.value.code == "CLIENT_NOT_ASSOCIATED"

    privileged.stations = [station(MAC_A, ap_rx=10, ap_tx=20)]
    save_clients(operations)
    privileged.fail_client_action = True
    with pytest.raises(PinePiError) as failure:
        operations.manage_ap_client(MAC_A, "block")

    assert failure.value.code == "HELPER_UNAVAILABLE"
    row = database.fetchone(
        "SELECT blocked,association_state FROM ap_clients WHERE session_id=? AND mac=?",
        (started["session_id"], MAC_A),
    )
    assert row == {"blocked": 0, "association_state": "associated"}
    privileged.fail_client_action = False
    operations.stop_ap()


def test_dead_hostapd_cleanup_is_not_blocked_by_final_telemetry_failure(service, monkeypatch):
    operations, privileged, registry, database = service
    started = start_ap(operations)
    operations._ap.hostapd.running = False

    def fail_snapshot(*_args):
        raise PinePiError("AP_NOT_ACTIVE", "AP process is no longer active.", 409)

    privileged.ap_client_snapshot = fail_snapshot
    monkeypatch.setattr("pinepi.operations.time.sleep", lambda _seconds: None)

    operations._watch_loop("ap", started["session_id"])

    assert operations.ap_status()["active"] is False
    assert registry.snapshot() == {}
    row = database.fetchone(
        "SELECT status,stop_reason FROM ap_sessions WHERE id=?", (started["session_id"],),
    )
    assert row == {"status": "ERROR", "stop_reason": "process_exit"}
    assert ("restore", "wlan1") in privileged.calls


def test_ap_client_api_has_explicit_semantics_and_structured_action_errors(tmp_path, service):
    operations, privileged, _registry, _database = service
    privileged.stations = [station(
        MAC_A, ap_rx=205599, ap_tx=1528305, ip="10.77.0.25", hostname="laptop",
    )]
    app = create_app({
        "TESTING": True,
        "DATA_DIR": tmp_path / "client-api",
        "DATABASE": tmp_path / "client-api" / "api.db",
        "PRIVILEGED_SERVICE": privileged,
        "ADAPTER_SERVICE": operations.adapters,
        "RECONCILE_ON_STARTUP": False,
    })
    client = app.test_client()

    started = client.post("/api/access-point", json={
        "interface": "wlan1", "ssid": "API-Client-Lab", "channel": 6,
        "security": "open", "forwarding": False,
    })
    payload = started.get_json()["data"]
    item = payload["clients"][0]
    malformed = client.post("/api/access-point/clients/not-a-mac/kick")
    unknown = client.post(f"/api/access-point/clients/{MAC_B}/kick")
    kicked = client.post(f"/api/access-point/clients/{MAC_A}/kick")
    blocked = client.put(f"/api/access-point/clients/{MAC_A}/block")
    unblocked = client.delete(f"/api/access-point/clients/{MAC_A}/block")

    assert started.status_code == 201
    assert item["download_bytes"] == 1528305
    assert item["upload_bytes"] == 205599
    assert "rx_bytes" not in item and "tx_bytes" not in item
    assert payload["traffic_totals"] == {"download_bytes": 1528305, "upload_bytes": 205599}
    assert "AP TX / client RX" in payload["client_counter_semantics"]["download_bytes"]
    assert malformed.status_code == 400
    assert malformed.get_json()["error"]["code"] == "INVALID_CLIENT_MAC"
    assert unknown.status_code == 404
    assert unknown.get_json()["error"]["code"] == "CLIENT_NOT_ASSOCIATED"
    assert kicked.status_code == 200
    assert kicked.get_json()["data"]["action"] == "kick"
    assert blocked.get_json()["data"]["association_state"] == "blocked"
    assert unblocked.get_json()["data"]["action"] == "unblock"
    assert client.delete("/api/access-point").status_code == 200


def test_ap_export_uses_client_oriented_names_and_totals(service):
    operations, privileged, _registry, database = service
    started = start_ap(operations)
    privileged.stations = [station(
        MAC_A, ap_rx=205599, ap_tx=1528305, ip="10.77.0.25", hostname="laptop",
    )]
    save_clients(operations)
    operations.stop_ap()

    export_path, _name = ExportService(database, operations.events, operations).ap_zip(
        started["session_id"],
    )
    with zipfile.ZipFile(export_path) as archive:
        rows = list(csv.DictReader(io.StringIO(archive.read("clients.csv").decode("utf-8"))))
        metadata = json.loads(archive.read("metadata.json"))

    assert rows[0]["download_bytes"] == "1528305"
    assert rows[0]["upload_bytes"] == "205599"
    assert rows[0]["ap_rx_bytes"] == "205599"
    assert rows[0]["ap_tx_bytes"] == "1528305"
    assert "rx_bytes" not in rows[0] and "tx_bytes" not in rows[0]
    assert metadata["traffic_totals"] == {"download_bytes": 1528305, "upload_bytes": 205599}
    assert metadata["client_counter_semantics"]["scope"].startswith("Accumulated per MAC")
