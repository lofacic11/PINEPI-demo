from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import pytest

from pinepi import create_app
from pinepi.errors import PinePiError
from pinepi.exports import ExportService
from pinepi.helper import HelperState
from pinepi.operations import analyze_eapol_key_frames
from pinepi.privileged import PrivilegedService

BSSID = "AA:BB:CC:DD:EE:20"
OTHER_BSSID = "AC:BB:CC:DD:EE:20"
CLIENT_A = "02:11:22:33:44:55"
CLIENT_B = "06:66:77:88:99:AA"


def eapol(
    message: str,
    client: str = CLIENT_A,
    bssid: str = BSSID,
    replay_counter: int | None = None,
) -> dict:
    key_info = {
        "m1": "0x008a",
        "m2": "0x010a",
        "m3": "0x038a",
        "m4": "0x030a",
    }[message]
    if replay_counter is None:
        replay_counter = 2 if message in {"m3", "m4"} else 1
    from_ap = message in {"m1", "m3"}
    return {
        "bssid": bssid,
        "source": bssid if from_ap else client,
        "destination": client if from_ap else bssid,
        "key_info": key_info,
        "message_number": int(message[-1]),
        "replay_counter": str(replay_counter),
    }


def seed_target(database, *, security: str = "WPA2", with_client: bool = True) -> str:
    session_id = uuid.uuid4().hex
    stamp = datetime.now(UTC).isoformat()
    database.execute(
        "INSERT INTO recon_sessions(id,interface,mode,started_at,ended_at,status) VALUES(?,?,?,?,?,?)",
        (session_id, "wlan1", "passive", stamp, stamp, "COMPLETED"),
    )
    database.execute(
        "INSERT INTO access_points(session_id,bssid,ssid,channel,signal,security,first_seen,last_seen) "
        "VALUES(?,?,?,?,?,?,?,?)",
        (session_id, BSSID, "Authorized-Lab", 44, -35, security, stamp, stamp),
    )
    if with_client:
        database.execute(
            "INSERT INTO recon_clients(session_id,mac,bssid,signal,first_seen,last_seen) "
            "VALUES(?,?,?,?,?,?)",
            (session_id, CLIENT_A, BSSID, -42, stamp, stamp),
        )
    return session_id


def start_handshake(service, *, with_client: bool = True):
    operations, privileged, registry, database = service
    operations._watch = lambda *_args: None
    seed_target(database, with_client=with_client)
    operations.set_current_target({"bssid": BSSID})
    status = operations.start_capture("wlan2", 1, "lab_handshake", "handshake")
    return operations, privileged, registry, database, status


@pytest.mark.parametrize(
    ("frames", "expected"),
    [
        ([], "not_captured"),
        ([eapol("m1")], "partial"),
        ([eapol("m1"), eapol("m2")], "full"),
        ([eapol("m2"), eapol("m1")], "full"),
        ([eapol("m2"), eapol("m3")], "full"),
        ([eapol("m1"), eapol("m1"), eapol("m1")], "partial"),
    ],
)
def test_handshake_states_handle_duplicates_retransmissions_and_order(frames, expected):
    assert analyze_eapol_key_frames(frames, BSSID)["state"] == expected


def test_handshake_analysis_ignores_unrelated_and_malformed_frames():
    frames = [
        eapol("m1", bssid=OTHER_BSSID),
        eapol("m2", bssid=OTHER_BSSID),
        None,
        {},
        {"bssid": BSSID, "source": CLIENT_A, "destination": BSSID, "key_info": "invalid"},
        {"bssid": BSSID, "source": CLIENT_A, "destination": BSSID, "key_info": "0x0102"},
        {"bssid": BSSID, "source": CLIENT_A, "destination": CLIENT_B, "key_info": "0x010a"},
    ]

    result = analyze_eapol_key_frames(frames, BSSID)

    assert result == {
        "state": "not_captured", "client_mac": None, "clients": [],
        "unique_message_count": 0,
    }


def test_handshake_analysis_keeps_clients_separate_and_selects_full_client():
    result = analyze_eapol_key_frames(
        [eapol("m1", CLIENT_A), eapol("m3", CLIENT_B), eapol("m2", CLIENT_B)],
        BSSID,
    )

    assert result["state"] == "full"
    assert result["client_mac"] == CLIENT_B
    assert result["clients"] == [
        {"mac": CLIENT_B, "state": "full"},
        {"mac": CLIENT_A, "state": "partial"},
    ]


def test_handshake_analysis_does_not_combine_different_replay_exchanges():
    result = analyze_eapol_key_frames(
        [eapol("m1", replay_counter=1), eapol("m2", replay_counter=9)],
        BSSID,
    )

    assert result["state"] == "partial"


def test_handshake_capture_lifecycle_reserves_tunes_persists_and_restores(service):
    operations, privileged, registry, database, status = start_handshake(service)
    capture_id = status["capture_id"]
    row = database.fetchone("SELECT * FROM captures WHERE id=?", (capture_id,))

    assert status["capture_mode"] == "handshake"
    assert status["target"]["bssid"] == BSSID
    assert status["channel"] == 44
    assert status["handshake_state"] == "not_captured"
    assert status["observed_clients"][0]["mac"] == CLIENT_A
    assert registry.role("wlan2") == "capture"
    assert ("set_monitor", "wlan2", 44) in privileged.calls
    assert any(call[:2] == ("start_capture", "wlan2") and call[-2:] == (44, BSSID) for call in privileged.calls)
    assert row["handshake_state"] == "not_captured"
    assert row["reconnect_count"] == 0

    operations.stop_capture()

    assert registry.snapshot() == {}
    assert ("restore", "wlan2") in privileged.calls
    assert database.fetchone("SELECT status FROM captures WHERE id=?", (capture_id,))["status"] == "COMPLETED"


def test_handshake_capture_remains_passive_when_no_client_is_known(service):
    operations, _privileged, registry, _database, status = start_handshake(
        service, with_client=False,
    )

    assert status["observed_clients"] == []
    assert status["handshake_state"] == "not_captured"
    assert registry.role("wlan2") == "capture"
    operations.stop_capture()


def test_handshake_capture_stop_logs_confirmed_adapter_restoration(service):
    operations, _privileged, _registry, database, status = start_handshake(service)

    operations.stop_capture()

    event = database.fetchone(
        "SELECT context_json FROM events WHERE component='capture' AND event='adapter_restored'",
    )
    assert event is not None
    assert status["capture_id"] in event["context_json"]


def test_final_handshake_analysis_failure_cannot_skip_adapter_cleanup(service):
    operations, privileged, registry, _database, _status = start_handshake(service)

    def fail_analysis(*_args):
        raise RuntimeError("unexpected parser failure")

    privileged.capture_handshake_frames = fail_analysis

    operations.stop_capture()

    assert ("restore", "wlan2") in privileged.calls
    assert registry.snapshot() == {}


def test_live_handshake_status_progresses_monotonically_and_logs_events(service):
    operations, privileged, _registry, database, status = start_handshake(service)
    capture_id = status["capture_id"]
    privileged.handshake_frames = [eapol("m1")]
    operations._capture.handshake_checked_at = 0
    partial = operations.capture_status()
    privileged.handshake_frames = [eapol("m2"), eapol("m1"), eapol("m1")]
    operations._capture.handshake_checked_at = 0
    full = operations.capture_status()
    privileged.handshake_frames = []
    operations._capture.handshake_checked_at = 0
    still_full = operations.capture_status()

    assert partial["handshake_state"] == "partial"
    assert full["handshake_state"] == "full"
    assert full["handshake_client_mac"] == CLIENT_A
    assert still_full["handshake_state"] == "full"
    assert database.fetchone("SELECT handshake_state FROM captures WHERE id=?", (capture_id,))["handshake_state"] == "full"
    events = {row["event"] for row in database.fetchall("SELECT event FROM events WHERE component='capture'")}
    assert {"handshake_capture_started", "client_detected", "partial_handshake_detected", "full_handshake_detected"} <= events
    operations.stop_capture()


def test_capture_summary_exports_handshake_metadata(service):
    operations, privileged, _registry, database, status = start_handshake(service)
    privileged.handshake_frames = [eapol("m1"), eapol("m2")]
    operations._capture.handshake_checked_at = 0
    operations.capture_status()
    operations.stop_capture()

    payload, _name, _mimetype = ExportService(
        database, operations.events, operations,
    ).capture_summary(status["capture_id"])
    capture = json.loads(payload)["capture"]

    assert capture["handshake_state"] == "full"
    assert capture["handshake_client_mac"] == CLIENT_A
    assert capture["target_bssid"] == BSSID
    assert "path" not in capture


def test_full_handshake_client_does_not_switch_to_later_partial_client(service):
    operations, privileged, _registry, _database, _status = start_handshake(service)
    privileged.handshake_frames = [eapol("m1", CLIENT_A), eapol("m2", CLIENT_A)]
    operations._capture.handshake_checked_at = 0
    assert operations.capture_status()["handshake_client_mac"] == CLIENT_A

    privileged.handshake_frames = [eapol("m1", CLIENT_B)]
    operations._capture.handshake_checked_at = 0
    status = operations.capture_status()

    assert status["handshake_state"] == "full"
    assert status["handshake_client_mac"] == CLIENT_A
    operations.stop_capture()


def test_unexpected_handshake_capture_exit_cleans_up(service, monkeypatch):
    operations, _privileged, registry, database, status = start_handshake(service)
    operations._capture.process.running = False
    monkeypatch.setattr("pinepi.operations.time.sleep", lambda _seconds: None)

    operations._watch_loop("capture", status["capture_id"])

    assert operations.capture_status()["active"] is False
    assert registry.snapshot() == {}
    row = database.fetchone("SELECT status,stop_reason FROM captures WHERE id=?", (status["capture_id"],))
    assert row == {"status": "ERROR", "stop_reason": "process_exit"}


def test_handshake_capture_rejects_duplicate_conflict_missing_and_wlan0(service):
    operations, _privileged, registry, database, _status = start_handshake(service)
    with pytest.raises(PinePiError) as duplicate:
        operations.start_capture("wlan1", 44, "second", "handshake")
    assert duplicate.value.code == "OPERATION_ACTIVE"
    operations.stop_capture()

    operations.start_ap({"interface": "wlan2", "ssid": "Owned", "channel": 6, "security": "open", "forwarding": False})
    with pytest.raises(PinePiError) as conflict:
        operations.start_capture("wlan2", 44, "busy", "handshake")
    assert conflict.value.code == "ADAPTER_BUSY"
    operations.stop_ap()
    with pytest.raises(PinePiError) as missing:
        operations.start_capture("wlan9", 44, "missing", "handshake")
    with pytest.raises(PinePiError) as management:
        operations.start_capture("wlan0", 44, "management", "handshake")
    assert missing.value.code == "ADAPTER_NOT_FOUND"
    assert management.value.code == "MANAGEMENT_INTERFACE_RESERVED"
    assert registry.snapshot() == {}
    assert database.fetchone("SELECT COUNT(*) AS count FROM captures")["count"] >= 1


def test_reconnect_is_bounded_client_specific_and_capture_keeps_running(service):
    operations, privileged, registry, database, status = start_handshake(service)

    result = operations.request_capture_reconnect(status["capture_id"], {
        "bssid": BSSID, "channel": 44, "client_mac": CLIENT_A,
        "count": 3, "duration_seconds": 10,
    })

    assert result["bounded"] is True
    assert result["capture_active"] is True
    assert operations._capture.process.alive() is True
    assert registry.role("wlan2") == "capture"
    assert ("capture_reconnect", "wlan2", status["capture_id"], BSSID, 44, CLIENT_A, 3, 10) in privileged.calls
    row = database.fetchone(
        "SELECT reconnect_count,last_reconnect_client,last_reconnect_at FROM captures WHERE id=?",
        (status["capture_id"],),
    )
    assert row["reconnect_count"] == 1
    assert row["last_reconnect_client"] == CLIENT_A
    assert row["last_reconnect_at"]
    operations.stop_capture()
    assert registry.snapshot() == {}


@pytest.mark.parametrize(
    ("changes", "code"),
    [
        ({"client_mac": "not-a-mac"}, "INVALID_CLIENT_MAC"),
        ({"client_mac": CLIENT_B}, "CLIENT_NOT_OBSERVED"),
        ({"bssid": OTHER_BSSID}, "CAPTURE_TARGET_MISMATCH"),
        ({"channel": 0}, "INVALID_CHANNEL"),
        ({"channel": 44.0}, "INVALID_CHANNEL"),
        ({"count": 0}, "DEAUTH_LIMIT_EXCEEDED"),
        ({"count": 4}, "DEAUTH_LIMIT_EXCEEDED"),
        ({"count": 1.5}, "DEAUTH_LIMIT_EXCEEDED"),
        ({"duration_seconds": 16}, "DEAUTH_LIMIT_EXCEEDED"),
    ],
)
def test_reconnect_rejects_invalid_or_excessive_requests(service, changes, code):
    operations, _privileged, _registry, _database, status = start_handshake(service)
    payload = {
        "bssid": BSSID, "channel": 44, "client_mac": CLIENT_A,
        "count": 3, "duration_seconds": 10, **changes,
    }

    with pytest.raises(PinePiError) as error:
        operations.request_capture_reconnect(status["capture_id"], payload)

    assert error.value.code == code
    assert operations._capture.process.alive() is True
    operations.stop_capture()


def test_reconnect_requires_handshake_capture_and_failure_does_not_stop_it(service):
    operations, privileged, registry, _database = service
    operations._watch = lambda *_args: None
    raw = operations.start_capture("wlan2", 6, "raw", "raw")
    with pytest.raises(PinePiError) as wrong_mode:
        operations.request_capture_reconnect(raw["capture_id"], {"client_mac": CLIENT_A})
    assert wrong_mode.value.code == "HANDSHAKE_CAPTURE_REQUIRED"
    operations.stop_capture()

    operations, privileged, registry, _database, status = start_handshake(service)
    privileged.fail_reconnect = True
    with pytest.raises(PinePiError) as failed:
        operations.request_capture_reconnect(status["capture_id"], {"client_mac": CLIENT_A})
    assert failed.value.code == "DEAUTH_FAILED"
    assert operations._capture.process.alive() is True
    assert registry.role("wlan2") == "capture"
    operations.stop_capture()

    with pytest.raises(PinePiError) as idle:
        operations.request_capture_reconnect(status["capture_id"], {"client_mac": CLIENT_A})
    assert idle.value.code == "HANDSHAKE_CAPTURE_NOT_ACTIVE"


def test_helper_revalidates_live_capture_identity_and_limits(tmp_path):
    state = HelperState(tmp_path / "data")
    operation_id = "a" * 32
    process = SimpleNamespace(alive=lambda: True)
    state.processes[operation_id] = process
    state.captures[operation_id] = {
        "interface": "wlan2", "channel": 44, "target_bssid": BSSID,
        "path": str(state.data_dir / "captures" / f"{operation_id}_test.pcapng"),
    }
    calls = []
    state.privileged.capture_reconnect = lambda *args: calls.append(args) or {"bounded": True}
    payload = {
        "operation_id": operation_id, "interface": "wlan2", "bssid": BSSID,
        "channel": 44, "client_mac": CLIENT_A, "count": 3, "duration_seconds": 10,
    }

    assert state.dispatch("capture_reconnect", payload)["bounded"] is True
    with pytest.raises(PinePiError) as wrong_interface:
        state.dispatch("capture_reconnect", {**payload, "interface": "wlan3"})
    with pytest.raises(PinePiError) as unbounded:
        state.dispatch("capture_reconnect", {**payload, "count": 4})

    assert wrong_interface.value.code == "HANDSHAKE_CAPTURE_NOT_ACTIVE"
    assert unbounded.value.code == "DEAUTH_LIMIT_EXCEEDED"
    assert calls == [("wlan2", operation_id, BSSID, 44, CLIENT_A, 3, 10)]


def test_privileged_reconnect_uses_fixed_argv_and_rejects_wlan0_and_limits(tmp_path):
    calls = []

    def runner(argv, **kwargs):
        calls.append((argv, kwargs))
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    privileged = PrivilegedService(tmp_path / "runtime", runner=runner)
    result = privileged.capture_reconnect("wlan2", "a" * 32, BSSID, 44, CLIENT_A, 3, 10)

    assert result["bounded"] is True
    assert calls[0][0] == [
        "aireplay-ng", "--deauth", "3", "-a", BSSID, "-c", CLIENT_A, "wlan2",
    ]
    assert calls[0][1]["shell"] is False
    assert calls[0][1]["timeout"] == 10
    with pytest.raises(PinePiError) as management:
        privileged.capture_reconnect("wlan0", "a" * 32, BSSID, 44, CLIENT_A, 3, 10)
    with pytest.raises(PinePiError) as count:
        privileged.capture_reconnect("wlan2", "a" * 32, BSSID, 44, CLIENT_A, 4, 10)
    assert management.value.code == "MANAGEMENT_INTERFACE_RESERVED"
    assert count.value.code == "DEAUTH_LIMIT_EXCEEDED"


def test_truncated_capture_keeps_parseable_eapol_metadata(tmp_path):
    output = "\n".join(
        f"{item['bssid']}\t{item['source']}\t{item['destination']}\t"
        f"{item['message_number']}\t{item['replay_counter']}\t{item['key_info']}"
        for item in (eapol("m1"), eapol("m2"))
    )
    commands = []

    def runner(argv, **_kwargs):
        commands.append(argv)
        return SimpleNamespace(
            returncode=2, stdout=output,
            stderr="The file appears to have been cut short in the middle of a packet.",
        )

    privileged = PrivilegedService(tmp_path / "runtime", runner=runner)
    frames = privileged.capture_handshake_frames(Path(tmp_path / "capture.pcapng"), "a" * 32, BSSID)

    assert analyze_eapol_key_frames(frames, BSSID)["state"] == "full"
    assert "wlan_rsna_eapol.keydes.msgnr" in commands[0]
    assert "eapol.keydes.replay_counter" in commands[0]
    assert "wlan_rsna_eapol.keydes.key_info" in commands[0]
    assert "eapol.keydes.key_info" not in commands[0]


def test_reconnect_api_is_scoped_to_active_capture(tmp_path, service):
    operations, privileged, _registry, _database = service
    app = create_app({
        "TESTING": True,
        "DATA_DIR": tmp_path / "app",
        "DATABASE": tmp_path / "app" / "api.db",
        "PRIVILEGED_SERVICE": privileged,
        "ADAPTER_SERVICE": operations.adapters,
        "RECONCILE_ON_STARTUP": False,
        "MIN_FREE_BYTES": 1,
    })
    api_operations = app.extensions["operations"]
    api_operations._watch = lambda *_args: None
    seed_target(app.extensions["database"])
    api_operations.set_current_target({"bssid": BSSID})
    started = api_operations.start_capture("wlan2", 44, "api_handshake", "handshake")

    response = app.test_client().post(
        f"/api/captures/{started['capture_id']}/reconnect",
        json={"bssid": BSSID, "channel": 44, "client_mac": CLIENT_A},
    )

    assert response.status_code == 200
    assert response.get_json()["data"]["bounded"] is True
    assert api_operations.capture_status()["active"] is True
    api_operations.stop_capture()
