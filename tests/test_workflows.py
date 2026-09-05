from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime, timedelta

import pytest

from pinepi import create_app
from pinepi.errors import PinePiError


def now() -> str:
    return datetime.now(UTC).isoformat()


def seed_recon(database, access_points, *, started_at: str | None = None):
    session_id = uuid.uuid4().hex
    stamp = started_at or now()
    database.execute(
        "INSERT INTO recon_sessions(id,interface,mode,started_at,ended_at,status) VALUES(?,?,?,?,?,?)",
        (session_id, "wlan1", "passive", stamp, stamp, "COMPLETED"),
    )
    for item in access_points:
        database.execute(
            "INSERT INTO access_points(session_id,bssid,ssid,channel,signal,security,first_seen,last_seen) "
            "VALUES(?,?,?,?,?,?,?,?)",
            (
                session_id, item["bssid"], item.get("ssid", "Lab-WiFi"), item["channel"],
                item.get("signal", -60), item.get("security", "WPA2"),
                item.get("first_seen", stamp), item.get("last_seen", stamp),
            ),
        )
    return session_id


def test_ap_auto_band_prefers_safe_5ghz_and_has_no_data_fallback(service):
    operations, _privileged, _registry, _database = service

    recommendation = operations.ap_recommendation("wlan2", "auto")

    assert recommendation["resolved_band"] == "5"
    assert recommendation["resolved_channel"] == 36
    assert recommendation["fallback_used"] is True
    assert "no recent Recon data" in recommendation["recommendation_reason"]


def test_ap_24_auto_uses_only_1_6_11_and_strong_ap_changes_choice(service):
    operations, _privileged, _registry, database = service
    operations.adapters.ap_channels = list(range(1, 14))
    seed_recon(database, [{"bssid": "AA:BB:CC:DD:EE:01", "channel": 1, "signal": -20}])

    recommendation = operations.ap_recommendation("wlan1", "2.4")

    assert {item["channel"] for item in recommendation["candidate_scores"]} == {1, 6, 11}
    assert recommendation["resolved_channel"] == 6
    assert recommendation["channel_score"] == 0


def test_ap_5ghz_auto_avoids_strong_occupied_channel(service):
    operations, _privileged, _registry, database = service
    seed_recon(database, [{"bssid": "AA:BB:CC:DD:EE:02", "channel": 36, "signal": -18}])

    recommendation = operations.ap_recommendation("wlan2", "5")

    assert recommendation["resolved_channel"] == 40
    scores = {item["channel"]: item["score"] for item in recommendation["candidate_scores"]}
    assert scores[36] > scores[40]


def test_ap_auto_ignores_stale_recon_observations(service):
    operations, _privileged, _registry, database = service
    stale = (datetime.now(UTC) - timedelta(hours=1)).isoformat()
    seed_recon(database, [{
        "bssid": "AA:BB:CC:DD:EE:03", "channel": 36, "signal": -10,
        "last_seen": stale,
    }], started_at=stale)

    recommendation = operations.ap_recommendation("wlan2", "5")

    assert recommendation["resolved_channel"] == 36
    assert recommendation["fallback_used"] is True
    assert recommendation["recent_network_count"] == 0


def test_auto_band_falls_back_to_24_and_never_chooses_dfs(service):
    operations, _privileged, _registry, _database = service
    operations.adapters.ap_channels = [1, 6, 11, 52, 56, 100]

    recommendation = operations.ap_recommendation("wlan1", "auto")

    assert recommendation["resolved_band"] == "2.4"
    assert recommendation["resolved_channel"] in {1, 6, 11}
    assert all(item["channel"] not in {52, 56, 100} for item in recommendation["candidate_scores"])


def test_recommendation_and_manual_selection_use_adapter_valid_channels(service):
    operations, _privileged, _registry, _database = service
    operations.adapters.ap_channels = [6, 44, 48]

    recommendation = operations.ap_recommendation("wlan2", "5")
    manual = operations.resolve_ap_configuration("wlan2", "5", 48)

    assert recommendation["resolved_channel"] == 44
    assert manual["requested_channel"] == "48"
    assert manual["resolved_channel"] == 48
    with pytest.raises(PinePiError) as unsupported:
        operations.resolve_ap_configuration("wlan2", "5", 40)
    assert unsupported.value.code == "UNSUPPORTED_CHANNEL"


def test_adapter_without_5ghz_does_not_offer_or_select_it(service):
    operations, _privileged, _registry, _database = service
    operations.adapters.ap_channels = [1, 6, 11]

    automatic = operations.ap_recommendation("wlan1", "auto")

    assert automatic["available_bands"] == ["2.4"]
    assert automatic["resolved_band"] == "2.4"
    with pytest.raises(PinePiError) as unavailable:
        operations.ap_recommendation("wlan1", "5")
    assert unavailable.value.code == "BAND_UNSUPPORTED"


def test_ap_start_logs_and_stores_requested_and_resolved_values(service):
    operations, _privileged, _registry, database = service

    started = operations.start_ap({
        "interface": "wlan2", "ssid": "Auto-Lab", "band": "auto", "channel": "auto",
        "security": "open", "forwarding": False,
    })
    row = database.fetchone("SELECT * FROM ap_sessions WHERE id=?", (started["session_id"],))
    event = database.fetchone("SELECT context_json FROM events WHERE event='started' AND component='access_point'")
    operations.stop_ap()

    assert started["requested_band"] == "auto"
    assert started["resolved_band"] == "5"
    assert started["resolved_channel"] == 36
    assert row["requested_channel"] == "auto"
    assert row["resolved_channel"] == 36
    assert json.loads(event["context_json"])["resolved_channel"] == 36


def test_target_is_bssid_keyed_survives_navigation_state_and_can_be_cleared(service):
    operations, _privileged, _registry, database = service
    seed_recon(database, [
        {"bssid": "AA:BB:CC:DD:EE:10", "ssid": "Lab-WiFi", "channel": 6},
        {"bssid": "AA:BB:CC:DD:EE:11", "ssid": "Lab-WiFi", "channel": 44},
    ])

    first = operations.set_current_target({"bssid": "AA:BB:CC:DD:EE:10", "ssid": "ignored"})
    second = operations.set_current_target({"bssid": "AA:BB:CC:DD:EE:11"})

    assert first["bssid"] == "AA:BB:CC:DD:EE:10"
    assert second["bssid"] == "AA:BB:CC:DD:EE:11"
    assert second["channel"] == 44
    assert second["currently_observed"] is False
    assert operations.current_target()["bssid"] == "AA:BB:CC:DD:EE:11"
    assert operations.clear_current_target()["selected"] is False


def test_missing_target_remains_selected_and_is_marked_not_observed(service):
    operations, _privileged, _registry, database = service
    old = (datetime.now(UTC) - timedelta(hours=2)).isoformat()
    seed_recon(database, [{
        "bssid": "AA:BB:CC:DD:EE:12", "channel": 11, "last_seen": old,
    }], started_at=old)
    operations.set_current_target({"bssid": "AA:BB:CC:DD:EE:12"})

    target = operations.current_target()

    assert target["selected"] is True
    assert target["currently_observed"] is False
    assert target["last_seen_age_seconds"] >= 3600


def test_target_rejects_invalid_or_unobserved_bssid(service):
    operations, _privileged, _registry, _database = service

    with pytest.raises(PinePiError) as invalid:
        operations.set_current_target({"bssid": "not-a-bssid"})
    with pytest.raises(PinePiError) as missing:
        operations.set_current_target({"bssid": "AA:BB:CC:DD:EE:99"})

    assert invalid.value.code == "INVALID_BSSID"
    assert missing.value.code == "TARGET_NOT_OBSERVED"


def test_targeted_capture_tunes_target_channel_and_stores_metadata(service):
    operations, privileged, _registry, database = service
    seed_recon(database, [{
        "bssid": "AA:BB:CC:DD:EE:20", "ssid": "Capture-Me", "channel": 44,
        "security": "WPA3 WPA2", "signal": -35,
    }])
    operations.set_current_target({"bssid": "AA:BB:CC:DD:EE:20"})

    status = operations.start_capture("wlan2", 1, "target_capture", "targeted")
    row = database.fetchone("SELECT * FROM captures WHERE id=?", (status["capture_id"],))
    operations.stop_capture()

    assert status["channel"] == 44
    assert status["capture_mode"] == "targeted"
    assert status["target"]["bssid"] == "AA:BB:CC:DD:EE:20"
    assert ("set_monitor", "wlan2", 44) in privileged.calls
    assert row["target_ssid"] == "Capture-Me"
    assert row["target_band"] == "5"
    assert row["target_frequency"] == 5220


def test_targeted_capture_rejects_stale_target(service):
    operations, _privileged, _registry, database = service
    stale = (datetime.now(UTC) - timedelta(hours=1)).isoformat()
    seed_recon(database, [{
        "bssid": "AA:BB:CC:DD:EE:21", "channel": 6, "last_seen": stale,
    }], started_at=stale)
    operations.set_current_target({"bssid": "AA:BB:CC:DD:EE:21"})

    with pytest.raises(PinePiError) as rejected:
        operations.start_capture("wlan1", 6, "stale_target", "targeted")

    assert rejected.value.code == "TARGET_NOT_RECENT"


def test_raw_capture_remains_adapter_and_channel_driven(service):
    operations, privileged, _registry, database = service

    status = operations.start_capture("wlan1", 11, "raw_capture", "raw")
    row = database.fetchone("SELECT capture_mode,target_bssid FROM captures WHERE id=?", (status["capture_id"],))
    operations.stop_capture()

    assert ("set_monitor", "wlan1", 11) in privileged.calls
    assert row == {"capture_mode": "raw", "target_bssid": None}


@pytest.mark.parametrize(
    ("security", "assessment"),
    [("Open", "Risk"), ("WPA", "Risk"), ("WPA2", "Warning"), ("WPA3", "Good")],
)
def test_passive_audit_security_cases_have_no_active_side_effects(service, security, assessment):
    operations, privileged, _registry, database = service
    bssid = f"AA:BB:CC:DD:EE:{len(security):02X}"
    seed_recon(database, [{"bssid": bssid, "channel": 6, "security": security}])
    before = list(privileged.calls)

    report = operations.passive_audit(bssid)

    assert report["assessment"] == assessment
    assert "no frames were transmitted" in report["method"]
    assert privileged.calls == before


def test_duplicate_check_surfaces_differences_without_false_confirmation(service):
    operations, _privileged, _registry, database = service
    seed_recon(database, [
        {"bssid": "AA:BB:CC:DD:EE:30", "ssid": "Shared", "channel": 44, "security": "WPA3"},
        {"bssid": "AA:BB:CC:DD:EE:31", "ssid": "Shared", "channel": 6, "security": "Open"},
    ])

    report = operations.duplicate_check("AA:BB:CC:DD:EE:30")

    assert report["matches"][0]["assessment"] == "Potentially inconsistent AP"
    assert report["matches"][0]["guidance"].startswith("Requires verification")
    assert report["confirmed_rogue"] is False
    assert "confirmed rogue" not in json.dumps(report).lower()


def test_notes_and_bookmarks_store_update_and_remove(service):
    operations, _privileged, _registry, database = service
    seed_recon(database, [{"bssid": "AA:BB:CC:DD:EE:40", "channel": 1}])

    saved = operations.update_network_note("AA:BB:CC:DD:EE:40", {
        "bookmarked": True, "note": "Verify during lab", "label": "investigate",
    })
    updated = operations.update_network_note("AA:BB:CC:DD:EE:40", {
        "bookmarked": False, "note": "Trusted lab AP", "label": "trusted",
    })
    removed = operations.delete_network_note("AA:BB:CC:DD:EE:40")

    assert saved["bookmarked"] == 1
    assert updated["note"] == "Trusted lab AP"
    assert removed["note"] == ""
    assert database.fetchone("SELECT * FROM network_notes WHERE bssid=?", ("AA:BB:CC:DD:EE:40",)) is None


def test_minimal_monitor_uses_recon_observations_and_tracks_changes(service, monkeypatch):
    operations, privileged, _registry, _database = service
    operations.start_recon("wlan1")
    observations = [[{
        "bssid": "AA:BB:CC:DD:EE:50", "ssid": "Monitor-Me", "channel": 6,
        "signal": -60, "security": "WPA2", "first_seen": now(), "last_seen": now(),
    }], []]
    monkeypatch.setattr(operations, "_parse_airodump", lambda _prefix: (observations[0], observations[1]))
    before = list(privileged.calls)

    started = operations.start_network_monitor({"bssid": "AA:BB:CC:DD:EE:50"})
    observations[0][0] = {**observations[0][0], "channel": 11, "signal": -42}
    operations._refresh_network_monitor(*observations)
    changed = operations.network_monitor_status()
    operations.stop_recon()

    assert started["active"] is True
    assert {item["field"] for item in changed["changes"]} >= {"channel", "signal"}
    assert privileged.calls[:len(before)] == before
    assert operations.network_monitor_status()["active"] is False


def test_target_and_network_workflow_api(tmp_path, service):
    operations, privileged, _registry, _database = service
    app = create_app({
        "TESTING": True, "DATA_DIR": tmp_path / "workflow-app",
        "DATABASE": tmp_path / "workflow-app" / "api.db",
        "PRIVILEGED_SERVICE": privileged, "ADAPTER_SERVICE": operations.adapters,
        "RECONCILE_ON_STARTUP": False,
    })
    database = app.extensions["database"]
    seed_recon(database, [{
        "bssid": "AA:BB:CC:DD:EE:60", "ssid": "API-Lab", "channel": 44, "security": "WPA3",
    }])
    client = app.test_client()

    selected = client.put("/api/target", json={"bssid": "AA:BB:CC:DD:EE:60"})
    audit = client.get("/api/networks/AA:BB:CC:DD:EE:60/audit")
    note = client.put("/api/networks/AA:BB:CC:DD:EE:60/note", json={"bookmarked": True, "note": "API", "label": "lab AP"})
    recommendation = client.get("/api/access-point/recommendation?interface=wlan2&band=auto")

    assert selected.status_code == 200
    assert selected.get_json()["data"]["bssid"] == "AA:BB:CC:DD:EE:60"
    assert audit.get_json()["data"]["assessment"] == "Good"
    assert note.get_json()["data"]["bookmarked"] == 1
    assert recommendation.get_json()["data"]["resolved_band"] == "5"
    assert client.delete("/api/target").get_json()["data"]["selected"] is False
