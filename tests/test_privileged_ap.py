from __future__ import annotations

from types import SimpleNamespace

import pytest

from pinepi.errors import PinePiError
from pinepi.privileged import PrivilegedService


class ProcessStub:
    def __init__(self, operation_id, running=True, output="", returncode=1):
        self.operation_id = operation_id
        self.pid = 4321
        self.running = running
        self._output = output
        self._returncode = returncode

    def alive(self):
        return self.running

    @property
    def returncode(self):
        return None if self.running else self._returncode

    def output(self):
        return self._output


def ap_service(tmp_path, monkeypatch, mode_before="managed", final_mode="AP", final_ssid="PinePi-Test", status="state=ENABLED\nssid[0]=PinePi-Test\n"):
    calls = []

    def runner(argv, **_kwargs):
        calls.append(list(argv))
        stdout = status if argv[0] == "hostapd_cli" else ""
        return SimpleNamespace(returncode=0, stdout=stdout, stderr="")

    service = PrivilegedService(tmp_path / "runtime", runner=runner)
    service.validate_ap_channel = lambda _interface, _channel: {
        "known": True, "managed": True, "monitor": True, "ap": True,
        "ap_channels": [1, 6, 11], "regulatory_domain": "AT",
    }
    service._unblock_wireless = lambda _interface, _stage: {
        "available": True, "soft_blocked": False, "hard_blocked": False,
    }
    service.networkmanager_details = lambda _interface: {"state": "disconnected", "managed": False}
    info_values = [
        {"type": mode_before, "wiphy": "1"},
        {"type": "managed", "wiphy": "1"},
        {"type": final_mode, "ssid": final_ssid, "wiphy": "1"},
    ]
    info_index = [0]

    def wireless_info(_interface):
        value = info_values[min(info_index[0], len(info_values) - 1)]
        info_index[0] += 1
        return value

    service.wireless_info = wireless_info
    spawned = []

    def spawn(argv, operation_id, **_kwargs):
        process = ProcessStub(operation_id)
        spawned.append((list(argv), process))
        return process

    service.spawn = spawn
    stopped = []

    def stop(process, _grace=3):
        if process:
            process.running = False
            stopped.append(process.operation_id)

    service.stop_process = stop
    monkeypatch.setattr("pinepi.privileged.time.sleep", lambda _seconds: None)
    return service, calls, spawned, stopped


@pytest.mark.parametrize("mode_before", ["managed", "monitor"])
def test_managed_or_monitor_adapter_transitions_to_verified_ap_then_gets_address(tmp_path, monkeypatch, mode_before):
    service, calls, _spawned, _stopped = ap_service(tmp_path, monkeypatch, mode_before=mode_before)
    session_dir = tmp_path / "session"
    session_dir.mkdir()

    hostapd, dnsmasq = service.start_ap("wlan1", "PinePi-Test", 6, "wpa2", "super-secret", session_dir, "a" * 32)

    assert hostapd.alive() and dnsmasq.alive()
    assert ["iw", "dev", "wlan1", "set", "type", "managed"] in calls
    verify_index = next(index for index, argv in enumerate(calls) if argv[0] == "hostapd_cli")
    address_index = calls.index(["ip", "address", "add", "10.77.0.1/24", "dev", "wlan1"])
    assert verify_index < address_index
    assert not (session_dir / "hostapd.conf").exists()
    assert "super-secret" not in (session_dir / "hostapd.debug.conf").read_text(encoding="utf-8")
    assert "wpa_passphrase=<redacted>" in (session_dir / "hostapd.debug.conf").read_text(encoding="utf-8")
    service.restore_interface("wlan1")
    assert calls.count(["iw", "dev", "wlan1", "set", "type", "managed"]) == 2


def test_ap_verification_timeout_is_specific_and_stops_hostapd(tmp_path, monkeypatch):
    service, _calls, _spawned, stopped = ap_service(
        tmp_path, monkeypatch, final_mode="managed", final_ssid=None,
        status="state=STARTING\nssid[0]=PinePi-Test\n",
    )
    tick = [0.0]
    monkeypatch.setattr("pinepi.privileged.time.monotonic", lambda: tick.__setitem__(0, tick[0] + 1.0) or tick[0])
    session_dir = tmp_path / "session"
    session_dir.mkdir()

    with pytest.raises(PinePiError) as error:
        service.start_ap("wlan1", "PinePi-Test", 6, "open", None, session_dir, "b" * 32)

    assert error.value.code == "AP_VERIFICATION_FAILED"
    assert error.value.message == "wlan1 remained in managed mode instead of AP mode."
    assert error.value.details["stage"] == "hostapd_verify"
    assert "b" * 32 + "-hostapd" in stopped


def test_ap_ssid_mismatch_is_detected(tmp_path, monkeypatch):
    service, _calls, _spawned, _stopped = ap_service(
        tmp_path, monkeypatch, final_mode="AP", final_ssid="Wrong",
        status="state=ENABLED\nssid[0]=Wrong\n",
    )
    tick = [0.0]
    monkeypatch.setattr("pinepi.privileged.time.monotonic", lambda: tick.__setitem__(0, tick[0] + 1.0) or tick[0])
    session_dir = tmp_path / "session"
    session_dir.mkdir()

    with pytest.raises(PinePiError) as error:
        service.start_ap("wlan1", "PinePi-Test", 6, "open", None, session_dir, "c" * 32)

    assert error.value.code == "AP_VERIFICATION_FAILED"
    assert "expected SSID" in error.value.message
    assert error.value.details["actual_ssid"] == "Wrong"


def test_hostapd_early_exit_reports_captured_reason(tmp_path, monkeypatch):
    service, _calls, _spawned, stopped = ap_service(tmp_path, monkeypatch)

    def spawn(_argv, operation_id, **_kwargs):
        return ProcessStub(operation_id, running=False, output="nl80211: Could not configure driver mode", returncode=1)

    service.spawn = spawn
    session_dir = tmp_path / "session"
    session_dir.mkdir()

    with pytest.raises(PinePiError) as error:
        service.start_ap("wlan1", "PinePi-Test", 6, "open", None, session_dir, "d" * 32)

    assert error.value.code == "HOSTAPD_START_FAILED"
    assert "Could not configure driver mode" in error.value.message
    assert error.value.details["hostapd_exit"] == 1
    assert "d" * 32 + "-hostapd" in stopped


def test_dnsmasq_early_exit_reports_output_and_stops_both_processes(tmp_path, monkeypatch):
    service, _calls, _spawned, stopped = ap_service(tmp_path, monkeypatch)
    started = []

    def spawn(_argv, operation_id, **_kwargs):
        started.append(operation_id)
        if operation_id.endswith("-dnsmasq"):
            return ProcessStub(operation_id, running=False, output="failed to bind DHCP socket: Address already in use", returncode=2)
        return ProcessStub(operation_id)

    service.spawn = spawn
    session_dir = tmp_path / "session"
    session_dir.mkdir()

    with pytest.raises(PinePiError) as error:
        service.start_ap("wlan1", "PinePi-Test", 6, "open", None, session_dir, "1" * 32)

    assert error.value.code == "DNSMASQ_START_FAILED"
    assert "Address already in use" in error.value.message
    assert error.value.details["dnsmasq_status"] == "exited"
    assert set(started) == {"1" * 32 + "-hostapd", "1" * 32 + "-dnsmasq"}
    assert set(stopped) == set(started)


def test_rfkill_failure_and_adapter_disappearance_are_specific(tmp_path, monkeypatch):
    service, _calls, _spawned, _stopped = ap_service(tmp_path, monkeypatch)
    service._unblock_wireless = lambda _interface, _stage: (_ for _ in ()).throw(
        PinePiError("RFKILL_BLOCKED", "wlan1 is rfkill blocked.", 409, {"stage": "rfkill_check"})
    )
    session_dir = tmp_path / "rfkill"
    session_dir.mkdir()
    with pytest.raises(PinePiError) as blocked:
        service.start_ap("wlan1", "PinePi-Test", 6, "open", None, session_dir, "e" * 32)
    assert blocked.value.code == "RFKILL_BLOCKED"

    service, _calls, _spawned, _stopped = ap_service(tmp_path, monkeypatch)
    infos = iter([{"type": "managed", "wiphy": "1"}, {}])
    service.wireless_info = lambda _interface: next(infos)
    session_dir = tmp_path / "missing"
    session_dir.mkdir()
    with pytest.raises(PinePiError) as missing:
        service.start_ap("wlan1", "PinePi-Test", 6, "open", None, session_dir, "f" * 32)
    assert missing.value.code == "ADAPTER_DISAPPEARED"


def test_ap_capability_and_channel_are_validated_from_nl80211_data(tmp_path):
    service = PrivilegedService(tmp_path / "runtime")
    service.wireless_capabilities = lambda _interface: {
        "known": True, "managed": True, "monitor": True, "ap": False,
        "ap_channels": [1, 6, 11], "regulatory_domain": "AT",
    }
    with pytest.raises(PinePiError) as unsupported:
        service.validate_ap_channel("wlan1", 6)
    assert unsupported.value.code == "ADAPTER_UNSUPPORTED"
    assert unsupported.value.message == "This adapter supports monitor mode but not AP mode."

    service.wireless_capabilities = lambda _interface: {
        "known": True, "managed": True, "monitor": True, "ap": True,
        "ap_channels": [1, 6, 11], "regulatory_domain": "AT",
    }
    with pytest.raises(PinePiError) as channel:
        service.validate_ap_channel("wlan1", 36)
    assert channel.value.code == "UNSUPPORTED_CHANNEL"
    assert "Channel 36 is not supported" in channel.value.message


def test_command_failure_includes_arguments_exit_code_and_stderr(tmp_path):
    def runner(_argv, **_kwargs):
        return SimpleNamespace(returncode=2, stdout="", stderr="RTNETLINK answers: Operation not possible due to RF-kill")

    service = PrivilegedService(tmp_path / "runtime", runner=runner)
    with pytest.raises(PinePiError) as error:
        service.run(
            ["ip", "link", "set", "dev", "wlan1", "up"],
            error_message="Failed to bring wlan1 up: interface may be rfkill blocked.", stage="link_up",
        )
    assert error.value.message.startswith("Failed to bring wlan1 up")
    assert error.value.details["command"] == "ip"
    assert error.value.details["arguments"][-1] == "up"
    assert error.value.details["exit_code"] == 2
    assert "RF-kill" in error.value.details["stderr"]


def test_process_spawn_failure_includes_command_and_os_error(tmp_path):
    def popen(_argv, **_kwargs):
        raise FileNotFoundError("hostapd executable was not found")

    service = PrivilegedService(tmp_path / "runtime", popen=popen)
    with pytest.raises(PinePiError) as error:
        service.spawn(["hostapd", "/tmp/test.conf"], "2" * 32 + "-hostapd", capture_output=True)
    assert error.value.code == "PROCESS_START_FAILED"
    assert error.value.details["command"] == "hostapd"
    assert error.value.details["arguments"] == ["/tmp/test.conf"]
    assert "not found" in error.value.details["stderr"]


def test_managed_monitor_managed_transition_uses_owned_interface_only(tmp_path):
    calls = []

    def runner(argv, **_kwargs):
        calls.append(list(argv))
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    service = PrivilegedService(tmp_path / "runtime", runner=runner)
    service._unblock_wireless = lambda _interface, _stage: {}
    service.wireless_info = lambda _interface: {"type": "monitor", "wiphy": "1"}
    service.set_monitor("wlan1", 6)
    service.restore_interface("wlan1")

    assert ["iw", "dev", "wlan1", "set", "type", "monitor"] in calls
    assert ["iw", "dev", "wlan1", "set", "channel", "6"] in calls
    assert calls[-5:-1] == [
        ["ip", "link", "set", "dev", "wlan1", "down"],
        ["iw", "dev", "wlan1", "set", "type", "managed"],
        ["ip", "address", "flush", "dev", "wlan1"],
        ["ip", "link", "set", "dev", "wlan1", "up"],
    ]


def test_wireless_capabilities_parse_modes_and_regulatory_channels(tmp_path):
    phy = """
Supported interface modes:
         * managed
         * AP
         * AP/VLAN
         * monitor
Band 1:
        * 2412 MHz [1] (20.0 dBm)
        * 2437 MHz [6] (20.0 dBm)
        * 2462 MHz [11] (disabled)
        * 5180 MHz [36] (20.0 dBm) (no IR)
"""

    def runner(argv, **_kwargs):
        if argv[:3] == ["iw", "dev", "wlan1"]:
            return SimpleNamespace(returncode=0, stdout="Interface wlan1\n\twiphy 1\n\ttype managed\n", stderr="")
        if argv[:3] == ["iw", "phy", "phy1"]:
            return SimpleNamespace(returncode=0, stdout=phy, stderr="")
        if argv[:3] == ["iw", "reg", "get"]:
            return SimpleNamespace(returncode=0, stdout="country AT: DFS-ETSI\n", stderr="")
        return SimpleNamespace(returncode=1, stdout="", stderr="unexpected")

    capabilities = PrivilegedService(tmp_path / "runtime", runner=runner).wireless_capabilities("wlan1")
    assert capabilities["known"] is True
    assert capabilities["managed"] is True
    assert capabilities["monitor"] is True
    assert capabilities["ap"] is True
    assert capabilities["ap_channels"] == [1, 6]
    assert capabilities["regulatory_domain"] == "AT"
