from __future__ import annotations

import ipaddress
from pathlib import Path
from types import SimpleNamespace

import pytest

from pinepi.errors import PinePiError
from pinepi.privileged import OwnedProcess, PrivilegedService, parse_iw_ap_channels


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
        if argv[:6] == ["ip", "-o", "-4", "address", "show", "dev"]:
            interface = argv[-1]
            stdout = f"7: {interface}    inet 10.77.0.1/24 scope global {interface}\n"
        else:
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


def test_dnsmasq_early_exit_reports_output_and_stops_both_processes(tmp_path, monkeypatch, capsys):
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
    assert error.value.details["stage"] == "dnsmasq_start"
    assert error.value.details["interface"] == "wlan1"
    assert error.value.details["gateway_ip"] == "10.77.0.1"
    assert error.value.details["subnet"] == "10.77.0.0/24"
    assert error.value.details["dhcp_start"] == "10.77.0.10"
    assert error.value.details["dhcp_end"] == "10.77.0.200"
    assert error.value.details["listen_address"] == "10.77.0.1"
    assert error.value.details["dns_listen_addresses"] == ["10.77.0.1"]
    assert error.value.details["pid"] == 4321
    assert error.value.details["exit_code"] == 2
    assert "Address already in use" in error.value.details["stderr"]
    assert set(started) == {"1" * 32 + "-hostapd", "1" * 32 + "-dnsmasq"}
    assert set(stopped) == set(started)
    assert not (session_dir / "dnsmasq-state" / "dnsmasq.pid").exists()
    assert not (session_dir / "dnsmasq-state" / "dnsmasq.leases").exists()
    diagnostic = capsys.readouterr().out
    assert "stage=dnsmasq_start interface=wlan1" in diagnostic
    assert "listen_address=10.77.0.1 dns_listen_addresses=[\"10.77.0.1\"]" in diagnostic
    assert "pid=4321 exit_code=2 result=failure" in diagnostic


@pytest.mark.parametrize("interface", ["wlan1", "wlan2"])
def test_temporary_dnsmasq_binds_only_ap_interface_and_gateway(tmp_path, interface):
    service = PrivilegedService(tmp_path / "runtime")
    session_dir = tmp_path / interface
    session_dir.mkdir()

    config_path = service._write_dnsmasq_config(interface, session_dir)
    lines = config_path.read_text(encoding="utf-8").splitlines()

    assert f"interface={interface}" in lines
    assert "except-interface=lo" in lines
    assert "bind-interfaces" in lines
    assert "listen-address=10.77.0.1" in lines
    assert "interface=wlan0" not in lines
    assert not any(
        address in line
        for line in lines
        for address in ("127.0.0.1", "::1", "0.0.0.0")
    )
    subnet = ipaddress.ip_network("10.77.0.0/24")
    for address in ("10.77.0.1", "10.77.0.10", "10.77.0.200"):
        assert ipaddress.ip_address(address) in subnet


def test_management_and_temporary_dnsmasq_configs_are_disjoint(tmp_path):
    management = (Path(__file__).parents[1] / "config" / "management-dnsmasq.conf").read_text(
        encoding="utf-8"
    )
    service = PrivilegedService(tmp_path / "runtime")
    session_dir = tmp_path / "session"
    session_dir.mkdir()
    temporary = service._write_dnsmasq_config("wlan1", session_dir).read_text(encoding="utf-8")

    assert "interface=wlan0" in management
    assert "interface=wlan1" in temporary
    assert "except-interface=lo" in temporary
    assert "listen-address=10.77.0.1" in temporary
    assert "10.42.0.1" not in temporary

    management_listeners = {"127.0.0.1", "::1", "10.42.0.1"}
    temporary_listeners = {
        line.split("=", 1)[1]
        for line in temporary.splitlines()
        if line.startswith("listen-address=")
    }
    assert temporary_listeners == {"10.77.0.1"}
    assert management_listeners.isdisjoint(temporary_listeners)


def test_ap_gateway_is_verified_before_dnsmasq_start(tmp_path, monkeypatch):
    service, calls, spawned, _stopped = ap_service(tmp_path, monkeypatch)
    session_dir = tmp_path / "session"
    session_dir.mkdir()

    service.start_ap("wlan2", "PinePi-Test", 6, "open", None, session_dir, "2" * 32)

    address_probe = ["ip", "-o", "-4", "address", "show", "dev", "wlan2"]
    assert address_probe in calls
    assert spawned[-1][0][0] == "dnsmasq"
    assert calls.index(address_probe) > calls.index(
        ["ip", "address", "add", "10.77.0.1/24", "dev", "wlan2"]
    )


def test_missing_ap_gateway_prevents_dnsmasq_and_cleans_temporary_state(tmp_path, monkeypatch):
    service, _calls, spawned, stopped = ap_service(tmp_path, monkeypatch)
    original_runner = service._runner

    def runner(argv, **kwargs):
        result = original_runner(argv, **kwargs)
        if argv[:6] == ["ip", "-o", "-4", "address", "show", "dev"]:
            return SimpleNamespace(returncode=0, stdout="", stderr="")
        return result

    service._runner = runner
    session_dir = tmp_path / "session"
    session_dir.mkdir()

    with pytest.raises(PinePiError) as error:
        service.start_ap("wlan1", "PinePi-Test", 6, "open", None, session_dir, "3" * 32)

    assert error.value.code == "AP_ADDRESS_FAILED"
    assert error.value.details["stage"] == "address_verification"
    assert all(argv[0][0] != "dnsmasq" for argv in spawned)
    assert "3" * 32 + "-hostapd" in stopped
    assert not (session_dir / "dnsmasq-state" / "dnsmasq.leases").exists()


def test_stopping_owned_ap_dnsmasq_removes_only_temporary_pid_and_leases(tmp_path):
    class FinishedProcess:
        pid = 9876

        @staticmethod
        def poll():
            return 0

    service = PrivilegedService(tmp_path / "runtime")
    session_dir = tmp_path / "session"
    state_dir = session_dir / "dnsmasq-state"
    state_dir.mkdir(parents=True)
    config_path = session_dir / "dnsmasq.conf"
    config_path.write_text("interface=wlan1\n", encoding="utf-8")
    (state_dir / "dnsmasq.pid").write_text("9876\n", encoding="utf-8")
    (state_dir / "dnsmasq.leases").write_text("temporary lease\n", encoding="utf-8")
    process = OwnedProcess(
        FinishedProcess(),
        ("dnsmasq", "--keep-in-foreground", f"--conf-file={config_path}"),
        "4" * 32 + "-dnsmasq",
    )

    service.stop_process(process)

    assert config_path.exists()
    assert not state_dir.exists()


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


def test_wireless_capabilities_parse_modes_and_regulatory_channels(tmp_path, capsys):
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
    assert capabilities["ap_channel_state"] == "known"
    assert capabilities["raw_frequency_count"] == 4
    assert capabilities["parsed_channel_count"] == 4
    assert capabilities["regulatory_domain"] == "AT"
    diagnostic = capsys.readouterr().out
    assert "stage=capability_detection interface=wlan1 phy=phy1 ap_capable=true" in diagnostic
    assert "raw_frequency_count=4 parsed_channel_count=4" in diagnostic
    assert "filtered_ap_channels=[1,6] regulatory_domain=AT" in diagnostic


def test_real_iw_69_decimal_fixture_retains_at_ap_channels(tmp_path):
    fixture = Path(__file__).parent / "fixtures" / "iw_phy2_decimal.txt"
    phy = fixture.read_text(encoding="utf-8")

    def runner(argv, **_kwargs):
        if argv[:3] == ["iw", "dev", "wlan1"]:
            return SimpleNamespace(
                returncode=0,
                stdout="Interface wlan1\n\twiphy 2\n\ttype managed\n",
                stderr="",
            )
        if argv[:3] == ["iw", "phy", "phy2"]:
            return SimpleNamespace(returncode=0, stdout=phy, stderr="")
        if argv[:3] == ["iw", "reg", "get"]:
            return SimpleNamespace(returncode=0, stdout="country AT: DFS-ETSI\n", stderr="")
        return SimpleNamespace(returncode=1, stdout="", stderr="unexpected")

    capabilities = PrivilegedService(
        tmp_path / "runtime", runner=runner
    ).wireless_capabilities("wlan1")

    assert capabilities["ap"] is True
    assert capabilities["ap_channel_state"] == "known"
    assert capabilities["raw_frequency_count"] == 62
    assert capabilities["parsed_channel_count"] == 62
    assert capabilities["restricted_channel_count"] == 34
    assert capabilities["channel_restrictions"] == {
        "disabled": 5,
        "no_ir": 0,
        "passive_scan": 0,
        "radar": 29,
    }
    assert capabilities["channel_parse_errors"] == []
    assert capabilities["regulatory_domain"] == "AT"
    assert capabilities["ap_channels"] == [
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13,
        36, 38, 40, 42, 44, 46, 48,
        149, 151, 153, 155, 157, 159, 161, 165,
    ]


def test_second_real_iw_69_adapter_fixture_retains_channel_6():
    fixture = Path(__file__).parent / "fixtures" / "iw_phy3_decimal.txt"

    result = parse_iw_ap_channels(fixture.read_text(encoding="utf-8"))

    assert result["raw_frequency_count"] == 39
    assert result["parsed_channel_count"] == 39
    assert result["restricted_channel_count"] == 17
    assert result["channel_parse_errors"] == []
    assert result["ap_channels"] == [
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13,
        36, 40, 44, 48, 149, 153, 157, 161, 165,
    ]


def test_frequency_parser_handles_integer_decimal_6ghz_spacing_and_restrictions():
    fixture = Path(__file__).parent / "fixtures" / "iw_phy_mixed_formats.txt"

    result = parse_iw_ap_channels(fixture.read_text(encoding="utf-8"))

    assert result["raw_frequency_count"] == 8
    assert result["parsed_channel_count"] == 7
    assert result["restricted_channel_count"] == 3
    assert result["channel_restrictions"] == {
        "disabled": 1,
        "no_ir": 1,
        "passive_scan": 0,
        "radar": 1,
    }
    assert result["ap_channels"] == [1, 6, 13, 36]
    assert result["ap_channel_state"] == "known"
    assert result["channel_parse_errors"] == [
        "line 19: unrecognized frequency/channel syntax"
    ]


def test_frequency_parser_keeps_band_specific_channels_so_6ghz_is_not_exposed_as_24ghz():
    result = parse_iw_ap_channels(
        """
        * 2412.0 MHz [1] (20.0 dBm)
        * 5180 MHz [36] (20.0 dBm)
        * 5955.0 MHz [1] (20.0 dBm)
        * 5975.0 MHz [5] (20.0 dBm)
        """
    )

    assert result["ap_channels_by_band"] == {
        "2.4": [1],
        "5": [36],
        "6": [1, 5],
    }
    assert result["ap_channels"] == [1, 5, 36]


def test_ap_mode_and_channel_detection_states_are_independent(tmp_path):
    outputs = [
        "Supported interface modes:\n * managed\n * AP\n * monitor\n * 2412.0 MHz channel 1 (20.0 dBm)\n",
        "Supported interface modes:\n * managed\n * AP\n * monitor\n * 2412.0 MHz [1] (disabled)\n * 5180.0 MHz [36] (no IR)\n",
        "Supported interface modes:\n * managed\n * monitor\n * 2412.0 MHz [1] (20.0 dBm)\n",
    ]

    def capabilities_for(index):
        def runner(argv, **_kwargs):
            if argv[:3] == ["iw", "dev", "wlan1"]:
                return SimpleNamespace(
                    returncode=0,
                    stdout="Interface wlan1\n wiphy 2\n type managed\n",
                    stderr="",
                )
            if argv[:3] == ["iw", "phy", "phy2"]:
                return SimpleNamespace(returncode=0, stdout=outputs[index], stderr="")
            if argv[:3] == ["iw", "reg", "get"]:
                return SimpleNamespace(returncode=0, stdout="country AT: DFS-ETSI\n", stderr="")
            return SimpleNamespace(returncode=1, stdout="", stderr="unexpected")

        return PrivilegedService(
            tmp_path / f"runtime-{index}", runner=runner
        ).wireless_capabilities("wlan1")

    parse_failure = capabilities_for(0)
    assert parse_failure["ap"] is True
    assert parse_failure["ap_channels"] == []
    assert parse_failure["ap_channel_state"] == "unknown"

    no_usable_channels = capabilities_for(1)
    assert no_usable_channels["ap"] is True
    assert no_usable_channels["ap_channel_state"] == "none"

    no_ap_mode = capabilities_for(2)
    assert no_ap_mode["ap"] is False
    assert no_ap_mode["ap_channels"] == [1]
    assert no_ap_mode["ap_channel_state"] == "known"


@pytest.mark.parametrize(
    ("channel_state", "error_code", "message"),
    [
        ("unknown", "AP_CHANNELS_UNKNOWN", "Unable to determine supported AP channels."),
        (
            "none",
            "NO_AP_CHANNELS",
            "Adapter supports AP mode but no usable AP channels are available in the AT regulatory domain.",
        ),
    ],
)
def test_ap_channel_validation_reports_detection_state(
    tmp_path, channel_state, error_code, message
):
    service = PrivilegedService(tmp_path / f"runtime-{channel_state}")
    service.wireless_capabilities = lambda _interface: {
        "known": True,
        "managed": True,
        "monitor": True,
        "ap": True,
        "ap_channels": [],
        "ap_channel_state": channel_state,
        "regulatory_domain": "AT",
    }

    with pytest.raises(PinePiError) as caught:
        service.validate_ap_channel("wlan1", 6)

    assert caught.value.code == error_code
    assert caught.value.message == message
