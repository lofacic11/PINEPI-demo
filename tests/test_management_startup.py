from __future__ import annotations

import signal
import subprocess
from pathlib import Path

import pytest

from pinepi.management import ManagementError, ManagementService, parse_rfkill_state


class FakeRadio:
    def __init__(
        self,
        *,
        interface_after: int = 0,
        unblock_failures: int = 0,
        link_up_failures: int = 0,
        hard_blocked: bool = False,
    ) -> None:
        self.tick = 0
        self.interface_after = interface_after
        self.unblock_failures = unblock_failures
        self.link_up_failures = link_up_failures
        self.blocks = {
            "phy0": [True, hard_blocked],
            "phy2": [True, False],
            "phy3": [True, False],
        }
        self.commands: list[tuple[str, ...]] = []
        self.processes: dict[int, str] = {}
        self.kills: list[tuple[int, int]] = []
        self.next_pid = 4100

    def interface_exists(self) -> bool:
        return self.tick >= self.interface_after

    def sleep(self, _seconds: float) -> None:
        self.tick += 1

    def process_alive(self, pid: int, expected_name: str) -> bool:
        return self.processes.get(pid) == expected_name

    def kill(self, pid: int, sig: int) -> None:
        self.kills.append((pid, sig))
        self.processes.pop(pid, None)

    def _rfkill_output(self) -> str:
        sections = []
        for index, (phy, state) in enumerate(self.blocks.items()):
            sections.append(
                f"{index}: {phy}: Wireless LAN\n"
                f"\tSoft blocked: {'yes' if state[0] else 'no'}\n"
                f"\tHard blocked: {'yes' if state[1] else 'no'}"
            )
        return "\n".join(sections) + "\n"

    @staticmethod
    def _completed(argv: list[str], code: int = 0, stdout: str = "", stderr: str = ""):
        return subprocess.CompletedProcess(argv, code, stdout, stderr)

    def __call__(self, argv: list[str], **_kwargs: object):
        command = tuple(argv)
        self.commands.append(command)

        if command == ("iw", "dev", "wlan0", "info"):
            if not self.interface_exists():
                return self._completed(argv, 1, stderr="No such device")
            mode = "AP" if "hostapd" in self.processes.values() else "managed"
            return self._completed(argv, stdout=f"Interface wlan0\n\twiphy 0\n\ttype {mode}\n")

        if command == ("rfkill", "list"):
            return self._completed(argv, stdout=self._rfkill_output())

        if command == ("rfkill", "unblock", "wifi"):
            if self.unblock_failures:
                self.unblock_failures -= 1
                return self._completed(argv, 1, stderr="temporary rfkill error")
            for state in self.blocks.values():
                if not state[1]:
                    state[0] = False
            return self._completed(argv)

        if command == ("ip", "link", "set", "dev", "wlan0", "up"):
            if self.blocks["phy0"][0] or self.blocks["phy0"][1]:
                return self._completed(
                    argv, 2, stderr="RTNETLINK answers: Operation not possible due to RF-kill"
                )
            if self.link_up_failures:
                self.link_up_failures -= 1
                return self._completed(argv, 2, stderr="device is not ready")
            return self._completed(argv)

        if argv[0] == "hostapd":
            pid = self.next_pid
            self.next_pid += 1
            self.processes[pid] = "hostapd"
            Path(argv[argv.index("-P") + 1]).write_text(str(pid), encoding="utf-8")
            return self._completed(argv)

        if argv[0] == "hostapd_cli":
            return self._completed(argv, stdout="state=ENABLED\nssid[0]=PinePi\n")

        if argv[0] == "dnsmasq":
            pid = self.next_pid
            self.next_pid += 1
            self.processes[pid] = "dnsmasq"
            pidfile = next(value.split("=", 1)[1] for value in argv if value.startswith("--pid-file="))
            Path(pidfile).write_text(str(pid), encoding="utf-8")
            return self._completed(argv)

        return self._completed(argv)


def make_service(tmp_path: Path, hardware: FakeRadio, **kwargs: object) -> ManagementService:
    return ManagementService(
        runtime_dir=tmp_path / "run",
        hostapd_config=tmp_path / "hostapd.conf",
        dnsmasq_config=tmp_path / "dnsmasq.conf",
        ready_attempts=int(kwargs.pop("ready_attempts", 6)),
        ready_interval=1,
        daemon_attempts=2,
        daemon_interval=0,
        runner=hardware,
        sleeper=hardware.sleep,
        interface_exists=hardware.interface_exists,
        process_alive=hardware.process_alive,
        killer=hardware.kill,
        **kwargs,
    )


def test_rfkill_parser_selects_only_management_phy():
    output = """0: phy0: Wireless LAN
\tSoft blocked: no
\tHard blocked: no
1: phy2: Wireless LAN
\tSoft blocked: yes
\tHard blocked: no
"""
    assert parse_rfkill_state(output, "phy0") == (False, False)
    assert parse_rfkill_state(output, "phy2") == (True, False)
    assert parse_rfkill_state(output, "phy9") is None


def test_already_unblocked_boot_still_verifies_before_link_up(tmp_path):
    hardware = FakeRadio()
    for state in hardware.blocks.values():
        state[0] = False
    service = make_service(tmp_path, hardware)

    service.start()

    unblock_index = hardware.commands.index(("rfkill", "unblock", "wifi"))
    first_link_index = hardware.commands.index(("ip", "link", "set", "dev", "wlan0", "up"))
    assert unblock_index < first_link_index
    assert list(hardware.processes.values()).count("hostapd") == 1
    assert list(hardware.processes.values()).count("dnsmasq") == 1


def test_all_wifi_soft_blocked_boot_recovers_without_configuring_external_radios(
    tmp_path, capsys
):
    hardware = FakeRadio()
    service = make_service(tmp_path, hardware)

    service.start()

    assert all(not state[0] for state in hardware.blocks.values())
    assert ("rfkill", "unblock", "wifi") in hardware.commands
    assert not any("wlan1" in command or "wlan2" in command for command in hardware.commands)
    output = capsys.readouterr().out
    assert "stage=rfkill_check interface=wlan0 phy=phy0 attempt=1 soft_blocked=true" in output
    assert "stage=rfkill_unblock" in output and "scope=all-wifi result=success" in output
    assert "stage=rfkill_verify" in output
    assert "stage=interface_up" in output
    assert "stage=hostapd_ready" in output
    assert "stage=dnsmasq_ready" in output
    assert "stage=management_ready" in output


def test_failed_unblock_is_retried_and_then_recovers(tmp_path, capsys):
    hardware = FakeRadio(unblock_failures=1)
    service = make_service(tmp_path, hardware)

    service.start()

    assert hardware.commands.count(("rfkill", "unblock", "wifi")) == 2
    output = capsys.readouterr().out
    assert "stage=rfkill_unblock" in output
    assert "result=retry" in output
    assert "stage=management_ready" in output


def test_delayed_interface_appearance_is_bounded_and_recovers(tmp_path):
    hardware = FakeRadio(interface_after=2)
    service = make_service(tmp_path, hardware, ready_attempts=5)

    service.start()

    assert hardware.tick >= 2
    assert hardware.commands[0] == ("iw", "dev", "wlan0", "info")


def test_transient_link_up_failure_is_retried(tmp_path):
    hardware = FakeRadio(link_up_failures=1)
    service = make_service(tmp_path, hardware)

    service.start()

    link_up = ("ip", "link", "set", "dev", "wlan0", "up")
    # Two readiness attempts plus the post-address-configuration link-up.
    assert hardware.commands.count(link_up) == 3


def test_new_service_attempt_recovers_after_transient_boot_failure(tmp_path):
    hardware = FakeRadio(unblock_failures=2)
    first_attempt = make_service(tmp_path, hardware, ready_attempts=2)

    with pytest.raises(ManagementError, match="rfkill unblock failed"):
        first_attempt.start()

    restarted_attempt = make_service(tmp_path, hardware, ready_attempts=2)
    restarted_attempt.start()

    assert list(hardware.processes.values()).count("hostapd") == 1
    assert list(hardware.processes.values()).count("dnsmasq") == 1


def test_permanent_hard_block_times_out_with_clear_stage(tmp_path, capsys):
    hardware = FakeRadio(hard_blocked=True)
    service = make_service(tmp_path, hardware, ready_attempts=3)

    with pytest.raises(ManagementError, match="remains hard blocked"):
        service.wait_until_radio_ready()

    assert hardware.tick == 2
    output = capsys.readouterr().out
    assert "stage=rfkill_verify" in output
    assert "stage=startup_timeout" in output
    assert "attempts=3" in output


def test_startup_timeout_does_not_manipulate_unverified_interface(tmp_path):
    hardware = FakeRadio(hard_blocked=True)
    service = make_service(tmp_path, hardware, ready_attempts=2)

    with pytest.raises(ManagementError):
        service.start()

    mutating_commands = [
        command
        for command in hardware.commands
        if command[0] in {"ip", "nmcli"}
    ]
    assert mutating_commands == []
    assert hardware.kills == []


def test_repeated_start_replaces_owned_daemons_without_duplicates(tmp_path):
    hardware = FakeRadio()
    service = make_service(tmp_path, hardware)

    service.start()
    first_pids = set(hardware.processes)
    service.start()

    assert first_pids.isdisjoint(hardware.processes)
    assert {sig for _pid, sig in hardware.kills} == {signal.SIGTERM}
    assert list(hardware.processes.values()).count("hostapd") == 1
    assert list(hardware.processes.values()).count("dnsmasq") == 1
    assert sum(command[0] == "hostapd" for command in hardware.commands) == 2
    assert sum(command[0] == "dnsmasq" for command in hardware.commands) == 2


def test_boot_units_and_installer_include_recovery_contract():
    root = Path(__file__).resolve().parents[1]
    management_unit = (root / "systemd" / "pinepi-management.service").read_text(
        encoding="utf-8"
    )
    web_unit = (root / "systemd" / "pinepi.service").read_text(encoding="utf-8")
    installer = (root / "scripts" / "install.sh").read_text(encoding="utf-8")
    wrapper = (root / "scripts" / "pinepi-management").read_text(encoding="utf-8")

    assert "After=systemd-rfkill.service NetworkManager.service" in management_unit
    assert "Wants=systemd-rfkill.service NetworkManager.service" in management_unit
    assert "Restart=on-failure" in management_unit
    assert "RestartSec=3" in management_unit
    assert "StartLimitIntervalSec=300" in management_unit
    assert "StartLimitBurst=3" in management_unit
    assert "Wants=pinepi-management.service" in web_unit
    assert "Requires=pinepi-management.service" not in web_unit
    assert " rfkill " in installer
    assert "if [[ ! -e /etc/pinepi/management-hostapd.conf ]]" in installer
    assert "if [[ ! -e /etc/pinepi/management-dnsmasq.conf ]]" in installer
    assert "systemctl daemon-reload" in installer
    assert (
        "systemctl enable --now pinepi-management.service pinepi-helper.service pinepi.service"
        in installer
    )
    assert "-m pinepi.management" in wrapper
