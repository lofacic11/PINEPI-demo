"""Boot-safe lifecycle management for PinePi's reserved management AP."""

from __future__ import annotations

import json
import os
import re
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Callable, Sequence


class ManagementError(RuntimeError):
    """Raised when the management access point cannot reach a safe state."""


Runner = Callable[..., subprocess.CompletedProcess[str]]


def _default_runner(argv: Sequence[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
    return subprocess.run(argv, **kwargs)  # noqa: S603 - argv is never passed to a shell


def _format_log_value(value: object) -> str:
    if isinstance(value, bool):
        return str(value).lower()
    if value is None:
        return "unknown"
    rendered = str(value)
    if not rendered or any(character.isspace() for character in rendered):
        return json.dumps(rendered)
    return rendered


def parse_wiphy(iw_output: str) -> str | None:
    """Return the rfkill PHY name corresponding to ``iw dev ... info`` output."""

    match = re.search(r"^\s*wiphy\s+(\d+)\s*$", iw_output, re.MULTILINE)
    return f"phy{match.group(1)}" if match else None


def parse_rfkill_state(output: str, phy: str) -> tuple[bool, bool] | None:
    """Return (soft_blocked, hard_blocked) for a PHY from ``rfkill list``."""

    current_phy: str | None = None
    soft: bool | None = None
    hard: bool | None = None

    for raw_line in output.splitlines():
        header = re.match(r"^\s*\d+:\s*([^:]+):", raw_line)
        if header:
            current_phy = header.group(1).strip()
            soft = None
            hard = None
            continue
        if current_phy != phy:
            continue

        field = re.match(r"^\s*(Soft|Hard) blocked:\s*(yes|no)\s*$", raw_line, re.I)
        if not field:
            continue
        blocked = field.group(2).lower() == "yes"
        if field.group(1).lower() == "soft":
            soft = blocked
        else:
            hard = blocked
        if soft is not None and hard is not None:
            return soft, hard

    return None


class ManagementService:
    """Own wlan0 and the hostapd/dnsmasq processes used by the management AP."""

    def __init__(
        self,
        *,
        interface: str = "wlan0",
        address: str = "10.42.0.1/24",
        expected_ssid: str = "PinePi",
        hostapd_config: Path = Path("/etc/pinepi/management-hostapd.conf"),
        dnsmasq_config: Path = Path("/etc/pinepi/management-dnsmasq.conf"),
        runtime_dir: Path = Path("/run/pinepi-management"),
        sys_class_net: Path = Path("/sys/class/net"),
        ready_attempts: int = 15,
        ready_interval: float = 1.0,
        daemon_attempts: int = 20,
        daemon_interval: float = 0.5,
        runner: Runner = _default_runner,
        sleeper: Callable[[float], None] = time.sleep,
        interface_exists: Callable[[], bool] | None = None,
        process_alive: Callable[[int, str], bool] | None = None,
        killer: Callable[[int, int], None] = os.kill,
    ) -> None:
        self.interface = interface
        self.address = address
        self.expected_ssid = expected_ssid
        self.hostapd_config = hostapd_config
        self.dnsmasq_config = dnsmasq_config
        self.runtime_dir = runtime_dir
        self.sys_class_net = sys_class_net
        self.ready_attempts = max(1, ready_attempts)
        self.ready_interval = max(0.0, ready_interval)
        self.daemon_attempts = max(1, daemon_attempts)
        self.daemon_interval = max(0.0, daemon_interval)
        self.runner = runner
        self.sleeper = sleeper
        self._interface_exists = interface_exists or (
            lambda: (self.sys_class_net / self.interface).exists()
        )
        self._process_alive_override = process_alive
        self.killer = killer
        self.interface_prepared = False
        self.hostapd_pidfile = self.runtime_dir / "hostapd.pid"
        self.dnsmasq_pidfile = self.runtime_dir / "dnsmasq.pid"

    def log(self, stage: str, **fields: object) -> None:
        context = " ".join(
            f"{key}={_format_log_value(value)}" for key, value in fields.items()
        )
        suffix = f" {context}" if context else ""
        print(f"pinepi-management stage={stage}{suffix}", flush=True)

    def run(self, argv: Sequence[str]) -> subprocess.CompletedProcess[str]:
        try:
            return self.runner(
                list(argv),
                check=False,
                capture_output=True,
                text=True,
                timeout=10,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            return subprocess.CompletedProcess(list(argv), 127, "", str(exc))

    @staticmethod
    def _result_detail(result: subprocess.CompletedProcess[str]) -> str:
        return (result.stderr or result.stdout or "no command output").strip()

    def require(self, argv: Sequence[str], stage: str) -> subprocess.CompletedProcess[str]:
        result = self.run(argv)
        if result.returncode != 0:
            detail = self._result_detail(result)
            self.log(stage, result="failure", command=" ".join(argv), detail=detail)
            raise ManagementError(f"{stage} failed: {detail}")
        return result

    def _process_alive(self, pid: int, expected_name: str) -> bool:
        if self._process_alive_override is not None:
            return self._process_alive_override(pid, expected_name)
        try:
            comm = Path(f"/proc/{pid}/comm").read_text(encoding="utf-8").strip()
        except (FileNotFoundError, PermissionError, OSError):
            return False
        return comm == expected_name

    @staticmethod
    def _read_pid(pidfile: Path) -> int | None:
        try:
            value = pidfile.read_text(encoding="utf-8").strip()
        except (FileNotFoundError, PermissionError, OSError):
            return None
        return int(value) if value.isdigit() and int(value) > 1 else None

    def _stop_owned_process(self, pidfile: Path, expected_name: str) -> None:
        pid = self._read_pid(pidfile)
        if pid is None or not self._process_alive(pid, expected_name):
            pidfile.unlink(missing_ok=True)
            return

        self.log("daemon_stop", daemon=expected_name, pid=pid)
        try:
            self.killer(pid, signal.SIGTERM)
        except (ProcessLookupError, PermissionError, OSError):
            pidfile.unlink(missing_ok=True)
            return

        for _ in range(20):
            if not self._process_alive(pid, expected_name):
                break
            self.sleeper(0.1)
        else:
            self.log("daemon_stop", daemon=expected_name, pid=pid, action="sigkill")
            try:
                self.killer(pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError, OSError):
                pass
        pidfile.unlink(missing_ok=True)

    def stop_daemons(self) -> None:
        self._stop_owned_process(self.dnsmasq_pidfile, "dnsmasq")
        self._stop_owned_process(self.hostapd_pidfile, "hostapd")

    def _management_phy(self) -> str | None:
        info = self.run(["iw", "dev", self.interface, "info"])
        return parse_wiphy(info.stdout) if info.returncode == 0 else None

    def _rfkill_state(self, phy: str) -> tuple[bool, bool] | None:
        result = self.run(["rfkill", "list"])
        if result.returncode != 0:
            self.log(
                "rfkill_check",
                interface=self.interface,
                phy=phy,
                result="failure",
                detail=self._result_detail(result),
            )
            return None
        return parse_rfkill_state(result.stdout, phy)

    def wait_until_radio_ready(self) -> str:
        """Wait for wlan0, clear global Wi-Fi rfkill, verify its PHY, then raise it."""

        last_reason = "interface has not appeared"
        for attempt in range(1, self.ready_attempts + 1):
            if not self._interface_exists():
                last_reason = f"{self.interface} is not present in sysfs"
                self.log(
                    "interface_wait",
                    interface=self.interface,
                    attempt=attempt,
                    limit=self.ready_attempts,
                    result="waiting",
                )
            else:
                self.log(
                    "interface_detected",
                    interface=self.interface,
                    attempt=attempt,
                    result="success",
                )
                phy = self._management_phy()
                if phy is None:
                    last_reason = f"could not resolve the PHY for {self.interface}"
                    self.log(
                        "phy_detect",
                        interface=self.interface,
                        attempt=attempt,
                        result="waiting",
                    )
                else:
                    before = self._rfkill_state(phy)
                    if before is None:
                        last_reason = f"rfkill did not report {phy}"
                        self.log(
                            "rfkill_check",
                            interface=self.interface,
                            phy=phy,
                            attempt=attempt,
                            result="retry",
                            detail=last_reason,
                        )
                    else:
                        self.log(
                            "rfkill_check",
                            interface=self.interface,
                            phy=phy,
                            attempt=attempt,
                            soft_blocked=before[0],
                            hard_blocked=before[1],
                        )
                        unblock = self.run(["rfkill", "unblock", "wifi"])
                        if unblock.returncode != 0:
                            last_reason = f"rfkill unblock failed: {self._result_detail(unblock)}"
                            self.log(
                                "rfkill_unblock",
                                interface=self.interface,
                                phy=phy,
                                attempt=attempt,
                                result="retry",
                                detail=self._result_detail(unblock),
                            )
                        else:
                            self.log(
                                "rfkill_unblock",
                                interface=self.interface,
                                phy=phy,
                                attempt=attempt,
                                scope="all-wifi",
                                result="success",
                            )
                            after = self._rfkill_state(phy)
                            if after is None:
                                last_reason = f"rfkill verification did not report {phy}"
                                self.log(
                                    "rfkill_verify",
                                    interface=self.interface,
                                    phy=phy,
                                    attempt=attempt,
                                    result="retry",
                                    detail=last_reason,
                                )
                            elif after[0] or after[1]:
                                block_type = "hard" if after[1] else "soft"
                                last_reason = f"{phy} remains {block_type} blocked"
                                self.log(
                                    "rfkill_verify",
                                    interface=self.interface,
                                    phy=phy,
                                    attempt=attempt,
                                    soft_blocked=after[0],
                                    hard_blocked=after[1],
                                    result="retry",
                                )
                            else:
                                self.log(
                                    "rfkill_verify",
                                    interface=self.interface,
                                    phy=phy,
                                    attempt=attempt,
                                    soft_blocked=False,
                                    hard_blocked=False,
                                    result="success",
                                )
                                link = self.run(["ip", "link", "set", "dev", self.interface, "up"])
                                if link.returncode == 0:
                                    self.interface_prepared = True
                                    self.log(
                                        "interface_up",
                                        interface=self.interface,
                                        phy=phy,
                                        attempt=attempt,
                                        result="success",
                                    )
                                    return phy
                                last_reason = (
                                    f"could not bring {self.interface} up: "
                                    f"{self._result_detail(link)}"
                                )
                                self.log(
                                    "link_up",
                                    interface=self.interface,
                                    phy=phy,
                                    attempt=attempt,
                                    result="retry",
                                    detail=self._result_detail(link),
                                )

            if attempt < self.ready_attempts:
                self.sleeper(self.ready_interval)

        self.log(
            "startup_timeout",
            interface=self.interface,
            attempts=self.ready_attempts,
            elapsed_seconds=(self.ready_attempts - 1) * self.ready_interval,
            reason=last_reason,
        )
        raise ManagementError(
            f"management radio was not ready after {self.ready_attempts} attempts: {last_reason}"
        )

    def configure_interface(self) -> None:
        managed = self.run(["nmcli", "device", "set", self.interface, "managed", "no"])
        if managed.returncode != 0:
            self.log(
                "network_manager",
                interface=self.interface,
                result="warning",
                detail=self._result_detail(managed),
            )

        self.require(["ip", "link", "set", "dev", self.interface, "down"], "link_down")
        self.require(["ip", "address", "flush", "dev", self.interface], "address_flush")
        self.require(
            ["ip", "address", "add", self.address, "dev", self.interface],
            "address_add",
        )
        self.require(["ip", "link", "set", "dev", self.interface, "up"], "link_up")
        self.log("interface_configured", interface=self.interface, address=self.address)

    @staticmethod
    def _status_fields(output: str) -> dict[str, str]:
        return {
            key: value
            for line in output.splitlines()
            if "=" in line
            for key, value in [line.split("=", 1)]
        }

    @staticmethod
    def _interface_mode(output: str) -> str | None:
        match = re.search(r"^\s*type\s+(\S+)\s*$", output, re.MULTILINE)
        return match.group(1) if match else None

    def start_hostapd(self) -> None:
        self.hostapd_pidfile.unlink(missing_ok=True)
        self.require(
            [
                "hostapd",
                "-B",
                "-P",
                str(self.hostapd_pidfile),
                str(self.hostapd_config),
            ],
            "hostapd_start",
        )

        last_state = "unavailable"
        last_ssid = "unavailable"
        last_mode = "unavailable"
        for attempt in range(1, self.daemon_attempts + 1):
            pid = self._read_pid(self.hostapd_pidfile)
            if pid is not None and self._process_alive(pid, "hostapd"):
                status = self.run(
                    ["hostapd_cli", "-p", "/run/hostapd", "-i", self.interface, "status"]
                )
                info = self.run(["iw", "dev", self.interface, "info"])
                fields = self._status_fields(status.stdout) if status.returncode == 0 else {}
                last_state = fields.get("state", "unavailable")
                last_ssid = fields.get("ssid[0]", fields.get("ssid", "unavailable"))
                last_mode = self._interface_mode(info.stdout) or "unavailable"
                if (
                    last_state == "ENABLED"
                    and last_ssid == self.expected_ssid
                    and last_mode.upper() == "AP"
                ):
                    self.log(
                        "hostapd_ready",
                        interface=self.interface,
                        pid=pid,
                        state=last_state,
                        ssid=last_ssid,
                        mode=last_mode,
                        attempt=attempt,
                    )
                    return
            if attempt < self.daemon_attempts:
                self.sleeper(self.daemon_interval)

        self.log(
            "hostapd_timeout",
            interface=self.interface,
            state=last_state,
            ssid=last_ssid,
            mode=last_mode,
            result="failure",
        )
        raise ManagementError("hostapd did not reach the expected AP state and SSID")

    def start_dnsmasq(self) -> None:
        self.dnsmasq_pidfile.unlink(missing_ok=True)
        self.require(
            [
                "dnsmasq",
                f"--conf-file={self.dnsmasq_config}",
                f"--pid-file={self.dnsmasq_pidfile}",
            ],
            "dnsmasq_start",
        )
        for attempt in range(1, self.daemon_attempts + 1):
            pid = self._read_pid(self.dnsmasq_pidfile)
            if pid is not None and self._process_alive(pid, "dnsmasq"):
                self.log("dnsmasq_ready", interface=self.interface, pid=pid, attempt=attempt)
                return
            if attempt < self.daemon_attempts:
                self.sleeper(self.daemon_interval)
        self.log("dnsmasq_timeout", interface=self.interface, result="failure")
        raise ManagementError("dnsmasq did not create a live owned process")

    def cleanup(self) -> None:
        self.stop_daemons()
        if self._interface_exists():
            self.run(["ip", "address", "del", self.address, "dev", self.interface])
            self.run(["nmcli", "device", "set", self.interface, "managed", "yes"])
        self.interface_prepared = False
        self.log("cleanup", interface=self.interface, result="complete")

    def start(self) -> None:
        self.runtime_dir.mkdir(parents=True, exist_ok=True)
        try:
            phy = self.wait_until_radio_ready()
            # Readiness is the gate for every startup-side state change. Once it has
            # passed, replace only daemons whose PID and executable prove ownership.
            self.stop_daemons()
            self.configure_interface()
            self.log(
                "management_ap_start",
                interface=self.interface,
                ssid=self.expected_ssid,
            )
            self.start_hostapd()
            self.start_dnsmasq()
        except Exception:
            # A readiness failure has not earned the right to touch wlan0. Cleanup
            # only stops/reverts resources after that gate has passed.
            if self.interface_prepared:
                self.cleanup()
            else:
                self.log("cleanup", interface=self.interface, result="not-required")
            raise
        self.log(
            "management_ready",
            interface=self.interface,
            phy=phy,
            address=self.address,
            ssid=self.expected_ssid,
            result="success",
        )


def service_from_environment() -> ManagementService:
    return ManagementService(
        interface=os.environ.get("PINEPI_MANAGEMENT_INTERFACE", "wlan0"),
        address=os.environ.get("PINEPI_MANAGEMENT_ADDRESS", "10.42.0.1/24"),
        expected_ssid=os.environ.get("PINEPI_MANAGEMENT_SSID", "PinePi"),
        hostapd_config=Path(
            os.environ.get("PINEPI_MANAGEMENT_HOSTAPD", "/etc/pinepi/management-hostapd.conf")
        ),
        dnsmasq_config=Path(
            os.environ.get("PINEPI_MANAGEMENT_DNSMASQ", "/etc/pinepi/management-dnsmasq.conf")
        ),
        runtime_dir=Path(
            os.environ.get("PINEPI_MANAGEMENT_RUNTIME", "/run/pinepi-management")
        ),
        sys_class_net=Path(os.environ.get("PINEPI_SYS_CLASS_NET", "/sys/class/net")),
        ready_attempts=int(os.environ.get("PINEPI_MANAGEMENT_READY_ATTEMPTS", "15")),
        ready_interval=float(os.environ.get("PINEPI_MANAGEMENT_READY_INTERVAL", "1")),
    )


def main(argv: Sequence[str] | None = None) -> int:
    arguments = list(argv if argv is not None else sys.argv[1:])
    if len(arguments) != 1 or arguments[0] not in {"start", "stop", "restart"}:
        print("Usage: pinepi-management {start|stop|restart}", file=sys.stderr)
        return 2

    service = service_from_environment()

    def terminate(signum: int, _frame: object) -> None:
        service.log("signal", signal=signum, action="cleanup")
        if service.interface_prepared or arguments[0] != "start":
            service.cleanup()
        else:
            service.log("cleanup", interface=service.interface, result="not-required")
        raise SystemExit(128 + signum)

    signal.signal(signal.SIGTERM, terminate)
    signal.signal(signal.SIGINT, terminate)

    try:
        if arguments[0] == "start":
            service.start()
        elif arguments[0] == "stop":
            service.cleanup()
        else:
            service.cleanup()
            service.start()
    except ManagementError as exc:
        service.log("fatal", operation=arguments[0], result="failure", reason=str(exc))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
