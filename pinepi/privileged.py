"""Small, validated boundary around commands that require root on Raspberry Pi OS."""

from __future__ import annotations

import json
import os
import re
import signal
import subprocess
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import BinaryIO

from .adapters import INTERFACE_PATTERN, MANAGEMENT_INTERFACE
from .errors import PinePiError


IW_FREQUENCY_PATTERN = re.compile(
    r"^\s*\*\s*(?P<frequency>\d+(?:\.\d+)?)\s*MHz\s*"
    r"\[\s*(?P<channel>\d+)\s*\](?P<details>.*)$",
    re.IGNORECASE,
)

AP_SUBNET = "10.77.0.0/24"
AP_GATEWAY_IP = "10.77.0.1"
AP_GATEWAY_CIDR = f"{AP_GATEWAY_IP}/24"
AP_DHCP_START = "10.77.0.10"
AP_DHCP_END = "10.77.0.200"
AP_NETMASK = "255.255.255.0"


def parse_iw_ap_channels(output: str) -> dict:
    """Parse AP-usable channels from integer or decimal ``iw phy`` frequencies."""

    raw_frequency_count = 0
    parsed_channel_count = 0
    usable_channels: list[int] = []
    usable_frequencies: list[tuple[float, int]] = []
    restricted_channels: list[int] = []
    restriction_counts = {"disabled": 0, "no_ir": 0, "passive_scan": 0, "radar": 0}
    errors: list[str] = []

    for line_number, raw_line in enumerate(output.splitlines(), start=1):
        if not re.search(r"\bMHz\b", raw_line, re.IGNORECASE):
            continue
        raw_frequency_count += 1
        match = IW_FREQUENCY_PATTERN.match(raw_line)
        if match is None:
            if len(errors) < 5:
                errors.append(f"line {line_number}: unrecognized frequency/channel syntax")
            continue

        parsed_channel_count += 1
        channel = int(match.group("channel"))
        frequency = float(match.group("frequency"))
        details = re.sub(r"[-_]", " ", match.group("details").lower())
        # The kernel has already applied the active regulatory domain to these
        # per-frequency flags. Avoid a second, brittle country/channel table here.
        restrictions = {
            "disabled": re.search(r"\bdisabled\b", details) is not None,
            "no_ir": re.search(r"\bno\s+ir\b", details) is not None,
            "passive_scan": re.search(r"\bpassive\s+scan(?:ning)?\b", details) is not None,
            "radar": re.search(r"\bradar(?:\s+detection)?\b", details) is not None,
        }
        for restriction, present in restrictions.items():
            if present:
                restriction_counts[restriction] += 1
        if any(restrictions.values()):
            restricted_channels.append(channel)
        else:
            usable_channels.append(channel)
            usable_frequencies.append((frequency, channel))

    channels = sorted(set(usable_channels))
    if channels:
        state = "known"
        reason = None
    elif errors:
        state = "unknown"
        reason = "Unable to parse usable frequency/channel entries from iw PHY output."
    elif parsed_channel_count:
        state = "none"
        reason = (
            "The PHY exposes frequencies, but none can currently initiate an AP "
            "under its regulatory restrictions."
        )
    else:
        state = "unknown"
        reason = "No frequency/channel entries were found in iw PHY output."

    channels_by_band = {"2.4": [], "5": [], "6": []}
    for frequency, channel in usable_frequencies:
        if 2400 <= frequency < 2500:
            channels_by_band["2.4"].append(channel)
        elif 4900 <= frequency < 5925:
            channels_by_band["5"].append(channel)
        elif 5925 <= frequency < 7125:
            channels_by_band["6"].append(channel)
    channels_by_band = {
        band: sorted(set(values)) for band, values in channels_by_band.items()
    }
    return {
        "ap_channels": channels,
        "ap_channels_by_band": channels_by_band,
        "ap_channel_frequencies": [
            {"frequency_mhz": frequency, "channel": channel}
            for frequency, channel in usable_frequencies
        ],
        "ap_channel_state": state,
        "channel_reason": reason,
        "raw_frequency_count": raw_frequency_count,
        "parsed_channel_count": parsed_channel_count,
        "restricted_channel_count": len(restricted_channels),
        "channel_restrictions": restriction_counts,
        "channel_parse_errors": errors,
    }


@dataclass
class CommandResult:
    returncode: int
    stdout: str = ""
    stderr: str = ""


@dataclass
class OwnedProcess:
    process: subprocess.Popen
    argv: tuple[str, ...]
    operation_id: str
    _output: _BoundedProcessOutput | None = field(default=None, repr=False)

    @property
    def pid(self) -> int:
        return self.process.pid

    def alive(self) -> bool:
        return self.process.poll() is None

    @property
    def returncode(self) -> int | None:
        return self.process.poll()

    def output(self) -> str:
        return self._output.text() if self._output else ""


class _BoundedProcessOutput:
    """Drain a child pipe continuously while retaining only its final bounded output."""

    def __init__(self, stream: BinaryIO, limit: int = 64 * 1024):
        self.stream = stream
        self.limit = limit
        self._data = bytearray()
        self._lock = threading.Lock()
        threading.Thread(target=self._drain, name="pinepi-process-output", daemon=True).start()

    def _drain(self) -> None:
        try:
            while True:
                chunk = self.stream.read(4096)
                if not chunk:
                    return
                if isinstance(chunk, str):
                    chunk = chunk.encode("utf-8", "replace")
                with self._lock:
                    self._data.extend(chunk)
                    if len(self._data) > self.limit:
                        del self._data[: len(self._data) - self.limit]
        except (OSError, ValueError):
            return

    def text(self) -> str:
        with self._lock:
            return bytes(self._data).decode("utf-8", "replace")


class PrivilegedService:
    def __init__(
        self,
        runtime_dir: Path,
        command_timeout: int = 15,
        runner: Callable[..., subprocess.CompletedProcess] = subprocess.run,
        popen: Callable[..., subprocess.Popen] = subprocess.Popen,
    ):
        self.runtime_dir = runtime_dir.resolve()
        self.runtime_dir.mkdir(parents=True, exist_ok=True)
        self.command_timeout = command_timeout
        self._runner = runner
        self._popen = popen

    @staticmethod
    def _interface(value: str, allow_management: bool = False) -> str:
        if not isinstance(value, str) or not INTERFACE_PATTERN.fullmatch(value):
            raise PinePiError("INVALID_INTERFACE", "Invalid interface name.")
        if value == MANAGEMENT_INTERFACE and not allow_management:
            raise PinePiError("MANAGEMENT_INTERFACE_RESERVED", "wlan0 is reserved for management.", 409)
        return value

    @staticmethod
    def _bounded_text(value: str, limit: int = 4096) -> str:
        value = value.strip()
        return value[-limit:] if len(value) > limit else value

    @staticmethod
    def _interface_from_command(argv: list[str]) -> str | None:
        for marker in ("dev", "device", "-i"):
            if marker in argv:
                index = argv.index(marker) + 1
                if index < len(argv) and INTERFACE_PATTERN.fullmatch(argv[index]):
                    return argv[index]
        return next((value for value in argv[1:] if INTERFACE_PATTERN.fullmatch(value) and value.startswith(("wl", "wlan"))), None)

    def _command_failure_message(self, argv: list[str], base: str, stderr: str) -> str:
        reason = self._last_output_line(stderr)
        lower = stderr.lower()
        interface = self._interface_from_command(argv)
        if interface and any(marker in lower for marker in ("cannot find device", "no such device", "does not exist", "not found")):
            return f"{interface} disappeared during the operation."
        if "rfkill" in lower or "rf-kill" in lower:
            return f"{base.rstrip('.')}: interface is rfkill blocked."
        return f"{base.rstrip('.')}: {reason}" if reason else base

    def run(
        self,
        argv: list[str],
        check: bool = True,
        timeout: int | None = None,
        *,
        error_code: str = "SYSTEM_COMMAND_FAILED",
        error_message: str | None = None,
        stage: str | None = None,
    ) -> CommandResult:
        try:
            result = self._runner(
                argv,
                shell=False,
                check=False,
                capture_output=True,
                text=True,
                timeout=timeout or self.command_timeout,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            if check:
                stderr = self._bounded_text(str(exc))
                details = {
                    "stage": stage,
                    "command": argv[0],
                    "arguments": argv[1:],
                    "exit_code": None,
                    "stderr": stderr,
                }
                raise PinePiError(
                    error_code,
                    self._command_failure_message(argv, error_message or f"Required system operation failed: {argv[0]}.", stderr),
                    500,
                    {key: value for key, value in details.items() if value is not None},
                ) from exc
            return CommandResult(127, "", str(exc))
        wrapped = CommandResult(result.returncode, result.stdout or "", result.stderr or "")
        if check and result.returncode != 0:
            stderr = self._bounded_text(wrapped.stderr)
            message = self._command_failure_message(argv, error_message or f"{argv[0]} failed.", stderr)
            raise PinePiError(
                error_code,
                message,
                500,
                {key: value for key, value in {
                    "stage": stage,
                    "command": argv[0],
                    "arguments": argv[1:],
                    "exit_code": result.returncode,
                    "stderr": stderr,
                }.items() if value is not None},
            )
        return wrapped

    def spawn(
        self,
        argv: list[str],
        operation_id: str,
        stdout_path: Path | None = None,
        capture_output: bool = False,
    ) -> OwnedProcess:
        stdout = subprocess.PIPE if capture_output else subprocess.DEVNULL
        file_handle = None
        if stdout_path:
            stdout_path.parent.mkdir(parents=True, exist_ok=True)
            file_handle = stdout_path.open("ab", buffering=0)
            stdout = file_handle
        try:
            try:
                process = self._popen(
                    argv,
                    shell=False,
                    stdin=subprocess.DEVNULL,
                    stdout=stdout,
                    stderr=subprocess.STDOUT,
                    start_new_session=True,
                )
            except OSError as exc:
                raise PinePiError(
                    "PROCESS_START_FAILED", f"Failed to start {argv[0]}: {exc}.", 500,
                    {
                        "stage": f"{Path(argv[0]).name}_start", "command": argv[0],
                        "arguments": argv[1:], "exit_code": None, "stderr": self._bounded_text(str(exc)),
                    },
                ) from exc
        finally:
            if file_handle:
                file_handle.close()
        output = _BoundedProcessOutput(process.stdout) if capture_output and process.stdout is not None else None
        owned = OwnedProcess(process, tuple(argv), operation_id, output)
        self._record_process(owned)
        return owned

    def _record_process(self, owned: OwnedProcess) -> None:
        state = {"pid": owned.pid, "argv": list(owned.argv), "operation_id": owned.operation_id}
        path = self.runtime_dir / f"process-{owned.operation_id}.json"
        path.write_text(json.dumps(state), encoding="utf-8")

    def forget_process(self, operation_id: str) -> None:
        (self.runtime_dir / f"process-{operation_id}.json").unlink(missing_ok=True)

    def stop_process(self, owned: OwnedProcess | None, grace: float = 3.0) -> None:
        if owned is None:
            return
        if owned.alive():
            try:
                os.killpg(owned.pid, signal.SIGTERM)
            except (OSError, AttributeError):
                owned.process.terminate()
            try:
                owned.process.wait(timeout=grace)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(owned.pid, signal.SIGKILL)
                except (OSError, AttributeError):
                    owned.process.kill()
                owned.process.wait(timeout=2)
        self.forget_process(owned.operation_id)
        if owned.operation_id.endswith("-dnsmasq"):
            config_argument = next(
                (value for value in owned.argv if value.startswith("--conf-file=")), None,
            )
            if config_argument:
                config_path = Path(config_argument.split("=", 1)[1])
                if config_path.name == "dnsmasq.conf":
                    self._clear_ap_dnsmasq_state(config_path.parent)

    def wireless_info(self, interface: str) -> dict:
        if not INTERFACE_PATTERN.fullmatch(interface):
            return {}
        result = self.run(["iw", "dev", interface, "info"], check=False)
        info: dict[str, str] = {}
        for line in result.stdout.splitlines():
            parts = line.strip().split(None, 1)
            if len(parts) == 2 and parts[0] in {"type", "ssid", "channel", "wiphy"}:
                info[parts[0]] = parts[1].split()[0] if parts[0] == "channel" else parts[1]
        return info

    def wireless_capabilities(self, interface: str) -> dict:
        def finish(capabilities: dict) -> dict:
            self._log_capability_detection(interface, capabilities)
            return capabilities

        if not INTERFACE_PATTERN.fullmatch(interface):
            return finish({
                "known": False, "managed": False, "monitor": False, "ap": False,
                "ap_channels": [], "ap_channel_state": "unknown",
                "channel_reason": "Invalid interface name.", "raw_frequency_count": 0,
                "parsed_channel_count": 0, "restricted_channel_count": 0,
                "channel_restrictions": {},
                "channel_parse_errors": ["Invalid interface name."],
                "reason": "Invalid interface name.",
            })
        info = self.wireless_info(interface)
        wiphy = info.get("wiphy")
        if wiphy is None:
            reason = "Waiting for nl80211 to expose wireless capabilities."
            return finish({
                "known": False, "managed": False, "monitor": False, "ap": False, "ap_channels": [],
                "ap_channel_state": "unknown", "channel_reason": reason,
                "raw_frequency_count": 0, "parsed_channel_count": 0,
                "restricted_channel_count": 0,
                "channel_restrictions": {}, "channel_parse_errors": [reason], "reason": reason,
            })
        result = self.run(["iw", "phy", f"phy{wiphy}", "info"], check=False)
        if result.returncode != 0:
            reason = self._bounded_text(result.stderr) or "Unable to read nl80211 capabilities."
            return finish({
                "known": False, "managed": False, "monitor": False, "ap": False, "ap_channels": [],
                "ap_channel_state": "unknown", "channel_reason": reason,
                "raw_frequency_count": 0, "parsed_channel_count": 0,
                "restricted_channel_count": 0,
                "channel_restrictions": {}, "channel_parse_errors": [reason[:240]],
                "reason": reason, "wiphy": f"phy{wiphy}",
            })
        text = result.stdout.lower()
        channel_data = parse_iw_ap_channels(result.stdout)
        capabilities = {
            "known": True,
            "managed": bool(re.search(r"^\s*\*\s+managed\s*$", text, re.MULTILINE)),
            "monitor": bool(re.search(r"^\s*\*\s+monitor\s*$", text, re.MULTILINE)),
            "ap": bool(re.search(r"^\s*\*\s+ap\s*$", text, re.MULTILINE)),
            "regulatory_domain": self.regulatory_domain(),
            "wiphy": f"phy{wiphy}",
            **channel_data,
        }
        return finish(capabilities)

    @staticmethod
    def _log_capability_detection(interface: str, capabilities: dict) -> None:
        safe_interface = interface if INTERFACE_PATTERN.fullmatch(interface) else "invalid"
        errors = [str(error)[:240] for error in (capabilities.get("channel_parse_errors") or [])[:5]]
        channels = capabilities.get("ap_channels") or []
        fields = (
            f"interface={safe_interface}",
            f"phy={capabilities.get('wiphy', 'unknown')}",
            f"ap_capable={str(bool(capabilities.get('ap'))).lower()}",
            f"raw_frequency_count={capabilities.get('raw_frequency_count', 0)}",
            f"parsed_channel_count={capabilities.get('parsed_channel_count', 0)}",
            f"filtered_ap_channels={json.dumps(channels, separators=(',', ':'))}",
            f"regulatory_domain={capabilities.get('regulatory_domain', 'unknown')}",
            f"ap_channel_state={capabilities.get('ap_channel_state', 'unknown')}",
            "channel_restrictions="
            f"{json.dumps(capabilities.get('channel_restrictions') or {}, separators=(',', ':'))}",
            f"channel_parse_errors={json.dumps(errors, separators=(',', ':'))}",
        )
        try:
            print(f"pinepi-helper stage=capability_detection {' '.join(fields)}", flush=True)
        except OSError:
            pass

    def regulatory_domain(self) -> str:
        result = self.run(["iw", "reg", "get"], check=False)
        match = re.search(r"^country\s+([A-Z0-9]{2}):", result.stdout, re.MULTILINE | re.IGNORECASE)
        return match.group(1).upper() if match else "unknown"

    def networkmanager_state(self, interface: str) -> str:
        return str(self.networkmanager_details(interface)["state"])

    def networkmanager_details(self, interface: str) -> dict:
        if not INTERFACE_PATTERN.fullmatch(interface):
            return {"state": "unknown", "managed": None}
        result = self.run(["nmcli", "-g", "GENERAL.STATE,GENERAL.NM-MANAGED", "device", "show", interface], check=False)
        if result.returncode != 0:
            fallback = self.run(["nmcli", "-g", "GENERAL.STATE", "device", "show", interface], check=False)
            if fallback.returncode != 0:
                return {"state": "unavailable", "managed": None, "error": self._bounded_text(fallback.stderr or result.stderr)}
            result = fallback
        lines = result.stdout.splitlines()
        value = lines[0].strip() if lines else ""
        match = re.match(r"\d+\s*\(([^)]+)\)", value)
        managed_value = lines[1].strip().lower() if len(lines) > 1 else ""
        state = (match.group(1) if match else value or "unknown").lower()
        managed = managed_value in {"yes", "true"} if managed_value else (False if state == "unmanaged" else None)
        return {"state": state, "managed": managed}

    def rfkill_state(self, interface: str) -> dict:
        info = self.wireless_info(interface)
        wiphy = info.get("wiphy")
        result = self.run(["rfkill", "list"], check=False)
        state = {"available": result.returncode == 0, "soft_blocked": None, "hard_blocked": None}
        if result.returncode != 0:
            state["error"] = self._bounded_text(result.stderr)
            return state
        blocks = re.split(r"(?m)(?=^\d+:\s)", result.stdout)
        target = next((block for block in blocks if wiphy and f"phy{wiphy}" in block), None)
        if target is None:
            target = next((block for block in blocks if "Wireless LAN" in block), "")
        soft = re.search(r"Soft blocked:\s*(yes|no)", target, re.IGNORECASE)
        hard = re.search(r"Hard blocked:\s*(yes|no)", target, re.IGNORECASE)
        state["soft_blocked"] = soft.group(1).lower() == "yes" if soft else None
        state["hard_blocked"] = hard.group(1).lower() == "yes" if hard else None
        return state

    def _unblock_wireless(self, interface: str, stage: str) -> dict:
        state = self.rfkill_state(interface)
        if state.get("hard_blocked"):
            raise PinePiError(
                "RFKILL_BLOCKED", f"{interface} is hardware rfkill blocked.", 409,
                {"stage": stage, "interface": interface, "rfkill_state": state},
            )
        if state.get("soft_blocked"):
            self.run(
                ["rfkill", "unblock", "wifi"], error_code="RFKILL_BLOCKED",
                error_message=f"Failed to unblock {interface}.", stage=stage,
            )
            state = self.rfkill_state(interface)
            if state.get("soft_blocked") or state.get("hard_blocked"):
                raise PinePiError(
                    "RFKILL_BLOCKED", f"{interface} is rfkill blocked.", 409,
                    {"stage": stage, "interface": interface, "rfkill_state": state},
                )
        return state

    def validate_ap_channel(self, interface: str, channel: int) -> dict:
        interface = self._interface(interface)
        capabilities = self.wireless_capabilities(interface)
        if not capabilities.get("known"):
            raise PinePiError(
                "ADAPTER_UNAVAILABLE", f"{interface} wireless capabilities are not available.", 409,
                {"stage": "capability_check", "interface": interface, "capabilities": capabilities},
            )
        if not capabilities.get("ap"):
            message = "This adapter supports monitor mode but not AP mode." if capabilities.get("monitor") else f"{interface} does not support AP mode."
            raise PinePiError(
                "ADAPTER_UNSUPPORTED", message, 409,
                {"stage": "capability_check", "interface": interface, "capabilities": capabilities},
            )
        available_channels = capabilities.get("ap_channels") or []
        channel_state = capabilities.get("ap_channel_state") or (
            "known" if available_channels else "unknown"
        )
        if channel_state == "unknown":
            raise PinePiError(
                "AP_CHANNELS_UNKNOWN",
                "Unable to determine supported AP channels.",
                409,
                {"stage": "channel_detection", "interface": interface, "capabilities": capabilities},
            )
        if channel_state == "none":
            domain = capabilities.get("regulatory_domain") or "current"
            raise PinePiError(
                "NO_AP_CHANNELS",
                "Adapter supports AP mode but no usable AP channels are available "
                f"in the {domain} regulatory domain.",
                409,
                {"stage": "channel_validation", "interface": interface, "capabilities": capabilities},
            )
        if channel not in available_channels:
            domain = capabilities.get("regulatory_domain") or "current"
            raise PinePiError(
                "UNSUPPORTED_CHANNEL",
                f"Channel {channel} is not supported by {interface} in the {domain} regulatory domain.",
                409,
                {
                    "stage": "channel_validation", "interface": interface, "channel": channel,
                    "supported_channels": available_channels, "regulatory_domain": domain,
                },
            )
        return capabilities

    def default_routes(self) -> set[str]:
        result = self.run(["ip", "route", "show", "default"], check=False)
        return set(re.findall(r"\bdev\s+([A-Za-z0-9_.:-]{1,15})\b", result.stdout))

    def set_monitor(self, interface: str, channel: int | None = None) -> None:
        interface = self._interface(interface)
        self._unblock_wireless(interface, "monitor_prepare")
        self.run(
            ["ip", "link", "set", "dev", interface, "down"],
            error_code="MONITOR_MODE_FAILED", error_message=f"Failed to bring {interface} down for monitor mode.",
            stage="monitor_link_down",
        )
        try:
            self.run(
                ["iw", "dev", interface, "set", "type", "monitor"],
                error_code="MONITOR_MODE_FAILED", error_message=f"Failed to change {interface} to monitor mode.",
                stage="monitor_mode_transition",
            )
            self.run(
                ["ip", "link", "set", "dev", interface, "up"],
                error_code="MONITOR_MODE_FAILED", error_message=f"Failed to bring {interface} up in monitor mode.",
                stage="monitor_link_up",
            )
            if channel:
                self.run(
                    ["iw", "dev", interface, "set", "channel", str(channel)],
                    error_code="MONITOR_MODE_FAILED", error_message=f"Failed to set channel {channel} on {interface}.",
                    stage="monitor_channel",
                )
            if self.wireless_info(interface).get("type") != "monitor":
                raise PinePiError(
                    "MONITOR_MODE_FAILED", f"{interface} did not enter monitor mode.", 500,
                    {"stage": "monitor_verify", "interface": interface, "expected_mode": "monitor", "actual_mode": self.wireless_info(interface).get("type")},
                )
        except Exception:
            self.restore_interface(interface)
            raise

    def restore_interface(self, interface: str) -> None:
        interface = self._interface(interface)
        commands = [
            ["ip", "link", "set", "dev", interface, "down"],
            ["iw", "dev", interface, "set", "type", "managed"],
            ["ip", "address", "flush", "dev", interface],
            ["ip", "link", "set", "dev", interface, "up"],
            ["nmcli", "device", "set", interface, "managed", "yes"],
        ]
        failures = []
        for argv in commands:
            result = self.run(argv, check=False)
            if result.returncode != 0:
                failures.append({
                    "command": argv[0], "arguments": argv[1:], "exit_code": result.returncode,
                    "stderr": self._bounded_text(result.stderr),
                })
        if failures and all(
            any(marker in item["stderr"].lower() for marker in ("cannot find device", "no such device", "does not exist", "not found"))
            for item in failures
        ):
            return
        if failures:
            raise PinePiError(
                "INTERFACE_RESTORE_FAILED", f"{interface} could not be fully restored to managed idle mode.", 500,
                {"stage": "interface_restore", "interface": interface, "failures": failures},
            )

    def start_recon(self, interface: str, prefix: Path, operation_id: str) -> OwnedProcess:
        interface = self._interface(interface)
        return self.spawn(
            ["airodump-ng", "--write", str(prefix), "--write-interval", "2", "--output-format", "csv", interface],
            operation_id,
        )

    def start_capture(self, interface: str, path: Path, max_bytes: int, operation_id: str) -> OwnedProcess:
        interface = self._interface(interface)
        max_kb = max(1, max_bytes // 1000)
        return self.spawn(
            ["dumpcap", "-q", "-i", interface, "-w", str(path), "-a", f"filesize:{max_kb}"],
            operation_id,
        )

    def start_ap(
        self, interface: str, ssid: str, channel: int, security: str, password: str | None,
        session_dir: Path, operation_id: str,
    ) -> tuple[OwnedProcess, OwnedProcess]:
        interface = self._interface(interface)
        if security not in {"open", "wpa2"}:
            raise PinePiError("INVALID_SECURITY", "Security must be open or WPA2-PSK.")
        if not isinstance(ssid, str) or not 1 <= len(ssid.encode("utf-8")) <= 32 or {"\r", "\n"} & set(ssid):
            raise PinePiError("INVALID_SSID", "SSID must be 1–32 bytes.")
        if not isinstance(channel, int) or not 1 <= channel <= 196:
            raise PinePiError("INVALID_CHANNEL", "Channel is out of range.")
        if security == "wpa2" and (
            not isinstance(password, str)
            or not 8 <= len(password.encode("utf-8")) <= 63
            or {"\r", "\n"} & set(password)
        ):
            raise PinePiError("INVALID_PASSPHRASE", "WPA2 passphrase must be 8–63 bytes.")
        return self._start_ap_lifecycle(interface, ssid, channel, security, password, session_dir, operation_id)

    def _start_ap_lifecycle(
        self, interface: str, ssid: str, channel: int, security: str, password: str | None,
        session_dir: Path, operation_id: str,
    ) -> tuple[OwnedProcess, OwnedProcess]:
        mode_before = self.wireless_info(interface).get("type")
        diagnostics: dict = {
            "interface": interface, "channel": channel, "mode_before": mode_before,
            "expected_interface": interface, "expected_mode": "AP", "expected_ssid": ssid,
            "cleanup_result": "pending",
        }
        hostapd: OwnedProcess | None = None
        dnsmasq: OwnedProcess | None = None
        hostapd_conf = session_dir / "hostapd.conf"
        try:
            diagnostics["stage"] = "capability_check"
            capabilities = self.validate_ap_channel(interface, channel)
            diagnostics["capabilities"] = capabilities
            diagnostics["regulatory_domain"] = capabilities.get("regulatory_domain")

            diagnostics["stage"] = "rfkill_check"
            diagnostics["rfkill_state"] = self._unblock_wireless(interface, "rfkill_check")

            diagnostics["stage"] = "networkmanager_release"
            diagnostics["nm_state_before"] = self.networkmanager_details(interface)
            self.run(["nmcli", "device", "disconnect", interface], check=False)
            nm_release = self.run(["nmcli", "device", "set", interface, "managed", "no"], check=False)
            diagnostics["nm_release_exit"] = nm_release.returncode
            diagnostics["nm_release_stderr"] = self._bounded_text(nm_release.stderr)
            nm_after = self.networkmanager_details(interface)
            if nm_release.returncode == 0:
                deadline = time.monotonic() + 2
                while (
                    nm_after.get("managed") is not False
                    and nm_after.get("state") not in {"unmanaged", "unavailable"}
                    and time.monotonic() < deadline
                ):
                    time.sleep(0.1)
                    nm_after = self.networkmanager_details(interface)
            diagnostics["nm_state_after"] = nm_after
            if (
                (nm_release.returncode != 0 and diagnostics["nm_state_before"].get("state") not in {"unmanaged", "unavailable"})
                or (nm_after.get("managed") is not False and nm_after.get("state") not in {"unmanaged", "unavailable"})
            ):
                raise PinePiError(
                    "NETWORKMANAGER_RELEASE_FAILED", f"NetworkManager did not release {interface} for AP mode.", 500,
                    {"stage": "networkmanager_release", "interface": interface, "nm_state_after": nm_after},
                )

            diagnostics["stage"] = "mode_transition"
            self.run(
                ["ip", "link", "set", "dev", interface, "down"],
                error_code="AP_MODE_FAILED", error_message=f"Failed to bring {interface} down for AP mode.", stage="ap_link_down",
            )
            self.run(
                ["iw", "dev", interface, "set", "type", "managed"],
                error_code="AP_MODE_FAILED", error_message=f"Failed to prepare {interface} for AP mode.", stage="ap_mode_prepare",
            )
            self.run(
                ["ip", "address", "flush", "dev", interface],
                error_code="AP_ADDRESS_FAILED", error_message=f"Failed to clear temporary addresses from {interface}.",
                stage="ap_address_cleanup",
            )
            self.run(
                ["ip", "link", "set", "dev", interface, "up"],
                error_code="AP_MODE_FAILED", error_message=f"Failed to bring {interface} up for AP mode.", stage="ap_link_up",
            )
            if not self.wireless_info(interface):
                raise PinePiError(
                    "ADAPTER_DISAPPEARED", f"{interface} disappeared during AP startup.", 409,
                    {"stage": "ap_link_up", "interface": interface},
                )

            diagnostics["stage"] = "configuration"
            control_dir = session_dir / "hostapd-control"
            control_dir.mkdir(mode=0o700, exist_ok=True)
            domain = capabilities.get("regulatory_domain")
            hostapd_lines = [
                f"interface={interface}", "driver=nl80211", f"ctrl_interface={control_dir}", f"ssid={ssid}",
                f"channel={channel}", "hw_mode=g" if channel <= 14 else "hw_mode=a",
                f"country_code={domain if domain not in {None, 'unknown', '00'} else 'AT'}", "ieee80211d=1",
            ]
            if security == "wpa2":
                hostapd_lines.extend(["wpa=2", f"wpa_passphrase={password}", "wpa_key_mgmt=WPA-PSK", "rsn_pairwise=CCMP"])
            hostapd_conf.write_text("\n".join(hostapd_lines) + "\n", encoding="utf-8")
            hostapd_conf.chmod(0o600)
            redacted = ["wpa_passphrase=<redacted>" if line.startswith("wpa_passphrase=") else line for line in hostapd_lines]
            (session_dir / "hostapd.debug.conf").write_text("\n".join(redacted) + "\n", encoding="utf-8")

            dnsmasq_conf = self._write_dnsmasq_config(interface, session_dir)

            diagnostics["stage"] = "hostapd_start"
            hostapd = self.spawn(["hostapd", str(hostapd_conf)], operation_id + "-hostapd", capture_output=True)
            deadline = time.monotonic() + 8
            status_text = ""
            actual_interface = actual_mode = actual_ssid = None
            hostapd_status: dict[str, str] = {}
            while time.monotonic() < deadline:
                if not hostapd.alive():
                    break
                status_result = self.run(["hostapd_cli", "-p", str(control_dir), "-i", interface, "status"], check=False)
                status_text = status_result.stdout
                hostapd_status = self._key_value_output(status_text)
                current = self.wireless_info(interface)
                actual_mode = current.get("type")
                actual_ssid = current.get("ssid") or hostapd_status.get("ssid[0]") or hostapd_status.get("ssid")
                actual_interface = hostapd_status.get("bss[0]") or (interface if hostapd_status else None)
                if actual_interface == interface and actual_mode and actual_mode.lower() == "ap" and hostapd_status.get("state") == "ENABLED" and actual_ssid == ssid:
                    break
                time.sleep(0.2)
            diagnostics.update({
                "stage": "hostapd_verify", "actual_interface": actual_interface,
                "mode_after": actual_mode, "actual_mode": actual_mode,
                "actual_ssid": actual_ssid, "hostapd_exit": hostapd.returncode,
                "hostapd_status": self._bounded_text(status_text), "hostapd_output": self._bounded_text(hostapd.output()),
            })
            if not (
                hostapd.alive() and actual_interface == interface and actual_mode and actual_mode.lower() == "ap"
                and hostapd_status.get("state") == "ENABLED" and actual_ssid == ssid
            ):
                raise self._hostapd_failure(interface, ssid, diagnostics)

            diagnostics["stage"] = "address_configuration"
            self.run(
                ["ip", "address", "add", AP_GATEWAY_CIDR, "dev", interface],
                error_code="AP_ADDRESS_FAILED", error_message=f"Failed to assign the AP address to {interface}.",
                stage="address_configuration",
            )
            self.run(
                ["ip", "link", "set", "dev", interface, "up"],
                error_code="AP_MODE_FAILED", error_message=f"Failed to bring {interface} up after assigning its AP address.",
                stage="address_configuration",
            )

            address_result = self.run(
                ["ip", "-o", "-4", "address", "show", "dev", interface], check=False,
            )
            address_output = self._bounded_text(address_result.stdout)
            diagnostics.update({
                "stage": "address_verification", "gateway_ip": AP_GATEWAY_IP,
                "gateway_cidr": AP_GATEWAY_CIDR, "subnet": AP_SUBNET,
                "dhcp_start": AP_DHCP_START, "dhcp_end": AP_DHCP_END,
                "listen_address": AP_GATEWAY_IP,
                "dns_listen_addresses": [AP_GATEWAY_IP],
                "address_probe_exit": address_result.returncode,
                "address_probe_output": address_output,
                "address_probe_stderr": self._bounded_text(address_result.stderr),
            })
            address_present = re.search(
                rf"\binet\s+{re.escape(AP_GATEWAY_CIDR)}(?:\s|$)", address_output,
            ) is not None
            if address_result.returncode != 0 or not address_present:
                self._log_ap_network_stage("address_verification", diagnostics, result="failure")
                raise PinePiError(
                    "AP_ADDRESS_FAILED",
                    f"The expected AP gateway address {AP_GATEWAY_CIDR} was not present on {interface}.",
                    500,
                    diagnostics,
                )
            self._log_ap_network_stage("address_verification", diagnostics, result="success")

            diagnostics.update({
                "stage": "dnsmasq_start", "pid": None, "exit_code": None,
                "stderr": "", "dnsmasq_status": "starting",
            })
            try:
                dnsmasq = self.spawn(
                    ["dnsmasq", "--keep-in-foreground", "--conf-file=" + str(dnsmasq_conf)],
                    operation_id + "-dnsmasq", capture_output=True,
                )
            except PinePiError as exc:
                stderr = self._bounded_text(str(exc.details.get("stderr") or exc.message), 1024)
                diagnostics.update({
                    "dnsmasq_status": "spawn_failed", "exit_code": exc.details.get("exit_code"),
                    "stderr": stderr, "dnsmasq_exit": exc.details.get("exit_code"),
                    "dnsmasq_output": stderr,
                })
                self._log_ap_network_stage("dnsmasq_start", diagnostics, result="failure")
                raise PinePiError(
                    "DNSMASQ_START_FAILED",
                    f"dnsmasq failed to start on {interface}: {self._last_output_line(stderr)}.",
                    500,
                    diagnostics,
                ) from exc
            diagnostics["pid"] = dnsmasq.pid
            time.sleep(0.5)
            if not dnsmasq.alive():
                stderr = self._bounded_text(dnsmasq.output(), 1024)
                diagnostics.update({
                    "dnsmasq_exit": dnsmasq.returncode, "dnsmasq_status": "exited",
                    "dnsmasq_output": stderr, "exit_code": dnsmasq.returncode,
                    "stderr": stderr,
                })
                self._log_ap_network_stage("dnsmasq_start", diagnostics, result="failure")
                reason = self._last_output_line(dnsmasq.output())
                message = f"dnsmasq failed to start on {interface}" + (f": {reason}" if reason else "")
                raise PinePiError("DNSMASQ_START_FAILED", message + ".", 500, diagnostics)
            diagnostics.update({
                "dnsmasq_status": "running", "exit_code": None,
                "stderr": self._bounded_text(dnsmasq.output(), 1024),
            })
            self._log_ap_network_stage("dnsmasq_start", diagnostics, result="success")
            hostapd_conf.unlink(missing_ok=True)
            return hostapd, dnsmasq
        except Exception as exc:
            self.stop_process(dnsmasq)
            self.stop_process(hostapd)
            self._clear_ap_dnsmasq_state(session_dir)
            if hostapd is not None:
                diagnostics["hostapd_exit"] = hostapd.returncode
                diagnostics["hostapd_output"] = self._bounded_text(hostapd.output())
            if dnsmasq is not None:
                diagnostics["dnsmasq_exit"] = dnsmasq.returncode
                diagnostics["dnsmasq_output"] = self._bounded_text(dnsmasq.output())
            hostapd_conf.unlink(missing_ok=True)
            diagnostics["cleanup_result"] = "processes_stopped; interface_restore_pending"
            if isinstance(exc, PinePiError):
                details = self._redact_value({**diagnostics, **exc.details}, password)
                message = exc.message.replace(password, "<redacted>") if password else exc.message
                raise PinePiError(exc.code, message, exc.status, details) from exc
            raise PinePiError(
                "AP_START_FAILED", f"Unexpected AP startup failure on {interface}.", 500,
                self._redact_value({**diagnostics, "error": type(exc).__name__}, password),
            ) from exc

    @classmethod
    def _redact_value(cls, value, secret: str | None):
        if not secret:
            return value
        if isinstance(value, dict):
            return {key: cls._redact_value(item, secret) for key, item in value.items()}
        if isinstance(value, list):
            return [cls._redact_value(item, secret) for item in value]
        if isinstance(value, str):
            return value.replace(secret, "<redacted>")
        return value

    def _write_dnsmasq_config(self, interface: str, session_dir: Path) -> Path:
        lease_dir = session_dir / "dnsmasq-state"
        lease_dir.mkdir(mode=0o770, exist_ok=True)
        lease_dir.chmod(0o770)
        leases = lease_dir / "dnsmasq.leases"
        leases.touch(mode=0o660, exist_ok=True)
        leases.chmod(0o660)
        try:
            import pwd

            dnsmasq_uid = pwd.getpwnam("dnsmasq").pw_uid
            os.chown(lease_dir, dnsmasq_uid, os.getgid())
            os.chown(leases, dnsmasq_uid, os.getgid())
        except (ImportError, KeyError, PermissionError):
            pass
        path = session_dir / "dnsmasq.conf"
        path.write_text(
            "\n".join([
                f"interface={interface}", "except-interface=lo", "bind-interfaces",
                f"listen-address={AP_GATEWAY_IP}",
                f"dhcp-range={AP_DHCP_START},{AP_DHCP_END},{AP_NETMASK},12h",
                f"dhcp-option=3,{AP_GATEWAY_IP}", f"dhcp-option=6,{AP_GATEWAY_IP}",
                f"dhcp-leasefile={leases}",
                f"pid-file={lease_dir / 'dnsmasq.pid'}", "log-dhcp",
            ]) + "\n", encoding="utf-8",
        )
        return path

    @staticmethod
    def _clear_ap_dnsmasq_state(session_dir: Path) -> None:
        state_dir = session_dir / "dnsmasq-state"
        for name in ("dnsmasq.pid", "dnsmasq.leases"):
            (state_dir / name).unlink(missing_ok=True)
        try:
            state_dir.rmdir()
        except FileNotFoundError:
            pass
        except OSError:
            # Keep unexpected files for diagnosis; never recursively remove session data.
            pass

    @staticmethod
    def _log_ap_network_stage(stage: str, diagnostics: dict, *, result: str) -> None:
        stderr = str(diagnostics.get("stderr") or diagnostics.get("address_probe_stderr") or "")
        fields = (
            f"interface={diagnostics.get('interface', 'unknown')}",
            f"gateway_ip={diagnostics.get('gateway_ip', AP_GATEWAY_IP)}",
            f"subnet={diagnostics.get('subnet', AP_SUBNET)}",
            f"dhcp_start={diagnostics.get('dhcp_start', AP_DHCP_START)}",
            f"dhcp_end={diagnostics.get('dhcp_end', AP_DHCP_END)}",
            f"listen_address={diagnostics.get('listen_address', AP_GATEWAY_IP)}",
            "dns_listen_addresses="
            f"{json.dumps(diagnostics.get('dns_listen_addresses') or [AP_GATEWAY_IP], separators=(',', ':'))}",
            f"pid={diagnostics.get('pid', 'none')}",
            f"exit_code={diagnostics.get('exit_code', 'none')}",
            f"result={result}",
            f"stderr={json.dumps(stderr[-1024:], separators=(',', ':'))}",
        )
        try:
            print(f"pinepi-helper stage={stage} {' '.join(fields)}", flush=True)
        except OSError:
            pass

    @staticmethod
    def _key_value_output(value: str) -> dict[str, str]:
        result: dict[str, str] = {}
        for line in value.splitlines():
            if "=" in line:
                key, item = line.split("=", 1)
                result[key.strip()] = item.strip()
        return result

    @staticmethod
    def _last_output_line(value: str) -> str:
        lines = [line.strip() for line in value.splitlines() if line.strip()]
        return lines[-1][:240] if lines else ""

    def _hostapd_failure(self, interface: str, ssid: str, diagnostics: dict) -> PinePiError:
        output = str(diagnostics.get("hostapd_output") or "")
        lower = output.lower()
        actual_interface = diagnostics.get("actual_interface")
        actual_mode = diagnostics.get("actual_mode")
        actual_ssid = diagnostics.get("actual_ssid")
        if "rfkill" in lower:
            return PinePiError("RFKILL_BLOCKED", f"{interface} is rfkill blocked.", 409, diagnostics)
        if "no such device" in lower or "does not exist" in lower:
            return PinePiError("ADAPTER_DISAPPEARED", f"{interface} disappeared during AP startup.", 409, diagnostics)
        if "channel" in lower and any(marker in lower for marker in ("not supported", "not allowed", "disabled", "could not select")):
            return PinePiError("UNSUPPORTED_CHANNEL", f"hostapd failed to start on {interface}: unsupported channel.", 409, diagnostics)
        if diagnostics.get("hostapd_exit") is not None:
            reason = self._last_output_line(output)
            message = f"hostapd failed to start on {interface}" + (f": {reason}" if reason else "")
            return PinePiError("HOSTAPD_START_FAILED", message + ".", 500, diagnostics)
        if actual_interface and actual_interface != interface:
            return PinePiError(
                "AP_VERIFICATION_FAILED",
                f"hostapd reported {actual_interface} instead of the requested interface {interface}.",
                500, diagnostics,
            )
        if not actual_mode or str(actual_mode).lower() != "ap":
            return PinePiError(
                "AP_VERIFICATION_FAILED", f"{interface} remained in {actual_mode or 'unknown'} mode instead of AP mode.",
                500, diagnostics,
            )
        if actual_ssid != ssid:
            return PinePiError(
                "AP_VERIFICATION_FAILED", f"hostapd started on {interface}, but the expected SSID was not active.",
                500, diagnostics,
            )
        reason = self._last_output_line(output)
        message = f"hostapd failed to become ready on {interface}" + (f": {reason}" if reason else "")
        return PinePiError("HOSTAPD_START_FAILED", message + ".", 500, diagnostics)

    def setup_routing(self, ap_interface: str, uplink: str, operation_id: str) -> dict:
        ap_interface = self._interface(ap_interface)
        uplink = self._interface(uplink)
        table = "pinepi_" + re.sub(r"[^a-f0-9]", "", operation_id.lower())[:12]
        previous = Path("/proc/sys/net/ipv4/ip_forward").read_text(encoding="ascii").strip()
        try:
            self.run(["sysctl", "-w", "net.ipv4.ip_forward=1"])
            self.run(["nft", "add", "table", "inet", table])
            self.run(["nft", "add", "chain", "inet", table, "forward", "{ type filter hook forward priority 0; policy accept; }"])
            self.run(["nft", "add", "chain", "inet", table, "postrouting", "{ type nat hook postrouting priority 100; }"])
            self.run(["nft", "add", "rule", "inet", table, "postrouting", "oifname", uplink, "ip", "saddr", AP_SUBNET, "masquerade"])
            state = {"table": table, "previous_forwarding": previous, "operation_id": operation_id}
            (self.runtime_dir / f"routing-{operation_id}.json").write_text(json.dumps(state), encoding="utf-8")
        # Roll back every partial nft/sysctl failure, including an injected runner failure.
        except Exception as exc:  # noqa: BLE001
            nft_cleanup = self.run(["nft", "delete", "table", "inet", table], check=False)
            forwarding_cleanup = self.run(["sysctl", "-w", f"net.ipv4.ip_forward={previous}"], check=False)
            details = {
                "stage": "routing_setup", "ap_interface": ap_interface, "uplink": uplink,
                "cleanup_result": "complete" if nft_cleanup.returncode == 0 and forwarding_cleanup.returncode == 0 else "incomplete",
            }
            if isinstance(exc, PinePiError):
                details.update(exc.details)
            raise PinePiError(
                "ROUTING_SETUP_FAILED", f"Temporary AP routing could not be configured: {getattr(exc, 'message', str(exc))}",
                500, details,
            ) from exc
        return state

    def teardown_routing(self, state: dict | None) -> None:
        if not state:
            return
        table = state.get("table", "")
        if re.fullmatch(r"pinepi_[a-f0-9]{1,12}", table):
            self.run(["nft", "delete", "table", "inet", table], check=False)
        previous = state.get("previous_forwarding")
        if previous in {"0", "1"}:
            self.run(["sysctl", "-w", f"net.ipv4.ip_forward={previous}"], check=False)
        operation_id = state.get("operation_id", "")
        if re.fullmatch(r"[a-f0-9]{32}", operation_id):
            (self.runtime_dir / f"routing-{operation_id}.json").unlink(missing_ok=True)

    def station_dump(self, interface: str) -> list[dict]:
        interface = self._interface(interface)
        result = self.run(["iw", "dev", interface, "station", "dump"], check=False)
        stations: list[dict] = []
        current: dict | None = None
        for raw in result.stdout.splitlines():
            line = raw.strip()
            match = re.match(r"Station ([0-9a-fA-F:]{17})", line)
            if match:
                current = {"mac": match.group(1).upper(), "rx_bytes": None, "tx_bytes": None}
                stations.append(current)
            elif current and line.startswith("rx bytes:"):
                try:
                    current["rx_bytes"] = int(line.split(":", 1)[1].strip())
                except ValueError:
                    current["rx_bytes"] = None
            elif current and line.startswith("tx bytes:"):
                try:
                    current["tx_bytes"] = int(line.split(":", 1)[1].strip())
                except ValueError:
                    current["tx_bytes"] = None
        return stations

    def inspect_capture(self, path: Path) -> CommandResult:
        return self.run(["capinfos", "-c", "-M", str(path)], check=False, timeout=10)

    def reconcile_runtime(self) -> list[str]:
        """Kill only recorded processes whose live command line still matches our record."""
        restored: list[str] = []
        for path in self.runtime_dir.glob("process-*.json"):
            try:
                state = json.loads(path.read_text(encoding="utf-8"))
                pid = int(state["pid"])
                expected = tuple(state["argv"])
                cmdline_path = Path(f"/proc/{pid}/cmdline")
                if cmdline_path.exists():
                    live = tuple(part.decode() for part in cmdline_path.read_bytes().split(b"\0") if part)
                    same_executable = live and Path(live[0]).name == Path(expected[0]).name
                    if same_executable and live[1 : len(expected)] == expected[1:]:
                        os.killpg(pid, signal.SIGTERM)
                path.unlink(missing_ok=True)
            except (OSError, ValueError, TypeError, IndexError, KeyError, UnicodeDecodeError, json.JSONDecodeError):
                path.unlink(missing_ok=True)
        for path in self.runtime_dir.glob("restore-*.json"):
            try:
                state = json.loads(path.read_text(encoding="utf-8"))
                interface = state["interface"] if isinstance(state, dict) else ""
                if interface != MANAGEMENT_INTERFACE and INTERFACE_PATTERN.fullmatch(interface):
                    self.restore_interface(interface)
                    restored.append(interface)
            except (OSError, TypeError, KeyError, json.JSONDecodeError):
                pass
            finally:
                path.unlink(missing_ok=True)
        for path in self.runtime_dir.glob("routing-*.json"):
            try:
                state = json.loads(path.read_text(encoding="utf-8"))
                if isinstance(state, dict):
                    self.teardown_routing(state)
            except (OSError, TypeError, KeyError, json.JSONDecodeError):
                path.unlink(missing_ok=True)
        # Remove only our dedicated nft tables; unrelated rules are untouched.
        result = self.run(["nft", "list", "tables"], check=False)
        for table in re.findall(r"table inet (pinepi_[a-f0-9]{1,12})", result.stdout):
            self.run(["nft", "delete", "table", "inet", table], check=False)
        return restored

    def record_restore(self, interface: str, operation_id: str) -> None:
        interface = self._interface(interface)
        (self.runtime_dir / f"restore-{operation_id}.json").write_text(
            json.dumps({"interface": interface}), encoding="utf-8"
        )

    def forget_restore(self, operation_id: str) -> None:
        (self.runtime_dir / f"restore-{operation_id}.json").unlink(missing_ok=True)
