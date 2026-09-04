"""Small, validated boundary around commands that require root on Raspberry Pi OS."""

from __future__ import annotations

import json
import os
import re
import signal
import subprocess
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from .adapters import INTERFACE_PATTERN, MANAGEMENT_INTERFACE
from .errors import PinePiError


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

    @property
    def pid(self) -> int:
        return self.process.pid

    def alive(self) -> bool:
        return self.process.poll() is None


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

    def run(self, argv: list[str], check: bool = True, timeout: int | None = None) -> CommandResult:
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
                raise PinePiError("SYSTEM_COMMAND_FAILED", f"Required system operation failed: {argv[0]}.", 500) from exc
            return CommandResult(127, "", str(exc))
        wrapped = CommandResult(result.returncode, result.stdout or "", result.stderr or "")
        if check and result.returncode != 0:
            raise PinePiError(
                "SYSTEM_COMMAND_FAILED", f"{argv[0]} failed.", 500, {"tool": argv[0], "returncode": result.returncode}
            )
        return wrapped

    def spawn(self, argv: list[str], operation_id: str, stdout_path: Path | None = None) -> OwnedProcess:
        stdout = subprocess.DEVNULL
        file_handle = None
        if stdout_path:
            stdout_path.parent.mkdir(parents=True, exist_ok=True)
            file_handle = stdout_path.open("ab", buffering=0)
            stdout = file_handle
        try:
            process = self._popen(
                argv,
                shell=False,
                stdin=subprocess.DEVNULL,
                stdout=stdout,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
        finally:
            if file_handle:
                file_handle.close()
        owned = OwnedProcess(process, tuple(argv), operation_id)
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
        if not INTERFACE_PATTERN.fullmatch(interface):
            return {"monitor": False, "ap": False}
        info = self.wireless_info(interface)
        wiphy = info.get("wiphy")
        if wiphy is None:
            return {"monitor": False, "ap": False}
        result = self.run(["iw", "phy", f"phy{wiphy}", "info"], check=False)
        text = result.stdout.lower()
        return {"monitor": "* monitor" in text, "ap": "* ap" in text}

    def default_routes(self) -> set[str]:
        result = self.run(["ip", "route", "show", "default"], check=False)
        return set(re.findall(r"\bdev\s+([A-Za-z0-9_.:-]{1,15})\b", result.stdout))

    def set_monitor(self, interface: str, channel: int | None = None) -> None:
        interface = self._interface(interface)
        self.run(["ip", "link", "set", "dev", interface, "down"])
        try:
            self.run(["iw", "dev", interface, "set", "type", "monitor"])
            self.run(["ip", "link", "set", "dev", interface, "up"])
            if channel:
                self.run(["iw", "dev", interface, "set", "channel", str(channel)])
            if self.wireless_info(interface).get("type") != "monitor":
                raise PinePiError("MONITOR_MODE_FAILED", f"{interface} did not enter monitor mode.", 500)
        except Exception:
            self.restore_interface(interface)
            raise

    def restore_interface(self, interface: str) -> None:
        interface = self._interface(interface)
        self.run(["ip", "link", "set", "dev", interface, "down"], check=False)
        self.run(["iw", "dev", interface, "set", "type", "managed"], check=False)
        self.run(["ip", "address", "flush", "dev", interface], check=False)
        self.run(["ip", "link", "set", "dev", interface, "up"], check=False)
        self.run(["nmcli", "device", "set", interface, "managed", "yes"], check=False)

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
        control_dir = session_dir / "hostapd-control"
        control_dir.mkdir(mode=0o700, exist_ok=True)
        hostapd_lines = [
            f"interface={interface}", "driver=nl80211", f"ctrl_interface={control_dir}", f"ssid={ssid}", f"channel={channel}",
            "hw_mode=g" if channel <= 14 else "hw_mode=a", "country_code=AT", "ieee80211d=1",
        ]
        if security == "wpa2":
            hostapd_lines.extend(["wpa=2", f"wpa_passphrase={password}", "wpa_key_mgmt=WPA-PSK", "rsn_pairwise=CCMP"])
        hostapd_conf = session_dir / "hostapd.conf"
        hostapd_conf.write_text("\n".join(hostapd_lines) + "\n", encoding="utf-8")
        hostapd_conf.chmod(0o600)
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
        dnsmasq_conf = session_dir / "dnsmasq.conf"
        dnsmasq_conf.write_text(
            "\n".join([
                f"interface={interface}", "bind-interfaces", "dhcp-range=10.77.0.10,10.77.0.200,255.255.255.0,12h",
                "dhcp-option=3,10.77.0.1", "dhcp-option=6,10.77.0.1", f"dhcp-leasefile={leases}",
                f"pid-file={lease_dir / 'dnsmasq.pid'}", "log-dhcp",
            ]) + "\n", encoding="utf-8"
        )
        self.run(["nmcli", "device", "set", interface, "managed", "no"], check=False)
        self.run(["ip", "link", "set", "dev", interface, "down"])
        self.run(["ip", "address", "flush", "dev", interface])
        self.run(["ip", "address", "add", "10.77.0.1/24", "dev", interface])
        self.run(["ip", "link", "set", "dev", interface, "up"])
        hostapd = self.spawn(["hostapd", str(hostapd_conf)], operation_id + "-hostapd")
        time.sleep(1)
        if not hostapd.alive():
            self.stop_process(hostapd)
            raise PinePiError("HOSTAPD_START_FAILED", "hostapd exited before the AP became ready.", 500)
        status = self.run(["hostapd_cli", "-p", str(control_dir), "-i", interface, "status"], check=False).stdout
        actual_mode = self.wireless_info(interface).get("type")
        if actual_mode != "AP" or "state=ENABLED" not in status or f"ssid[0]={ssid}" not in status:
            self.stop_process(hostapd)
            raise PinePiError("HOSTAPD_START_FAILED", "The interface did not reach the expected AP state and SSID.", 500)
        dnsmasq = None
        try:
            dnsmasq = self.spawn(["dnsmasq", "--keep-in-foreground", "--conf-file=" + str(dnsmasq_conf)], operation_id + "-dnsmasq")
            time.sleep(0.3)
            if not dnsmasq.alive():
                raise PinePiError("DNSMASQ_START_FAILED", "dnsmasq exited during startup.", 500)
        except Exception:
            self.stop_process(dnsmasq)
            self.stop_process(hostapd)
            hostapd_conf.unlink(missing_ok=True)
            raise
        # hostapd has parsed the configuration. Remove the only plaintext credential copy.
        hostapd_conf.unlink(missing_ok=True)
        return hostapd, dnsmasq

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
            self.run(["nft", "add", "rule", "inet", table, "postrouting", "oifname", uplink, "ip", "saddr", "10.77.0.0/24", "masquerade"])
            state = {"table": table, "previous_forwarding": previous, "operation_id": operation_id}
            (self.runtime_dir / f"routing-{operation_id}.json").write_text(json.dumps(state), encoding="utf-8")
        # Roll back every partial nft/sysctl failure, including an injected runner failure.
        except Exception:  # noqa: BLE001
            self.run(["nft", "delete", "table", "inet", table], check=False)
            self.run(["sysctl", "-w", f"net.ipv4.ip_forward={previous}"], check=False)
            raise PinePiError("ROUTING_SETUP_FAILED", "Temporary AP routing could not be configured.", 500)
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
