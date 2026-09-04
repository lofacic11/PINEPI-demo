"""Unprivileged client for the root-owned PinePi helper socket."""

from __future__ import annotations

import json
import socket
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .errors import PinePiError
from .privileged import CommandResult


@dataclass
class RemoteProcess:
    service: RemotePrivilegedService
    operation_id: str
    pid: int

    def alive(self) -> bool:
        return bool(self.service._rpc("process_alive", operation_id=self.operation_id)["alive"])


class RemotePrivilegedService:
    """Same narrow interface as PrivilegedService, transported as one JSON request per socket."""

    def __init__(self, socket_path: Path, timeout: int = 15):
        self.socket_path = socket_path
        self.timeout = timeout
        self._request_lock = threading.Lock()

    def _rpc(self, action: str, **params: Any):
        request = json.dumps({"action": action, "params": params}, separators=(",", ":")).encode() + b"\n"
        try:
            with self._request_lock, socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                client.settimeout(self.timeout)
                client.connect(str(self.socket_path))
                client.sendall(request)
                chunks = bytearray()
                while not chunks.endswith(b"\n"):
                    part = client.recv(65536)
                    if not part:
                        break
                    chunks.extend(part)
                    if len(chunks) > 4 * 1024 * 1024:
                        raise PinePiError("HELPER_PROTOCOL_ERROR", "Privileged helper response was too large.", 500)
        except (OSError, TimeoutError) as exc:
            raise PinePiError("HELPER_UNAVAILABLE", "The PinePi privileged helper is unavailable.", 503) from exc
        try:
            response = json.loads(chunks)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise PinePiError("HELPER_PROTOCOL_ERROR", "Invalid response from the privileged helper.", 500) from exc
        if not response.get("ok"):
            error = response.get("error") or {}
            raise PinePiError(error.get("code", "HELPER_ERROR"), error.get("message", "Privileged operation failed."), int(error.get("status", 500)), error.get("details"))
        return response.get("data")

    def wireless_info(self, interface: str) -> dict:
        return self._rpc("wireless_info", interface=interface)

    def wireless_capabilities(self, interface: str) -> dict:
        return self._rpc("wireless_capabilities", interface=interface)

    def networkmanager_state(self, interface: str) -> str:
        return str(self._rpc("networkmanager_state", interface=interface))

    def default_routes(self) -> set[str]:
        return set(self._rpc("default_routes"))

    def set_monitor(self, interface: str, channel: int | None = None) -> None:
        self._rpc("set_monitor", interface=interface, channel=channel)

    def restore_interface(self, interface: str) -> None:
        self._rpc("restore_interface", interface=interface)

    def start_recon(self, interface: str, prefix: Path, operation_id: str) -> RemoteProcess:
        data = self._rpc("start_recon", interface=interface, prefix=str(prefix), operation_id=operation_id)
        return RemoteProcess(self, data["operation_id"], data["pid"])

    def start_capture(self, interface: str, path: Path, max_bytes: int, operation_id: str) -> RemoteProcess:
        data = self._rpc("start_capture", interface=interface, path=str(path), max_bytes=max_bytes, operation_id=operation_id)
        return RemoteProcess(self, data["operation_id"], data["pid"])

    def start_ap(
        self, interface: str, ssid: str, channel: int, security: str, password: str | None,
        session_dir: Path, operation_id: str,
    ) -> tuple[RemoteProcess, RemoteProcess]:
        data = self._rpc(
            "start_ap", interface=interface, ssid=ssid, channel=channel, security=security,
            password=password, session_dir=str(session_dir), operation_id=operation_id,
        )
        return (
            RemoteProcess(self, data["hostapd"]["operation_id"], data["hostapd"]["pid"]),
            RemoteProcess(self, data["dnsmasq"]["operation_id"], data["dnsmasq"]["pid"]),
        )

    def setup_routing(self, ap_interface: str, uplink: str, operation_id: str) -> dict:
        return self._rpc("setup_routing", ap_interface=ap_interface, uplink=uplink, operation_id=operation_id)

    def teardown_routing(self, state: dict | None) -> None:
        self._rpc("teardown_routing", state=state)

    def station_dump(self, interface: str) -> list[dict]:
        return self._rpc("station_dump", interface=interface)

    def inspect_capture(self, path: Path) -> CommandResult:
        data = self._rpc("inspect_capture", path=str(path))
        return CommandResult(data["returncode"], data.get("stdout", ""), data.get("stderr", ""))

    def stop_process(self, process: RemoteProcess | None, grace: float = 3.0) -> None:
        if process:
            self._rpc("stop_process", operation_id=process.operation_id, grace=grace)

    def record_restore(self, interface: str, operation_id: str) -> None:
        self._rpc("record_restore", interface=interface, operation_id=operation_id)

    def forget_restore(self, operation_id: str) -> None:
        self._rpc("forget_restore", operation_id=operation_id)

    def reconcile_runtime(self) -> list[str]:
        return self._rpc("reconcile_runtime")
