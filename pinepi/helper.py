"""Root-owned, allowlisted Unix-socket helper for PinePi hardware operations."""

from __future__ import annotations

import json
import os
import re
import signal
import socketserver
from pathlib import Path

from .config import Config
from .errors import PinePiError
from .privileged import OwnedProcess, PrivilegedService

OPERATION_ID = re.compile(r"^[a-f0-9]{32}(?:-(?:traffic|hostapd|dnsmasq))?$")


class HelperState:
    def __init__(self, data_dir: Path, runtime_dir: Path | None = None):
        self.data_dir = data_dir.resolve()
        self.privileged = PrivilegedService(runtime_dir or self.data_dir / "runtime", Config.COMMAND_TIMEOUT)
        self.processes: dict[str, OwnedProcess] = {}

    def operation_id(self, value) -> str:
        if not isinstance(value, str) or not OPERATION_ID.fullmatch(value):
            raise PinePiError("INVALID_OPERATION_ID", "Invalid operation identifier.")
        return value

    def path(self, value, *allowed_roots: Path) -> Path:
        try:
            path = Path(value).resolve(strict=False)
            path.relative_to(self.data_dir)
            if allowed_roots and not any(self._within(path, root) for root in allowed_roots):
                raise ValueError("path is outside the permitted operation storage")
        except (TypeError, OSError, ValueError) as exc:
            raise PinePiError("INVALID_STORAGE_PATH", "Helper path is outside PinePi storage.", 403) from exc
        return path

    @staticmethod
    def _within(path: Path, root: Path) -> bool:
        try:
            path.relative_to(root.resolve())
            return True
        except ValueError:
            return False

    def remember(self, process: OwnedProcess) -> dict:
        self.processes[process.operation_id] = process
        return {"operation_id": process.operation_id, "pid": process.pid}

    def dispatch(self, action: str, params: dict):
        service = self.privileged
        if action == "wireless_info":
            return service.wireless_info(str(params.get("interface", "")))
        if action == "wireless_capabilities":
            return service.wireless_capabilities(str(params.get("interface", "")))
        if action == "default_routes":
            return sorted(service.default_routes())
        if action == "set_monitor":
            channel = params.get("channel")
            if channel is not None and (not isinstance(channel, int) or not 1 <= channel <= 196):
                raise PinePiError("INVALID_CHANNEL", "Channel is out of range.")
            service.set_monitor(str(params.get("interface", "")), channel)
            return {}
        if action == "restore_interface":
            service.restore_interface(str(params.get("interface", "")))
            return {}
        if action == "start_recon":
            operation_id = self.operation_id(params.get("operation_id"))
            prefix = self.path(params.get("prefix"), self.data_dir / "recon")
            if prefix != (self.data_dir / "recon" / operation_id / "recon").resolve():
                raise PinePiError("INVALID_STORAGE_PATH", "Recon output path does not match its operation.", 403)
            process = service.start_recon(str(params.get("interface", "")), prefix, operation_id)
            return self.remember(process)
        if action == "start_capture":
            operation_id = self.operation_id(params.get("operation_id"))
            max_bytes = params.get("max_bytes")
            if not isinstance(max_bytes, int) or not 1 <= max_bytes <= Config.MAX_CAPTURE_BYTES:
                raise PinePiError("INVALID_CAPTURE_LIMIT", "Invalid capture size limit.")
            path = self.path(params.get("path"), self.data_dir / "captures", self.data_dir / "ap_sessions")
            if operation_id.endswith("-traffic"):
                session_id = operation_id.removesuffix("-traffic")
                expected = (self.data_dir / "ap_sessions" / session_id / "traffic.pcapng").resolve()
                valid_path = path == expected
            else:
                valid_path = path.parent == (self.data_dir / "captures").resolve() and path.name.startswith(operation_id + "_") and path.suffix == ".pcapng"
            if not valid_path:
                raise PinePiError("INVALID_STORAGE_PATH", "Capture path does not match its operation.", 403)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.touch(exist_ok=True)
            path.chmod(0o660)
            process = service.start_capture(str(params.get("interface", "")), path, max_bytes, operation_id)
            return self.remember(process)
        if action == "start_ap":
            operation_id = self.operation_id(params.get("operation_id"))
            session_dir = self.path(params.get("session_dir"), self.data_dir / "ap_sessions")
            if session_dir != (self.data_dir / "ap_sessions" / operation_id).resolve():
                raise PinePiError("INVALID_STORAGE_PATH", "AP session path does not match its operation.", 403)
            hostapd, dnsmasq = service.start_ap(
                str(params.get("interface", "")), params.get("ssid"), params.get("channel"),
                params.get("security"), params.get("password"), session_dir, operation_id,
            )
            return {"hostapd": self.remember(hostapd), "dnsmasq": self.remember(dnsmasq)}
        if action == "setup_routing":
            operation_id = self.operation_id(params.get("operation_id"))
            return service.setup_routing(str(params.get("ap_interface", "")), str(params.get("uplink", "")), operation_id)
        if action == "teardown_routing":
            state = params.get("state")
            if state is not None and not isinstance(state, dict):
                raise PinePiError("INVALID_ROUTING_STATE", "Invalid routing state.")
            service.teardown_routing(state)
            return {}
        if action == "station_dump":
            return service.station_dump(str(params.get("interface", "")))
        if action == "inspect_capture":
            path = self.path(params.get("path"), self.data_dir / "captures", self.data_dir / "ap_sessions")
            if path.suffix not in {".pcap", ".pcapng"}:
                raise PinePiError("INVALID_STORAGE_PATH", "Only PinePi packet captures may be inspected.", 403)
            result = service.inspect_capture(path)
            return {"returncode": result.returncode, "stdout": result.stdout[:1024 * 1024], "stderr": result.stderr[:4096]}
        if action == "process_alive":
            operation_id = self.operation_id(params.get("operation_id"))
            process = self.processes.get(operation_id)
            return {"alive": bool(process and process.alive())}
        if action == "stop_process":
            operation_id = self.operation_id(params.get("operation_id"))
            process = self.processes.pop(operation_id, None)
            service.stop_process(process, min(max(float(params.get("grace", 3)), 0), 10))
            return {}
        if action == "record_restore":
            operation_id = self.operation_id(params.get("operation_id"))
            service.record_restore(str(params.get("interface", "")), operation_id)
            return {}
        if action == "forget_restore":
            service.forget_restore(self.operation_id(params.get("operation_id")))
            return {}
        if action == "reconcile_runtime":
            for process in list(self.processes.values()):
                service.stop_process(process)
            self.processes.clear()
            return service.reconcile_runtime()
        raise PinePiError("HELPER_ACTION_DENIED", "The requested helper action is not permitted.", 403)

    def cleanup(self) -> None:
        for process in list(self.processes.values()):
            self.privileged.stop_process(process)
        self.processes.clear()
        self.privileged.reconcile_runtime()


class RequestHandler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        try:
            raw = self.rfile.readline(1024 * 1024 + 1)
            if not raw or len(raw) > 1024 * 1024:
                raise PinePiError("HELPER_PROTOCOL_ERROR", "Invalid helper request size.")
            request = json.loads(raw)
            if not isinstance(request, dict) or not isinstance(request.get("params", {}), dict):
                raise PinePiError("HELPER_PROTOCOL_ERROR", "Invalid helper request.")
            data = self.server.state.dispatch(request.get("action"), request.get("params", {}))
            response = {"ok": True, "data": data}
        except PinePiError as error:
            response = {"ok": False, "error": {**error.as_dict(), "status": error.status}}
        except (json.JSONDecodeError, UnicodeDecodeError, TypeError, ValueError):
            response = {"ok": False, "error": {"code": "HELPER_PROTOCOL_ERROR", "message": "Invalid helper request.", "status": 400}}
        except Exception:  # noqa: BLE001
            response = {"ok": False, "error": {"code": "HELPER_INTERNAL_ERROR", "message": "Privileged helper operation failed.", "status": 500}}
        self.wfile.write(json.dumps(response, separators=(",", ":")).encode() + b"\n")


if hasattr(socketserver, "ThreadingUnixStreamServer"):
    _HelperServerBase = socketserver.ThreadingUnixStreamServer
elif hasattr(socketserver, "UnixStreamServer"):
    class _HelperServerBase(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
        daemon_threads = True
else:  # Import-only fallback for platforms without AF_UNIX; main() is Linux-only.
    _HelperServerBase = socketserver.ThreadingTCPServer


class HelperServer(_HelperServerBase):
    daemon_threads = True

    def __init__(self, socket_path: Path, state: HelperState):
        self.state = state
        super().__init__(str(socket_path), RequestHandler)


def main() -> None:
    import grp

    data_dir = Path(os.getenv("PINEPI_DATA_DIR", "/var/lib/pinepi"))
    runtime_dir = Path(os.getenv("PINEPI_RUNTIME_DIR", str(data_dir / "runtime")))
    socket_path = Path(os.getenv("PINEPI_HELPER_SOCKET", "/run/pinepi/helper.sock"))
    socket_path.parent.mkdir(parents=True, exist_ok=True)
    socket_path.unlink(missing_ok=True)
    os.umask(0o027)
    state = HelperState(data_dir, runtime_dir)
    state.privileged.reconcile_runtime()
    server = HelperServer(socket_path, state)
    socket_path.chmod(0o660)
    try:
        group = grp.getgrnam("pinepi")
        os.chown(socket_path, 0, group.gr_gid)
    except KeyError:
        pass

    def stop(_signum, _frame):
        state.cleanup()
        raise SystemExit(0)

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    try:
        server.serve_forever(poll_interval=0.5)
    finally:
        server.server_close()
        socket_path.unlink(missing_ok=True)


if __name__ == "__main__":
    main()
