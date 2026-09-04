from __future__ import annotations

import re
import threading
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

import psutil

from .errors import PinePiError

if TYPE_CHECKING:
    from .privileged import PrivilegedService


MANAGEMENT_INTERFACE = "wlan0"
INTERFACE_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,14}$")


@dataclass(frozen=True)
class Reservation:
    interface: str
    owner: str
    operation_id: str
    token: str


class ReservationRegistry:
    """Owns adapters per interface; unrelated interfaces do not block each other."""

    def __init__(self):
        self._guard = threading.RLock()
        self._owners: dict[str, Reservation] = {}

    def reserve(self, interface: str, owner: str, operation_id: str) -> Reservation:
        if interface == MANAGEMENT_INTERFACE:
            raise PinePiError(
                "MANAGEMENT_INTERFACE_RESERVED", "wlan0 is permanently reserved for PinePi management.", 409
            )
        with self._guard:
            current = self._owners.get(interface)
            if current:
                raise PinePiError(
                    "ADAPTER_BUSY",
                    f"{interface} is already assigned to {current.owner}.",
                    409,
                    {"owner": current.owner, "operation_id": current.operation_id},
                )
            reservation = Reservation(interface, owner, operation_id, uuid.uuid4().hex)
            self._owners[interface] = reservation
            return reservation

    def release(self, reservation: Reservation | None) -> bool:
        if reservation is None:
            return False
        with self._guard:
            current = self._owners.get(reservation.interface)
            if not current or current.token != reservation.token:
                return False
            del self._owners[reservation.interface]
            return True

    def role(self, interface: str) -> str | None:
        if interface == MANAGEMENT_INTERFACE:
            return "management"
        with self._guard:
            item = self._owners.get(interface)
            return item.owner if item else None

    def snapshot(self) -> dict[str, dict]:
        with self._guard:
            return {
                name: {"owner": item.owner, "operation_id": item.operation_id}
                for name, item in self._owners.items()
            }

    def clear(self) -> None:
        with self._guard:
            self._owners.clear()


class AdapterService:
    def __init__(self, registry: ReservationRegistry, privileged: PrivilegedService, sys_net: Path = Path("/sys/class/net")):
        self.registry = registry
        self.privileged = privileged
        self.sys_net = sys_net
        self._capability_cache: dict[str, tuple[float, dict]] = {}
        self._first_seen: dict[str, float] = {}

    @staticmethod
    def validate_name(interface: str) -> str:
        if not isinstance(interface, str) or not INTERFACE_PATTERN.fullmatch(interface):
            raise PinePiError("INVALID_INTERFACE", "Invalid network interface name.")
        return interface

    def list(self) -> list[dict]:
        stats = psutil.net_if_stats()
        addresses = psutil.net_if_addrs()
        default_routes = self.privileged.default_routes()
        now = time.monotonic()
        present = set(stats) | set(addresses)
        self._first_seen = {name: seen for name, seen in self._first_seen.items() if name in present}
        self._capability_cache = {name: value for name, value in self._capability_cache.items() if name in present}
        interfaces: list[dict] = []
        for name in sorted(present):
            if not INTERFACE_PATTERN.fullmatch(name) or name == "lo":
                continue
            self._first_seen.setdefault(name, now)
            stat = stats.get(name)
            wireless = (self.sys_net / name / "wireless").exists() or name.startswith(("wl", "wlan"))
            info = self.privileged.wireless_info(name) if wireless else {}
            capabilities = self._capabilities(name) if wireless else {
                "known": True, "managed": False, "monitor": False, "ap": False,
                "ap_channels": [], "ap_channel_state": "none",
            }
            ipv4 = [a.address for a in addresses.get(name, []) if getattr(a.family, "name", "") == "AF_INET"]
            is_up = bool(stat and stat.isup)
            role = self.registry.role(name)
            reserved = name == MANAGEMENT_INTERFACE
            capable = bool(capabilities.get("monitor") or capabilities.get("ap"))
            if reserved:
                pinepi_state = "reserved_management"
                usable = False
                reason = "Reserved for the PinePi management access point."
            elif role:
                pinepi_state = f"active_{role}"
                usable = False
                reason = f"Assigned to {role.replace('_', ' ')}."
            elif wireless and capabilities.get("known") and capable:
                pinepi_state = "ready"
                usable = True
                reason = None
            elif wireless and not capabilities.get("known") and now - self._first_seen[name] < 15:
                pinepi_state = "initializing"
                usable = False
                reason = capabilities.get("reason") or "Waiting for wireless capabilities to become available."
            elif wireless:
                pinepi_state = "unavailable"
                usable = False
                reason = capabilities.get("reason") or "This adapter does not advertise monitor or AP mode."
            else:
                pinepi_state = "online" if is_up and ipv4 else "idle"
                usable = bool(is_up)
                reason = None if is_up else "No active network link."
            nm_state = self.privileged.networkmanager_state(name)
            ap_capable = bool(capabilities.get("ap"))
            ap_channels = capabilities.get("ap_channels") or []
            reported_channel_state = capabilities.get("ap_channel_state")
            if ap_channels:
                ap_channel_state = "known"
            elif reported_channel_state in {"unknown", "none"}:
                ap_channel_state = reported_channel_state
            else:
                # Empty legacy results from AP-capable radios are indeterminate, not
                # proof that the PHY has no regulatory-valid channels.
                ap_channel_state = "unknown" if ap_capable else "none"

            ap_selectable = bool(
                wireless
                and ap_capable
                and not reserved
                and role is None
                and usable
                and ap_channel_state == "known"
                and ap_channels
            )
            if reserved:
                ap_selection_reason = "Reserved for the PinePi management access point."
            elif ap_capable and role:
                ap_selection_reason = f"Busy with {role.replace('_', ' ')}."
            elif not ap_capable:
                ap_selection_reason = "Adapter does not support AP mode."
            elif not usable:
                ap_selection_reason = reason or "Adapter is not ready."
            elif ap_channel_state == "unknown":
                ap_selection_reason = "Unable to determine supported AP channels."
            elif ap_channel_state == "none":
                ap_selection_reason = (
                    "Adapter supports AP mode but no usable AP channels are available "
                    "in the current regulatory domain."
                )
            else:
                ap_selection_reason = None
            interfaces.append(
                {
                    "name": name,
                    "exists": True,
                    "wireless": wireless,
                    "kind": "management" if reserved else ("audit" if wireless else "network"),
                    "state": "up" if is_up else "down",  # Backward-compatible raw link state.
                    "link_state": "up" if is_up else "down",
                    "nm_state": nm_state,
                    "mode": info.get("type") or ("ethernet" if not wireless else "unknown"),
                    "role": role or "available",
                    "pinepi_state": pinepi_state,
                    "current_operation": role,
                    "reserved": reserved,
                    "busy": role is not None,
                    "usable": usable,
                    "reason": reason,
                    "capabilities": capabilities,
                    "ap_capable": ap_capable,
                    "ap_channel_state": ap_channel_state,
                    "ap_selectable": ap_selectable,
                    "ap_selection_reason": ap_selection_reason,
                    "monitor_capable": bool(capabilities.get("monitor")),
                    "connected": is_up and bool(ipv4),
                    "connectivity": name in default_routes,
                    "ipv4": ipv4,
                    "description": "Management AP" if reserved else ("Audit adapter" if wireless else "Network uplink"),
                }
            )
        return interfaces

    def _capabilities(self, interface: str) -> dict:
        cached = self._capability_cache.get(interface)
        if cached and time.monotonic() - cached[0] < (10 if cached[1].get("known") else 2):
            return cached[1]
        value = self.privileged.wireless_capabilities(interface)
        self._capability_cache[interface] = (time.monotonic(), value)
        return value

    def get(self, interface: str) -> dict:
        self.validate_name(interface)
        item = next((item for item in self.list() if item["name"] == interface), None)
        if item is None:
            raise PinePiError("ADAPTER_NOT_FOUND", f"Network interface {interface} is unavailable.", 404)
        return item

    def require_wireless(self, interface: str, capability: str) -> dict:
        item = self.get(interface)
        if interface == MANAGEMENT_INTERFACE:
            raise PinePiError("MANAGEMENT_INTERFACE_RESERVED", "wlan0 is reserved for management.", 409)
        if not item["wireless"] or not item.get(f"{capability}_capable"):
            if capability == "ap" and item.get("monitor_capable"):
                raise PinePiError(
                    "ADAPTER_UNSUPPORTED",
                    "This adapter supports monitor mode but not AP mode.",
                    409,
                    {"interface": interface, "capability": capability},
                )
            raise PinePiError("ADAPTER_UNSUPPORTED", f"{interface} does not advertise {capability} capability.", 409)
        return item

    def require_ap_channel(self, interface: str, channel: int) -> dict:
        item = self.get(interface)
        capabilities = item.get("capabilities", {})
        channels = capabilities.get("ap_channels") or []
        channel_state = item.get("ap_channel_state")
        if channel_state == "unknown":
            raise PinePiError(
                "AP_CHANNELS_UNKNOWN",
                "Unable to determine supported AP channels.",
                409,
                {"interface": interface, "channel_state": channel_state},
            )
        if channel_state == "none":
            domain = capabilities.get("regulatory_domain") or "current"
            raise PinePiError(
                "NO_AP_CHANNELS",
                "Adapter supports AP mode but no usable AP channels are available "
                f"in the {domain} regulatory domain.",
                409,
                {"interface": interface, "channel_state": channel_state, "regulatory_domain": domain},
            )
        if channel not in channels:
            domain = capabilities.get("regulatory_domain") or "current"
            raise PinePiError(
                "UNSUPPORTED_CHANNEL",
                f"Channel {channel} is not supported by {interface} in the {domain} regulatory domain.",
                409,
                {"interface": interface, "channel": channel, "supported_channels": channels, "regulatory_domain": domain},
            )
        return item

    def uplinks(self, ap_interface: str | None = None) -> list[dict]:
        result = []
        for item in self.list():
            if item["name"] in {MANAGEMENT_INTERFACE, ap_interface}:
                continue
            if item["busy"]:
                continue
            # An uplink must already be connected; merely existing is insufficient.
            if item["connected"]:
                result.append(item)
        return sorted(result, key=self._uplink_score, reverse=True)

    @staticmethod
    def _uplink_score(item: dict) -> tuple[int, int, str]:
        name = item["name"].lower()
        if name.startswith(("eth", "en")):
            kind = 3
        elif name.startswith(("usb", "rndis")):
            kind = 2
        else:
            kind = 1
        return (1 if item["connectivity"] else 0, kind, name)

    def choose_uplink(self, requested: str, ap_interface: str) -> str | None:
        if requested in {"none", ""}:
            return None
        if requested == MANAGEMENT_INTERFACE:
            raise PinePiError("MANAGEMENT_INTERFACE_RESERVED", "wlan0 cannot be used as an uplink.", 409)
        candidates = self.uplinks(ap_interface)
        if requested == "auto":
            return candidates[0]["name"] if candidates else None
        self.validate_name(requested)
        match = next((item for item in candidates if item["name"] == requested), None)
        if match is None:
            raise PinePiError("NO_UPLINK", f"Uplink {requested} is not connected or available.", 409)
        return requested
