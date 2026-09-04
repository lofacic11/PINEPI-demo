from __future__ import annotations

from types import SimpleNamespace

from pinepi.adapters import AdapterService, ReservationRegistry


class AdapterProbe:
    def __init__(self, capabilities=None):
        self.capabilities = capabilities or {
            "known": True,
            "managed": True,
            "monitor": True,
            "ap": True,
            "ap_channels": [1, 6, 11],
            "regulatory_domain": "AT",
        }

    def default_routes(self):
        return set()

    def wireless_info(self, _interface):
        return {"type": "managed", "wiphy": "1"}

    def wireless_capabilities(self, _interface):
        return dict(self.capabilities)

    def networkmanager_state(self, _interface):
        return "disconnected"


def install_interfaces(monkeypatch, names):
    stats = {name: SimpleNamespace(isup=False) for name in names}
    monkeypatch.setattr("pinepi.adapters.psutil.net_if_stats", lambda: stats)
    monkeypatch.setattr("pinepi.adapters.psutil.net_if_addrs", lambda: {name: [] for name in names})
    return stats


def test_idle_link_down_audit_adapter_is_ready(monkeypatch, tmp_path):
    install_interfaces(monkeypatch, ["wlan1"])
    adapter = AdapterService(ReservationRegistry(), AdapterProbe(), tmp_path)

    item = adapter.list()[0]

    assert item["link_state"] == "down"
    assert item["nm_state"] == "disconnected"
    assert item["pinepi_state"] == "ready"
    assert item["usable"] is True


def test_ready_ap_adapter_with_channels_is_selectable(monkeypatch, tmp_path):
    install_interfaces(monkeypatch, ["wlan1"])
    probe = AdapterProbe({
        "known": True,
        "managed": True,
        "monitor": True,
        "ap": True,
        "ap_channels": [1, 6, 11],
        "ap_channel_state": "known",
        "regulatory_domain": "AT",
    })

    item = AdapterService(ReservationRegistry(), probe, tmp_path).list()[0]

    assert item["ap_capable"] is True
    assert item["usable"] is True
    assert item["busy"] is False
    assert item["reserved"] is False
    assert item["ap_channel_state"] == "known"
    assert item["ap_selectable"] is True
    assert item["ap_selection_reason"] is None


def test_ap_channel_unknown_and_none_have_distinct_selection_reasons(monkeypatch, tmp_path):
    install_interfaces(monkeypatch, ["wlan1"])
    probe = AdapterProbe({
        "known": True, "managed": True, "monitor": True, "ap": True,
        "ap_channels": [], "ap_channel_state": "unknown", "regulatory_domain": "AT",
    })
    adapter = AdapterService(ReservationRegistry(), probe, tmp_path)

    unknown = adapter.list()[0]
    assert unknown["pinepi_state"] == "ready"
    assert unknown["usable"] is True
    assert unknown["ap_capable"] is True
    assert unknown["ap_selectable"] is False
    assert unknown["ap_selection_reason"] == "Unable to determine supported AP channels."

    probe.capabilities["ap_channel_state"] = "none"
    adapter._capability_cache.clear()
    none = adapter.list()[0]
    assert none["ap_selectable"] is False
    assert none["ap_selection_reason"] == (
        "Adapter supports AP mode but no usable AP channels are available "
        "in the current regulatory domain."
    )


def test_reserved_active_and_unavailable_states(monkeypatch, tmp_path):
    install_interfaces(monkeypatch, ["wlan0", "wlan1"])
    registry = ReservationRegistry()
    registry.reserve("wlan1", "capture", "capture-one")
    adapter = AdapterService(registry, AdapterProbe(), tmp_path)

    items = {item["name"]: item for item in adapter.list()}

    assert items["wlan0"]["pinepi_state"] == "reserved_management"
    assert items["wlan0"]["reserved"] is True
    assert items["wlan0"]["ap_selectable"] is False
    assert items["wlan0"]["ap_selection_reason"] == (
        "Reserved for the PinePi management access point."
    )
    assert items["wlan1"]["pinepi_state"] == "active_capture"
    assert items["wlan1"]["current_operation"] == "capture"
    assert items["wlan1"]["ap_selectable"] is False
    assert items["wlan1"]["ap_selection_reason"] == "Busy with capture."

    registry.clear()
    adapter.privileged.capabilities = {
        "known": True, "managed": True, "monitor": False, "ap": False, "ap_channels": [],
    }
    adapter._capability_cache.clear()
    item = adapter.list()[1]
    assert item["pinepi_state"] == "unavailable"
    assert item["usable"] is False


def test_hotplug_initializing_transitions_to_ready_without_restart(monkeypatch, tmp_path):
    stats = install_interfaces(monkeypatch, [])
    clock = [0.0]
    monkeypatch.setattr("pinepi.adapters.time.monotonic", lambda: clock[0])
    probe = AdapterProbe({
        "known": False, "managed": False, "monitor": False, "ap": False, "ap_channels": [],
        "reason": "Waiting for nl80211.",
    })
    adapter = AdapterService(ReservationRegistry(), probe, tmp_path)
    assert adapter.list() == []

    stats["wlan1"] = SimpleNamespace(isup=False)
    item = adapter.list()[0]
    assert item["pinepi_state"] == "initializing"

    clock[0] = 3.0
    probe.capabilities = {
        "known": True, "managed": True, "monitor": True, "ap": True,
        "ap_channels": [1, 6, 11], "regulatory_domain": "AT",
    }
    item = adapter.list()[0]
    assert item["pinepi_state"] == "ready"
    assert item["usable"] is True
