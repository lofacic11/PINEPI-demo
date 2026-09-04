from __future__ import annotations

from pathlib import Path


def test_recon_details_use_single_selection_inline_accordion():
    root = Path(__file__).parents[1]
    template = (root / "pinepi" / "templates" / "index.html").read_text(encoding="utf-8")
    script = (root / "pinepi" / "static" / "app.js").read_text(encoding="utf-8")

    assert 'id="networkDetail"' not in template
    assert "selectedNetworkKey" in script
    assert "inline-detail-row" in script
    assert "mobile-network-detail" in script
    assert "state.selectedNetworkKey === key ? null : key" in script
    assert "function showNetwork" not in script


def test_dashboard_uses_pinepi_state_and_ap_errors_are_persistent():
    root = Path(__file__).parents[1]
    script = (root / "pinepi" / "static" / "app.js").read_text(encoding="utf-8")

    assert 'item.pinepi_state === "ready"' in script
    assert 'label = "Ready"' in script
    assert 'item.connected ? "Online" : item.state' not in script
    assert "state.apError" in script
    assert "function apSelectable(item)" in script
    assert "item.ap_selectable === true || inferred" in script
    assert 'apChannelState(item) === "known"' in script
    assert "Unable to determine supported AP channels." in script
    assert "Adapter supports AP mode but no usable AP channels are available" in script
    assert "Adapter does not support AP mode." in script
    assert "No ready adapter currently supports AP mode." in script
    assert "No free AP-capable adapter" not in script
