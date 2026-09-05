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


def test_ap_band_and_auto_channel_controls_are_adapter_aware():
    root = Path(__file__).parents[1]
    template = (root / "pinepi" / "templates" / "index.html").read_text(encoding="utf-8")
    script = (root / "pinepi" / "static" / "app.js").read_text(encoding="utf-8")

    assert 'id="apBand"' in template
    assert 'id="apChannelMode"' in template
    assert "Auto / Recommended" in template
    assert 'id="apRecommendation"' in template
    assert 'band: $("#apBand").value' in script
    assert '$("#apChannelMode").value === "auto" ? "auto"' in script
    assert 'groups["5"].length' in script
    assert "ap_channels" in script


def test_recon_action_hub_and_target_indicator_have_mobile_contract():
    root = Path(__file__).parents[1]
    template = (root / "pinepi" / "templates" / "index.html").read_text(encoding="utf-8")
    script = (root / "pinepi" / "static" / "app.js").read_text(encoding="utf-8")
    styles = (root / "pinepi" / "static" / "app.css").read_text(encoding="utf-8")

    assert 'id="currentTargetIndicator"' in template
    assert 'id="clearTarget"' in template
    for label in ("Set Target", "Passive Audit", "Capture"):
        assert f'actionButton("{label}"' in script
    assert '"Stop Monitor" : "Monitor"' in script
    for label in ("View Clients", "Rogue / Duplicate Check", "Technical Details", "Add Note / Bookmark"):
        assert f'actionButton("{label}"' in script
    assert 'element("details", "network-more")' in script
    assert "network-primary-actions" in styles
    assert "grid-template-columns:1fr 1fr" in styles
    assert "current-target-indicator" in styles


def test_targeted_and_raw_capture_modes_preserve_truthful_capture_semantics():
    root = Path(__file__).parents[1]
    template = (root / "pinepi" / "templates" / "index.html").read_text(encoding="utf-8")
    script = (root / "pinepi" / "static" / "app.js").read_text(encoding="utf-8")

    assert 'id="captureMode"' in template
    assert "Targeted Capture" in template
    assert "Raw Capture" in template
    assert "receives all frames it can hear on this channel" in template
    assert "not a hardware frame filter" in template
    assert "Raw mode captures all visible 802.11 traffic" in template
    assert 'gotoPage("capture")' in script
    assert 'target: mode === "targeted"' in script
    assert "No free compatible monitor-capable adapter." in script
