from __future__ import annotations

import pytest

from pinepi.adapters import ReservationRegistry
from pinepi.errors import PinePiError


def test_wlan0_is_permanently_reserved():
    registry = ReservationRegistry()
    with pytest.raises(PinePiError) as error:
        registry.reserve("wlan0", "recon", "one")
    assert error.value.code == "MANAGEMENT_INTERFACE_RESERVED"
    assert registry.role("wlan0") == "management"


def test_busy_adapter_is_rejected_but_separate_adapter_is_independent():
    registry = ReservationRegistry()
    first = registry.reserve("wlan1", "recon", "one")
    with pytest.raises(PinePiError) as error:
        registry.reserve("wlan1", "ap", "two")
    assert error.value.code == "ADAPTER_BUSY"
    second = registry.reserve("wlan2", "ap", "two")
    assert registry.role("wlan1") == "recon"
    assert registry.role("wlan2") == "ap"
    assert registry.release(first) and registry.release(second)


def test_stale_token_cannot_release_new_owner():
    registry = ReservationRegistry()
    old = registry.reserve("wlan1", "recon", "one")
    registry.release(old)
    registry.reserve("wlan1", "capture", "two")
    assert registry.release(old) is False
    assert registry.role("wlan1") == "capture"
