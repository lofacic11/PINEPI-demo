from __future__ import annotations

import os
from pathlib import Path


class Config:
    DATA_DIR = Path(os.getenv("PINEPI_DATA_DIR", "/var/lib/pinepi"))
    DATABASE = Path(os.getenv("PINEPI_DATABASE", str(DATA_DIR / "pinepi.db")))
    RUNTIME_DIR = os.getenv("PINEPI_RUNTIME_DIR")
    MAX_CAPTURE_BYTES = int(os.getenv("PINEPI_MAX_CAPTURE_BYTES", str(250 * 1024 * 1024)))
    MIN_FREE_BYTES = int(os.getenv("PINEPI_MIN_FREE_BYTES", str(512 * 1024 * 1024)))
    COMMAND_TIMEOUT = int(os.getenv("PINEPI_COMMAND_TIMEOUT", "15"))
    HELPER_SOCKET = os.getenv("PINEPI_HELPER_SOCKET")
    RECONCILE_ON_STARTUP = True
    JSON_SORT_KEYS = False
