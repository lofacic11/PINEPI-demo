"""PinePi application factory."""

from __future__ import annotations

from pathlib import Path

from flask import Flask, jsonify
from werkzeug.exceptions import HTTPException

from .adapters import AdapterService, ReservationRegistry
from .config import Config
from .db import Database
from .errors import PinePiError
from .events import EventLog
from .operations import OperationService
from .privileged import PrivilegedService
from .remote import RemotePrivilegedService
from .routes import api, ui


def create_app(overrides: dict | None = None) -> Flask:
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_object(Config)
    if overrides:
        app.config.update(overrides)

    data_dir = Path(app.config["DATA_DIR"])
    data_dir.mkdir(parents=True, exist_ok=True)
    for name in ("captures", "ap_sessions", "exports"):
        (data_dir / name).mkdir(exist_ok=True)

    database = Database(Path(app.config["DATABASE"]))
    database.migrate()
    events = EventLog(database)
    privileged = app.config.get("PRIVILEGED_SERVICE")
    if privileged is None and app.config.get("HELPER_SOCKET"):
        privileged = RemotePrivilegedService(Path(app.config["HELPER_SOCKET"]), app.config["COMMAND_TIMEOUT"])
    if privileged is None:
        runtime_dir = Path(app.config.get("RUNTIME_DIR") or data_dir / "runtime")
        privileged = PrivilegedService(runtime_dir=runtime_dir, command_timeout=app.config["COMMAND_TIMEOUT"])
    registry = ReservationRegistry()
    adapters = app.config.get("ADAPTER_SERVICE") or AdapterService(
        registry=registry,
        privileged=privileged,
    )
    operations = OperationService(
        database=database,
        events=events,
        adapters=adapters,
        registry=registry,
        privileged=privileged,
        data_dir=data_dir,
        max_capture_bytes=app.config["MAX_CAPTURE_BYTES"],
        min_free_bytes=app.config["MIN_FREE_BYTES"],
        reconcile=app.config.get("RECONCILE_ON_STARTUP", True),
    )

    app.extensions.update(
        database=database,
        events=events,
        adapters=adapters,
        reservations=registry,
        privileged=privileged,
        operations=operations,
    )
    app.register_blueprint(ui)
    app.register_blueprint(api, url_prefix="/api")

    @app.errorhandler(PinePiError)
    def handle_pinepi_error(error: PinePiError):
        return jsonify({"ok": False, "error": error.as_dict()}), error.status

    @app.errorhandler(404)
    def not_found(_error):
        return jsonify({"ok": False, "error": {"code": "NOT_FOUND", "message": "Resource not found."}}), 404

    @app.errorhandler(HTTPException)
    def http_error(error: HTTPException):
        code = error.name.upper().replace(" ", "_")
        return jsonify({"ok": False, "error": {"code": code, "message": error.description}}), error.code

    @app.errorhandler(Exception)
    def unexpected(error: Exception):
        app.logger.exception("Unhandled request error", exc_info=error)
        return jsonify({"ok": False, "error": {"code": "INTERNAL_ERROR", "message": "Unexpected server error."}}), 500

    return app
