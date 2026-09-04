from __future__ import annotations

import json
from io import BytesIO

from flask import Blueprint, current_app, jsonify, render_template, request, send_file

from .errors import PinePiError
from .exports import ExportService

ui = Blueprint("ui", __name__)
api = Blueprint("api", __name__)


def services():
    return current_app.extensions


def body() -> dict:
    value = request.get_json(silent=True)
    if not isinstance(value, dict):
        raise PinePiError("INVALID_REQUEST", "A JSON object is required.")
    return value


def success(data=None, status: int = 200):
    return jsonify({"ok": True, "data": data if data is not None else {}}), status


@ui.get("/")
def index():
    return render_template("index.html")


@api.get("/dashboard")
def dashboard():
    ops = services()["operations"]
    return success(
        {
            "system": ops.system_metrics(),
            "interfaces": services()["adapters"].list(),
            "operations": ops.active_operations(),
            "landscape": ops.landscape(),
        }
    )


@api.get("/interfaces")
def interfaces():
    adapters = services()["adapters"]
    ap_interface = request.args.get("ap_interface")
    return success({"interfaces": adapters.list(), "uplinks": adapters.uplinks(ap_interface)})


@api.route("/recon", methods=["GET", "POST", "DELETE"])
def recon():
    ops = services()["operations"]
    if request.method == "POST":
        data = body()
        return success(ops.start_recon(str(data.get("interface", "")), str(data.get("mode", "normal"))), 201)
    if request.method == "DELETE":
        return success(ops.stop_recon())
    return success({"status": ops.recon_status(), "results": ops.recon_results(), "history": ops.recon_history()})


@api.get("/recon/<session_id>")
def recon_session(session_id: str):
    return success(services()["operations"].recon_results(session_id))


@api.get("/recon/<session_id>/export.<kind>")
def recon_export(session_id: str, kind: str):
    exporter = ExportService(services()["database"], services()["events"], services()["operations"])
    data, filename, mimetype = exporter.recon(session_id, kind.lower())
    return send_file(BytesIO(data), mimetype=mimetype, as_attachment=True, download_name=filename, max_age=0)


@api.route("/access-point", methods=["GET", "POST", "DELETE"])
def access_point():
    ops = services()["operations"]
    if request.method == "POST":
        return success(ops.start_ap(body()), 201)
    if request.method == "DELETE":
        return success(ops.stop_ap())
    return success({"status": ops.ap_status(), "history": ops.ap_history()})


@api.get("/access-point/<session_id>/export.zip")
def ap_export(session_id: str):
    exporter = ExportService(services()["database"], services()["events"], services()["operations"])
    path, filename = exporter.ap_zip(session_id)
    response = send_file(path, mimetype="application/zip", as_attachment=True, download_name=filename, max_age=0)
    response.call_on_close(lambda: path.unlink(missing_ok=True))
    return response


@api.route("/captures", methods=["GET", "POST", "DELETE"])
def captures():
    ops = services()["operations"]
    if request.method == "POST":
        data = body()
        try:
            channel = int(data.get("channel", 6))
        except (TypeError, ValueError):
            raise PinePiError("INVALID_CHANNEL", "Channel must be a number.")
        return success(ops.start_capture(str(data.get("interface", "")), channel, str(data.get("name", "capture"))), 201)
    if request.method == "DELETE":
        return success(ops.stop_capture())
    return success({"status": ops.capture_status(), "history": ops.capture_history()})


@api.delete("/captures/<capture_id>")
def capture_delete(capture_id: str):
    services()["operations"].delete_capture(capture_id)
    return success()


@api.get("/captures/<capture_id>/download")
def capture_download(capture_id: str):
    ops = services()["operations"]
    row = services()["database"].fetchone("SELECT * FROM captures WHERE id=?", (capture_id,))
    if not row:
        raise PinePiError("CAPTURE_NOT_FOUND", "Capture not found.", 404)
    path = ops.authorized_path(row["path"], ops.data_dir / "captures")
    if not path.is_file():
        raise PinePiError("CAPTURE_FILE_MISSING", "Capture file is unavailable.", 404)
    return send_file(path, mimetype="application/vnd.tcpdump.pcap", as_attachment=True, download_name=f"{row['name']}_{capture_id[:8]}{path.suffix}", max_age=0)


@api.get("/captures/<capture_id>/summary.json")
def capture_summary(capture_id: str):
    exporter = ExportService(services()["database"], services()["events"], services()["operations"])
    data, filename, mimetype = exporter.capture_summary(capture_id)
    return send_file(BytesIO(data), mimetype=mimetype, as_attachment=True, download_name=filename, max_age=0)


@api.get("/logs")
def logs():
    try:
        limit = int(request.args.get("limit", "500"))
    except ValueError:
        raise PinePiError("INVALID_LIMIT", "Log limit must be a number.")
    rows = services()["events"].list(
        request.args.get("level") or None,
        request.args.get("component") or None,
        request.args.get("search") or None,
        limit,
    )
    for row in rows:
        try:
            row["context"] = json.loads(row.pop("context_json"))
        except json.JSONDecodeError:
            row["context"] = {}
    return success(rows)


@api.get("/logs/export.<kind>")
def logs_export(kind: str):
    exporter = ExportService(services()["database"], services()["events"], services()["operations"])
    data, filename, mimetype = exporter.logs(
        kind.lower(), request.args.get("level") or None, request.args.get("component") or None, request.args.get("search") or None
    )
    return send_file(BytesIO(data), mimetype=mimetype, as_attachment=True, download_name=filename, max_age=0)


@api.get("/health")
def health():
    return success({"status": "online", "version": "1.0.0"})
