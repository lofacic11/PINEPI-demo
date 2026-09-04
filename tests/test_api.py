from __future__ import annotations

from pinepi import create_app


def test_health_and_idle_status_gets_are_machine_readable(tmp_path, service):
    operations, privileged, _registry, _database = service
    app = create_app({
        "TESTING": True,
        "DATA_DIR": tmp_path / "app",
        "DATABASE": tmp_path / "app" / "api.db",
        "PRIVILEGED_SERVICE": privileged,
        "ADAPTER_SERVICE": operations.adapters,
        "RECONCILE_ON_STARTUP": False,
    })
    client = app.test_client()
    health = client.get("/api/health")
    assert health.status_code == 200
    assert health.get_json()["data"]["status"] == "online"
    for path in ("/api/recon", "/api/access-point", "/api/captures", "/api/logs"):
        response = client.get(path)
        assert response.status_code == 200
        assert response.get_json()["ok"] is True


def test_invalid_json_has_stable_error_shape(tmp_path, service):
    operations, privileged, _registry, _database = service
    app = create_app({
        "TESTING": True, "DATA_DIR": tmp_path / "app2", "DATABASE": tmp_path / "app2" / "api.db",
        "PRIVILEGED_SERVICE": privileged, "ADAPTER_SERVICE": operations.adapters, "RECONCILE_ON_STARTUP": False,
    })
    response = app.test_client().post("/api/recon", data="bad", content_type="application/json")
    assert response.status_code == 400
    assert response.get_json()["error"]["code"] == "INVALID_REQUEST"
