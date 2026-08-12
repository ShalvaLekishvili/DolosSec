from __future__ import annotations

import time
from pathlib import Path

from fastapi.testclient import TestClient

from dolossec.web.app import create_app, manager


def test_web_health_and_local_scan(tmp_path: Path):
    target = tmp_path / "sample"
    target.mkdir()
    (target / "app.py").write_text('password = "super-secret-value"\n', encoding="utf-8")

    app = create_app()
    with TestClient(app) as client:
        health = client.get("/api/health")
        assert health.status_code == 200
        assert health.json()["status"] == "ok"

        response = client.post(
            "/api/runs",
            json={"target_type": "local_path", "target": str(target), "mode": "standard"},
        )
        assert response.status_code == 202
        run_id = response.json()["run_id"]

        payload = None
        for _ in range(60):
            status = client.get(f"/api/runs/{run_id}")
            assert status.status_code == 200
            payload = status.json()
            if payload["status"] in {"completed", "failed"}:
                break
            time.sleep(0.05)

        assert payload is not None
        assert payload["status"] == "completed"
        assert payload["findings_count"] >= 1
        assert "DolosSec Security Assessment" in payload["report"]
        assert client.get(f"/api/runs/{run_id}/download/report").status_code == 200


def test_remote_scan_requires_authorization():
    app = create_app()
    with TestClient(app) as client:
        response = client.post(
            "/api/runs",
            json={"target_type": "url", "target": "https://example.com", "mode": "quick"},
        )
        assert response.status_code == 400
        assert "authorization" in response.json()["detail"].lower()


def test_non_local_browser_origin_is_denied(tmp_path: Path):
    app = create_app()
    with TestClient(app) as client:
        response = client.post(
            "/api/runs",
            headers={"Origin": "https://evil.example"},
            json={"target_type": "local_path", "target": str(tmp_path), "mode": "quick"},
        )
        assert response.status_code == 403


def test_deep_scan_requires_explicit_approval(tmp_path: Path):
    target = tmp_path / "deep-sample"
    target.mkdir()
    (target / "app.py").write_text('debug = True\n', encoding="utf-8")

    app = create_app()
    with TestClient(app) as client:
        response = client.post(
            "/api/runs",
            json={"target_type": "local_path", "target": str(target), "mode": "deep"},
        )
        assert response.status_code == 202
        payload = response.json()
        assert payload["status"] == "awaiting_approval"
        assert payload["approval_required"] is True
        run_id = payload["run_id"]

        approved = client.post(f"/api/runs/{run_id}/approve", json={"analyst": "test-analyst"})
        assert approved.status_code == 200
        assert approved.json()["approved_by"] == "test-analyst"

        final = None
        for _ in range(80):
            final = client.get(f"/api/runs/{run_id}").json()
            if final["status"] in {"completed", "failed"}:
                break
            time.sleep(0.05)
        assert final is not None
        assert final["status"] == "completed"
        assert final["approved_by"] == "test-analyst"


def test_history_and_capabilities_endpoints():
    app = create_app()
    with TestClient(app) as client:
        history = client.get("/api/runs")
        assert history.status_code == 200
        assert isinstance(history.json()["runs"], list)
        capabilities = client.get("/api/capabilities")
        assert capabilities.status_code == 200
        ids = {x["id"] for x in capabilities.json()["adapters"]}
        assert {"bandit_scan", "semgrep_scan", "trivy_fs_scan", "nuclei"}.issubset(ids)
        assert capabilities.json()["deep_requires_approval"] is True
