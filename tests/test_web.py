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


def test_remote_web_scan_builds_target_specific_surface():
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from threading import Thread

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            return

        def do_HEAD(self):
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()

        def do_GET(self):
            if self.path.startswith("/login"):
                body = b"<html><title>Login</title><form method='post' action='/session'><input name='user'><input type='password' name='password'></form></html>"
                code = 200
            elif self.path == "/robots.txt":
                body = b"User-agent: *\nDisallow: /private\n"
                code = 200
            elif self.path == "/sitemap.xml":
                body = b"not found"
                code = 404
            else:
                body = b"<html><title>Fixture Home</title><a href='/login?next=/account'>Login</a><a href='/api/docs'>API</a><script src='/static/app.js'></script></html>"
                code = 200
            self.send_response(code)
            self.send_header("Content-Type", "text/html" if self.path != "/robots.txt" else "text/plain")
            self.send_header("X-Powered-By", "FixtureFramework/1.0")
            self.end_headers()
            self.wfile.write(body)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        port = server.server_address[1]
        target = f"http://127.0.0.1:{port}/"
        app = create_app()
        with TestClient(app) as client:
            response = client.post(
                "/api/runs",
                json={
                    "target_type": "url",
                    "target": target,
                    "mode": "quick",
                    "planner_provider": "deterministic",
                    "allow_private_networks": True,
                    "authorization": {
                        "owner": "test-owner",
                        "ticket": "WEB-E2E",
                        "purpose": "authorized local HTTP fixture",
                        "expires_hours": 1,
                    },
                },
            )
            assert response.status_code == 202, response.text
            run_id = response.json()["run_id"]
            payload = None
            for _ in range(100):
                payload = client.get(f"/api/runs/{run_id}").json()
                if payload["status"] in {"completed", "failed"}:
                    break
                time.sleep(0.05)
            assert payload is not None
            assert payload["status"] == "completed", payload.get("error")
            assert payload["surface"]["pages_crawled"] >= 3
            assert any("/login" in p.get("url", "") for p in payload["surface"]["pages"])
            assert any(f.get("has_password") for f in payload["surface"]["forms"])
            assert "next" in payload["surface"]["parameters"]
            assert "## Web attack surface" in payload["report"]
            assert "/login?next=/account" in payload["report"]
    finally:
        server.shutdown()
        server.server_close()
