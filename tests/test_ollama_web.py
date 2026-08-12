from __future__ import annotations

import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from fastapi.testclient import TestClient

from dolossec.config import settings
from dolossec.web.app import create_app


class FakeOllamaHandler(BaseHTTPRequestHandler):
    chat_calls = 0

    def log_message(self, format, *args):  # noqa: A003
        return

    def _json(self, status: int, payload: dict) -> None:
        data = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):  # noqa: N802
        if self.path == "/api/version":
            return self._json(200, {"version": "test-ollama"})
        if self.path == "/api/tags":
            return self._json(
                200,
                {
                    "models": [
                        {
                            "name": "qwen3.5:9b",
                            "model": "qwen3.5:9b",
                            "size": 1,
                            "details": {"parameter_size": "9B", "quantization_level": "Q4_K_M"},
                        }
                    ]
                },
            )
        return self._json(404, {"error": "not found"})

    def do_POST(self):  # noqa: N802
        if self.path != "/api/chat":
            return self._json(404, {"error": "not found"})
        length = int(self.headers.get("Content-Length", "0"))
        body = json.loads(self.rfile.read(length))
        context = json.loads(body["messages"][-1]["content"])
        FakeOllamaHandler.chat_calls += 1
        if FakeOllamaHandler.chat_calls == 1:
            output = {
                "summary": "Review the authorized source for high-signal security issues.",
                "actions": [
                    {
                        "tool": "source_review",
                        "arguments": {"path": context["target"]["value"]},
                        "reason": "Analyze the selected source tree.",
                    }
                ],
            }
        else:
            output = {
                "summary": "Evidence is sufficient for this test assessment.",
                "actions": [{"tool": "finish", "arguments": {}, "reason": "Complete the assessment."}],
            }
        return self._json(200, {"message": {"role": "assistant", "content": json.dumps(output)}, "done": True})


def test_web_scan_can_use_real_ollama_http_planner_path(tmp_path: Path):
    target = tmp_path / "ollama-target"
    target.mkdir()
    (target / "config.py").write_text('api_key = "hard-coded-example-secret"\n', encoding="utf-8")

    FakeOllamaHandler.chat_calls = 0
    server = ThreadingHTTPServer(("127.0.0.1", 0), FakeOllamaHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    old_url = settings.ollama_base_url
    old_allow_remote = settings.ollama_allow_remote
    settings.ollama_base_url = f"http://127.0.0.1:{server.server_port}"
    settings.ollama_allow_remote = False
    try:
        app = create_app()
        with TestClient(app) as client:
            ai = client.get("/api/ai/status")
            assert ai.status_code == 200
            assert ai.json()["ollama"]["reachable"] is True

            response = client.post(
                "/api/runs",
                json={
                    "target_type": "local_path",
                    "target": str(target),
                    "mode": "standard",
                    "planner_provider": "ollama",
                    "model": "qwen3.5:9b",
                },
            )
            assert response.status_code == 202
            assert response.json()["planner"] == "ollama"
            assert response.json()["planner_model"] == "qwen3.5:9b"
            run_id = response.json()["run_id"]

            final = None
            for _ in range(80):
                final = client.get(f"/api/runs/{run_id}").json()
                if final["status"] in {"completed", "failed"}:
                    break
                time.sleep(0.05)

            assert final is not None
            assert final["status"] == "completed"
            assert final["findings_count"] >= 1
            assert FakeOllamaHandler.chat_calls >= 2
    finally:
        settings.ollama_base_url = old_url
        settings.ollama_allow_remote = old_allow_remote
        server.shutdown()
        server.server_close()
