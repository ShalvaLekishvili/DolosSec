from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest

from dolossec.models import Authorization, PolicySpec, ScopeManifest, ScopeSpec
from dolossec.policy import ScopePolicy
from dolossec.reporting import findings_from_observations, write_reports
from dolossec.tooling.http import WebInventoryTool


def _policy() -> ScopePolicy:
    return ScopePolicy(
        ScopeManifest(
            authorization=Authorization(
                owner="tester",
                ticket="WEB-TEST",
                purpose="authorized test fixture",
                expires_at=datetime.now(UTC) + timedelta(hours=1),
            ),
            scope=ScopeSpec(urls=["https://example.test"], hosts=["example.test"]),
            policy=PolicySpec(requests_per_second=20, max_response_bytes=200_000),
        )
    )


@pytest.mark.asyncio
async def test_web_inventory_is_target_specific_and_passive(tmp_path: Path):
    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/":
            html = """<html><head><title>Acme Portal</title><meta name='generator' content='DemoCMS 2'></head>
            <body>
              <a href='/login?next=/account'>Login</a>
              <a href='/api/docs'>API docs</a>
              <script src='/static/app.js'></script>
            </body></html>"""
            return httpx.Response(
                200,
                text=html,
                headers={
                    "content-type": "text/html",
                    "x-powered-by": "DemoFramework/1.2",
                    "set-cookie": "sessionid=abc123; Path=/; SameSite=Lax",
                },
            )
        if path == "/login":
            return httpx.Response(
                200,
                text="""<html><head><title>Login</title></head><body>
                <form action='/session' method='post'>
                  <input name='username'><input name='password' type='password'>
                </form></body></html>""",
                headers={"content-type": "text/html"},
            )
        if path == "/api/docs":
            return httpx.Response(200, text="<html><title>API</title></html>", headers={"content-type": "text/html"})
        if path == "/robots.txt":
            return httpx.Response(200, text="User-agent: *\nDisallow: /internal\n", headers={"content-type": "text/plain"})
        if path == "/sitemap.xml":
            return httpx.Response(404, text="not found", headers={"content-type": "text/plain"})
        return httpx.Response(404, text="not found")

    tool = WebInventoryTool(_policy(), transport=httpx.MockTransport(handler))
    obs = await tool.run({"url": "https://example.test", "max_pages": 10, "max_depth": 2})

    assert obs.ok is True
    assert obs.data["pages_crawled"] >= 4
    assert any(p.get("url", "").startswith("https://example.test/login") for p in obs.data["pages"])
    assert any(f.get("has_password") for f in obs.data["forms"])
    assert "next" in obs.data["parameters"]
    assert "https://example.test/static/app.js" in obs.data["scripts"]
    assert any("/api/docs" in x for x in obs.data["api_hints"])
    assert "generator:DemoCMS 2" in obs.data["technologies"]
    assert "x-powered-by:DemoFramework/1.2" in obs.data["technologies"]

    findings = findings_from_observations([obs], "https://example.test")
    titles = {f.title for f in findings}
    assert "Session-like cookie missing HttpOnly: sessionid" in titles
    assert "Cookie missing Secure attribute: sessionid" in titles
    assert "Technology disclosure via X-Powered-By" in titles

    write_reports(tmp_path, findings, [obs])
    report = (tmp_path / "report.md").read_text(encoding="utf-8")
    assert "## Web attack surface" in report
    assert "Acme" not in report  # titles are not used as security claims
    assert "https://example.test/login?next=/account" in report
    assert "Forms discovered: **1**" in report
    assert "API / service hints" in report
