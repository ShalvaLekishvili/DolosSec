from __future__ import annotations

import asyncio
from collections import deque
from time import monotonic
from typing import Any
from urllib.parse import urljoin

import httpx

from ..models import Observation
from ..policy import ScopePolicy
from .base import Tool


class RateLimiter:
    def __init__(self, per_second: float):
        self.interval = 1.0 / per_second
        self.last = 0.0
        self.lock = asyncio.Lock()

    async def wait(self) -> None:
        async with self.lock:
            delay = self.interval - (monotonic() - self.last)
            if delay > 0:
                await asyncio.sleep(delay)
            self.last = monotonic()


class HttpProbeTool(Tool):
    name = "http_probe"

    def __init__(self, policy: ScopePolicy):
        self.policy = policy
        self.limiter = RateLimiter(policy.manifest.policy.requests_per_second)

    async def run(self, arguments: dict[str, Any]) -> Observation:
        url = str(arguments.get("url", ""))
        method = str(arguments.get("method", "GET")).upper()
        try:
            self.policy.assert_url_allowed(url)
            self.policy.assert_method_allowed(method)
            host = httpx.URL(url).host
            if host:
                self.policy.validate_resolved_ips(host)
        except Exception as exc:
            return Observation(tool=self.name, ok=False, error=str(exc))

        max_redirects = self.policy.manifest.policy.max_redirects
        max_bytes = self.policy.manifest.policy.max_response_bytes
        timeout = self.policy.manifest.policy.request_timeout_seconds
        history: list[dict[str, Any]] = []
        current = url

        async with httpx.AsyncClient(timeout=timeout, follow_redirects=False, verify=True) as client:
            for _ in range(max_redirects + 1):
                await self.limiter.wait()
                try:
                    async with client.stream(method, current, headers={"User-Agent": "DolosSec-Agent/0.1"}) as resp:
                        body = bytearray()
                        async for chunk in resp.aiter_bytes():
                            remaining = max_bytes - len(body)
                            if remaining <= 0:
                                break
                            body.extend(chunk[:remaining])
                        item = {
                            "url": current,
                            "status_code": resp.status_code,
                            "headers": dict(resp.headers),
                            "body_preview": bytes(body[:8192]).decode("utf-8", errors="replace"),
                            "truncated": len(body) >= max_bytes,
                        }
                        history.append(item)
                        if resp.status_code not in {301, 302, 303, 307, 308}:
                            return Observation(tool=self.name, ok=True, data={"history": history})
                        location = resp.headers.get("location")
                        if not location:
                            return Observation(tool=self.name, ok=True, data={"history": history})
                        next_url = urljoin(current, location)
                        self.policy.assert_url_allowed(next_url)
                        next_host = httpx.URL(next_url).host
                        if next_host:
                            self.policy.validate_resolved_ips(next_host)
                        current = next_url
                except Exception as exc:
                    return Observation(tool=self.name, ok=False, data={"history": history}, error=str(exc))

        return Observation(tool=self.name, ok=False, data={"history": history}, error="redirect limit exceeded")


class SecurityHeadersTool(Tool):
    name = "security_headers"

    def __init__(self, policy: ScopePolicy):
        self.http = HttpProbeTool(policy)

    async def run(self, arguments: dict[str, Any]) -> Observation:
        url = str(arguments.get("url", ""))
        result = await self.http.run({"url": url, "method": "HEAD"})
        if not result.ok:
            result = await self.http.run({"url": url, "method": "GET"})
        if not result.ok:
            return Observation(tool=self.name, ok=False, error=result.error, data=result.data)
        final = result.data["history"][-1]
        headers = {k.lower(): v for k, v in final.get("headers", {}).items()}
        expected = {
            "content-security-policy": "CSP reduces script injection impact",
            "strict-transport-security": "HSTS enforces HTTPS on future requests",
            "x-content-type-options": "nosniff reduces MIME confusion",
            "referrer-policy": "limits referrer data leakage",
        }
        missing = {k: why for k, why in expected.items() if k not in headers}
        return Observation(
            tool=self.name,
            ok=True,
            data={"url": final.get("url"), "status_code": final.get("status_code"), "missing": missing, "headers": headers},
        )
