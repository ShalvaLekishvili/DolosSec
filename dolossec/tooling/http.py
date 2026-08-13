from __future__ import annotations

import asyncio
import re
from collections import deque
from html.parser import HTMLParser
from time import monotonic
from typing import Any
from urllib.parse import parse_qsl, urljoin, urlparse, urlunparse

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


def _clean_url(raw: str) -> str:
    parsed = urlparse(raw)
    # Fragments are client-side only and create duplicate crawl entries.
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path or "/", parsed.params, parsed.query, ""))


def _same_origin(base: str, candidate: str) -> bool:
    left = urlparse(base)
    right = urlparse(candidate)
    return (
        left.scheme.lower() == right.scheme.lower()
        and (left.hostname or "").lower() == (right.hostname or "").lower()
        and (left.port or (443 if left.scheme == "https" else 80))
        == (right.port or (443 if right.scheme == "https" else 80))
    )


class _SurfaceParser(HTMLParser):
    def __init__(self, page_url: str):
        super().__init__(convert_charrefs=True)
        self.page_url = page_url
        self.links: list[str] = []
        self.scripts: list[str] = []
        self.stylesheets: list[str] = []
        self.images: list[str] = []
        self.forms: list[dict[str, Any]] = []
        self.generator: str | None = None
        self._current_form: dict[str, Any] | None = None

    @staticmethod
    def _attrs(attrs: list[tuple[str, str | None]]) -> dict[str, str]:
        return {str(k).lower(): str(v or "") for k, v in attrs}

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        data = self._attrs(attrs)
        tag = tag.lower()
        if tag == "a" and data.get("href"):
            self.links.append(urljoin(self.page_url, data["href"]))
        elif tag == "script" and data.get("src"):
            self.scripts.append(urljoin(self.page_url, data["src"]))
        elif tag == "link" and data.get("href") and "stylesheet" in data.get("rel", "").lower():
            self.stylesheets.append(urljoin(self.page_url, data["href"]))
        elif tag == "img" and data.get("src"):
            self.images.append(urljoin(self.page_url, data["src"]))
        elif tag == "meta" and data.get("name", "").lower() == "generator":
            self.generator = data.get("content") or None
        elif tag == "form":
            self._current_form = {
                "page": self.page_url,
                "action": urljoin(self.page_url, data.get("action") or self.page_url),
                "method": (data.get("method") or "GET").upper(),
                "enctype": data.get("enctype") or "application/x-www-form-urlencoded",
                "inputs": [],
            }
            self.forms.append(self._current_form)
        elif tag in {"input", "textarea", "select"} and self._current_form is not None:
            self._current_form["inputs"].append(
                {
                    "name": data.get("name") or "",
                    "type": (data.get("type") or tag).lower(),
                    "autocomplete": data.get("autocomplete") or "",
                }
            )

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "form":
            self._current_form = None


class HttpProbeTool(Tool):
    name = "http_probe"

    def __init__(self, policy: ScopePolicy, transport: httpx.AsyncBaseTransport | None = None):
        self.policy = policy
        self.transport = transport
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

        async with httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=False,
            verify=True,
            trust_env=False,
            transport=self.transport,
        ) as client:
            for _ in range(max_redirects + 1):
                await self.limiter.wait()
                try:
                    async with client.stream(method, current, headers={"User-Agent": "DolosSec-Agent/0.5"}) as resp:
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
                            "set_cookies": resp.headers.get_list("set-cookie"),
                            "body_preview": bytes(body[:32768]).decode("utf-8", errors="replace"),
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

    def __init__(self, policy: ScopePolicy, transport: httpx.AsyncBaseTransport | None = None):
        self.http = HttpProbeTool(policy, transport=transport)

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


class WebInventoryTool(Tool):
    """Passive, same-origin attack-surface discovery.

    This tool intentionally does not submit forms, mutate state, brute-force paths, or send
    exploit payloads. It follows links already exposed by the application and inspects the
    responses that an ordinary browser can retrieve with GET/HEAD.
    """

    name = "web_inventory"

    def __init__(self, policy: ScopePolicy, transport: httpx.AsyncBaseTransport | None = None):
        self.policy = policy
        self.http = HttpProbeTool(policy, transport=transport)

    async def run(self, arguments: dict[str, Any]) -> Observation:
        start_url = _clean_url(str(arguments.get("url", "")))
        requested_pages = int(arguments.get("max_pages", 20) or 20)
        requested_depth = int(arguments.get("max_depth", 2) or 2)
        max_pages = max(1, min(requested_pages, 80))
        max_depth = max(0, min(requested_depth, 4))
        try:
            self.policy.assert_url_allowed(start_url)
        except Exception as exc:
            return Observation(tool=self.name, ok=False, error=str(exc))

        queue: deque[tuple[str, int]] = deque([(start_url, 0)])
        root = urlparse(start_url)
        origin = f"{root.scheme}://{root.netloc}"
        for well_known in ("/robots.txt", "/sitemap.xml"):
            candidate = _clean_url(urljoin(origin, well_known))
            if candidate != start_url:
                queue.append((candidate, 1))

        seen: set[str] = set()
        pages: list[dict[str, Any]] = []
        all_forms: list[dict[str, Any]] = []
        scripts: set[str] = set()
        external_scripts: set[str] = set()
        stylesheets: set[str] = set()
        api_hints: set[str] = set()
        parameters: set[str] = set()
        technologies: set[str] = set()
        cookies: list[dict[str, Any]] = []
        mixed_content: set[str] = set()

        while queue and len(pages) < max_pages:
            url, depth = queue.popleft()
            url = _clean_url(url)
            if url in seen or not _same_origin(start_url, url):
                continue
            seen.add(url)
            result = await self.http.run({"url": url, "method": "GET"})
            if not result.ok or not result.data.get("history"):
                pages.append({"url": url, "ok": False, "error": result.error})
                continue

            final = result.data["history"][-1]
            final_url = _clean_url(str(final.get("url") or url))
            headers = {k.lower(): v for k, v in (final.get("headers") or {}).items()}
            body = str(final.get("body_preview") or "")
            content_type = headers.get("content-type", "")
            page_record: dict[str, Any] = {
                "url": final_url,
                "status_code": final.get("status_code"),
                "content_type": content_type,
                "title": None,
                "links": 0,
                "forms": 0,
            }

            server = headers.get("server")
            powered = headers.get("x-powered-by")
            if server:
                technologies.add(f"server:{server}")
            if powered:
                technologies.add(f"x-powered-by:{powered}")

            acao = headers.get("access-control-allow-origin")
            acac = headers.get("access-control-allow-credentials")
            if acao:
                page_record["cors"] = {"allow_origin": acao, "allow_credentials": acac}

            for raw_cookie in final.get("set_cookies") or []:
                first, *attrs = [part.strip() for part in raw_cookie.split(";") if part.strip()]
                name = first.split("=", 1)[0].strip() if "=" in first else first
                attr_names = {part.split("=", 1)[0].strip().lower() for part in attrs}
                cookies.append(
                    {
                        "page": final_url,
                        "name": name,
                        "secure": "secure" in attr_names,
                        "httponly": "httponly" in attr_names,
                        "samesite": next((part.split("=", 1)[1] for part in attrs if part.lower().startswith("samesite=")), None),
                    }
                )

            for key, _ in parse_qsl(urlparse(final_url).query, keep_blank_values=True):
                if key:
                    parameters.add(key)

            if "html" in content_type.lower() or "<html" in body[:1000].lower():
                parser = _SurfaceParser(final_url)
                try:
                    parser.feed(body)
                except Exception:
                    pass

                title_match = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
                if title_match:
                    page_record["title"] = re.sub(r"\s+", " ", title_match.group(1)).strip()[:200]
                if parser.generator:
                    technologies.add(f"generator:{parser.generator}")

                page_record["links"] = len(parser.links)
                page_record["forms"] = len(parser.forms)
                all_forms.extend(parser.forms)
                stylesheets.update(parser.stylesheets)

                for script in parser.scripts:
                    if _same_origin(start_url, script):
                        scripts.add(_clean_url(script))
                    else:
                        external_scripts.add(script)
                    if final_url.startswith("https://") and script.startswith("http://"):
                        mixed_content.add(script)

                for resource in [*parser.stylesheets, *parser.images]:
                    if final_url.startswith("https://") and resource.startswith("http://"):
                        mixed_content.add(resource)

                candidates = [*parser.links, *(f.get("action", "") for f in parser.forms), *parser.scripts]
                for candidate in candidates:
                    low = candidate.lower()
                    if any(marker in low for marker in ("/api/", "/graphql", "swagger", "openapi", "/rest/")):
                        api_hints.add(candidate)
                    for key, _ in parse_qsl(urlparse(candidate).query, keep_blank_values=True):
                        if key:
                            parameters.add(key)

                if depth < max_depth:
                    for link in parser.links[:100]:
                        clean = _clean_url(link)
                        parsed = urlparse(clean)
                        if parsed.scheme not in {"http", "https"} or not _same_origin(start_url, clean):
                            continue
                        # Avoid obvious binary/media downloads during passive crawling.
                        if re.search(r"\.(?:png|jpe?g|gif|webp|svg|ico|pdf|zip|tar|gz|mp4|mp3|woff2?|ttf)(?:$|\?)", parsed.path, re.I):
                            continue
                        if clean not in seen:
                            queue.append((clean, depth + 1))

            pages.append(page_record)

        form_summaries: list[dict[str, Any]] = []
        for form in all_forms[:100]:
            inputs = form.get("inputs") or []
            form_summaries.append(
                {
                    "page": form.get("page"),
                    "action": form.get("action"),
                    "method": form.get("method"),
                    "enctype": form.get("enctype"),
                    "input_names": [i.get("name") for i in inputs if i.get("name")][:30],
                    "input_types": sorted({i.get("type") for i in inputs if i.get("type")}),
                    "has_password": any(i.get("type") == "password" for i in inputs),
                    "has_file_upload": any(i.get("type") == "file" for i in inputs),
                }
            )

        return Observation(
            tool=self.name,
            ok=True,
            data={
                "start_url": start_url,
                "pages_crawled": len(pages),
                "pages": pages,
                "forms": form_summaries,
                "scripts": sorted(scripts)[:200],
                "external_scripts": sorted(external_scripts)[:100],
                "stylesheets": sorted(stylesheets)[:100],
                "api_hints": sorted(api_hints)[:100],
                "parameters": sorted(parameters)[:200],
                "technologies": sorted(technologies)[:100],
                "cookies": cookies[:200],
                "mixed_content": sorted(mixed_content)[:100],
                "limits": {"max_pages": max_pages, "max_depth": max_depth},
            },
        )
