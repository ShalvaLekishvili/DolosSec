from __future__ import annotations

import asyncio
import ipaddress
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlparse

import yaml
from fastapi import FastAPI, Header, HTTPException, Query, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, PlainTextResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, field_validator

from ..agents.orchestrator import Orchestrator
from ..config import settings
from ..llm.deterministic import DeterministicPlanner
from ..models import Authorization, PolicySpec, ScopeManifest, ScopeSpec, Target, TargetKind
from ..policy import PolicyViolation, ScopePolicy


class AuthorizationInput(BaseModel):
    owner: str = Field(min_length=2, max_length=120)
    ticket: str = Field(min_length=2, max_length=120)
    purpose: str = Field(min_length=4, max_length=500)
    expires_hours: int = Field(default=24, ge=1, le=168)


class StartRunRequest(BaseModel):
    target_type: Literal["local_path", "url"]
    target: str = Field(min_length=1, max_length=4096)
    mode: Literal["quick", "standard", "deep"] = "standard"
    authorization: AuthorizationInput | None = None
    allow_private_networks: bool = False

    @field_validator("target")
    @classmethod
    def normalize_target(cls, value: str) -> str:
        return value.strip()


@dataclass
class RunState:
    run_id: str
    target: str
    target_type: str
    mode: str
    planner: str
    output_dir: Path
    status: str = "queued"
    current_stage: str = "Queued"
    findings_count: int = 0
    findings: list[dict[str, Any]] = field(default_factory=list)
    report: str = ""
    error: str | None = None
    created_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    started_at: str | None = None
    finished_at: str | None = None
    events: list[dict[str, Any]] = field(default_factory=list)
    condition: asyncio.Condition = field(default_factory=asyncio.Condition)

    def public(self, include_events: bool = False) -> dict[str, Any]:
        data = {
            "run_id": self.run_id,
            "target": self.target,
            "target_type": self.target_type,
            "mode": self.mode,
            "planner": self.planner,
            "status": self.status,
            "current_stage": self.current_stage,
            "findings_count": self.findings_count,
            "findings": self.findings,
            "report": self.report,
            "error": self.error,
            "created_at": self.created_at,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
        }
        if include_events:
            data["events"] = self.events
        return data


class RunManager:
    def __init__(self) -> None:
        self.runs: dict[str, RunState] = {}
        self.semaphore = asyncio.Semaphore(max(1, settings.web_max_concurrent_scans))

    async def emit(self, state: RunState, event: dict[str, Any]) -> None:
        event = dict(event)
        event["seq"] = len(state.events) + 1
        state.events.append(event)
        event_type = event.get("type", "")
        state.current_stage = event.get("message") or state.current_stage
        if event_type == "run_started":
            state.status = "running"
            state.started_at = event.get("timestamp")
        elif event_type == "findings_updated":
            state.findings = event.get("data", {}).get("findings", [])
            state.findings_count = len(state.findings)
        elif event_type == "run_finished":
            state.status = "completed"
            state.finished_at = event.get("timestamp")
        elif event_type == "run_failed":
            state.status = "failed"
            state.finished_at = event.get("timestamp")
        async with state.condition:
            state.condition.notify_all()

    def _planner(self):
        if settings.llm_provider.lower() == "openai":
            from ..llm.openai_provider import OpenAIPlanner

            return OpenAIPlanner(settings.model)
        return DeterministicPlanner()

    def _local_target(self, request: StartRunRequest) -> tuple[Target, ScopeManifest]:
        path = Path(request.target).expanduser().resolve()
        if not path.exists() or not path.is_dir():
            raise PolicyViolation(f"local target does not exist or is not a directory: {path}")
        manifest = ScopeManifest(
            authorization=Authorization(
                owner="local-operator",
                ticket="LOCAL-WEB-REVIEW",
                purpose="Local source-code security review via DolosSec web UI",
                expires_at=datetime.now(UTC) + timedelta(hours=24),
            ),
            scope=ScopeSpec(local_paths=[str(path)]),
            policy=PolicySpec(),
        )
        return Target(kind=TargetKind.local_path, value=str(path)), manifest

    def _url_target(self, request: StartRunRequest) -> tuple[Target, ScopeManifest]:
        parsed = urlparse(request.target)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise PolicyViolation("enter a valid http:// or https:// target URL")
        if request.authorization is None:
            raise PolicyViolation("remote URL scans require authorization details")

        host = parsed.hostname
        hosts: list[str] = []
        cidrs: list[str] = []
        try:
            ip = ipaddress.ip_address(host)
            cidrs.append(f"{ip}/{32 if ip.version == 4 else 128}")
        except ValueError:
            hosts.append(host)

        auth = request.authorization
        manifest = ScopeManifest(
            authorization=Authorization(
                owner=auth.owner,
                ticket=auth.ticket,
                purpose=auth.purpose,
                expires_at=datetime.now(UTC) + timedelta(hours=auth.expires_hours),
            ),
            scope=ScopeSpec(urls=[request.target], hosts=hosts, cidrs=cidrs),
            policy=PolicySpec(allow_private_networks=request.allow_private_networks),
        )
        return Target(kind=TargetKind.url, value=request.target), manifest

    async def start(self, request: StartRunRequest) -> RunState:
        if request.target_type == "local_path":
            target, manifest = self._local_target(request)
        else:
            target, manifest = self._url_target(request)

        policy = ScopePolicy(manifest)
        policy.validate_initial_target(target)
        planner = self._planner()
        orchestrator = Orchestrator(target, planner, policy, request.mode, None)
        state = RunState(
            run_id=orchestrator.run_id,
            target=target.value,
            target_type=target.kind.value,
            mode=request.mode,
            planner=planner.name,
            output_dir=orchestrator.output_dir,
        )
        self.runs[state.run_id] = state

        orchestrator.output_dir.mkdir(parents=True, exist_ok=True)
        scope_path = orchestrator.output_dir / "scope.yaml"
        scope_path.write_text(
            yaml.safe_dump(manifest.model_dump(mode="json"), sort_keys=False),
            encoding="utf-8",
        )
        orchestrator.scope_file = str(scope_path)
        orchestrator.progress_sink = lambda event: self.emit(state, event)
        asyncio.create_task(self._execute(orchestrator, state))
        return state

    async def _execute(self, orchestrator: Orchestrator, state: RunState) -> None:
        async with self.semaphore:
            try:
                state.status = "running"
                record = await orchestrator.run()
                state.findings_count = record.findings_count
                findings_path = state.output_dir / "findings.json"
                report_path = state.output_dir / "report.md"
                if findings_path.exists():
                    state.findings = json.loads(findings_path.read_text(encoding="utf-8"))
                if report_path.exists():
                    state.report = report_path.read_text(encoding="utf-8")
                state.status = "completed"
                state.finished_at = record.finished_at.isoformat() if record.finished_at else datetime.now(UTC).isoformat()
            except Exception as exc:  # boundary: surface a safe UI error and preserve server availability
                state.error = str(exc)
                await self.emit(
                    state,
                    {
                        "type": "run_failed",
                        "message": "Assessment failed",
                        "timestamp": datetime.now(UTC).isoformat(),
                        "data": {"error": str(exc)},
                    },
                )

    def get(self, run_id: str) -> RunState:
        state = self.runs.get(run_id)
        if state:
            return state
        raise HTTPException(status_code=404, detail="run not found")


manager = RunManager()


def _is_loopback_origin(origin: str) -> bool:
    try:
        host = urlparse(origin).hostname
        if host == "localhost":
            return True
        return bool(host and ipaddress.ip_address(host).is_loopback)
    except ValueError:
        return False


def create_app() -> FastAPI:
    app = FastAPI(title="DolosSec Web", version="0.2.0", docs_url=None, redoc_url=None)
    static_dir = Path(__file__).resolve().parent / "static"
    app.mount("/static", StaticFiles(directory=static_dir), name="static")

    @app.middleware("http")
    async def origin_guard(request: Request, call_next):
        if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
            origin = request.headers.get("origin")
            if origin and not _is_loopback_origin(origin):
                return JSONResponse(status_code=403, content={"detail": "non-local browser origin denied"})
        return await call_next(request)

    @app.get("/", response_class=HTMLResponse)
    async def index() -> FileResponse:
        return FileResponse(static_dir / "index.html")

    @app.get("/api/health")
    async def health() -> dict[str, Any]:
        return {
            "status": "ok",
            "planner": settings.llm_provider,
            "model": settings.model or None,
            "output_dir": str(settings.output_dir.resolve()),
            "browse_root": str(settings.web_browse_root.expanduser().resolve()),
        }

    @app.get("/api/fs")
    async def browse_filesystem(path: str | None = Query(default=None)) -> dict[str, Any]:
        root = settings.web_browse_root.expanduser().resolve()
        requested = Path(path).expanduser().resolve() if path else root
        if requested != root and root not in requested.parents:
            raise HTTPException(status_code=403, detail="directory browser is restricted to the configured browse root")
        if not requested.exists() or not requested.is_dir():
            raise HTTPException(status_code=404, detail="directory not found")
        directories: list[dict[str, str]] = []
        try:
            children = sorted((p for p in requested.iterdir() if p.is_dir()), key=lambda p: p.name.lower())
        except PermissionError as exc:
            raise HTTPException(status_code=403, detail="permission denied") from exc
        for child in children[:250]:
            try:
                resolved = child.resolve()
            except OSError:
                continue
            if resolved == root or root in resolved.parents:
                directories.append({"name": child.name, "path": str(resolved)})
        parent = requested.parent if requested != root else None
        return {
            "root": str(root),
            "path": str(requested),
            "parent": str(parent) if parent and (parent == root or root in parent.parents) else None,
            "directories": directories,
        }

    @app.post("/api/runs", status_code=202)
    async def start_run(body: StartRunRequest) -> dict[str, Any]:
        try:
            state = await manager.start(body)
        except (PolicyViolation, ValueError, OSError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return state.public()

    @app.get("/api/runs/{run_id}")
    async def run_status(run_id: str) -> dict[str, Any]:
        return manager.get(run_id).public(include_events=True)

    @app.get("/api/runs/{run_id}/events")
    async def run_events(
        run_id: str,
        request: Request,
        last_event_id: str | None = Header(default=None, alias="Last-Event-ID"),
    ) -> StreamingResponse:
        state = manager.get(run_id)
        try:
            start_at = max(0, int(last_event_id or "0"))
        except ValueError:
            start_at = 0

        async def stream():
            cursor = start_at
            while True:
                while cursor < len(state.events):
                    event = state.events[cursor]
                    cursor += 1
                    payload = json.dumps(event, default=str)
                    yield f"id: {event['seq']}\nevent: progress\ndata: {payload}\n\n"
                if state.status in {"completed", "failed"}:
                    yield "event: done\ndata: {}\n\n"
                    break
                if await request.is_disconnected():
                    break
                try:
                    async with state.condition:
                        await asyncio.wait_for(state.condition.wait(), timeout=15)
                except TimeoutError:
                    yield ": keep-alive\n\n"

        return StreamingResponse(
            stream(),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
        )

    @app.get("/api/runs/{run_id}/report", response_class=PlainTextResponse)
    async def run_report(run_id: str) -> PlainTextResponse:
        state = manager.get(run_id)
        report = state.output_dir / "report.md"
        if not report.exists():
            raise HTTPException(status_code=404, detail="report is not ready")
        return PlainTextResponse(report.read_text(encoding="utf-8"), media_type="text/markdown")

    @app.get("/api/runs/{run_id}/download/{artifact}")
    async def download_artifact(run_id: str, artifact: Literal["report", "findings", "audit", "run", "scope"]):
        state = manager.get(run_id)
        names = {
            "report": "report.md",
            "findings": "findings.json",
            "audit": "audit.jsonl",
            "run": "run.json",
            "scope": "scope.yaml",
        }
        path = state.output_dir / names[artifact]
        if not path.exists():
            raise HTTPException(status_code=404, detail="artifact is not ready")
        return FileResponse(path, filename=path.name)

    return app


app = create_app()
