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
from ..llm.factory import create_planner
from ..llm.ollama_provider import ollama_status
from ..models import Authorization, PolicySpec, ScopeManifest, ScopeSpec, Target, TargetKind
from ..policy import PolicyViolation, ScopePolicy, load_manifest
from ..tooling.external import adapter_capabilities

ALLOWED_ADAPTERS = {"bandit_scan", "semgrep_scan", "trivy_fs_scan"}


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
    enabled_adapters: list[str] = Field(default_factory=list, max_length=3)
    planner_provider: Literal["default", "deterministic", "ollama", "openai"] = "default"
    model: str | None = Field(default=None, max_length=200)

    @field_validator("target")
    @classmethod
    def normalize_target(cls, value: str) -> str:
        return value.strip()

    @field_validator("enabled_adapters")
    @classmethod
    def validate_adapters(cls, values: list[str]) -> list[str]:
        clean = list(dict.fromkeys(values))
        invalid = [x for x in clean if x not in ALLOWED_ADAPTERS]
        if invalid:
            raise ValueError(f"unsupported adapter(s): {', '.join(invalid)}")
        return clean


class ApprovalRequest(BaseModel):
    analyst: str = Field(min_length=2, max_length=120)


@dataclass
class RunState:
    run_id: str
    target: str
    target_type: str
    mode: str
    planner: str
    planner_model: str | None
    output_dir: Path
    status: str = "queued"
    current_stage: str = "Queued"
    findings_count: int = 0
    findings: list[dict[str, Any]] = field(default_factory=list)
    surface: dict[str, Any] = field(default_factory=dict)
    report: str = ""
    error: str | None = None
    created_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    started_at: str | None = None
    finished_at: str | None = None
    events: list[dict[str, Any]] = field(default_factory=list)
    enabled_adapters: list[str] = field(default_factory=list)
    approval_required: bool = False
    approved_by: str | None = None
    approved_at: str | None = None
    condition: asyncio.Condition = field(default_factory=asyncio.Condition, repr=False)
    orchestrator: Orchestrator | None = field(default=None, repr=False)
    task: asyncio.Task[Any] | None = field(default=None, repr=False)

    def severity_counts(self) -> dict[str, int]:
        counts = {k: 0 for k in ["critical", "high", "medium", "low", "info"]}
        for finding in self.findings:
            sev = str(finding.get("severity", "info"))
            counts[sev] = counts.get(sev, 0) + 1
        return counts

    def public(self, include_events: bool = False, include_report: bool = True) -> dict[str, Any]:
        data = {
            "run_id": self.run_id,
            "target": self.target,
            "target_type": self.target_type,
            "mode": self.mode,
            "planner": self.planner,
            "planner_model": self.planner_model,
            "status": self.status,
            "current_stage": self.current_stage,
            "findings_count": self.findings_count,
            "severity_counts": self.severity_counts(),
            "findings": self.findings,
            "surface": self.surface,
            "report": self.report if include_report else "",
            "error": self.error,
            "created_at": self.created_at,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "enabled_adapters": self.enabled_adapters,
            "approval_required": self.approval_required,
            "approved_by": self.approved_by,
            "approved_at": self.approved_at,
        }
        if include_events:
            data["events"] = self.events
        return data


class RunManager:
    def __init__(self) -> None:
        self.runs: dict[str, RunState] = {}
        self.semaphore = asyncio.Semaphore(max(1, settings.web_max_concurrent_scans))
        self._hydrate_history()

    def _state_file(self, state: RunState) -> Path:
        return state.output_dir / "web_state.json"

    def _persist(self, state: RunState) -> None:
        state.output_dir.mkdir(parents=True, exist_ok=True)
        payload = state.public(include_events=True, include_report=False)
        self._state_file(state).write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")

    def _hydrate_history(self) -> None:
        root = settings.output_dir.expanduser().resolve()
        if not root.exists():
            return
        for run_dir in sorted((p for p in root.iterdir() if p.is_dir()), reverse=True):
            state_file = run_dir / "web_state.json"
            run_file = run_dir / "run.json"
            try:
                if state_file.exists():
                    raw = json.loads(state_file.read_text(encoding="utf-8"))
                    status = raw.get("status", "unknown")
                    if status in {"running", "queued"}:
                        status = "interrupted"
                    state = RunState(
                        run_id=raw["run_id"], target=raw["target"], target_type=raw["target_type"],
                        mode=raw.get("mode", "standard"), planner=raw.get("planner", "unknown"),
                        planner_model=raw.get("planner_model"), output_dir=run_dir, status=status, current_stage=raw.get("current_stage", status.title()),
                        findings_count=raw.get("findings_count", 0), findings=raw.get("findings", []), surface=raw.get("surface", {}),
                        error=raw.get("error"), created_at=raw.get("created_at", ""), started_at=raw.get("started_at"),
                        finished_at=raw.get("finished_at"), events=raw.get("events", []),
                        enabled_adapters=raw.get("enabled_adapters", []), approval_required=raw.get("approval_required", False),
                        approved_by=raw.get("approved_by"), approved_at=raw.get("approved_at"),
                    )
                elif run_file.exists():
                    raw = json.loads(run_file.read_text(encoding="utf-8"))
                    target = raw.get("target", {})
                    state = RunState(
                        run_id=raw["run_id"], target=target.get("value", ""), target_type=target.get("kind", "local_path"),
                        mode=raw.get("mode", "standard"), planner=raw.get("planner", "unknown"), planner_model=raw.get("planner_model"), output_dir=run_dir,
                        status="completed", current_stage="Assessment complete", findings_count=raw.get("findings_count", 0),
                        created_at=raw.get("started_at", ""), started_at=raw.get("started_at"), finished_at=raw.get("finished_at"),
                        enabled_adapters=raw.get("enabled_adapters", []), approval_required=raw.get("approval_required", False),
                        approved_by=raw.get("approved_by"), approved_at=raw.get("approved_at"),
                    )
                else:
                    continue
                findings_path = run_dir / "findings.json"
                report_path = run_dir / "report.md"
                if findings_path.exists():
                    state.findings = json.loads(findings_path.read_text(encoding="utf-8"))
                    state.findings_count = len(state.findings)
                if report_path.exists():
                    state.report = report_path.read_text(encoding="utf-8")
                observations_path = run_dir / "observations.json"
                if observations_path.exists() and not state.surface:
                    try:
                        observations = json.loads(observations_path.read_text(encoding="utf-8"))
                        inv = next((o for o in observations if o.get("tool") == "web_inventory" and o.get("ok")), None)
                        if inv:
                            state.surface = inv.get("data") or {}
                    except (ValueError, json.JSONDecodeError):
                        pass
                self.runs[state.run_id] = state
            except (OSError, ValueError, KeyError, json.JSONDecodeError):
                continue

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
        elif event_type == "tool_completed" and event.get("data", {}).get("tool") == "web_inventory":
            state.surface = event.get("data", {}).get("data") or {}
        elif event_type == "run_finished":
            state.status = "completed"
            state.finished_at = event.get("timestamp")
        elif event_type == "run_failed":
            state.status = "failed"
            state.finished_at = event.get("timestamp")
        self._persist(state)
        async with state.condition:
            state.condition.notify_all()

    async def _planner_for_request(self, request: StartRunRequest):
        provider = settings.llm_provider if request.planner_provider == "default" else request.planner_provider
        model = (request.model or settings.model).strip()
        if provider.lower() == "ollama":
            if not model:
                model = "qwen3.5:9b"
            status = await ollama_status()
            if not status["reachable"]:
                raise PolicyViolation(
                    "Ollama is not reachable. Install/start Ollama, then run `dolos ollama status`. "
                    f"Details: {status.get('error') or 'connection failed'}"
                )
            installed = {str(item.get("name")) for item in status.get("models", [])}
            if model not in installed:
                raise PolicyViolation(
                    f"Ollama model {model!r} is not installed. Run: ollama pull {model}"
                )
        return create_planner(provider, model)

    def _local_target(self, request: StartRunRequest) -> tuple[Target, ScopeManifest]:
        path = Path(request.target).expanduser().resolve()
        if not path.exists() or not path.is_dir():
            raise PolicyViolation(f"local target does not exist or is not a directory: {path}")
        manifest = ScopeManifest(
            authorization=Authorization(
                owner="local-operator", ticket="LOCAL-WEB-REVIEW",
                purpose="Local source-code security review via DolosSec web UI",
                expires_at=datetime.now(UTC) + timedelta(hours=24),
            ),
            scope=ScopeSpec(local_paths=[str(path)]), policy=PolicySpec(),
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
            authorization=Authorization(owner=auth.owner, ticket=auth.ticket, purpose=auth.purpose,
                                        expires_at=datetime.now(UTC) + timedelta(hours=auth.expires_hours)),
            scope=ScopeSpec(urls=[request.target], hosts=hosts, cidrs=cidrs),
            policy=PolicySpec(allow_private_networks=request.allow_private_networks),
        )
        return Target(kind=TargetKind.url, value=request.target), manifest

    def _make_orchestrator(self, state: RunState) -> Orchestrator:
        scope_path = state.output_dir / "scope.yaml"
        manifest = load_manifest(scope_path)
        target = Target(kind=TargetKind(state.target_type), value=state.target)
        policy = ScopePolicy(manifest)
        policy.validate_initial_target(target)
        planner = create_planner(state.planner, state.planner_model)
        approved_at = datetime.fromisoformat(state.approved_at) if state.approved_at else None
        orchestrator = Orchestrator(
            target, planner, policy, state.mode, str(scope_path), enabled_adapters=state.enabled_adapters,
            approval_required=state.approval_required, approved_by=state.approved_by, approved_at=approved_at,
            run_id=state.run_id,
        )
        orchestrator.progress_sink = lambda event: self.emit(state, event)
        return orchestrator

    async def start(self, request: StartRunRequest) -> RunState:
        if request.target_type == "local_path":
            target, manifest = self._local_target(request)
        else:
            target, manifest = self._url_target(request)
            if request.enabled_adapters:
                raise PolicyViolation("source adapters can only be enabled for local directory targets")

        if request.enabled_adapters and not settings.enable_external_tools:
            raise PolicyViolation("external adapters are disabled by server policy; set DOLOS_ENABLE_EXTERNAL_TOOLS=true to opt in")

        policy = ScopePolicy(manifest)
        policy.validate_initial_target(target)
        planner = await self._planner_for_request(request)
        approval_required = request.mode == "deep"
        orchestrator = Orchestrator(
            target, planner, policy, request.mode, None, enabled_adapters=request.enabled_adapters,
            approval_required=approval_required,
        )
        status = "awaiting_approval" if approval_required else "queued"
        stage = "Analyst approval required" if approval_required else "Queued"
        state = RunState(
            run_id=orchestrator.run_id, target=target.value, target_type=target.kind.value, mode=request.mode,
            planner=planner.name, planner_model=getattr(planner, "model", None), output_dir=orchestrator.output_dir, status=status, current_stage=stage,
            enabled_adapters=request.enabled_adapters, approval_required=approval_required, orchestrator=orchestrator,
        )
        self.runs[state.run_id] = state
        state.output_dir.mkdir(parents=True, exist_ok=True)
        scope_path = state.output_dir / "scope.yaml"
        scope_path.write_text(yaml.safe_dump(manifest.model_dump(mode="json"), sort_keys=False), encoding="utf-8")
        orchestrator.scope_file = str(scope_path)
        orchestrator.progress_sink = lambda event: self.emit(state, event)
        self._persist(state)

        if approval_required:
            await self.emit(state, {
                "type": "approval_required", "message": "Deep assessment is waiting for analyst approval",
                "timestamp": datetime.now(UTC).isoformat(),
                "data": {"agent": "policy-gate", "reason": "Deep mode enables an extended assessment loop"},
            })
        else:
            state.task = asyncio.create_task(self._execute(orchestrator, state))
        return state

    async def approve(self, run_id: str, analyst: str) -> RunState:
        state = self.get(run_id)
        if not state.approval_required:
            raise HTTPException(status_code=409, detail="this run does not require approval")
        if state.status != "awaiting_approval":
            raise HTTPException(status_code=409, detail=f"run cannot be approved from status {state.status}")
        state.approved_by = analyst
        state.approved_at = datetime.now(UTC).isoformat()
        state.status = "queued"
        state.current_stage = "Approved; waiting for execution slot"
        orchestrator = state.orchestrator or self._make_orchestrator(state)
        orchestrator.approved_by = analyst
        orchestrator.approved_at = datetime.fromisoformat(state.approved_at)
        orchestrator.progress_sink = lambda event: self.emit(state, event)
        state.orchestrator = orchestrator
        await self.emit(state, {
            "type": "approval_granted", "message": f"Deep assessment approved by {analyst}",
            "timestamp": state.approved_at, "data": {"agent": "policy-gate", "analyst": analyst},
        })
        state.task = asyncio.create_task(self._execute(orchestrator, state))
        return state

    async def _execute(self, orchestrator: Orchestrator, state: RunState) -> None:
        async with self.semaphore:
            try:
                state.status = "running"
                self._persist(state)
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
                self._persist(state)
            except Exception as exc:
                state.error = str(exc)
                await self.emit(state, {
                    "type": "run_failed", "message": "Assessment failed", "timestamp": datetime.now(UTC).isoformat(),
                    "data": {"error": str(exc), "agent": "orchestrator"},
                })

    def get(self, run_id: str) -> RunState:
        state = self.runs.get(run_id)
        if state:
            return state
        raise HTTPException(status_code=404, detail="run not found")

    def list(self, limit: int = 50) -> list[dict[str, Any]]:
        states = sorted(self.runs.values(), key=lambda s: s.created_at or "", reverse=True)[:limit]
        return [s.public(include_events=False, include_report=False) for s in states]


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
    app = FastAPI(title="DolosSec Web", version="0.4.0", docs_url=None, redoc_url=None)
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
            "status": "ok", "version": "0.4.0", "planner": settings.llm_provider, "model": settings.model or None,
            "output_dir": str(settings.output_dir.resolve()), "browse_root": str(settings.web_browse_root.expanduser().resolve()),
            "external_tools_enabled": settings.enable_external_tools,
        }

    @app.get("/api/ai/status")
    async def ai_status() -> dict[str, Any]:
        status = await ollama_status()
        return {
            "configured_provider": settings.llm_provider,
            "configured_model": settings.model or None,
            "ollama": status,
            "recommended": [
                {"model": "qwen3.5:4b", "profile": "lightweight", "download_size": "3.4GB"},
                {"model": "qwen3.5:9b", "profile": "balanced", "download_size": "6.6GB"},
                {"model": "qwen3.5:27b", "profile": "strong", "download_size": "17GB"},
            ],
        }

    @app.get("/api/capabilities")
    async def capabilities() -> dict[str, Any]:
        return {"adapters": adapter_capabilities(), "deep_requires_approval": True}

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
            "root": str(root), "path": str(requested),
            "parent": str(parent) if parent and (parent == root or root in parent.parents) else None,
            "directories": directories,
        }

    @app.get("/api/runs")
    async def list_runs(limit: int = Query(default=50, ge=1, le=200)) -> dict[str, Any]:
        return {"runs": manager.list(limit)}

    @app.post("/api/runs", status_code=202)
    async def start_run(body: StartRunRequest) -> dict[str, Any]:
        try:
            state = await manager.start(body)
        except (PolicyViolation, ValueError, OSError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return state.public()

    @app.post("/api/runs/{run_id}/approve")
    async def approve_run(run_id: str, body: ApprovalRequest) -> dict[str, Any]:
        return (await manager.approve(run_id, body.analyst)).public()

    @app.get("/api/runs/{run_id}")
    async def run_status(run_id: str) -> dict[str, Any]:
        return manager.get(run_id).public(include_events=True)

    @app.get("/api/runs/{run_id}/events")
    async def run_events(run_id: str, request: Request,
                         last_event_id: str | None = Header(default=None, alias="Last-Event-ID")) -> StreamingResponse:
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
                if state.status in {"completed", "failed", "interrupted"}:
                    yield "event: done\ndata: {}\n\n"
                    break
                if await request.is_disconnected():
                    break
                try:
                    async with state.condition:
                        await asyncio.wait_for(state.condition.wait(), timeout=15)
                except TimeoutError:
                    yield ": keep-alive\n\n"

        return StreamingResponse(stream(), media_type="text/event-stream",
                                 headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

    @app.get("/api/runs/{run_id}/report", response_class=PlainTextResponse)
    async def run_report(run_id: str) -> PlainTextResponse:
        state = manager.get(run_id)
        report = state.output_dir / "report.md"
        if not report.exists():
            raise HTTPException(status_code=404, detail="report is not ready")
        return PlainTextResponse(report.read_text(encoding="utf-8"), media_type="text/markdown")

    @app.get("/api/runs/{run_id}/download/{artifact}")
    async def download_artifact(run_id: str, artifact: Literal["report", "findings", "audit", "run", "scope", "observations"]):
        state = manager.get(run_id)
        names = {
            "report": "report.md", "findings": "findings.json", "audit": "audit.jsonl",
            "run": "run.json", "scope": "scope.yaml", "observations": "observations.json",
        }
        path = state.output_dir / names[artifact]
        if not path.exists():
            raise HTTPException(status_code=404, detail="artifact is not ready")
        return FileResponse(path, filename=path.name)

    return app


app = create_app()
