from __future__ import annotations

import inspect
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from ..audit import AuditLog
from ..config import settings
from ..llm.base import Planner
from ..models import Action, Observation, RunRecord, Target
from ..policy import ScopePolicy
from ..reporting import findings_from_observations, write_reports
from ..tooling.registry import ToolBroker

ProgressSink = Callable[[dict[str, Any]], Awaitable[None] | None]


def _agent_for_tool(tool: str) -> str:
    if tool in {"source_map", "source_review", "bandit_scan", "semgrep_scan", "trivy_fs_scan"}:
        return "source-researcher"
    if tool in {"http_probe", "security_headers", "web_inventory"}:
        return "web-researcher"
    if tool == "finish":
        return "orchestrator"
    return "tool-broker"


class Orchestrator:
    def __init__(
        self,
        target: Target,
        planner: Planner,
        policy: ScopePolicy | None,
        mode: str,
        scope_file: str | None,
        progress_sink: ProgressSink | None = None,
        *,
        enabled_adapters: list[str] | None = None,
        approval_required: bool = False,
        approved_by: str | None = None,
        approved_at: datetime | None = None,
        run_id: str | None = None,
    ):
        self.target = target
        self.planner = planner
        self.policy = policy
        self.mode = mode
        self.scope_file = scope_file
        self.progress_sink = progress_sink
        self.enabled_adapters = enabled_adapters or []
        self.approval_required = approval_required
        self.approved_by = approved_by
        self.approved_at = approved_at
        self.run_id = run_id or (datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid4().hex[:6])
        self.output_dir = settings.output_dir / self.run_id
        self.audit = AuditLog(self.output_dir / "audit.jsonl")
        self.broker = ToolBroker(policy, self.audit)

    async def _emit(self, event_type: str, message: str, data: dict[str, Any] | None = None) -> None:
        if not self.progress_sink:
            return
        event = {
            "type": event_type,
            "message": message,
            "timestamp": datetime.now(UTC).isoformat(),
            "data": data or {},
        }
        result = self.progress_sink(event)
        if inspect.isawaitable(result):
            await result

    async def run(self) -> RunRecord:
        started = datetime.now(UTC)
        record = RunRecord(
            run_id=self.run_id,
            started_at=started,
            target=self.target,
            scope_file=self.scope_file,
            mode=self.mode,
            planner=self.planner.name,
            planner_model=getattr(self.planner, "model", None),
            output_dir=self.output_dir,
            enabled_adapters=self.enabled_adapters,
            approval_required=self.approval_required,
            approved_by=self.approved_by,
            approved_at=self.approved_at,
        )
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.audit.append("run_started", record.model_dump())
        await self._emit(
            "run_started",
            "Assessment initialized",
            {
                "run_id": self.run_id,
                "target": self.target.model_dump(mode="json"),
                "mode": self.mode,
                "planner": self.planner.name,
                "planner_model": getattr(self.planner, "model", None),
                "agent": "orchestrator",
                "enabled_adapters": self.enabled_adapters,
            },
        )

        observations: list[Observation] = []

        # Remote assessments always perform a minimum host-controlled discovery phase.
        # The AI planner cannot skip this coverage by immediately returning finish().
        if self.target.kind.value == "url":
            crawl_limits = {
                "quick": {"max_pages": 8, "max_depth": 1},
                "standard": {"max_pages": 25, "max_depth": 2},
                "deep": {"max_pages": 60, "max_depth": 3},
            }.get(self.mode, {"max_pages": 25, "max_depth": 2})
            baseline_actions = [
                Action(
                    tool="http_probe",
                    arguments={"url": self.target.value, "method": "GET"},
                    reason="Establish target-specific HTTP baseline",
                ),
                Action(
                    tool="security_headers",
                    arguments={"url": self.target.value},
                    reason="Evaluate baseline browser security controls",
                ),
                Action(
                    tool="web_inventory",
                    arguments={"url": self.target.value, **crawl_limits},
                    reason="Build same-origin attack-surface inventory before AI reasoning",
                ),
            ]
            for action in baseline_actions:
                agent = _agent_for_tool(action.tool)
                await self._emit(
                    "tool_started",
                    f"Running mandatory {action.tool}",
                    {
                        "tool": action.tool,
                        "reason": action.reason,
                        "arguments": action.arguments,
                        "agent": agent,
                        "mandatory": True,
                    },
                )
                obs = await self.broker.execute(action)
                observations.append(obs)
                await self._emit(
                    "tool_completed" if obs.ok else "tool_failed",
                    f"{action.tool} {'completed' if obs.ok else 'failed'}",
                    {
                        "tool": action.tool,
                        "ok": obs.ok,
                        "error": obs.error,
                        "data": obs.data,
                        "agent": agent,
                        "mandatory": True,
                    },
                )
                partial_findings = findings_from_observations(observations, self.target.value)
                await self._emit(
                    "findings_updated",
                    f"{len(partial_findings)} finding(s) identified so far",
                    {
                        "count": len(partial_findings),
                        "findings": [f.model_dump(mode="json") for f in partial_findings],
                        "agent": "reporter",
                    },
                )

        max_steps = {
            "quick": 3,
            "standard": settings.max_steps,
            "deep": max(settings.max_steps, 12),
        }.get(self.mode, settings.max_steps)

        for step in range(max_steps):
            await self._emit(
                "planning",
                f"Planning step {step + 1}",
                {"step": step + 1, "max_steps": max_steps, "agent": "planner"},
            )
            turn = await self.planner.next_turn(self.target, observations, step)
            self.audit.append("planner_turn", turn.model_dump())
            await self._emit(
                "plan_ready",
                turn.summary or f"Plan ready for step {step + 1}",
                {
                    "step": step + 1,
                    "summary": turn.summary,
                    "actions": [a.model_dump(mode="json") for a in turn.actions],
                    "agent": "planner",
                },
            )
            if not turn.actions:
                break

            should_finish = False
            for action in turn.actions:
                agent = _agent_for_tool(action.tool)
                await self._emit(
                    "tool_started",
                    f"Running {action.tool}",
                    {
                        "tool": action.tool,
                        "reason": action.reason,
                        "arguments": action.arguments,
                        "agent": agent,
                    },
                )
                obs = await self.broker.execute(action)
                observations.append(obs)
                await self._emit(
                    "tool_completed" if obs.ok else "tool_failed",
                    f"{action.tool} {'completed' if obs.ok else 'failed'}",
                    {
                        "tool": action.tool,
                        "ok": obs.ok,
                        "error": obs.error,
                        "data": obs.data,
                        "agent": agent,
                    },
                )

                partial_findings = findings_from_observations(observations, self.target.value)
                await self._emit(
                    "findings_updated",
                    f"{len(partial_findings)} finding(s) identified so far",
                    {
                        "count": len(partial_findings),
                        "findings": [f.model_dump(mode="json") for f in partial_findings],
                        "agent": "reporter",
                    },
                )

                if action.tool == "finish":
                    should_finish = True
                    break
            if should_finish:
                break

        # External source adapters are a host-controlled phase, not LLM-selected commands.
        # This preserves deterministic scope/argv controls even when an AI planner is enabled.
        if self.target.kind.value == "local_path" and self.enabled_adapters:
            for tool_name in self.enabled_adapters:
                if any(o.tool == tool_name for o in observations):
                    continue
                await self._emit(
                    "tool_started",
                    f"Running approved adapter {tool_name}",
                    {"tool": tool_name, "reason": "Operator-selected adapter", "arguments": {"path": self.target.value}, "agent": "source-researcher"},
                )
                obs = await self.broker.execute(Action(tool=tool_name, arguments={"path": self.target.value}, reason="Operator-selected adapter"))
                observations.append(obs)
                await self._emit(
                    "tool_completed" if obs.ok else "tool_failed",
                    f"{tool_name} {'completed' if obs.ok else 'failed'}",
                    {"tool": tool_name, "ok": obs.ok, "error": obs.error, "data": obs.data, "agent": "source-researcher"},
                )
                partial_findings = findings_from_observations(observations, self.target.value)
                await self._emit(
                    "findings_updated",
                    f"{len(partial_findings)} finding(s) identified so far",
                    {"count": len(partial_findings), "findings": [f.model_dump(mode="json") for f in partial_findings], "agent": "reporter"},
                )

        await self._emit("reporting", "Building assessment report", {"agent": "reporter"})
        findings = findings_from_observations(observations, self.target.value)
        write_reports(self.output_dir, findings, observations)
        record.findings_count = len(findings)
        record.finished_at = datetime.now(UTC)
        (self.output_dir / "run.json").write_text(record.model_dump_json(indent=2), encoding="utf-8")
        self.audit.append(
            "run_finished",
            {"findings_count": len(findings), "finished_at": record.finished_at},
        )
        await self._emit(
            "run_finished",
            "Assessment complete",
            {
                "run_id": self.run_id,
                "findings_count": len(findings),
                "output_dir": str(self.output_dir),
                "agent": "orchestrator",
            },
        )
        return record
