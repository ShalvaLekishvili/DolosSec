from __future__ import annotations

import inspect
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

from ..audit import AuditLog
from ..config import settings
from ..llm.base import Planner
from ..models import Observation, RunRecord, Target
from ..policy import ScopePolicy
from ..reporting import findings_from_observations, write_reports
from ..tooling.registry import ToolBroker

ProgressSink = Callable[[dict[str, Any]], Awaitable[None] | None]


class Orchestrator:
    def __init__(
        self,
        target: Target,
        planner: Planner,
        policy: ScopePolicy | None,
        mode: str,
        scope_file: str | None,
        progress_sink: ProgressSink | None = None,
    ):
        self.target = target
        self.planner = planner
        self.policy = policy
        self.mode = mode
        self.scope_file = scope_file
        self.progress_sink = progress_sink
        self.run_id = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid4().hex[:6]
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
            output_dir=self.output_dir,
        )
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.audit.append("run_started", record.model_dump())
        await self._emit(
            "run_started",
            "Scan initialized",
            {
                "run_id": self.run_id,
                "target": self.target.model_dump(mode="json"),
                "mode": self.mode,
                "planner": self.planner.name,
            },
        )

        observations: list[Observation] = []
        max_steps = {
            "quick": 3,
            "standard": settings.max_steps,
            "deep": max(settings.max_steps, 12),
        }.get(self.mode, settings.max_steps)

        for step in range(max_steps):
            await self._emit(
                "planning",
                f"Planning step {step + 1}",
                {"step": step + 1, "max_steps": max_steps},
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
                },
            )
            if not turn.actions:
                break

            should_finish = False
            for action in turn.actions:
                await self._emit(
                    "tool_started",
                    f"Running {action.tool}",
                    {
                        "tool": action.tool,
                        "reason": action.reason,
                        "arguments": action.arguments,
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
                    },
                )

                partial_findings = findings_from_observations(observations, self.target.value)
                await self._emit(
                    "findings_updated",
                    f"{len(partial_findings)} finding(s) identified so far",
                    {
                        "count": len(partial_findings),
                        "findings": [f.model_dump(mode="json") for f in partial_findings],
                    },
                )

                if action.tool == "finish":
                    should_finish = True
                    break
            if should_finish:
                break

        await self._emit("reporting", "Building assessment report")
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
            },
        )
        return record
