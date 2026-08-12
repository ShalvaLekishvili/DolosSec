from __future__ import annotations

from ..models import Action, Observation, PlannerTurn, Target, TargetKind
from .base import Planner


class DeterministicPlanner(Planner):
    name = "deterministic"

    def __init__(self, external_tools: list[str] | None = None):
        self.external_tools = [x for x in (external_tools or []) if x in {"bandit_scan", "semgrep_scan", "trivy_fs_scan"}]

    async def next_turn(self, target: Target, observations: list[Observation], step: int) -> PlannerTurn:
        if target.kind == TargetKind.local_path:
            actions = [
                Action(tool="source_map", arguments={"path": target.value}, reason="Establish source attack surface"),
                Action(tool="source_review", arguments={"path": target.value}, reason="Identify high-signal code paths requiring validation"),
            ]
            actions.extend(
                Action(tool=tool, arguments={"path": target.value}, reason=f"Run approved {tool} adapter")
                for tool in self.external_tools
            )
            if step < len(actions):
                action = actions[step]
                return PlannerTurn(summary=action.reason, actions=[action])
            return PlannerTurn(summary="Source review complete", actions=[Action(tool="finish", reason="No more deterministic local checks")])

        if step == 0:
            return PlannerTurn(summary="Probe target", actions=[Action(tool="http_probe", arguments={"url": target.value, "method": "GET"}, reason="Establish HTTP behavior")])
        if step == 1:
            return PlannerTurn(summary="Review response security headers", actions=[Action(tool="security_headers", arguments={"url": target.value}, reason="Check baseline browser security controls")])
        return PlannerTurn(summary="Web baseline complete", actions=[Action(tool="finish", reason="No more deterministic remote checks")])
