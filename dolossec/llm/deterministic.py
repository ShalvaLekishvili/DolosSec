from __future__ import annotations

from ..models import Action, Observation, PlannerTurn, Target, TargetKind
from .base import Planner


class DeterministicPlanner(Planner):
    name = "deterministic"

    async def next_turn(self, target: Target, observations: list[Observation], step: int) -> PlannerTurn:
        if target.kind == TargetKind.local_path:
            if step == 0:
                return PlannerTurn(summary="Map the source tree", actions=[Action(tool="source_map", arguments={"path": target.value}, reason="Establish attack surface")])
            if step == 1:
                return PlannerTurn(summary="Review high-signal security patterns", actions=[Action(tool="source_review", arguments={"path": target.value}, reason="Identify code paths requiring manual validation")])
            return PlannerTurn(summary="Source review complete", actions=[Action(tool="finish", reason="No more deterministic local checks")])
        if step == 0:
            return PlannerTurn(summary="Probe target", actions=[Action(tool="http_probe", arguments={"url": target.value, "method": "GET"}, reason="Establish HTTP behavior")])
        if step == 1:
            return PlannerTurn(summary="Review response security headers", actions=[Action(tool="security_headers", arguments={"url": target.value}, reason="Check baseline browser security controls")])
        return PlannerTurn(summary="Web baseline complete", actions=[Action(tool="finish", reason="No more deterministic remote checks")])
