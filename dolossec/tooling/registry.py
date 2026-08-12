from __future__ import annotations

from typing import Any

from ..audit import AuditLog
from ..models import Action, Observation
from ..policy import ScopePolicy
from .base import Tool
from .http import HttpProbeTool, SecurityHeadersTool
from .source import SourceMapTool, SourceReviewTool


class ToolBroker:
    def __init__(self, policy: ScopePolicy | None, audit: AuditLog):
        self.policy = policy
        self.audit = audit
        self.tools: dict[str, Tool] = {
            "source_map": SourceMapTool(policy),
            "source_review": SourceReviewTool(policy),
        }
        if policy:
            self.tools["http_probe"] = HttpProbeTool(policy)
            self.tools["security_headers"] = SecurityHeadersTool(policy)

    async def execute(self, action: Action) -> Observation:
        self.audit.append("tool_requested", action.model_dump())
        if action.tool == "finish":
            obs = Observation(tool="finish", ok=True, data={})
            self.audit.append("tool_completed", obs.model_dump())
            return obs
        tool = self.tools.get(action.tool)
        if not tool:
            obs = Observation(tool=action.tool, ok=False, error="tool unavailable for this run")
            self.audit.append("tool_denied", obs.model_dump())
            return obs
        obs = await tool.run(action.arguments)
        self.audit.append("tool_completed" if obs.ok else "tool_failed", obs.model_dump())
        return obs
