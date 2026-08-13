from __future__ import annotations

from ..audit import AuditLog
from ..models import Action, Observation
from ..policy import ScopePolicy
from .base import Tool
from .external import BanditTool, SemgrepTool, TrivyFsTool
from .http import HttpProbeTool, SecurityHeadersTool, WebInventoryTool
from .source import SourceMapTool, SourceReviewTool


class ToolBroker:
    def __init__(self, policy: ScopePolicy | None, audit: AuditLog):
        self.policy = policy
        self.audit = audit
        self.tools: dict[str, Tool] = {
            "source_map": SourceMapTool(policy),
            "source_review": SourceReviewTool(policy),
            "bandit_scan": BanditTool(policy),
            "semgrep_scan": SemgrepTool(policy),
            "trivy_fs_scan": TrivyFsTool(policy),
        }
        if policy:
            self.tools["http_probe"] = HttpProbeTool(policy)
            self.tools["security_headers"] = SecurityHeadersTool(policy)
            self.tools["web_inventory"] = WebInventoryTool(policy)

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
