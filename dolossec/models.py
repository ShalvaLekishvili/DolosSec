from __future__ import annotations

from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator


class Severity(str, Enum):
    info = "info"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class Authorization(BaseModel):
    owner: str
    ticket: str
    purpose: str
    expires_at: datetime


class ScopeSpec(BaseModel):
    urls: list[str] = Field(default_factory=list)
    hosts: list[str] = Field(default_factory=list)
    cidrs: list[str] = Field(default_factory=list)
    local_paths: list[str] = Field(default_factory=list)


class PolicySpec(BaseModel):
    allowed_http_methods: list[str] = Field(default_factory=lambda: ["GET", "HEAD", "OPTIONS"])
    max_redirects: int = Field(default=3, ge=0, le=10)
    max_response_bytes: int = Field(default=524288, ge=1024, le=5_242_880)
    request_timeout_seconds: float = Field(default=10.0, gt=0, le=60)
    requests_per_second: float = Field(default=2.0, gt=0, le=20)
    allow_private_networks: bool = False

    @field_validator("allowed_http_methods")
    @classmethod
    def normalize_methods(cls, value: list[str]) -> list[str]:
        return sorted({v.upper().strip() for v in value})


class ScopeManifest(BaseModel):
    authorization: Authorization
    scope: ScopeSpec
    policy: PolicySpec = Field(default_factory=PolicySpec)


class TargetKind(str, Enum):
    url = "url"
    local_path = "local_path"


class Target(BaseModel):
    kind: TargetKind
    value: str


ToolName = Literal[
    "http_probe",
    "security_headers",
    "web_inventory",
    "source_map",
    "source_review",
    "bandit_scan",
    "semgrep_scan",
    "trivy_fs_scan",
    "finish",
]


class Action(BaseModel):
    tool: ToolName
    arguments: dict[str, Any] = Field(default_factory=dict)
    reason: str = ""


class PlannerTurn(BaseModel):
    summary: str = ""
    actions: list[Action] = Field(default_factory=list, max_length=5)


class Observation(BaseModel):
    tool: str
    ok: bool
    data: dict[str, Any] = Field(default_factory=dict)
    error: str | None = None


class Finding(BaseModel):
    id: str
    title: str
    severity: Severity
    confidence: float = Field(ge=0, le=1)
    target: str
    category: str
    description: str
    evidence: list[str] = Field(default_factory=list)
    remediation: str
    cwe: str | None = None
    cvss_score: float | None = Field(default=None, ge=0, le=10)
    cvss_vector: str | None = None
    references: list[str] = Field(default_factory=list)
    source_tool: str | None = None


class RunRecord(BaseModel):
    run_id: str
    started_at: datetime
    finished_at: datetime | None = None
    target: Target
    scope_file: str | None = None
    mode: str
    planner: str
    planner_model: str | None = None
    findings_count: int = 0
    output_dir: Path
    enabled_adapters: list[str] = Field(default_factory=list)
    approval_required: bool = False
    approved_by: str | None = None
    approved_at: datetime | None = None
