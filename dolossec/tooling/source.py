from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from ..models import Observation
from ..policy import ScopePolicy
from .base import Tool


IGNORED_DIRS = {".git", ".venv", "venv", "node_modules", "dist", "build", "__pycache__"}
TEXT_EXTS = {".py", ".js", ".ts", ".tsx", ".jsx", ".java", ".go", ".rs", ".rb", ".php", ".env", ".yml", ".yaml", ".json", ".toml", ".ini", ".conf", ".sh"}


class SourceMapTool(Tool):
    name = "source_map"

    def __init__(self, policy: ScopePolicy | None = None):
        self.policy = policy

    async def run(self, arguments: dict[str, Any]) -> Observation:
        path = Path(str(arguments.get("path", "."))).expanduser().resolve()
        if self.policy:
            try:
                self.policy.assert_path_allowed(path)
            except Exception as exc:
                return Observation(tool=self.name, ok=False, error=str(exc))
        if not path.exists() or not path.is_dir():
            return Observation(tool=self.name, ok=False, error=f"not a directory: {path}")
        files: list[str] = []
        by_ext: dict[str, int] = {}
        for item in path.rglob("*"):
            if any(part in IGNORED_DIRS for part in item.parts):
                continue
            if item.is_file():
                rel = str(item.relative_to(path))
                files.append(rel)
                ext = item.suffix.lower() or "<none>"
                by_ext[ext] = by_ext.get(ext, 0) + 1
                if len(files) >= 2000:
                    break
        return Observation(tool=self.name, ok=True, data={"path": str(path), "files": files, "by_extension": by_ext, "truncated": len(files) >= 2000})


PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    ("hardcoded_secret", re.compile(r'''(?i)(api[_-]?key|secret|password|token)\s*[:=]\s*['"][^'"]{8,}['"]'''), "Potential hard-coded credential or secret"),
    ("dangerous_eval", re.compile(r"(?<![A-Za-z0-9_])(eval|exec)\s*\("), "Dynamic code execution primitive"),
    ("shell_true", re.compile(r"subprocess\.(run|Popen|call)\([^\n]{0,180}shell\s*=\s*True"), "subprocess with shell=True"),
    ("weak_hash", re.compile(r"(?i)(hashlib\.)?(md5|sha1)\s*\("), "Weak hash primitive; review whether used for security"),
    ("debug_enabled", re.compile(r"(?i)debug\s*=\s*(true|1)"), "Debug mode appears enabled"),
]


class SourceReviewTool(Tool):
    name = "source_review"

    def __init__(self, policy: ScopePolicy | None = None):
        self.policy = policy

    async def run(self, arguments: dict[str, Any]) -> Observation:
        path = Path(str(arguments.get("path", "."))).expanduser().resolve()
        if self.policy:
            try:
                self.policy.assert_path_allowed(path)
            except Exception as exc:
                return Observation(tool=self.name, ok=False, error=str(exc))
        findings: list[dict[str, Any]] = []
        scanned = 0
        for item in path.rglob("*"):
            if any(part in IGNORED_DIRS for part in item.parts) or not item.is_file():
                continue
            if item.suffix.lower() not in TEXT_EXTS and item.name not in {"Dockerfile", ".env"}:
                continue
            try:
                text = item.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            scanned += 1
            if len(text) > 1_000_000:
                text = text[:1_000_000]
            for line_no, line in enumerate(text.splitlines(), start=1):
                for rule_id, regex, description in PATTERNS:
                    if regex.search(line):
                        findings.append({
                            "rule_id": rule_id,
                            "description": description,
                            "file": str(item.relative_to(path)),
                            "line": line_no,
                            "preview": line.strip()[:240],
                        })
                        if len(findings) >= 250:
                            return Observation(tool=self.name, ok=True, data={"path": str(path), "scanned_files": scanned, "matches": findings, "truncated": True})
        return Observation(tool=self.name, ok=True, data={"path": str(path), "scanned_files": scanned, "matches": findings, "truncated": False})
