from __future__ import annotations

import asyncio
import json
import os
import shutil
from pathlib import Path
from typing import Any, Callable

from ..config import settings
from ..models import Observation
from ..policy import ScopePolicy
from .base import Tool


SAFE_ENV_KEYS = {"PATH", "HOME", "USER", "TMPDIR", "TEMP", "TMP", "SYSTEMROOT", "WINDIR"}


def _safe_env() -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if k in SAFE_ENV_KEYS}
    env.update({
        "NO_COLOR": "1",
        "SEMGREP_SEND_METRICS": "off",
        "TRIVY_DISABLE_VEX_NOTICE": "true",
    })
    return env


class FixedCommandTool(Tool):
    """Run a fixed security adapter without shell interpolation.

    This is intentionally narrower than arbitrary command execution. The tool validates
    the source path against DolosSec scope, resolves a known executable, constructs a
    fixed argv list, strips most inherited environment variables, caps output and applies
    a timeout. External tools remain opt-in through DOLOS_ENABLE_EXTERNAL_TOOLS.
    """

    executable: str

    def __init__(self, policy: ScopePolicy | None, command_builder: Callable[[Path], list[str]]):
        self.policy = policy
        self.command_builder = command_builder

    async def run(self, arguments: dict[str, Any]) -> Observation:
        if not settings.enable_external_tools:
            return Observation(tool=self.name, ok=False, error="external adapters are disabled; set DOLOS_ENABLE_EXTERNAL_TOOLS=true to opt in")

        path = Path(str(arguments.get("path", "."))).expanduser().resolve()
        if self.policy:
            try:
                self.policy.assert_path_allowed(path)
            except Exception as exc:
                return Observation(tool=self.name, ok=False, error=str(exc))
        if not path.exists() or not path.is_dir():
            return Observation(tool=self.name, ok=False, error=f"not a directory: {path}")

        binary = shutil.which(self.executable)
        if not binary:
            return Observation(tool=self.name, ok=False, error=f"{self.executable} is not installed or not on PATH")

        argv = [binary, *self.command_builder(path)]
        try:
            proc = await asyncio.create_subprocess_exec(
                *argv,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=str(path),
                env=_safe_env(),
            )
            try:
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(), timeout=settings.external_tool_timeout_seconds
                )
            except TimeoutError:
                proc.kill()
                await proc.communicate()
                return Observation(tool=self.name, ok=False, error="adapter timed out and was terminated")
        except OSError as exc:
            return Observation(tool=self.name, ok=False, error=f"adapter launch failed: {exc}")

        limit = settings.external_tool_max_output_bytes
        raw = stdout[:limit].decode("utf-8", errors="replace")
        err = stderr[: min(limit // 4, 250_000)].decode("utf-8", errors="replace")
        data: dict[str, Any] = {
            "exit_code": proc.returncode,
            "stdout_truncated": len(stdout) > limit,
            "stderr": err[-4000:],
        }
        try:
            data["json"] = json.loads(raw) if raw.strip() else {}
        except json.JSONDecodeError:
            data["stdout"] = raw[-20_000:]

        # Security scanners commonly use non-zero codes to signal findings. Parsing/reporting
        # decides whether findings exist; launch/timeout failures are represented separately.
        return Observation(tool=self.name, ok=True, data=data)


class BanditTool(FixedCommandTool):
    name = "bandit_scan"
    executable = "bandit"

    def __init__(self, policy: ScopePolicy | None):
        super().__init__(policy, lambda path: ["-r", str(path), "-f", "json", "-q"])


class SemgrepTool(FixedCommandTool):
    name = "semgrep_scan"
    executable = "semgrep"

    def __init__(self, policy: ScopePolicy | None):
        # `--config auto` can download rules. DolosSec does not silently do that here.
        # Users can place a local `.semgrep.yml` in the authorized project root.
        super().__init__(policy, self._command)

    async def run(self, arguments: dict[str, Any]) -> Observation:
        path = Path(str(arguments.get("path", "."))).expanduser().resolve()
        if not (path / ".semgrep.yml").exists():
            return Observation(tool=self.name, ok=False, error="Semgrep adapter requires a project-local .semgrep.yml; remote rule-pack download is not automatic")
        return await super().run(arguments)

    @staticmethod
    def _command(path: Path) -> list[str]:
        return ["scan", "--config", str(path / ".semgrep.yml"), "--json", "--metrics=off", str(path)]


class TrivyFsTool(FixedCommandTool):
    name = "trivy_fs_scan"
    executable = "trivy"

    def __init__(self, policy: ScopePolicy | None):
        super().__init__(
            policy,
            lambda path: [
                "fs",
                "--format",
                "json",
                "--scanners",
                "vuln,misconfig,secret",
                "--skip-db-update",
                "--no-progress",
                str(path),
            ],
        )


def adapter_capabilities() -> list[dict[str, Any]]:
    semgrep_ready = bool(shutil.which("semgrep"))
    return [
        {
            "id": "bandit_scan",
            "name": "Bandit",
            "kind": "source",
            "installed": bool(shutil.which("bandit")),
            "enabled": settings.enable_external_tools,
            "description": "Python security static analysis through fixed argv execution.",
        },
        {
            "id": "semgrep_scan",
            "name": "Semgrep",
            "kind": "source",
            "installed": semgrep_ready,
            "enabled": settings.enable_external_tools,
            "description": "Local-rule Semgrep adapter; DolosSec does not auto-download rule packs.",
        },
        {
            "id": "trivy_fs_scan",
            "name": "Trivy FS",
            "kind": "source/dependency",
            "installed": bool(shutil.which("trivy")),
            "enabled": settings.enable_external_tools,
            "description": "Filesystem vulnerability, misconfiguration and secret scan using the local DB.",
        },
        {
            "id": "nuclei",
            "name": "Nuclei",
            "kind": "network",
            "installed": bool(shutil.which("nuclei")),
            "enabled": False,
            "description": "Network adapter is intentionally reserved/disabled in v0.4 until per-template policy gating is implemented.",
        },
    ]
