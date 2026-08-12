from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Iterable

from .models import Finding, Observation, Severity, TargetKind


def _fid(seed: str) -> str:
    return "DS-" + hashlib.sha256(seed.encode()).hexdigest()[:10].upper()


def findings_from_observations(observations: Iterable[Observation], target: str) -> list[Finding]:
    findings: list[Finding] = []
    for obs in observations:
        if obs.tool == "security_headers" and obs.ok:
            missing = obs.data.get("missing", {})
            for header, why in missing.items():
                findings.append(Finding(
                    id=_fid(f"{target}:header:{header}"),
                    title=f"Missing security header: {header}",
                    severity=Severity.low,
                    confidence=0.95,
                    target=target,
                    category="security_headers",
                    description=why,
                    evidence=[f"Header {header!r} was not present in the observed response."],
                    remediation=f"Evaluate and deploy an appropriate {header} policy for this application.",
                    references=["OWASP Secure Headers Project"],
                ))
        if obs.tool == "source_review" and obs.ok:
            for match in obs.data.get("matches", []):
                rule = match["rule_id"]
                sev = Severity.medium if rule in {"hardcoded_secret", "shell_true", "dangerous_eval"} else Severity.low
                remediation = {
                    "hardcoded_secret": "Move credentials to a secret manager or runtime environment and rotate any exposed value.",
                    "shell_true": "Avoid shell=True; pass argument arrays and validate any user-controlled input.",
                    "dangerous_eval": "Remove dynamic code execution or strictly constrain the evaluated language/input.",
                    "weak_hash": "Use a modern cryptographic primitive when collision/preimage resistance is required.",
                    "debug_enabled": "Disable debug behavior in production builds and deployment configuration.",
                }.get(rule, "Review and remediate the flagged construct.")
                findings.append(Finding(
                    id=_fid(f"{target}:{match['file']}:{match['line']}:{rule}"),
                    title=match["description"],
                    severity=sev,
                    confidence=0.65,
                    target=target,
                    category=rule,
                    description="Heuristic source review found a construct that warrants security validation. This is not treated as a confirmed exploit by itself.",
                    evidence=[f"{match['file']}:{match['line']}: {match['preview']}"],
                    remediation=remediation,
                ))
    dedup = {f.id: f for f in findings}
    return list(dedup.values())


def write_reports(output_dir: Path, findings: list[Finding], observations: list[Observation]) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "findings.json").write_text(json.dumps([f.model_dump(mode="json") for f in findings], indent=2), encoding="utf-8")
    lines = ["# DolosSec Security Assessment", "", f"Findings: **{len(findings)}**", ""]
    if not findings:
        lines.append("No findings were produced by the enabled checks. This does not prove the target is vulnerability-free.")
    for finding in findings:
        lines.extend([
            f"## {finding.id} — {finding.title}",
            "",
            f"- Severity: **{finding.severity.value}**",
            f"- Confidence: **{finding.confidence:.0%}**",
            f"- Target: `{finding.target}`",
            f"- Category: `{finding.category}`",
            "",
            finding.description,
            "",
            "### Evidence",
            *[f"- {e}" for e in finding.evidence],
            "",
            "### Remediation",
            finding.remediation,
            "",
        ])
    (output_dir / "report.md").write_text("\n".join(lines), encoding="utf-8")
    (output_dir / "observations.json").write_text(json.dumps([o.model_dump(mode="json") for o in observations], indent=2), encoding="utf-8")
