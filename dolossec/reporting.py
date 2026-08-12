from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Iterable

from .models import Finding, Observation, Severity


def _fid(seed: str) -> str:
    return "DS-" + hashlib.sha256(seed.encode()).hexdigest()[:10].upper()


def _severity(value: str | None, default: Severity = Severity.medium) -> Severity:
    raw = (value or "").lower()
    aliases = {"error": "high", "warning": "medium", "note": "low", "unknown": "info"}
    raw = aliases.get(raw, raw)
    try:
        return Severity(raw)
    except ValueError:
        return default


def _first_cwe(value: Any) -> str | None:
    if value is None:
        return None
    values = value if isinstance(value, list) else [value]
    for item in values:
        text = str(item)
        marker = "CWE-"
        pos = text.upper().find(marker)
        if pos >= 0:
            suffix = "".join(ch for ch in text[pos + len(marker):] if ch.isdigit())
            if suffix:
                return f"CWE-{suffix}"
    return None


def _cvss_from_trivy(vuln: dict[str, Any]) -> tuple[float | None, str | None]:
    cvss = vuln.get("CVSS") or {}
    best_score: float | None = None
    best_vector: str | None = None
    for source in cvss.values() if isinstance(cvss, dict) else []:
        if not isinstance(source, dict):
            continue
        for key in ("V3Score", "V2Score"):
            score = source.get(key)
            if isinstance(score, (int, float)) and (best_score is None or float(score) > best_score):
                best_score = float(score)
                vector_key = "V3Vector" if key == "V3Score" else "V2Vector"
                best_vector = source.get(vector_key)
    return best_score, best_vector


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
                    cwe="CWE-693",
                    references=["OWASP Secure Headers Project"],
                    source_tool=obs.tool,
                ))

        if obs.tool == "source_review" and obs.ok:
            mapping = {
                "hardcoded_secret": (Severity.medium, "CWE-798"),
                "shell_true": (Severity.medium, "CWE-78"),
                "dangerous_eval": (Severity.medium, "CWE-95"),
                "weak_hash": (Severity.low, "CWE-327"),
                "debug_enabled": (Severity.low, "CWE-489"),
            }
            for match in obs.data.get("matches", []):
                rule = match["rule_id"]
                sev, cwe = mapping.get(rule, (Severity.low, None))
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
                    cwe=cwe,
                    source_tool=obs.tool,
                ))

        if obs.tool == "bandit_scan" and obs.ok:
            payload = obs.data.get("json") or {}
            for item in payload.get("results", []) if isinstance(payload, dict) else []:
                cwe_raw = (item.get("issue_cwe") or {}).get("id") if isinstance(item.get("issue_cwe"), dict) else None
                cwe = f"CWE-{cwe_raw}" if cwe_raw else None
                filename = item.get("filename", "unknown")
                line = item.get("line_number", "?")
                test_id = item.get("test_id", "bandit")
                findings.append(Finding(
                    id=_fid(f"{target}:bandit:{filename}:{line}:{test_id}"),
                    title=item.get("issue_text") or f"Bandit finding {test_id}",
                    severity=_severity(item.get("issue_severity"), Severity.medium),
                    confidence={"HIGH": .9, "MEDIUM": .75, "LOW": .55}.get(str(item.get("issue_confidence", "")).upper(), .7),
                    target=target,
                    category=test_id,
                    description="Bandit static analysis reported this Python security issue.",
                    evidence=[f"{filename}:{line}: {item.get('code', '').strip()[:500]}"],
                    remediation="Review the flagged code path and apply the secure alternative recommended for the Bandit rule.",
                    cwe=cwe,
                    references=[f"Bandit rule {test_id}"],
                    source_tool=obs.tool,
                ))

        if obs.tool == "semgrep_scan" and obs.ok:
            payload = obs.data.get("json") or {}
            for item in payload.get("results", []) if isinstance(payload, dict) else []:
                extra = item.get("extra") or {}
                metadata = extra.get("metadata") or {}
                start = item.get("start") or {}
                path = item.get("path", "unknown")
                line = start.get("line", "?")
                check_id = item.get("check_id", "semgrep")
                findings.append(Finding(
                    id=_fid(f"{target}:semgrep:{path}:{line}:{check_id}"),
                    title=extra.get("message") or check_id,
                    severity=_severity(extra.get("severity"), Severity.medium),
                    confidence=0.8,
                    target=target,
                    category=check_id,
                    description="Semgrep matched a local security rule against this source location.",
                    evidence=[f"{path}:{line}: rule={check_id}"],
                    remediation=metadata.get("fix") or "Review the matching rule guidance and remediate the affected code path.",
                    cwe=_first_cwe(metadata.get("cwe")),
                    references=[str(x) for x in (metadata.get("references") or [])][:5],
                    source_tool=obs.tool,
                ))

        if obs.tool == "trivy_fs_scan" and obs.ok:
            payload = obs.data.get("json") or {}
            for result in payload.get("Results", []) if isinstance(payload, dict) else []:
                result_target = result.get("Target", "")
                for vuln in result.get("Vulnerabilities") or []:
                    score, vector = _cvss_from_trivy(vuln)
                    vid = vuln.get("VulnerabilityID", "trivy-vuln")
                    findings.append(Finding(
                        id=_fid(f"{target}:trivy:{result_target}:{vid}:{vuln.get('PkgName','')}"),
                        title=f"{vid}: {vuln.get('Title') or vuln.get('PkgName') or 'Dependency vulnerability'}",
                        severity=_severity(vuln.get("Severity"), Severity.medium),
                        confidence=0.95,
                        target=target,
                        category="dependency_vulnerability",
                        description=vuln.get("Description") or "Trivy identified a known vulnerability in a dependency.",
                        evidence=[f"{result_target}: {vuln.get('PkgName','?')} {vuln.get('InstalledVersion','?')} → fixed {vuln.get('FixedVersion') or 'not listed'}"],
                        remediation=f"Upgrade or replace the affected package. Fixed version: {vuln.get('FixedVersion') or 'consult vendor advisory'}.",
                        cvss_score=score,
                        cvss_vector=vector,
                        references=[x for x in [vuln.get("PrimaryURL")] if x],
                        source_tool=obs.tool,
                    ))
                for misconfig in result.get("Misconfigurations") or []:
                    mid = misconfig.get("ID", "trivy-misconfig")
                    findings.append(Finding(
                        id=_fid(f"{target}:trivy:{result_target}:{mid}"),
                        title=misconfig.get("Title") or mid,
                        severity=_severity(misconfig.get("Severity"), Severity.medium),
                        confidence=0.9,
                        target=target,
                        category="misconfiguration",
                        description=misconfig.get("Description") or "Trivy identified a configuration security issue.",
                        evidence=[f"{result_target}: {misconfig.get('Message') or mid}"],
                        remediation=misconfig.get("Resolution") or "Apply the secure configuration recommended by the scanner rule.",
                        references=[x for x in (misconfig.get("References") or [])][:5],
                        source_tool=obs.tool,
                    ))
                for secret in result.get("Secrets") or []:
                    rid = secret.get("RuleID", "trivy-secret")
                    findings.append(Finding(
                        id=_fid(f"{target}:trivy-secret:{result_target}:{secret.get('StartLine','')}:{rid}"),
                        title=secret.get("Title") or "Potential secret detected",
                        severity=_severity(secret.get("Severity"), Severity.high),
                        confidence=0.85,
                        target=target,
                        category="secret_exposure",
                        description="Trivy secret scanning identified a value matching a credential pattern.",
                        evidence=[f"{result_target}:{secret.get('StartLine','?')}: {rid}"],
                        remediation="Remove the secret from source control, rotate it, and store replacements in an approved secret manager.",
                        cwe="CWE-798",
                        source_tool=obs.tool,
                    ))

    dedup = {f.id: f for f in findings}
    return list(dedup.values())


def write_reports(output_dir: Path, findings: list[Finding], observations: list[Observation]) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "findings.json").write_text(
        json.dumps([f.model_dump(mode="json") for f in findings], indent=2), encoding="utf-8"
    )
    severity_counts = {s.value: sum(1 for f in findings if f.severity == s) for s in Severity}
    lines = [
        "# DolosSec Security Assessment",
        "",
        f"Findings: **{len(findings)}**",
        "",
        "## Severity summary",
        "",
        *[f"- {name.title()}: **{count}**" for name, count in severity_counts.items()],
        "",
    ]
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
            f"- Source tool: `{finding.source_tool or 'dolossec'}`",
            f"- CWE: `{finding.cwe or 'Unmapped'}`",
            f"- CVSS: `{finding.cvss_score if finding.cvss_score is not None else 'Pending validation'}`",
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
    (output_dir / "observations.json").write_text(
        json.dumps([o.model_dump(mode="json") for o in observations], indent=2), encoding="utf-8"
    )
