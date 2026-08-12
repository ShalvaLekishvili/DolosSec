# Threat Model

## Assets

- Assessment credentials and API keys.
- Source code and proprietary application data.
- The operator workstation and Docker daemon.
- Authorized target environments.
- Findings and evidence integrity.

## Primary threats

### Prompt injection / goal hijack
Untrusted pages, README files, comments, logs or source strings may contain instructions intended to redirect the model. Mitigation: planner output is treated as untrusted; policy is enforced outside the model.

### Tool misuse
An agent may request an action outside the operator's intent. Mitigation: narrow action schemas, method allowlists, URL/host/IP/CIDR checks, request limits and explicit denial records.

### Scope escape through redirects or DNS
A permitted URL may redirect to another host. Mitigation: redirects are not automatically followed; each redirect target is normalized and policy-checked first. IP/CIDR policy is also evaluated for literal-IP targets.

### Data exfiltration
A compromised model may try to send secrets to an attacker-controlled host. Mitigation: remote requests can only address declared scope targets; arbitrary egress tools are not exposed.

### Host compromise through local analyzers
Third-party tools may be vulnerable or parse malicious input. Mitigation target: rootless containers, read-only root FS, dropped capabilities, no-new-privileges, seccomp/AppArmor defaults, network disabled for source analysis, resource caps.

### Audit tampering
An attacker may try to alter the run history. Mitigation: each JSONL event includes the previous event hash and a new SHA-256 hash over canonicalized event data.

## Non-goals in v0.1

- Stealth, evasion or persistence.
- Credential spraying/brute force.
- Autonomous destructive exploitation.
- Arbitrary post-exploitation shell access.
- Unrestricted scanning of third-party infrastructure.
