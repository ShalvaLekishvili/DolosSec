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

## v0.3 external adapter boundary

`DOLOS_ENABLE_EXTERNAL_TOOLS` defaults to false. Enabling it permits explicitly selected local scanner binaries to execute against an already-authorized source directory. DolosSec constrains executable name, argv construction, working directory, inherited environment, timeout and captured output, but v0.3 does not yet provide kernel/container network isolation for those subprocesses. Therefore installed third-party scanner binaries remain part of the trusted computing base.

Deep mode requires a human approval event. This reduces accidental extended execution but does not replace authorization; scope validation still occurs before and during tool execution.

## Local AI / Ollama additions

### Threat: unauthenticated AI endpoint exposed beyond localhost

Ollama's normal local API does not require authentication. DolosSec therefore rejects non-loopback `DOLOS_OLLAMA_BASE_URL` values unless `DOLOS_OLLAMA_ALLOW_REMOTE=true` is explicitly enabled. Remote Ollama mode is not the recommended single-user deployment.

### Threat: prompt injection in source code or HTTP content

Model inputs may contain attacker-controlled instructions embedded in code comments, webpages, README files, logs or tool output. DolosSec treats these values as untrusted data, bounds the observation context and instructs the planner not to follow target-provided instructions. Most importantly, planner output is only a typed proposal; it cannot bypass `ScopePolicy` or directly invoke a shell.

### Threat: malformed local-model output

Ollama responses use the `PlannerTurn` JSON schema and are validated again by Pydantic. Invalid or unsupported actions fail closed rather than being interpreted as shell text.
