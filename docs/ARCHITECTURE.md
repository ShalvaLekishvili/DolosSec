# DolosSec architecture

DolosSec separates **reasoning** from **authority**. A planner may decide what it wants to inspect, but trusted application code determines what it is allowed to execute.

## Components

1. **Local web control plane** — target selection, authorization input, live progress, findings and artifacts. It remains loopback-only in v0.4.
2. **CLI** — scriptable access to the same orchestration and policy primitives.
3. **ScopePolicy** — validates authorization expiration, URL/host/IP/CIDR/path boundaries, allowed methods and private-network policy.
4. **Planner** — deterministic or AI-backed component that proposes typed actions.
5. **Orchestrator** — runs the bounded planning loop and emits structured progress events.
6. **ToolBroker** — maps typed actions to trusted tool implementations and writes audit events.
7. **Tools** — HTTP probing, security-header review, source mapping and source review in the current release.
8. **Reporting** — converts observations into structured findings and writes JSON/Markdown artifacts.
9. **AuditLog** — appends hash-linked execution records so later modification is detectable.

## Web data flow

```text
Browser (127.0.0.1)
        │
        │ POST target + authorization
        ▼
FastAPI Web Control Plane
        │
        ├── local directory → local ScopeManifest
        │
        └── URL → explicit expiring ScopeManifest
                    │
                    ▼
                ScopePolicy
                    │
                    ▼
             Orchestrator + Planner
                    │
              typed Action[]
                    ▼
                ToolBroker
                    │
          policy-aware trusted tools
                    ▼
                Observations
                    │
          ┌─────────┴─────────┐
          ▼                   ▼
      Findings            AuditLog
          │
          ▼
      report.md
          │
          └── SSE progress + API state → Browser
```

## Trust boundaries

- Browser input is untrusted.
- Remote content and local source content are untrusted.
- Planner output is untrusted until the broker/policy layer accepts it.
- The current web UI is trusted only as a local loopback operator surface; it must not be exposed directly to untrusted networks.
- Adding a tool must not bypass `ScopePolicy` merely because an earlier stage already validated the target.

## Future direction

A hardened multi-user/server mode should add authenticated operators, CSRF/session protections, per-user authorization objects, persistent run state, encrypted secret storage, worker isolation and an authenticated WebSocket/SSE channel. Until those controls exist, remote UI binding remains intentionally disabled.

## v0.3 control-plane additions

The local control plane now persists `web_state.json` beside each run so completed assessments can be recovered into scan history after a restart. Deep-mode runs enter an `awaiting_approval` state and do not enter the orchestrator until an analyst records approval.

Optional source adapters are operator-selected. They execute as fixed argument vectors through `create_subprocess_exec`; the LLM cannot construct an arbitrary command line. The current adapters are Bandit, Semgrep with a project-local `.semgrep.yml`, and Trivy filesystem scanning with database updates disabled. Nuclei is detected as a capability but remote template execution is intentionally disabled in v0.3 pending per-template policy classification.

```text
Browser UI
   |
   +--> Scope/authorization policy
   |
   +--> Deep approval gate -----------+
   |                                  |
   +--> Orchestrator --> Tool Broker  |
                          |            |
                          +--> built-in HTTP/source tools
                          +--> operator-selected fixed adapters
                                      |
                                      v
                              observations/findings
                                      |
                           history + report + audit
```

The adapter subprocess restriction is **not an OS-level sandbox**. A locally installed third-party scanner still executes with the permissions of the DolosSec process. Production isolation for those adapters is a future runtime layer; keep external adapters disabled unless the local scanner binaries are trusted.

## v0.4 Local AI planner

DolosSec can now use Ollama as a first-class planner provider.

```text
Authorized target + bounded evidence
              │
              ▼
      OllamaPlanner
              │
    POST /api/chat
    stream=false
    format=PlannerTurn JSON schema
              │
              ▼
      Pydantic validation
              │
              ▼
       ScopePolicy / ToolBroker
              │
              ▼
        actual tool execution
```

`OllamaPlanner` does not expose Ollama tool calling directly. The model produces a `PlannerTurn` object and the host is the only component permitted to dispatch actions.

The default Ollama endpoint is loopback only. `DOLOS_OLLAMA_ALLOW_REMOTE=false` rejects non-loopback base URLs before any request is sent. This is intentional because the normal local Ollama API is not authenticated.

Recent observations are recursively bounded before being included in AI context. Source code, HTTP output and tool results are explicitly labeled untrusted data in the model system policy. This reduces context growth and limits the amount of prompt-injection content forwarded to the planner, while the real security control remains the typed host policy.
