# DolosSec architecture

DolosSec separates **reasoning** from **authority**. A planner may decide what it wants to inspect, but trusted application code determines what it is allowed to execute.

## Components

1. **Local web control plane** — target selection, authorization input, live progress, findings and artifacts. It binds to loopback only in v0.2.
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
