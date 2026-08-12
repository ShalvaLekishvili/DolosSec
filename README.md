# DolosSec Agent

**DolosSec** is a clean-room, policy-gated autonomous application-security research framework with a local web control plane. It is designed around a simple trust rule:

> **The agent proposes → policy authorizes → tools execute → evidence becomes findings.**

The project intentionally avoids giving an LLM an unrestricted network shell. Remote actions are validated against an explicit authorization scope, while local source analysis can run without granting arbitrary network execution.

## v0.2 — Web Control Plane

The main workflow is now available through a local browser interface:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e '.[ai,dev]'

dolos web
```

Open `http://127.0.0.1:8787` if the browser does not open automatically.

The UI is loopback-only in this release and provides:

- Local-directory target selection with a restricted server-side directory browser.
- Manual absolute-path entry for local source trees.
- Authorized `http://` / `https://` target entry.
- Remote authorization metadata: owner, ticket/reference, purpose and expiration.
- Quick, Standard and Deep scan modes.
- Live planner/tool execution timeline over Server-Sent Events.
- Incremental findings while the assessment is still running.
- Final Markdown report inside the UI.
- Downloadable `report.md`, `findings.json` and hash-chained `audit.jsonl`.
- Automatic scope snapshot stored with each remote run.

## Current security research capabilities

- Expiring authorization/scope manifests in YAML.
- URL, hostname, IP and CIDR scope enforcement.
- Private-network blocking unless explicitly enabled for an authorized lab/internal target.
- Typed planner actions and strict validation.
- Policy-gated HTTP probing with redirect re-validation.
- Source-tree mapping and heuristic source security review.
- OpenAI planner support as an optional extra.
- Deterministic fallback planner for offline and reproducible operation.
- Structured findings in JSON and Markdown.
- Tamper-evident hash-chained JSONL audit log.
- Conservative defaults: GET/HEAD/OPTIONS only, bounded response size, timeouts and rate limits.

## Web workflow

```text
┌──────────────────────┐
│  Local Web Control   │
│  127.0.0.1:8787      │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│ Target + Authorization│
│ Local path / URL     │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│  ScopePolicy         │
│  validates boundary  │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│ Planner / Orchestrator│
└──────────┬───────────┘
           │ typed actions
           ▼
┌──────────────────────┐
│ Trusted Tool Broker  │
└──────────┬───────────┘
           │
     ┌─────┴─────────┐
     ▼               ▼
 HTTP checks     Source review
     │               │
     └─────┬─────────┘
           ▼
 Evidence → Findings → Report
           │
           ▼
       Live Web UI
```

## CLI remains available

### Local source scan

```bash
dolos scan ./your-app --mode standard
```

### Authorized web scan

```bash
dolos init scope.yaml
# edit the authorization/scope values

dolos scan https://staging.example.com --scope scope.yaml --mode standard
```

Remote CLI targets require an explicit, non-expired scope manifest. The web UI collects the same authorization data and stores the resulting scope with the run.

## Optional AI planner

```bash
export DOLOS_LLM_PROVIDER=openai
export DOLOS_MODEL='<supported-model>'
export OPENAI_API_KEY='...'
dolos web
```

Without a configured model, DolosSec uses the deterministic planner so the system stays testable and useful offline.

## Run artifacts

Each assessment is written to `dolos_runs/<run-id>/`:

```text
scope.yaml          authorization/scope snapshot
run.json            run metadata
observations.json   structured tool observations
findings.json       normalized findings
report.md           human-readable assessment
audit.jsonl         hash-chained execution record
```

## Development

```bash
pip install -e '.[ai,dev]'
pytest
```

The current test suite covers policy enforcement, path/method denial, audit-chain integrity, source review, web-origin protection, remote authorization requirements and a web-triggered end-to-end local assessment.

## Security model

Read [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) and [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) before extending the tool layer.

Important current limitation: the v0.2 web control plane is intended for **local loopback use**. It does not yet provide multi-user authentication or a hardened remote-management deployment mode.

## Project status

DolosSec is an early security-research platform, not a replacement for a professional penetration test. The current release deliberately does not ship credential attacks, persistence, destructive actions, arbitrary remote shells, or data-exfiltration modules.

## License

Apache License 2.0. See [`LICENSE`](LICENSE).
