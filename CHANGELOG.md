# Changelog

## 0.5.0

- Added mandatory same-origin passive web attack-surface discovery for URL assessments.
- Added route, form, script, query-parameter, cookie, CORS, technology, API-hint, robots.txt and sitemap.xml inventory.
- Added target-specific Web attack surface section to Markdown reports.
- Added live web-console attack-surface panel.
- Added conservative findings for observed cookie flags, password forms using GET, mixed content, directory listings, wildcard CORS and X-Powered-By disclosure.
- Prevented deterministic and AI planners from skipping the minimum remote discovery phase.
- Added passive web inventory regression tests.

## 0.4.0 — Local Ollama AI

- Added a native Ollama REST client with no paid API dependency.
- Added `OllamaPlanner` using Pydantic/JSON-schema structured outputs.
- Added bounded observation context and explicit prompt-injection handling instructions for model input.
- Added loopback-only Ollama enforcement by default; remote AI hosts require explicit opt-in.
- Added Ollama service/version/model discovery.
- Added pre-run validation that the selected local model is installed.
- Added per-run planner model metadata.
- Added web-console AI provider/model selection and local Ollama status.
- Added `dolos ollama status`, `pull`, `test`, and `install-guide` commands.
- Added Linux bootstrap and Windows model setup helpers.
- Added full Kali/Linux, macOS, Windows and troubleshooting documentation in `docs/OLLAMA.md`.
- Added Ollama unit tests and raised the suite to 15 tests.

## 0.3.0 — Security Research Console

- Added persistent scan history and recovery from run artifacts.
- Added human approval gate for Deep mode.
- Added operator-selected Bandit, Semgrep and Trivy filesystem adapters.
- Added finding CWE/CVSS/source-tool metadata.
- Added richer live agent execution UI and evidence views.
- Added adapter capability endpoint and tightened repository packaging.

## 0.2.0 — Web Control Plane

- Added local web UI for local directories and authorized URLs.
- Added live Server-Sent Events scan progress and incremental findings.
- Added report/artifact download endpoints.

## 0.1.0 — Foundation

- Initial policy-gated orchestrator, deterministic/OpenAI planners, source/HTTP tools, scope manifests and hash-chained audit log.
