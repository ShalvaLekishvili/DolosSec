# Contributing to DolosSec

DolosSec is built around a policy-gated agent model. Contributions that add scanners, agent actions, integrations, or execution capabilities must preserve that boundary.

## Development setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e '.[ai,dev]'
pytest
```

## Pull request expectations

- Add tests for new policy, tool, web API, or reporting behavior.
- Do not give the planner an unrestricted remote shell.
- Network-capable tools must validate scope at execution time, not only during planning.
- Keep secrets and generated assessment output out of commits.
- Update architecture or threat-model documentation for trust-boundary changes.
- Prefer typed actions and structured evidence over free-form execution.
