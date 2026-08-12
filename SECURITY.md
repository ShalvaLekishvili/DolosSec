# Security Policy

DolosSec is security software and should be treated as a privileged local application.

## Supported version

Security fixes are currently applied to the latest development release only.

## Reporting a vulnerability

Please avoid publishing exploit details for a previously unknown DolosSec vulnerability before maintainers have had a reasonable opportunity to investigate and patch it. Include the affected version, reproduction steps, impact, and any suggested mitigation.

## Operating assumptions

- Run the web interface on the default loopback binding (`127.0.0.1`).
- Do not expose the current web control plane directly to an untrusted network.
- Keep remote assessment targets inside an explicit, unexpired authorization scope.
- Treat reports, audit logs, source paths, API keys and assessment evidence as sensitive data.
- Review `docs/THREAT_MODEL.md` before adding new tools or agent capabilities.

The core invariant is: **the model proposes; policy code authorizes; tools execute.**
