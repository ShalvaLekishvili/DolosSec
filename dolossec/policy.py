from __future__ import annotations

import ipaddress
import socket
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlparse

import yaml

from .models import ScopeManifest, Target, TargetKind


class PolicyViolation(ValueError):
    pass


def load_manifest(path: Path) -> ScopeManifest:
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    return ScopeManifest.model_validate(raw)


class ScopePolicy:
    def __init__(self, manifest: ScopeManifest):
        self.manifest = manifest
        self.allowed_hosts = {h.lower().rstrip(".") for h in manifest.scope.hosts}
        for raw_url in manifest.scope.urls:
            host = urlparse(raw_url).hostname
            if host:
                self.allowed_hosts.add(host.lower().rstrip("."))
        self.allowed_networks = [ipaddress.ip_network(c, strict=False) for c in manifest.scope.cidrs]
        self.allowed_paths = [Path(p).expanduser().resolve() for p in manifest.scope.local_paths]

    def validate_authorization(self) -> None:
        expiry = self.manifest.authorization.expires_at
        if expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=UTC)
        if expiry.astimezone(UTC) <= datetime.now(UTC):
            raise PolicyViolation("authorization scope has expired")

    def validate_initial_target(self, target: Target) -> None:
        self.validate_authorization()
        if target.kind == TargetKind.url:
            self.assert_url_allowed(target.value)
        else:
            self.assert_path_allowed(Path(target.value))

    def assert_method_allowed(self, method: str) -> None:
        method = method.upper()
        if method not in self.manifest.policy.allowed_http_methods:
            raise PolicyViolation(f"HTTP method {method} is not allowed by scope policy")

    def assert_path_allowed(self, path: Path) -> None:
        resolved = path.expanduser().resolve()
        if not self.allowed_paths:
            raise PolicyViolation("scope manifest contains no local_paths")
        if not any(resolved == base or base in resolved.parents for base in self.allowed_paths):
            raise PolicyViolation(f"local path is outside authorized scope: {resolved}")

    def assert_url_allowed(self, url: str) -> None:
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"}:
            raise PolicyViolation("only http and https URLs are supported")
        if parsed.username or parsed.password:
            raise PolicyViolation("userinfo in target URLs is not permitted")
        if not parsed.hostname:
            raise PolicyViolation("URL has no hostname")
        self.assert_host_allowed(parsed.hostname)

    def assert_host_allowed(self, host: str) -> None:
        host_norm = host.lower().rstrip(".")
        try:
            ip = ipaddress.ip_address(host_norm)
        except ValueError:
            if host_norm not in self.allowed_hosts:
                raise PolicyViolation(f"host is outside authorized scope: {host_norm}")
            return

        if self.allowed_networks and any(ip in net for net in self.allowed_networks):
            if (ip.is_private or ip.is_loopback or ip.is_link_local) and not self.manifest.policy.allow_private_networks:
                raise PolicyViolation("private/link-local/loopback network access is disabled")
            return
        raise PolicyViolation(f"IP is outside authorized CIDR scope: {ip}")

    def validate_resolved_ips(self, host: str) -> list[str]:
        """Defense-in-depth DNS check. Hostname scope remains authoritative.

        If private network access is disabled, a scoped hostname resolving to a private,
        loopback, link-local or reserved address is rejected to reduce DNS rebinding/SSRF risk.
        """
        self.assert_host_allowed(host)
        try:
            infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        except socket.gaierror:
            return []
        ips = sorted({info[4][0] for info in infos})
        if self.manifest.policy.allow_private_networks:
            return ips
        for raw in ips:
            ip = ipaddress.ip_address(raw)
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
                raise PolicyViolation(f"scoped hostname resolves to non-public address: {raw}")
        return ips
