from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from dolossec.models import Authorization, PolicySpec, ScopeManifest, ScopeSpec, Target, TargetKind
from dolossec.policy import PolicyViolation, ScopePolicy


def manifest(**scope_kwargs):
    return ScopeManifest(
        authorization=Authorization(owner="tester", ticket="T-1", purpose="test", expires_at=datetime.now(UTC) + timedelta(hours=1)),
        scope=ScopeSpec(**scope_kwargs),
        policy=PolicySpec(),
    )


def test_exact_host_allowed():
    p = ScopePolicy(manifest(urls=["https://example.com"], hosts=["example.com"]))
    p.assert_url_allowed("https://example.com/a")


def test_subdomain_not_implicitly_allowed():
    p = ScopePolicy(manifest(hosts=["example.com"]))
    with pytest.raises(PolicyViolation):
        p.assert_url_allowed("https://evil.example.com")


def test_remote_method_default_denies_post():
    p = ScopePolicy(manifest(hosts=["example.com"]))
    with pytest.raises(PolicyViolation):
        p.assert_method_allowed("POST")


def test_local_path_boundary(tmp_path: Path):
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    p = ScopePolicy(manifest(local_paths=[str(allowed)]))
    p.assert_path_allowed(allowed)
    with pytest.raises(PolicyViolation):
        p.assert_path_allowed(tmp_path / "other")
