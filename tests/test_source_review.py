import asyncio
from datetime import UTC, datetime, timedelta
from pathlib import Path

from dolossec.models import Authorization, ScopeManifest, ScopeSpec
from dolossec.policy import ScopePolicy
from dolossec.tooling.source import SourceReviewTool


def test_source_review_finds_hardcoded_secret(tmp_path: Path):
    (tmp_path / "app.py").write_text('API_KEY = "1234567890abcdef"\n', encoding="utf-8")
    policy = ScopePolicy(ScopeManifest(
        authorization=Authorization(owner="x", ticket="t", purpose="p", expires_at=datetime.now(UTC) + timedelta(hours=1)),
        scope=ScopeSpec(local_paths=[str(tmp_path)]),
    ))
    obs = asyncio.run(SourceReviewTool(policy).run({"path": str(tmp_path)}))
    assert obs.ok
    assert any(x["rule_id"] == "hardcoded_secret" for x in obs.data["matches"])
