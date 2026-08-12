import json
from pathlib import Path

from dolossec.audit import AuditLog


def test_hash_chain(tmp_path: Path):
    log = AuditLog(tmp_path / "audit.jsonl")
    h1 = log.append("a", {"x": 1})
    h2 = log.append("b", {"y": 2})
    rows = [json.loads(x) for x in (tmp_path / "audit.jsonl").read_text().splitlines()]
    assert rows[0]["event_hash"] == h1
    assert rows[1]["previous_hash"] == h1
    assert rows[1]["event_hash"] == h2
