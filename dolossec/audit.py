from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


class AuditLog:
    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.previous_hash = "0" * 64

    def append(self, event_type: str, data: dict[str, Any]) -> str:
        event = {
            "timestamp": datetime.now(UTC).isoformat(),
            "event_type": event_type,
            "data": data,
            "previous_hash": self.previous_hash,
        }
        canonical = json.dumps(event, sort_keys=True, separators=(",", ":"), default=str)
        event_hash = hashlib.sha256(canonical.encode()).hexdigest()
        event["event_hash"] = event_hash
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(event, sort_keys=True, default=str) + "\n")
        self.previous_hash = event_hash
        return event_hash
