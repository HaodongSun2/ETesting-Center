from __future__ import annotations

import json
from pathlib import Path

from .models import Finding


class HashDatabase:
    def __init__(self, records: dict[str, dict[str, str]] | None = None) -> None:
        self.records = {key.lower(): value for key, value in (records or {}).items()}

    @classmethod
    def load(cls, path: Path) -> "HashDatabase":
        if not path.exists():
            return cls()
        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, list):
            records = {item["sha256"].lower(): item for item in data if "sha256" in item}
        elif isinstance(data, dict):
            records = data
        else:
            records = {}
        return cls(records)

    def match(self, md5: str, sha256: str) -> Finding | None:
        record = self.records.get(sha256.lower()) or self.records.get(md5.lower())
        if not record:
            return None
        name = record.get("name", "Known malicious hash")
        family = record.get("family", "unknown")
        return Finding(
            engine="hash",
            rule=name,
            severity="malicious",
            confidence=100,
            description=f"Known malicious file hash matched: {name}",
            details={"family": family, "source": record.get("source", "local")},
        )
