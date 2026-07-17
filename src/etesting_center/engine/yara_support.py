from __future__ import annotations

from pathlib import Path

from .models import Finding


class YaraScanner:
    def __init__(self, rules_dir: Path) -> None:
        self.rules_dir = rules_dir
        self.enabled = False
        self.error: str | None = None
        self._rules = None
        self._load_rules()

    def _load_rules(self) -> None:
        try:
            import yara  # type: ignore
        except Exception as exc:  # pragma: no cover - depends on optional binary package
            self.error = f"yara-python is unavailable: {exc}"
            return

        rule_files = [path for path in self.rules_dir.glob("*.yar")] + [path for path in self.rules_dir.glob("*.yara")]
        if not rule_files:
            self.enabled = True
            self._rules = None
            return

        try:
            file_map = {path.stem: str(path) for path in rule_files}
            self._rules = yara.compile(filepaths=file_map)
            self.enabled = True
        except Exception as exc:
            self.error = f"YARA rules failed to compile: {exc}"

    def scan(self, path: Path) -> list[Finding]:
        if not self.enabled or self._rules is None:
            return []
        try:
            matches = self._rules.match(str(path), timeout=10)
        except Exception as exc:
            return [
                Finding(
                    engine="yara",
                    rule="yara_scan_error",
                    severity="suspicious",
                    confidence=20,
                    description="YARA scan could not complete for this file.",
                    details={"error": str(exc)},
                )
            ]

        findings: list[Finding] = []
        for match in matches:
            severity = str(match.meta.get("severity", "suspicious")).lower()
            confidence = int(match.meta.get("confidence", 50))
            description = str(match.meta.get("description", f"YARA rule matched: {match.rule}"))
            findings.append(
                Finding(
                    engine="yara",
                    rule=match.rule,
                    severity="malicious" if severity == "malicious" else "suspicious",
                    confidence=confidence,
                    description=description,
                    details={"namespace": match.namespace, "tags": list(match.tags)},
                )
            )
        return findings
