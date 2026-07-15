from __future__ import annotations

import math
from pathlib import Path

from .models import Finding

SUSPICIOUS_IMPORTS = {
    b"VirtualAlloc",
    b"VirtualProtect",
    b"WriteProcessMemory",
    b"CreateRemoteThread",
    b"WinExec",
    b"ShellExecute",
    b"URLDownloadToFile",
    b"InternetOpen",
    b"HttpSendRequest",
    b"CryptDecrypt",
    b"IsDebuggerPresent",
}

SUSPICIOUS_SCRIPT_TOKENS = {
    b"powershell -enc",
    b"frombase64string",
    b"invoke-expression",
    b"wscript.shell",
    b"createobject",
    b"downloadstring",
    b"certutil -decode",
    b"regsvr32",
    b"rundll32",
}

PACKER_MARKERS = {
    b"UPX0",
    b"UPX1",
    b"MPRESS",
    b"Themida",
    b"VMProtect",
    b"ASPack",
}

SCRIPT_EXTENSIONS = {".ps1", ".vbs", ".js", ".jse", ".bat", ".cmd", ".hta", ".wsf"}
DOCUMENT_EXTENSIONS = {".doc", ".docm", ".xls", ".xlsm", ".ppt", ".pptm", ".rtf"}


def detect_file_type(path: Path, data: bytes) -> str:
    suffix = path.suffix.lower().lstrip(".") or "unknown"
    if data.startswith(b"MZ"):
        return "PE executable"
    if data.startswith(b"\x7fELF"):
        return "ELF binary"
    if data[:4] in {b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe"}:
        return "Mach-O binary"
    if data.startswith(b"PK\x03\x04"):
        return f"ZIP container / {suffix}"
    if data.startswith(b"%PDF"):
        return "PDF document"
    return suffix.upper() if suffix != "unknown" else "unknown"


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    length = len(data)
    return -sum((count / length) * math.log2(count / length) for count in counts if count)


def heuristic_findings(path: Path, data: bytes) -> list[Finding]:
    lowered = data.lower()
    findings: list[Finding] = []

    if data.startswith(b"MZ"):
        file_entropy = entropy(data[: min(len(data), 2 * 1024 * 1024)])
        if file_entropy >= 7.2:
            findings.append(
                Finding(
                    engine="heuristic",
                    rule="high_entropy_pe",
                    severity="suspicious",
                    confidence=55,
                    description="PE file has high entropy, which can indicate packing or encryption.",
                    details={"entropy": round(file_entropy, 3)},
                )
            )

        matched_imports = sorted(token.decode("ascii", errors="ignore") for token in SUSPICIOUS_IMPORTS if token.lower() in lowered)
        if len(matched_imports) >= 3:
            findings.append(
                Finding(
                    engine="heuristic",
                    rule="suspicious_windows_api_cluster",
                    severity="suspicious",
                    confidence=min(80, 30 + len(matched_imports) * 8),
                    description="Executable references multiple APIs commonly used by loaders or injectors.",
                    details={"imports": matched_imports[:12]},
                )
            )

        packer_hits = sorted(marker.decode("ascii", errors="ignore") for marker in PACKER_MARKERS if marker.lower() in lowered)
        if packer_hits:
            findings.append(
                Finding(
                    engine="heuristic",
                    rule="packer_marker",
                    severity="suspicious",
                    confidence=60,
                    description="Executable contains known packer marker strings.",
                    details={"markers": packer_hits},
                )
            )

    suffix = path.suffix.lower()
    if suffix in SCRIPT_EXTENSIONS:
        token_hits = sorted(token.decode("ascii", errors="ignore") for token in SUSPICIOUS_SCRIPT_TOKENS if token in lowered)
        if token_hits:
            findings.append(
                Finding(
                    engine="heuristic",
                    rule="suspicious_script_tokens",
                    severity="suspicious",
                    confidence=min(85, 35 + len(token_hits) * 10),
                    description="Script contains command patterns often used for obfuscation or download execution.",
                    details={"tokens": token_hits},
                )
            )

    if suffix in DOCUMENT_EXTENSIONS and (b"autoopen" in lowered or b"document_open" in lowered or b"vba" in lowered):
        findings.append(
            Finding(
                engine="heuristic",
                rule="macro_document_indicator",
                severity="suspicious",
                confidence=45,
                description="Document contains macro-related indicators.",
                details={"extension": suffix},
            )
        )

    return findings
