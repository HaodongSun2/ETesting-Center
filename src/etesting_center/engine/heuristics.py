"""Heuristic analysis engine for ETestingCenter.

Detects suspicious patterns in files:
1. PE files - entropy, packer signatures, suspicious imports
2. Scripts - suspicious tokens, obfuscation patterns
3. Documents - auto-open macros, embedded scripts
4. General - extension mismatches, double extensions
"""

from __future__ import annotations

import math
from pathlib import Path

from .models import Finding

# ===========================================================================
# Suspicious API / Token Sets
# ===========================================================================

INJECTION_APIS = {
    b"VirtualAlloc", b"VirtualAllocEx", b"VirtualProtect", b"VirtualProtectEx",
    b"WriteProcessMemory", b"ReadProcessMemory", b"CreateRemoteThread",
    b"NtCreateThreadEx", b"RtlCreateUserThread", b"QueueUserAPC",
    b"SetThreadContext", b"MapViewOfFile",
}

EXEC_APIS = {
    b"WinExec", b"ShellExecute", b"ShellExecuteEx",
    b"CreateProcess", b"system", b"popen",
}

NETWORK_APIS = {
    b"URLDownloadToFile", b"URLDownloadToCacheFile", b"InternetOpen",
    b"InternetConnect", b"InternetOpenUrl", b"HttpSendRequest",
    b"WinHttpOpen", b"WinHttpConnect", b"socket", b"connect",
    b"WSAConnect", b"send", b"recv", b"gethostbyname",
}

CREDENTIAL_APIS = {
    b"CredEnumerate", b"CredRead", b"CryptUnprotectData",
    b"LsaRetrievePrivateData", b"SamQueryInformationUser",
    b"VaultEnumerateItems",
}

KEYLOG_APIS = {
    b"SetWindowsHookEx", b"GetAsyncKeyState", b"GetKeyState",
    b"GetKeyboardState", b"GetForegroundWindow", b"keylog",
}

SUSPICIOUS_SCRIPT_TOKENS = {
    b"powershell -enc", b"frombase64string", b"invoke-expression",
    b"iex ", b"wscript.shell", b"createobject",
    b"downloadstring", b"downloadfile", b"certutil -decode",
    b"regsvr32", b"rundll32", b"mshta",
    b"bitsadmin", b"start-process", b"-windowstyle hidden",
    b"-executionpolicy bypass", b"new-object net.webclient",
    b"new-object system.net.sockets.tcpclient",
}

PACKER_MARKERS = {
    b"UPX0", b"UPX1", b"UPX2",
    b"MPRESS", b".mpress",
    b"Themida", b"WinLic",
    b"VMProtect", b"VMP0", b"VMP1", b"VMP2", b"VMP3",
    b"ASPack", b".aspack",
    b".enigma", b"Enigma",
    b".pelock", b"pelock",
    b"petite", b".yoda", b"yoda", b".ccg",
}

SCRIPT_EXTENSIONS = {".ps1", ".vbs", ".js", ".jse", ".bat", ".cmd", ".hta", ".wsf", ".wsc", ".sct"}
DOCUMENT_EXTENSIONS = {".doc", ".docm", ".xls", ".xlsm", ".ppt", ".pptm", ".rtf", ".dot", ".dotm"}
EXECUTABLE_EXTENSIONS = {".exe", ".dll", ".sys", ".ocx", ".drv", ".scr", ".com", ".cpl", ".msi"}


def detect_file_type(path: Path, data: bytes) -> str:
    """Detect file type via magic bytes and extension."""
    suffix = path.suffix.lower().lstrip(".") or "unknown"

    if len(data) < 2:
        return suffix

    if data[:2] == b"MZ":
        return "pe"
    if data[:4] == b"\x7fELF":
        return "elf"
    if data[:4] == b"\xca\xfe\xba\xbe" or data[:4] == b"\xfe\xed\xfa\xce":
        return "mach-o"
    if data[:4] == b"\x50\x4b\x03\x04":
        return "zip"
    if data[:8] == b"\x89PNG\r\n\x1a\n":
        return "png"
    if data[:3] == b"\xff\xd8\xff":
        return "jpeg"
    if data[:4] == b"%PDF":
        return "pdf"
    if data[:4] == b"\xd0\xcf\x11\xe0":
        return "ole"
    if data[:4] == b"\x25\x21\x50\x53":
        return "postscript"
    if data[:4] == b"Rar!":
        return "rar"
    if data[:2] == b"\x1f\x8b":
        return "gzip"
    if data[:4] == b"\x1f\x9d\x90\x00":
        return "lzma"

    if suffix in SCRIPT_EXTENSIONS:
        return "script"
    if suffix in DOCUMENT_EXTENSIONS:
        return "document"
    if suffix in EXECUTABLE_EXTENSIONS:
        return "executable"

    return suffix


def compute_entropy(data: bytes) -> float:
    """Compute Shannon entropy (0-8). >7.2 suggests encryption or packing."""
    if not data:
        return 0.0
    length = len(data)
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    entropy = 0.0
    for c in counts:
        if c > 0:
            p = c / length
            entropy -= p * math.log2(p)
    return entropy


def heuristic_findings(path: Path, data: bytes) -> list[Finding]:
    """Run heuristic analysis on a file. Returns list of Finding objects.

    Confidence scale (reduced to lower false positives):
    - 50-55: High suspicion (extension mismatch, double extension)
    - 40-45: Medium suspicion (suspicious imports, tokens)
    - 25-35: Low suspicion (entropy, minor patterns)
    """
    findings: list[Finding] = []
    ent = compute_entropy(data)
    file_type = detect_file_type(path, data)
    ext = path.suffix.lower()

    # 1. Extension mismatch (PE in non-exe extension)
    if file_type == "pe" and ext not in EXECUTABLE_EXTENSIONS:
        findings.append(Finding(
            engine="heuristic", rule="extension_mismatch_pe",
            severity="suspicious", confidence=55,
            description=f"PE file with non-executable extension: {ext}",
        ))

    # 2. Double extension disguise
    stem_parts = path.stem.split(".")
    if len(stem_parts) >= 2:
        second = "." + stem_parts[-1]
        if second.lower() in EXECUTABLE_EXTENSIONS and ext != second:
            findings.append(Finding(
                engine="heuristic", rule="double_extension_disguise",
                severity="suspicious", confidence=50,
                description=f"Double extension disguise: {path.name}",
            ))

    # 3. High entropy (potential packing/encryption)
    if ent > 7.2:
        findings.append(Finding(
            engine="heuristic", rule="high_entropy",
            severity="suspicious", confidence=35,
            description=f"High entropy ({ent:.1f}) indicates packing or encryption",
        ))

    # 4. Detect packer signatures in PE files
    if file_type == "pe":
        packer_hits = [m for m in PACKER_MARKERS if m in data]
        if packer_hits:
            severity = "suspicious"
            conf = min(45, 25 + len(packer_hits) * 5)
            findings.append(Finding(
                engine="heuristic", rule="packer_signature",
                severity=severity, confidence=conf,
                description=f"Packer signatures: {', '.join(s.decode('utf-8', errors='replace') for s in packer_hits)}",
            ))

    # 5. Suspicious imported APIs in PE
    if file_type == "pe":
        inj_count = sum(1 for api in INJECTION_APIS if api in data)
        exec_count = sum(1 for api in EXEC_APIS if api in data)
        net_count = sum(1 for api in NETWORK_APIS if api in data)
        cred_count = sum(1 for api in CREDENTIAL_APIS if api in data)
        key_count = sum(1 for api in KEYLOG_APIS if api in data)
        total = inj_count + exec_count + net_count + cred_count + key_count

        if total >= 3:
            severity = "suspicious"
            conf = min(45, 20 + total * 4)
            details = []
            if inj_count:
                details.append(f"{inj_count} injection APIs")
            if exec_count:
                details.append(f"{exec_count} execution APIs")
            if net_count:
                details.append(f"{net_count} network APIs")
            if cred_count:
                details.append(f"{cred_count} credential APIs")
            if key_count:
                details.append(f"{key_count} keylogging APIs")
            findings.append(Finding(
                engine="heuristic", rule="suspicious_api_imports",
                severity=severity, confidence=conf,
                description=f"Suspicious API imports ({total}): {', '.join(details)}",
            ))

    # 6. Suspicious tokens in scripts
    if file_type == "script":
        tokens_found = [t for t in SUSPICIOUS_SCRIPT_TOKENS if t.lower() in data.lower()]
        if tokens_found:
            conf = min(40, 20 + len(tokens_found) * 3)
            findings.append(Finding(
                engine="heuristic", rule="suspicious_script_tokens",
                severity="suspicious", confidence=conf,
                description=f"Suspicious script tokens: {', '.join(t.decode('utf-8', errors='replace') for t in tokens_found[:5])}",
            ))

    # 7. Auto-execution macros in documents
    if file_type in ("document", "ole"):
        doc_markers = [b"AutoOpen", b"Document_Open", b"AutoExec", b"AutoClose"]
        hits = [m for m in doc_markers if m in data]
        if hits:
            findings.append(Finding(
                engine="heuristic", rule="auto_exec_macro",
                severity="suspicious", confidence=35,
                description=f"Auto-execution macro markers: {', '.join(h.decode() for h in hits)}",
            ))

    # 8. PowerShell obfuscation patterns
    if file_type == "script":
        obf_indicators = 0
        if b"frombase64string" in data.lower():
            obf_indicators += 1
        if b"-enc " in data.lower() or b"-encodedcommand" in data.lower():
            obf_indicators += 1
        if data.count(b"`") > 10:
            obf_indicators += 1
        if b"iex " in data.lower() or b"invoke-expression" in data.lower():
            obf_indicators += 1
        if obf_indicators >= 2:
            findings.append(Finding(
                engine="heuristic", rule="powershell_obfuscation",
                severity="suspicious", confidence=40,
                description=f"PowerShell obfuscation detected ({obf_indicators} indicators)",
            ))

    # 9. WMI/COM lateral movement in scripts
    if file_type == "script":
        wmi_markers = [b"wmi", b"winmgmts", b"swbemlocator", b"getobject(\"winmgmts"]
        if any(m in data.lower() for m in wmi_markers):
            findings.append(Finding(
                engine="heuristic", rule="wmi_lateral_movement",
                severity="suspicious", confidence=30,
                description="WMI/COM lateral movement pattern",
            ))

    return findings
