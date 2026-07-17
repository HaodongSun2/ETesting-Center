rule Suspicious_PowerShell_Encoded_Command
{
    meta:
        description = "PowerShell encoded command pattern"
        severity = "suspicious"
        confidence = 65
    strings:
        $ps = "powershell" nocase
        $enc1 = "-enc" nocase
        $enc2 = "-encodedcommand" nocase
    condition:
        $ps and any of ($enc*)
}

rule Suspicious_Windows_Loader_API_Strings
{
    meta:
        description = "Executable contains a cluster of loader or injection related API strings"
        severity = "suspicious"
        confidence = 70
    strings:
        $a1 = "VirtualAlloc" ascii wide
        $a2 = "WriteProcessMemory" ascii wide
        $a3 = "CreateRemoteThread" ascii wide
        $a4 = "VirtualProtect" ascii wide
    condition:
        uint16(0) == 0x5a4d and 3 of them
}
