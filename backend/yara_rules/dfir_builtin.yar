/*
    DFIR Investigation Suite — Built-in YARA Rules
    These rules detect common malware patterns, tools, and techniques
*/

rule Suspicious_PowerShell_Encoded {
    meta:
        description = "Detects encoded PowerShell commands"
        severity = "high"
        mitre_attack = "T1059.001"
    strings:
        $enc1 = "-EncodedCommand" nocase
        $enc2 = "-enc " nocase
        $enc3 = "-e " nocase
        $bypass = "bypass" nocase
        $hidden = "-WindowStyle Hidden" nocase
        $nop = "-NoProfile" nocase
    condition:
        ($enc1 or $enc2) and ($bypass or $hidden or $nop)
}

rule Mimikatz_Strings {
    meta:
        description = "Detects Mimikatz credential dumping tool"
        severity = "critical"
        mitre_attack = "T1003.001"
    strings:
        $s1 = "mimikatz" nocase
        $s2 = "sekurlsa::logonpasswords" nocase
        $s3 = "lsadump::sam" nocase
        $s4 = "privilege::debug" nocase
        $s5 = "Benjamin DELPY" nocase
        $s6 = "gentilkiwi" nocase
        $s7 = "kiwi" nocase
    condition:
        any of them
}

rule Meterpreter_Payload {
    meta:
        description = "Detects Metasploit Meterpreter payload strings"
        severity = "critical"
        mitre_attack = "T1059"
    strings:
        $s1 = "meterpreter" nocase
        $s2 = "metasploit" nocase
        $s3 = "ReflectiveDllInjection" nocase
        $s4 = "MSFPAYLOAD" nocase
        $pe1 = { 4D 5A 90 00 }
    condition:
        ($s1 or $s2 or $s3 or $s4)
}

rule Cobalt_Strike_Beacon {
    meta:
        description = "Detects Cobalt Strike beacon patterns"
        severity = "critical"
        mitre_attack = "T1071.001"
    strings:
        $s1 = "cobaltstrike" nocase
        $s2 = "beacon" nocase
        $s3 = "sleep_mask" nocase
        $s4 = { 69 68 69 68 69 6B }
        $watermark = "Cobalt Strike" nocase
    condition:
        any of them
}

rule Ransomware_Note_Pattern {
    meta:
        description = "Detects common ransomware note patterns"
        severity = "critical"
        mitre_attack = "T1486"
    strings:
        $n1 = "YOUR FILES HAVE BEEN ENCRYPTED" nocase
        $n2 = "All your files are encrypted" nocase
        $n3 = "To decrypt your files" nocase
        $n4 = "bitcoin" nocase
        $n5 = "pay the ransom" nocase
        $n6 = "DECRYPT_INSTRUCTION" nocase
        $n7 = "YOUR_FILES_ARE_ENCRYPTED" nocase
    condition:
        2 of them
}

rule Suspicious_Script_Download {
    meta:
        description = "Detects scripts downloading payloads from internet"
        severity = "high"
        mitre_attack = "T1105"
    strings:
        $dl1 = "Invoke-WebRequest" nocase
        $dl2 = "DownloadString" nocase
        $dl3 = "DownloadFile" nocase
        $dl4 = "WebClient" nocase
        $dl5 = "curl " nocase
        $dl6 = "wget " nocase
        $url1 = "http://" nocase
        $url2 = "https://" nocase
    condition:
        ($dl1 or $dl2 or $dl3 or $dl4 or $dl5 or $dl6) and ($url1 or $url2)
}

rule Process_Injection_Shellcode {
    meta:
        description = "Detects process injection / shellcode patterns"
        severity = "critical"
        mitre_attack = "T1055"
    strings:
        $api1 = "VirtualAllocEx" nocase
        $api2 = "WriteProcessMemory" nocase
        $api3 = "CreateRemoteThread" nocase
        $api4 = "NtCreateThreadEx" nocase
        $api5 = "RtlCreateUserThread" nocase
        $sc = { FC E8 82 00 00 00 }
    condition:
        2 of ($api*) or $sc
}

rule Suspicious_WMI_Execution {
    meta:
        description = "Detects suspicious WMI command execution"
        severity = "high"
        mitre_attack = "T1047"
    strings:
        $w1 = "wmic" nocase
        $w2 = "Win32_Process" nocase
        $w3 = "CREATE" nocase
        $w4 = "wbemtest" nocase
    condition:
        ($w1 and $w2 and $w3) or $w4
}

rule LSASS_Access_Attempt {
    meta:
        description = "Detects LSASS memory access for credential dumping"
        severity = "critical"
        mitre_attack = "T1003.001"
    strings:
        $s1 = "lsass.exe" nocase
        $s2 = "lsass.dmp" nocase
        $s3 = "procdump" nocase
        $s4 = "sekurlsa" nocase
        $s5 = "wdigest" nocase
    condition:
        any of them
}

rule Suspicious_Registry_Modification {
    meta:
        description = "Detects suspicious registry modifications for persistence"
        severity = "high"
        mitre_attack = "T1547.001"
    strings:
        $r1 = "CurrentVersion\\Run" nocase
        $r2 = "CurrentVersion\\RunOnce" nocase
        $r3 = "Winlogon\\Shell" nocase
        $r4 = "reg add" nocase
        $r5 = "REG_SZ" nocase
    condition:
        ($r1 or $r2 or $r3) and ($r4 or $r5)
}
