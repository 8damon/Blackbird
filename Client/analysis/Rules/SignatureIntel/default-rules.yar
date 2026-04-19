rule direct_syscall_stub
{
    meta:
        title = "Direct syscall stub bytes"
        detection = "YARA_DIRECT_SYSCALL_STUB"
        severity = "7"
        mitre_technique_id = "T1106"
        mitre_technique = "Native API"
        sigma_rule_id = "blackbird.direct_syscall_stub"
        scope = "file,memory,page"
    strings:
        $a = { 4C 8B D1 B8 ?? ?? ?? ?? 0F 05 }
    condition:
        $a
}

rule amsi_patch_signature
{
    meta:
        title = "Common AMSI patch bytes"
        detection = "YARA_AMSI_PATCH_BYTES"
        severity = "6"
        mitre_technique_id = "T1562.001"
        mitre_technique = "Impair Defenses"
        sigma_rule_id = "blackbird.amsi_patch_signature"
        scope = "file,memory,page"
    strings:
        $a = { B8 57 00 07 80 C3 }
        $b = { 31 C0 C3 }
    condition:
        any of them
}
