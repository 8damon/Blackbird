rule twodtc_bluehammer_defender_update_abuse
{
    meta:
        title = "2Dtc BlueHammer Defender update abuse artifact"
        detection = "YARA_2DTC_BLUEHAMMER_DEFENDER_UPDATE_ABUSE"
        severity = "8"
        mitre_technique_id = "T1562.001"
        mitre_technique = "Impair Defenses"
        sigma_rule_id = "blackbird.sigma.2dtc.defender_signature_update_rpc_abuse"
        scope = "file,memory,page"
    strings:
        $rpc = "IMpService77BDAF73-B396-481F-9042-AD358843EC24" ascii wide
        $call = "ServerMpUpdateEngineSignature" ascii wide
        $dir = "WDUpdateDirectory" ascii wide
        $vdm = "mpasbase.vdm" ascii wide
        $defs = "Definition Updates" ascii wide
    condition:
        2 of them
}

rule twodtc_plasma_cloudfiles_abort_hydration
{
    meta:
        title = "2Dtc Plasma Cloud Files abort hydration artifact"
        detection = "YARA_2DTC_PLASMA_CLOUDFILES_ABORT_HYDRATION"
        severity = "8"
        mitre_technique_id = "T1068"
        mitre_technique = "Exploitation for Privilege Escalation"
        sigma_rule_id = "blackbird.sigma.2dtc.cloudfiles_policy_link_abuse"
        scope = "file,memory,page"
    strings:
        $abort = "CfAbortOperation" ascii wide
        $cloud = "Software\\Policies\\Microsoft\\CloudFiles\\BlockedApps" ascii wide
        $link = "SymbolicLinkValue" ascii wide
        $lock = "DisableLockWorkstation" ascii wide
        $wer = "MiniPlasmaWERPipe" ascii wide
        $queue = "\\Microsoft\\Windows\\Windows Error Reporting\\QueueReporting" ascii wide
    condition:
        2 of them
}

rule twodtc_undefend_signature_lock
{
    meta:
        title = "2Dtc UnDefend Defender signature locking artifact"
        detection = "YARA_2DTC_UNDEFEND_SIGNATURE_LOCK"
        severity = "7"
        mitre_technique_id = "T1562.001"
        mitre_technique = "Impair Defenses"
        sigma_rule_id = "blackbird.sigma.2dtc.defender_definition_vdm_tampering"
        scope = "file,memory,page"
    strings:
        $svc = "WinDefend" ascii wide
        $sig = "SignatureLocation" ascii wide
        $base = "mpavbase.vdm" ascii wide
        $lkg = "mpavbase.lkg" ascii wide
        $mrt = "\\Windows\\System32\\MRT" ascii wide
        $notify = "NotifyServiceStatusChange" ascii wide
    condition:
        3 of them
}

rule twodtc_redsun_defender_cloudtag_rewrite
{
    meta:
        title = "2Dtc RedSun Defender cloud-tag rewrite artifact"
        detection = "YARA_2DTC_REDSUN_DEFENDER_CLOUDTAG_REWRITE"
        severity = "8"
        mitre_technique_id = "T1574.011"
        mitre_technique = "Hijack Execution Flow: Services File Permissions Weakness"
        sigma_rule_id = "blackbird.sigma.2dtc.system32_tiering_engine_service_overwrite"
        scope = "file,memory,page"
    strings:
        $provider = "SERIOUSLYMSFT" ascii wide
        $tier = "TieringEngineService.exe" ascii wide
        $pipe = "\\??\\pipe\\REDSUN" ascii wide
        $vss = "HarddiskVolumeShadowCopy" ascii wide
        $reparse = "FSCTL_SET_REPARSE_POINT" ascii wide
        $oplock = "FSCTL_REQUEST_BATCH_OPLOCK" ascii wide
    condition:
        2 of them
}

rule twodtc_yellowkey_fstx_artifact
{
    meta:
        title = "2Dtc YellowKey FsTx artifact marker"
        detection = "YARA_2DTC_YELLOWKEY_FSTX_ARTIFACT"
        severity = "7"
        mitre_technique_id = "T1006"
        mitre_technique = "Direct Volume Access"
        sigma_rule_id = "blackbird.sigma.2dtc.yellowkey_winre_fstx_artifact_staging"
        scope = "file,memory,page"
    strings:
        $fstx = "FsTx" ascii wide
        $ktm = "FsTxKtmLog" ascii wide
        $temp = "FsTxTemp" ascii wide
        $svi = "System Volume Information" ascii wide
    condition:
        2 of them
}
