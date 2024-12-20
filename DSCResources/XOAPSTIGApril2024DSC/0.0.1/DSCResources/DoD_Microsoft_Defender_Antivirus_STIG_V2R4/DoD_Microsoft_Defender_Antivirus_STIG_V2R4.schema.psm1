configuration DoD_Microsoft_Defender_Antivirus_STIG_V2R4
{
    param(
        [System.Boolean]$PUAProtection = $true,
        [System.Boolean]$DisableAutoExclusions = $true,
        [System.Boolean]$DisableRemovableDriveScanning = $true,
        [System.Boolean]$DisableEmailScanning = $true,
        [System.Boolean]$ScheduleDay = $true,
        [System.Boolean]$ASSignatureDue = $true,
        [System.Boolean]$AVSignatureDue = $true,
        [System.Boolean]$SignatureUpdatesScheduleDay = $true,
        [System.Boolean]$DisableBlockAtFirstSeen = $true,
        [System.Boolean]$SpyNetReporting = $true,
        [System.Boolean]$SubmitSamplesConsent = $true,
        [System.Boolean]$ThreatsThreatSeverityDefaultAction = $true,
        [System.Boolean]$ExploitGuardASRRules = $true,
        [System.Boolean]$EnableNetworkProtection = $true
    )

	Import-DSCResource -ModuleName 'GPRegistryPolicyDsc'
	Import-DSCResource -ModuleName 'AuditPolicyDSC'
	Import-DSCResource -ModuleName 'SecurityPolicyDSC'
    f ($PUAProtection) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\PUAProtection'
        {
            Key = 'Software\Policies\Microsoft\Windows Defender'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'PUAProtection'
        }
    }
    
    if ($DisableAutoExclusions) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Exclusions\DisableAutoExclusions'
        {
            Key = 'Software\Policies\Microsoft\Windows Defender\Exclusions'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'DisableAutoExclusions'
        }
    }
    
    if ($DisableRemovableDriveScanning) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Scan\DisableRemovableDriveScanning'
        {
            Key = 'Software\Policies\Microsoft\Windows Defender\Scan'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'DisableRemovableDriveScanning'
        }
    }
    
    if ($DisableEmailScanning) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Scan\DisableEmailScanning'
        {
            Key = 'Software\Policies\Microsoft\Windows Defender\Scan'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'DisableEmailScanning'
        }
    }
    
    if ($ScheduleDay) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Scan\ScheduleDay'
        {
            Key = 'Software\Policies\Microsoft\Windows Defender\Scan'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'ScheduleDay'
        }
    }
    
    if ($ASSignatureDue) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Signature Updates\ASSignatureDue'
        {
            Key = 'Software\Policies\Microsoft\Windows Defender\Signature Updates'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 7
            ValueName = 'ASSignatureDue'
        }
    }
    
    if ($AVSignatureDue) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Signature Updates\AVSignatureDue'
        {
            Key = 'Software\Policies\Microsoft\Windows Defender\Signature Updates'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 7
            ValueName = 'AVSignatureDue'
        }
    }
    
    if ($SignatureUpdatesScheduleDay) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Signature Updates\ScheduleDay'
        {
            Key = 'Software\Policies\Microsoft\Windows Defender\Signature Updates'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'ScheduleDay'
        }
    }
    
    if ($DisableBlockAtFirstSeen) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Spynet\DisableBlockAtFirstSeen'
        {
            Key = 'Software\Policies\Microsoft\Windows Defender\Spynet'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'DisableBlockAtFirstSeen'
        }
    }
    
    if ($SpyNetReporting) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Spynet\SpynetReporting'
        {
            Key = 'Software\Policies\Microsoft\Windows Defender\Spynet'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 2
            ValueName = 'SpynetReporting'
        }
    }
    
    if ($SubmitSamplesConsent) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Spynet\SubmitSamplesConsent'
        {
            Key = 'Software\Policies\Microsoft\Windows Defender\Spynet'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'SubmitSamplesConsent'
        }
    }
    
    if ($ThreatsThreatSeverityDefaultAction) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Threats\Threats_ThreatSeverityDefaultAction'
        {
            Key = 'Software\Policies\Microsoft\Windows Defender\Threats'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'Threats_ThreatSeverityDefaultAction'
        }
    }
    
    if ($ExploitGuardASRRules) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\ExploitGuard_ASR_Rules'
        {
            Key = 'Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'ExploitGuard_ASR_Rules'
        }
    }
    
    if ($EnableNetworkProtection) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection\EnableNetworkProtection'
        {
            Key = 'Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'EnableNetworkProtection'
        }
    }
}

