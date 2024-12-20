configuration DoD_Internet_Explorer_11_V2R4
{

    param(
        [System.Boolean]$RunThisTimeEnabled = $true,
        [System.Boolean]$VersionCheckEnabled = $true,
        [System.Boolean]$History = $true,
        [System.Boolean]$RunInvalidSignatures = $true,
        [System.Boolean]$CheckExeSignatures = $true,
        [System.Boolean]$Disabled = $true,
        [System.Boolean]$DisableEPMCompat = $true,
        [System.Boolean]$Isolation64Bit = $true,
        [System.Boolean]$Isolation = $true,
        [System.Boolean]$NotifyDisableIEOptions = $true,
        [System.Boolean]$FeatureControlDisableMKProtocolReserved = $true,
        [System.Boolean]$FeatureControlDisableMKProtocolExplorer = $true,
        [System.Boolean]$FeatureControlDisableMKProtocolIE = $true,
        [System.Boolean]$FeatureControlMIMEHandlingReserved = $true,
        [System.Boolean]$FeatureControlMIMEHandlingExplorer = $true,
        [System.Boolean]$FeatureControlMIMEHandlingIE = $true,
        [System.Boolean]$FeatureControlMIMESniffingReserved = $true,
        [System.Boolean]$FeatureControlMIMESniffingExplorer = $true,
        [System.Boolean]$FeatureControlMIMESniffingIE = $true,
        [System.Boolean]$FeatureControlRestrictActiveXInstallReserved = $true,
        [System.Boolean]$FeatureControlRestrictActiveXInstallExplorer = $true,
        [System.Boolean]$ieActiveXInstall = $true,
        [System.Boolean]$restrictFileDownloadReserved = $true,
        [System.Boolean]$restrictFileDownloadExplorer = $true,
        [System.Boolean]$restrictFileDownloadIE = $true,
        [System.Boolean]$securityBandReserved = $true,
        [System.Boolean]$securityBandExplorer = $true,
        [System.Boolean]$securityBandIE = $true,
        [System.Boolean]$windowRestrictionsReserved = $true,
        [System.Boolean]$windowRestrictionsExplorer = $true,
        [System.Boolean]$windowRestrictionsIE = $true,
        [System.Boolean]$FeatureZoneElevationReserved = $true,
        [System.Boolean]$FeatureZoneElevationExplorer = $true,
        [System.Boolean]$FeatureZoneElevationIE = $true,
        [System.Boolean]$PhishingFilterPreventOverride = $true,
        [System.Boolean]$PhishingFilterPreventOverrideAppRepUnknown = $true,
        [System.Boolean]$PhishingFilterEnabledV9 = $true,
        [System.Boolean]$ClearBrowsingHistoryOnExit = $true,
        [System.Boolean]$CleanHistory = $true,
        [System.Boolean]$EnableInPrivateBrowsing = $true,
        [System.Boolean]$NoCrashDetection = $true,
        [System.Boolean]$DisableSecuritySettingsCheck = $true,
        [System.Boolean]$BlockNonAdminActiveXInstall = $true,
        [System.Boolean]$SecurityZonesMapEdit = $true,
        [System.Boolean]$SecurityOptionsEdit = $true,
        [System.Boolean]$SecurityHKLMOnly = $true,
        [System.Boolean]$PreventIgnoreCertErrors = $true,
        [System.Boolean]$CertificateRevocation = $true,
        [System.Boolean]$WarnOnBadCertRecving = $true,
        [System.Boolean]$EnableSSL3Fallback = $true,
        [System.Boolean]$SecureProtocols = $true,
        [System.Boolean]$LockdownZone0 = $true,
        [System.Boolean]$LockdownZone1 = $true,
        [System.Boolean]$LockdownZone2 = $true,
        [System.Boolean]$LockdownZone4 = $true,
        [System.Boolean]$DaysToKeep = $true,
        [System.Boolean]$UNCAsIntranet = $true,
        [System.Boolean]$Zone0_270C = $true,
        [System.Boolean]$Zone0_1C00 = $true,
        [System.Boolean]$Zone1_270C = $true,
        [System.Boolean]$Zone1_1201 = $true,
        [System.Boolean]$Zone1_1C00 = $true,
        [System.Boolean]$Zone2_270C = $true,
        [System.Boolean]$Zone2_1201 = $true,
        [System.Boolean]$Zone2_1C00 = $true,
        [System.Boolean]$Zone3_1406 = $true,
        [System.Boolean]$Zone3_1407 = $true,
        [System.Boolean]$Zone3_1802 = $true,
        [System.Boolean]$Zone3_2402 = $true,
        [System.Boolean]$Zone3_120b = $true,
        [System.Boolean]$Zone3_120c = $true,
        [System.Boolean]$Zone3_1206 = $true,
        [System.Boolean]$Zone3_2102 = $true,
        [System.Boolean]$Zone3_1209 = $true,
        [System.Boolean]$Zone3_2103 = $true,
        [System.Boolean]$Zone3_2200 = $true,
        [System.Boolean]$Zone3_270C = $true,
        [System.Boolean]$Zone3_1001 = $true,
        [System.Boolean]$Zone3_1004 = $true,
        [System.Boolean]$Zone3_2709 = $true,
        [System.Boolean]$Zone3_2708 = $true,
        [System.Boolean]$Zone3_160A = $true,
        [System.Boolean]$Zone3_1201 = $true,
        [System.Boolean]$Zone3_1C00 = $true,
        [System.Boolean]$Zone3_1804 = $true,
        [System.Boolean]$Zone3_1A00 = $true,
        [System.Boolean]$Zone3_1607 = $true,
        [System.Boolean]$Zone3_2004 = $true,
        [System.Boolean]$Zone3_2001 = $true,
        [System.Boolean]$Zone3_1806 = $true,
        [System.Boolean]$Zone3_1409 = $true,
        [System.Boolean]$Zone3_2500 = $true,
        [System.Boolean]$Zone3_2301 = $true,
        [System.Boolean]$Zone3_1809 = $true,
        [System.Boolean]$Zone3_1606 = $true,
        [System.Boolean]$Zone3_2101 = $true,
        [System.Boolean]$Zone3_140C = $true,
        [System.Boolean]$Zone4_1406 = $true,
        [System.Boolean]$Zone4_1400 = $true,
        [System.Boolean]$Zone4_2000 = $true,
        [System.Boolean]$Zone4_1407 = $true,
        [System.Boolean]$Zone4_1802 = $true,  
        [System.Boolean]$Zone4_1803 = $true,
        [System.Boolean]$Zone4_2402 = $true,
        [System.Boolean]$Zone4_1608 = $true,
        [System.Boolean]$Zone4_120b = $true,
        [System.Boolean]$Zone4_120c = $true,
        [System.Boolean]$Zone4_1206 = $true,
        [System.Boolean]$Zone4_2102 = $true,
        [System.Boolean]$Zone4_1209 = $true,
        [System.Boolean]$Zone4_2103 = $true,
        [System.Boolean]$Zone4_2200 = $true,
        [System.Boolean]$Zone4_270C = $true,
        [System.Boolean]$Zone4_1001 = $true,
        [System.Boolean]$Zone4_1004 = $true,
        [System.Boolean]$Zone4_2709 = $true,
        [System.Boolean]$Zone4_2708 = $true,
        [System.Boolean]$Zone4_160A = $true,
        [System.Boolean]$Zone4_1201 = $true,
        [System.Boolean]$Zone4_1C00 = $true,
        [System.Boolean]$Zone4_1804 = $true,
        [System.Boolean]$Zone4_1A00 = $true,
        [System.Boolean]$Zone4_1607 = $true,
        [System.Boolean]$Zone4_2004 = $true,
        [System.Boolean]$Zone4_1200 = $true,
        [System.Boolean]$Zone4_1405 = $true,
        [System.Boolean]$Zone4_1402 = $true,
        [System.Boolean]$Zone4_1806 = $true,
        [System.Boolean]$Zone4_1409 = $true,
        [System.Boolean]$Zone4_2500 = $true,
        [System.Boolean]$Zone4_2301 = $true,
        [System.Boolean]$Zone4_1809 = $true,
        [System.Boolean]$Zone4_1606 = $true,
        [System.Boolean]$Zone4_2101 = $true,
        [System.Boolean]$Zone4_2001 = $true,
        [System.Boolean]$Zone4_140C = $true
    )

    Import-DSCResource -ModuleName 'GPRegistryPolicyDsc'
	Import-DSCResource -ModuleName 'AuditPolicyDSC'
	Import-DSCResource -ModuleName 'SecurityPolicyDSC'
    
    if ($RunThisTimeEnabled) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Ext\RunThisTimeEnabled'
        {
            Key = 'Software\Microsoft\Windows\CurrentVersion\Policies\Ext'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'RunThisTimeEnabled'
        }
    }
    
    if ($VersionCheckEnabled) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Ext\VersionCheckEnabled'
        {
            Key = 'Software\Microsoft\Windows\CurrentVersion\Policies\Ext'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'VersionCheckEnabled'
        }
    }
    
    if ($History) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Control Panel\History'
        {
            Key = 'Software\Policies\Microsoft\Internet Explorer\Control Panel'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'History'
        }
    }
    
    if ($RunInvalidSignatures) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Download\RunInvalidSignatures'
        {
            Key = 'Software\Policies\Microsoft\Internet Explorer\Download'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'RunInvalidSignatures'
        }
    }
    if ($CheckExeSignatures) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Download\CheckExeSignatures'
        {
            Key = 'Software\Policies\Microsoft\Internet Explorer\Download'
            TargetType = 'ComputerConfiguration'
            ValueType = 'String'
            ValueData = 'yes'
            ValueName = 'CheckExeSignatures'
        }
    }
    
    if ($Disabled) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\IEDevTools\Disabled'
        {
            Key = 'Software\Policies\Microsoft\Internet Explorer\IEDevTools'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'Disabled'
        }
    }
    
    if ($DisableEPMCompat) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\DisableEPMCompat'
        {
            Key = 'Software\Policies\Microsoft\Internet Explorer\Main'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'DisableEPMCompat'
        }
    }
    
    if ($Isolation64Bit) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\Isolation64Bit'
        {
            Key = 'Software\Policies\Microsoft\Internet Explorer\Main'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'Isolation64Bit'
        }
    }
    
    if ($Isolation) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\Isolation'
        {
            Key = 'Software\Policies\Microsoft\Internet Explorer\Main'
            TargetType = 'ComputerConfiguration'
            ValueType = 'String'
            ValueData = 'PMEM'
            ValueName = 'Isolation'
        }
    }
    
    if ($NotifyDisableIEOptions) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\NotifyDisableIEOptions'
        {
            Key = 'Software\Policies\Microsoft\Internet Explorer\Main'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'NotifyDisableIEOptions'
        }
    }
    if ($FeatureControlDisableMKProtocolReserved) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_DISABLE_MK_PROTOCOL\(Reserved)'
        {
            Key = 'Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_DISABLE_MK_PROTOCOL'
            TargetType = 'ComputerConfiguration'
            ValueType = 'String'
            ValueData = '1'
            ValueName = '(Reserved)'
        }
    }
    
    if ($FeatureControlDisableMKProtocolExplorer) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_DISABLE_MK_PROTOCOL\explorer.exe'
        {
            Key = 'Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_DISABLE_MK_PROTOCOL'
            TargetType = 'ComputerConfiguration'
            ValueType = 'String'
            ValueData = '1'
            ValueName = 'explorer.exe'
        }
    }
    
    if ($FeatureControlDisableMKProtocolIE) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_DISABLE_MK_PROTOCOL\iexplore.exe'
        {
            Key = 'Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_DISABLE_MK_PROTOCOL'
            TargetType = 'ComputerConfiguration'
            ValueType = 'String'
            ValueData = '1'
            ValueName = 'iexplore.exe'
        }
    }
    
    if ($FeatureControlMIMEHandlingReserved) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_HANDLING\(Reserved)'
        {
            Key = 'Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_HANDLING'
            TargetType = 'ComputerConfiguration'
            ValueType = 'String'
            ValueData = '1'
            ValueName = '(Reserved)'
        }
    }
    
    if ($FeatureControlMIMEHandlingExplorer) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_HANDLING\explorer.exe'
        {
            Key = 'Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_HANDLING'
            TargetType = 'ComputerConfiguration'
            ValueType = 'String'
            ValueData = '1'
            ValueName = 'explorer.exe'
        }
    }
    
    if ($FeatureControlMIMEHandlingIE) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_HANDLING\iexplore.exe'
        {
            Key = 'Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_HANDLING'
            TargetType = 'ComputerConfiguration'
            ValueType = 'String'
            ValueData = '1'
            ValueName = 'iexplore.exe'
        }
    }
    
    if ($FeatureControlMIMESniffingReserved) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_SNIFFING\(Reserved)'
        {
            Key = 'Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_SNIFFING'
            TargetType = 'ComputerConfiguration'
            ValueType = 'String'
            ValueData = '1'
            ValueName = '(Reserved)'
        }
    }
    
    if ($FeatureControlMIMESniffingExplorer) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_SNIFFING\explorer.exe'
        {
            Key = 'Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_SNIFFING'
            TargetType = 'ComputerConfiguration'
            ValueType = 'String'
            ValueData = '1'
            ValueName = 'explorer.exe'
        }
    }
    
    if ($FeatureControlMIMESniffingIE) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_SNIFFING\iexplore.exe'
        {
            Key = 'Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_SNIFFING'
            TargetType = 'ComputerConfiguration'
            ValueType = 'String'
            ValueData = '1'
            ValueName = 'iexplore.exe'
        }
    }
    
    if ($FeatureControlRestrictActiveXInstallReserved) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_ACTIVEXINSTALL\(Reserved)'
        {
            Key = 'Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_ACTIVEXINSTALL'
            TargetType = 'ComputerConfiguration'
            ValueType = 'String'
            ValueData = '1'
            ValueName = '(Reserved)'
        }
    }
    
    if ($FeatureControlRestrictActiveXInstallExplorer) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_ACTIVEXINSTALL\explorer.exe'
        {
            Key = 'Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_ACTIVEXINSTALL'
            TargetType = 'ComputerConfiguration'
            ValueType = 'String'
            ValueData = '1'
            ValueName = 'explorer.exe'
        }
    }
    if ($ieActiveXInstall) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_ACTIVEXINSTALL\iexplore.exe'
        {
            Key = 'Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_ACTIVEXINSTALL'
            TargetType = 'ComputerConfiguration'
            ValueType = 'String'
            ValueData = '1'
            ValueName = 'iexplore.exe'
        }
    }
    
    if ($restrictFileDownloadReserved) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_FILEDOWNLOAD\(Reserved)'
        {
            Key = 'Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_FILEDOWNLOAD'
            TargetType = 'ComputerConfiguration'
            ValueType = 'String'
            ValueData = '1'
            ValueName = '(Reserved)'
        }
    }
    
    if ($restrictFileDownloadExplorer) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_FILEDOWNLOAD\explorer.exe'
        {
            Key = 'Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_FILEDOWNLOAD'
            TargetType = 'ComputerConfiguration'
            ValueType = 'String'
            ValueData = '1'
            ValueName = 'explorer.exe'
        }
    }
    
    if ($restrictFileDownloadIE) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_FILEDOWNLOAD\iexplore.exe'
        {
            Key = 'Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_FILEDOWNLOAD'
            TargetType = 'ComputerConfiguration'
            ValueType = 'String'
            ValueData = '1'
            ValueName = 'iexplore.exe'
        }
    }
    
    if ($securityBandReserved) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_SECURITYBAND\(Reserved)'
        {
            Key = 'Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_SECURITYBAND'
            TargetType = 'ComputerConfiguration'
            ValueType = 'String'
            ValueData = '1'
            ValueName = '(Reserved)'
        }
    }
    
    if ($securityBandExplorer) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_SECURITYBAND\explorer.exe'
        {
            Key = 'Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_SECURITYBAND'
            TargetType = 'ComputerConfiguration'
            ValueType = 'String'
            ValueData = '1'
            ValueName = 'explorer.exe'
        }
    }
    
    if ($securityBandIE) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_SECURITYBAND\iexplore.exe'
        {
            Key = 'Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_SECURITYBAND'
            TargetType = 'ComputerConfiguration'
            ValueType = 'String'
            ValueData = '1'
            ValueName = 'iexplore.exe'
        }
    }
    
    if ($windowRestrictionsReserved) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WINDOW_RESTRICTIONS\(Reserved)'
        {
            Key = 'Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WINDOW_RESTRICTIONS'
            TargetType = 'ComputerConfiguration'
            ValueType = 'String'
            ValueData = '1'
            ValueName = '(Reserved)'
        }
    }
    
    if ($windowRestrictionsExplorer) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WINDOW_RESTRICTIONS\explorer.exe'
        {
            Key = 'Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WINDOW_RESTRICTIONS'
            TargetType = 'ComputerConfiguration'
            ValueType = 'String'
            ValueData = '1'
            ValueName = 'explorer.exe'
        }
    }
    
    if ($windowRestrictionsIE) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WINDOW_RESTRICTIONS\iexplore.exe'
        {
            Key = 'Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WINDOW_RESTRICTIONS'
            TargetType = 'ComputerConfiguration'
            ValueType = 'String'
            ValueData = '1'
            ValueName = 'iexplore.exe'
        }
    }

    if ($FeatureZoneElevationReserved) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ZONE_ELEVATION\(Reserved)'
        {
            Key = 'Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ZONE_ELEVATION'
            TargetType = 'ComputerConfiguration'
            ValueType = 'String'
            ValueData = '1'
            ValueName = '(Reserved)'
        }
    }
    
    if ($FeatureZoneElevationExplorer) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ZONE_ELEVATION\explorer.exe'
        {
            Key = 'Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ZONE_ELEVATION'
            TargetType = 'ComputerConfiguration'
            ValueType = 'String'
            ValueData = '1'
            ValueName = 'explorer.exe'
        }
    }
    
    if ($FeatureZoneElevationIE) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ZONE_ELEVATION\iexplore.exe'
        {
            Key = 'Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ZONE_ELEVATION'
            TargetType = 'ComputerConfiguration'
            ValueType = 'String'
            ValueData = '1'
            ValueName = 'iexplore.exe'
        }
    }
    
    if ($PhishingFilterPreventOverride) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\PhishingFilter\PreventOverride'
        {
            Key = 'Software\Policies\Microsoft\Internet Explorer\PhishingFilter'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'PreventOverride'
        }
    }
    
    if ($PhishingFilterPreventOverrideAppRepUnknown) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\PhishingFilter\PreventOverrideAppRepUnknown'
        {
            Key = 'Software\Policies\Microsoft\Internet Explorer\PhishingFilter'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'PreventOverrideAppRepUnknown'
        }
    }
    
    if ($PhishingFilterEnabledV9) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\PhishingFilter\EnabledV9'
        {
            Key = 'Software\Policies\Microsoft\Internet Explorer\PhishingFilter'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'EnabledV9'
        }
    }
    
    if ($ClearBrowsingHistoryOnExit) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Privacy\ClearBrowsingHistoryOnExit'
        {
            Key = 'Software\Policies\Microsoft\Internet Explorer\Privacy'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'ClearBrowsingHistoryOnExit'
        }
    }
    
    if ($CleanHistory) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Privacy\CleanHistory'
        {
            Key = 'Software\Policies\Microsoft\Internet Explorer\Privacy'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'CleanHistory'
        }
    }
    
    if ($EnableInPrivateBrowsing) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Privacy\EnableInPrivateBrowsing'
        {
            Key = 'Software\Policies\Microsoft\Internet Explorer\Privacy'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'EnableInPrivateBrowsing'
        }
    }
    
    if ($NoCrashDetection) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Restrictions\NoCrashDetection'
        {
            Key = 'Software\Policies\Microsoft\Internet Explorer\Restrictions'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'NoCrashDetection'
        }
    }
    
    if ($DisableSecuritySettingsCheck) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Security\DisableSecuritySettingsCheck'
        {
            Key = 'Software\Policies\Microsoft\Internet Explorer\Security'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'DisableSecuritySettingsCheck'
        }
    }
    
    if ($BlockNonAdminActiveXInstall) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Security\ActiveX\BlockNonAdminActiveXInstall'
        {
            Key = 'Software\Policies\Microsoft\Internet Explorer\Security\ActiveX'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'BlockNonAdminActiveXInstall'
        }
    }
    
    if ($SecurityZonesMapEdit) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Security_zones_map_edit'
        {
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'Security_zones_map_edit'
        }
    }
    
    if ($SecurityOptionsEdit) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Security_options_edit'
        {
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'Security_options_edit'
        }
    }

    if ($SecurityHKLMOnly) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Security_HKLM_only'
        {
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'Security_HKLM_only'
        }
    }
    
    if ($PreventIgnoreCertErrors) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\PreventIgnoreCertErrors'
        {
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'PreventIgnoreCertErrors'
        }
    }
    
    if ($CertificateRevocation) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\CertificateRevocation'
        {
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'CertificateRevocation'
        }
    }
    
    if ($WarnOnBadCertRecving) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\WarnOnBadCertRecving'
        {
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'WarnOnBadCertRecving'
        }
    }
    
    if ($EnableSSL3Fallback) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\EnableSSL3Fallback'
        {
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'EnableSSL3Fallback'
        }
    }
    
    if ($SecureProtocols) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\SecureProtocols'
        {
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 2048
            ValueName = 'SecureProtocols'
        }
    }
    
    if ($LockdownZone0) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\0\1C00'
        {
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\0'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = '1C00'
        }
    }
    
    if ($LockdownZone1) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\1\1C00'
        {
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\1'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = '1C00'
        }
    }
    
    if ($LockdownZone2) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\2\1C00'
        {
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\2'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = '1C00'
        }
    }
    
    if ($LockdownZone4) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\4\1C00'
        {
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\4'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = '1C00'
        }
    }
    if ($DaysToKeep) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Url History\DaysToKeep'
        {
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Url History'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 40
            ValueName = 'DaysToKeep'
        }
    }
    
    if ($UNCAsIntranet) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\UNCAsIntranet'
        {
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'UNCAsIntranet'
        }
    }
    
    if ($Zone0_270C) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\0\270C'
        {
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\0'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = '270C'
        }
    }
    
    if ($Zone0_1C00) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\0\1C00'
        {
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\0'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = '1C00'
        }
    }
    
    if ($Zone1_270C) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\1\270C'
        {
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\1'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = '270C'
        }
    }
    
    if ($Zone1_1201) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\1\1201'
        {
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\1'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 3
            ValueName = '1201'
        }
    }
    
    if ($Zone1_1C00) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\1\1C00'
        {
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\1'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 65536
            ValueName = '1C00'
        }
    }
    
    if ($Zone2_270C) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2\270C'
        {
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = '270C'
        }
    }
    
    if ($Zone2_1201) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2\1201'
        {
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 3
            ValueName = '1201'
        }
    }
    
    if ($Zone2_1C00) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2\1C00'
        {
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 65536
            ValueName = '1C00'
        }
    }
    
    if ($Zone3_1406) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\1406'
        {
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 3
            ValueName = '1406'
        }
    }
    if ($Zone3_1407) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\1407'
        {
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 3
            ValueName = '1407'
        }
    }
    
    if ($Zone3_1802) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\1802'
        {
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 3
            ValueName = '1802'
        }
    }
    
    if ($Zone3_2402) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\2402'
        {
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 3
            ValueName = '2402'
        }
    }
    
    if ($Zone3_120b) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\120b'
        {
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 3
            ValueName = '120b'
        }
    }
    
    if ($Zone3_120c) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\120c'
        {
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 3
            ValueName = '120c'
        }
    }
    
    if ($Zone3_1206) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\1206'
        {
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 3
            ValueName = '1206'
        }
    }
    
    if ($Zone3_2102) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\2102'
        {
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 3
            ValueName = '2102'
        }
    }
    
    if ($Zone3_1209) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\1209'
        {
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 3
            ValueName = '1209'
        }
    }
    
    if ($Zone3_2103) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\2103'
        {
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 3
            ValueName = '2103'
        }
    }
    
    if ($Zone3_2200) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\2200'
        {
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 3
            ValueName = '2200'
        }
    }
    
    if ($Zone3_270C) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\270C'
        {
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = '270C'
        }
    }
    
    if ($Zone3_1001) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\1001'
        {
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 3
            ValueName = '1001'
        }
    }
    
    if ($Zone3_1004) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\1004'
        {
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 3
            ValueName = '1004'
        }
    }
    if ($Zone3_2709) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\2709'
        {
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 3
            ValueName = '2709'
        }
    }
    
    if ($Zone3_2708) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\2708'
        {
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 3
            ValueName = '2708'
        }
    }
    
    if ($Zone3_160A) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\160A'
        {
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 3
            ValueName = '160A'
        }
    }
    
    if ($Zone3_1201) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\1201'
        {
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 3
            ValueName = '1201'
        }
    }
    
    if ($Zone3_1C00) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\1C00'
        {
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = '1C00'
        }
    }
    
    if ($Zone3_1804) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\1804'
        {
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 3
            ValueName = '1804'
        }
    }
    
    if ($Zone3_1A00) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\1A00'
        {
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 65536
            ValueName = '1A00'
        }
    }
    
    if ($Zone3_1607) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\1607'
        {
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 3
            ValueName = '1607'
        }
    }
    
    if ($Zone3_2004) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\2004'
        {
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 3
            ValueName = '2004'
        }
    }
    
    if ($Zone3_2001) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\2001'
        {
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 3
            ValueName = '2001'
        }
    }
    
    if ($Zone3_1806) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\1806'
        {
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = '1806'
        }
    }
    
    if ($Zone3_1409) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\1409'
        {
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = '1409'
        }
    }
    
    if ($Zone3_2500) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\2500'
        {
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = '2500'
        }
    }
    
    if ($Zone3_2301) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\2301'
        {
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = '2301'
        }
    }
    
    if ($Zone3_1809) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\1809'
        {
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = '1809'
        }
    }

    if ($Zone3_1606) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\1606'
        {
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 3
            ValueName = '1606'
        }
    }
    
    if ($Zone3_2101) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\2101'
        {
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 3
            ValueName = '2101'
        }
    }
    
    if ($Zone3_140C) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\140C'
        {
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 3
            ValueName = '140C'
        }
    }
    
    if ($Zone4_1406) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\1406'
        {
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 3
            ValueName = '1406'
        }
    }
    
    if ($Zone4_1400) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\1400'
        {
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 3
            ValueName = '1400'
        }
    }
    
    if ($Zone4_2000) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\2000'
        {
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 3
            ValueName = '2000'
        }
    }
    
    if ($Zone4_1407) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\1407'
        {
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 3
            ValueName = '1407'
        }
    }
    
    if ($Zone4_1802) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\1802'
        {
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 3
            ValueName = '1802'
        }
    }

    if ($Zone4_1803) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\1803'
        {
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 3
            ValueName = '1803'
        }
    }
    
    if ($Zone4_2402) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\2402'
        {
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 3
            ValueName = '2402'
        }
    }
    
    if ($Zone4_1608) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\1608'
        {
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 3
            ValueName = '1608'
        }
    }
    
    if ($Zone4_120b) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\120b'
        {
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 3
            ValueName = '120b'
        }
    }
    
    if ($Zone4_120c) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\120c'
        {
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 3
            ValueName = '120c'
        }
    }
    
    if ($Zone4_1206) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\1206'
        {
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 3
            ValueName = '1206'
        }
    }
    
    if ($Zone4_2102) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\2102'
        {
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 3
            ValueName = '2102'
        }
    }
    
    if ($Zone4_1209) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\1209'
        {
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 3
            ValueName = '1209'
        }
    }
    
    if ($Zone4_2103) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\2103'
        {
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 3
            ValueName = '2103'
        }
    }

    if ($Zone4_2200) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\2200'
        {
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 3
            ValueName = '2200'
        }
    }
    
    if ($Zone4_270C) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\270C'
        {
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = '270C'
        }
    }
    
    if ($Zone4_1001) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\1001'
        {
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 3
            ValueName = '1001'
        }
    }
    
    if ($Zone4_1004) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\1004'
        {
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 3
            ValueName = '1004'
        }
    }
    
    if ($Zone4_2709) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\2709'
        {
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 3
            ValueName = '2709'
        }
    }
    
    if ($Zone4_2708) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\2708'
        {
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 3
            ValueName = '2708'
        }
    }
    
    if ($Zone4_160A) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\160A'
        {
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 3
            ValueName = '160A'
        }
    }
    
    if ($Zone4_1201) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\1201'
        {
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 3
            ValueName = '1201'
        }
    }
    
    if ($Zone4_1C00) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\1C00'
        {
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = '1C00'
        }
    }
    
    if ($Zone4_1804) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\1804'
        {
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 3
            ValueName = '1804'
        }
    }
    if ($Zone4_1A00) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\1A00'
        {
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 196608
            ValueName = '1A00'
        }
    }
    
    if ($Zone4_1607) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\1607'
        {
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 3
            ValueName = '1607'
        }
    }
    
    if ($Zone4_2004) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\2004'
        {
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 3
            ValueName = '2004'
        }
    }
    
    if ($Zone4_1200) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\1200'
        {
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 3
            ValueName = '1200'
        }
    }
    
    if ($Zone4_1405) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\1405'
        {
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 3
            ValueName = '1405'
        }
    }
    
    if ($Zone4_1402) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\1402'
        {
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 3
            ValueName = '1402'
        }
    }
    
    if ($Zone4_1806) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\1806'
        {
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 3
            ValueName = '1806'
        }
    }
    
    if ($Zone4_1409) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\1409'
        {
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = '1409'
        }
    }
    
    if ($Zone4_2500) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\2500'
        {
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = '2500'
        }
    }
    if ($Zone4_2301) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\2301'
        {
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = '2301'
        }
    }
    
    if ($Zone4_1809) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\1809'
        {
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = '1809'
        }
    }
    
    if ($Zone4_1606) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\1606'
        {
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 3
            ValueName = '1606'
        }
    }
    
    if ($Zone4_2101) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\2101'
        {
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 3
            ValueName = '2101'
        }
    }
    
    if ($Zone4_2001) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\2001'
        {
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 3
            ValueName = '2001'
        }
    }
    
    if ($Zone4_140C) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\140C'
        {
            Key = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 3
            ValueName = '140C'
        }
    }
}

