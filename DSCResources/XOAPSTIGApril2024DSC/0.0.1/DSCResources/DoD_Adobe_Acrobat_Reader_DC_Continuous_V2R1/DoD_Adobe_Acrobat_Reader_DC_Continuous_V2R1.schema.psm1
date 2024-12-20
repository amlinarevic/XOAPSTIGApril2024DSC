configuration DoD_Adobe_Acrobat_Reader_DC_Continuous_V2R1
{

    param(
        [System.Boolean]$DisableMaintenance = $true,
        [System.Boolean]$bEnhancedSecurityStandalone = $true,
        [System.Boolean]$bProtectedMode = $true,
        [System.Boolean]$iProtectedView = $true,
        [System.Boolean]$iFileAttachmentPerms = $true,
        [System.Boolean]$bEnableFlash = $true,
        [System.Boolean]$bDisablePDFHandlerSwitching = $true,
        [System.Boolean]$bAcroSuppressUpsell = $true,
        [System.Boolean]$bEnhancedSecurityInBrowser = $true,
        [System.Boolean]$bDisableTrustedFolders = $true,
        [System.Boolean]$bDisableTrustedSites = $true,
        [System.Boolean]$bAdobeSendPluginToggle = $true,
        [System.Boolean]$iURLPerms = $true,
        [System.Boolean]$iUnknownURLPerms = $true,
        [System.Boolean]$bToggleAdobeDocumentServices = $true,
        [System.Boolean]$bTogglePrefsSync = $true,
        [System.Boolean]$bToggleWebConnectors = $true,
        [System.Boolean]$bToggleAdobeSign = $true,
        [System.Boolean]$bUpdater = $true,
        [System.Boolean]$bDisableSharePointFeatures = $true,
        [System.Boolean]$bDisableWebmail = $true,
        [System.Boolean]$bShowWelcomeScreen = $true,
        [System.Boolean]$DisableMaintenanceWow6432Node = $true
    )
	
    Import-DSCResource -ModuleName 'GPRegistryPolicyDsc'
	Import-DSCResource -ModuleName 'AuditPolicyDSC'
	Import-DSCResource -ModuleName 'SecurityPolicyDSC'

    if ($DisableMaintenance) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Adobe\Acrobat Reader\DC\Installer\DisableMaintenance'
        {
            Key = 'SOFTWARE\Adobe\Acrobat Reader\DC\Installer'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'DisableMaintenance'
        }
    }
    
    if ($bEnhancedSecurityStandalone) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\bEnhancedSecurityStandalone'
        {
            Key = 'SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'bEnhancedSecurityStandalone'
        }
    }
    
    if ($bProtectedMode) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\bProtectedMode'
        {
            Key = 'SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'bProtectedMode'
        }
    }
    
    if ($iProtectedView) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\iProtectedView'
        {
            Key = 'SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 2
            ValueName = 'iProtectedView'
        }
    }
    
    if ($iFileAttachmentPerms) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\iFileAttachmentPerms'
        {
            Key = 'SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'iFileAttachmentPerms'
        }
    }
    
    if ($bEnableFlash) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\bEnableFlash'
        {
            Key = 'SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'bEnableFlash'
        }
    }
    
    if ($bDisablePDFHandlerSwitching) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\bDisablePDFHandlerSwitching'
        {
            Key = 'SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'bDisablePDFHandlerSwitching'
        }
    }
    if ($bAcroSuppressUpsell) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\bAcroSuppressUpsell'
        {
            Key = 'SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'bAcroSuppressUpsell'
        }
    }
    
    if ($bEnhancedSecurityInBrowser) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\bEnhancedSecurityInBrowser'
        {
            Key = 'SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'bEnhancedSecurityInBrowser'
        }
    }
    
    if ($bDisableTrustedFolders) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\bDisableTrustedFolders'
        {
            Key = 'SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'bDisableTrustedFolders'
        }
    }
    
    if ($bDisableTrustedSites) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\bDisableTrustedSites'
        {
            Key = 'SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'bDisableTrustedSites'
        }
    }
    
    if ($bAdobeSendPluginToggle) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\cCloud\bAdobeSendPluginToggle'
        {
            Key = 'SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\cCloud'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'bAdobeSendPluginToggle'
        }
    }
    
    if ($iURLPerms) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\cDefaultLaunchURLPerms\iURLPerms'
        {
            Key = 'SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\cDefaultLaunchURLPerms'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'iURLPerms'
        }
    }
    
    if ($iUnknownURLPerms) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\cDefaultLaunchURLPerms\iUnknownURLPerms'
        {
            Key = 'SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\cDefaultLaunchURLPerms'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 3
            ValueName = 'iUnknownURLPerms'
        }
    }
    
    if ($bToggleAdobeDocumentServices) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\cServices\bToggleAdobeDocumentServices'
        {
            Key = 'SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\cServices'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'bToggleAdobeDocumentServices'
        }
    }
    
    if ($bTogglePrefsSync) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\cServices\bTogglePrefsSync'
        {
            Key = 'SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\cServices'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'bTogglePrefsSync'
        }
    }
    
    if ($bToggleWebConnectors) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\cServices\bToggleWebConnectors'
        {
            Key = 'SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\cServices'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'bToggleWebConnectors'
        }
    }
    
    if ($bToggleAdobeSign) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\cServices\bToggleAdobeSign'
        {
            Key = 'SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\cServices'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'bToggleAdobeSign'
        }
    }
    
    if ($bUpdater) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\cServices\bUpdater'
        {
            Key = 'SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\cServices'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'bUpdater'
        }
    }
    
    if ($bDisableSharePointFeatures) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\cSharePoint\bDisableSharePointFeatures'
        {
            Key = 'SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\cSharePoint'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'bDisableSharePointFeatures'
        }
    }
    
    if ($bDisableWebmail) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\cWebmailProfiles\bDisableWebmail'
        {
            Key = 'SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\cWebmailProfiles'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'bDisableWebmail'
        }
    }
    
    if ($bShowWelcomeScreen) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\cWelcomeScreen\bShowWelcomeScreen'
        {
            Key = 'SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\cWelcomeScreen'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'bShowWelcomeScreen'
        }
    }
    
    if ($DisableMaintenanceWow6432Node) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Wow6432Node\Adobe\Acrobat Reader\DC\Installer\DisableMaintenance'
        {
            Key = 'SOFTWARE\Wow6432Node\Adobe\Acrobat Reader\DC\Installer'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'DisableMaintenance'
        }
    }
}

