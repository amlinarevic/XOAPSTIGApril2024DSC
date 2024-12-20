configuration DoD_Adobe_Acrobat_Pro_DC_Continuous_V2R1
{
    
    param(
        [System.Boolean]$DisableMaintenance = $true,
        [System.Boolean]$bEnhancedSecurityStandalone = $true,
        [System.Boolean]$bEnhancedSecurityInBrowser = $true,
        [System.Boolean]$iFileAttachmentPerms = $true,
        [System.Boolean]$bEnableFlash = $true,
        [System.Boolean]$bDisableTrustedFolders = $true,
        [System.Boolean]$bProtectedMode = $true,
        [System.Boolean]$iProtectedView = $true,
        [System.Boolean]$bDisablePDFHandlerSwitching = $true,
        [System.Boolean]$bDisableTrustedSites = $true,
        [System.Boolean]$bAdobeSendPluginToggle = $true,
        [System.Boolean]$bDisableADCFileStore = $true,
        [System.Boolean]$iUnknownURLPerms = $true,
        [System.Boolean]$iURLPerms = $true,
        [System.Boolean]$bTogglePrefsSync = $true,
        [System.Boolean]$bToggleWebConnectors = $true,
        [System.Boolean]$bDisableSharePointFeatures = $true,
        [System.Boolean]$bDisableWebmail = $true,
        [System.Boolean]$bShowWelcomeScreen = $true,
        [System.Boolean]$DisableMaintenanceWow6432Node = $true
    )
    
    
    Import-DSCResource -ModuleName 'GPRegistryPolicyDsc'
	Import-DSCResource -ModuleName 'AuditPolicyDSC'
	Import-DSCResource -ModuleName 'SecurityPolicyDSC'


	{
        if($DisableMaintenance){
            RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Adobe\Adobe Acrobat\DC\Installer\DisableMaintenance'
            {
                Key = 'HKLM:\SOFTWARE\Adobe\Adobe Acrobat\DC\Installer'
                TargetType = 'ComputerConfiguration'
                ValueType = 'Dword'
                ValueData = 1
                ValueName = 'DisableMaintenance'
            }
        }

        if($bEnhancedSecurityStandalone){
            RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockdown\bEnhancedSecurityStandalone'
            {
                Key = 'SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockdown'
                TargetType = 'ComputerConfiguration'
                ValueType = 'Dword'
                ValueData = 1
                ValueName = 'bEnhancedSecurityStandalone'
            }
        }

        if ($bEnhancedSecurityInBrowser) {
            RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockdown\bEnhancedSecurityInBrowser'
            {
                Key = 'SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockdown'
                TargetType = 'ComputerConfiguration'
                ValueType = 'Dword'
                ValueData = 1
                ValueName = 'bEnhancedSecurityInBrowser'
            }
        }
        
        if ($iFileAttachmentPerms) {
            RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockdown\iFileAttachmentPerms'
            {
                Key = 'SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockdown'
                TargetType = 'ComputerConfiguration'
                ValueType = 'Dword'
                ValueData = 1
                ValueName = 'iFileAttachmentPerms'
            }
        }
        
        if ($bEnableFlash) {
            RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockdown\bEnableFlash'
            {
                Key = 'SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockdown'
                TargetType = 'ComputerConfiguration'
                ValueType = 'Dword'
                ValueData = 0
                ValueName = 'bEnableFlash'
            }
        }
        if ($bDisableTrustedFolders) {
            RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockdown\bDisableTrustedFolders'
            {
                Key = 'SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockdown'
                TargetType = 'ComputerConfiguration'
                ValueType = 'Dword'
                ValueData = 1
                ValueName = 'bDisableTrustedFolders'
            }
        }
        
        if ($bProtectedMode) {
            RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockdown\bProtectedMode'
            {
                Key = 'SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockdown'
                TargetType = 'ComputerConfiguration'
                ValueType = 'Dword'
                ValueData = 1
                ValueName = 'bProtectedMode'
            }
        }
        
        if ($iProtectedView) {
            RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockdown\iProtectedView'
            {
                Key = 'SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockdown'
                TargetType = 'ComputerConfiguration'
                ValueType = 'Dword'
                ValueData = 1
                ValueName = 'iProtectedView'
            }
        }
        
        if ($bDisablePDFHandlerSwitching) {
            RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockdown\bDisablePDFHandlerSwitching'
            {
                Key = 'SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockdown'
                TargetType = 'ComputerConfiguration'
                ValueType = 'Dword'
                ValueData = 1
                ValueName = 'bDisablePDFHandlerSwitching'
            }
        }
        
        if ($bDisableTrustedSites) {
            RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockdown\bDisableTrustedSites'
            {
                Key = 'SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockdown'
                TargetType = 'ComputerConfiguration'
                ValueType = 'Dword'
                ValueData = 1
                ValueName = 'bDisableTrustedSites'
            }
        }
        
        if ($bAdobeSendPluginToggle) {
            RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockdown\cCloud\bAdobeSendPluginToggle'
            {
                Key = 'SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockdown\cCloud'
                TargetType = 'ComputerConfiguration'
                ValueType = 'Dword'
                ValueData = 1
                ValueName = 'bAdobeSendPluginToggle'
            }
        }
        
        if ($bDisableADCFileStore) {
            RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockdown\cCloud\bDisableADCFileStore'
            {
                Key = 'SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockdown\cCloud'
                TargetType = 'ComputerConfiguration'
                ValueType = 'Dword'
                ValueData = 1
                ValueName = 'bDisableADCFileStore'
            }
        }
        
        if ($iUnknownURLPerms) {
            RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockdown\cDefaultLaunchURLPerms\iUnknownURLPerms'
            {
                Key = 'SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockdown\cDefaultLaunchURLPerms'
                TargetType = 'ComputerConfiguration'
                ValueType = 'Dword'
                ValueData = 1
                ValueName = 'iUnknownURLPerms'
            }
        }
        
        if ($iURLPerms) {
            RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockdown\cDefaultLaunchURLPerms\iURLPerms'
            {
                Key = 'SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockdown\cDefaultLaunchURLPerms'
                TargetType = 'ComputerConfiguration'
                ValueType = 'Dword'
                ValueData = 1
                ValueName = 'iURLPerms'
            }
        }
        
        if ($bTogglePrefsSync) {
            RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockdown\cServices\bTogglePrefsSync'
            {
                Key = 'SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockdown\cServices'
                TargetType = 'ComputerConfiguration'
                ValueType = 'Dword'
                ValueData = 1
                ValueName = 'bTogglePrefsSync'
            }
        }
        
        if ($bToggleWebConnectors) {
            RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockdown\cServices\bToggleWebConnectors'
            {
                Key = 'SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockdown\cServices'
                TargetType = 'ComputerConfiguration'
                ValueType = 'Dword'
                ValueData = 1
                ValueName = 'bToggleWebConnectors'
            }
        }
        
        if ($bDisableSharePointFeatures) {
            RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockdown\cSharePoint\bDisableSharePointFeatures'
            {
                Key = 'SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockdown\cSharePoint'
                TargetType = 'ComputerConfiguration'
                ValueType = 'Dword'
                ValueData = 1
                ValueName = 'bDisableSharePointFeatures'
            }
        }
        
        if ($bDisableWebmail) {
            RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockdown\cWebmailProfiles\bDisableWebmail'
            {
                Key = 'SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockdown\cWebmailProfiles'
                TargetType = 'ComputerConfiguration'
                ValueType = 'Dword'
                ValueData = 1
                ValueName = 'bDisableWebmail'
            }
        }
        
        if ($bShowWelcomeScreen) {
            RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockdown\cWelcomeScreen\bShowWelcomeScreen'
            {
                Key = 'SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockdown\cWelcomeScreen'
                TargetType = 'ComputerConfiguration'
                ValueType = 'Dword'
                ValueData = 0
                ValueName = 'bShowWelcomeScreen'
            }
        }
        
        if ($DisableMaintenanceWow6432Node) {
            RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Wow6432Node\Adobe\Adobe Acrobat\DC\Installer\DisableMaintenance'
            {
                Key = 'SOFTWARE\Wow6432Node\Adobe\Adobe Acrobat\DC\Installer'
                TargetType = 'ComputerConfiguration'
                ValueType = 'Dword'
                ValueData = 1
                ValueName = 'DisableMaintenance'
            }
        }

         RefreshRegistryPolicy 'ActivateClientSideExtension'
         {
             IsSingleInstance = 'Yes'
         }
     }



}

