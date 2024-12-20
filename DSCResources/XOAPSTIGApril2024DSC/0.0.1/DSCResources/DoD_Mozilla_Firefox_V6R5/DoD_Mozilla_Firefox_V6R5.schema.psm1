configuration DoD_Mozilla_Firefox_V6R5
{

	param(
        [System.Boolean]$SSLVersionMin = $true,
        [System.Boolean]$ExtensionUpdate = $true,
        [System.Boolean]$DisableFormHistory = $true,
        [System.Boolean]$PasswordManagerEnabled = $true,
        [System.Boolean]$DisableTelemetry = $true,
        [System.Boolean]$DisableDeveloperTools = $true,
        [System.Boolean]$DisableForgetButton = $true,
        [System.Boolean]$DisablePrivateBrowsing = $true,
        [System.Boolean]$SearchSuggestEnabled = $true,
        [System.Boolean]$NetworkPrediction = $true,
        [System.Boolean]$DisableFirefoxAccounts = $true,
        [System.Boolean]$DisableFeedbackCommands = $true,
        [System.Boolean]$DisablePocket = $true,
        [System.Boolean]$DisableFirefoxStudies = $true,
        [System.Boolean]$ImportEnterpriseRoots = $true,
        [System.Boolean]$DisabledCiphersTLS_RSA_WITH_3DES_EDE_CBC_SHA = $true, 
        [System.Boolean]$EnableTrackingProtectionFingerprinting = $true,
        [System.Boolean]$EnableTrackingProtectionCryptomining = $true,
        [System.Boolean]$EncryptedMediaExtensionsEnabled = $true,
        [System.Boolean]$EncryptedMediaExtensionsLocked = $true,
        [System.Boolean]$FirefoxHomeSearch = $true,
        [System.Boolean]$FirefoxHomeTopSites = $true,
        [System.Boolean]$FirefoxHomeSponsoredTopSites = $true,
        [System.Boolean]$FirefoxHomeHighlights = $true,
        [System.Boolean]$FirefoxHomePocket = $true,    
        [System.Boolean]$SponsoredPocket = $true,
        [System.Boolean]$Snippets = $true,
        [System.Boolean]$FirefoxHomeLocked = $true,
        [System.Boolean]$InstallAddonsPermissionDefault = $true,
        [System.Boolean]$PermissionsAutoplayDefault = $true,
        [System.Boolean]$PopupBlockingDefault = $true,
        [System.Boolean]$PopupBlockingLocked = $true,
        [System.Boolean]$SanitizeOnShutdownCache = $true,
        [System.Boolean]$SanitizeOnShutdownCookies = $true,
        [System.Boolean]$SanitizeOnShutdownDownloads = $true,
        [System.Boolean]$SanitizeOnShutdownFormData = $true,
        [System.Boolean]$SanitizeOnShutdownHistory = $true,
        [System.Boolean]$SanitizeOnShutdownSessions = $true,
        [System.Boolean]$SanitizeOnShutdownSiteSettings = $true,
        [System.Boolean]$SanitizeOnShutdownOfflineApps = $true,
        [System.Boolean]$SanitizeOnShutdownLocked = $true,
        [System.Boolean]$ExtensionRecommendations = $true        
        )
    
    Import-DSCResource -ModuleName 'GPRegistryPolicyDsc'
	Import-DSCResource -ModuleName 'AuditPolicyDSC'
	Import-DSCResource -ModuleName 'SecurityPolicyDSC'    


    if ($SSLVersionMin) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\SSLVersionMin'
        {
            Key = 'Software\Policies\Mozilla\Firefox'
            TargetType = 'ComputerConfiguration'
            ValueType = 'String'
            ValueData = 'tls1.2'
            ValueName = 'SSLVersionMin'
        }
    }
    
    if ($ExtensionUpdate) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\ExtensionUpdate'
        {
            Key = 'Software\Policies\Mozilla\Firefox'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'ExtensionUpdate'
        }
    }
    
    if ($DisableFormHistory) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\DisableFormHistory'
        {
            Key = 'Software\Policies\Mozilla\Firefox'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'DisableFormHistory'
        }
    }
    
    if ($PasswordManagerEnabled) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\PasswordManagerEnabled'
        {
            Key = 'Software\Policies\Mozilla\Firefox'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'PasswordManagerEnabled'
        }
    }
    
    if ($DisableTelemetry) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\DisableTelemetry'
        {
            Key = 'Software\Policies\Mozilla\Firefox'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'DisableTelemetry'
        }
    }
    
    if ($DisableDeveloperTools) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\DisableDeveloperTools'
        {
            Key = 'Software\Policies\Mozilla\Firefox'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'DisableDeveloperTools'
        }
    }
    
    if ($DisableForgetButton) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\DisableForgetButton'
        {
            Key = 'Software\Policies\Mozilla\Firefox'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'DisableForgetButton'
        }
    }
    
    if ($DisablePrivateBrowsing) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\DisablePrivateBrowsing'
        {
            Key = 'Software\Policies\Mozilla\Firefox'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'DisablePrivateBrowsing'
        }
    }
    
    if ($SearchSuggestEnabled) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\SearchSuggestEnabled'
        {
            Key = 'Software\Policies\Mozilla\Firefox'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'SearchSuggestEnabled'
        }
    }
    
    if ($NetworkPrediction) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\NetworkPrediction'
        {
            Key = 'Software\Policies\Mozilla\Firefox'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'NetworkPrediction'
        }
    }
    
    if ($DisableFirefoxAccounts) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\DisableFirefoxAccounts'
        {
            Key = 'Software\Policies\Mozilla\Firefox'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'DisableFirefoxAccounts'
        }
    }
    
    if ($DisableFeedbackCommands) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\DisableFeedbackCommands'
        {
            Key = 'Software\Policies\Mozilla\Firefox'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'DisableFeedbackCommands'
        }
    }
    
    if ($DisablePocket) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\DisablePocket'
        {
            Key = 'Software\Policies\Mozilla\Firefox'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'DisablePocket'
        }
    }
    
    if ($DisableFirefoxStudies) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\DisableFirefoxStudies'
        {
            Key = 'Software\Policies\Mozilla\Firefox'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'DisableFirefoxStudies'
        }
    }
    
    if ($ImportEnterpriseRoots) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\Certificates\ImportEnterpriseRoots'
        {
            Key = 'Software\Policies\Mozilla\Firefox\Certificates'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'ImportEnterpriseRoots'
        }
    }
    
    if ($DisabledCiphersTLS_RSA_WITH_3DES_EDE_CBC_SHA) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\DisabledCiphers\TLS_RSA_WITH_3DES_EDE_CBC_SHA'
        {
            Key = 'Software\Policies\Mozilla\Firefox\DisabledCiphers'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'TLS_RSA_WITH_3DES_EDE_CBC_SHA'
        }
    }
    if ($EnableTrackingProtectionFingerprinting) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\EnableTrackingProtection\Fingerprinting'
        {
            Key = 'Software\Policies\Mozilla\Firefox\EnableTrackingProtection'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'Fingerprinting'
        }
    }
    
    if ($EnableTrackingProtectionCryptomining) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\EnableTrackingProtection\Cryptomining'
        {
            Key = 'Software\Policies\Mozilla\Firefox\EnableTrackingProtection'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'Cryptomining'
        }
    }
    
    if ($EncryptedMediaExtensionsEnabled) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\EncryptedMediaExtensions\Enabled'
        {
            Key = 'Software\Policies\Mozilla\Firefox\EncryptedMediaExtensions'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'Enabled'
        }
    }
    
    if ($EncryptedMediaExtensionsLocked) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\EncryptedMediaExtensions\Locked'
        {
            Key = 'Software\Policies\Mozilla\Firefox\EncryptedMediaExtensions'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'Locked'
        }
    }
    
    if ($FirefoxHomeSearch) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\FirefoxHome\Search'
        {
            Key = 'Software\Policies\Mozilla\Firefox\FirefoxHome'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'Search'
        }
    }
    
    if ($FirefoxHomeTopSites) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\FirefoxHome\TopSites'
        {
            Key = 'Software\Policies\Mozilla\Firefox\FirefoxHome'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'TopSites'
        }
    }
    
    if ($FirefoxHomeSponsoredTopSites) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\FirefoxHome\SponsoredTopSites'
        {
            Key = 'Software\Policies\Mozilla\Firefox\FirefoxHome'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'SponsoredTopSites'
        }
    }
    
    if ($FirefoxHomeHighlights) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\FirefoxHome\Highlights'
        {
            Key = 'Software\Policies\Mozilla\Firefox\FirefoxHome'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'Highlights'
        }
    }
    
    if ($FirefoxHomePocket) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\FirefoxHome\Pocket'
        {
            Key = 'Software\Policies\Mozilla\Firefox\FirefoxHome'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'Pocket'
        }
    }

    if ($SponsoredPocket) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\FirefoxHome\SponsoredPocket'
        {
            Key = 'Software\Policies\Mozilla\Firefox\FirefoxHome'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'SponsoredPocket'
        }
    }
    
    if ($Snippets) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\FirefoxHome\Snippets'
        {
            Key = 'Software\Policies\Mozilla\Firefox\FirefoxHome'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'Snippets'
        }
    }
    
    if ($FirefoxHomeLocked) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\FirefoxHome\Locked'
        {
            Key = 'Software\Policies\Mozilla\Firefox\FirefoxHome'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'Locked'
        }
    }
    
    if ($InstallAddonsPermissionDefault) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\InstallAddonsPermission\Default'
        {
            Key = 'Software\Policies\Mozilla\Firefox\InstallAddonsPermission'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'Default'
        }
    }
    
    if ($PermissionsAutoplayDefault) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\Permissions\Autoplay\Default'
        {
            Key = 'Software\Policies\Mozilla\Firefox\Permissions\Autoplay'
            TargetType = 'ComputerConfiguration'
            ValueType = 'String'
            ValueData = 'block-audio-video'
            ValueName = 'Default'
        }
    }
    
    if ($PopupBlockingDefault) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\PopupBlocking\Default'
        {
            Key = 'Software\Policies\Mozilla\Firefox\PopupBlocking'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'Default'
        }
    }
    
    if ($PopupBlockingLocked) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\PopupBlocking\Locked'
        {
            Key = 'Software\Policies\Mozilla\Firefox\PopupBlocking'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'Locked'
        }
    }
    
    if ($SanitizeOnShutdownCache) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\SanitizeOnShutdown\Cache'
        {
            Key = 'Software\Policies\Mozilla\Firefox\SanitizeOnShutdown'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'Cache'
        }
    }
    
    if ($SanitizeOnShutdownCookies) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\SanitizeOnShutdown\Cookies'
        {
            Key = 'Software\Policies\Mozilla\Firefox\SanitizeOnShutdown'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'Cookies'
        }
    }
    
    if ($SanitizeOnShutdownDownloads) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\SanitizeOnShutdown\Downloads'
        {
            Key = 'Software\Policies\Mozilla\Firefox\SanitizeOnShutdown'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'Downloads'
        }
    }
    
    if ($SanitizeOnShutdownFormData) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\SanitizeOnShutdown\FormData'
        {
            Key = 'Software\Policies\Mozilla\Firefox\SanitizeOnShutdown'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'FormData'
        }
    }
    
    if ($SanitizeOnShutdownHistory) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\SanitizeOnShutdown\History'
        {
            Key = 'Software\Policies\Mozilla\Firefox\SanitizeOnShutdown'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'History'
        }
    }
    
    if ($SanitizeOnShutdownSessions) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\SanitizeOnShutdown\Sessions'
        {
            Key = 'Software\Policies\Mozilla\Firefox\SanitizeOnShutdown'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'Sessions'
        }
    }
    
    if ($SanitizeOnShutdownSiteSettings) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\SanitizeOnShutdown\SiteSettings'
        {
            Key = 'Software\Policies\Mozilla\Firefox\SanitizeOnShutdown'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'SiteSettings'
        }
    }
    
    if ($SanitizeOnShutdownOfflineApps) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\SanitizeOnShutdown\OfflineApps'
        {
            Key = 'Software\Policies\Mozilla\Firefox\SanitizeOnShutdown'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'OfflineApps'
        }
    }
    
    if ($SanitizeOnShutdownLocked) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\SanitizeOnShutdown\Locked'
        {
            Key = 'Software\Policies\Mozilla\Firefox\SanitizeOnShutdown'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'Locked'
        }
    }
    
    if ($ExtensionRecommendations) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\UserMessaging\ExtensionRecommendations'
        {
            Key = 'Software\Policies\Mozilla\Firefox\UserMessaging'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'ExtensionRecommendations'
        }
    }

    RefreshRegistryPolicy 'ActivateClientSideExtension'
    {
        IsSingleInstance = 'Yes'
    }
}

