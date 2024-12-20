configuration DoD_Microsoft_Edge_V1R8
{

    param(
        [System.Boolean]$SSLVersionMin = $true,
        [System.Boolean]$SyncDisabled = $true,
        [System.Boolean]$ImportBrowserSettings = $true,
        [System.Boolean]$DeveloperToolsAvailability = $true,
        [System.Boolean]$PromptForDownloadLocation = $true,
        [System.Boolean]$PreventSmartScreenPromptOverride = $true,
        [System.Boolean]$PreventSmartScreenPromptOverrideForFiles = $true,
        [System.Boolean]$InPrivateModeAvailability = $true,
        [System.Boolean]$AllowDeletingBrowserHistory = $true,
        [System.Boolean]$BackgroundModeEnabled = $true,
        [System.Boolean]$DefaultPopupsSetting = $true,
        [System.Boolean]$NetworkPredictionOptions = $true,
        [System.Boolean]$SearchSuggestEnabled = $true,
        [System.Boolean]$ImportAutofillFormData = $true,
        [System.Boolean]$ImportCookies = $true,
        [System.Boolean]$ImportExtensions = $true,
        [System.Boolean]$ImportHistory = $true,
        [System.Boolean]$ImportHomepage = $true,
        [System.Boolean]$ImportOpenTabs = $true,
        [System.Boolean]$ImportPaymentInfo = $true,
        [System.Boolean]$ImportSavedPasswords = $true,
        [System.Boolean]$ImportSearchEngine = $true,
        [System.Boolean]$ImportShortcuts = $true,
        [System.Boolean]$AutoplayAllowed = $true,
        [System.Boolean]$EnableMediaRouter = $true,
        [System.Boolean]$AutofillCreditCardEnabled = $true,
        [System.Boolean]$AutofillAddressEnabled = $true,
        [System.Boolean]$PersonalizationReportingEnabled = $true,
        [System.Boolean]$DefaultGeolocationSetting = $true,
        [System.Boolean]$PasswordManagerEnabled = $true,
        [System.Boolean]$IsolateOrigins = $true,
        [System.Boolean]$SmartScreenEnabled = $true,
        [System.Boolean]$SmartScreenPuaEnabled = $true,
        [System.Boolean]$PaymentMethodQueryEnabled = $true,
        [System.Boolean]$AlternateErrorPagesEnabled = $true,
        [System.Boolean]$UserFeedbackAllowed = $true,
        [System.Boolean]$EdgeCollectionsEnabled = $true,
        [System.Boolean]$ConfigureShare = $true,
        [System.Boolean]$BrowserGuestModeEnabled = $true,
        [System.Boolean]$BuiltInDnsClientEnabled = $true,
        [System.Boolean]$SitePerProcess = $true,
        [System.Boolean]$ManagedSearchEngines = $true,
        [System.Boolean]$AuthSchemes = $true,
        [System.Boolean]$DefaultWebUsbGuardSetting = $true,
        [System.Boolean]$DefaultWebBluetoothGuardSetting = $true,
        [System.Boolean]$TrackingPrevention = $true,
        [System.Boolean]$RelaunchNotification = $true,
        [System.Boolean]$ProxySettings = $true,
        [System.Boolean]$EnableOnlineRevocationChecks = $true,
        [System.Boolean]$QuicAllowed = $true,
        [System.Boolean]$DownloadRestrictions = $true,
        [System.Boolean]$VisualSearchEnabled = $true,
        [System.Boolean]$HubsSidebarEnabled = $true,
        [System.Boolean]$DefaultCookiesSetting = $true,
        [System.Boolean]$AutoplayAllowlist1 = $true,
        [System.Boolean]$AutoplayAllowlist2 = $true,
        [System.Boolean]$ExtensionInstallBlocklist1 = $true,
        [System.Boolean]$PopupsAllowedForUrls1 = $true,
        [System.Boolean]$PopupsAllowedForUrls2 = $true                        
    )

	Import-DSCResource -ModuleName 'GPRegistryPolicyDsc'
	Import-DSCResource -ModuleName 'AuditPolicyDSC'
	Import-DSCResource -ModuleName 'SecurityPolicyDSC'    

    if ($SSLVersionMin) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\SSLVersionMin'
        {
            Key = 'Software\Policies\Microsoft\Edge'
            TargetType = 'ComputerConfiguration'
            ValueType = 'String'
            ValueData = 'tls1.2'
            ValueName = 'SSLVersionMin'
        }
    }
    
    if ($SyncDisabled) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\SyncDisabled'
        {
            Key = 'Software\Policies\Microsoft\Edge'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'SyncDisabled'
        }
    }
    
    if ($ImportBrowserSettings) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\ImportBrowserSettings'
        {
            Key = 'Software\Policies\Microsoft\Edge'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'ImportBrowserSettings'
        }
    }
    
    if ($DeveloperToolsAvailability) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\DeveloperToolsAvailability'
        {
            Key = 'Software\Policies\Microsoft\Edge'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 2
            ValueName = 'DeveloperToolsAvailability'
        }
    }
    
    if ($PromptForDownloadLocation) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\PromptForDownloadLocation'
        {
            Key = 'Software\Policies\Microsoft\Edge'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'PromptForDownloadLocation'
        }
    }
    
    if ($PreventSmartScreenPromptOverride) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\PreventSmartScreenPromptOverride'
        {
            Key = 'Software\Policies\Microsoft\Edge'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'PreventSmartScreenPromptOverride'
        }
    }
    
    if ($PreventSmartScreenPromptOverrideForFiles) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\PreventSmartScreenPromptOverrideForFiles'
        {
            Key = 'Software\Policies\Microsoft\Edge'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'PreventSmartScreenPromptOverrideForFiles'
        }
    }
    
    if ($InPrivateModeAvailability) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\InPrivateModeAvailability'
        {
            Key = 'Software\Policies\Microsoft\Edge'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'InPrivateModeAvailability'
        }
    }
    
    if ($AllowDeletingBrowserHistory) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\AllowDeletingBrowserHistory'
        {
            Key = 'Software\Policies\Microsoft\Edge'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'AllowDeletingBrowserHistory'
        }
    }
    
    if ($BackgroundModeEnabled) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\BackgroundModeEnabled'
        {
            Key = 'Software\Policies\Microsoft\Edge'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'BackgroundModeEnabled'
        }
    }
    
    if ($DefaultPopupsSetting) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\DefaultPopupsSetting'
        {
            Key = 'Software\Policies\Microsoft\Edge'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 2
            ValueName = 'DefaultPopupsSetting'
        }
    }

    if ($NetworkPredictionOptions) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\NetworkPredictionOptions'
        {
            Key = 'Software\Policies\Microsoft\Edge'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 2
            ValueName = 'NetworkPredictionOptions'
        }
    }
    
    if ($SearchSuggestEnabled) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\SearchSuggestEnabled'
        {
            Key = 'Software\Policies\Microsoft\Edge'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'SearchSuggestEnabled'
        }
    }
    
    if ($ImportAutofillFormData) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\ImportAutofillFormData'
        {
            Key = 'Software\Policies\Microsoft\Edge'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'ImportAutofillFormData'
        }
    }
    
    if ($ImportCookies) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\ImportCookies'
        {
            Key = 'Software\Policies\Microsoft\Edge'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'ImportCookies'
        }
    }
    
    if ($ImportExtensions) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\ImportExtensions'
        {
            Key = 'Software\Policies\Microsoft\Edge'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'ImportExtensions'
        }
    }
    
    if ($ImportHistory) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\ImportHistory'
        {
            Key = 'Software\Policies\Microsoft\Edge'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'ImportHistory'
        }
    }
    
    if ($ImportHomepage) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\ImportHomepage'
        {
            Key = 'Software\Policies\Microsoft\Edge'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'ImportHomepage'
        }
    }
    
    if ($ImportOpenTabs) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\ImportOpenTabs'
        {
            Key = 'Software\Policies\Microsoft\Edge'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'ImportOpenTabs'
        }
    }
    
    if ($ImportPaymentInfo) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\ImportPaymentInfo'
        {
            Key = 'Software\Policies\Microsoft\Edge'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'ImportPaymentInfo'
        }
    }
    
    if ($ImportSavedPasswords) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\ImportSavedPasswords'
        {
            Key = 'Software\Policies\Microsoft\Edge'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'ImportSavedPasswords'
        }
    }
    if ($ImportSearchEngine) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\ImportSearchEngine'
        {
            Key = 'Software\Policies\Microsoft\Edge'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'ImportSearchEngine'
        }
    }
    
    if ($ImportShortcuts) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\ImportShortcuts'
        {
            Key = 'Software\Policies\Microsoft\Edge'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'ImportShortcuts'
        }
    }
    
    if ($AutoplayAllowed) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\AutoplayAllowed'
        {
            Key = 'Software\Policies\Microsoft\Edge'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'AutoplayAllowed'
        }
    }
    
    if ($EnableMediaRouter) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\EnableMediaRouter'
        {
            Key = 'Software\Policies\Microsoft\Edge'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'EnableMediaRouter'
        }
    }
    
    if ($AutofillCreditCardEnabled) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\AutofillCreditCardEnabled'
        {
            Key = 'Software\Policies\Microsoft\Edge'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'AutofillCreditCardEnabled'
        }
    }
    
    if ($AutofillAddressEnabled) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\AutofillAddressEnabled'
        {
            Key = 'Software\Policies\Microsoft\Edge'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'AutofillAddressEnabled'
        }
    }
    
    if ($PersonalizationReportingEnabled) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\PersonalizationReportingEnabled'
        {
            Key = 'Software\Policies\Microsoft\Edge'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'PersonalizationReportingEnabled'
        }
    }
    
    if ($DefaultGeolocationSetting) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\DefaultGeolocationSetting'
        {
            Key = 'Software\Policies\Microsoft\Edge'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 2
            ValueName = 'DefaultGeolocationSetting'
        }
    }
    
    if ($IsolateOrigins) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\IsolateOrigins'
        {
            Key = 'Software\Policies\Microsoft\Edge'
            TargetType = 'ComputerConfiguration'
            ValueType = 'String'
            ValueData = $null
            ValueName = 'IsolateOrigins'
        }
    }
    
    if ($SmartScreenEnabled) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\SmartScreenEnabled'
        {
            Key = 'Software\Policies\Microsoft\Edge'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'SmartScreenEnabled'
        }
    }
    
    if ($SmartScreenPuaEnabled) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\SmartScreenPuaEnabled'
        {
            Key = 'Software\Policies\Microsoft\Edge'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'SmartScreenPuaEnabled'
        }
    }
    
    if ($PaymentMethodQueryEnabled) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\PaymentMethodQueryEnabled'
        {
            Key = 'Software\Policies\Microsoft\Edge'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'PaymentMethodQueryEnabled'
        }
    }
    
    if ($AlternateErrorPagesEnabled) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\AlternateErrorPagesEnabled'
        {
            Key = 'Software\Policies\Microsoft\Edge'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'AlternateErrorPagesEnabled'
        }
    }
    
    if ($UserFeedbackAllowed) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\UserFeedbackAllowed'
        {
            Key = 'Software\Policies\Microsoft\Edge'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'UserFeedbackAllowed'
        }
    }
    
    if ($EdgeCollectionsEnabled) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\EdgeCollectionsEnabled'
        {
            Key = 'Software\Policies\Microsoft\Edge'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'EdgeCollectionsEnabled'
        }
    }
    
    if ($ConfigureShare) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\ConfigureShare'
        {
            Key = 'Software\Policies\Microsoft\Edge'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'ConfigureShare'
        }
    }
    if ($PasswordManagerEnabled) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\PasswordManagerEnabled'
        {
            Key = 'Software\Policies\Microsoft\Edge'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'PasswordManagerEnabled'
        }
    }
    
    if ($BrowserGuestModeEnabled) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\BrowserGuestModeEnabled'
        {
            Key = 'Software\Policies\Microsoft\Edge'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'BrowserGuestModeEnabled'
        }
    }
    
    if ($BuiltInDnsClientEnabled) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\BuiltInDnsClientEnabled'
        {
            Key = 'Software\Policies\Microsoft\Edge'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'BuiltInDnsClientEnabled'
        }
    }
    
    if ($SitePerProcess) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\SitePerProcess'
        {
            Key = 'Software\Policies\Microsoft\Edge'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'SitePerProcess'
        }
    }
    
    if ($ManagedSearchEngines) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\ManagedSearchEngines'
        {
            Key = 'Software\Policies\Microsoft\Edge'
            TargetType = 'ComputerConfiguration'
            ValueType = 'String'
            ValueData = '[{"allow_search_engine_discovery": false},{"is_default": true,"name": "Microsoft Bing","keyword": "bing","search_url": "https://www.bing.com/search?q={searchTerms}"},{"name": "Google","keyword": "google","search_url": "https://www.google.com/search?q={searchTerms}"}]'
            ValueName = 'ManagedSearchEngines'
        }
    }
    
    if ($AuthSchemes) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\AuthSchemes'
        {
            Key = 'Software\Policies\Microsoft\Edge'
            TargetType = 'ComputerConfiguration'
            ValueType = 'String'
            ValueData = 'ntlm,negotiate'
            ValueName = 'AuthSchemes'
        }
    }
    
    if ($DefaultWebUsbGuardSetting) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\DefaultWebUsbGuardSetting'
        {
            Key = 'Software\Policies\Microsoft\Edge'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 2
            ValueName = 'DefaultWebUsbGuardSetting'
        }
    }
    
    if ($DefaultWebBluetoothGuardSetting) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\DefaultWebBluetoothGuardSetting'
        {
            Key = 'Software\Policies\Microsoft\Edge'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 2
            ValueName = 'DefaultWebBluetoothGuardSetting'
        }
    }
    
    if ($TrackingPrevention) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\TrackingPrevention'
        {
            Key = 'Software\Policies\Microsoft\Edge'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 2
            ValueName = 'TrackingPrevention'
        }
    }
    
    if ($RelaunchNotification) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\RelaunchNotification'
        {
            Key = 'Software\Policies\Microsoft\Edge'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 2
            ValueName = 'RelaunchNotification'
        }
    }
    
    if ($ProxySettings) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\ProxySettings'
        {
            Key = 'Software\Policies\Microsoft\Edge'
            TargetType = 'ComputerConfiguration'
            ValueType = 'String'
            ValueData = 'ADD YOUR PROXY CONFIGURATIONS HERE'
            ValueName = 'ProxySettings'
        }
    }
    
    if ($EnableOnlineRevocationChecks) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\EnableOnlineRevocationChecks'
        {
            Key = 'Software\Policies\Microsoft\Edge'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'EnableOnlineRevocationChecks'
        }
    }
    
    if ($QuicAllowed) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\QuicAllowed'
        {
            Key = 'Software\Policies\Microsoft\Edge'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'QuicAllowed'
        }
    }
    
    if ($DownloadRestrictions) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\DownloadRestrictions'
        {
            Key = 'Software\Policies\Microsoft\Edge'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'DownloadRestrictions'
        }
    }
    
    if ($VisualSearchEnabled) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\VisualSearchEnabled'
        {
            Key = 'Software\Policies\Microsoft\Edge'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'VisualSearchEnabled'
        }
    }
    
    if ($HubsSidebarEnabled) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\HubsSidebarEnabled'
        {
            Key = 'Software\Policies\Microsoft\Edge'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'HubsSidebarEnabled'
        }
    }
    
    if ($DefaultCookiesSetting) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\DefaultCookiesSetting'
        {
            Key = 'Software\Policies\Microsoft\Edge'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 4
            ValueName = 'DefaultCookiesSetting'
        }
    }

    if ($AutoplayAllowlist1) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\AutoplayAllowlist\1'
        {
            Key = 'Software\Policies\Microsoft\Edge\AutoplayAllowlist'
            TargetType = 'ComputerConfiguration'
            ValueType = 'String'
            ValueData = '[*.]gov'
            ValueName = '1'
        }
    }
    
    if ($AutoplayAllowlist2) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\AutoplayAllowlist\2'
        {
            Key = 'Software\Policies\Microsoft\Edge\AutoplayAllowlist'
            TargetType = 'ComputerConfiguration'
            ValueType = 'String'
            ValueData = '[*.]mil'
            ValueName = '2'
        }
    }
    
    if ($ExtensionInstallBlocklist1) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\ExtensionInstallBlocklist\1'
        {
            Key = 'Software\Policies\Microsoft\Edge\ExtensionInstallBlocklist'
            TargetType = 'ComputerConfiguration'
            ValueType = 'String'
            ValueData = '*'
            ValueName = '1'
        }
    }
    
    if ($PopupsAllowedForUrls1) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\PopupsAllowedForUrls\1'
        {
            Key = 'Software\Policies\Microsoft\Edge\PopupsAllowedForUrls'
            TargetType = 'ComputerConfiguration'
            ValueType = 'String'
            ValueData = '[*.]mil'
            ValueName = '1'
        }
    }
    
    if ($PopupsAllowedForUrls2) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\PopupsAllowedForUrls\2'
        {
            Key = 'Software\Policies\Microsoft\Edge\PopupsAllowedForUrls'
            TargetType = 'ComputerConfiguration'
            ValueType = 'String'
            ValueData = '[*.]gov'
            ValueName = '2'
        }
    }
    
    RefreshRegistryPolicy 'ActivateClientSideExtension'
    {
        IsSingleInstance = 'Yes'
    }
}

