configuration DoD_Google_Chrome_V2R8
{

    param(
        [System.Boolean]$RemoteAccessHostFirewallTraversal = $true,
        [System.Boolean]$DefaultPopupsSetting = $true,
        [System.Boolean]$DefaultGeolocationSetting = $true,
        [System.Boolean]$DefaultSearchProviderName = $true,
        [System.Boolean]$DefaultSearchProviderEnabled = $true,
        [System.Boolean]$PasswordManagerEnabled = $true,
        [System.Boolean]$BackgroundModeEnabled = $true,
        [System.Boolean]$SyncDisabled = $true,
        [System.Boolean]$CloudPrintProxyEnabled = $true,
        [System.Boolean]$MetricsReportingEnabled = $true,
        [System.Boolean]$SearchSuggestEnabled = $true,
        [System.Boolean]$ImportSavedPasswords = $true,
        [System.Boolean]$IncognitoModeAvailability = $true,
        [System.Boolean]$SavingBrowserHistoryDisabled = $true,
        [System.Boolean]$AllowDeletingBrowserHistory = $true,
        [System.Boolean]$PromptForDownloadLocation = $true,
        [System.Boolean]$AutoplayAllowed = $true,
        [System.Boolean]$SafeBrowsingExtendedReportingEnabled = $true,
        [System.Boolean]$DefaultWebUsbGuardSetting = $true,
        [System.Boolean]$ChromeCleanupEnabled = $true,
        [System.Boolean]$ChromeCleanupReportingEnabled = $true,
        [System.Boolean]$EnableMediaRouter = $true,
        [System.Boolean]$UrlKeyedAnonymizedDataCollectionEnabled = $true,
        [System.Boolean]$WebRtcEventLogCollectionAllowed = $true,
        [System.Boolean]$NetworkPredictionOptions = $true,
        [System.Boolean]$DeveloperToolsAvailability = $true,
        [System.Boolean]$BrowserGuestModeEnabled = $true,
        [System.Boolean]$AutofillCreditCardEnabled = $true,
        [System.Boolean]$AutofillAddressEnabled = $true,
        [System.Boolean]$ImportAutofillFormData = $true,
        [System.Boolean]$SafeBrowsingProtectionLevel = $true,
        [System.Boolean]$DefaultSearchProviderSearchURL = $true,
        [System.Boolean]$DownloadRestrictions = $true,
        [System.Boolean]$DefaultWebBluetoothGuardSetting = $true,
        [System.Boolean]$QuicAllowed = $true,
        [System.Boolean]$EnableOnlineRevocationChecks = $true,
        [System.Boolean]$SSLVersionMin = $true,
        [System.Boolean]$AutoplayAllowlist1 = $true,
        [System.Boolean]$AutoplayAllowlist2 = $true,
        [System.Boolean]$ExtensionInstallAllowlist1 = $true,
        [System.Boolean]$ExtensionInstallBlocklist1 = $true,
        [System.Boolean]$URLBlocklist1 = $true
    )
    
    Import-DSCResource -ModuleName 'GPRegistryPolicyDsc'
	Import-DSCResource -ModuleName 'AuditPolicyDSC'
	Import-DSCResource -ModuleName 'SecurityPolicyDSC'

    if ($RemoteAccessHostFirewallTraversal) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\RemoteAccessHostFirewallTraversal'
        {
            Key = 'Software\Policies\Google\Chrome'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'RemoteAccessHostFirewallTraversal'
        }
    }
    
    if ($DefaultPopupsSetting) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\DefaultPopupsSetting'
        {
            Key = 'Software\Policies\Google\Chrome'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 2
            ValueName = 'DefaultPopupsSetting'
        }
    }
    
    if ($DefaultGeolocationSetting) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\DefaultGeolocationSetting'
        {
            Key = 'Software\Policies\Google\Chrome'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 2
            ValueName = 'DefaultGeolocationSetting'
        }
    }
    
    if ($DefaultSearchProviderName) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\DefaultSearchProviderName'
        {
            Key = 'Software\Policies\Google\Chrome'
            TargetType = 'ComputerConfiguration'
            ValueType = 'String'
            ValueData = 'Google Encrypted'
            ValueName = 'DefaultSearchProviderName'
        }
    }
    
    if ($DefaultSearchProviderEnabled) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\DefaultSearchProviderEnabled'
        {
            Key = 'Software\Policies\Google\Chrome'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'DefaultSearchProviderEnabled'
        }
    }
    if ($PasswordManagerEnabled) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\PasswordManagerEnabled'
        {
            Key = 'Software\Policies\Google\Chrome'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'PasswordManagerEnabled'
        }
    }
    
    if ($BackgroundModeEnabled) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\BackgroundModeEnabled'
        {
            Key = 'Software\Policies\Google\Chrome'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'BackgroundModeEnabled'
        }
    }
    
    if ($SyncDisabled) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\SyncDisabled'
        {
            Key = 'Software\Policies\Google\Chrome'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'SyncDisabled'
        }
    }
    
    if ($CloudPrintProxyEnabled) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\CloudPrintProxyEnabled'
        {
            Key = 'Software\Policies\Google\Chrome'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'CloudPrintProxyEnabled'
        }
    }
    
    if ($MetricsReportingEnabled) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\MetricsReportingEnabled'
        {
            Key = 'Software\Policies\Google\Chrome'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'MetricsReportingEnabled'
        }
    }
    
    if ($SearchSuggestEnabled) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\SearchSuggestEnabled'
        {
            Key = 'Software\Policies\Google\Chrome'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'SearchSuggestEnabled'
        }
    }
    
    if ($ImportSavedPasswords) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\ImportSavedPasswords'
        {
            Key = 'Software\Policies\Google\Chrome'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'ImportSavedPasswords'
        }
    }
    if ($IncognitoModeAvailability) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\IncognitoModeAvailability'
        {
            Key = 'Software\Policies\Google\Chrome'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'IncognitoModeAvailability'
        }
    }
    
    if ($SavingBrowserHistoryDisabled) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\SavingBrowserHistoryDisabled'
        {
            Key = 'Software\Policies\Google\Chrome'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'SavingBrowserHistoryDisabled'
        }
    }
    
    if ($AllowDeletingBrowserHistory) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\AllowDeletingBrowserHistory'
        {
            Key = 'Software\Policies\Google\Chrome'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'AllowDeletingBrowserHistory'
        }
    }
    
    if ($PromptForDownloadLocation) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\PromptForDownloadLocation'
        {
            Key = 'Software\Policies\Google\Chrome'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'PromptForDownloadLocation'
        }
    }
    
    if ($AutoplayAllowed) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\AutoplayAllowed'
        {
            Key = 'Software\Policies\Google\Chrome'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'AutoplayAllowed'
        }
    }
    
    if ($SafeBrowsingExtendedReportingEnabled) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\SafeBrowsingExtendedReportingEnabled'
        {
            Key = 'Software\Policies\Google\Chrome'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'SafeBrowsingExtendedReportingEnabled'
        }
    }
    
    if ($DefaultWebUsbGuardSetting) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\DefaultWebUsbGuardSetting'
        {
            Key = 'Software\Policies\Google\Chrome'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 2
            ValueName = 'DefaultWebUsbGuardSetting'
        }
    }
    
    if ($ChromeCleanupEnabled) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\ChromeCleanupEnabled'
        {
            Key = 'Software\Policies\Google\Chrome'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'ChromeCleanupEnabled'
        }
    }

    if ($ChromeCleanupReportingEnabled) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\ChromeCleanupReportingEnabled'
        {
            Key = 'Software\Policies\Google\Chrome'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'ChromeCleanupReportingEnabled'
        }
    }
    
    if ($EnableMediaRouter) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\EnableMediaRouter'
        {
            Key = 'Software\Policies\Google\Chrome'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'EnableMediaRouter'
        }
    }
    
    if ($UrlKeyedAnonymizedDataCollectionEnabled) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\UrlKeyedAnonymizedDataCollectionEnabled'
        {
            Key = 'Software\Policies\Google\Chrome'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'UrlKeyedAnonymizedDataCollectionEnabled'
        }
    }
    
    if ($WebRtcEventLogCollectionAllowed) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\WebRtcEventLogCollectionAllowed'
        {
            Key = 'Software\Policies\Google\Chrome'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'WebRtcEventLogCollectionAllowed'
        }
    }
    
    if ($NetworkPredictionOptions) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\NetworkPredictionOptions'
        {
            Key = 'Software\Policies\Google\Chrome'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 2
            ValueName = 'NetworkPredictionOptions'
        }
    }
    
    if ($DeveloperToolsAvailability) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\DeveloperToolsAvailability'
        {
            Key = 'Software\Policies\Google\Chrome'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 2
            ValueName = 'DeveloperToolsAvailability'
        }
    }
    
    if ($BrowserGuestModeEnabled) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\BrowserGuestModeEnabled'
        {
            Key = 'Software\Policies\Google\Chrome'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'BrowserGuestModeEnabled'
        }
    }
    
    if ($AutofillCreditCardEnabled) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\AutofillCreditCardEnabled'
        {
            Key = 'Software\Policies\Google\Chrome'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'AutofillCreditCardEnabled'
        }
    }
    
    if ($AutofillAddressEnabled) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\AutofillAddressEnabled'
        {
            Key = 'Software\Policies\Google\Chrome'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'AutofillAddressEnabled'
        }
    }

    if ($ImportAutofillFormData) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\ImportAutofillFormData'
        {
            Key = 'Software\Policies\Google\Chrome'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'ImportAutofillFormData'
        }
    }
    
    if ($SafeBrowsingProtectionLevel) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\SafeBrowsingProtectionLevel'
        {
            Key = 'Software\Policies\Google\Chrome'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'SafeBrowsingProtectionLevel'
        }
    }
    
    if ($DefaultSearchProviderSearchURL) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\DefaultSearchProviderSearchURL'
        {
            Key = 'Software\Policies\Google\Chrome'
            TargetType = 'ComputerConfiguration'
            ValueType = 'String'
            ValueData = 'https://www.google.com/search?q={searchTerms}'
            ValueName = 'DefaultSearchProviderSearchURL'
        }
    }
    
    if ($DownloadRestrictions) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\DownloadRestrictions'
        {
            Key = 'Software\Policies\Google\Chrome'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'DownloadRestrictions'
        }
    }
    
    if ($DefaultWebBluetoothGuardSetting) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\DefaultWebBluetoothGuardSetting'
        {
            Key = 'Software\Policies\Google\Chrome'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 2
            ValueName = 'DefaultWebBluetoothGuardSetting'
        }
    }
    
    if ($QuicAllowed) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\QuicAllowed'
        {
            Key = 'Software\Policies\Google\Chrome'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'QuicAllowed'
        }
    }
    
    if ($EnableOnlineRevocationChecks) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\EnableOnlineRevocationChecks'
        {
            Key = 'Software\Policies\Google\Chrome'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'EnableOnlineRevocationChecks'
        }
    }
    
    if ($SSLVersionMin) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\SSLVersionMin'
        {
            Key = 'Software\Policies\Google\Chrome'
            TargetType = 'ComputerConfiguration'
            ValueType = 'String'
            ValueData = 'tls1.2'
            ValueName = 'SSLVersionMin'
        }
    }
    f ($AutoplayAllowlist1) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\AutoplayAllowlist\1'
        {
            Key = 'Software\Policies\Google\Chrome\AutoplayAllowlist'
            TargetType = 'ComputerConfiguration'
            ValueType = 'String'
            ValueData = '[*.]mil'
            ValueName = '1'
        }
    }
    
    if ($AutoplayAllowlist2) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\AutoplayAllowlist\2'
        {
            Key = 'Software\Policies\Google\Chrome\AutoplayAllowlist'
            TargetType = 'ComputerConfiguration'
            ValueType = 'String'
            ValueData = '[*.]gov'
            ValueName = '2'
        }
    }
    
    if ($ExtensionInstallAllowlist1) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\ExtensionInstallAllowlist\1'
        {
            Key = 'Software\Policies\Google\Chrome\ExtensionInstallAllowlist'
            TargetType = 'ComputerConfiguration'
            ValueType = 'String'
            ValueData = 'oiigbmnaadbkfbmpbfijlflahbdbdgdf'
            ValueName = '1'
        }
    }
    
    if ($ExtensionInstallBlocklist1) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\ExtensionInstallBlocklist\1'
        {
            Key = 'Software\Policies\Google\Chrome\ExtensionInstallBlocklist'
            TargetType = 'ComputerConfiguration'
            ValueType = 'String'
            ValueData = '*'
            ValueName = '1'
        }
    }
    
    if ($URLBlocklist1) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\URLBlocklist\1'
        {
            Key = 'Software\Policies\Google\Chrome\URLBlocklist'
            TargetType = 'ComputerConfiguration'
            ValueType = 'String'
            ValueData = 'javascript://*'
            ValueName = '1'
        }
    }
}

