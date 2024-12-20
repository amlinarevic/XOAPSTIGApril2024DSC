Configuration 'XOAPSTIGApril2024DSC'
{
    Import-DSCResource -Module 'XOAPSTIGApril2024DSC' -Name 'DoD_Google_Chrome_V2R8 ' -ModuleVersion '0.0.1'

    param
        (
        )

    Node 'XOAPSTIGApril2024DSC'
    {
        DoD_Google_Chrome_V2R8 'Example'
        {
            RemoteAccessHostFirewallTraversal = $true,
            DefaultPopupsSetting = $true,
            DefaultGeolocationSetting = $true,
            DefaultSearchProviderName = $true,
            DefaultSearchProviderEnabled = $true,
            PasswordManagerEnabled = $true,
            BackgroundModeEnabled = $true,
            SyncDisabled = $true,
            CloudPrintProxyEnabled = $true,
            MetricsReportingEnabled = $true,
            SearchSuggestEnabled = $true,
            ImportSavedPasswords = $true,
            IncognitoModeAvailability = $true,
            SavingBrowserHistoryDisabled = $true,
            AllowDeletingBrowserHistory = $true,
            PromptForDownloadLocation = $true,
            AutoplayAllowed = $true,
            SafeBrowsingExtendedReportingEnabled = $true,
            DefaultWebUsbGuardSetting = $true,
            ChromeCleanupEnabled = $true,
            ChromeCleanupReportingEnabled = $true,
            EnableMediaRouter = $true,
            UrlKeyedAnonymizedDataCollectionEnabled = $true,
            WebRtcEventLogCollectionAllowed = $true,
            NetworkPredictionOptions = $true,
            DeveloperToolsAvailability = $true,
            BrowserGuestModeEnabled = $true,
            AutofillCreditCardEnabled = $true,
            AutofillAddressEnabled = $true,
            ImportAutofillFormData = $true,
            SafeBrowsingProtectionLevel = $true,
            DefaultSearchProviderSearchURL = $true,
            DownloadRestrictions = $true,
            DefaultWebBluetoothGuardSetting = $true,
            QuicAllowed = $true,
            EnableOnlineRevocationChecks = $true,
            SSLVersionMin = $true,
            AutoplayAllowlist1 = $true,
            AutoplayAllowlist2 = $true,
            ExtensionInstallAllowlist1 = $true,
            ExtensionInstallBlocklist1 = $true,
            URLBlocklist1 = $true
        }

    }
}
XOAPSTIGApril2024DSC -OutputPath 'C:\XOAPSTIGApril2024DSC'
