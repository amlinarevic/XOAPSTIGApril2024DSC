# XOAPSTIGApril2024DSC

This repository contains the **XOAPSTIGApril2024DSC** DSC module.

## Code of Conduct

This project has adopted this [Code of Conduct](CODE_OF_CONDUCT.md).

## Contributing

Please check out common DSC Community [contributing guidelines](https://dsccommunity.org/guidelines/contributing).

## Change log

A full list of changes in each version can be found in the  [Releases](https://github.com/xoap-io/XOAPSTIGAugust2023DSC/releases).

## Prerequisites

Be sure that the following DSC modules are installed on your system:

- GPRegistryPolicyDsc (1.2.0)
- AuditPolicyDSC (1.4.0.0)
- SecurityPolicyDSC (2.10.0.0)

## Documentation

The XOAP STIG April 2024 DSC module contains the following resources:

- DoD_Adobe_Acrobat_Reader_DC_Continuous_V2R1
- DoD_Google_Chrome_v2r8
- DoD_Internet_Explorer_11_v2r5
- DoD_Microsoft_Defender_Antivirus_STIG_v2r4
- DoD_Microsoft_Edge_v1r7
- DoD_Mozilla_Firefox_v6r5
- DoD_Office_2019-M365_Apps_v2r11
- DoD_Office_System_2013_and_Components
- DoD_Office_System_2016_and_Components
- DoD_Windows_10_v2r8
- DoD_Windows_11_v1r5
- DoD_Windows_Defender_Firewall_v2r2
- DoD_WinSvr_2012_R2_MS_and_DC_v3r7
- DoD_WinSvr_2016_MS_and_DC_v2r7
- DoD_WinSvr_2019_MS_and_DC_v2r8
- DoD_WinSvr_2022_MS_and_DC_v1r4

## Configuration example

To implement the STIG April 2024 DSC module, add the following resources to your DSC configuration and adjust accordingly:

### DoD_Google_Chrome_V2R8 

```PowerShell
Configuration 'XOAPSTIGApril2024DSC'
{
    Import-DSCResource -Module 'XOAPSTIGApril2024DSC' -Name 'DoD_Google_Chrome_V2R8' -ModuleVersion '0.0.1'

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
