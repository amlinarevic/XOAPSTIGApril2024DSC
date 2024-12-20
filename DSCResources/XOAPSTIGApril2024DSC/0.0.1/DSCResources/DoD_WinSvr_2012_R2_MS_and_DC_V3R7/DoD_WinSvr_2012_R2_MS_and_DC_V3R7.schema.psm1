configuration DoD_WinSvr_2012_R2_MS_and_DC_V3R7
{

    param(
        [System.Boolean]$EnumerateAdmins = $true,
        [System.Boolean]$NoDriveTypeAutoRun = $true,
        [System.Boolean]$NoInternetOpenWith = $true,
        [System.Boolean]$PreXPSP2ShellProtocolBehavior = $true,
        [System.Boolean]$NoAutorun = $true,
        [System.Boolean]$UseWindowsUpdate = $true,
        [System.Boolean]$MSAOptional = $true,
        [System.Boolean]$DisableAutomaticRestartSignOn = $true,
        [System.Boolean]$ProcessCreationIncludeCmdLineEnabled = $true,
        [System.Boolean]$EnabledBiometrics = $true,
        [System.Boolean]$BlockUserInputMethodsForSignIn = $true,
        [System.Boolean]$MicrosoftEventVwrDisableLinks = $true,
        [System.Boolean]$DisableEnclosureDownload = $true,
        [System.Boolean]$AllowBasicAuthInClear = $true,
        [System.Boolean]$PeernetDisabled = $true,
        [System.Boolean]$DCSettingIndex = $true,
        [System.Boolean]$ACSettingIndex = $true,
        [System.Boolean]$CEIPEnable = $true,
        [System.Boolean]$DisableInventory = $true,
        [System.Boolean]$DisablePcaUI = $true,
        [System.Boolean]$AllowAllTrustedApps = $true,
        [System.Boolean]$DisablePasswordReveal = $true,
        [System.Boolean]$PreventDeviceMetadataFromNetwork = $true,
        [System.Boolean]$AllowRemoteRPC = $true,
        [System.Boolean]$DisableSystemRestore = $true,
        [System.Boolean]$DisableSendGenericDriverNotFoundToWER = $true,
        [System.Boolean]$DisableSendRequestAdditionalSoftwareToWER = $true,
        [System.Boolean]$DontSearchWindowsUpdate = $true,
        [System.Boolean]$DontPromptForWindowsUpdate = $true,
        [System.Boolean]$SearchOrderConfig = $true,
        [System.Boolean]$DriverServerSelection = $true,
        [System.Boolean]$MaxSizeApplicationLog = $true,
        [System.Boolean]$MaxSizeSecurityLog = $true,
        [System.Boolean]$MaxSizeSetupLog = $true,
        [System.Boolean]$MaxSizeSystemLog = $true,
        [System.Boolean]$NoHeapTerminationOnCorruption = $true,
        [System.Boolean]$NoAutoplayfornonVolume = $true,
        [System.Boolean]$NoDataExecutionPrevention = $true,
        [System.Boolean]$NoUseStoreOpenWith = $true,
        [System.Boolean]$NoBackgroundPolicy = $true,
        [System.Boolean]$NoGPOListChanges = $true,
        [System.Boolean]$PreventHandwritingErrorReports = $true,
        [System.Boolean]$SafeForScripting = $true,
        [System.Boolean]$EnableUserControl = $true,
        [System.Boolean]$DisableLUAPatching = $true,
        [System.Boolean]$AlwaysInstallElevated = $true,
        [System.Boolean]$EnableLLTDIO = $true,
        [System.Boolean]$AllowLLTDIOOnDomain = $true,
        [System.Boolean]$AllowLLTDIOOnPublicNet = $true,
        [System.Boolean]$ProhibitLLTDIOOnPrivateNet = $true,
        [System.Boolean]$EnableRspndr = $true,
        [System.Boolean]$AllowRspndrOnDomain = $true,
        [System.Boolean]$AllowRspndrOnPublicNet = $true,
        [System.Boolean]$ProhibitRspndrOnPrivateNet = $true,
        [System.Boolean]$DisableLocation = $true,
        [System.Boolean]$NC_AllowNetBridge_NLA = $true,
        [System.Boolean]$NC_StdDomainUserSetLocation = $true,
        [System.Boolean]$NoLockScreenSlideshow = $true,
        [System.Boolean]$EnableScriptBlockLogging = $true,
        [System.Boolean]$DisableQueryRemoteServer = $true,
        [System.Boolean]$EnableQueryRemoteServer = $true,
        [System.Boolean]$EnumerateLocalUsers = $true,
        [System.Boolean]$DisableLockScreenAppNotifications = $true,
        [System.Boolean]$DontDisplayNetworkSelectionUI = $true,
        [System.Boolean]$EnableSmartScreen = $true,
        [System.Boolean]$PreventHandwritingDataSharing = $true,
        [System.Boolean]$ForceTunneling = $true,
        [System.Boolean]$EnableRegistrars = $true,
        [System.Boolean]$DisableUPnPRegistrar = $true,
        [System.Boolean]$DisableInBand802DOT11Registrar = $true,
        [System.Boolean]$DisableFlashConfigRegistrar = $true,
        [System.Boolean]$DisableWPDRegistrar = $true,
        [System.Boolean]$DisableWcnUi = $true,
        [System.Boolean]$ScenarioExecutionEnabled = $true,
        [System.Boolean]$WinRMAllowBasic = $true,
        [System.Boolean]$WinRMAllowUnencryptedTraffic = $true,
        [System.Boolean]$WinRMAllowDigest = $true,
        [System.Boolean]$WinRMServiceAllowBasic = $true,
        [System.Boolean]$WinRMServiceAllowUnencryptedTraffic = $true,
        [System.Boolean]$WinRMServiceDisableRunAs = $true,
        [System.Boolean]$DisableHTTPPrinting = $true,
        [System.Boolean]$DisableWebPnPDownload = $true,
        [System.Boolean]$DoNotInstallCompatibleDriverFromWindowsUpdate = $true,
        [System.Boolean]$TerminalServicesAllowGetHelp = $true,
        [System.Boolean]$fAllowFullControl = $true,
        [System.Boolean]$MaxTicketExpiry = $true,
        [System.Boolean]$MaxTicketExpiryUnits = $true,
        [System.Boolean]$fUseMailto = $true,
        [System.Boolean]$fPromptForPassword = $true,
        [System.Boolean]$MinEncryptionLevel = $true,
        [System.Boolean]$PerSessionTempDir = $true,
        [System.Boolean]$DeleteTempDirsOnExit = $true,
        [System.Boolean]$fAllowUnsolicited = $true,
        [System.Boolean]$fAllowUnsolicitedFullControl = $true,
        [System.Boolean]$fEncryptRPCTraffic = $true,
        [System.Boolean]$DisablePasswordSaving = $true,
        [System.Boolean]$fDisableCdm = $true,
        [System.Boolean]$LoggingEnabled = $true,
        [System.Boolean]$fDisableCcm = $true,
        [System.Boolean]$fDisableLPT = $true,
        [System.Boolean]$fDisablePNPRedir = $true,
        [System.Boolean]$fEnableSmartCard = $true,
        [System.Boolean]$RedirectOnlyDefaultClientPrinter = $true,
        [System.Boolean]$DisableAutoUpdate = $true,
        [System.Boolean]$GroupPrivacyAcceptance = $true,
        [System.Boolean]$DisableOnline = $true,
        [System.Boolean]$UseLogonCredential = $true,
        [System.Boolean]$SafeDllSearchMode = $true,
        [System.Boolean]$DriverLoadPolicy = $true,
        [System.Boolean]$WarningLevel = $true,
        [System.Boolean]$NoDefaultExempt = $true,
        [System.Boolean]$SMB1 = $true,
        [System.Boolean]$SmbStart = $true,
        [System.Boolean]$NoNameReleaseOnDemand = $true,
        [System.Boolean]$DisableIPSourceRouting = $true,
        [System.Boolean]$EnableICMPRedirect = $true,
        [System.Boolean]$PerformRouterDiscovery = $true,
        [System.Boolean]$KeepAliveTime = $true,
        [System.Boolean]$TcpMaxDataRetransmissions = $true,
        [System.Boolean]$EnableIPAutoConfigurationLimits = $true,
        [System.Boolean]$DisableIPSourceRoutingIPv6 = $true,
        [System.Boolean]$TcpMaxDataRetransmissionsIPv6 = $true,
        [System.Boolean]$RestrictRemoteClients = $true,
        [System.Boolean]$AuditCredentialValidationSuccess = $true,
        [System.Boolean]$AuditCredentialValidationFailure = $true,
        [System.Boolean]$AuditComputerAccountManagementSuccess = $true,
        [System.Boolean]$AuditComputerAccountManagementFailure = $true,
        [System.Boolean]$AuditOtherAccountManagementEventsSuccess = $true,
        [System.Boolean]$AuditOtherAccountManagementEventsFailure = $true,
        [System.Boolean]$AuditSecurityGroupManagementSuccess = $true,
        [System.Boolean]$AuditSecurityGroupManagementFailure = $true,
        [System.Boolean]$AuditUserAccountManagementSuccess = $true,
        [System.Boolean]$AuditUserAccountManagementFailure = $true,
        [System.Boolean]$AuditProcessCreationSuccess = $true,
        [System.Boolean]$AuditProcessCreationFailure = $true,
        [System.Boolean]$AuditDirectoryServiceAccessSuccess = $true,
        [System.Boolean]$AuditDirectoryServiceAccessFailure = $true,
        [System.Boolean]$AuditDirectoryServiceChangesSuccess = $true,
        [System.Boolean]$AuditDirectoryServiceChangesFailure = $true,
        [System.Boolean]$AuditAccountLockoutFailure = $true,
        [System.Boolean]$AuditAccountLockoutSuccess = $true,
        [System.Boolean]$AuditLogoffSuccess = $true,
        [System.Boolean]$AuditLogoffFailure = $true,
        [System.Boolean]$AuditLogonSuccess = $true,
        [System.Boolean]$AuditLogonFailure = $true,
        [System.Boolean]$AuditSpecialLogonSuccess = $true,
        [System.Boolean]$AuditSpecialLogonFailure = $true,
        [System.Boolean]$AuditRemovableStorageSuccess = $true,
        [System.Boolean]$AuditRemovableStorageFailure = $true,
        [System.Boolean]$AuditCentralAccessPolicyStagingSuccess = $true,
        [System.Boolean]$AuditCentralAccessPolicyStagingFailure = $true,
        [System.Boolean]$AuditPolicyChangeSuccess = $true,
        [System.Boolean]$AuditPolicyChangeFailure = $true,
        [System.Boolean]$AuditAuthenticationPolicyChangeSuccess = $true,
        [System.Boolean]$AuditAuthenticationPolicyChangeFailure = $true,
        [System.Boolean]$AuditAuthorizationPolicyChangeSuccess = $true,
        [System.Boolean]$AuditAuthorizationPolicyChangeFailure = $true,
        [System.Boolean]$AuditSensitivePrivilegeUseSuccess = $true,
        [System.Boolean]$AuditSensitivePrivilegeUseFailure = $true,
        [System.Boolean]$AuditIPsecDriverSuccess = $true,
        [System.Boolean]$AuditIPsecDriverFailure = $true,
        [System.Boolean]$AuditOtherSystemEventsSuccess = $true,
        [System.Boolean]$AuditOtherSystemEventsFailure = $true,
        [System.Boolean]$AuditSecurityStateChangeSuccess = $true,
        [System.Boolean]$AuditSecurityStateChangeFailure = $true,
        [System.Boolean]$AuditSecuritySystemExtensionSuccess = $true,
        [System.Boolean]$AuditSecuritySystemExtensionFailure = $true,
        [System.Boolean]$AuditSystemIntegritySuccess = $true,
        [System.Boolean]$AuditSystemIntegrityFailure = $true,
        [System.Boolean]$UserAccountControlSecureDesktopElevation = $true,
        [System.Boolean]$AuditAccessGlobalSystemObjects = $true,
        [System.Boolean]$SPNTargetNameValidationLevel = $true,
        [System.Boolean]$PreventInstallPrinterDrivers = $true,
        [System.Boolean]$AllowPKU2UAuthenticationOnlineIdentities = $true,
        [System.Boolean]$DoNotStoreLANManagerHash = $true,
        [System.Boolean]$OnlyElevateSignedExecutables = $true,
        [System.Boolean]$DigitallySignCommunicationsAlways = $true,
        [System.Boolean]$AdminApprovalModeForBuiltInAdmin = $true,
        [System.Boolean]$VirtualizeWriteFailures = $true,
        [System.Boolean]$DetectApplicationInstallations = $true,
        [System.Boolean]$StrongKeyProtectionUserKeys = $true,
        [System.Boolean]$EnableLocalSystemNullSessionFallback = $true,
        [System.Boolean]$OnlyElevateUIAccessApplications = $true,
        [System.Boolean]$DoNotRequireCtrlAltDel = $true,
        [System.Boolean]$ElevationPromptStandardUsers = $true,
        [System.Boolean]$MinimumSessionSecurityNTLM = $true,
        [System.Boolean]$DoNotDisplayLastUserName = $true,
        [System.Boolean]$AllowLocalSystemComputerIdentityNTLM = $true,
        [System.Boolean]$KerberosEncryptionTypes = $true,
        [System.Boolean]$MaxMachineAccountPasswordAge = $true,
        [System.Boolean]$IdleTimeBeforeSuspendingSession = $true,
        [System.Boolean]$RemotelyAccessibleRegistryPaths = $true,
        [System.Boolean]$ElevationPromptAdminApprovalMode = $true,
        [System.Boolean]$DisableMachineAccountPasswordChanges = $true,
        [System.Boolean]$SharesAccessibleAnonymously = $true,
        [System.Boolean]$FIPSAlgorithmUsage = $true,
        [System.Boolean]$EncryptOrSignSecureChannelDataAlways = $true,
        [System.Boolean]$RequireCaseInsensitivityNonWindowsSubsystems = $true,
        [System.Boolean]$RefuseMachineAccountPasswordChanges = $true,
        [System.Boolean]$DisconnectClientsWhenLogonHoursExpire = $true,
        [System.Boolean]$StrengthenPermissionsInternalObjects = $true,
        [System.Boolean]$AuditPolicySubcategoryOverride = $true,
        [System.Boolean]$PromptUserChangePasswordExpiration = $true,
        [System.Boolean]$LDAPClientSigningRequirements = $true,
        [System.Boolean]$PreviousLogonsCacheCount = $true,
        [System.Boolean]$AllowUIAccessElevationWithoutSecureDesktop = $true,
        [System.Boolean]$SendUnencryptedPasswordThirdPartySMB = $true,
        [System.Boolean]$EncryptSecureChannelDataIfPossible = $true,
        [System.Boolean]$DoNotAllowAnonymousEnumeration = $true,
        [System.Boolean]$SignCommunicationsAlways = $true,
        [System.Boolean]$DoNotAllowAnonymousEnumerationSAMAccounts = $true,
        [System.Boolean]$RunAllAdministratorsInAdminApprovalMode = $true,
        [System.Boolean]$InteractiveLogonMessageTitle = $true,
        [System.Boolean]$SmartCardRemovalBehavior = $true,
        [System.Boolean]$LANManagerAuthenticationLevel = $true,
        [System.Boolean]$LimitBlankPasswordConsoleLogon = $true,
        [System.Boolean]$SignCommunicationsIfClientAgrees = $true,
        [System.Boolean]$LDAPServerSigningRequirements = $true,
        [System.Boolean]$DigitallySignSecureChannelDataIfPossible = $true,
        [System.Boolean]$DigitallySignCommunicationsIfServerAgrees = $true,
        [System.Boolean]$RequireStrongWindows2000SessionKey = $true,
        [System.Boolean]$RestrictAnonymousAccessNamedPipesShares = $true,
        [System.Boolean]$SharingSecurityModelForLocalAccounts = $true,
        [System.Boolean]$AuditUseOfBackupRestorePrivilege = $false,
        [System.Boolean]$AddWorkstationsToDomain = $true,
        [System.Boolean]$CreateGlobalObjects = $true,
        [System.Boolean]$CreatePagefile = $true,
        [System.Boolean]$AllowLogOnLocally = $true,
        [System.Boolean]$LockPagesInMemory = $true,
        [System.Boolean]$DenyLogOnLocally = $true,
        [System.Boolean]$DenyLogOnAsAService = $true,
        [System.Boolean]$TakeOwnershipOfFiles = $true,
        [System.Boolean]$PerformVolumeMaintenanceTasks = $true,
        [System.Boolean]$CreateTokenObject = $true,
        [System.Boolean]$AccessCredentialManagerTrustedCaller = $true,
        [System.Boolean]$DebugPrograms = $true,
        [System.Boolean]$ModifyFirmwareEnvironmentValues = $true,
        [System.Boolean]$LoadUnloadDeviceDrivers = $true,
        [System.Boolean]$DenyAccessFromNetwork = $true,
        [System.Boolean]$AccessFromNetwork = $true

    )

    Import-DSCResource -ModuleName 'GPRegistryPolicyDsc'
	Import-DSCResource -ModuleName 'AuditPolicyDSC'
	Import-DSCResource -ModuleName 'SecurityPolicyDSC'

    if($EnumerateAdmins){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\CredUI\EnumerateAdministrators'
        {
            Key = 'Software\Microsoft\Windows\CurrentVersion\Policies\CredUI'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'EnumerateAdministrators'
        }
    }
    
    if($NoDriveTypeAutoRun){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoDriveTypeAutoRun'
        {
            Key = 'Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 255
            ValueName = 'NoDriveTypeAutoRun'
        }
    }
    
    if($NoInternetOpenWith){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoInternetOpenWith'
        {
            Key = 'Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'NoInternetOpenWith'
        }
    }
    
    if($PreXPSP2ShellProtocolBehavior){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\PreXPSP2ShellProtocolBehavior'
        {
            Key = 'Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'PreXPSP2ShellProtocolBehavior'
        }
    }
    
    if($NoAutorun){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoAutorun'
        {
            Key = 'Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'NoAutorun'
        }
    }
    
    if($UseWindowsUpdate){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Servicing\UseWindowsUpdate'
        {
            Key = 'Software\Microsoft\Windows\CurrentVersion\Policies\Servicing'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 2
            ValueName = 'UseWindowsUpdate'
        }
    }
    
    if($MSAOptional){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\MSAOptional'
        {
            Key = 'Software\Microsoft\Windows\CurrentVersion\Policies\System'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'MSAOptional'
        }
    }
    
    if($DisableAutomaticRestartSignOn){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\DisableAutomaticRestartSignOn'
        {
            Key = 'Software\Microsoft\Windows\CurrentVersion\Policies\System'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'DisableAutomaticRestartSignOn'
        }
    }
    
    if($ProcessCreationIncludeCmdLineEnabled){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit\ProcessCreationIncludeCmdLine_Enabled'
        {
            Key = 'Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'ProcessCreationIncludeCmdLine_Enabled'
        }
    }
    
    if($EnabledBiometrics){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Biometrics\Enabled'
        {
            Key = 'Software\policies\Microsoft\Biometrics'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'Enabled'
        }
    }

    if($BlockUserInputMethodsForSignIn){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Control Panel\International\BlockUserInputMethodsForSignIn'
        {
            Key = 'Software\policies\Microsoft\Control Panel\International'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'BlockUserInputMethodsForSignIn'
        }
    }
    
    if($MicrosoftEventVwrDisableLinks){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\EventViewer\MicrosoftEventVwrDisableLinks'
        {
            Key = 'Software\policies\Microsoft\EventViewer'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'MicrosoftEventVwrDisableLinks'
        }
    }
    
    if($DisableEnclosureDownload){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Internet Explorer\Feeds\DisableEnclosureDownload'
        {
            Key = 'Software\policies\Microsoft\Internet Explorer\Feeds'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'DisableEnclosureDownload'
        }
    }
    
    if($AllowBasicAuthInClear){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Internet Explorer\Feeds\AllowBasicAuthInClear'
        {
            Key = 'Software\policies\Microsoft\Internet Explorer\Feeds'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'AllowBasicAuthInClear'
        }
    }
    
    if($PeernetDisabled){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Peernet\Disabled'
        {
            Key = 'Software\policies\Microsoft\Peernet'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'Disabled'
        }
    }
    
    if($DCSettingIndex){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\DCSettingIndex'
        {
            Key = 'Software\policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'DCSettingIndex'
        }
    }
    
    if($ACSettingIndex){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\ACSettingIndex'
        {
            Key = 'Software\policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'ACSettingIndex'
        }
    }
    
    if($CEIPEnable){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\SQMClient\Windows\CEIPEnable'
        {
            Key = 'Software\policies\Microsoft\SQMClient\Windows'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'CEIPEnable'
        }
    }
    
    if($DisableInventory){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\AppCompat\DisableInventory'
        {
            Key = 'Software\policies\Microsoft\Windows\AppCompat'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'DisableInventory'
        }
    }
    
    if($DisablePcaUI){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\AppCompat\DisablePcaUI'
        {
            Key = 'Software\policies\Microsoft\Windows\AppCompat'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'DisablePcaUI'
        }
    }
    
    if($AllowAllTrustedApps){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\Appx\AllowAllTrustedApps'
        {
            Key = 'Software\policies\Microsoft\Windows\Appx'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'AllowAllTrustedApps'
        }
    }
    
    if($DisablePasswordReveal){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\CredUI\DisablePasswordReveal'
        {
            Key = 'Software\policies\Microsoft\Windows\CredUI'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'DisablePasswordReveal'
        }
    }
    
    if($PreventDeviceMetadataFromNetwork){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\Device Metadata\PreventDeviceMetadataFromNetwork'
        {
            Key = 'Software\policies\Microsoft\Windows\Device Metadata'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'PreventDeviceMetadataFromNetwork'
        }
    }
    
    if($AllowRemoteRPC){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\DeviceInstall\Settings\AllowRemoteRPC'
        {
            Key = 'Software\policies\Microsoft\Windows\DeviceInstall\Settings'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'AllowRemoteRPC'
        }
    }
    
    if($DisableSystemRestore){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\DeviceInstall\Settings\DisableSystemRestore'
        {
            Key = 'Software\policies\Microsoft\Windows\DeviceInstall\Settings'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'DisableSystemRestore'
        }
    }
    if($DisableSendGenericDriverNotFoundToWER){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\DeviceInstall\Settings\DisableSendGenericDriverNotFoundToWER'
        {
            Key = 'Software\policies\Microsoft\Windows\DeviceInstall\Settings'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'DisableSendGenericDriverNotFoundToWER'
        }
    }
    
    if($DisableSendRequestAdditionalSoftwareToWER){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\DeviceInstall\Settings\DisableSendRequestAdditionalSoftwareToWER'
        {
            Key = 'Software\policies\Microsoft\Windows\DeviceInstall\Settings'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'DisableSendRequestAdditionalSoftwareToWER'
        }
    }
    
    if($DontSearchWindowsUpdate){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\DriverSearching\DontSearchWindowsUpdate'
        {
            Key = 'Software\policies\Microsoft\Windows\DriverSearching'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'DontSearchWindowsUpdate'
        }
    }
    
    if($DontPromptForWindowsUpdate){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\DriverSearching\DontPromptForWindowsUpdate'
        {
            Key = 'Software\policies\Microsoft\Windows\DriverSearching'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'DontPromptForWindowsUpdate'
        }
    }
    
    if($SearchOrderConfig){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\DriverSearching\SearchOrderConfig'
        {
            Key = 'Software\policies\Microsoft\Windows\DriverSearching'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'SearchOrderConfig'
        }
    }
    
    if($DriverServerSelection){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\DriverSearching\DriverServerSelection'
        {
            Key = 'Software\policies\Microsoft\Windows\DriverSearching'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'DriverServerSelection'
        }
    }
    
    if($MaxSizeApplicationLog){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\EventLog\Application\MaxSize'
        {
            Key = 'Software\policies\Microsoft\Windows\EventLog\Application'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 32768
            ValueName = 'MaxSize'
        }
    }
    
    if($MaxSizeSecurityLog){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\EventLog\Security\MaxSize'
        {
            Key = 'Software\policies\Microsoft\Windows\EventLog\Security'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 196608
            ValueName = 'MaxSize'
        }
    }
    
    if($MaxSizeSetupLog){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\EventLog\Setup\MaxSize'
        {
            Key = 'Software\policies\Microsoft\Windows\EventLog\Setup'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 32768
            ValueName = 'MaxSize'
        }
    }
    
    if($MaxSizeSystemLog){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\EventLog\System\MaxSize'
        {
            Key = 'Software\policies\Microsoft\Windows\EventLog\System'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 32768
            ValueName = 'MaxSize'
        }
    }
    
    if($NoHeapTerminationOnCorruption){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\Explorer\NoHeapTerminationOnCorruption'
        {
            Key = 'Software\policies\Microsoft\Windows\Explorer'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'NoHeapTerminationOnCorruption'
        }
    }
    
    if($NoAutoplayfornonVolume){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\Explorer\NoAutoplayfornonVolume'
        {
            Key = 'Software\policies\Microsoft\Windows\Explorer'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'NoAutoplayfornonVolume'
        }
    }
    
    if($NoDataExecutionPrevention){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\Explorer\NoDataExecutionPrevention'
        {
            Key = 'Software\policies\Microsoft\Windows\Explorer'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'NoDataExecutionPrevention'
        }
    }
    
    if($NoUseStoreOpenWith){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\Explorer\NoUseStoreOpenWith'
        {
            Key = 'Software\policies\Microsoft\Windows\Explorer'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'NoUseStoreOpenWith'
        }
    }
    
    if($NoBackgroundPolicy){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}\NoBackgroundPolicy'
        {
            Key = 'Software\policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'NoBackgroundPolicy'
        }
    }
    
    if($NoGPOListChanges){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}\NoGPOListChanges'
        {
            Key = 'Software\policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'NoGPOListChanges'
        }
    }
    
    if($PreventHandwritingErrorReports){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\HandwritingErrorReports\PreventHandwritingErrorReports'
        {
            Key = 'Software\policies\Microsoft\Windows\HandwritingErrorReports'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'PreventHandwritingErrorReports'
        }
    }
    
    if($SafeForScripting){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\Installer\SafeForScripting'
        {
            Key = 'Software\policies\Microsoft\Windows\Installer'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'SafeForScripting'
        }
    }
    
    if($EnableUserControl){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\Installer\EnableUserControl'
        {
            Key = 'Software\policies\Microsoft\Windows\Installer'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'EnableUserControl'
        }
    }
    
    if($DisableLUAPatching){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\Installer\DisableLUAPatching'
        {
            Key = 'Software\policies\Microsoft\Windows\Installer'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'DisableLUAPatching'
        }
    }
    
    if($AlwaysInstallElevated){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\Installer\AlwaysInstallElevated'
        {
            Key = 'Software\policies\Microsoft\Windows\Installer'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'AlwaysInstallElevated'
        }
    }
    if($EnableLLTDIO){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\LLTD\EnableLLTDIO'
        {
            Key = 'Software\policies\Microsoft\Windows\LLTD'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'EnableLLTDIO'
        }
    }
    
    if($AllowLLTDIOOnDomain){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\LLTD\AllowLLTDIOOnDomain'
        {
            Key = 'Software\policies\Microsoft\Windows\LLTD'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'AllowLLTDIOOnDomain'
        }
    }
    
    if($AllowLLTDIOOnPublicNet){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\LLTD\AllowLLTDIOOnPublicNet'
        {
            Key = 'Software\policies\Microsoft\Windows\LLTD'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'AllowLLTDIOOnPublicNet'
        }
    }
    
    if($ProhibitLLTDIOOnPrivateNet){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\LLTD\ProhibitLLTDIOOnPrivateNet'
        {
            Key = 'Software\policies\Microsoft\Windows\LLTD'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'ProhibitLLTDIOOnPrivateNet'
        }
    }
    
    if($EnableRspndr){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\LLTD\EnableRspndr'
        {
            Key = 'Software\policies\Microsoft\Windows\LLTD'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'EnableRspndr'
        }
    }
    
    if($AllowRspndrOnDomain){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\LLTD\AllowRspndrOnDomain'
        {
            Key = 'Software\policies\Microsoft\Windows\LLTD'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'AllowRspndrOnDomain'
        }
    }
    
    if($AllowRspndrOnPublicNet){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\LLTD\AllowRspndrOnPublicNet'
        {
            Key = 'Software\policies\Microsoft\Windows\LLTD'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'AllowRspndrOnPublicNet'
        }
    }
    
    if($ProhibitRspndrOnPrivateNet){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\LLTD\ProhibitRspndrOnPrivateNet'
        {
            Key = 'Software\policies\Microsoft\Windows\LLTD'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'ProhibitRspndrOnPrivateNet'
        }
    }
    
    if($DisableLocation){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\LocationAndSensors\DisableLocation'
        {
            Key = 'Software\policies\Microsoft\Windows\LocationAndSensors'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'DisableLocation'
        }
    }
    
    if($NC_AllowNetBridge_NLA){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\Network Connections\NC_AllowNetBridge_NLA'
        {
            Key = 'Software\policies\Microsoft\Windows\Network Connections'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'NC_AllowNetBridge_NLA'
        }
    }
    
    if($NC_StdDomainUserSetLocation){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\Network Connections\NC_StdDomainUserSetLocation'
        {
            Key = 'Software\policies\Microsoft\Windows\Network Connections'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'NC_StdDomainUserSetLocation'
        }
    }
    
    if($NoLockScreenSlideshow){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\Personalization\NoLockScreenSlideshow'
        {
            Key = 'Software\policies\Microsoft\Windows\Personalization'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'NoLockScreenSlideshow'
        }
    }
    
    if($EnableScriptBlockLogging){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\EnableScriptBlockLogging'
        {
            Key = 'Software\policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'EnableScriptBlockLogging'
        }
    }
    
    if($DisableQueryRemoteServer){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy\DisableQueryRemoteServer'
        {
            Key = 'Software\policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'DisableQueryRemoteServer'
        }
    }
    
    if($EnableQueryRemoteServer){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy\EnableQueryRemoteServer'
        {
            Key = 'Software\policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'EnableQueryRemoteServer'
        }
    }
    
    if($EnumerateLocalUsers){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\System\EnumerateLocalUsers'
        {
            Key = 'Software\policies\Microsoft\Windows\System'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'EnumerateLocalUsers'
        }
    }
    
    if($DisableLockScreenAppNotifications){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\System\DisableLockScreenAppNotifications'
        {
            Key = 'Software\policies\Microsoft\Windows\System'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'DisableLockScreenAppNotifications'
        }
    }
    
    if($DontDisplayNetworkSelectionUI){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\System\DontDisplayNetworkSelectionUI'
        {
            Key = 'Software\policies\Microsoft\Windows\System'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'DontDisplayNetworkSelectionUI'
        }
    }
    
    if($EnableSmartScreen){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\System\EnableSmartScreen'
        {
            Key = 'Software\policies\Microsoft\Windows\System'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 2
            ValueName = 'EnableSmartScreen'
        }
    }
    
    if($PreventHandwritingDataSharing){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\TabletPC\PreventHandwritingDataSharing'
        {
            Key = 'Software\policies\Microsoft\Windows\TabletPC'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'PreventHandwritingDataSharing'
        }
    }
    if($ForceTunneling){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\TCPIP\v6Transition\Force_Tunneling'
        {
            Key = 'Software\policies\Microsoft\Windows\TCPIP\v6Transition'
            TargetType = 'ComputerConfiguration'
            ValueType = 'String'
            ValueData = 'Enabled'
            ValueName = 'Force_Tunneling'
        }
    }
    
    if($EnableRegistrars){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\WCN\Registrars\EnableRegistrars'
        {
            Key = 'Software\policies\Microsoft\Windows\WCN\Registrars'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'EnableRegistrars'
        }
    }
    
    if($DisableUPnPRegistrar){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\WCN\Registrars\DisableUPnPRegistrar'
        {
            Key = 'Software\policies\Microsoft\Windows\WCN\Registrars'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'DisableUPnPRegistrar'
        }
    }
    
    if($DisableInBand802DOT11Registrar){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\WCN\Registrars\DisableInBand802DOT11Registrar'
        {
            Key = 'Software\policies\Microsoft\Windows\WCN\Registrars'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'DisableInBand802DOT11Registrar'
        }
    }
    
    if($DisableFlashConfigRegistrar){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\WCN\Registrars\DisableFlashConfigRegistrar'
        {
            Key = 'Software\policies\Microsoft\Windows\WCN\Registrars'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'DisableFlashConfigRegistrar'
        }
    }
    
    if($DisableWPDRegistrar){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\WCN\Registrars\DisableWPDRegistrar'
        {
            Key = 'Software\policies\Microsoft\Windows\WCN\Registrars'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'DisableWPDRegistrar'
        }
    }
    
    if($DisableWcnUi){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\WCN\UI\DisableWcnUi'
        {
            Key = 'Software\policies\Microsoft\Windows\WCN\UI'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'DisableWcnUi'
        }
    }
    
    if($ScenarioExecutionEnabled){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\WDI\{9c5a40da-b965-4fc3-8781-88dd50a6299d}\ScenarioExecutionEnabled'
        {
            Key = 'Software\policies\Microsoft\Windows\WDI\{9c5a40da-b965-4fc3-8781-88dd50a6299d}'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'ScenarioExecutionEnabled'
        }
    }
    
    if($WinRMAllowBasic){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\WinRM\Client\AllowBasic'
        {
            Key = 'Software\policies\Microsoft\Windows\WinRM\Client'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'AllowBasic'
        }
    }
    
    if($WinRMAllowUnencryptedTraffic){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\WinRM\Client\AllowUnencryptedTraffic'
        {
            Key = 'Software\policies\Microsoft\Windows\WinRM\Client'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'AllowUnencryptedTraffic'
        }
    }
    
    if($WinRMAllowDigest){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\WinRM\Client\AllowDigest'
        {
            Key = 'Software\policies\Microsoft\Windows\WinRM\Client'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'AllowDigest'
        }
    }
    
    if($WinRMServiceAllowBasic){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\WinRM\Service\AllowBasic'
        {
            Key = 'Software\policies\Microsoft\Windows\WinRM\Service'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'AllowBasic'
        }
    }
    
    if($WinRMServiceAllowUnencryptedTraffic){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\WinRM\Service\AllowUnencryptedTraffic'
        {
            Key = 'Software\policies\Microsoft\Windows\WinRM\Service'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'AllowUnencryptedTraffic'
        }
    }
    
    if($WinRMServiceDisableRunAs){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\WinRM\Service\DisableRunAs'
        {
            Key = 'Software\policies\Microsoft\Windows\WinRM\Service'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'DisableRunAs'
        }
    }
    
    if($DisableHTTPPrinting){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows NT\Printers\DisableHTTPPrinting'
        {
            Key = 'Software\policies\Microsoft\Windows NT\Printers'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'DisableHTTPPrinting'
        }
    }
    
    if($DisableWebPnPDownload){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows NT\Printers\DisableWebPnPDownload'
        {
            Key = 'Software\policies\Microsoft\Windows NT\Printers'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'DisableWebPnPDownload'
        }
    }
    
    if($DoNotInstallCompatibleDriverFromWindowsUpdate){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows NT\Printers\DoNotInstallCompatibleDriverFromWindowsUpdate'
        {
            Key = 'Software\policies\Microsoft\Windows NT\Printers'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'DoNotInstallCompatibleDriverFromWindowsUpdate'
        }
    }
    
    if($TerminalServicesAllowGetHelp){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows NT\Terminal Services\fAllowToGetHelp'
        {
            Key = 'Software\policies\Microsoft\Windows NT\Terminal Services'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'fAllowToGetHelp'
        }
    }

    if($fAllowFullControl){
        RegistryPolicyFile 'DEL_\Software\policies\Microsoft\Windows NT\Terminal Services\fAllowFullControl'
        {
            Key = 'Software\policies\Microsoft\Windows NT\Terminal Services'
            TargetType = 'ComputerConfiguration'
            ValueType = 'String'
            ValueData = ''
            ValueName = 'fAllowFullControl'
            Ensure = 'Absent'
        }
    }
    
    if($MaxTicketExpiry){
        RegistryPolicyFile 'DEL_\Software\policies\Microsoft\Windows NT\Terminal Services\MaxTicketExpiry'
        {
            Key = 'Software\policies\Microsoft\Windows NT\Terminal Services'
            TargetType = 'ComputerConfiguration'
            ValueType = 'String'
            ValueData = ''
            ValueName = 'MaxTicketExpiry'
            Ensure = 'Absent'
        }
    }
    
    if($MaxTicketExpiryUnits){
        RegistryPolicyFile 'DEL_\Software\policies\Microsoft\Windows NT\Terminal Services\MaxTicketExpiryUnits'
        {
            Key = 'Software\policies\Microsoft\Windows NT\Terminal Services'
            TargetType = 'ComputerConfiguration'
            ValueType = 'String'
            ValueData = ''
            ValueName = 'MaxTicketExpiryUnits'
            Ensure = 'Absent'
        }
    }
    
    if($fUseMailto){
        RegistryPolicyFile 'DEL_\Software\policies\Microsoft\Windows NT\Terminal Services\fUseMailto'
        {
            Key = 'Software\policies\Microsoft\Windows NT\Terminal Services'
            TargetType = 'ComputerConfiguration'
            ValueType = 'String'
            ValueData = ''
            ValueName = 'fUseMailto'
            Ensure = 'Absent'
        }
    }
    
    if($fPromptForPassword){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows NT\Terminal Services\fPromptForPassword'
        {
            Key = 'Software\policies\Microsoft\Windows NT\Terminal Services'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'fPromptForPassword'
        }
    }
    
    if($MinEncryptionLevel){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows NT\Terminal Services\MinEncryptionLevel'
        {
            Key = 'Software\policies\Microsoft\Windows NT\Terminal Services'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 3
            ValueName = 'MinEncryptionLevel'
        }
    }
    
    if($PerSessionTempDir){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows NT\Terminal Services\PerSessionTempDir'
        {
            Key = 'Software\policies\Microsoft\Windows NT\Terminal Services'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'PerSessionTempDir'
        }
    }
    
    if($DeleteTempDirsOnExit){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows NT\Terminal Services\DeleteTempDirsOnExit'
        {
            Key = 'Software\policies\Microsoft\Windows NT\Terminal Services'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'DeleteTempDirsOnExit'
        }
    }
    
    if($fAllowUnsolicited){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows NT\Terminal Services\fAllowUnsolicited'
        {
            Key = 'Software\policies\Microsoft\Windows NT\Terminal Services'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'fAllowUnsolicited'
        }
    }
    
    if($fAllowUnsolicitedFullControl){
        RegistryPolicyFile 'DEL_\Software\policies\Microsoft\Windows NT\Terminal Services\fAllowUnsolicitedFullControl'
        {
            Key = 'Software\policies\Microsoft\Windows NT\Terminal Services'
            TargetType = 'ComputerConfiguration'
            ValueType = 'String'
            ValueData = ''
            ValueName = 'fAllowUnsolicitedFullControl'
            Ensure = 'Absent'
        }
    }
    
    if($fEncryptRPCTraffic){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows NT\Terminal Services\fEncryptRPCTraffic'
        {
            Key = 'Software\policies\Microsoft\Windows NT\Terminal Services'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'fEncryptRPCTraffic'
        }
    }
    
    if($DisablePasswordSaving){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows NT\Terminal Services\DisablePasswordSaving'
        {
            Key = 'Software\policies\Microsoft\Windows NT\Terminal Services'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'DisablePasswordSaving'
        }
    }
    
    if($fDisableCdm){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows NT\Terminal Services\fDisableCdm'
        {
            Key = 'Software\policies\Microsoft\Windows NT\Terminal Services'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'fDisableCdm'
        }
    }
    
    if($LoggingEnabled){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows NT\Terminal Services\LoggingEnabled'
        {
            Key = 'Software\policies\Microsoft\Windows NT\Terminal Services'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'LoggingEnabled'
        }
    }
    
    if($fDisableCcm){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows NT\Terminal Services\fDisableCcm'
        {
            Key = 'Software\policies\Microsoft\Windows NT\Terminal Services'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'fDisableCcm'
        }
    }
    
    if($fDisableLPT){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows NT\Terminal Services\fDisableLPT'
        {
            Key = 'Software\policies\Microsoft\Windows NT\Terminal Services'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'fDisableLPT'
        }
    }
    
    if($fDisablePNPRedir){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows NT\Terminal Services\fDisablePNPRedir'
        {
            Key = 'Software\policies\Microsoft\Windows NT\Terminal Services'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'fDisablePNPRedir'
        }
    }
    
    if($fEnableSmartCard){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows NT\Terminal Services\fEnableSmartCard'
        {
            Key = 'Software\policies\Microsoft\Windows NT\Terminal Services'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'fEnableSmartCard'
        }
    }
    
    if($RedirectOnlyDefaultClientPrinter){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows NT\Terminal Services\RedirectOnlyDefaultClientPrinter'
        {
            Key = 'Software\policies\Microsoft\Windows NT\Terminal Services'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'RedirectOnlyDefaultClientPrinter'
        }
    }
    if($DisableAutoUpdate){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\WindowsMediaPlayer\DisableAutoUpdate'
        {
            Key = 'Software\policies\Microsoft\WindowsMediaPlayer'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'DisableAutoUpdate'
        }
    }
    
    if($GroupPrivacyAcceptance){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\WindowsMediaPlayer\GroupPrivacyAcceptance'
        {
            Key = 'Software\policies\Microsoft\WindowsMediaPlayer'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'GroupPrivacyAcceptance'
        }
    }
    
    if($DisableOnline){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\WMDRM\DisableOnline'
        {
            Key = 'Software\policies\Microsoft\WMDRM'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'DisableOnline'
        }
    }
    
    if($UseLogonCredential){
        RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential'
        {
            Key = 'SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'UseLogonCredential'
        }
    }
    
    if($SafeDllSearchMode){
        RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\SafeDllSearchMode'
        {
            Key = 'SYSTEM\CurrentControlSet\Control\Session Manager'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'SafeDllSearchMode'
        }
    }
    
    if($DriverLoadPolicy){
        RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch\DriverLoadPolicy'
        {
            Key = 'SYSTEM\CurrentControlSet\Policies\EarlyLaunch'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'DriverLoadPolicy'
        }
    }
    
    if($WarningLevel){
        RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Services\Eventlog\Security\WarningLevel'
        {
            Key = 'SYSTEM\CurrentControlSet\Services\Eventlog\Security'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 90
            ValueName = 'WarningLevel'
        }
    }
    
    if($NoDefaultExempt){
        RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Services\IPSEC\NoDefaultExempt'
        {
            Key = 'SYSTEM\CurrentControlSet\Services\IPSEC'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 3
            ValueName = 'NoDefaultExempt'
        }
    }
    
    if($SMB1){
        RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\SMB1'
        {
            Key = 'SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'SMB1'
        }
    }
    
    if($SmbStart){
        RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Services\MrxSmb10\Start'
        {
            Key = 'SYSTEM\CurrentControlSet\Services\MrxSmb10'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 4
            ValueName = 'Start'
        }
    }
    
    if($NoNameReleaseOnDemand){
        RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Services\Netbt\Parameters\NoNameReleaseOnDemand'
        {
            Key = 'SYSTEM\CurrentControlSet\Services\Netbt\Parameters'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'NoNameReleaseOnDemand'
        }
    }
    
    if($DisableIPSourceRouting){
        RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\DisableIPSourceRouting'
        {
            Key = 'SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 2
            ValueName = 'DisableIPSourceRouting'
        }
    }
    
    if($EnableICMPRedirect){
        RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\EnableICMPRedirect'
        {
            Key = 'SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'EnableICMPRedirect'
        }
    }
    
    if($PerformRouterDiscovery){
        RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\PerformRouterDiscovery'
        {
            Key = 'SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'PerformRouterDiscovery'
        }
    }
    
    if($KeepAliveTime){
        RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\KeepAliveTime'
        {
            Key = 'SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 300000
            ValueName = 'KeepAliveTime'
        }
    }
    
    if($TcpMaxDataRetransmissions){
        RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\TcpMaxDataRetransmissions'
        {
            Key = 'SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 3
            ValueName = 'TcpMaxDataRetransmissions'
        }
    }
    
    if($EnableIPAutoConfigurationLimits){
        RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\EnableIPAutoConfigurationLimits'
        {
            Key = 'SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'EnableIPAutoConfigurationLimits'
        }
    }
    
    if($DisableIPSourceRoutingIPv6){
        RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\DisableIPSourceRouting'
        {
            Key = 'SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 2
            ValueName = 'DisableIPSourceRouting'
        }
    }
    
    if($TcpMaxDataRetransmissionsIPv6){
        RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\TcpMaxDataRetransmissions'
        {
            Key = 'SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 3
            ValueName = 'TcpMaxDataRetransmissions'
        }
    }
    if($RestrictRemoteClients){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows NT\Rpc\RestrictRemoteClients'
        {
            Key = 'Software\policies\Microsoft\Windows NT\Rpc'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'RestrictRemoteClients'
        }
    }
    if($AuditCredentialValidationSuccess){
        AuditPolicySubcategory 'Audit Credential Validation (Success) - Inclusion'
        {
            Name = 'Credential Validation'
            Ensure = 'Present'
            AuditFlag = 'Success'
        }
    }
    
    if($AuditCredentialValidationFailure){
        AuditPolicySubcategory 'Audit Credential Validation (Failure) - Inclusion'
        {
            Name = 'Credential Validation'
            Ensure = 'Present'
            AuditFlag = 'Failure'
        }
    }
    
    if($AuditComputerAccountManagementSuccess){
        AuditPolicySubcategory 'Audit Computer Account Management (Success) - Inclusion'
        {
            Name = 'Computer Account Management'
            Ensure = 'Present'
            AuditFlag = 'Success'
        }
    }
    
    if(-not $AuditComputerAccountManagementFailure){
        AuditPolicySubcategory 'Audit Computer Account Management (Failure) - Inclusion'
        {
            Name = 'Computer Account Management'
            Ensure = 'Absent'
            AuditFlag = 'Failure'
        }
    }
    
    if($AuditOtherAccountManagementEventsSuccess){
        AuditPolicySubcategory 'Audit Other Account Management Events (Success) - Inclusion'
        {
            Name = 'Other Account Management Events'
            Ensure = 'Present'
            AuditFlag = 'Success'
        }
    }
    
    if(-not $AuditOtherAccountManagementEventsFailure){
        AuditPolicySubcategory 'Audit Other Account Management Events (Failure) - Inclusion'
        {
            Name = 'Other Account Management Events'
            Ensure = 'Absent'
            AuditFlag = 'Failure'
        }
    }
    
    if($AuditSecurityGroupManagementSuccess){
        AuditPolicySubcategory 'Audit Security Group Management (Success) - Inclusion'
        {
            Name = 'Security Group Management'
            Ensure = 'Present'
            AuditFlag = 'Success'
        }
    }
    
    if(-not $AuditSecurityGroupManagementFailure){
        AuditPolicySubcategory 'Audit Security Group Management (Failure) - Inclusion'
        {
            Name = 'Security Group Management'
            Ensure = 'Absent'
            AuditFlag = 'Failure'
        }
    }
    
    if($AuditUserAccountManagementSuccess){
        AuditPolicySubcategory 'Audit User Account Management (Success) - Inclusion'
        {
            Name = 'User Account Management'
            Ensure = 'Present'
            AuditFlag = 'Success'
        }
    }
    
    if($AuditUserAccountManagementFailure){
        AuditPolicySubcategory 'Audit User Account Management (Failure) - Inclusion'
        {
            Name = 'User Account Management'
            Ensure = 'Present'
            AuditFlag = 'Failure'
        }
    }
    
    if($AuditProcessCreationSuccess){
        AuditPolicySubcategory 'Audit Process Creation (Success) - Inclusion'
        {
            Name = 'Process Creation'
            Ensure = 'Present'
            AuditFlag = 'Success'
        }
    }
    
    if(-not $AuditProcessCreationFailure){
        AuditPolicySubcategory 'Audit Process Creation (Failure) - Inclusion'
        {
            Name = 'Process Creation'
            Ensure = 'Absent'
            AuditFlag = 'Failure'
        }
    }
    
    if($AuditDirectoryServiceAccessSuccess){
        AuditPolicySubcategory 'Audit Directory Service Access (Success) - Inclusion'
        {
            Name = 'Directory Service Access'
            Ensure = 'Present'
            AuditFlag = 'Success'
        }
    }
    
    if($AuditDirectoryServiceAccessFailure){
        AuditPolicySubcategory 'Audit Directory Service Access (Failure) - Inclusion'
        {
            Name = 'Directory Service Access'
            Ensure = 'Present'
            AuditFlag = 'Failure'
        }
    }
    
    if($AuditDirectoryServiceChangesSuccess){
        AuditPolicySubcategory 'Audit Directory Service Changes (Success) - Inclusion'
        {
            Name = 'Directory Service Changes'
            Ensure = 'Present'
            AuditFlag = 'Success'
        }
    }
    
    if(-not $AuditDirectoryServiceChangesFailure){
        AuditPolicySubcategory 'Audit Directory Service Changes (Failure) - Inclusion'
        {
            Name = 'Directory Service Changes'
            Ensure = 'Absent'
            AuditFlag = 'Failure'
        }
    }
    
    if($AuditAccountLockoutFailure){
        AuditPolicySubcategory 'Audit Account Lockout (Failure) - Inclusion'
        {
            Name = 'Account Lockout'
            Ensure = 'Present'
            AuditFlag = 'Failure'
        }
    }
    
    if(-not $AuditAccountLockoutSuccess){
        AuditPolicySubcategory 'Audit Account Lockout (Success) - Inclusion'
        {
            Name = 'Account Lockout'
            Ensure = 'Absent'
            AuditFlag = 'Success'
        }
    }
    
    if($AuditLogoffSuccess){
        AuditPolicySubcategory 'Audit Logoff (Success) - Inclusion'
        {
            Name = 'Logoff'
            Ensure = 'Present'
            AuditFlag = 'Success'
        }
    }
    
    if(-not $AuditLogoffFailure){
        AuditPolicySubcategory 'Audit Logoff (Failure) - Inclusion'
        {
            Name = 'Logoff'
            Ensure = 'Absent'
            AuditFlag = 'Failure'
        }
    }
    
    if($AuditLogonSuccess){
        AuditPolicySubcategory 'Audit Logon (Success) - Inclusion'
        {
            Name = 'Logon'
            Ensure = 'Present'
            AuditFlag = 'Success'
        }
    }
    
    if($AuditLogonFailure){
        AuditPolicySubcategory 'Audit Logon (Failure) - Inclusion'
        {
            Name = 'Logon'
            Ensure = 'Present'
            AuditFlag = 'Failure'
        }
    }
    
    if($AuditSpecialLogonSuccess){
        AuditPolicySubcategory 'Audit Special Logon (Success) - Inclusion'
        {
            Name = 'Special Logon'
            Ensure = 'Present'
            AuditFlag = 'Success'
        }
    }
    if($AuditSpecialLogonFailure){
        AuditPolicySubcategory 'Audit Special Logon (Failure) - Inclusion'
        {
            Name = 'Special Logon'
            Ensure = 'Absent'
            AuditFlag = 'Failure'
        }
    }
    
    if($AuditRemovableStorageSuccess){
        AuditPolicySubcategory 'Audit Removable Storage (Success) - Inclusion'
        {
            Name = 'Removable Storage'
            Ensure = 'Present'
            AuditFlag = 'Success'
        }
    }
    
    if($AuditRemovableStorageFailure){
        AuditPolicySubcategory 'Audit Removable Storage (Failure) - Inclusion'
        {
            Name = 'Removable Storage'
            Ensure = 'Present'
            AuditFlag = 'Failure'
        }
    }
    
    if($AuditCentralAccessPolicyStagingSuccess){
        AuditPolicySubcategory 'Audit Central Access Policy Staging (Success) - Inclusion'
        {
            Name = 'Central Policy Staging'
            Ensure = 'Present'
            AuditFlag = 'Success'
        }
    }
    
    if($AuditCentralAccessPolicyStagingFailure){
        AuditPolicySubcategory 'Audit Central Access Policy Staging (Failure) - Inclusion'
        {
            Name = 'Central Policy Staging'
            Ensure = 'Present'
            AuditFlag = 'Failure'
        }
    }
    
    if($AuditPolicyChangeSuccess){
        AuditPolicySubcategory 'Audit Audit Policy Change (Success) - Inclusion'
        {
            Name = 'Audit Policy Change'
            Ensure = 'Present'
            AuditFlag = 'Success'
        }
    }
    
    if($AuditPolicyChangeFailure){
        AuditPolicySubcategory 'Audit Audit Policy Change (Failure) - Inclusion'
        {
            Name = 'Audit Policy Change'
            Ensure = 'Present'
            AuditFlag = 'Failure'
        }
    }
    
    if($AuditAuthenticationPolicyChangeSuccess){
        AuditPolicySubcategory 'Audit Authentication Policy Change (Success) - Inclusion'
        {
            Name = 'Authentication Policy Change'
            Ensure = 'Present'
            AuditFlag = 'Success'
        }
    }
    
    if($AuditAuthenticationPolicyChangeFailure){
        AuditPolicySubcategory 'Audit Authentication Policy Change (Failure) - Inclusion'
        {
            Name = 'Authentication Policy Change'
            Ensure = 'Absent'
            AuditFlag = 'Failure'
        }
    }
    
    if($AuditAuthorizationPolicyChangeSuccess){
        AuditPolicySubcategory 'Audit Authorization Policy Change (Success) - Inclusion'
        {
            Name = 'Authorization Policy Change'
            Ensure = 'Present'
            AuditFlag = 'Success'
        }
    }
    
    if($AuditAuthorizationPolicyChangeFailure){
        AuditPolicySubcategory 'Audit Authorization Policy Change (Failure) - Inclusion'
        {
            Name = 'Authorization Policy Change'
            Ensure = 'Absent'
            AuditFlag = 'Failure'
        }
    }
    
    if($AuditSensitivePrivilegeUseSuccess){
        AuditPolicySubcategory 'Audit Sensitive Privilege Use (Success) - Inclusion'
        {
            Name = 'Sensitive Privilege Use'
            Ensure = 'Present'
            AuditFlag = 'Success'
        }
    }
    
    if($AuditSensitivePrivilegeUseFailure){
        AuditPolicySubcategory 'Audit Sensitive Privilege Use (Failure) - Inclusion'
        {
            Name = 'Sensitive Privilege Use'
            Ensure = 'Present'
            AuditFlag = 'Failure'
        }
    }
    
    if($AuditIPsecDriverSuccess){
        AuditPolicySubcategory 'Audit IPsec Driver (Success) - Inclusion'
        {
            Name = 'IPsec Driver'
            Ensure = 'Present'
            AuditFlag = 'Success'
        }
    }
    
    if($AuditIPsecDriverFailure){
        AuditPolicySubcategory 'Audit IPsec Driver (Failure) - Inclusion'
        {
            Name = 'IPsec Driver'
            Ensure = 'Present'
            AuditFlag = 'Failure'
        }
    }
    
    if($AuditOtherSystemEventsSuccess){
        AuditPolicySubcategory 'Audit Other System Events (Success) - Inclusion'
        {
            Name = 'Other System Events'
            Ensure = 'Present'
            AuditFlag = 'Success'
        }
    }
    
    if($AuditOtherSystemEventsFailure){
        AuditPolicySubcategory 'Audit Other System Events (Failure) - Inclusion'
        {
            Name = 'Other System Events'
            Ensure = 'Present'
            AuditFlag = 'Failure'
        }
    }
    
    if($AuditSecurityStateChangeSuccess){
        AuditPolicySubcategory 'Audit Security State Change (Success) - Inclusion'
        {
            Name = 'Security State Change'
            Ensure = 'Present'
            AuditFlag = 'Success'
        }
    }
    
    if($AuditSecurityStateChangeFailure){
        AuditPolicySubcategory 'Audit Security State Change (Failure) - Inclusion'
        {
            Name = 'Security State Change'
            Ensure = 'Absent'
            AuditFlag = 'Failure'
        }
    }
    
    if($AuditSecuritySystemExtensionSuccess){
        AuditPolicySubcategory 'Audit Security System Extension (Success) - Inclusion'
        {
            Name = 'Security System Extension'
            Ensure = 'Present'
            AuditFlag = 'Success'
        }
    }
    
    if($AuditSecuritySystemExtensionFailure){
        AuditPolicySubcategory 'Audit Security System Extension (Failure) - Inclusion'
        {
            Name = 'Security System Extension'
            Ensure = 'Absent'
            AuditFlag = 'Failure'
        }
    }
    
    if($AuditSystemIntegritySuccess){
        AuditPolicySubcategory 'Audit System Integrity (Success) - Inclusion'
        {
            Name = 'System Integrity'
            Ensure = 'Present'
            AuditFlag = 'Success'
        }
    }
    
    if($AuditSystemIntegrityFailure){
        AuditPolicySubcategory 'Audit System Integrity (Failure) - Inclusion'
        {
            Name = 'System Integrity'
            Ensure = 'Present'
            AuditFlag = 'Failure'
        }
    }
    if($UserAccountControlSecureDesktopElevation){
        SecurityOption 'SecurityRegistry(INF): User_Account_Control_Switch_to_the_secure_desktop_when_prompting_for_elevation'
        {
            Name = 'User_Account_Control_Switch_to_the_secure_desktop_when_prompting_for_elevation'
            User_Account_Control_Switch_to_the_secure_desktop_when_prompting_for_elevation = 'Enabled'
        }
    }
    
    if($AuditAccessGlobalSystemObjects){
        SecurityOption 'SecurityRegistry(INF): Audit_Audit_the_access_of_global_system_objects'
        {
            Name = 'Audit_Audit_the_access_of_global_system_objects'
            Audit_Audit_the_access_of_global_system_objects = 'Disabled'
        }
    }
    
    if($SPNTargetNameValidationLevel){
        SecurityOption 'SecurityRegistry(INF): Microsoft_network_server_Server_SPN_target_name_validation_level'
        {
            Name = 'Microsoft_network_server_Server_SPN_target_name_validation_level'
            Microsoft_network_server_Server_SPN_target_name_validation_level = 'Off'
        }
    }
    
    if($PreventInstallPrinterDrivers){
        SecurityOption 'SecurityRegistry(INF): Devices_Prevent_users_from_installing_printer_drivers'
        {
            Name = 'Devices_Prevent_users_from_installing_printer_drivers'
            Devices_Prevent_users_from_installing_printer_drivers = 'Enabled'
        }
    }
    
    if($AllowPKU2UAuthenticationOnlineIdentities){
        SecurityOption 'SecurityRegistry(INF): Network_security_Allow_PKU2U_authentication_requests_to_this_computer_to_use_online_identities'
        {
            Name = 'Network_security_Allow_PKU2U_authentication_requests_to_this_computer_to_use_online_identities'
            Network_security_Allow_PKU2U_authentication_requests_to_this_computer_to_use_online_identities = 'Disabled'
        }
    }
    
    if($DoNotStoreLANManagerHash){
        SecurityOption 'SecurityRegistry(INF): Network_security_Do_not_store_LAN_Manager_hash_value_on_next_password_change'
        {
            Name = 'Network_security_Do_not_store_LAN_Manager_hash_value_on_next_password_change'
            Network_security_Do_not_store_LAN_Manager_hash_value_on_next_password_change = 'Enabled'
        }
    }
    
    if($OnlyElevateSignedExecutables){
        SecurityOption 'SecurityRegistry(INF): User_Account_Control_Only_elevate_executables_that_are_signed_and_validated'
        {
            Name = 'User_Account_Control_Only_elevate_executables_that_are_signed_and_validated'
            User_Account_Control_Only_elevate_executables_that_are_signed_and_validated = 'Disabled'
        }
    }
    
    if($DigitallySignCommunicationsAlways){
        SecurityOption 'SecurityRegistry(INF): Microsoft_network_server_Digitally_sign_communications_always'
        {
            Name = 'Microsoft_network_server_Digitally_sign_communications_always'
            Microsoft_network_server_Digitally_sign_communications_always = 'Enabled'
        }
    }
    
    if($AdminApprovalModeForBuiltInAdmin){
        SecurityOption 'SecurityRegistry(INF): User_Account_Control_Admin_Approval_Mode_for_the_Built_in_Administrator_account'
        {
            Name = 'User_Account_Control_Admin_Approval_Mode_for_the_Built_in_Administrator_account'
            User_Account_Control_Admin_Approval_Mode_for_the_Built_in_Administrator_account = 'Enabled'
        }
    }
    
    if($VirtualizeWriteFailures){
        SecurityOption 'SecurityRegistry(INF): User_Account_Control_Virtualize_file_and_registry_write_failures_to_per_user_locations'
        {
            Name = 'User_Account_Control_Virtualize_file_and_registry_write_failures_to_per_user_locations'
            User_Account_Control_Virtualize_file_and_registry_write_failures_to_per_user_locations = 'Enabled'
        }
    }
    
    if($DetectApplicationInstallations){
        SecurityOption 'SecurityRegistry(INF): User_Account_Control_Detect_application_installations_and_prompt_for_elevation'
        {
            Name = 'User_Account_Control_Detect_application_installations_and_prompt_for_elevation'
            User_Account_Control_Detect_application_installations_and_prompt_for_elevation = 'Enabled'
        }
    }
    
    if($StrongKeyProtectionUserKeys){
        SecurityOption 'SecurityRegistry(INF): System_cryptography_Force_strong_key_protection_for_user_keys_stored_on_the_computer'
        {
            Name = 'System_cryptography_Force_strong_key_protection_for_user_keys_stored_on_the_computer'
            System_cryptography_Force_strong_key_protection_for_user_keys_stored_on_the_computer = 'User must enter a password each time they use a key'
        }
    }
    
    if($MinimumSessionSecurityNTLM){
        SecurityOption 'SecurityRegistry(INF): Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_servers'
        {
            Name = 'Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_servers'
            Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_servers = 'Both options checked'
        }
    }
    
    if($DoNotDisplayLastUserName){
        SecurityOption 'SecurityRegistry(INF): Interactive_logon_Do_not_display_last_user_name'
        {
            Name = 'Interactive_logon_Do_not_display_last_user_name'
            Interactive_logon_Do_not_display_last_user_name = 'Enabled'
        }
    }
    
    if($AllowLocalSystemComputerIdentityNTLM){
        SecurityOption 'SecurityRegistry(INF): Network_security_Allow_LocalSystem_NULL_session_fallback'
        {
            Name = 'Network_security_Allow_LocalSystem_NULL_session_fallback'
            Network_security_Allow_LocalSystem_NULL_session_fallback = 'Disabled'
        }
    }
    
    if($KerberosEncryptionTypes){
        SecurityOption 'SecurityRegistry(INF): Network_security_Configure_encryption_types_allowed_for_Kerberos'
        {
            Name = 'Network_security_Configure_encryption_types_allowed_for_Kerberos'
            Network_security_Configure_encryption_types_allowed_for_Kerberos = '2147483640'
        }
    }
    
    if($MaxMachineAccountPasswordAge){
        SecurityOption 'SecurityRegistry(INF): Domain_member_Maximum_machine_account_password_age'
        {
            Name = 'Domain_member_Maximum_machine_account_password_age'
            Domain_member_Maximum_machine_account_password_age = '30'
        }
    }
    
    if($IdleTimeBeforeSuspendingSession){
        SecurityOption 'SecurityRegistry(INF): Microsoft_network_server_Amount_of_idle_time_required_before_suspending_session'
        {
            Name = 'Microsoft_network_server_Amount_of_idle_time_required_before_suspending_session'
            Microsoft_network_server_Amount_of_idle_time_required_before_suspending_session = '15'
        }
    }
    
    if($RemotelyAccessibleRegistryPaths){
        SecurityOption 'SecurityRegistry(INF): Network_access_Remotely_accessible_registry_paths'
        {
            Name = 'Network_access_Remotely_accessible_registry_paths'
            Network_access_Remotely_accessible_registry_paths = 'System\CurrentControlSet\Control\ProductOptions,System\CurrentControlSet\Control\Server Applications,Software\Microsoft\Windows NT\CurrentVersion'
        }
    }
    
    if($ElevationPromptAdminApprovalMode){
        SecurityOption 'SecurityRegistry(INF): User_Account_Control_Behavior_of_the_elevation_prompt_for_administrators_in_Admin_Approval_Mode'
        {
            Name = 'User_Account_Control_Behavior_of_the_elevation_prompt_for_administrators_in_Admin_Approval_Mode'
            User_Account_Control_Behavior_of_the_elevation_prompt_for_administrators_in_Admin_Approval_Mode = 'Prompt for consent'
        }
    }
    
    if($DisableMachineAccountPasswordChanges){
        SecurityOption 'SecurityRegistry(INF): Domain_member_Disable_machine_account_password_changes'
        {
            Name = 'Domain_member_Disable_machine_account_password_changes'
            Domain_member_Disable_machine_account_password_changes = 'Disabled'
        }
    }
    
    if($SharesAccessibleAnonymously){
        SecurityOption 'SecurityRegistry(INF): Network_access_Shares_that_can_be_accessed_anonymously'
        {
            Name = 'Network_access_Shares_that_can_be_accessed_anonymously'
            Network_access_Shares_that_can_be_accessed_anonymously = 'String'
        }
    }
    
    if($RemotelyAccessibleRegistryPaths){
        SecurityOption 'SecurityRegistry(INF): Network_access_Remotely_accessible_registry_paths_and_subpaths'
        {
            Name = 'Network_access_Remotely_accessible_registry_paths_and_subpaths'
            Network_access_Remotely_accessible_registry_paths_and_subpaths = 'Software\Microsoft\Windows NT\CurrentVersion\Print,Software\Microsoft\Windows NT\CurrentVersion\Windows,System\CurrentControlSet\Control\Print\Printers,System\CurrentControlSet\Services\Eventlog,Software\Microsoft\OLAP Server,System\CurrentControlSet\Control\ContentIndex,System\CurrentControlSet\Control\Terminal Server,System\CurrentControlSet\Control\Terminal Server\UserConfig,System\CurrentControlSet\Control\Terminal Server\DefaultUserConfiguration,Software\Microsoft\Windows NT\CurrentVersion\Perflib,System\CurrentControlSet\Services\SysmonLog'
        }
    }
    
    if($FIPSAlgorithmUsage){
        SecurityOption 'SecurityRegistry(INF): System_cryptography_Use_FIPS_compliant_algorithms_for_encryption_hashing_and_signing'
        {
            Name = 'System_cryptography_Use_FIPS_compliant_algorithms_for_encryption_hashing_and_signing'
            System_cryptography_Use_FIPS_compliant_algorithms_for_encryption_hashing_and_signing = 'Enabled'
        }
    }
    
    if($EncryptOrSignSecureChannelDataAlways){
        SecurityOption 'SecurityRegistry(INF): Domain_member_Digitally_encrypt_or_sign_secure_channel_data_always'
        {
            Name = 'Domain_member_Digitally_encrypt_or_sign_secure_channel_data_always'
            Domain_member_Digitally_encrypt_or_sign_secure_channel_data_always = 'Enabled'
        }
    }
    
    if($RequireCaseInsensitivityNonWindowsSubsystems){
        SecurityOption 'SecurityRegistry(INF): System_objects_Require_case_insensitivity_for_non_Windows_subsystems'
        {
            Name = 'System_objects_Require_case_insensitivity_for_non_Windows_subsystems'
            System_objects_Require_case_insensitivity_for_non_Windows_subsystems = 'Enabled'
        }
    }
    
    if($RefuseMachineAccountPasswordChanges){
        SecurityOption 'SecurityRegistry(INF): Domain_controller_Refuse_machine_account_password_changes'
        {
            Name = 'Domain_controller_Refuse_machine_account_password_changes'
            Domain_controller_Refuse_machine_account_password_changes = 'Disabled'
        }
    }
    
    if($DisconnectClientsWhenLogonHoursExpire){
        SecurityOption 'SecurityRegistry(INF): Microsoft_network_server_Disconnect_clients_when_logon_hours_expire'
        {
            Name = 'Microsoft_network_server_Disconnect_clients_when_logon_hours_expire'
            Microsoft_network_server_Disconnect_clients_when_logon_hours_expire = 'Enabled'
        }
    }
    
    if($StrengthenPermissionsInternalObjects){
        SecurityOption 'SecurityRegistry(INF): System_objects_Strengthen_default_permissions_of_internal_system_objects_eg_Symbolic_Links'
        {
            Name = 'System_objects_Strengthen_default_permissions_of_internal_system_objects_eg_Symbolic_Links'
            System_objects_Strengthen_default_permissions_of_internal_system_objects_eg_Symbolic_Links = 'Enabled'
        }
    }
    
    if($AuditPolicySubcategoryOverride){
        SecurityOption 'SecurityRegistry(INF): Audit_Force_audit_policy_subcategory_settings_Windows_Vista_or_later_to_override_audit_policy_category_settings'
        {
            Name = 'Audit_Force_audit_policy_subcategory_settings_Windows_Vista_or_later_to_override_audit_policy_category_settings'
            Audit_Force_audit_policy_subcategory_settings_Windows_Vista_or_later_to_override_audit_policy_category_settings = 'Enabled'
        }
    }
    
    if($PromptUserChangePasswordExpiration){
        SecurityOption 'SecurityRegistry(INF): Interactive_logon_Prompt_user_to_change_password_before_expiration'
        {
            Name = 'Interactive_logon_Prompt_user_to_change_password_before_expiration'
            Interactive_logon_Prompt_user_to_change_password_before_expiration = '14'
        }
    }
    
    if($LDAPClientSigningRequirements){
        SecurityOption 'SecurityRegistry(INF): Network_security_LDAP_client_signing_requirements'
        {
            Name = 'Network_security_LDAP_client_signing_requirements'
            Network_security_LDAP_client_signing_requirements = 'Negotiate Signing'
        }
    }
    
    if($PreviousLogonsCacheCount){
        SecurityOption 'SecurityRegistry(INF): Interactive_logon_Number_of_previous_logons_to_cache_in_case_domain_controller_is_not_available'
        {
            Name = 'Interactive_logon_Number_of_previous_logons_to_cache_in_case_domain_controller_is_not_available'
            Interactive_logon_Number_of_previous_logons_to_cache_in_case_domain_controller_is_not_available = '4'
        }
    }
    
    if($AllowUIAccessElevationWithoutSecureDesktop){
        SecurityOption 'SecurityRegistry(INF): User_Account_Control_Allow_UIAccess_applications_to_prompt_for_elevation_without_using_the_secure_desktop'
        {
            Name = 'User_Account_Control_Allow_UIAccess_applications_to_prompt_for_elevation_without_using_the_secure_desktop'
            User_Account_Control_Allow_UIAccess_applications_to_prompt_for_elevation_without_using_the_secure_desktop = 'Disabled'
        }
    }
    
    if($SendUnencryptedPasswordThirdPartySMB){
        SecurityOption 'SecurityRegistry(INF): Microsoft_network_client_Send_unencrypted_password_to_third_party_SMB_servers'
        {
            Name = 'Microsoft_network_client_Send_unencrypted_password_to_third_party_SMB_servers'
            Microsoft_network_client_Send_unencrypted_password_to_third_party_SMB_servers = 'Disabled'
        }
    }
    
    if($EncryptSecureChannelDataIfPossible){
        SecurityOption 'SecurityRegistry(INF): Domain_member_Digitally_encrypt_secure_channel_data_when_possible'
        {
            Name = 'Domain_member_Digitally_encrypt_secure_channel_data_when_possible'
            Domain_member_Digitally_encrypt_secure_channel_data_when_possible = 'Enabled'
        }
    }
    
    if($DoNotAllowAnonymousEnumeration){
        SecurityOption 'SecurityRegistry(INF): Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts_and_shares'
        {
            Name = 'Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts_and_shares'
            Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts_and_shares = 'Enabled'
        }
    }
    
    if($SignCommunicationsAlways){
        SecurityOption 'SecurityRegistry(INF): Microsoft_network_client_Digitally_sign_communications_always'
        {
            Name = 'Microsoft_network_client_Digitally_sign_communications_always'
            Microsoft_network_client_Digitally_sign_communications_always = 'Enabled'
        }
    }
    
    if($DoNotAllowAnonymousEnumerationSAMAccounts){
        SecurityOption 'SecurityRegistry(INF): Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts'
        {
            Name = 'Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts'
            Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts = 'Enabled'
        }
    }
    
    if($RunAllAdministratorsInAdminApprovalMode){
        SecurityOption 'SecurityRegistry(INF): User_Account_Control_Run_all_administrators_in_Admin_Approval_Mode'
        {
            Name = 'User_Account_Control_Run_all_administrators_in_Admin_Approval_Mode'
            User_Account_Control_Run_all_administrators_in_Admin_Approval_Mode = 'Enabled'
        }
    }
    
    if($MinimumSessionSecurityNTLM){
        SecurityOption 'SecurityRegistry(INF): Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_clients'
        {
            Name = 'Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_clients'
            Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_clients = 'Both options checked'
        }
    }
    
    if($InteractiveLogonMessageTitle){
        SecurityOption 'SecurityRegistry(INF): Interactive_logon_Message_title_for_users_attempting_to_log_on'
        {
            Name = 'Interactive_logon_Message_title_for_users_attempting_to_log_on'
            Interactive_logon_Message_title_for_users_attempting_to_log_on = 'US Department of Defense Warning Statement'
        }
    }
    
    if($SmartCardRemovalBehavior){
        SecurityOption 'SecurityRegistry(INF): Interactive_logon_Smart_card_removal_behavior'
        {
            Name = 'Interactive_logon_Smart_card_removal_behavior'
            Interactive_logon_Smart_card_removal_behavior = 'Lock workstation'
        }
    }
    
    if($LANManagerAuthenticationLevel){
        SecurityOption 'SecurityRegistry(INF): Network_security_LAN_Manager_authentication_level'
        {
            Name = 'Network_security_LAN_Manager_authentication_level'
            Network_security_LAN_Manager_authentication_level = 'Send NTLMv2 responses only. Refuse LM & NTLM'
        }
    }
    
    if($LimitBlankPasswordConsoleLogon){
        SecurityOption 'SecurityRegistry(INF): Accounts_Limit_local_account_use_of_blank_passwords_to_console_logon_only'
        {
            Name = 'Accounts_Limit_local_account_use_of_blank_passwords_to_console_logon_only'
            Accounts_Limit_local_account_use_of_blank_passwords_to_console_logon_only = 'Enabled'
        }
    }
    
    if($SignCommunicationsIfClientAgrees){
        SecurityOption 'SecurityRegistry(INF): Microsoft_network_server_Digitally_sign_communications_if_client_agrees'
        {
            Name = 'Microsoft_network_server_Digitally_sign_communications_if_client_agrees'
            Microsoft_network_server_Digitally_sign_communications_if_client_agrees = 'Enabled'
        }
    }
    
    if($LDAPServerSigningRequirements){
        SecurityOption 'SecurityRegistry(INF): Domain_controller_LDAP_server_signing_requirements'
        {
            Name = 'Domain_controller_LDAP_server_signing_requirements'
            Domain_controller_LDAP_server_signing_requirements = 'Require Signing'
        }
    }
    
    if($DigitallySignSecureChannelDataIfPossible){
        SecurityOption 'SecurityRegistry(INF): Domain_member_Digitally_sign_secure_channel_data_when_possible'
        {
            Name = 'Domain_member_Digitally_sign_secure_channel_data_when_possible'
            Domain_member_Digitally_sign_secure_channel_data_when_possible = 'Enabled'
        }
    }
    
    if($InteractiveLogonMessageText){
        SecurityOption 'SecurityRegistry(INF): Interactive_logon_Message_text_for_users_attempting_to_log_on'
        {
            Name = 'Interactive_logon_Message_text_for_users_attempting_to_log_on'
            Interactive_logon_Message_text_for_users_attempting_to_log_on = 'You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.,By using this IS (which includes any device attached to this IS) you consent to the following conditions:,-The USG routinely intercepts and monitors communications on this IS for purposes including but not limited to penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.,-At any time, the USG may inspect and seize data stored on this IS.,-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.,-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.,-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details.'
        }
    }
    
    if($AllowShutdownWithoutLogon){
        SecurityOption 'SecurityRegistry(INF): Shutdown_Allow_system_to_be_shut_down_without_having_to_log_on'
        {
            Name = 'Shutdown_Allow_system_to_be_shut_down_without_having_to_log_on'
            Shutdown_Allow_system_to_be_shut_down_without_having_to_log_on = 'Disabled'
        }

    }
    if($DigitallySignCommunicationsIfServerAgrees){
        SecurityOption 'SecurityRegistry(INF): Microsoft_network_client_Digitally_sign_communications_if_server_agrees'
        {
            Name = 'Microsoft_network_client_Digitally_sign_communications_if_server_agrees'
            Microsoft_network_client_Digitally_sign_communications_if_server_agrees = 'Enabled'
        }
    }
    
    if($RequireStrongWindows2000SessionKey){
        SecurityOption 'SecurityRegistry(INF): Domain_member_Require_strong_Windows_2000_or_later_session_key'
        {
            Name = 'Domain_member_Require_strong_Windows_2000_or_later_session_key'
            Domain_member_Require_strong_Windows_2000_or_later_session_key = 'Enabled'
        }
    }
    
    if($RestrictAnonymousAccessNamedPipesShares){
        SecurityOption 'SecurityRegistry(INF): Network_access_Restrict_anonymous_access_to_Named_Pipes_and_Shares'
        {
            Name = 'Network_access_Restrict_anonymous_access_to_Named_Pipes_and_Shares'
            Network_access_Restrict_anonymous_access_to_Named_Pipes_and_Shares = 'Enabled'
        }
    }
    
    if($SharingSecurityModelForLocalAccounts){
        SecurityOption 'SecurityRegistry(INF): Network_access_Sharing_and_security_model_for_local_accounts'
        {
            Name = 'Network_access_Sharing_and_security_model_for_local_accounts'
            Network_access_Sharing_and_security_model_for_local_accounts = 'Classic - Local users authenticate as themselves'
        }
    }
    
    if($AuditUseOfBackupRestorePrivilege){
        SecurityOption 'SecurityRegistry(INF): Audit_Audit_the_use_of_Backup_and_Restore_privilege'
        {
            Name = 'Audit_Audit_the_use_of_Backup_and_Restore_privilege'
            Audit_Audit_the_use_of_Backup_and_Restore_privilege = 'Disabled'
        }
    }
    
    if($AddWorkstationsToDomain){
        UserRightsAssignment 'UserRightsAssignment(INF): Add_workstations_to_domain'
        {
            Force = $true
            Identity = @('*S-1-5-32-544')
            Policy = 'Add_workstations_to_domain'
        }
    }
    
    if($CreateGlobalObjects){
        UserRightsAssignment 'UserRightsAssignment(INF): Create_global_objects'
        {
            Force = $true
            Identity = @('*S-1-5-6', '*S-1-5-20', '*S-1-5-19', '*S-1-5-32-544')
            Policy = 'Create_global_objects'
        }
    }
    
    if($CreatePagefile){
        UserRightsAssignment 'UserRightsAssignment(INF): Create_a_pagefile'
        {
            Force = $true
            Identity = @('*S-1-5-32-544')
            Policy = 'Create_a_pagefile'
        }
    }
    
    if($AllowLogOnLocally){
        UserRightsAssignment 'UserRightsAssignment(INF): Allow_log_on_locally'
        {
            Force = $true
            Identity = @('*S-1-5-32-544')
            Policy = 'Allow_log_on_locally'
        }
    }
    
    if($LockPagesInMemory){
        UserRightsAssignment 'UserRightsAssignment(INF): Lock_pages_in_memory'
        {
            Force = $true
            Identity = @('')
            Policy = 'Lock_pages_in_memory'
        }
    }
    
    if($DenyLogOnLocally){
        UserRightsAssignment 'UserRightsAssignment(INF): Deny_log_on_locally'
        {
            Force = $true
            Identity = @('*S-1-5-32-546')
            Policy = 'Deny_log_on_locally'
        }
    }
    
    if($DenyLogOnAsAService){
        UserRightsAssignment 'UserRightsAssignment(INF): Deny_log_on_as_a_service'
        {
            Force = $true
            Identity = @('')
            Policy = 'Deny_log_on_as_a_service'
        }
    }
    
    if($TakeOwnershipOfFiles){
        UserRightsAssignment 'UserRightsAssignment(INF): Take_ownership_of_files_or_other_objects'
        {
            Force = $true
            Identity = @('*S-1-5-32-544')
            Policy = 'Take_ownership_of_files_or_other_objects'
        }
    }
    
    if($PerformVolumeMaintenanceTasks){
        UserRightsAssignment 'UserRightsAssignment(INF): Perform_volume_maintenance_tasks'
        {
            Force = $true
            Identity = @('*S-1-5-32-544')
            Policy = 'Perform_volume_maintenance_tasks'
        }
    }
    
    if($CreateTokenObject){
        UserRightsAssignment 'UserRightsAssignment(INF): Create_a_token_object'
        {
            Force = $true
            Identity = @('')
            Policy = 'Create_a_token_object'
        }
    }
    
    if($AccessCredentialManagerTrustedCaller){
        UserRightsAssignment 'UserRightsAssignment(INF): Access_Credential_Manager_as_a_trusted_caller'
        {
            Force = $true
            Identity = @('')
            Policy = 'Access_Credential_Manager_as_a_trusted_caller'
        }
    }
    
    if($DebugPrograms){
        UserRightsAssignment 'UserRightsAssignment(INF): Debug_programs'
        {
            Force = $true
            Identity = @('*S-1-5-32-544')
            Policy = 'Debug_programs'
        }
    }
    
    if($ModifyFirmwareEnvironmentValues){
        UserRightsAssignment 'UserRightsAssignment(INF): Modify_firmware_environment_values'
        {
            Force = $true
            Identity = @('*S-1-5-32-544')
            Policy = 'Modify_firmware_environment_values'
        }
    }
    
    if($LoadUnloadDeviceDrivers){
        UserRightsAssignment 'UserRightsAssignment(INF): Load_and_unload_device_drivers'
        {
            Force = $true
            Identity = @('*S-1-5-32-544')
            Policy = 'Load_and_unload_device_drivers'
        }
    }
    
    if($DenyAccessFromNetwork){
        UserRightsAssignment 'UserRightsAssignment(INF): Deny_access_to_this_computer_from_the_network'
        {
            Force = $true
            Identity = @('*S-1-5-32-546')
            Policy = 'Deny_access_to_this_computer_from_the_network'
        }
    }
    
    if($AccessFromNetwork){
        UserRightsAssignment 'UserRightsAssignment(INF): Access_this_computer_from_the_network'
        {
            Force = $true
            Identity = @('*S-1-5-9', '*S-1-5-11', '*S-1-5-32-544')
            Policy = 'Access_this_computer_from_the_network'
        }
    }
    RefreshRegistryPolicy 'ActivateClientSideExtension'
    {
        IsSingleInstance = 'Yes'
    }
}

