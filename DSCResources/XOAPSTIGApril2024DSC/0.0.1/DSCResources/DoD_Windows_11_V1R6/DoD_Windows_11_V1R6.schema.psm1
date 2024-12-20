configuration DoD_Windows_11_V1R6
{

    param(
        [system.string]$enterpriseAdmins,
        [system.string]$domainAdmins,
        [System.Boolean]$EnableSuppressionPolicyBatfile = $true,
        [System.Boolean]$EnableSuppressionPolicyCmdfile = $true,
        [System.Boolean]$EnableSuppressionPolicyExefile = $true,
        [System.Boolean]$EnableSuppressionPolicyMscfile = $true,
        [System.Boolean]$DisableAutoConnectOEM = $true,
        [System.Boolean]$DisableEnumerateAdministrators = $true,
        [System.Boolean]$EnableNoStartBanner = $true,
        [System.Boolean]$DisableWebServices = $true,
        [System.Boolean]$DisableAutoRun = $true,
        [System.Boolean]$SetNoDriveTypeAutoRun = $true,
        [System.Boolean]$SetPreXPSP2ShellProtocolBehavior = $true,
        [System.Boolean]$SetPasswordComplexity = $true,
        [System.Boolean]$SetPasswordLength = $true,
        [System.Boolean]$SetPasswordAgeDays = $true,
        [System.Boolean]$SetLocalAccountTokenFilterPolicy = $true,
        [System.Boolean]$SetMSAOptional = $true,
        [System.Boolean]$DisableAutomaticRestartSignOn = $true,
        [System.Boolean]$EnableProcessCreationIncludeCmdLine = $true,
        [System.Boolean]$EnableDevicePKInit = $true,
        [System.Boolean]$SetDevicePKInitBehavior = $true,
        [System.Boolean]$EnableEnhancedAntiSpoofing = $true,
        [System.Boolean]$SetEccCurves = $true,
        [System.Boolean]$EnableAdvancedStartup = $true,
        [System.Boolean]$EnableBDEWithNoTPM = $true,
        [System.Boolean]$SetUseTPM = $true,
        [System.Boolean]$EnableUseTPMPIN = $true,
        [System.Boolean]$SetUseTPMKey = $true,
        [System.Boolean]$SetUseTPMKeyPIN = $true,
        [System.Boolean]$SetMinimumPIN = $true,
        [System.Boolean]$DisableEnclosureDownload = $true,
        [System.Boolean]$AllowBasicAuthInClear = $true,
        [System.Boolean]$NotifyDisableIEOptions = $true,
        [System.Boolean]$RequireSecurityDevice = $true,
        [System.Boolean]$ExcludeTPM12SecurityDevices = $true,
        [System.Boolean]$SetMinimumPINLength = $true,
        [System.Boolean]$SetDCSettingIndex = $true,
        [System.Boolean]$SetACSettingIndex = $true,
        [System.Boolean]$DisableAppCompatInventory = $true,
        [System.Boolean]$LetAppsActivateWithVoiceAboveLock = $true,
        [System.Boolean]$DisableWindowsConsumerFeatures = $true,
        [System.Boolean]$AllowProtectedCreds = $true,
        [System.Boolean]$LimitEnhancedDiagnosticData = $true,
        [System.Boolean]$AllowTelemetry = $true,
        [System.Boolean]$SetDODownloadMode = $true,
        [System.Boolean]$EnableVirtualizationBasedSecurity = $true,
        [System.Boolean]$RequirePlatformSecurityFeatures = $true,
        [System.Boolean]$EnableHypervisorEnforcedCodeIntegrity = $true,
        [System.Boolean]$SetHVCIMATRequired = $true,
        [System.Boolean]$SetLsaCfgFlags = $true,
        [System.Boolean]$ConfigureSystemGuardLaunch = $true,
        [System.Boolean]$SetApplicationEventLogMaxSize = $true,
        [System.Boolean]$SetSecurityEventLogMaxSize = $true,
        [System.Boolean]$SetSystemEventLogMaxSize = $true,
        [System.Boolean]$NoAutoplayForNonVolume = $true,
        [System.Boolean]$NoDataExecutionPrevention = $true,
        [System.Boolean]$NoHeapTerminationOnCorruption = $true,
        [System.Boolean]$AllowGameDVR = $false,
        [System.Boolean]$NoBackgroundPolicy = $true,
        [System.Boolean]$NoGPOListChanges = $true,
        [System.Boolean]$SetEnableUserControl = $false,
        [System.Boolean]$DisableAlwaysInstallElevated = $true,
        [System.Boolean]$DisableSafeForScripting = $true,
        [System.Boolean]$SetDeviceEnumerationPolicy = $true,
        [System.Boolean]$DisableAllowInsecureGuestAuth = $true,
        [System.Boolean]$HideSharedAccessUI = $true,
        [System.Boolean]$HardenSYSVOLPaths = $true,
        [System.Boolean]$HardenNETLOGONPaths = $true,
        [System.Boolean]$DisableLockScreenCamera = $true,
        [System.Boolean]$DisableLockScreenSlideshow = $true,
        [System.Boolean]$EnableScriptBlockLogging = $true,
        [System.Boolean]$DisableScriptBlockInvocationLogging = $true,
        [System.Boolean]$EnableTranscripting = $true,
        [System.Boolean]$SetTranscriptionOutputDirectory = $true,
        [System.Boolean]$DisableInvocationHeader = $true,
        [System.Boolean]$DontDisplayNetworkSelectionUI = $true,
        [System.Boolean]$DisableEnumerateLocalUsers = $true,
        [System.Boolean]$EnableSmartScreen = $true,
        [System.Boolean]$SetShellSmartScreenLevel = $true,
        [System.Boolean]$DisableDomainPINLogon = $true,
        [System.Boolean]$MinimizeConnections = $true,
        [System.Boolean]$BlockNonDomainConnections = $true,
        [System.Boolean]$DisableIndexingEncryptedItems = $true,
        [System.Boolean]$DisableWinRMClientAllowBasic = $true,
        [System.Boolean]$DisableWinRMClientUnencryptedTraffic = $true,
        [System.Boolean]$DisableWinRMClientAllowDigest = $true,
        [System.Boolean]$DisableWinRMServiceAllowBasic = $true,
        [System.Boolean]$DisableWinRMServiceUnencryptedTraffic = $true,
        [System.Boolean]$EnableWinRMServiceDisableRunAs = $true,
        [System.Boolean]$DisableWebPnPDownload = $true,
        [System.Boolean]$DisableHTTPPrinting = $true,
        [System.Boolean]$RestrictRemoteClients = $true,
        [System.Boolean]$DisallowRemoteHelp = $true,
        [System.Boolean]$RemoveAllowFullControl = $true,
        [System.Boolean]$RemoveMaxTicketExpiry = $true,
        [System.Boolean]$RemoveMaxTicketExpiryUnits = $true,
        [System.Boolean]$RemoveUseMailto = $true,
        [System.Boolean]$DisablePasswordSaving = $true,
        [System.Boolean]$DisableCdm = $true,
        [System.Boolean]$PromptForPassword = $true,
        [System.Boolean]$EncryptRPCTraffic = $true,
        [System.Boolean]$SetMinEncryptionLevel = $true,
        [System.Boolean]$AllowWindowsInkWorkspace = $true,
        [System.Boolean]$UseLogonCredential = $true,
        [System.Boolean]$DisableExceptionChainValidation = $true,
        [System.Boolean]$SetDriverLoadPolicy = $true,
        [System.Boolean]$DisableSMB1 = $true,
        [System.Boolean]$DisableMrxSmb10 = $true,
        [System.Boolean]$EnableNoNameReleaseOnDemand = $true,
        [System.Boolean]$ConfigDisableIPSourceRoutingV4 = $true,
        [System.Boolean]$DisableICMPRedirect = $true,
        [System.Boolean]$ConfigDisableIPSourceRoutingV6 = $true,
        [System.Boolean]$AuditCredentialValidationSuccess = $true,
        [System.Boolean]$AuditCredentialValidationFailure = $true,
        [System.Boolean]$AuditSecurityGroupManagementSuccess = $true,
        [System.Boolean]$DoNotAuditSecurityGroupManagementFailure = $true,
        [System.Boolean]$AuditUserAccountManagementSuccess = $true,
        [System.Boolean]$AuditUserAccountManagementFailure = $true,
        [System.Boolean]$AuditPNPActivitySuccess = $true,
        [System.Boolean]$DoNotAuditPNPActivityFailure = $true,
        [System.Boolean]$AuditProcessCreationSuccess = $true,
        [System.Boolean]$AuditProcessCreationFailure = $true,
        [System.Boolean]$AuditAccountLockoutFailure = $true,
        [System.Boolean]$DoNotAuditAccountLockoutSuccess = $true,
        [System.Boolean]$AuditGroupMembershipSuccess = $true,
        [System.Boolean]$DoNotAuditGroupMembershipFailure = $true,
        [System.Boolean]$AuditLogoffSuccess = $true,
        [System.Boolean]$DoNotAuditLogoffFailure = $true,
        [System.Boolean]$AuditLogonSuccess = $true,
        [System.Boolean]$AuditLogonFailure = $true,
        [System.Boolean]$AuditOtherLogonLogoffSuccess = $true,
        [System.Boolean]$AuditOtherLogonLogoffFailure = $true,
        [System.Boolean]$AuditSpecialLogonSuccess = $true,
        [System.Boolean]$DoNotAuditSpecialLogonFailure = $true,
        [System.Boolean]$AuditDetailedFileShareFailure = $true,
        [System.Boolean]$DoNotAuditDetailedFileShareSuccess = $true,
        [System.Boolean]$AuditFileShareSuccess = $true,
        [System.Boolean]$AuditFileShareFailure = $true,
        [System.Boolean]$AuditOtherObjectAccessSuccess = $true,
        [System.Boolean]$AuditOtherObjectAccessFailure = $true,
        [System.Boolean]$AuditRemovableStorageSuccess = $true,        
        [System.Boolean]$AuditRemovableStorageFailure = $true,
        [System.Boolean]$AuditPolicyChangeSuccess = $true,
        [System.Boolean]$DoNotAuditPolicyChangeFailure = $true,
        [System.Boolean]$AuditAuthenticationPolicyChangeSuccess = $true,
        [System.Boolean]$DoNotAuditAuthenticationPolicyChangeFailure = $true,
        [System.Boolean]$AuditAuthorizationPolicyChangeSuccess = $true,
        [System.Boolean]$DoNotAuditAuthorizationPolicyChangeFailure = $true,
        [System.Boolean]$AuditMPSSVCRuleLevelPolicyChangeSuccess = $true,
        [System.Boolean]$AuditMPSSVCRuleLevelPolicyChangeFailure = $true,
        [System.Boolean]$AuditOtherPolicyChangeEventsSuccess = $true,
        [System.Boolean]$AuditOtherPolicyChangeEventsFailure = $true,
        [System.Boolean]$AuditSensitivePrivilegeUseSuccess = $true,
        [System.Boolean]$AuditSensitivePrivilegeUseFailure = $true,
        [System.Boolean]$AuditIPsecDriverFailure = $true,
        [System.Boolean]$DoNotAuditIPsecDriverSuccess = $true,
        [System.Boolean]$AuditOtherSystemEventsSuccess = $true,
        [System.Boolean]$AuditOtherSystemEventsFailure = $true,
        [System.Boolean]$AuditSecurityStateChangeSuccess = $true,
        [System.Boolean]$AuditSecurityStateChangeFailure = $true,
        [System.Boolean]$AuditSecuritySystemExtensionSuccess = $true,
        [System.Boolean]$DoNotAuditSecuritySystemExtensionFailure = $true,
        [System.Boolean]$AuditSystemIntegritySuccess = $true,
        [System.Boolean]$AuditSystemIntegrityFailure = $true,
        [System.Boolean]$NetworkSecurityDoNotStoreLANManagerHash = $true,
        [System.Boolean]$UserAccountControlBehaviorElevationPromptStandardUsers = $true,
        [System.Boolean]$MicrosoftNetworkServerDigitallySignCommunicationsAlways = $true,
        [System.Boolean]$UserAccountControlDetectApplicationInstallations = $true,
        [System.Boolean]$UserAccountControlVirtualizeFileAndRegistryFailures = $true,
        [System.Boolean]$InteractiveLogonMachineInactivityLimit = $true,
        [System.Boolean]$NetworkAccessLetEveryonePermissionsApplyToAnonymous = $true,
        [System.Boolean]$NetworkSecurityAllowLocalSystemNullSessionFallback = $true,
        [System.Boolean]$DomainMemberMaxMachineAccountPasswordAge = $true,
        [System.Boolean]$NetworkAccessRestrictClientsAllowedToMakeRemoteCalls = $true,
        [System.Boolean]$NetworkSecurityMinimumSessionSecurityForNTLM = $true,
        [System.Boolean]$UserAccountControlAdminApprovalMode = $true,
        [System.Boolean]$NetworkSecurityConfigureEncryptionTypesAllowedForKerberos = $true,
        [System.Boolean]$AuditForceAuditPolicySubcategorySettings = $true,
        [System.Boolean]$UserAccountControlBehaviorElevationPromptAdministrators = $true,
        [System.Boolean]$DomainMemberDisableMachineAccountPasswordChanges = $true,
        [System.Boolean]$NetworkSecurityAllowPKU2UAuthentication = $true,
        [System.Boolean]$SystemObjectsStrengthenDefaultPermissions = $true,
        [System.Boolean]$DomainMemberRequireStrongSessionKey = $true,
        [System.Boolean]$NetworkSecurityLDAPClientSigningRequirements = $true,
        [System.Boolean]$InteractiveLogonPreviousLogonsCache = $true,
        [System.Boolean]$MicrosoftNetworkClientSendUnencryptedPassword = $true,
        [System.Boolean]$DomainMemberDigitallyEncryptSecureChannelData = $true,
        [System.Boolean]$NetworkAccessDoNotAllowAnonymousEnumeration = $true,
        [System.Boolean]$MicrosoftNetworkClientDigitallySignCommunications = $true,
        [System.Boolean]$NetworkAccessDoNotAllowAnonymousEnumerationSAMAccounts = $true,
        [System.Boolean]$UserAccountControlRunAllAdminsInApprovalMode = $true,
        [System.Boolean]$NetworkSecurityMinimumSessionSecurityNTLM = $true,
        [System.Boolean]$InteractiveLogonMessageTitle = $true,
        [System.Boolean]$InteractiveLogonSmartCardRemovalBehavior = $true,
        [System.Boolean]$NetworkSecurityLANManagerAuthenticationLevel = $true,
        [System.Boolean]$AccountsLimitLocalAccountUseBlankPasswords = $true,
        [System.Boolean]$UserAccountControlOnlyElevateUIAccessApplications = $true,
        [System.Boolean]$DomainMemberDigitallySignSecureChannelWhenPossible = $true,
        [System.Boolean]$SystemCryptographyUseFIPSCompliantAlgorithms = $true,
        [System.Boolean]$NetworkAccessRestrictAnonymousAccess = $true,
        [System.Boolean]$UserRightsCreateGlobalObjects = $true,
        [System.Boolean]$UserRightsCreatePagefile = $true,
        [System.Boolean]$UserRightsAllowLogOnLocally = $true,
        [System.Boolean]$UserRightsLockPagesInMemory = $true,
        [System.Boolean]$UserRightsDenyLogOnLocally = $true,
        [System.Boolean]$UserRightsDenyLogOnAsAService = $true,
        [System.Boolean]$UserRightsTakeOwnershipOfFiles = $true,
        [System.Boolean]$UserRightsPerformVolumeMaintenanceTasks = $true,
        [System.Boolean]$UserRightsCreateTokenObject = $true,
        [System.Boolean]$UserRightsChangeSystemTime = $true,
        [System.Boolean]$UserRightsAccessCredentialManager = $true,
        [System.Boolean]$UserRightsDebugPrograms = $true,
        [System.Boolean]$UserRightsModifyFirmwareEnvironmentValues = $true,
        [System.Boolean]$UserRightsLoadAndUnloadDeviceDrivers = $true,
        [System.Boolean]$UserRightsDenyAccessToThisComputerFromNetwork = $true,
        [System.Boolean]$UserRightsAccessThisComputerFromNetwork = $true,
        [System.Boolean]$UserRightsRestoreFilesAndDirectories = $true,
        [System.Boolean]$UserRightsEnableTrustedForDelegation = $true,
        [System.Boolean]$UserRightsBackupFilesAndDirectories = $true,
        [System.Boolean]$UserRightsProfileSingleProcess = $true,
        [System.Boolean]$UserRightsDenyLogOnAsABatchJob = $true,
        [System.Boolean]$UserRightsActAsPartOfOS = $true,
        [System.Boolean]$UserRightsForceShutdownRemoteSystem = $true,
        [System.Boolean]$UserRightsImpersonateClientAfterAuth = $true,
        [System.Boolean]$UserRightsDenyLogOnThroughRemoteDesktop = $true,
        [System.Boolean]$UserRightsCreatePermanentSharedObjects = $true,
        [System.Boolean]$UserRightsManageAuditingAndSecurityLog = $true,
        [System.Boolean]$UserRightsCreateSymbolicLinks = $true,
        [System.Boolean]$AccountPolicyResetLockoutCount = $true,
        [System.Boolean]$LSAAnonymousNameLookup = $true,
        [System.Boolean]$AccountPolicyLockoutDuration = $true,
        [System.Boolean]$AccountsRenameAdministratorAccount = $true,
        [System.Boolean]$AccountPolicyPasswordHistorySize = $true,
        [System.Boolean]$AccountPolicyMinimumPasswordLength = $true,
        [System.Boolean]$AccountPolicyMinimumPasswordAge = $true,
        [System.Boolean]$AccountPolicyClearTextPassword = $true,
        [System.Boolean]$AccountsRenameGuestAccount = $true,
        [System.Boolean]$AccountsGuestAccountStatus = $true,
        [System.Boolean]$AccountPolicyLockoutBadCount = $true,
        [System.Boolean]$AccountPolicyPasswordComplexity = $true,
        [System.Boolean]$AccountsAdministratorAccountStatus = $true,
        [System.Boolean]$AccountPolicyMaximumPasswordAge = $true
    )   

    Import-DSCResource -ModuleName 'GPRegistryPolicyDsc'
	Import-DSCResource -ModuleName 'AuditPolicyDSC'
	Import-DSCResource -ModuleName 'SecurityPolicyDSC'

    if($EnableSuppressionPolicyBatfile){
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Classes\batfile\shell\runasuser\SuppressionPolicy'
        {
            Key = 'SOFTWARE\Classes\batfile\shell\runasuser'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 4096
            ValueName = 'SuppressionPolicy'
        }
    }
    
    if($EnableSuppressionPolicyCmdfile){
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Classes\cmdfile\shell\runasuser\SuppressionPolicy'
        {
            Key = 'SOFTWARE\Classes\cmdfile\shell\runasuser'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 4096
            ValueName = 'SuppressionPolicy'
        }
    }
    
    if($EnableSuppressionPolicyExefile){
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Classes\exefile\shell\runasuser\SuppressionPolicy'
        {
            Key = 'SOFTWARE\Classes\exefile\shell\runasuser'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 4096
            ValueName = 'SuppressionPolicy'
        }
    }
    
    if($EnableSuppressionPolicyMscfile){
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Classes\mscfile\shell\runasuser\SuppressionPolicy'
        {
            Key = 'SOFTWARE\Classes\mscfile\shell\runasuser'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 4096
            ValueName = 'SuppressionPolicy'
        }
    }
    
    if($DisableAutoConnectOEM){
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Microsoft\wcmsvc\wifinetworkmanager\config\AutoConnectAllowedOEM'
        {
            Key = 'SOFTWARE\Microsoft\wcmsvc\wifinetworkmanager\config'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'AutoConnectAllowedOEM'
        }
    }
    
    if($DisableEnumerateAdministrators){
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI\EnumerateAdministrators'
        {
            Key = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'EnumerateAdministrators'
        }
    }
    
    if($EnableNoStartBanner){
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoStartBanner'
        {
            Key = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'NoStartBanner'
        }
    }
    
    if($DisableWebServices){
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoWebServices'
        {
            Key = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'NoWebServices'
        }
    }
    
    if($DisableAutoRun){
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoAutorun'
        {
            Key = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'NoAutorun'
        }
    }
    
    if($SetNoDriveTypeAutoRun){
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoDriveTypeAutoRun'
        {
            Key = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 255
            ValueName = 'NoDriveTypeAutoRun'
        }
    }
    
    if($SetPreXPSP2ShellProtocolBehavior){
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\PreXPSP2ShellProtocolBehavior'
        {
            Key = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'PreXPSP2ShellProtocolBehavior'
        }
    }
    
    if($SetPasswordComplexity){
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS\PasswordComplexity'
        {
            Key = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 4
            ValueName = 'PasswordComplexity'
        }
    }
    
    if($SetPasswordLength){
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS\PasswordLength'
        {
            Key = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 14
            ValueName = 'PasswordLength'
        }
    }
    if($SetPasswordAgeDays){
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS\PasswordAgeDays'
        {
            Key = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 60
            ValueName = 'PasswordAgeDays'
        }
    }
    
    if($SetLocalAccountTokenFilterPolicy){
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\LocalAccountTokenFilterPolicy'
        {
            Key = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'LocalAccountTokenFilterPolicy'
        }
    }
    
    if($SetMSAOptional){
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\MSAOptional'
        {
            Key = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'MSAOptional'
        }
    }
    
    if($DisableAutomaticRestartSignOn){
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\DisableAutomaticRestartSignOn'
        {
            Key = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'DisableAutomaticRestartSignOn'
        }
    }
    
    if($EnableProcessCreationIncludeCmdLine){
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit\ProcessCreationIncludeCmdLine_Enabled'
        {
            Key = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'ProcessCreationIncludeCmdLine_Enabled'
        }
    }
    
    if($EnableDevicePKInit){
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\DevicePKInitEnabled'
        {
            Key = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'DevicePKInitEnabled'
        }
    }
    
    if($SetDevicePKInitBehavior){
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\DevicePKInitBehavior'
        {
            Key = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'DevicePKInitBehavior'
        }
    }
    
    if($EnableEnhancedAntiSpoofing){
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures\EnhancedAntiSpoofing'
        {
            Key = 'SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'EnhancedAntiSpoofing'
        }
    }
    
    if($SetEccCurves){
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002\EccCurves'
        {
            Key = 'SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002'
            TargetType = 'ComputerConfiguration'
            ValueType = 'MultiString'
            ValueData = 'NistP384NistP256'
            ValueName = 'EccCurves'
        }
    }
    
    if($EnableAdvancedStartup){
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\FVE\UseAdvancedStartup'
        {
            Key = 'SOFTWARE\Policies\Microsoft\FVE'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'UseAdvancedStartup'
        }
    }
    
    if($EnableBDEWithNoTPM){
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\FVE\EnableBDEWithNoTPM'
        {
            Key = 'SOFTWARE\Policies\Microsoft\FVE'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'EnableBDEWithNoTPM'
        }
    }
    
    if($SetUseTPM){
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\FVE\UseTPM'
        {
            Key = 'SOFTWARE\Policies\Microsoft\FVE'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 2
            ValueName = 'UseTPM'
        }
    }
    
    if($EnableUseTPMPIN){
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\FVE\UseTPMPIN'
        {
            Key = 'SOFTWARE\Policies\Microsoft\FVE'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'UseTPMPIN'
        }
    }
    
    if($SetUseTPMKey){
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\FVE\UseTPMKey'
        {
            Key = 'SOFTWARE\Policies\Microsoft\FVE'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 2
            ValueName = 'UseTPMKey'
        }
    }
    
    if($SetUseTPMKeyPIN){
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\FVE\UseTPMKeyPIN'
        {
            Key = 'SOFTWARE\Policies\Microsoft\FVE'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 2
            ValueName = 'UseTPMKeyPIN'
        }
    }
    
    if($SetMinimumPIN){
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\FVE\MinimumPIN'
        {
            Key = 'SOFTWARE\Policies\Microsoft\FVE'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 6
            ValueName = 'MinimumPIN'
        }
    }
    if($DisableEnclosureDownload){
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds\DisableEnclosureDownload'
        {
            Key = 'SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'DisableEnclosureDownload'
        }
    }
    
    if($AllowBasicAuthInClear){
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds\AllowBasicAuthInClear'
        {
            Key = 'SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'AllowBasicAuthInClear'
        }
    }
    
    if($NotifyDisableIEOptions){
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main\NotifyDisableIEOptions'
        {
            Key = 'SOFTWARE\Policies\Microsoft\Internet Explorer\Main'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'NotifyDisableIEOptions'
        }
    }
    
    if($RequireSecurityDevice){
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork\RequireSecurityDevice'
        {
            Key = 'SOFTWARE\Policies\Microsoft\PassportForWork'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'RequireSecurityDevice'
        }
    }
    
    if($ExcludeTPM12SecurityDevices){
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork\ExcludeSecurityDevices\TPM12'
        {
            Key = 'SOFTWARE\Policies\Microsoft\PassportForWork\ExcludeSecurityDevices'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'TPM12'
        }
    }
    
    if($SetMinimumPINLength){
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork\PINComplexity\MinimumPINLength'
        {
            Key = 'SOFTWARE\Policies\Microsoft\PassportForWork\PINComplexity'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 6
            ValueName = 'MinimumPINLength'
        }
    }
    
    if($SetDCSettingIndex){
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\DCSettingIndex'
        {
            Key = 'SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'DCSettingIndex'
        }
    }
    
    if($SetACSettingIndex){
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\ACSettingIndex'
        {
            Key = 'SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'ACSettingIndex'
        }
    }
    
    if($DisableAppCompatInventory){
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat\DisableInventory'
        {
            Key = 'SOFTWARE\Policies\Microsoft\Windows\AppCompat'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'DisableInventory'
        }
    }
    
    if($LetAppsActivateWithVoiceAboveLock){
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy\LetAppsActivateWithVoiceAboveLock'
        {
            Key = 'SOFTWARE\Policies\Microsoft\Windows\AppPrivacy'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 2
            ValueName = 'LetAppsActivateWithVoiceAboveLock'
        }
    }
    
    if($DisableWindowsConsumerFeatures){
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent\DisableWindowsConsumerFeatures'
        {
            Key = 'SOFTWARE\Policies\Microsoft\Windows\CloudContent'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'DisableWindowsConsumerFeatures'
        }
    }
    
    if($AllowProtectedCreds){
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation\AllowProtectedCreds'
        {
            Key = 'SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'AllowProtectedCreds'
        }
    }
    
    if($LimitEnhancedDiagnosticData){
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection\LimitEnhancedDiagnosticDataWindowsAnalytics'
        {
            Key = 'SOFTWARE\Policies\Microsoft\Windows\DataCollection'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'LimitEnhancedDiagnosticDataWindowsAnalytics'
        }
    }
    
    if($AllowTelemetry){
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection\AllowTelemetry'
        {
            Key = 'SOFTWARE\Policies\Microsoft\Windows\DataCollection'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'AllowTelemetry'
        }
    }
    
    if($SetDODownloadMode){
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization\DODownloadMode'
        {
            Key = 'SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 2
            ValueName = 'DODownloadMode'
        }
    }
    
    if($EnableVirtualizationBasedSecurity){
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard\EnableVirtualizationBasedSecurity'
        {
            Key = 'SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'EnableVirtualizationBasedSecurity'
        }
    }
    if($RequirePlatformSecurityFeatures){
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard\RequirePlatformSecurityFeatures'
        {
            Key = 'SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'RequirePlatformSecurityFeatures'
        }
    }
    
    if($EnableHypervisorEnforcedCodeIntegrity){
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard\HypervisorEnforcedCodeIntegrity'
        {
            Key = 'SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'HypervisorEnforcedCodeIntegrity'
        }
    }
    
    if($SetHVCIMATRequired){
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard\HVCIMATRequired'
        {
            Key = 'SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'HVCIMATRequired'
        }
    }
    
    if($SetLsaCfgFlags){
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard\LsaCfgFlags'
        {
            Key = 'SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'LsaCfgFlags'
        }
    }
    
    if($ConfigureSystemGuardLaunch){
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard\ConfigureSystemGuardLaunch'
        {
            Key = 'SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'ConfigureSystemGuardLaunch'
        }
    }
    
    if($SetApplicationEventLogMaxSize){
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application\MaxSize'
        {
            Key = 'SOFTWARE\Policies\Microsoft\Windows\EventLog\Application'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 32768
            ValueName = 'MaxSize'
        }
    }
    
    if($SetSecurityEventLogMaxSize){
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security\MaxSize'
        {
            Key = 'SOFTWARE\Policies\Microsoft\Windows\EventLog\Security'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1024000
            ValueName = 'MaxSize'
        }
    }
    
    if($SetSystemEventLogMaxSize){
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System\MaxSize'
        {
            Key = 'SOFTWARE\Policies\Microsoft\Windows\EventLog\System'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 32768
            ValueName = 'MaxSize'
        }
    }
    
    if($NoAutoplayForNonVolume){
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer\NoAutoplayfornonVolume'
        {
            Key = 'SOFTWARE\Policies\Microsoft\Windows\Explorer'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'NoAutoplayfornonVolume'
        }
    }
    
    if($NoDataExecutionPrevention){
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer\NoDataExecutionPrevention'
        {
            Key = 'SOFTWARE\Policies\Microsoft\Windows\Explorer'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'NoDataExecutionPrevention'
        }
    }
    
    if($NoHeapTerminationOnCorruption){
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer\NoHeapTerminationOnCorruption'
        {
            Key = 'SOFTWARE\Policies\Microsoft\Windows\Explorer'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'NoHeapTerminationOnCorruption'
        }
    }
    
    if($AllowGameDVR){
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR\AllowGameDVR'
        {
            Key = 'SOFTWARE\Policies\Microsoft\Windows\GameDVR'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'AllowGameDVR'
        }
    }
    
    if($NoBackgroundPolicy){
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}\NoBackgroundPolicy'
        {
            Key = 'SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'NoBackgroundPolicy'
        }
    }
    
    if($NoGPOListChanges){
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}\NoGPOListChanges'
        {
            Key = 'SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'NoGPOListChanges'
        }
    }
    
    if($SetEnableUserControl){
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer\EnableUserControl'
        {
            Key = 'SOFTWARE\Policies\Microsoft\Windows\Installer'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'EnableUserControl'
        }
    }
    if($DisableAlwaysInstallElevated){
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated'
        {
            Key = 'SOFTWARE\Policies\Microsoft\Windows\Installer'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'AlwaysInstallElevated'
        }
    }
    
    if($DisableSafeForScripting){
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer\SafeForScripting'
        {
            Key = 'SOFTWARE\Policies\Microsoft\Windows\Installer'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'SafeForScripting'
        }
    }
    
    if($SetDeviceEnumerationPolicy){
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\Kernel DMA Protection\DeviceEnumerationPolicy'
        {
            Key = 'SOFTWARE\Policies\Microsoft\Windows\Kernel DMA Protection'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'DeviceEnumerationPolicy'
        }
    }
    
    if($DisableAllowInsecureGuestAuth){
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation\AllowInsecureGuestAuth'
        {
            Key = 'SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'AllowInsecureGuestAuth'
        }
    }
    
    if($HideSharedAccessUI){
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections\NC_ShowSharedAccessUI'
        {
            Key = 'SOFTWARE\Policies\Microsoft\Windows\Network Connections'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'NC_ShowSharedAccessUI'
        }
    }
    
    if($HardenSYSVOLPaths){
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths\*\SYSVOL'
        {
            Key = 'SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths'
            TargetType = 'ComputerConfiguration'
            ValueType = 'String'
            ValueData = 'RequireMutualAuthentication=1, RequireIntegrity=1'
            ValueName = '\\*\SYSVOL'
        }
    }
    
    if($HardenNETLOGONPaths){
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths\*\NETLOGON'
        {
            Key = 'SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths'
            TargetType = 'ComputerConfiguration'
            ValueType = 'String'
            ValueData = 'RequireMutualAuthentication=1, RequireIntegrity=1'
            ValueName = '\\*\NETLOGON'
        }
    }
    
    if($DisableLockScreenCamera){
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization\NoLockScreenCamera'
        {
            Key = 'SOFTWARE\Policies\Microsoft\Windows\Personalization'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'NoLockScreenCamera'
        }
    }
    
    if($DisableLockScreenSlideshow){
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization\NoLockScreenSlideshow'
        {
            Key = 'SOFTWARE\Policies\Microsoft\Windows\Personalization'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'NoLockScreenSlideshow'
        }
    }
    
    if($EnableScriptBlockLogging){
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\EnableScriptBlockLogging'
        {
            Key = 'SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'EnableScriptBlockLogging'
        }
    }
    
    if($DisableScriptBlockInvocationLogging){
        RegistryPolicyFile 'DEL_\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\EnableScriptBlockInvocationLogging'
        {
            Key = 'SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
            TargetType = 'ComputerConfiguration'
            ValueType = 'String'
            ValueData = ''
            ValueName = 'EnableScriptBlockInvocationLogging'
            Ensure = 'Absent'
        }
    }
    
    if($EnableTranscripting){
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription\EnableTranscripting'
        {
            Key = 'SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'EnableTranscripting'
        }
    }
    
    if($SetTranscriptionOutputDirectory){
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription\OutputDirectory'
        {
            Key = 'SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription'
            TargetType = 'ComputerConfiguration'
            ValueType = 'String'
            ValueData = 'C:\ProgramData\PS_Transcript'
            ValueName = 'OutputDirectory'
        }
    }
    
    if($DisableInvocationHeader){
        RegistryPolicyFile 'DEL_\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription\EnableInvocationHeader'
        {
            Key = 'SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription'
            TargetType = 'ComputerConfiguration'
            ValueType = 'String'
            ValueData = ''
            ValueName = 'EnableInvocationHeader'
            Ensure = 'Absent'
        }
    }
    
    if($DontDisplayNetworkSelectionUI){
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\System\DontDisplayNetworkSelectionUI'
        {
            Key = 'SOFTWARE\Policies\Microsoft\Windows\System'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'DontDisplayNetworkSelectionUI'
        }
    }
    if($DisableEnumerateLocalUsers){
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\System\EnumerateLocalUsers'
        {
            Key = 'SOFTWARE\Policies\Microsoft\Windows\System'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'EnumerateLocalUsers'
        }
    }
    
    if($EnableSmartScreen){
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\System\EnableSmartScreen'
        {
            Key = 'SOFTWARE\Policies\Microsoft\Windows\System'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'EnableSmartScreen'
        }
    }
    
    if($SetShellSmartScreenLevel){
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\System\ShellSmartScreenLevel'
        {
            Key = 'SOFTWARE\Policies\Microsoft\Windows\System'
            TargetType = 'ComputerConfiguration'
            ValueType = 'String'
            ValueData = 'Block'
            ValueName = 'ShellSmartScreenLevel'
        }
    }
    
    if($DisableDomainPINLogon){
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\System\AllowDomainPINLogon'
        {
            Key = 'SOFTWARE\Policies\Microsoft\Windows\System'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'AllowDomainPINLogon'
        }
    }
    
    if($MinimizeConnections){
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy\fMinimizeConnections'
        {
            Key = 'SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 3
            ValueName = 'fMinimizeConnections'
        }
    }
    
    if($BlockNonDomainConnections){
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy\fBlockNonDomain'
        {
            Key = 'SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'fBlockNonDomain'
        }
    }
    
    if($DisableIndexingEncryptedItems){
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search\AllowIndexingEncryptedStoresOrItems'
        {
            Key = 'SOFTWARE\Policies\Microsoft\Windows\Windows Search'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'AllowIndexingEncryptedStoresOrItems'
        }
    }
    
    if($DisableWinRMClientAllowBasic){
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client\AllowBasic'
        {
            Key = 'SOFTWARE\Policies\Microsoft\Windows\WinRM\Client'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'AllowBasic'
        }
    }
    
    if($DisableWinRMClientUnencryptedTraffic){
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client\AllowUnencryptedTraffic'
        {
            Key = 'SOFTWARE\Policies\Microsoft\Windows\WinRM\Client'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'AllowUnencryptedTraffic'
        }
    }
    
    if($DisableWinRMClientAllowDigest){
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client\AllowDigest'
        {
            Key = 'SOFTWARE\Policies\Microsoft\Windows\WinRM\Client'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'AllowDigest'
        }
    }
    
    if($DisableWinRMServiceAllowBasic){
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\AllowBasic'
        {
            Key = 'SOFTWARE\Policies\Microsoft\Windows\WinRM\Service'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'AllowBasic'
        }
    }
    
    if($DisableWinRMServiceUnencryptedTraffic){
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\AllowUnencryptedTraffic'
        {
            Key = 'SOFTWARE\Policies\Microsoft\Windows\WinRM\Service'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'AllowUnencryptedTraffic'
        }
    }
    
    if($EnableWinRMServiceDisableRunAs){
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\DisableRunAs'
        {
            Key = 'SOFTWARE\Policies\Microsoft\Windows\WinRM\Service'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'DisableRunAs'
        }
    }
    
    if($DisableWebPnPDownload){
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\DisableWebPnPDownload'
        {
            Key = 'SOFTWARE\Policies\Microsoft\Windows NT\Printers'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'DisableWebPnPDownload'
        }
    }
    
    if($DisableHTTPPrinting){
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\DisableHTTPPrinting'
        {
            Key = 'SOFTWARE\Policies\Microsoft\Windows NT\Printers'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'DisableHTTPPrinting'
        }
    }
    if($RestrictRemoteClients){
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc\RestrictRemoteClients'
        {
            Key = 'SOFTWARE\Policies\Microsoft\Windows NT\Rpc'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'RestrictRemoteClients'
        }
    }
    
    if($DisallowRemoteHelp){
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\fAllowToGetHelp'
        {
            Key = 'SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'fAllowToGetHelp'
        }
    }
    
    if($RemoveAllowFullControl){
        RegistryPolicyFile 'DEL_\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\fAllowFullControl'
        {
            Key = 'SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            TargetType = 'ComputerConfiguration'
            ValueType = 'String'
            ValueData = ''
            ValueName = 'fAllowFullControl'
            Ensure = 'Absent'
        }
    }
    
    if($RemoveMaxTicketExpiry){
        RegistryPolicyFile 'DEL_\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\MaxTicketExpiry'
        {
            Key = 'SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            TargetType = 'ComputerConfiguration'
            ValueType = 'String'
            ValueData = ''
            ValueName = 'MaxTicketExpiry'
            Ensure = 'Absent'
        }
    }
    
    if($RemoveMaxTicketExpiryUnits){
        RegistryPolicyFile 'DEL_\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\MaxTicketExpiryUnits'
        {
            Key = 'SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            TargetType = 'ComputerConfiguration'
            ValueType = 'String'
            ValueData = ''
            ValueName = 'MaxTicketExpiryUnits'
            Ensure = 'Absent'
        }
    }
    
    if($RemoveUseMailto){
        RegistryPolicyFile 'DEL_\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\fUseMailto'
        {
            Key = 'SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            TargetType = 'ComputerConfiguration'
            ValueType = 'String'
            ValueData = ''
            ValueName = 'fUseMailto'
            Ensure = 'Absent'
        }
    }
    
    if($DisablePasswordSaving){
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\DisablePasswordSaving'
        {
            Key = 'SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'DisablePasswordSaving'
        }
    }
    
    if($DisableCdm){
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\fDisableCdm'
        {
            Key = 'SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'fDisableCdm'
        }
    }
    
    if($PromptForPassword){
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\fPromptForPassword'
        {
            Key = 'SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'fPromptForPassword'
        }
    }
    
    if($EncryptRPCTraffic){
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\fEncryptRPCTraffic'
        {
            Key = 'SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'fEncryptRPCTraffic'
        }
    }
    
    if($SetMinEncryptionLevel){
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\MinEncryptionLevel'
        {
            Key = 'SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 3
            ValueName = 'MinEncryptionLevel'
        }
    }
    
    if($AllowWindowsInkWorkspace){
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace\AllowWindowsInkWorkspace'
        {
            Key = 'SOFTWARE\Policies\Microsoft\WindowsInkWorkspace'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'AllowWindowsInkWorkspace'
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
    
    if($DisableExceptionChainValidation){
        RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel\DisableExceptionChainValidation'
        {
            Key = 'SYSTEM\CurrentControlSet\Control\Session Manager\kernel'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'DisableExceptionChainValidation'
        }
    }

    if($SetDriverLoadPolicy){
        RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch\DriverLoadPolicy'
        {
            Key = 'SYSTEM\CurrentControlSet\Policies\EarlyLaunch'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 3
            ValueName = 'DriverLoadPolicy'
        }
    }
    
    if($DisableSMB1){
        RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\SMB1'
        {
            Key = 'SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'SMB1'
        }
    }
    
    if($DisableMrxSmb10){
        RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Services\MrxSmb10\Start'
        {
            Key = 'SYSTEM\CurrentControlSet\Services\MrxSmb10'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 4
            ValueName = 'Start'
        }
    }
    
    if($EnableNoNameReleaseOnDemand){
        RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Services\Netbt\Parameters\NoNameReleaseOnDemand'
        {
            Key = 'SYSTEM\CurrentControlSet\Services\Netbt\Parameters'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'NoNameReleaseOnDemand'
        }
    }
    
    if($ConfigDisableIPSourceRoutingV4){
        RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\DisableIPSourceRouting'
        {
            Key = 'SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 2
            ValueName = 'DisableIPSourceRouting'
        }
    }
    
    if($DisableICMPRedirect){
        RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\EnableICMPRedirect'
        {
            Key = 'SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'EnableICMPRedirect'
        }
    }
    
    if($ConfigDisableIPSourceRoutingV6){
        RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\DisableIPSourceRouting'
        {
            Key = 'SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 2
            ValueName = 'DisableIPSourceRouting'
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
    
    if($AuditSecurityGroupManagementSuccess){
        AuditPolicySubcategory 'Audit Security Group Management (Success) - Inclusion'
        {
            Name = 'Security Group Management'
            Ensure = 'Present'
            AuditFlag = 'Success'
        }
    }
    
    if($DoNotAuditSecurityGroupManagementFailure){
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
    
    if($AuditPNPActivitySuccess){
        AuditPolicySubcategory 'Audit PNP Activity (Success) - Inclusion'
        {
            Name = 'Plug and Play Events'
            Ensure = 'Present'
            AuditFlag = 'Success'
        }
    }
    
    if($DoNotAuditPNPActivityFailure){
        AuditPolicySubcategory 'Audit PNP Activity (Failure) - Inclusion'
        {
            Name = 'Plug and Play Events'
            Ensure = 'Absent'
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
    
    if($AuditProcessCreationFailure){
        AuditPolicySubcategory 'Audit Process Creation (Failure) - Inclusion'
        {
            Name = 'Process Creation'
            Ensure = 'Present'
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
    
    if($DoNotAuditAccountLockoutSuccess){
        AuditPolicySubcategory 'Audit Account Lockout (Success) - Inclusion'
        {
            Name = 'Account Lockout'
            Ensure = 'Absent'
            AuditFlag = 'Success'
        }
    }
    
    if($AuditGroupMembershipSuccess){
        AuditPolicySubcategory 'Audit Group Membership (Success) - Inclusion'
        {
            Name = 'Group Membership'
            Ensure = 'Present'
            AuditFlag = 'Success'
        }
    }
    
    if($DoNotAuditGroupMembershipFailure){
        AuditPolicySubcategory 'Audit Group Membership (Failure) - Inclusion'
        {
            Name = 'Group Membership'
            Ensure = 'Absent'
            AuditFlag = 'Failure'
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
    
    if($DoNotAuditLogoffFailure){
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
    
    if($AuditOtherLogonLogoffSuccess){
        AuditPolicySubcategory 'Audit Other Logon/Logoff Events (Success) - Inclusion'
        {
            Name = 'Other Logon/Logoff Events'
            Ensure = 'Present'
            AuditFlag = 'Success'
        }
    }
    
    if($AuditOtherLogonLogoffFailure){
        AuditPolicySubcategory 'Audit Other Logon/Logoff Events (Failure) - Inclusion'
        {
            Name = 'Other Logon/Logoff Events'
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
    
    if($DoNotAuditSpecialLogonFailure){
        AuditPolicySubcategory 'Audit Special Logon (Failure) - Inclusion'
        {
            Name = 'Special Logon'
            Ensure = 'Absent'
            AuditFlag = 'Failure'
        }
    }
    
    if($AuditDetailedFileShareFailure){
        AuditPolicySubcategory 'Audit Detailed File Share (Failure) - Inclusion'
        {
            Name = 'Detailed File Share'
            Ensure = 'Present'
            AuditFlag = 'Failure'
        }
    }
    
    if($DoNotAuditDetailedFileShareSuccess){
        AuditPolicySubcategory 'Audit Detailed File Share (Success) - Inclusion'
        {
            Name = 'Detailed File Share'
            Ensure = 'Absent'
            AuditFlag = 'Success'
        }
    }
    
    if($AuditFileShareSuccess){
        AuditPolicySubcategory 'Audit File Share (Success) - Inclusion'
        {
            Name = 'File Share'
            Ensure = 'Present'
            AuditFlag = 'Success'
        }
    }
    
    if($AuditFileShareFailure){
        AuditPolicySubcategory 'Audit File Share (Failure) - Inclusion'
        {
            Name = 'File Share'
            Ensure = 'Present'
            AuditFlag = 'Failure'
        }
    }
    
    if($AuditOtherObjectAccessSuccess){
        AuditPolicySubcategory 'Audit Other Object Access Events (Success) - Inclusion'
        {
            Name = 'Other Object Access Events'
            Ensure = 'Present'
            AuditFlag = 'Success'
        }
    }
    
    if($AuditOtherObjectAccessFailure){
        AuditPolicySubcategory 'Audit Other Object Access Events (Failure) - Inclusion'
        {
            Name = 'Other Object Access Events'
            Ensure = 'Present'
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
    
    if($AuditPolicyChangeSuccess){
        AuditPolicySubcategory 'Audit Audit Policy Change (Success) - Inclusion'
        {
            Name = 'Audit Policy Change'
            Ensure = 'Present'
            AuditFlag = 'Success'
        }
    }
    
    if($DoNotAuditPolicyChangeFailure){
        AuditPolicySubcategory 'Audit Audit Policy Change (Failure) - Inclusion'
        {
            Name = 'Audit Policy Change'
            Ensure = 'Absent'
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
    
    if($DoNotAuditAuthenticationPolicyChangeFailure){
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
    
    if($DoNotAuditAuthorizationPolicyChangeFailure){
        AuditPolicySubcategory 'Audit Authorization Policy Change (Failure) - Inclusion'
        {
            Name = 'Authorization Policy Change'
            Ensure = 'Absent'
            AuditFlag = 'Failure'
        }
    }
    
    if($AuditMPSSVCRuleLevelPolicyChangeSuccess){
        AuditPolicySubcategory 'Audit MPSSVC Rule-Level Policy Change (Success) - Inclusion'
        {
            Name = 'MPSSVC Rule-Level Policy Change'
            Ensure = 'Present'
            AuditFlag = 'Success'
        }
    }
    
    if($AuditMPSSVCRuleLevelPolicyChangeFailure){
        AuditPolicySubcategory 'Audit MPSSVC Rule-Level Policy Change (Failure) - Inclusion'
        {
            Name = 'MPSSVC Rule-Level Policy Change'
            Ensure = 'Present'
            AuditFlag = 'Failure'
        }
    }
    
    if($AuditOtherPolicyChangeEventsSuccess){
        AuditPolicySubcategory 'Audit Other Policy Change Events (Success) - Inclusion'
        {
            Name = 'Other Policy Change Events'
            Ensure = 'Present'
            AuditFlag = 'Success'
        }
    }
    
    if($AuditOtherPolicyChangeEventsFailure){
        AuditPolicySubcategory 'Audit Other Policy Change Events (Failure) - Inclusion'
        {
            Name = 'Other Policy Change Events'
            Ensure = 'Present'
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
    
    if($AuditIPsecDriverFailure){
        AuditPolicySubcategory 'Audit IPsec Driver (Failure) - Inclusion'
        {
            Name = 'IPsec Driver'
            Ensure = 'Present'
            AuditFlag = 'Failure'
        }
    }
    
    if($DoNotAuditIPsecDriverSuccess){
        AuditPolicySubcategory 'Audit IPsec Driver (Success) - Inclusion'
        {
            Name = 'IPsec Driver'
            Ensure = 'Absent'
            AuditFlag = 'Success'
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
    
    if($DoNotAuditSecuritySystemExtensionFailure){
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
    
    if($NetworkSecurityDoNotStoreLANManagerHash){
        SecurityOption 'SecurityRegistry(INF): Network_security_Do_not_store_LAN_Manager_hash_value_on_next_password_change'
        {
            Name = 'Network_security_Do_not_store_LAN_Manager_hash_value_on_next_password_change'
            Network_security_Do_not_store_LAN_Manager_hash_value_on_next_password_change = 'Enabled'
        }
    }
    
    if($UserAccountControlBehaviorElevationPromptStandardUsers){
        SecurityOption 'SecurityRegistry(INF): User_Account_Control_Behavior_of_the_elevation_prompt_for_standard_users'
        {
            Name = 'User_Account_Control_Behavior_of_the_elevation_prompt_for_standard_users'
            User_Account_Control_Behavior_of_the_elevation_prompt_for_standard_users = 'Automatically deny elevation request'
        }
    }
    
    if($MicrosoftNetworkServerDigitallySignCommunicationsAlways){
        SecurityOption 'SecurityRegistry(INF): Microsoft_network_server_Digitally_sign_communications_always'
        {
            Name = 'Microsoft_network_server_Digitally_sign_communications_always'
            Microsoft_network_server_Digitally_sign_communications_always = 'Enabled'
        }
    }
    
    if($UserAccountControlDetectApplicationInstallations){
        SecurityOption 'SecurityRegistry(INF): User_Account_Control_Detect_application_installations_and_prompt_for_elevation'
        {
            Name = 'User_Account_Control_Detect_application_installations_and_prompt_for_elevation'
            User_Account_Control_Detect_application_installations_and_prompt_for_elevation = 'Enabled'
        }
    }
    
    if($UserAccountControlVirtualizeFileAndRegistryFailures){
        SecurityOption 'SecurityRegistry(INF): User_Account_Control_Virtualize_file_and_registry_write_failures_to_per_user_locations'
        {
            Name = 'User_Account_Control_Virtualize_file_and_registry_write_failures_to_per_user_locations'
            User_Account_Control_Virtualize_file_and_registry_write_failures_to_per_user_locations = 'Enabled'
        }
    }
    
    if($InteractiveLogonMachineInactivityLimit){
        SecurityOption 'SecurityRegistry(INF): Interactive_logon_Machine_inactivity_limit'
        {
            Name = 'Interactive_logon_Machine_inactivity_limit'
            Interactive_logon_Machine_inactivity_limit = '900'
        }
    }
    
    if($NetworkAccessLetEveryonePermissionsApplyToAnonymous){
        SecurityOption 'SecurityRegistry(INF): Network_access_Let_Everyone_permissions_apply_to_anonymous_users'
        {
            Name = 'Network_access_Let_Everyone_permissions_apply_to_anonymous_users'
            Network_access_Let_Everyone_permissions_apply_to_anonymous_users = 'Disabled'
        }
    }
    
    if($NetworkSecurityAllowLocalSystemNullSessionFallback){
        SecurityOption 'SecurityRegistry(INF): Network_security_Allow_LocalSystem_NULL_session_fallback'
        {
            Name = 'Network_security_Allow_LocalSystem_NULL_session_fallback'
            Network_security_Allow_LocalSystem_NULL_session_fallback = 'Disabled'
        }
    }
    
    if($DomainMemberMaxMachineAccountPasswordAge){
        SecurityOption 'SecurityRegistry(INF): Domain_member_Maximum_machine_account_password_age'
        {
            Name = 'Domain_member_Maximum_machine_account_password_age'
            Domain_member_Maximum_machine_account_password_age = '30'
        }
    }
    
    if($NetworkAccessRestrictClientsAllowedToMakeRemoteCalls){
        SecurityOption 'SecurityRegistry(INF): Network_access_Restrict_clients_allowed_to_make_remote_calls_to_SAM'
        {
            Name = 'Network_access_Restrict_clients_allowed_to_make_remote_calls_to_SAM'
            Network_access_Restrict_clients_allowed_to_make_remote_calls_to_SAM =  @(

            MSFT_RestrictedRemoteSamSecurityDescriptor
            
            {
            
            Permission = 'Allow'
            
            Identity   = 'Administrators'
            
            }
            
            )
        }
    }
    
    if($NetworkSecurityMinimumSessionSecurityForNTLM){
        SecurityOption 'SecurityRegistry(INF): Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_servers'
        {
            Name = 'Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_servers'
            Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_servers = 'Both options checked'
        }
    }
    
    if($UserAccountControlAdminApprovalMode){
        SecurityOption 'SecurityRegistry(INF): User_Account_Control_Admin_Approval_Mode_for_the_Built_in_Administrator_account'
        {
            Name = 'User_Account_Control_Admin_Approval_Mode_for_the_Built_in_Administrator_account'
            User_Account_Control_Admin_Approval_Mode_for_the_Built_in_Administrator_account = 'Enabled'
        }
    }
    
    if($NetworkSecurityConfigureEncryptionTypesAllowedForKerberos){
        SecurityOption 'SecurityRegistry(INF): Network_security_Configure_encryption_types_allowed_for_Kerberos'
        {
            Name = 'Network_security_Configure_encryption_types_allowed_for_Kerberos'
            Network_security_Configure_encryption_types_allowed_for_Kerberos = '2147483640'
        }
    }
    
    if($AuditForceAuditPolicySubcategorySettings){
        SecurityOption 'SecurityRegistry(INF): Audit_Force_audit_policy_subcategory_settings_Windows_Vista_or_later_to_override_audit_policy_category_settings'
        {
            Name = 'Audit_Force_audit_policy_subcategory_settings_Windows_Vista_or_later_to_override_audit_policy_category_settings'
            Audit_Force_audit_policy_subcategory_settings_Windows_Vista_or_later_to_override_audit_policy_category_settings = 'Enabled'
        }
    }
    
    if($UserAccountControlBehaviorElevationPromptAdministrators){
        SecurityOption 'SecurityRegistry(INF): User_Account_Control_Behavior_of_the_elevation_prompt_for_administrators_in_Admin_Approval_Mode'
        {
            Name = 'User_Account_Control_Behavior_of_the_elevation_prompt_for_administrators_in_Admin_Approval_Mode'
            User_Account_Control_Behavior_of_the_elevation_prompt_for_administrators_in_Admin_Approval_Mode = 'Prompt for consent on the secure desktop'
        }
    }
    
    if($DomainMemberDisableMachineAccountPasswordChanges){
        SecurityOption 'SecurityRegistry(INF): Domain_member_Disable_machine_account_password_changes'
        {
            Name = 'Domain_member_Disable_machine_account_password_changes'
            Domain_member_Disable_machine_account_password_changes = 'Disabled'
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
    
    if($DoNotAuditSecuritySystemExtensionFailure){
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
    
    if($NetworkSecurityDoNotStoreLANManagerHash){
        SecurityOption 'SecurityRegistry(INF): Interactive_logon_Message_text_for_users_attempting_to_log_on'
        {
            Name = 'Interactive_logon_Message_text_for_users_attempting_to_log_on'
            Interactive_logon_Message_text_for_users_attempting_to_log_on = 'You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only. By using this IS (which includes any device attached to this IS), you consent to the following conditions: - The USG routinely intercepts and monitors communications on this IS for purposes including but not limited to penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations. - At any time, the USG may inspect and seize data stored on this IS. - Communications using or data stored on this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose. - This IS includes security measures (e.g. authentication and access controls) to protect USG interests -- not for your personal benefit or privacy. - Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications or work product related to personal representation or services by attorneys, psychotherapists or clergy and their assistants. Such communications and work product are private and confidential. See User Agreement for details.'
        }
    }
    
    if($UserAccountControlBehaviorElevationPromptStandardUsers){
        SecurityOption 'SecurityRegistry(INF): User_Account_Control_Behavior_of_the_elevation_prompt_for_standard_users'
        {
            Name = 'User_Account_Control_Behavior_of_the_elevation_prompt_for_standard_users'
            User_Account_Control_Behavior_of_the_elevation_prompt_for_standard_users = 'Automatically deny elevation request'
        }
    }
    
    if($NetworkSecurityAllowPKU2UAuthentication){
        SecurityOption 'SecurityRegistry(INF): Network_Security_Allow_PKU2U_authentication_requests_to_this_computer_to_use_online_identities'
        {
            Name = 'Network_Security_Allow_PKU2U_authentication_requests_to_this_computer_to_use_online_identities'
            Network_Security_Allow_PKU2U_authentication_requests_to_this_computer_to_use_online_identities = 'Disabled'
        }
    }
    
    if($SystemObjectsStrengthenDefaultPermissions){
        SecurityOption 'SecurityRegistry(INF): System_objects_Strengthen_default_permissions_of_internal_system_objects_eg_Symbolic_Links'
        {
            Name = 'System_objects_Strengthen_default_permissions_of_internal_system_objects_eg_Symbolic_Links'
            System_objects_Strengthen_default_permissions_of_internal_system_objects_eg_Symbolic_Links = 'Enabled'
        }
    }
    
    if($DomainMemberRequireStrongSessionKey){
        SecurityOption 'SecurityRegistry(INF): Domain_member_Require_strong_Windows_2000_or_later_session_key'
        {
            Name = 'Domain_member_Require_strong_Windows_2000_or_later_session_key'
            Domain_member_Require_strong_Windows_2000_or_later_session_key = 'Enabled'
        }
    }
    
    if($NetworkSecurityLDAPClientSigningRequirements){
        SecurityOption 'SecurityRegistry(INF): Network_security_LDAP_client_signing_requirements'
        {
            Name = 'Network_security_LDAP_client_signing_requirements'
            Network_security_LDAP_client_signing_requirements = 'Negotiate Signing'
        }
    }
    
    if($InteractiveLogonMachineInactivityLimit){
        SecurityOption 'SecurityRegistry(INF): Interactive_logon_Number_of_previous_logons_to_cache_in_case_domain_controller_is_not_available'
        {
            Name = 'Interactive_logon_Number_of_previous_logons_to_cache_in_case_domain_controller_is_not_available'
            Interactive_logon_Number_of_previous_logons_to_cache_in_case_domain_controller_is_not_available = '10'
        }
    }
    
    if($MicrosoftNetworkClientSendUnencryptedPassword){
        SecurityOption 'SecurityRegistry(INF): Microsoft_network_client_Send_unencrypted_password_to_third_party_SMB_servers'
        {
            Name = 'Microsoft_network_client_Send_unencrypted_password_to_third_party_SMB_servers'
            Microsoft_network_client_Send_unencrypted_password_to_third_party_SMB_servers = 'Disabled'
        }
    }
    
    if($DomainMemberDigitallyEncryptSecureChannelWhenPossible){
        SecurityOption 'SecurityRegistry(INF): Domain_member_Digitally_encrypt_secure_channel_data_when_possible'
        {
            Name = 'Domain_member_Digitally_encrypt_secure_channel_data_when_possible'
            Domain_member_Digitally_encrypt_secure_channel_data_when_possible = 'Enabled'
        }
    }
    
    if($NetworkAccessDoNotAllowAnonymousEnumeration){
        SecurityOption 'SecurityRegistry(INF): Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts_and_shares'
        {
            Name = 'Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts_and_shares'
            Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts_and_shares = 'Enabled'
        }
    }
    
    if($MicrosoftNetworkClientDigitallySignCommunications){
        SecurityOption 'SecurityRegistry(INF): Microsoft_network_client_Digitally_sign_communications_always'
        {
            Name = 'Microsoft_network_client_Digitally_sign_communications_always'
            Microsoft_network_client_Digitally_sign_communications_always = 'Enabled'
        }
    }
    
    if($NetworkAccessDoNotAllowAnonymousEnumerationSAMAccounts){
        SecurityOption 'SecurityRegistry(INF): Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts'
        {
            Name = 'Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts'
            Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts = 'Enabled'
        }
    }
    
    if($UserAccountControlRunAllAdminsInApprovalMode){
        SecurityOption 'SecurityRegistry(INF): User_Account_Control_Run_all_administrators_in_Admin_Approval_Mode'
        {
            Name = 'User_Account_Control_Run_all_administrators_in_Admin_Approval_Mode'
            User_Account_Control_Run_all_administrators_in_Admin_Approval_Mode = 'Enabled'
        }
    }
    
    if($NetworkSecurityMinimumSessionSecurityNTLM){
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
    
    if($InteractiveLogonSmartCardRemovalBehavior){
        SecurityOption 'SecurityRegistry(INF): Interactive_logon_Smart_card_removal_behavior'
        {
            Name = 'Interactive_logon_Smart_card_removal_behavior'
            Interactive_logon_Smart_card_removal_behavior = 'Lock workstation'
        }
    }
    
    if($NetworkSecurityLANManagerAuthenticationLevel){
        SecurityOption 'SecurityRegistry(INF): Network_security_LAN_Manager_authentication_level'
        {
            Name = 'Network_security_LAN_Manager_authentication_level'
            Network_security_LAN_Manager_authentication_level = 'Send NTLMv2 responses only. Refuse LM & NTLM'
        }
    }
    
    if($AccountsLimitLocalAccountUseBlankPasswords){
        SecurityOption 'SecurityRegistry(INF): Accounts_Limit_local_account_use_of_blank_passwords_to_console_logon_only'
        {
            Name = 'Accounts_Limit_local_account_use_of_blank_passwords_to_console_logon_only'
            Accounts_Limit_local_account_use_of_blank_passwords_to_console_logon_only = 'Enabled'
        }
    }
    
    if($UserAccountControlOnlyElevateUIAccessApplications){
        SecurityOption 'SecurityRegistry(INF): User_Account_Control_Only_elevate_UIAccess_applications_that_are_installed_in_secure_locations'
        {
            Name = 'User_Account_Control_Only_elevate_UIAccess_applications_that_are_installed_in_secure_locations'
            User_Account_Control_Only_elevate_UIAccess_applications_that_are_installed_in_secure_locations = 'Enabled'
        }
    }
    
    if($DomainMemberDigitallySignSecureChannelWhenPossible){
        SecurityOption 'SecurityRegistry(INF): Domain_member_Digitally_sign_secure_channel_data_when_possible'
        {
            Name = 'Domain_member_Digitally_sign_secure_channel_data_when_possible'
            Domain_member_Digitally_sign_secure_channel_data_when_possible = 'Enabled'
        }
    }
    
    if($SystemCryptographyUseFIPSCompliantAlgorithms){
        SecurityOption 'SecurityRegistry(INF): System_cryptography_Use_FIPS_compliant_algorithms_for_encryption_hashing_and_signing'
        {
            Name = 'System_cryptography_Use_FIPS_compliant_algorithms_for_encryption_hashing_and_signing'
            System_cryptography_Use_FIPS_compliant_algorithms_for_encryption_hashing_and_signing = 'Enabled'
        }
    }
    if($NetworkAccessRestrictAnonymousAccess){
        SecurityOption 'SecurityRegistry(INF): Network_access_Restrict_anonymous_access_to_Named_Pipes_and_Shares'
        {
            Name = 'Network_access_Restrict_anonymous_access_to_Named_Pipes_and_Shares'
            Network_access_Restrict_anonymous_access_to_Named_Pipes_and_Shares = 'Enabled'
        }
    }
    
    if($UserRightsCreateGlobalObjects){
        UserRightsAssignment 'UserRightsAssignment(INF): Create_global_objects'
        {
            Force = $True
            Identity = @('*S-1-5-32-544', '*S-1-5-19', '*S-1-5-20', '*S-1-5-6')
            Policy = 'Create_global_objects'
        }
    }
    
    if($UserRightsCreatePagefile){
        UserRightsAssignment 'UserRightsAssignment(INF): Create_a_pagefile'
        {
            Force = $True
            Identity = @('*S-1-5-32-544')
            Policy = 'Create_a_pagefile'
        }
    }
    
    if($UserRightsAllowLogOnLocally){
        UserRightsAssignment 'UserRightsAssignment(INF): Allow_log_on_locally'
        {
            Force = $True
            Identity = @('*S-1-5-32-544', '*S-1-5-32-545')
            Policy = 'Allow_log_on_locally'
        }
    }
    
    if($UserRightsLockPagesInMemory){
        UserRightsAssignment 'UserRightsAssignment(INF): Lock_pages_in_memory'
        {
            Force = $True
            Identity = @('')
            Policy = 'Lock_pages_in_memory'
        }
    }
    
    if($UserRightsDenyLogOnLocally){
        UserRightsAssignment 'UserRightsAssignment(INF): Deny_log_on_locally'
        {
            Force = $True
            Identity = @('*S-1-5-32-546', $enterpriseAdmins, $domainAdmins)
            Policy = 'Deny_log_on_locally'
        }
    }
    
    if($UserRightsDenyLogOnAsAService){
        UserRightsAssignment 'UserRightsAssignment(INF): Deny_log_on_as_a_service'
        {
            Force = $True
            Identity = @($enterpriseAdmins, $domainAdmins)
            Policy = 'Deny_log_on_as_a_service'
        }
    }
    
    if($UserRightsTakeOwnershipOfFiles){
        UserRightsAssignment 'UserRightsAssignment(INF): Take_ownership_of_files_or_other_objects'
        {
            Force = $True
            Identity = @('*S-1-5-32-544')
            Policy = 'Take_ownership_of_files_or_other_objects'
        }
    }
    
    if($UserRightsPerformVolumeMaintenanceTasks){
        UserRightsAssignment 'UserRightsAssignment(INF): Perform_volume_maintenance_tasks'
        {
            Force = $True
            Identity = @('*S-1-5-32-544')
            Policy = 'Perform_volume_maintenance_tasks'
        }
    }
    
    if($UserRightsCreateTokenObject){
        UserRightsAssignment 'UserRightsAssignment(INF): Create_a_token_object'
        {
            Force = $True
            Identity = @('')
            Policy = 'Create_a_token_object'
        }
    }
    
    if($UserRightsChangeSystemTime){
        UserRightsAssignment 'UserRightsAssignment(INF): Change_the_system_time'
        {
            Force = $True
            Identity = @('*S-1-5-32-544', '*S-1-5-19')
            Policy = 'Change_the_system_time'
        }
    }
    
    if($UserRightsAccessCredentialManager){
        UserRightsAssignment 'UserRightsAssignment(INF): Access_Credential_Manager_as_a_trusted_caller'
        {
            Force = $True
            Identity = @('')
            Policy = 'Access_Credential_Manager_as_a_trusted_caller'
        }
    }
    
    if($UserRightsDebugPrograms){
        UserRightsAssignment 'UserRightsAssignment(INF): Debug_programs'
        {
            Force = $True
            Identity = @('*S-1-5-32-544')
            Policy = 'Debug_programs'
        }
    }
    
    if($UserRightsModifyFirmwareEnvironmentValues){
        UserRightsAssignment 'UserRightsAssignment(INF): Modify_firmware_environment_values'
        {
            Force = $True
            Identity = @('*S-1-5-32-544')
            Policy = 'Modify_firmware_environment_values'
        }
    }
    
    if($UserRightsLoadAndUnloadDeviceDrivers){
        UserRightsAssignment 'UserRightsAssignment(INF): Load_and_unload_device_drivers'
        {
            Force = $True
            Identity = @('*S-1-5-32-544')
            Policy = 'Load_and_unload_device_drivers'
        }
    }
    
    if($UserRightsDenyAccessToThisComputerFromNetwork){
        UserRightsAssignment 'UserRightsAssignment(INF): Deny_access_to_this_computer_from_the_network'
        {
            Force = $True
            Identity = @('*S-1-5-113', '*S-1-5-32-546', $enterpriseAdmins, $domainAdmins)
            Policy = 'Deny_access_to_this_computer_from_the_network'
        }
    }
    
    if($UserRightsAccessThisComputerFromNetwork){
        UserRightsAssignment 'UserRightsAssignment(INF): Access_this_computer_from_the_network'
        {
            Force = $True
            Identity = @('*S-1-5-32-544', '*S-1-5-32-555')
            Policy = 'Access_this_computer_from_the_network'
        }
    }
    
    if($UserRightsRestoreFilesAndDirectories){
        UserRightsAssignment 'UserRightsAssignment(INF): Restore_files_and_directories'
        {
            Force = $True
            Identity = @('*S-1-5-32-544')
            Policy = 'Restore_files_and_directories'
        }
    }
    
    if($UserRightsEnableTrustedForDelegation){
        UserRightsAssignment 'UserRightsAssignment(INF): Enable_computer_and_user_accounts_to_be_trusted_for_delegation'
        {
            Force = $True
            Identity = @('')
            Policy = 'Enable_computer_and_user_accounts_to_be_trusted_for_delegation'
        }
    }
    
    if($UserRightsBackupFilesAndDirectories){
        UserRightsAssignment 'UserRightsAssignment(INF): Back_up_files_and_directories'
        {
            Force = $True
            Identity = @('*S-1-5-32-544')
            Policy = 'Back_up_files_and_directories'
        }
    }
    
    if($UserRightsProfileSingleProcess){
        UserRightsAssignment 'UserRightsAssignment(INF): Profile_single_process'
        {
            Force = $True
            Identity = @('*S-1-5-32-544')
            Policy = 'Profile_single_process'
        }
    }
    
    if($UserRightsDenyLogOnAsABatchJob){
        UserRightsAssignment 'UserRightsAssignment(INF): Deny_log_on_as_a_batch_job'
        {
            Force = $True
            Identity = @($enterpriseAdmins, $domainAdmins)
            Policy = 'Deny_log_on_as_a_batch_job'
        }
    }
    
    if($UserRightsActAsPartOfOS){
        UserRightsAssignment 'UserRightsAssignment(INF): Act_as_part_of_the_operating_system'
        {
            Force = $True
            Identity = @('')
            Policy = 'Act_as_part_of_the_operating_system'
        }
    }
    
    if($UserRightsForceShutdownRemoteSystem){
        UserRightsAssignment 'UserRightsAssignment(INF): Force_shutdown_from_a_remote_system'
        {
            Force = $True
            Identity = @('*S-1-5-32-544')
            Policy = 'Force_shutdown_from_a_remote_system'
        }
    }
    
    if($UserRightsImpersonateClientAfterAuth){
        UserRightsAssignment 'UserRightsAssignment(INF): Impersonate_a_client_after_authentication'
        {
            Force = $True
            Identity = @('*S-1-5-6', '*S-1-5-20', '*S-1-5-19', '*S-1-5-32-544')
            Policy = 'Impersonate_a_client_after_authentication'
        }
    }
    
    if($UserRightsDenyLogOnThroughRemoteDesktop){
        UserRightsAssignment 'UserRightsAssignment(INF): Deny_log_on_through_Remote_Desktop_Services'
        {
            Force = $True
            Identity = @('*S-1-5-113', '*S-1-5-32-546', $enterpriseAdmins, $domainAdmins)
            Policy = 'Deny_log_on_through_Remote_Desktop_Services'
        }
    }
    
    if($UserRightsCreatePermanentSharedObjects){
        UserRightsAssignment 'UserRightsAssignment(INF): Create_permanent_shared_objects'
        {
            Force = $True
            Identity = @('')
            Policy = 'Create_permanent_shared_objects'
        }
    }
    
    if($UserRightsManageAuditingAndSecurityLog){
        UserRightsAssignment 'UserRightsAssignment(INF): Manage_auditing_and_security_log'
        {
            Force = $True
            Identity = @('*S-1-5-32-544')
            Policy = 'Manage_auditing_and_security_log'
        }
    }
    
    if($UserRightsCreateSymbolicLinks){
        UserRightsAssignment 'UserRightsAssignment(INF): Create_symbolic_links'
        {
            Force = $True
            Identity = @('*S-1-5-32-544')
            Policy = 'Create_symbolic_links'
        }
    }
    
    if($AccountPolicyResetLockoutCount){
        AccountPolicy 'SecuritySetting(INF): ResetLockoutCount'
        {
            Name = 'Reset_account_lockout_counter_after'
            Reset_account_lockout_counter_after = 15
        }
    }
    
    if($LSAAnonymousNameLookup){
        SecurityOption 'SecuritySetting(INF): LSAAnonymousNameLookup'
        {
            Network_access_Allow_anonymous_SID_Name_translation = 'Disabled'
            Name = 'Network_access_Allow_anonymous_SID_Name_translation'
        }
    }
    
    if($AccountPolicyLockoutDuration){
        AccountPolicy 'SecuritySetting(INF): LockoutDuration'
        {
            Account_lockout_duration = 15
            Name = 'Account_lockout_duration'
        }
    }
    
    if($AccountsRenameAdministratorAccount){
        SecurityOption 'SecuritySetting(INF): NewAdministratorName'
        {
            Name = 'Accounts_Rename_administrator_account'
            Accounts_Rename_administrator_account = 'X_Admin'
        }
    }
    
    if($AccountPolicyPasswordHistorySize){
        AccountPolicy 'SecuritySetting(INF): PasswordHistorySize'
        {
            Name = 'Enforce_password_history'
            Enforce_password_history = 24
        }
    }
    
    if($AccountPolicyMinimumPasswordLength){
        AccountPolicy 'SecuritySetting(INF): MinimumPasswordLength'
        {
            Minimum_Password_Length = 14
            Name = 'Minimum_Password_Length'
        }
    }
    
    if($AccountPolicyMinimumPasswordAge){
        AccountPolicy 'SecuritySetting(INF): MinimumPasswordAge'
        {
            Minimum_Password_Age = 1
            Name = 'Minimum_Password_Age'
        }
    }
    
    if($AccountPolicyClearTextPassword){
        AccountPolicy 'SecuritySetting(INF): ClearTextPassword'
        {
            Store_passwords_using_reversible_encryption = 'Disabled'
            Name = 'Store_passwords_using_reversible_encryption'
        }
    }
    
    if($AccountsRenameGuestAccount){
        SecurityOption 'SecuritySetting(INF): NewGuestName'
        {
            Accounts_Rename_guest_account = 'Visitor'
            Name = 'Accounts_Rename_guest_account'
        }
    }
    
    if($AccountsGuestAccountStatus){
        SecurityOption 'SecuritySetting(INF): EnableGuestAccount'
        {
            Accounts_Guest_account_status = 'Disabled'
            Name = 'Accounts_Guest_account_status'
        }
    }
    
    if($AccountPolicyLockoutBadCount){
        AccountPolicy 'SecuritySetting(INF): LockoutBadCount'
        {
            Account_lockout_threshold = 3
            Name = 'Account_lockout_threshold'
        }
    }
    
    if($AccountPolicyPasswordComplexity){
        AccountPolicy 'SecuritySetting(INF): PasswordComplexity'
        {
            Password_must_meet_complexity_requirements = 'Enabled'
            Name = 'Password_must_meet_complexity_requirements'
        }
    }
    
    if($AccountsAdministratorAccountStatus){
        SecurityOption 'SecuritySetting(INF): EnableAdminAccount'
        {
            Accounts_Administrator_account_status = 'Disabled'
            Name = 'Accounts_Administrator_account_status'
        }
    }
    
    if($AccountPolicyMaximumPasswordAge){
        AccountPolicy 'SecuritySetting(INF): MaximumPasswordAge'
        {
            Maximum_Password_Age = 60
            Name = 'Maximum_Password_Age'
        }
    }
    RefreshRegistryPolicy 'ActivateClientSideExtension'
    {
        IsSingleInstance = 'Yes'
    }
}

