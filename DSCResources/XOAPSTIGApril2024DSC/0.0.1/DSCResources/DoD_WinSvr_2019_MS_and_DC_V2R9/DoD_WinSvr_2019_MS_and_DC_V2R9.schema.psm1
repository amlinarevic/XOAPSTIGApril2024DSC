configuration DoD_WinSvr_2019_MS_and_DC_V2R9
{


    param(
        [System.Boolean]$WindowsCredUIEnumerateAdministrators = $true,
        [System.Boolean]$WindowsExplorerNoAutorun = $true,
        [System.Boolean]$WindowsExplorerNoDriveTypeAutoRun = $true,
        [System.Boolean]$LAPSPasswordComplexity = $true,
        [System.Boolean]$LAPSPasswordLength = $true,
        [System.Boolean]$LAPSPasswordAgeDays = $true,
        [System.Boolean]$WindowsSystemDisableAutomaticRestartSignOn = $true,
        [System.Boolean]$WindowsSystemLocalAccountTokenFilterPolicy = $true,
        [System.Boolean]$WindowsSystemProcessCreationIncludeCmdLineEnabled = $true,
        [System.Boolean]$InternetExplorerFeedsDisableEnclosureDownload = $true,
        [System.Boolean]$PowerDCSettingIndex = $true,
        [System.Boolean]$PowerACSettingIndex = $true,
        [System.Boolean]$WindowsAppCompatDisableInventory = $true,
        [System.Boolean]$WindowsCredentialsDelegationAllowProtectedCreds = $true,
        [System.Boolean]$WindowsDataCollectionAllowTelemetry = $true,
        [System.Boolean]$WindowsDeliveryOptimizationDownloadMode = $true,
        [System.Boolean]$DeviceGuardEnableVirtualizationBasedSecurity = $true,
        [System.Boolean]$DeviceGuardRequirePlatformSecurityFeatures = $true,
        [System.Boolean]$DeviceGuardHypervisorEnforcedCodeIntegrity = $true,
        [System.Boolean]$DeviceGuardHVCIMATRequired = $true,
        [System.Boolean]$DeviceGuardLsaCfgFlags = $true,
        [System.Boolean]$DeviceGuardConfigureSystemGuardLaunch = $true,
        [System.Boolean]$EventLogApplicationMaxSize = $true,
        [System.Boolean]$EventLogSecurityMaxSize = $true,
        [System.Boolean]$EventLogSystemMaxSize = $true,
        [System.Boolean]$ExplorerNoAutoplayForNonVolume = $true,
        [System.Boolean]$GroupPolicyNoBackgroundPolicy = $true,
        [System.Boolean]$GroupPolicyNoGPOListChanges = $true,
        [System.Boolean]$InstallerEnableUserControl = $true,
        [System.Boolean]$InstallerAlwaysInstallElevated = $true,
        [System.Boolean]$LanmanWorkstationAllowInsecureGuestAuth = $true,
        [System.Boolean]$NetworkProviderHardenedPathsNETLOGON = $true,
        [System.Boolean]$NetworkProviderHardenedPathsSYSVOL = $true,
        [System.Boolean]$PersonalizationNoLockScreenSlideshow = $true,
        [System.Boolean]$PowerShellEnableScriptBlockLogging = $true,
        [System.Boolean]$PowerShellEnableScriptBlockInvocationLogging = $true,
        [System.Boolean]$PowerShellEnableTranscripting = $true,
        [System.Boolean]$PowerShellOutputDirectory = $true,
        [System.Boolean]$PowerShellEnableInvocationHeader = $true,
        [System.Boolean]$SystemDontDisplayNetworkSelectionUI = $true,
        [System.Boolean]$SystemEnumerateLocalUsers = $true,
        [System.Boolean]$SystemEnableSmartScreen = $true,
        [System.Boolean]$WindowsSearchAllowIndexingEncryptedStoresOrItems = $true,
        [System.Boolean]$WinRMClientAllowBasic = $true,
        [System.Boolean]$WinRMClientAllowUnencryptedTraffic = $true,
        [System.Boolean]$WinRMClientAllowDigest = $true,
        [System.Boolean]$WinRMServiceAllowBasic = $true,
        [System.Boolean]$WinRMServiceAllowUnencryptedTraffic = $true,
        [System.Boolean]$WinRMServiceDisableRunAs = $true,
        [System.Boolean]$PrintersDisableWebPnPDownload = $true,
        [System.Boolean]$PrintersDisableHTTPPrinting = $true,
        [System.Boolean]$RpcRestrictRemoteClients = $true,
        [System.Boolean]$TerminalServicesDisablePasswordSaving = $true,
        [System.Boolean]$TerminalServicesDisableCdm = $true,
        [System.Boolean]$TerminalServicesPromptForPassword = $true,
        [System.Boolean]$TerminalServicesEncryptRPCTraffic = $true,
        [System.Boolean]$TerminalServicesMinEncryptionLevel = $true,
        [System.Boolean]$WDigestUseLogonCredential = $true,
        [System.Boolean]$LanmanServerSMB1 = $true,
        [System.Boolean]$MrxSmb10Start = $true,
        [System.Boolean]$NetbtNoNameReleaseOnDemand = $true,
        [System.Boolean]$TcpipDisableIPSourceRouting = $true,
        [System.Boolean]$TcpipEnableICMPRedirect = $true,
        [System.Boolean]$Tcpip6DisableIPSourceRouting = $true,        
        [System.Boolean]$AuditCredentialValidationSuccess = $true,
        [System.Boolean]$AuditCredentialValidationFailure = $true,
        [System.Boolean]$AuditOtherAccountManagementEventsSuccess = $true,
        [System.Boolean]$AuditOtherAccountManagementEventsFailure = $true,
        [System.Boolean]$AuditSecurityGroupManagementSuccess = $true,
        [System.Boolean]$AuditSecurityGroupManagementFailure = $true,
        [System.Boolean]$AuditUserAccountManagementSuccess = $true,
        [System.Boolean]$AuditUserAccountManagementFailure = $true,
        [System.Boolean]$AuditPnpActivitySuccess = $true,
        [System.Boolean]$AuditPnpActivityFailure = $true,
        [System.Boolean]$AuditProcessCreationSuccess = $true,
        [System.Boolean]$AuditProcessCreationFailure = $true,
        [System.Boolean]$AuditAccountLockoutFailure = $true,
        [System.Boolean]$AuditAccountLockoutSuccess = $true,
        [System.Boolean]$AuditGroupMembershipSuccess = $true,
        [System.Boolean]$AuditGroupMembershipFailure = $true,
        [System.Boolean]$AuditLogoffSuccess = $true,
        [System.Boolean]$AuditLogoffFailure = $true,
        [System.Boolean]$AuditLogonSuccess = $true,
        [System.Boolean]$AuditLogonFailure = $true,
        [System.Boolean]$AuditSpecialLogonSuccess = $true,
        [System.Boolean]$AuditSpecialLogonFailure = $true,
        [System.Boolean]$AuditOtherObjectAccessEventsSuccess = $true,
        [System.Boolean]$AuditOtherObjectAccessEventsFailure = $true,
        [System.Boolean]$AuditRemovableStorageSuccess = $true,
        [System.Boolean]$AuditRemovableStorageFailure = $true,
        [System.Boolean]$AuditAuditPolicyChangeSuccess = $true,
        [System.Boolean]$AuditAuditPolicyChangeFailure = $true,
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
        [System.Boolean]$AuditComputerAccountManagementSuccess = $true,
        [System.Boolean]$AuditComputerAccountManagementFailure = $true,
        [System.Boolean]$AuditDirectoryServiceAccessSuccess = $true,
        [System.Boolean]$AuditDirectoryServiceAccessFailure = $true,
        [System.Boolean]$AuditDirectoryServiceChangesSuccess = $true,
        [System.Boolean]$AuditDirectoryServiceChangesFailure = $true,
        [System.Boolean]$AccountPolicyResetLockoutCount = $true,
        [System.Boolean]$SecurityOptionLSAAnonymousNameLookup = $true,
        [System.Boolean]$AccountPolicyLockoutDuration = $true,
        [System.Boolean]$SecurityOptionNewAdministratorName = $true,
        [System.Boolean]$AccountPolicyPasswordHistorySize = $true,
        [System.Boolean]$AccountPolicyMinimumPasswordLength = $true,
        [System.Boolean]$AccountPolicyMinimumPasswordAge = $true,
        [System.Boolean]$AccountPolicyClearTextPassword = $true,
        [System.Boolean]$SecurityOptionNewGuestName = $true,
        [System.Boolean]$SecurityOptionEnableGuestAccount = $true,
        [System.Boolean]$AccountPolicyLockoutBadCount = $true,
        [System.Boolean]$AccountPolicyPasswordComplexity = $true,
        [System.Boolean]$AccountPolicyMaximumPasswordAge = $true,
        [System.Boolean]$SecurityRegistryNetworkSecurityDoNotStoreLanManagerHash = $true,
        [System.Boolean]$SecurityRegistryUserAccountControlBehaviorOfTheElevationPrompt = $true,
        [System.Boolean]$SecurityRegistryMicrosoftNetworkServerDigitallySignCommunicationsAlways = $true,
        [System.Boolean]$SecurityRegistryUserAccountControlAdminApprovalModeForBuiltInAdmin = $true,
        [System.Boolean]$SecurityRegistryUserAccountControlVirtualizeFileAndRegistryFailures = $true,
        [System.Boolean]$SecurityRegistryInteractiveLogonMachineInactivityLimit = $true,
        [System.Boolean]$SecurityRegistrySystemCryptographyForceStrongKeyProtection = $true,
        [System.Boolean]$SecurityOptionNetworkAccessLetEveryonePermissionsApplyToAnonymousUsers = $true,
        [System.Boolean]$SecurityOptionNetworkSecurityAllowLocalSystemNullSessionFallback = $true,
        [System.Boolean]$SecurityOptionDomainMemberMaximumMachineAccountPasswordAge = $true,
        [System.Boolean]$SecurityOptionNetworkAccessRestrictClientsAllowedToMakeRemoteCallsToSAM = $true,
        [System.Boolean]$SecurityOptionNetworkSecurityMinimumSessionSecurityForNTLMSSP = $true,
        [System.Boolean]$SecurityOptionNetworkSecurityAllowLocalSystemToUseComputerIdentityForNTLM = $true,
        [System.Boolean]$SecurityOptionNetworkSecurityConfigureEncryptionTypesAllowedForKerberos = $true,
        [System.Boolean]$SecurityOptionAuditForceAuditPolicySubcategorySettings = $true,
        [System.Boolean]$SecurityOptionUserAccountControlBehaviorOfTheElevationPromptForAdmins = $true,
        [System.Boolean]$SecurityOptionDomainMemberDisableMachineAccountPasswordChanges = $true,
        [System.Boolean]$SecurityOptionInteractiveLogonMessageTextForUsers = $true,
        [System.Boolean]$SecurityOptionSystemCryptographyUseFIPSCompliantAlgorithms = $true,
        [System.Boolean]$SecurityOptionDomainMemberDigitallyEncryptOrSignSecureChannelDataAlways = $true,
        [System.Boolean]$SecurityOptionNetworkSecurityAllowPKU2UAuthenticationRequests = $true,
        [System.Boolean]$SecurityOptionUserAccountControlDetectApplicationInstallations = $true,
        [System.Boolean]$SecurityOptionSystemObjectsStrengthenDefaultPermissions = $true,
        [System.Boolean]$SecurityOptionNetworkSecurityLDAPClientSigningRequirements = $true,
        [System.Boolean]$SecurityOptionInteractiveLogonNumberOfPreviousLogonsToCache = $true,
        [System.Boolean]$SecurityOptionUserAccountControlOnlyElevateUIAccessApplications = $true,
        [System.Boolean]$SecurityOptionMicrosoftNetworkClientSendUnencryptedPassword = $true,
        [System.Boolean]$SecurityOptionDomainMemberDigitallyEncryptSecureChannelDataWhenPossible = $true,
        [System.Boolean]$SecurityOptionNetworkAccessDoNotAllowAnonymousEnumeration = $true,
        [System.Boolean]$SecurityOptionMicrosoftNetworkClientDigitallySignCommunicationsAlways = $true,
        [System.Boolean]$SecurityOptionNetworkAccessDoNotAllowAnonymousEnumerationOfSAMAccounts = $true,
        [System.Boolean]$SecurityOptionUserAccountControlRunAllAdministratorsInAdminApprovalMode = $true,
        [System.Boolean]$SecurityOptionInteractiveLogonMessageTitleForUsers = $true,
        [System.Boolean]$SecurityOptionInteractiveLogonSmartCardRemovalBehavior = $true,
        [System.Boolean]$SecurityOptionNetworkSecurityLanManagerAuthenticationLevel = $true,
        [System.Boolean]$SecurityOptionAccountsLimitLocalAccountUseOfBlankPasswords = $true,
        [System.Boolean]$SecurityOptionMicrosoftNetworkServerDigitallySignCommunicationsIfClientAgrees = $true,
        [System.Boolean]$SecurityOptionUserAccountControlAllowUIAccessApplications = $true,
        [System.Boolean]$SecurityOptionDomainMemberDigitallySignSecureChannelData = $true,
        [System.Boolean]$SecurityOptionMicrosoftNetworkClientDigitallySignCommunicationsIfServerAgrees = $true,
        [System.Boolean]$SecurityOptionDomainMemberRequireStrongWindows2000SessionKey = $true,
        [System.Boolean]$SecurityOptionNetworkAccessRestrictAnonymousAccessToNamedPipes = $true,
        [System.Boolean]$UserRightsAssignmentCreateGlobalObjects = $true,
        [System.Boolean]$UserRightsAssignmentCreateAPagefile = $true,
        [System.Boolean]$UserRightsAssignmentAllowLogOnLocally = $true,
        [System.Boolean]$UserRightsAssignmentLockPagesInMemory = $true,
        [System.Boolean]$UserRightsAssignmentDenyLogOnLocally = $true,
        [System.Boolean]$UserRightsAssignmentDenyLogOnAsAService = $true,
        [System.Boolean]$UserRightsAssignmentTakeOwnershipOfFiles = $true,
        [System.Boolean]$UserRightsAssignmentPerformVolumeMaintenanceTasks = $true,
        [System.Boolean]$UserRightsAssignmentCreateATokenObject = $true,
        [System.Boolean]$UserRightsAssignmentAccessCredentialManagerAsTrustedCaller = $true,
        [System.Boolean]$UserRightsAssignmentDebugPrograms = $true,
        [System.Boolean]$UserRightsAssignmentModifyFirmwareEnvironmentValues = $true,
        [System.Boolean]$UserRightsAssignmentLoadAndUnloadDeviceDrivers = $true,
        [System.Boolean]$UserRightsAssignmentDenyAccessToThisComputerFromTheNetwork = $true,
        [System.Boolean]$UserRightsAssignmentAccessThisComputerFromTheNetwork = $true,
        [System.Boolean]$UserRightsAssignmentRestoreFilesAndDirectories = $true,
        [System.Boolean]$UserRightsAssignmentIncreaseSchedulingPriority = $true,
        [System.Boolean]$UserRightsAssignmentEnableAccountsToBeTrustedForDelegation = $true,
        [System.Boolean]$UserRightsAssignmentBackUpFilesAndDirectories = $true,
        [System.Boolean]$UserRightsAssignmentGenerateSecurityAudits = $true,
        [System.Boolean]$UserRightsAssignmentProfileSingleProcess = $true,
        [System.Boolean]$UserRightsAssignmentDenyLogOnAsABatchJob = $true,
        [System.Boolean]$UserRightsAssignmentActAsPartOfTheOperatingSystem = $true,
        [System.Boolean]$UserRightsAssignmentForceShutdownFromARemoteSystem = $true,
        [System.Boolean]$UserRightsAssignmentImpersonateAClientAfterAuthentication = $true,
        [System.Boolean]$UserRightsAssignmentDenyLogOnThroughRemoteDesktopServices = $true,
        [System.Boolean]$UserRightsAssignmentCreatePermanentSharedObjects = $true,
        [System.Boolean]$UserRightsAssignmentManageAuditingAndSecurityLog = $true,
        [System.Boolean]$UserRightsAssignmentCreateSymbolicLinks = $true,
        [System.Boolean]$SecurityOptionDomainControllerRefuseMachineAccountPasswordChanges = $true,
        [System.Boolean]$SecurityOptionDomainControllerLDAPServerSigningRequirements = $true,
        [System.Boolean]$UserRightsAssignmentAddWorkstationsToDomain = $true,
        [System.Boolean]$UserRightsAssignmentAllowLogOnThroughRemoteDesktopServices = $true,
        [System.String]$EnterpriseAdmins,
        [System.String]$DomainAdmins
    )

    Import-DSCResource -ModuleName 'GPRegistryPolicyDsc'
	Import-DSCResource -ModuleName 'AuditPolicyDSC'
	Import-DSCResource -ModuleName 'SecurityPolicyDSC'

    if($WindowsCredUIEnumerateAdministrators){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\CredUI\EnumerateAdministrators'
        {
            Key = 'Software\Microsoft\Windows\CurrentVersion\Policies\CredUI'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'EnumerateAdministrators'
        }
    }
    
    if($WindowsExplorerNoAutorun){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoAutorun'
        {
            Key = 'Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'NoAutorun'
        }
    }
    
    if($WindowsExplorerNoDriveTypeAutoRun){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoDriveTypeAutoRun'
        {
            Key = 'Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 255
            ValueName = 'NoDriveTypeAutoRun'
        }
    }
    
    if($LAPSPasswordComplexity){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\LAPS\PasswordComplexity'
        {
            Key = 'Software\Microsoft\Windows\CurrentVersion\Policies\LAPS'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 4
            ValueName = 'PasswordComplexity'
        }
    }
    
    if($LAPSPasswordLength){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\LAPS\PasswordLength'
        {
            Key = 'Software\Microsoft\Windows\CurrentVersion\Policies\LAPS'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 14
            ValueName = 'PasswordLength'
        }
    }
    
    if($LAPSPasswordAgeDays){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\LAPS\PasswordAgeDays'
        {
            Key = 'Software\Microsoft\Windows\CurrentVersion\Policies\LAPS'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 60
            ValueName = 'PasswordAgeDays'
        }
    }
    
    if($WindowsSystemDisableAutomaticRestartSignOn){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\DisableAutomaticRestartSignOn'
        {
            Key = 'Software\Microsoft\Windows\CurrentVersion\Policies\System'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'DisableAutomaticRestartSignOn'
        }
    }
    
    if($WindowsSystemLocalAccountTokenFilterPolicy){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\LocalAccountTokenFilterPolicy'
        {
            Key = 'Software\Microsoft\Windows\CurrentVersion\Policies\System'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'LocalAccountTokenFilterPolicy'
        }
    }
    
    if($WindowsSystemProcessCreationIncludeCmdLineEnabled){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit\ProcessCreationIncludeCmdLine_Enabled'
        {
            Key = 'Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'ProcessCreationIncludeCmdLine_Enabled'
        }
    }
    
    if($InternetExplorerFeedsDisableEnclosureDownload){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Feeds\DisableEnclosureDownload'
        {
            Key = 'Software\Policies\Microsoft\Internet Explorer\Feeds'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'DisableEnclosureDownload'
        }
    }
    
    if($PowerDCSettingIndex){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\DCSettingIndex'
        {
            Key = 'Software\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'DCSettingIndex'
        }
    }
    
    if($PowerACSettingIndex){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\ACSettingIndex'
        {
            Key = 'Software\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'ACSettingIndex'
        }
    }
    
    if($WindowsAppCompatDisableInventory){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\AppCompat\DisableInventory'
        {
            Key = 'Software\Policies\Microsoft\Windows\AppCompat'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'DisableInventory'
        }
    }
    
    if($WindowsCredentialsDelegationAllowProtectedCreds){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CredentialsDelegation\AllowProtectedCreds'
        {
            Key = 'Software\Policies\Microsoft\Windows\CredentialsDelegation'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'AllowProtectedCreds'
        }
    }
    
    if($WindowsDataCollectionAllowTelemetry){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\DataCollection\AllowTelemetry'
        {
            Key = 'Software\Policies\Microsoft\Windows\DataCollection'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'AllowTelemetry'
        }
    }
    if($WindowsDeliveryOptimizationDownloadMode){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\DeliveryOptimization\DODownloadMode'
        {
            Key = 'Software\Policies\Microsoft\Windows\DeliveryOptimization'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 2
            ValueName = 'DODownloadMode'
        }
    }
    
    if($DeviceGuardEnableVirtualizationBasedSecurity){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\DeviceGuard\EnableVirtualizationBasedSecurity'
        {
            Key = 'Software\Policies\Microsoft\Windows\DeviceGuard'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'EnableVirtualizationBasedSecurity'
        }
    }
    
    if($DeviceGuardRequirePlatformSecurityFeatures){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\DeviceGuard\RequirePlatformSecurityFeatures'
        {
            Key = 'Software\Policies\Microsoft\Windows\DeviceGuard'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'RequirePlatformSecurityFeatures'
        }
    }
    
    if($DeviceGuardHypervisorEnforcedCodeIntegrity){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\DeviceGuard\HypervisorEnforcedCodeIntegrity'
        {
            Key = 'Software\Policies\Microsoft\Windows\DeviceGuard'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 3
            ValueName = 'HypervisorEnforcedCodeIntegrity'
        }
    }
    
    if($DeviceGuardHVCIMATRequired){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\DeviceGuard\HVCIMATRequired'
        {
            Key = 'Software\Policies\Microsoft\Windows\DeviceGuard'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'HVCIMATRequired'
        }
    }
    
    if($DeviceGuardLsaCfgFlags){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\DeviceGuard\LsaCfgFlags'
        {
            Key = 'Software\Policies\Microsoft\Windows\DeviceGuard'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'LsaCfgFlags'
        }
    }
    
    if($DeviceGuardConfigureSystemGuardLaunch){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\DeviceGuard\ConfigureSystemGuardLaunch'
        {
            Key = 'Software\Policies\Microsoft\Windows\DeviceGuard'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'ConfigureSystemGuardLaunch'
        }
    }
    
    if($EventLogApplicationMaxSize){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\EventLog\Application\MaxSize'
        {
            Key = 'Software\Policies\Microsoft\Windows\EventLog\Application'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 32768
            ValueName = 'MaxSize'
        }
    }
    
    if($EventLogSecurityMaxSize){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\EventLog\Security\MaxSize'
        {
            Key = 'Software\Policies\Microsoft\Windows\EventLog\Security'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 196608
            ValueName = 'MaxSize'
        }
    }
    
    if($EventLogSystemMaxSize){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\EventLog\System\MaxSize'
        {
            Key = 'Software\Policies\Microsoft\Windows\EventLog\System'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 32768
            ValueName = 'MaxSize'
        }
    }
    
    if($ExplorerNoAutoplayForNonVolume){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\Explorer\NoAutoplayfornonVolume'
        {
            Key = 'Software\Policies\Microsoft\Windows\Explorer'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'NoAutoplayfornonVolume'
        }
    }
    
    if($GroupPolicyNoBackgroundPolicy){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}\NoBackgroundPolicy'
        {
            Key = 'Software\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'NoBackgroundPolicy'
        }
    }
    
    if($GroupPolicyNoGPOListChanges){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}\NoGPOListChanges'
        {
            Key = 'Software\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'NoGPOListChanges'
        }
    }
    
    if($InstallerEnableUserControl){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\Installer\EnableUserControl'
        {
            Key = 'Software\Policies\Microsoft\Windows\Installer'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'EnableUserControl'
        }
    }
    
    if($InstallerAlwaysInstallElevated){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated'
        {
            Key = 'Software\Policies\Microsoft\Windows\Installer'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'AlwaysInstallElevated'
        }
    }
    
    if($LanmanWorkstationAllowInsecureGuestAuth){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\LanmanWorkstation\AllowInsecureGuestAuth'
        {
            Key = 'Software\Policies\Microsoft\Windows\LanmanWorkstation'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'AllowInsecureGuestAuth'
        }
    }
    if($NetworkProviderHardenedPathsNETLOGON){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths\*\NETLOGON'
        {
            Key = 'Software\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths'
            TargetType = 'ComputerConfiguration'
            ValueType = 'String'
            ValueData = 'RequireMutualAuthentication=1,RequireIntegrity=1'
            ValueName = '\\*\NETLOGON'
        }
    }
    
    if($NetworkProviderHardenedPathsSYSVOL){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths\*\SYSVOL'
        {
            Key = 'Software\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths'
            TargetType = 'ComputerConfiguration'
            ValueType = 'String'
            ValueData = 'RequireMutualAuthentication=1,RequireIntegrity=1'
            ValueName = '\\*\SYSVOL'
        }
    }
    
    if($PersonalizationNoLockScreenSlideshow){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\Personalization\NoLockScreenSlideshow'
        {
            Key = 'Software\Policies\Microsoft\Windows\Personalization'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'NoLockScreenSlideshow'
        }
    }
    
    if($PowerShellEnableScriptBlockLogging){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\EnableScriptBlockLogging'
        {
            Key = 'Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'EnableScriptBlockLogging'
        }
    }
    
    if($PowerShellEnableScriptBlockInvocationLogging){
        RegistryPolicyFile 'DEL_\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\EnableScriptBlockInvocationLogging'
        {
            Key = 'Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
            TargetType = 'ComputerConfiguration'
            ValueType = 'String'
            ValueData = ''
            ValueName = 'EnableScriptBlockInvocationLogging'
            Ensure = 'Absent'
        }
    }
    
    if($PowerShellEnableTranscripting){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription\EnableTranscripting'
        {
            Key = 'Software\Policies\Microsoft\Windows\PowerShell\Transcription'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'EnableTranscripting'
        }
    }
    
    if($PowerShellOutputDirectory){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription\OutputDirectory'
        {
            Key = 'Software\Policies\Microsoft\Windows\PowerShell\Transcription'
            TargetType = 'ComputerConfiguration'
            ValueType = 'String'
            ValueData = 'C:\ProgramData\PS_Transcript'
            ValueName = 'OutputDirectory'
        }
    }
    
    if($PowerShellEnableInvocationHeader){
        RegistryPolicyFile 'DEL_\Software\Policies\Microsoft\Windows\PowerShell\Transcription\EnableInvocationHeader'
        {
            Key = 'Software\Policies\Microsoft\Windows\PowerShell\Transcription'
            TargetType = 'ComputerConfiguration'
            ValueType = 'String'
            ValueData = ''
            ValueName = 'EnableInvocationHeader'
            Ensure = 'Absent'
        }
    }
    
    if($SystemDontDisplayNetworkSelectionUI){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\System\DontDisplayNetworkSelectionUI'
        {
            Key = 'Software\Policies\Microsoft\Windows\System'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'DontDisplayNetworkSelectionUI'
        }
    }
    
    if($SystemEnumerateLocalUsers){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\System\EnumerateLocalUsers'
        {
            Key = 'Software\Policies\Microsoft\Windows\System'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'EnumerateLocalUsers'
        }
    }
    
    if($SystemEnableSmartScreen){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\System\EnableSmartScreen'
        {
            Key = 'Software\Policies\Microsoft\Windows\System'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'EnableSmartScreen'
        }
    }
    
    if($WindowsSearchAllowIndexingEncryptedStoresOrItems){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\Windows Search\AllowIndexingEncryptedStoresOrItems'
        {
            Key = 'Software\Policies\Microsoft\Windows\Windows Search'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'AllowIndexingEncryptedStoresOrItems'
        }
    }
    
    if($WinRMClientAllowBasic){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WinRM\Client\AllowBasic'
        {
            Key = 'Software\Policies\Microsoft\Windows\WinRM\Client'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'AllowBasic'
        }
    }
    
    if($WinRMClientAllowUnencryptedTraffic){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WinRM\Client\AllowUnencryptedTraffic'
        {
            Key = 'Software\Policies\Microsoft\Windows\WinRM\Client'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'AllowUnencryptedTraffic'
        }
    }
    
    if($WinRMClientAllowDigest){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WinRM\Client\AllowDigest'
        {
            Key = 'Software\Policies\Microsoft\Windows\WinRM\Client'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'AllowDigest'
        }
    }
    
    if($WinRMServiceAllowBasic){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service\AllowBasic'
        {
            Key = 'Software\Policies\Microsoft\Windows\WinRM\Service'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'AllowBasic'
        }
    }
    
    if($WinRMServiceAllowUnencryptedTraffic){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service\AllowUnencryptedTraffic'
        {
            Key = 'Software\Policies\Microsoft\Windows\WinRM\Service'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'AllowUnencryptedTraffic'
        }
    }
    if($WinRMServiceDisableRunAs){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service\DisableRunAs'
        {
            Key = 'Software\Policies\Microsoft\Windows\WinRM\Service'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'DisableRunAs'
        }
    }
    
    if($PrintersDisableWebPnPDownload){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows NT\Printers\DisableWebPnPDownload'
        {
            Key = 'Software\Policies\Microsoft\Windows NT\Printers'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'DisableWebPnPDownload'
        }
    }
    
    if($PrintersDisableHTTPPrinting){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows NT\Printers\DisableHTTPPrinting'
        {
            Key = 'Software\Policies\Microsoft\Windows NT\Printers'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'DisableHTTPPrinting'
        }
    }
    
    if($RpcRestrictRemoteClients){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows NT\Rpc\RestrictRemoteClients'
        {
            Key = 'Software\Policies\Microsoft\Windows NT\Rpc'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'RestrictRemoteClients'
        }
    }
    
    if($TerminalServicesDisablePasswordSaving){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\DisablePasswordSaving'
        {
            Key = 'Software\Policies\Microsoft\Windows NT\Terminal Services'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'DisablePasswordSaving'
        }
    }
    
    if($TerminalServicesDisableCdm){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\fDisableCdm'
        {
            Key = 'Software\Policies\Microsoft\Windows NT\Terminal Services'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'fDisableCdm'
        }
    }
    
    if($TerminalServicesPromptForPassword){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\fPromptForPassword'
        {
            Key = 'Software\Policies\Microsoft\Windows NT\Terminal Services'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'fPromptForPassword'
        }
    }
    
    if($TerminalServicesEncryptRPCTraffic){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\fEncryptRPCTraffic'
        {
            Key = 'Software\Policies\Microsoft\Windows NT\Terminal Services'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'fEncryptRPCTraffic'
        }
    }
    
    if($TerminalServicesMinEncryptionLevel){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\MinEncryptionLevel'
        {
            Key = 'Software\Policies\Microsoft\Windows NT\Terminal Services'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 3
            ValueName = 'MinEncryptionLevel'
        }
    }
    
    if($WDigestUseLogonCredential){
        RegistryPolicyFile 'Registry(POL): HKLM:\System\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential'
        {
            Key = 'System\CurrentControlSet\Control\SecurityProviders\WDigest'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'UseLogonCredential'
        }
    }
    
    if($LanmanServerSMB1){
        RegistryPolicyFile 'Registry(POL): HKLM:\System\CurrentControlSet\Services\LanmanServer\Parameters\SMB1'
        {
            Key = 'System\CurrentControlSet\Services\LanmanServer\Parameters'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'SMB1'
        }
    }
    
    if($MrxSmb10Start){
        RegistryPolicyFile 'Registry(POL): HKLM:\System\CurrentControlSet\Services\MrxSmb10\Start'
        {
            Key = 'System\CurrentControlSet\Services\MrxSmb10'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 4
            ValueName = 'Start'
        }
    }
    
    if($NetbtNoNameReleaseOnDemand){
        RegistryPolicyFile 'Registry(POL): HKLM:\System\CurrentControlSet\Services\Netbt\Parameters\NoNameReleaseOnDemand'
        {
            Key = 'System\CurrentControlSet\Services\Netbt\Parameters'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'NoNameReleaseOnDemand'
        }
    }
    
    if($TcpipDisableIPSourceRouting){
        RegistryPolicyFile 'Registry(POL): HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters\DisableIPSourceRouting'
        {
            Key = 'System\CurrentControlSet\Services\Tcpip\Parameters'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 2
            ValueName = 'DisableIPSourceRouting'
        }
    }
    
    if($TcpipEnableICMPRedirect){
        RegistryPolicyFile 'Registry(POL): HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters\EnableICMPRedirect'
        {
            Key = 'System\CurrentControlSet\Services\Tcpip\Parameters'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'EnableICMPRedirect'
        }
    }
    
    if($Tcpip6DisableIPSourceRouting){
        RegistryPolicyFile 'Registry(POL): HKLM:\System\CurrentControlSet\Services\Tcpip6\Parameters\DisableIPSourceRouting'
        {
            Key = 'System\CurrentControlSet\Services\Tcpip6\Parameters'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 2
            ValueName = 'DisableIPSourceRouting'
        }
    }
    if($AuditCredentialValidationSuccess) {
        AuditPolicySubcategory 'Audit Credential Validation (Success) - Inclusion'
        {
            Name = 'Credential Validation'
            Ensure = 'Present'
            AuditFlag = 'Success'
        }
    }
    
    if($AuditCredentialValidationFailure) {
        AuditPolicySubcategory 'Audit Credential Validation (Failure) - Inclusion'
        {
            Name = 'Credential Validation'
            Ensure = 'Present'
            AuditFlag = 'Failure'
        }
    }
    
    if($AuditOtherAccountManagementEventsSuccess) {
        AuditPolicySubcategory 'Audit Other Account Management Events (Success) - Inclusion'
        {
            Name = 'Other Account Management Events'
            Ensure = 'Present'
            AuditFlag = 'Success'
        }
    }
    
    if($AuditOtherAccountManagementEventsFailure) {
        AuditPolicySubcategory 'Audit Other Account Management Events (Failure) - Inclusion'
        {
            Name = 'Other Account Management Events'
            Ensure = 'Absent'
            AuditFlag = 'Failure'
        }
    }
    
    if($AuditSecurityGroupManagementSuccess) {
        AuditPolicySubcategory 'Audit Security Group Management (Success) - Inclusion'
        {
            Name = 'Security Group Management'
            Ensure = 'Present'
            AuditFlag = 'Success'
        }
    }
    
    if($AuditSecurityGroupManagementFailure) {
        AuditPolicySubcategory 'Audit Security Group Management (Failure) - Inclusion'
        {
            Name = 'Security Group Management'
            Ensure = 'Absent'
            AuditFlag = 'Failure'
        }
    }
    
    if($AuditUserAccountManagementSuccess) {
        AuditPolicySubcategory 'Audit User Account Management (Success) - Inclusion'
        {
            Name = 'User Account Management'
            Ensure = 'Present'
            AuditFlag = 'Success'
        }
    }
    
    if($AuditUserAccountManagementFailure) {
        AuditPolicySubcategory 'Audit User Account Management (Failure) - Inclusion'
        {
            Name = 'User Account Management'
            Ensure = 'Present'
            AuditFlag = 'Failure'
        }
    }
    
    if($AuditPnpActivitySuccess) {
        AuditPolicySubcategory 'Audit PNP Activity (Success) - Inclusion'
        {
            Name = 'Plug and Play Events'
            Ensure = 'Present'
            AuditFlag = 'Success'
        }
    }
    
    if($AuditPnpActivityFailure) {
        AuditPolicySubcategory 'Audit PNP Activity (Failure) - Inclusion'
        {
            Name = 'Plug and Play Events'
            Ensure = 'Absent'
            AuditFlag = 'Failure'
        }
    }
    
    if($AuditProcessCreationSuccess) {
        AuditPolicySubcategory 'Audit Process Creation (Success) - Inclusion'
        {
            Name = 'Process Creation'
            Ensure = 'Present'
            AuditFlag = 'Success'
        }
    }
    
    if($AuditProcessCreationFailure) {
        AuditPolicySubcategory 'Audit Process Creation (Failure) - Inclusion'
        {
            Name = 'Process Creation'
            Ensure = 'Absent'
            AuditFlag = 'Failure'
        }
    }
    
    if($AuditAccountLockoutFailure) {
        AuditPolicySubcategory 'Audit Account Lockout (Failure) - Inclusion'
        {
            Name = 'Account Lockout'
            Ensure = 'Present'
            AuditFlag = 'Failure'
        }
    }
    
    if($AuditAccountLockoutSuccess) {
        AuditPolicySubcategory 'Audit Account Lockout (Success) - Inclusion'
        {
            Name = 'Account Lockout'
            Ensure = 'Absent'
            AuditFlag = 'Success'
        }
    }
    
    if($AuditGroupMembershipSuccess) {
        AuditPolicySubcategory 'Audit Group Membership (Success) - Inclusion'
        {
            Name = 'Group Membership'
            Ensure = 'Present'
            AuditFlag = 'Success'
        }
    }
    
    if($AuditGroupMembershipFailure) {
        AuditPolicySubcategory 'Audit Group Membership (Failure) - Inclusion'
        {
            Name = 'Group Membership'
            Ensure = 'Absent'
            AuditFlag = 'Failure'
        }
    }
    
    if($AuditLogoffSuccess) {
        AuditPolicySubcategory 'Audit Logoff (Success) - Inclusion'
        {
            Name = 'Logoff'
            Ensure = 'Present'
            AuditFlag = 'Success'
        }
    }
    
    if($AuditLogoffFailure) {
        AuditPolicySubcategory 'Audit Logoff (Failure) - Inclusion'
        {
            Name = 'Logoff'
            Ensure = 'Absent'
            AuditFlag = 'Failure'
        }
    }
    
    if($AuditLogonSuccess) {
        AuditPolicySubcategory 'Audit Logon (Success) - Inclusion'
        {
            Name = 'Logon'
            Ensure = 'Present'
            AuditFlag = 'Success'
        }
    }
    
    if($AuditLogonFailure) {
        AuditPolicySubcategory 'Audit Logon (Failure) - Inclusion'
        {
            Name = 'Logon'
            Ensure = 'Present'
            AuditFlag = 'Failure'
        }
    }
    
    if($AuditSpecialLogonSuccess) {
        AuditPolicySubcategory 'Audit Special Logon (Success) - Inclusion'
        {
            Name = 'Special Logon'
            Ensure = 'Present'
            AuditFlag = 'Success'
        }
    }
    
    if($AuditSpecialLogonFailure) {
        AuditPolicySubcategory 'Audit Special Logon (Failure) - Inclusion'
        {
            Name = 'Special Logon'
            Ensure = 'Absent'
            AuditFlag = 'Failure'
        }
    }
    
    if($AuditOtherObjectAccessEventsSuccess) {
        AuditPolicySubcategory 'Audit Other Object Access Events (Success) - Inclusion'
        {
            Name = 'Other Object Access Events'
            Ensure = 'Present'
            AuditFlag = 'Success'
        }
    }
    
    if($AuditOtherObjectAccessEventsFailure) {
        AuditPolicySubcategory 'Audit Other Object Access Events (Failure) - Inclusion'
        {
            Name = 'Other Object Access Events'
            Ensure = 'Present'
            AuditFlag = 'Failure'
        }
    }
    
    if($AuditRemovableStorageSuccess) {
        AuditPolicySubcategory 'Audit Removable Storage (Success) - Inclusion'
        {
            Name = 'Removable Storage'
            Ensure = 'Present'
            AuditFlag = 'Success'
        }
    }
    if($AuditRemovableStorageFailure) {
        AuditPolicySubcategory 'Audit Removable Storage (Failure) - Inclusion'
        {
            Name = 'Removable Storage'
            Ensure = 'Present'
            AuditFlag = 'Failure'
        }
    }
    
    if($AuditAuditPolicyChangeSuccess) {
        AuditPolicySubcategory 'Audit Audit Policy Change (Success) - Inclusion'
        {
            Name = 'Audit Policy Change'
            Ensure = 'Present'
            AuditFlag = 'Success'
        }
    }
    
    if($AuditAuditPolicyChangeFailure) {
        AuditPolicySubcategory 'Audit Audit Policy Change (Failure) - Inclusion'
        {
            Name = 'Audit Policy Change'
            Ensure = 'Present'
            AuditFlag = 'Failure'
        }
    }
    
    if($AuditAuthenticationPolicyChangeSuccess) {
        AuditPolicySubcategory 'Audit Authentication Policy Change (Success) - Inclusion'
        {
            Name = 'Authentication Policy Change'
            Ensure = 'Present'
            AuditFlag = 'Success'
        }
    }
    
    if($AuditAuthenticationPolicyChangeFailure) {
        AuditPolicySubcategory 'Audit Authentication Policy Change (Failure) - Inclusion'
        {
            Name = 'Authentication Policy Change'
            Ensure = 'Absent'
            AuditFlag = 'Failure'
        }
    }
    
    if($AuditAuthorizationPolicyChangeSuccess) {
        AuditPolicySubcategory 'Audit Authorization Policy Change (Success) - Inclusion'
        {
            Name = 'Authorization Policy Change'
            Ensure = 'Present'
            AuditFlag = 'Success'
        }
    }
    
    if($AuditAuthorizationPolicyChangeFailure) {
        AuditPolicySubcategory 'Audit Authorization Policy Change (Failure) - Inclusion'
        {
            Name = 'Authorization Policy Change'
            Ensure = 'Absent'
            AuditFlag = 'Failure'
        }
    }
    
    if($AuditSensitivePrivilegeUseSuccess) {
        AuditPolicySubcategory 'Audit Sensitive Privilege Use (Success) - Inclusion'
        {
            Name = 'Sensitive Privilege Use'
            Ensure = 'Present'
            AuditFlag = 'Success'
        }
    }
    
    if($AuditSensitivePrivilegeUseFailure) {
        AuditPolicySubcategory 'Audit Sensitive Privilege Use (Failure) - Inclusion'
        {
            Name = 'Sensitive Privilege Use'
            Ensure = 'Present'
            AuditFlag = 'Failure'
        }
    }
    
    if($AuditIPsecDriverSuccess) {
        AuditPolicySubcategory 'Audit IPsec Driver (Success) - Inclusion'
        {
            Name = 'IPsec Driver'
            Ensure = 'Present'
            AuditFlag = 'Success'
        }
    }
    
    if($AuditIPsecDriverFailure) {
        AuditPolicySubcategory 'Audit IPsec Driver (Failure) - Inclusion'
        {
            Name = 'IPsec Driver'
            Ensure = 'Present'
            AuditFlag = 'Failure'
        }
    }
    
    if($AuditOtherSystemEventsSuccess) {
        AuditPolicySubcategory 'Audit Other System Events (Success) - Inclusion'
        {
            Name = 'Other System Events'
            Ensure = 'Present'
            AuditFlag = 'Success'
        }
    }
    
    if($AuditOtherSystemEventsFailure) {
        AuditPolicySubcategory 'Audit Other System Events (Failure) - Inclusion'
        {
            Name = 'Other System Events'
            Ensure = 'Present'
            AuditFlag = 'Failure'
        }
    }
    
    if($AuditSecurityStateChangeSuccess) {
        AuditPolicySubcategory 'Audit Security State Change (Success) - Inclusion'
        {
            Name = 'Security State Change'
            Ensure = 'Present'
            AuditFlag = 'Success'
        }
    }
    
    if($AuditSecurityStateChangeFailure) {
        AuditPolicySubcategory 'Audit Security State Change (Failure) - Inclusion'
        {
            Name = 'Security State Change'
            Ensure = 'Absent'
            AuditFlag = 'Failure'
        }
    }
    
    if($AuditSecuritySystemExtensionSuccess) {
        AuditPolicySubcategory 'Audit Security System Extension (Success) - Inclusion'
        {
            Name = 'Security System Extension'
            Ensure = 'Present'
            AuditFlag = 'Success'
        }
    }
    
    if($AuditSecuritySystemExtensionFailure) {
        AuditPolicySubcategory 'Audit Security System Extension (Failure) - Inclusion'
        {
            Name = 'Security System Extension'
            Ensure = 'Absent'
            AuditFlag = 'Failure'
        }
    }
    
    if($AuditSystemIntegritySuccess) {
        AuditPolicySubcategory 'Audit System Integrity (Success) - Inclusion'
        {
            Name = 'System Integrity'
            Ensure = 'Present'
            AuditFlag = 'Success'
        }
    }
    
    if($AuditSystemIntegrityFailure) {
        AuditPolicySubcategory 'Audit System Integrity (Failure) - Inclusion'
        {
            Name = 'System Integrity'
            Ensure = 'Present'
            AuditFlag = 'Failure'
        }
    }
    if($AuditComputerAccountManagementSuccess) {
        AuditPolicySubcategory 'Audit Computer Account Management (Success) - Inclusion'
        {
            Name = 'Computer Account Management'
            Ensure = 'Present'
            AuditFlag = 'Success'
        }
    }
    
    if($AuditComputerAccountManagementFailure) {
        AuditPolicySubcategory 'Audit Computer Account Management (Failure) - Inclusion'
        {
            Name = 'Computer Account Management'
            Ensure = 'Absent'
            AuditFlag = 'Failure'
        }
    }
    
    if($AuditDirectoryServiceAccessSuccess) {
        AuditPolicySubcategory 'Audit Directory Service Access (Success) - Inclusion'
        {
            Name = 'Directory Service Access'
            Ensure = 'Present'
            AuditFlag = 'Success'
        }
    }
    
    if($AuditDirectoryServiceAccessFailure) {
        AuditPolicySubcategory 'Audit Directory Service Access (Failure) - Inclusion'
        {
            Name = 'Directory Service Access'
            Ensure = 'Present'
            AuditFlag = 'Failure'
        }
    }
    
    if($AuditDirectoryServiceChangesSuccess) {
        AuditPolicySubcategory 'Audit Directory Service Changes (Success) - Inclusion'
        {
            Name = 'Directory Service Changes'
            Ensure = 'Present'
            AuditFlag = 'Success'
        }
    }
    
    if($AuditDirectoryServiceChangesFailure) {
        AuditPolicySubcategory 'Audit Directory Service Changes (Failure) - Inclusion'
        {
            Name = 'Directory Service Changes'
            Ensure = 'Absent'
            AuditFlag = 'Failure'
        }
    }
    
    if($AccountPolicyResetLockoutCount) {
        AccountPolicy 'SecuritySetting(INF): ResetLockoutCount'
        {
            Name = 'Reset_account_lockout_counter_after'
            Reset_account_lockout_counter_after = 15
        }
    }
    
    if($SecurityOptionLSAAnonymousNameLookup) {
        SecurityOption 'SecuritySetting(INF): LSAAnonymousNameLookup'
        {
            Network_access_Allow_anonymous_SID_Name_translation = 'Disabled'
            Name = 'Network_access_Allow_anonymous_SID_Name_translation'
        }
    }
    
    if($AccountPolicyLockoutDuration) {
        AccountPolicy 'SecuritySetting(INF): LockoutDuration'
        {
            Account_lockout_duration = 15
            Name = 'Account_lockout_duration'
        }
    }
    
    if($SecurityOptionNewAdministratorName) {
        SecurityOption 'SecuritySetting(INF): NewAdministratorName'
        {
            Name = 'Accounts_Rename_administrator_account'
            Accounts_Rename_administrator_account = 'X_Admin'
        }
    }
    
    if($AccountPolicyPasswordHistorySize) {
        AccountPolicy 'SecuritySetting(INF): PasswordHistorySize'
        {
            Name = 'Enforce_password_history'
            Enforce_password_history = 24
        }
    }
    
    if($AccountPolicyMinimumPasswordLength) {
        AccountPolicy 'SecuritySetting(INF): MinimumPasswordLength'
        {
            Minimum_Password_Length = 14
            Name = 'Minimum_Password_Length'
        }
    }
    
    if($AccountPolicyMinimumPasswordAge) {
        AccountPolicy 'SecuritySetting(INF): MinimumPasswordAge'
        {
            Minimum_Password_Age = 1
            Name = 'Minimum_Password_Age'
        }
    }
    
    if($AccountPolicyClearTextPassword) {
        AccountPolicy 'SecuritySetting(INF): ClearTextPassword'
        {
            Store_passwords_using_reversible_encryption = 'Disabled'
            Name = 'Store_passwords_using_reversible_encryption'
        }
    }
    
    if($SecurityOptionNewGuestName) {
        SecurityOption 'SecuritySetting(INF): NewGuestName'
        {
            Accounts_Rename_guest_account = 'Visitor'
            Name = 'Accounts_Rename_guest_account'
        }
    }
    
    if($SecurityOptionEnableGuestAccount) {
        SecurityOption 'SecuritySetting(INF): EnableGuestAccount'
        {
            Accounts_Guest_account_status = 'Disabled'
            Name = 'Accounts_Guest_account_status'
        }
    }
    
    if($AccountPolicyLockoutBadCount) {
        AccountPolicy 'SecuritySetting(INF): LockoutBadCount'
        {
            Account_lockout_threshold = 3
            Name = 'Account_lockout_threshold'
        }
    }
    
    if($AccountPolicyPasswordComplexity) {
        AccountPolicy 'SecuritySetting(INF): PasswordComplexity'
        {
            Password_must_meet_complexity_requirements = 'Enabled'
            Name = 'Password_must_meet_complexity_requirements'
        }
    }
    
    if($AccountPolicyMaximumPasswordAge) {
        AccountPolicy 'SecuritySetting(INF): MaximumPasswordAge'
        {
            Maximum_Password_Age = 60
            Name = 'Maximum_Password_Age'
        }
    }
    
    if($SecurityRegistryNetworkSecurityDoNotStoreLanManagerHash) {
        SecurityOption 'SecurityRegistry(INF): Network_security_Do_not_store_LAN_Manager_hash_value_on_next_password_change'
        {
            Name = 'Network_security_Do_not_store_LAN_Manager_hash_value_on_next_password_change'
            Network_security_Do_not_store_LAN_Manager_hash_value_on_next_password_change = 'Enabled'
        }
    }
    
    if($SecurityRegistryUserAccountControlBehaviorOfTheElevationPrompt) {
        SecurityOption 'SecurityRegistry(INF): User_Account_Control_Behavior_of_the_elevation_prompt_for_standard_users'
        {
            Name = 'User_Account_Control_Behavior_of_the_elevation_prompt_for_standard_users'
            User_Account_Control_Behavior_of_the_elevation_prompt_for_standard_users = 'Automatically deny elevation request'
        }
    }
    
    if($SecurityRegistryMicrosoftNetworkServerDigitallySignCommunicationsAlways) {
        SecurityOption 'SecurityRegistry(INF): Microsoft_network_server_Digitally_sign_communications_always'
        {
            Name = 'Microsoft_network_server_Digitally_sign_communications_always'
            Microsoft_network_server_Digitally_sign_communications_always = 'Enabled'
        }
    }
    
    if($SecurityRegistryUserAccountControlAdminApprovalModeForBuiltInAdmin) {
        SecurityOption 'SecurityRegistry(INF): User_Account_Control_Admin_Approval_Mode_for_the_Built_in_Administrator_account'
        {
            Name = 'User_Account_Control_Admin_Approval_Mode_for_the_Built_in_Administrator_account'
            User_Account_Control_Admin_Approval_Mode_for_the_Built_in_Administrator_account = 'Enabled'
        }
    }
    
    if($SecurityRegistryUserAccountControlVirtualizeFileAndRegistryFailures) {
        SecurityOption 'SecurityRegistry(INF): User_Account_Control_Virtualize_file_and_registry_write_failures_to_per_user_locations'
        {
            Name = 'User_Account_Control_Virtualize_file_and_registry_write_failures_to_per_user_locations'
            User_Account_Control_Virtualize_file_and_registry_write_failures_to_per_user_locations = 'Enabled'
        }
    }
    
    if($SecurityRegistryInteractiveLogonMachineInactivityLimit) {
        SecurityOption 'SecurityRegistry(INF): Interactive_logon_Machine_inactivity_limit'
        {
            Name = 'Interactive_logon_Machine_inactivity_limit'
            Interactive_logon_Machine_inactivity_limit = '900'
        }
    }
    
    if($SecurityRegistrySystemCryptographyForceStrongKeyProtection) {
        SecurityOption 'SecurityRegistry(INF): System_cryptography_Force_strong_key_protection_for_user_keys_stored_on_the_computer'
        {
            Name = 'System_cryptography_Force_strong_key_protection_for_user_keys_stored_on_the_computer'
            System_cryptography_Force_strong_key_protection_for_user_keys_stored_on_the_computer = 'User must enter a password each time they use a key'
        }
    }
    if($SecurityOptionNetworkAccessLetEveryonePermissionsApplyToAnonymousUsers) {
        SecurityOption 'SecurityRegistry(INF): Network_access_Let_Everyone_permissions_apply_to_anonymous_users'
        {
            Name = 'Network_access_Let_Everyone_permissions_apply_to_anonymous_users'
            Network_access_Let_Everyone_permissions_apply_to_anonymous_users = 'Disabled'
        }
    }
    
    if($SecurityOptionNetworkSecurityAllowLocalSystemNullSessionFallback) {
        SecurityOption 'SecurityRegistry(INF): Network_security_Allow_LocalSystem_NULL_session_fallback'
        {
            Name = 'Network_security_Allow_LocalSystem_NULL_session_fallback'
            Network_security_Allow_LocalSystem_NULL_session_fallback = 'Disabled'
        }
    }
    
    if($SecurityOptionDomainMemberMaximumMachineAccountPasswordAge) {
        SecurityOption 'SecurityRegistry(INF): Domain_member_Maximum_machine_account_password_age'
        {
            Name = 'Domain_member_Maximum_machine_account_password_age'
            Domain_member_Maximum_machine_account_password_age = '30'
        }
    }
    
    if($SecurityOptionNetworkAccessRestrictClientsAllowedToMakeRemoteCallsToSAM) {
        SecurityOption 'SecurityRegistry(INF): Network_access_Restrict_clients_allowed_to_make_remote_calls_to_SAM'
        {
            Name = 'Network_access_Restrict_clients_allowed_to_make_remote_calls_to_SAM'
            Network_access_Restrict_clients_allowed_to_make_remote_calls_to_SAM = @(

            MSFT_RestrictedRemoteSamSecurityDescriptor
            
            {
            
            Permission = 'Allow'
            
            Identity   = 'Administrators'
            
            }
            
            )
        }
    }
    
    if($SecurityOptionNetworkSecurityMinimumSessionSecurityForNTLMSSP) {
        SecurityOption 'SecurityRegistry(INF): Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_servers'
        {
            Name = 'Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_servers'
            Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_servers = 'Both options checked'
        }
    }
    
    if($SecurityOptionNetworkSecurityAllowLocalSystemToUseComputerIdentityForNTLM) {
        SecurityOption 'SecurityRegistry(INF): Network_security_Allow_Local_System_to_use_computer_identity_for_NTLM'
        {
            Name = 'Network_security_Allow_Local_System_to_use_computer_identity_for_NTLM'
            Network_security_Allow_Local_System_to_use_computer_identity_for_NTLM = 'Enabled'
        }
    }
    
    if($SecurityOptionNetworkSecurityConfigureEncryptionTypesAllowedForKerberos) {
        SecurityOption 'SecurityRegistry(INF): Network_security_Configure_encryption_types_allowed_for_Kerberos'
        {
            Name = 'Network_security_Configure_encryption_types_allowed_for_Kerberos'
            Network_security_Configure_encryption_types_allowed_for_Kerberos = '2147483640'
        }
    }
    
    if($SecurityOptionAuditForceAuditPolicySubcategorySettings) {
        SecurityOption 'SecurityRegistry(INF): Audit_Force_audit_policy_subcategory_settings_Windows_Vista_or_later_to_override_audit_policy_category_settings'
        {
            Name = 'Audit_Force_audit_policy_subcategory_settings_Windows_Vista_or_later_to_override_audit_policy_category_settings'
            Audit_Force_audit_policy_subcategory_settings_Windows_Vista_or_later_to_override_audit_policy_category_settings = 'Enabled'
        }
    }
    
    if($SecurityOptionUserAccountControlBehaviorOfTheElevationPromptForAdmins) {
        SecurityOption 'SecurityRegistry(INF): User_Account_Control_Behavior_of_the_elevation_prompt_for_administrators_in_Admin_Approval_Mode'
        {
            Name = 'User_Account_Control_Behavior_of_the_elevation_prompt_for_administrators_in_Admin_Approval_Mode'
            User_Account_Control_Behavior_of_the_elevation_prompt_for_administrators_in_Admin_Approval_Mode = 'Prompt for consent on the secure desktop'
        }
    }
    
    if($SecurityOptionDomainMemberDisableMachineAccountPasswordChanges) {
        SecurityOption 'SecurityRegistry(INF): Domain_member_Disable_machine_account_password_changes'
        {
            Name = 'Domain_member_Disable_machine_account_password_changes'
            Domain_member_Disable_machine_account_password_changes = 'Disabled'
        }
    }
    
    if($SecurityOptionInteractiveLogonMessageTextForUsers) {
        SecurityOption 'SecurityRegistry(INF): Interactive_logon_Message_text_for_users_attempting_to_log_on'
        {
            Name = 'Interactive_logon_Message_text_for_users_attempting_to_log_on'
            Interactive_logon_Message_text_for_users_attempting_to_log_on = 'You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.,By using this IS (which includes any device attached to this IS)"," you consent to the following conditions:,-The USG routinely intercepts and monitors communications on this IS for purposes including"," but not limited to"," penetration testing"," COMSEC monitoring"," network operations and defense"," personnel misconduct (PM)"," law enforcement (LE)"," and counterintelligence (CI) investigations.,-At any time"," the USG may inspect and seize data stored on this IS.,-Communications using"," or data stored on"," this IS are not private"," are subject to routine monitoring"," interception"," and search"," and may be disclosed or used for any USG-authorized purpose.,-This IS includes security measures (e.g."," authentication and access controls) to protect USG interests--not for your personal benefit or privacy.,-Notwithstanding the above"," using this IS does not constitute consent to PM"," LE or CI investigative searching or monitoring of the content of privileged communications"," or work product"," related to personal representation or services by attorneys"," psychotherapists"," or clergy"," and their assistants. Such communications and work product are private and confidential. See User Agreement for details.'
        }
    }
    
    if($SecurityOptionSystemCryptographyUseFIPSCompliantAlgorithms) {
        SecurityOption 'SecurityRegistry(INF): System_cryptography_Use_FIPS_compliant_algorithms_for_encryption_hashing_and_signing'
        {
            Name = 'System_cryptography_Use_FIPS_compliant_algorithms_for_encryption_hashing_and_signing'
            System_cryptography_Use_FIPS_compliant_algorithms_for_encryption_hashing_and_signing = 'Enabled'
        }
    }
    
    if($SecurityOptionDomainMemberDigitallyEncryptOrSignSecureChannelDataAlways) {
        SecurityOption 'SecurityRegistry(INF): Domain_member_Digitally_encrypt_or_sign_secure_channel_data_always'
        {
            Name = 'Domain_member_Digitally_encrypt_or_sign_secure_channel_data_always'
            Domain_member_Digitally_encrypt_or_sign_secure_channel_data_always = 'Enabled'
        }
    }
    
    if($SecurityOptionNetworkSecurityAllowPKU2UAuthenticationRequests) {
        SecurityOption 'SecurityRegistry(INF): Network_Security_Allow_PKU2U_authentication_requests_to_this_computer_to_use_online_identities'
        {
            Name = 'Network_Security_Allow_PKU2U_authentication_requests_to_this_computer_to_use_online_identities'
            Network_Security_Allow_PKU2U_authentication_requests_to_this_computer_to_use_online_identities = 'Disabled'
        }
    }
    
    if($SecurityOptionUserAccountControlDetectApplicationInstallations) {
        SecurityOption 'SecurityRegistry(INF): User_Account_Control_Detect_application_installations_and_prompt_for_elevation'
        {
            Name = 'User_Account_Control_Detect_application_installations_and_prompt_for_elevation'
            User_Account_Control_Detect_application_installations_and_prompt_for_elevation = 'Enabled'
        }
    }
    
    if($SecurityOptionSystemObjectsStrengthenDefaultPermissions) {
        SecurityOption 'SecurityRegistry(INF): System_objects_Strengthen_default_permissions_of_internal_system_objects_eg_Symbolic_Links'
        {
            Name = 'System_objects_Strengthen_default_permissions_of_internal_system_objects_eg_Symbolic_Links'
            System_objects_Strengthen_default_permissions_of_internal_system_objects_eg_Symbolic_Links = 'Enabled'
        }
    }
    
    if($SecurityOptionNetworkSecurityLDAPClientSigningRequirements) {
        SecurityOption 'SecurityRegistry(INF): Network_security_LDAP_client_signing_requirements'
        {
            Name = 'Network_security_LDAP_client_signing_requirements'
            Network_security_LDAP_client_signing_requirements = 'Negotiate Signing'
        }
    }
    
    if($SecurityOptionInteractiveLogonNumberOfPreviousLogonsToCache) {
        SecurityOption 'SecurityRegistry(INF): Interactive_logon_Number_of_previous_logons_to_cache_in_case_domain_controller_is_not_available'
        {
            Name = 'Interactive_logon_Number_of_previous_logons_to_cache_in_case_domain_controller_is_not_available'
            Interactive_logon_Number_of_previous_logons_to_cache_in_case_domain_controller_is_not_available = '4'
        }
    }
    
    if($SecurityOptionUserAccountControlOnlyElevateUIAccessApplications) {
        SecurityOption 'SecurityRegistry(INF): User_Account_Control_Only_elevate_UIAccess_applications_that_are_installed_in_secure_locations'
        {
            Name = 'User_Account_Control_Only_elevate_UIAccess_applications_that_are_installed_in_secure_locations'
            User_Account_Control_Only_elevate_UIAccess_applications_that_are_installed_in_secure_locations = 'Enabled'
        }
    }
    
    if($SecurityOptionMicrosoftNetworkClientSendUnencryptedPassword) {
        SecurityOption 'SecurityRegistry(INF): Microsoft_network_client_Send_unencrypted_password_to_third_party_SMB_servers'
        {
            Name = 'Microsoft_network_client_Send_unencrypted_password_to_third_party_SMB_servers'
            Microsoft_network_client_Send_unencrypted_password_to_third_party_SMB_servers = 'Disabled'
        }
    }
    
    if($SecurityOptionDomainMemberDigitallyEncryptSecureChannelDataWhenPossible) {
        SecurityOption 'SecurityRegistry(INF): Domain_member_Digitally_encrypt_secure_channel_data_when_possible'
        {
            Name = 'Domain_member_Digitally_encrypt_secure_channel_data_when_possible'
            Domain_member_Digitally_encrypt_secure_channel_data_when_possible = 'Enabled'
        }
    }
    
    if($SecurityOptionNetworkAccessDoNotAllowAnonymousEnumeration) {
        SecurityOption 'SecurityRegistry(INF): Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts_and_shares'
        {
            Name = 'Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts_and_shares'
            Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts_and_shares = 'Enabled'
        }
    }
    if($SecurityOptionMicrosoftNetworkClientDigitallySignCommunicationsAlways) {
        SecurityOption 'SecurityRegistry(INF): Microsoft_network_client_Digitally_sign_communications_always'
        {
            Name = 'Microsoft_network_client_Digitally_sign_communications_always'
            Microsoft_network_client_Digitally_sign_communications_always = 'Enabled'
        }
    }
    
    if($SecurityOptionNetworkAccessDoNotAllowAnonymousEnumerationOfSAMAccounts) {
        SecurityOption 'SecurityRegistry(INF): Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts'
        {
            Name = 'Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts'
            Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts = 'Enabled'
        }
    }
    
    if($SecurityOptionUserAccountControlRunAllAdministratorsInAdminApprovalMode) {
        SecurityOption 'SecurityRegistry(INF): User_Account_Control_Run_all_administrators_in_Admin_Approval_Mode'
        {
            Name = 'User_Account_Control_Run_all_administrators_in_Admin_Approval_Mode'
            User_Account_Control_Run_all_administrators_in_Admin_Approval_Mode = 'Enabled'
        }
    }
    
    if($SecurityOptionNetworkSecurityMinimumSessionSecurityForNTLMSSP) {
        SecurityOption 'SecurityRegistry(INF): Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_clients'
        {
            Name = 'Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_clients'
            Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_clients = 'Both options checked'
        }
    }
    
    if($SecurityOptionInteractiveLogonMessageTitleForUsers) {
        SecurityOption 'SecurityRegistry(INF): Interactive_logon_Message_title_for_users_attempting_to_log_on'
        {
            Name = 'Interactive_logon_Message_title_for_users_attempting_to_log_on'
            Interactive_logon_Message_title_for_users_attempting_to_log_on = 'US Department of Defense Warning Statement'
        }
    }
    
    if($SecurityOptionInteractiveLogonSmartCardRemovalBehavior) {
        SecurityOption 'SecurityRegistry(INF): Interactive_logon_Smart_card_removal_behavior'
        {
            Name = 'Interactive_logon_Smart_card_removal_behavior'
            Interactive_logon_Smart_card_removal_behavior = 'Lock workstation'
        }
    }
    
    if($SecurityOptionNetworkSecurityLanManagerAuthenticationLevel) {
        SecurityOption 'SecurityRegistry(INF): Network_security_LAN_Manager_authentication_level'
        {
            Name = 'Network_security_LAN_Manager_authentication_level'
            Network_security_LAN_Manager_authentication_level = 'Send NTLMv2 responses only. Refuse LM & NTLM'
        }
    }
    
    if($SecurityOptionAccountsLimitLocalAccountUseOfBlankPasswords) {
        SecurityOption 'SecurityRegistry(INF): Accounts_Limit_local_account_use_of_blank_passwords_to_console_logon_only'
        {
            Name = 'Accounts_Limit_local_account_use_of_blank_passwords_to_console_logon_only'
            Accounts_Limit_local_account_use_of_blank_passwords_to_console_logon_only = 'Enabled'
        }
    }
    
    if($SecurityOptionMicrosoftNetworkServerDigitallySignCommunicationsIfClientAgrees) {
        SecurityOption 'SecurityRegistry(INF): Microsoft_network_server_Digitally_sign_communications_if_client_agrees'
        {
            Name = 'Microsoft_network_server_Digitally_sign_communications_if_client_agrees'
            Microsoft_network_server_Digitally_sign_communications_if_client_agrees = 'Enabled'
        }
    }
    
    if($SecurityOptionDomainMemberDigitallySignSecureChannelData) {
        SecurityOption 'SecurityRegistry(INF): Domain_member_Digitally_sign_secure_channel_data_when_possible'
        {
            Name = 'Domain_member_Digitally_sign_secure_channel_data_when_possible'
            Domain_member_Digitally_sign_secure_channel_data_when_possible = 'Enabled'
        }
    }
    
    if($SecurityOptionMicrosoftNetworkClientDigitallySignCommunicationsIfServerAgrees) {
        SecurityOption 'SecurityRegistry(INF): Microsoft_network_client_Digitally_sign_communications_if_server_agrees'
        {
            Name = 'Microsoft_network_client_Digitally_sign_communications_if_server_agrees'
            Microsoft_network_client_Digitally_sign_communications_if_server_agrees = 'Enabled'
        }
    }
    
    if($SecurityOptionDomainMemberRequireStrongWindows2000SessionKey) {
        SecurityOption 'SecurityRegistry(INF): Domain_member_Require_strong_Windows_2000_or_later_session_key'
        {
            Name = 'Domain_member_Require_strong_Windows_2000_or_later_session_key'
            Domain_member_Require_strong_Windows_2000_or_later_session_key = 'Enabled'
        }
    }
    
    if($SecurityOptionNetworkAccessRestrictAnonymousAccessToNamedPipes) {
        SecurityOption 'SecurityRegistry(INF): Network_access_Restrict_anonymous_access_to_Named_Pipes_and_Shares'
        {
            Name = 'Network_access_Restrict_anonymous_access_to_Named_Pipes_and_Shares'
            Network_access_Restrict_anonymous_access_to_Named_Pipes_and_Shares = 'Enabled'
        }
    }
    
    if($UserRightsAssignmentCreateGlobalObjects) {
        UserRightsAssignment 'UserRightsAssignment(INF): Create_global_objects'
        {
            Force = $True
            Identity = @('*S-1-5-6', '*S-1-5-20', '*S-1-5-19', '*S-1-5-32-544')
            Policy = 'Create_global_objects'
        }
    }
    
    if($UserRightsAssignmentCreateAPagefile) {
        UserRightsAssignment 'UserRightsAssignment(INF): Create_a_pagefile'
        {
            Force = $True
            Identity = @('*S-1-5-32-544')
            Policy = 'Create_a_pagefile'
        }
    }
    
    if($UserRightsAssignmentAllowLogOnLocally) {
        UserRightsAssignment 'UserRightsAssignment(INF): Allow_log_on_locally'
        {
            Force = $True
            Identity = @('*S-1-5-32-544')
            Policy = 'Allow_log_on_locally'
        }
    }
    
    if($UserRightsAssignmentLockPagesInMemory) {
        UserRightsAssignment 'UserRightsAssignment(INF): Lock_pages_in_memory'
        {
            Force = $True
            Identity = @('')
            Policy = 'Lock_pages_in_memory'
        }
    }
    
    if($UserRightsAssignmentDenyLogOnLocally) {
        UserRightsAssignment 'UserRightsAssignment(INF): Deny_log_on_locally'
        {
            Force = $True
            Identity = @($DomainAdmins, $EnterpriseAdmins, '*S-1-5-32-546')
            Policy = 'Deny_log_on_locally'
        }
    }

    if($UserRightsAssignmentDenyLogOnAsAService) {
        UserRightsAssignment 'UserRightsAssignment(INF): Deny_log_on_as_a_service'
        {
            Force = $True
            Identity = @($DomainAdmins, $EnterpriseAdmins)
            Policy = 'Deny_log_on_as_a_service'
        }
    }
    
    if($UserRightsAssignmentTakeOwnershipOfFiles) {
        UserRightsAssignment 'UserRightsAssignment(INF): Take_ownership_of_files_or_other_objects'
        {
            Force = $True
            Identity = @('*S-1-5-32-544')
            Policy = 'Take_ownership_of_files_or_other_objects'
        }
    }
    
    if($UserRightsAssignmentPerformVolumeMaintenanceTasks) {
        UserRightsAssignment 'UserRightsAssignment(INF): Perform_volume_maintenance_tasks'
        {
            Force = $True
            Identity = @('*S-1-5-32-544')
            Policy = 'Perform_volume_maintenance_tasks'
        }
    }
    
    if($UserRightsAssignmentCreateATokenObject) {
        UserRightsAssignment 'UserRightsAssignment(INF): Create_a_token_object'
        {
            Force = $True
            Identity = @('')
            Policy = 'Create_a_token_object'
        }
    }
    
    if($UserRightsAssignmentAccessCredentialManagerAsTrustedCaller) {
        UserRightsAssignment 'UserRightsAssignment(INF): Access_Credential_Manager_as_a_trusted_caller'
        {
            Force = $True
            Identity = @('')
            Policy = 'Access_Credential_Manager_as_a_trusted_caller'
        }
    }
    
    if($UserRightsAssignmentDebugPrograms) {
        UserRightsAssignment 'UserRightsAssignment(INF): Debug_programs'
        {
            Force = $True
            Identity = @('*S-1-5-32-544')
            Policy = 'Debug_programs'
        }
    }
    
    if($UserRightsAssignmentModifyFirmwareEnvironmentValues) {
        UserRightsAssignment 'UserRightsAssignment(INF): Modify_firmware_environment_values'
        {
            Force = $True
            Identity = @('*S-1-5-32-544')
            Policy = 'Modify_firmware_environment_values'
        }
    }
    
    if($UserRightsAssignmentLoadAndUnloadDeviceDrivers) {
        UserRightsAssignment 'UserRightsAssignment(INF): Load_and_unload_device_drivers'
        {
            Force = $True
            Identity = @('*S-1-5-32-544')
            Policy = 'Load_and_unload_device_drivers'
        }
    }
    
    if($UserRightsAssignmentDenyAccessToThisComputerFromTheNetwork) {
        UserRightsAssignment 'UserRightsAssignment(INF): Deny_access_to_this_computer_from_the_network'
        {
            Force = $True
            Identity = @($DomainAdmins, $EnterpriseAdmins, '*S-1-5-32-546', '*S-1-5-113')
            Policy = 'Deny_access_to_this_computer_from_the_network'
        }
    }
    
    if($UserRightsAssignmentAccessThisComputerFromTheNetwork) {
        UserRightsAssignment 'UserRightsAssignment(INF): Access_this_computer_from_the_network'
        {
            Force = $True
            Identity = @('*S-1-5-32-544', '*S-1-5-11')
            Policy = 'Access_this_computer_from_the_network'
        }
    }
    
    if($UserRightsAssignmentRestoreFilesAndDirectories) {
        UserRightsAssignment 'UserRightsAssignment(INF): Restore_files_and_directories'
        {
            Force = $True
            Identity = @('*S-1-5-32-544')
            Policy = 'Restore_files_and_directories'
        }
    }
    
    if($UserRightsAssignmentIncreaseSchedulingPriority) {
        UserRightsAssignment 'UserRightsAssignment(INF): Increase_scheduling_priority'
        {
            Force = $True
            Identity = @('*S-1-5-32-544')
            Policy = 'Increase_scheduling_priority'
        }
    }
    
    if($UserRightsAssignmentEnableAccountsToBeTrustedForDelegation) {
        UserRightsAssignment 'UserRightsAssignment(INF): Enable_computer_and_user_accounts_to_be_trusted_for_delegation'
        {
            Force = $True
            Identity = @('')
            Policy = 'Enable_computer_and_user_accounts_to_be_trusted_for_delegation'
        }
    }
    
    if($UserRightsAssignmentBackUpFilesAndDirectories) {
        UserRightsAssignment 'UserRightsAssignment(INF): Back_up_files_and_directories'
        {
            Force = $True
            Identity = @('*S-1-5-32-544')
            Policy = 'Back_up_files_and_directories'
        }
    }
    
    if($UserRightsAssignmentGenerateSecurityAudits) {
        UserRightsAssignment 'UserRightsAssignment(INF): Generate_security_audits'
        {
            Force = $True
            Identity = @('*S-1-5-20', '*S-1-5-19')
            Policy = 'Generate_security_audits'
        }
    }
    
    if($UserRightsAssignmentProfileSingleProcess) {
        UserRightsAssignment 'UserRightsAssignment(INF): Profile_single_process'
        {
            Force = $True
            Identity = @('*S-1-5-32-544')
            Policy = 'Profile_single_process'
        }
    }
    
    if($UserRightsAssignmentDenyLogOnAsABatchJob) {
        UserRightsAssignment 'UserRightsAssignment(INF): Deny_log_on_as_a_batch_job'
        {
            Force = $True
            Identity = @($DomainAdmins, $EnterpriseAdmins, '*S-1-5-32-546')
            Policy = 'Deny_log_on_as_a_batch_job'
        }
    }
    
    if($UserRightsAssignmentActAsPartOfTheOperatingSystem) {
        UserRightsAssignment 'UserRightsAssignment(INF): Act_as_part_of_the_operating_system'
        {
            Force = $True
            Identity = @('')
            Policy = 'Act_as_part_of_the_operating_system'
        }
    }
    
    if($UserRightsAssignmentForceShutdownFromARemoteSystem) {
        UserRightsAssignment 'UserRightsAssignment(INF): Force_shutdown_from_a_remote_system'
        {
            Force = $True
            Identity = @('*S-1-5-32-544')
            Policy = 'Force_shutdown_from_a_remote_system'
        }
    }
    
    if($UserRightsAssignmentImpersonateAClientAfterAuthentication) {
        UserRightsAssignment 'UserRightsAssignment(INF): Impersonate_a_client_after_authentication'
        {
            Force = $True
            Identity = @('*S-1-5-6', '*S-1-5-20', '*S-1-5-19', '*S-1-5-32-544')
            Policy = 'Impersonate_a_client_after_authentication'
        }
    }
    
    if($UserRightsAssignmentDenyLogOnThroughRemoteDesktopServices) {
        UserRightsAssignment 'UserRightsAssignment(INF): Deny_log_on_through_Remote_Desktop_Services'
        {
            Force = $True
            Identity = @($DomainAdmins, $EnterpriseAdmins, '*S-1-5-32-546', '*S-1-5-113')
            Policy = 'Deny_log_on_through_Remote_Desktop_Services'
        }
    }
    
    if($UserRightsAssignmentCreatePermanentSharedObjects) {
        UserRightsAssignment 'UserRightsAssignment(INF): Create_permanent_shared_objects'
        {
            Force = $True
            Identity = @('')
            Policy = 'Create_permanent_shared_objects'
        }
    }
    
    if($UserRightsAssignmentManageAuditingAndSecurityLog) {
        UserRightsAssignment 'UserRightsAssignment(INF): Manage_auditing_and_security_log'
        {
            Force = $True
            Identity = @('*S-1-5-32-544')
            Policy = 'Manage_auditing_and_security_log'
        }
    }
    
    if($UserRightsAssignmentCreateSymbolicLinks) {
        UserRightsAssignment 'UserRightsAssignment(INF): Create_symbolic_links'
        {
            Force = $True
            Identity = @('*S-1-5-32-544')
            Policy = 'Create_symbolic_links'
        }
    }
    
    if($SecurityOptionDomainControllerRefuseMachineAccountPasswordChanges) {
        SecurityOption 'SecurityRegistry(INF): Domain_controller_Refuse_machine_account_password_changes'
        {
            Name = 'Domain_controller_Refuse_machine_account_password_changes'
            Domain_controller_Refuse_machine_account_password_changes = 'Disabled'
        }
    }
    
    if($SecurityOptionDomainControllerLDAPServerSigningRequirements) {
        SecurityOption 'SecurityRegistry(INF): Domain_controller_LDAP_server_signing_requirements'
        {
            Name = 'Domain_controller_LDAP_server_signing_requirements'
            Domain_controller_LDAP_server_signing_requirements = 'Require Signing'
        }
    }
    
    if($UserRightsAssignmentAddWorkstationsToDomain) {
        UserRightsAssignment 'UserRightsAssignment(INF): Add_workstations_to_domain'
        {
            Force = $True
            Identity = @('*S-1-5-32-544')
            Policy = 'Add_workstations_to_domain'
        }
    }
    if($UserRightsAssignmentAllowLogOnThroughRemoteDesktopServices) {
        UserRightsAssignment 'UserRightsAssignment(INF): Allow_log_on_through_Remote_Desktop_Services'
        {
            Force = $True
            Identity = @('*S-1-5-32-544')
            Policy = 'Allow_log_on_through_Remote_Desktop_Services'
        }
    }
    RefreshRegistryPolicy 'ActivateClientSideExtension'
    {
        IsSingleInstance = 'Yes'
    }
    

}

