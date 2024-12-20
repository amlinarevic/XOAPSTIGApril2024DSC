configuration DoD_WinSvr_2016_MS_and_DC_V2R8
{

    param(
        [System.Boolean]$EnumerateAdministrators = $true,
        [System.Boolean]$NoAutorun = $true,
        [System.Boolean]$NoDriveTypeAutoRun = $true,
        [System.Boolean]$DisableAutomaticRestartSignOn = $true,
        [System.Boolean]$LocalAccountTokenFilterPolicy = $true,
        [System.Boolean]$ProcessCreationIncludeCmdLine_Enabled = $true,
        [System.Boolean]$DisableEnclosureDownload = $true,
        [System.Boolean]$DCSettingIndex = $true,
        [System.Boolean]$ACSettingIndex = $true,
        [System.Boolean]$DisableInventory = $true,
        [System.Boolean]$AllowTelemetry = $true,
        [System.Boolean]$EnableVirtualizationBasedSecurity = $true,
        [System.Boolean]$RequirePlatformSecurityFeatures = $true,
        [System.Boolean]$HypervisorEnforcedCodeIntegrity = $true,
        [System.Boolean]$LsaCfgFlags = $true,
        [System.Boolean]$MaxSizeApplication = $true,
        [System.Boolean]$MaxSizeSecurity = $true,
        [System.Boolean]$MaxSizeSystem = $true,
        [System.Boolean]$NoAutoplayForNonVolume = $true,
        [System.Boolean]$NoBackgroundPolicy = $true,
        [System.Boolean]$NoGPOListChanges = $true,
        [System.Boolean]$EnableUserControl = $true,
        [System.Boolean]$AlwaysInstallElevated = $true,
        [System.Boolean]$AllowInsecureGuestAuth = $true,
        [System.Boolean]$HardenedPathsNetlogon = $true,
        [System.Boolean]$HardenedPathsSysvol = $true,
        [System.Boolean]$NoLockScreenSlideshow = $true,
        [System.Boolean]$EnableScriptBlockLogging = $true,
        [System.Boolean]$EnableScriptBlockInvocationLogging = $true,
        [System.Boolean]$EnableTranscripting = $true,
        [System.Boolean]$OutputDirectory = $true,
        [System.Boolean]$EnableInvocationHeader = $true,
        [System.Boolean]$DontDisplayNetworkSelectionUI = $true,
        [System.Boolean]$EnumerateLocalUsers = $true,
        [System.Boolean]$EnableSmartScreen = $true,
        [System.Boolean]$AllowIndexingEncryptedStoresOrItems = $true,
        [System.Boolean]$WinRMClientAllowBasic = $true,
        [System.Boolean]$WinRMClientAllowUnencryptedTraffic = $true,
        [System.Boolean]$WinRMClientAllowDigest = $true,
        [System.Boolean]$WinRMServiceAllowBasic = $true,
        [System.Boolean]$WinRMServiceAllowUnencryptedTraffic = $true,
        [System.Boolean]$WinRMServiceDisableRunAs = $true,
        [System.Boolean]$DisableWebPnPDownload = $true,
        [System.Boolean]$DisableHTTPPrinting = $true,
        [System.Boolean]$DisablePasswordSaving = $true,
        [System.Boolean]$fDisableCdm = $true,
        [System.Boolean]$fPromptForPassword = $true,
        [System.Boolean]$fEncryptRPCTraffic = $true,
        [System.Boolean]$MinEncryptionLevel = $true,
        [System.Boolean]$UseLogonCredential = $true,
        [System.Boolean]$SMB1 = $true,
        [System.Boolean]$StartMrxSmb10 = $true,
        [System.Boolean]$NoNameReleaseOnDemand = $true,
        [System.Boolean]$DisableIPSourceRoutingTcpip = $true,
        [System.Boolean]$EnableICMPRedirect = $true,
        [System.Boolean]$DisableIPSourceRoutingTcpip6 = $true,
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
        [System.Boolean]$AuditPnpActivitySuccess = $true,
        [System.Boolean]$AuditPnpActivityFailure = $true,
        [System.Boolean]$AuditProcessCreationSuccess = $true,
        [System.Boolean]$AuditProcessCreationFailure = $true,
        [System.Boolean]$AuditDirectoryServiceAccessSuccess = $true,
        [System.Boolean]$AuditDirectoryServiceAccessFailure = $true,
        [System.Boolean]$AuditDirectoryServiceChangesSuccess = $true,
        [System.Boolean]$AuditDirectoryServiceChangesFailure = $true,
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
        [System.Boolean]$ResetLockoutCount = $true,
        [System.Boolean]$LSAAnonymousNameLookup = $true,
        [System.Boolean]$LockoutDuration = $true,
        [System.Boolean]$NewAdministratorName = $true,
        [System.Boolean]$PasswordHistorySize = $true,
        [System.Boolean]$MinimumPasswordLength = $true,
        [System.Boolean]$MinimumPasswordAge = $true,
        [System.Boolean]$ClearTextPassword = $true,
        [System.Boolean]$NewGuestName = $true,
        [System.Boolean]$EnableGuestAccount = $true,
        [System.Boolean]$LockoutBadCount = $true,
        [System.Boolean]$PasswordComplexity = $true,
        [System.Boolean]$MaximumPasswordAge = $true,
        [System.Boolean]$NetworkSecurityDoNotStoreLANManagerHash = $true,
        [System.Boolean]$MicrosoftNetworkServerDigitallySignCommunicationsAlways = $true,
        [System.Boolean]$InteractiveLogonCachePreviousLogons = $true,
        [System.Boolean]$InteractiveLogonMachineInactivityLimit = $true,
        [System.Boolean]$SystemCryptographyForceStrongKeyProtection = $true,
        [System.Boolean]$NetworkAccessLetEveryonePermissionsApplyToAnonymousUsers = $true,
        [System.Boolean]$UserAccountControlOnlyElevateUIAccess = $true,
        [System.Boolean]$DomainMemberDigitallyEncryptSecureChannelData = $true,
        [System.Boolean]$NetworkAccessRestrictAnonymousAccess = $true,
        [System.Boolean]$NetworkSecurityMinimumSessionSecurityNTLM = $true,
        [System.Boolean]$NetworkSecurityAllowLocalSystemNTLM = $true,
        [System.Boolean]$NetworkSecurityConfigureEncryptionTypesKerberos = $true,
        [System.Boolean]$UserAccountControlDetectApplicationInstallations = $true,
        [System.Boolean]$MicrosoftNetworkClientDigitallySignCommunicationsAlways = $true,
        [System.Boolean]$UserAccountControlBehaviorOfAdminElevationPrompt = $true,
        [System.Boolean]$DomainMemberDisableMachineAccountPasswordChanges = $true,
        [System.Boolean]$InteractiveLogonMessageText = $true,
        [System.Boolean]$DomainMemberDigitallyEncryptOrSignDataAlways = $true,
        [System.Boolean]$NetworkSecurityAllowPKU2UAuthentication = $true,
        [System.Boolean]$DomainControllerRefuseMachineAccountPasswordChanges = $true,
        [System.Boolean]$DomainMemberMaximumMachineAccountPasswordAge = $true,
        [System.Boolean]$AccountsLimitBlankPasswordsToConsoleLogon = $true,
        [System.Boolean]$SystemObjectsStrengthenDefaultPermissions = $true,
        [System.Boolean]$AuditForceAuditPolicySubcategoryOverride = $true,
        [System.Boolean]$NetworkSecurityLDAPClientSigningRequirements = $true,
        [System.Boolean]$InteractiveLogonMessageTitle = $true,
        [System.Boolean]$UserAccountControlAllowUIAccessPrompt = $true,
        [System.Boolean]$MicrosoftNetworkClientSendUnencryptedPassword = $true,
        [System.Boolean]$InteractiveLogonSmartCardRemovalBehavior = $true,
        [System.Boolean]$UserAccountControlVirtualizeFileAndRegistryWriteFailures = $true,
        [System.Boolean]$UserAccountControlRunAllAdminsInAdminApprovalMode = $true,
        [System.Boolean]$NetworkAccessDoNotAllowAnonymousSAMEnumeration = $true,
        [System.Boolean]$NetworkSecurityMinimumSessionSecurityNTLMSP = $true,
        [System.Boolean]$UserAccountControlAdminApprovalModeForBuiltInAdmin = $true,
        [System.Boolean]$NetworkSecurityLANManagerAuthenticationLevel = $true,
        [System.Boolean]$UserAccountControlBehaviorOfElevationPromptForStandardUsers = $true,
        [System.Boolean]$MicrosoftNetworkServerDigitallySignCommunicationsIfClientAgrees = $true,
        [System.Boolean]$DomainControllerLDAPServerSigningRequirements = $true,
        [System.Boolean]$DomainMemberDigitallySignSecureChannelDataWhenPossible = $true,
        [System.Boolean]$DomainMemberRequireStrongSessionKey = $true,
        [System.Boolean]$MicrosoftNetworkClientDigitallySignCommunicationsIfServerAgrees = $true,
        [System.Boolean]$SystemCryptographyUseFIPSCompliantAlgorithms = $true,
        [System.Boolean]$NetworkSecurityAllowLocalSystemNullSessionFallback = $true,
        [System.Boolean]$NetworkAccessDoNotAllowAnonymousEnumerationSAMAndShares = $true,
        [System.Boolean]$AccessCredentialManagerAsTrustedCaller = $true,
        [System.Boolean]$DebugPrograms = $true,
        [System.Boolean]$ModifyFirmwareEnvironmentValues = $true,
        [System.Boolean]$LoadAndUnloadDeviceDrivers = $true,
        [System.Boolean]$DenyAccessToComputerFromNetwork = $true,
        [System.Boolean]$AccessComputerFromNetwork = $true,
        [System.Boolean]$RestoreFilesAndDirectories = $true,
        [System.Boolean]$IncreaseSchedulingPriority = $true,
        [System.Boolean]$EnableTrustedDelegation = $true,
        [System.Boolean]$BackupFilesAndDirectories = $true,
        [System.Boolean]$GenerateSecurityAudits = $true,
        [System.Boolean]$ProfileSingleProcess = $true,
        [System.Boolean]$DenyLogOnAsBatchJob = $true,
        [System.Boolean]$ActAsPartOfOperatingSystem = $true,
        [System.Boolean]$ForceShutdownFromRemoteSystem = $true,
        [System.Boolean]$AllowLogOnThroughRemoteDesktop = $true,
        [System.Boolean]$ImpersonateClientAfterAuthentication = $true,
        [System.Boolean]$DenyLogOnThroughRemoteDesktop = $true,
        [System.Boolean]$CreatePermanentSharedObjects = $true,
        [System.Boolean]$ManageAuditingAndSecurityLog = $true,
        [System.Boolean]$CreateSymbolicLinks = $true,
        [System.Boolean]$RestrictClientsToMakeRemoteCallsToSAM = $true                
    )

    Import-DSCResource -ModuleName 'GPRegistryPolicyDsc'
	Import-DSCResource -ModuleName 'AuditPolicyDSC'
	Import-DSCResource -ModuleName 'SecurityPolicyDSC'

    if($EnumerateAdministrators){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\CredUI\EnumerateAdministrators'
        {
            Key = 'Software\Microsoft\Windows\CurrentVersion\Policies\CredUI'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'EnumerateAdministrators'
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

    if($LocalAccountTokenFilterPolicy){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\LocalAccountTokenFilterPolicy'
        {
            Key = 'Software\Microsoft\Windows\CurrentVersion\Policies\System'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'LocalAccountTokenFilterPolicy'
        }
    }

    if($ProcessCreationIncludeCmdLine_Enabled){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit\ProcessCreationIncludeCmdLine_Enabled'
        {
            Key = 'Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'ProcessCreationIncludeCmdLine_Enabled'
        }
    }

    if($DisableEnclosureDownload){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Feeds\DisableEnclosureDownload'
        {
            Key = 'Software\Policies\Microsoft\Internet Explorer\Feeds'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'DisableEnclosureDownload'
        }
    }

    if($DCSettingIndex){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\DCSettingIndex'
        {
            Key = 'Software\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'DCSettingIndex'
        }
    }

    if($ACSettingIndex){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\ACSettingIndex'
        {
            Key = 'Software\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'ACSettingIndex'
        }
    }

    if($DisableInventory){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\AppCompat\DisableInventory'
        {
            Key = 'Software\Policies\Microsoft\Windows\AppCompat'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'DisableInventory'
        }
    }

    if($AllowTelemetry){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\DataCollection\AllowTelemetry'
        {
            Key = 'Software\Policies\Microsoft\Windows\DataCollection'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'AllowTelemetry'
        }
    }

    if($EnableVirtualizationBasedSecurity){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\DeviceGuard\EnableVirtualizationBasedSecurity'
        {
            Key = 'Software\Policies\Microsoft\Windows\DeviceGuard'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'EnableVirtualizationBasedSecurity'
        }
    }

    if($RequirePlatformSecurityFeatures){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\DeviceGuard\RequirePlatformSecurityFeatures'
        {
            Key = 'Software\Policies\Microsoft\Windows\DeviceGuard'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'RequirePlatformSecurityFeatures'
        }
    }

    if($HypervisorEnforcedCodeIntegrity){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\DeviceGuard\HypervisorEnforcedCodeIntegrity'
        {
            Key = 'Software\Policies\Microsoft\Windows\DeviceGuard'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'HypervisorEnforcedCodeIntegrity'
        }
    }
    if($LsaCfgFlags){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\DeviceGuard\LsaCfgFlags'
        {
            Key = 'Software\Policies\Microsoft\Windows\DeviceGuard'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'LsaCfgFlags'
        }
    }

    if($MaxSizeApplication){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\EventLog\Application\MaxSize'
        {
            Key = 'Software\Policies\Microsoft\Windows\EventLog\Application'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 32768
            ValueName = 'MaxSize'
        }
    }

    if($MaxSizeSecurity){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\EventLog\Security\MaxSize'
        {
            Key = 'Software\Policies\Microsoft\Windows\EventLog\Security'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 196608
            ValueName = 'MaxSize'
        }
    }

    if($MaxSizeSystem){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\EventLog\System\MaxSize'
        {
            Key = 'Software\Policies\Microsoft\Windows\EventLog\System'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 32768
            ValueName = 'MaxSize'
        }
    }

    if($NoAutoplayForNonVolume){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\Explorer\NoAutoplayfornonVolume'
        {
            Key = 'Software\Policies\Microsoft\Windows\Explorer'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'NoAutoplayfornonVolume'
        }
    }

    if($NoBackgroundPolicy){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}\NoBackgroundPolicy'
        {
            Key = 'Software\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'NoBackgroundPolicy'
        }
    }

    if($NoGPOListChanges){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}\NoGPOListChanges'
        {
            Key = 'Software\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'NoGPOListChanges'
        }
    }

    if($EnableUserControl){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\Installer\EnableUserControl'
        {
            Key = 'Software\Policies\Microsoft\Windows\Installer'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'EnableUserControl'
        }
    }

    if($AlwaysInstallElevated){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated'
        {
            Key = 'Software\Policies\Microsoft\Windows\Installer'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'AlwaysInstallElevated'
        }
    }

    if($AllowInsecureGuestAuth){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\LanmanWorkstation\AllowInsecureGuestAuth'
        {
            Key = 'Software\Policies\Microsoft\Windows\LanmanWorkstation'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'AllowInsecureGuestAuth'
        }
    }

    if($HardenedPathsNetlogon){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths\*\NETLOGON'
        {
            Key = 'Software\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths'
            TargetType = 'ComputerConfiguration'
            ValueType = 'String'
            ValueData = 'RequireMutualAuthentication=1,RequireIntegrity=1'
            ValueName = '\\*\NETLOGON'
        }
    }

    if($HardenedPathsSysvol){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths\*\SYSVOL'
        {
            Key = 'Software\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths'
            TargetType = 'ComputerConfiguration'
            ValueType = 'String'
            ValueData = 'RequireMutualAuthentication=1,RequireIntegrity=1'
            ValueName = '\\*\SYSVOL'
        }
    }

    if($NoLockScreenSlideshow){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\Personalization\NoLockScreenSlideshow'
        {
            Key = 'Software\Policies\Microsoft\Windows\Personalization'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'NoLockScreenSlideshow'
        }
    }

    if($EnableScriptBlockLogging){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\EnableScriptBlockLogging'
        {
            Key = 'Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'EnableScriptBlockLogging'
        }
    }

    if($EnableScriptBlockInvocationLogging){
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

    if($EnableTranscripting){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription\EnableTranscripting'
        {
            Key = 'Software\Policies\Microsoft\Windows\PowerShell\Transcription'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'EnableTranscripting'
        }
    }

    if($OutputDirectory){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription\OutputDirectory'
        {
            Key = 'Software\Policies\Microsoft\Windows\PowerShell\Transcription'
            TargetType = 'ComputerConfiguration'
            ValueType = 'String'
            ValueData = 'C:\ProgramData\PS_Transcript'
            ValueName = 'OutputDirectory'
        }
    }

    if($EnableInvocationHeader){
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

    if($DontDisplayNetworkSelectionUI){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\System\DontDisplayNetworkSelectionUI'
        {
            Key = 'Software\Policies\Microsoft\Windows\System'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'DontDisplayNetworkSelectionUI'
        }
    }

    if($EnumerateLocalUsers){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\System\EnumerateLocalUsers'
        {
            Key = 'Software\Policies\Microsoft\Windows\System'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'EnumerateLocalUsers'
        }
    }

    if($EnableSmartScreen){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\System\EnableSmartScreen'
        {
            Key = 'Software\Policies\Microsoft\Windows\System'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'EnableSmartScreen'
        }
    }

    if($AllowIndexingEncryptedStoresOrItems){
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

    if($DisableWebPnPDownload){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows NT\Printers\DisableWebPnPDownload'
        {
            Key = 'Software\Policies\Microsoft\Windows NT\Printers'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'DisableWebPnPDownload'
        }
    }

    if($DisableHTTPPrinting){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows NT\Printers\DisableHTTPPrinting'
        {
            Key = 'Software\Policies\Microsoft\Windows NT\Printers'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'DisableHTTPPrinting'
        }
    }

    if($DisablePasswordSaving){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\DisablePasswordSaving'
        {
            Key = 'Software\Policies\Microsoft\Windows NT\Terminal Services'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'DisablePasswordSaving'
        }
    }

    if($fDisableCdm){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\fDisableCdm'
        {
            Key = 'Software\Policies\Microsoft\Windows NT\Terminal Services'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'fDisableCdm'
        }
    }

    if($fPromptForPassword){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\fPromptForPassword'
        {
            Key = 'Software\Policies\Microsoft\Windows NT\Terminal Services'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'fPromptForPassword'
        }
    }

    if($fEncryptRPCTraffic){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\fEncryptRPCTraffic'
        {
            Key = 'Software\Policies\Microsoft\Windows NT\Terminal Services'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'fEncryptRPCTraffic'
        }
    }

    if($MinEncryptionLevel){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\MinEncryptionLevel'
        {
            Key = 'Software\Policies\Microsoft\Windows NT\Terminal Services'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 3
            ValueName = 'MinEncryptionLevel'
        }
    }

    if($UseLogonCredential){
        RegistryPolicyFile 'Registry(POL): HKLM:\System\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential'
        {
            Key = 'System\CurrentControlSet\Control\SecurityProviders\WDigest'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'UseLogonCredential'
        }
    }

    if($SMB1){
        RegistryPolicyFile 'Registry(POL): HKLM:\System\CurrentControlSet\Services\LanmanServer\Parameters\SMB1'
        {
            Key = 'System\CurrentControlSet\Services\LanmanServer\Parameters'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'SMB1'
        }
    }

    if($StartMrxSmb10){
        RegistryPolicyFile 'Registry(POL): HKLM:\System\CurrentControlSet\Services\MrxSmb10\Start'
        {
            Key = 'System\CurrentControlSet\Services\MrxSmb10'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 4
            ValueName = 'Start'
        }
    }

    if($NoNameReleaseOnDemand){
        RegistryPolicyFile 'Registry(POL): HKLM:\System\CurrentControlSet\Services\Netbt\Parameters\NoNameReleaseOnDemand'
        {
            Key = 'System\CurrentControlSet\Services\Netbt\Parameters'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'NoNameReleaseOnDemand'
        }
    }

    if($DisableIPSourceRoutingTcpip){
        RegistryPolicyFile 'Registry(POL): HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters\DisableIPSourceRouting'
        {
            Key = 'System\CurrentControlSet\Services\Tcpip\Parameters'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 2
            ValueName = 'DisableIPSourceRouting'
        }
    }

    if($EnableICMPRedirect){
        RegistryPolicyFile 'Registry(POL): HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters\EnableICMPRedirect'
        {
            Key = 'System\CurrentControlSet\Services\Tcpip\Parameters'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'EnableICMPRedirect'
        }
    }

    if($DisableIPSourceRoutingTcpip6){
        RegistryPolicyFile 'Registry(POL): HKLM:\System\CurrentControlSet\Services\Tcpip6\Parameters\DisableIPSourceRouting'
        {
            Key = 'System\CurrentControlSet\Services\Tcpip6\Parameters'
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

    if($AuditComputerAccountManagementSuccess){
        AuditPolicySubcategory 'Audit Computer Account Management (Success) - Inclusion'
        {
            Name = 'Computer Account Management'
            Ensure = 'Present'
            AuditFlag = 'Success'
        }
    }

    if($AuditComputerAccountManagementFailure){
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

    if($AuditOtherAccountManagementEventsFailure){
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

    if($AuditSecurityGroupManagementFailure){
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

    if($AuditPnpActivitySuccess){
        AuditPolicySubcategory 'Audit PNP Activity (Success) - Inclusion'
        {
            Name = 'Plug and Play Events'
            Ensure = 'Present'
            AuditFlag = 'Success'
        }
    }

    if($AuditPnpActivityFailure){
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

    if($AuditDirectoryServiceChangesFailure){
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

    if($AuditAccountLockoutSuccess){
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

    if($AuditGroupMembershipFailure){
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

    if($AuditLogoffFailure){
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

    if($AuditOtherObjectAccessEventsSuccess){
        AuditPolicySubcategory 'Audit Other Object Access Events (Success) - Inclusion'
        {
            Name = 'Other Object Access Events'
            Ensure = 'Present'
            AuditFlag = 'Success'
        }
    }

    if($AuditOtherObjectAccessEventsFailure){
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

    if($AuditAuditPolicyChangeSuccess){
        AuditPolicySubcategory 'Audit Audit Policy Change (Success) - Inclusion'
        {
            Name = 'Audit Policy Change'
            Ensure = 'Present'
            AuditFlag = 'Success'
        }
    }

    if($AuditAuditPolicyChangeFailure){
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

    if($ResetLockoutCount){
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

    if($LockoutDuration){
        AccountPolicy 'SecuritySetting(INF): LockoutDuration'
        {
            Account_lockout_duration = 15
            Name = 'Account_lockout_duration'
        }
    }

    if($NewAdministratorName){
        SecurityOption 'SecuritySetting(INF): NewAdministratorName'
        {
            Name = 'Accounts_Rename_administrator_account'
            Accounts_Rename_administrator_account = 'X_Admin'
        }
    }

    if($PasswordHistorySize){
        AccountPolicy 'SecuritySetting(INF): PasswordHistorySize'
        {
            Name = 'Enforce_password_history'
            Enforce_password_history = 24
        }
    }

    if($MinimumPasswordLength){
        AccountPolicy 'SecuritySetting(INF): MinimumPasswordLength'
        {
            Minimum_Password_Length = 14
            Name = 'Minimum_Password_Length'
        }
    }

    if($MinimumPasswordAge){
        AccountPolicy 'SecuritySetting(INF): MinimumPasswordAge'
        {
            Minimum_Password_Age = 1
            Name = 'Minimum_Password_Age'
        }
    }

    if($ClearTextPassword){
        AccountPolicy 'SecuritySetting(INF): ClearTextPassword'
        {
            Store_passwords_using_reversible_encryption = 'Disabled'
            Name = 'Store_passwords_using_reversible_encryption'
        }
    }

    if($NewGuestName){
        SecurityOption 'SecuritySetting(INF): NewGuestName'
        {
            Accounts_Rename_guest_account = 'Visitor'
            Name = 'Accounts_Rename_guest_account'
        }
    }

    if($EnableGuestAccount){
        SecurityOption 'SecuritySetting(INF): EnableGuestAccount'
        {
            Accounts_Guest_account_status = 'Disabled'
            Name = 'Accounts_Guest_account_status'
        }
    }

    if($LockoutBadCount){
        AccountPolicy 'SecuritySetting(INF): LockoutBadCount'
        {
            Account_lockout_threshold = 3
            Name = 'Account_lockout_threshold'
        }
    }

    if($PasswordComplexity){
        AccountPolicy 'SecuritySetting(INF): PasswordComplexity'
        {
            Password_must_meet_complexity_requirements = 'Enabled'
            Name = 'Password_must_meet_complexity_requirements'
        }
    }

    if($MaximumPasswordAge){
        AccountPolicy 'SecuritySetting(INF): MaximumPasswordAge'
        {
            Maximum_Password_Age = 60
            Name = 'Maximum_Password_Age'
        }
    }

    if($NetworkSecurityDoNotStoreLANManagerHash){
        SecurityOption 'SecurityRegistry(INF): Network_security_Do_not_store_LAN_Manager_hash_value_on_next_password_change'
        {
            Name = 'Network_security_Do_not_store_LAN_Manager_hash_value_on_next_password_change'
            Network_security_Do_not_store_LAN_Manager_hash_value_on_next_password_change = 'Enabled'
        }
    }

    if($MicrosoftNetworkServerDigitallySignCommunicationsAlways){
        SecurityOption 'SecurityRegistry(INF): Microsoft_network_server_Digitally_sign_communications_always'
        {
            Name = 'Microsoft_network_server_Digitally_sign_communications_always'
            Microsoft_network_server_Digitally_sign_communications_always = 'Enabled'
        }
    }

    if($InteractiveLogonCachePreviousLogons){
        SecurityOption 'SecurityRegistry(INF): Interactive_logon_Number_of_previous_logons_to_cache_in_case_domain_controller_is_not_available'
        {
            Name = 'Interactive_logon_Number_of_previous_logons_to_cache_in_case_domain_controller_is_not_available'
            Interactive_logon_Number_of_previous_logons_to_cache_in_case_domain_controller_is_not_available = '4'
        }
    }

    if($InteractiveLogonMachineInactivityLimit){
        SecurityOption 'SecurityRegistry(INF): Interactive_logon_Machine_inactivity_limit'
        {
            Name = 'Interactive_logon_Machine_inactivity_limit'
            Interactive_logon_Machine_inactivity_limit = '900'
        }
    }

    if($SystemCryptographyForceStrongKeyProtection){
        SecurityOption 'SecurityRegistry(INF): System_cryptography_Force_strong_key_protection_for_user_keys_stored_on_the_computer'
        {
            Name = 'System_cryptography_Force_strong_key_protection_for_user_keys_stored_on_the_computer'
            System_cryptography_Force_strong_key_protection_for_user_keys_stored_on_the_computer = 'User must enter a password each time they use a key'
        }
    }

    if($NetworkAccessLetEveryonePermissionsApplyToAnonymousUsers){
        SecurityOption 'SecurityRegistry(INF): Network_access_Let_Everyone_permissions_apply_to_anonymous_users'
        {
            Name = 'Network_access_Let_Everyone_permissions_apply_to_anonymous_users'
            Network_access_Let_Everyone_permissions_apply_to_anonymous_users = 'Disabled'
        }
    }

    if($UserAccountControlOnlyElevateUIAccess){
        SecurityOption 'SecurityRegistry(INF): User_Account_Control_Only_elevate_UIAccess_applications_that_are_installed_in_secure_locations'
        {
            Name = 'User_Account_Control_Only_elevate_UIAccess_applications_that_are_installed_in_secure_locations'
            User_Account_Control_Only_elevate_UIAccess_applications_that_are_installed_in_secure_locations = 'Enabled'
        }
    }

    if($DomainMemberDigitallyEncryptSecureChannelData){
        SecurityOption 'SecurityRegistry(INF): Domain_member_Digitally_encrypt_secure_channel_data_when_possible'
        {
            Name = 'Domain_member_Digitally_encrypt_secure_channel_data_when_possible'
            Domain_member_Digitally_encrypt_secure_channel_data_when_possible = 'Enabled'
        }
    }

    if($NetworkAccessRestrictAnonymousAccess){
        SecurityOption 'SecurityRegistry(INF): Network_access_Restrict_anonymous_access_to_Named_Pipes_and_Shares'
        {
            Name = 'Network_access_Restrict_anonymous_access_to_Named_Pipes_and_Shares'
            Network_access_Restrict_anonymous_access_to_Named_Pipes_and_Shares = 'Enabled'
        }
    }

    if($NetworkSecurityMinimumSessionSecurityNTLM){
        SecurityOption 'SecurityRegistry(INF): Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_servers'
        {
            Name = 'Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_servers'
            Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_servers = 'Both options checked'
        }
    }

    if($NetworkSecurityAllowLocalSystemNTLM){
        SecurityOption 'SecurityRegistry(INF): Network_security_Allow_Local_System_to_use_computer_identity_for_NTLM'
        {
            Name = 'Network_security_Allow_Local_System_to_use_computer_identity_for_NTLM'
            Network_security_Allow_Local_System_to_use_computer_identity_for_NTLM = 'Enabled'
        }
    }

    if($NetworkSecurityConfigureEncryptionTypesKerberos){
        SecurityOption 'SecurityRegistry(INF): Network_security_Configure_encryption_types_allowed_for_Kerberos'
        {
            Name = 'Network_security_Configure_encryption_types_allowed_for_Kerberos'
            Network_security_Configure_encryption_types_allowed_for_Kerberos = '2147483640'
        }
    }

    if($UserAccountControlDetectApplicationInstallations){
        SecurityOption 'SecurityRegistry(INF): User_Account_Control_Detect_application_installations_and_prompt_for_elevation'
        {
            Name = 'User_Account_Control_Detect_application_installations_and_prompt_for_elevation'
            User_Account_Control_Detect_application_installations_and_prompt_for_elevation = 'Enabled'
        }
    }

    if($MicrosoftNetworkClientDigitallySignCommunicationsAlways){
        SecurityOption 'SecurityRegistry(INF): Microsoft_network_client_Digitally_sign_communications_always'
        {
            Name = 'Microsoft_network_client_Digitally_sign_communications_always'
            Microsoft_network_client_Digitally_sign_communications_always = 'Enabled'
        }
    }

    if($UserAccountControlBehaviorOfAdminElevationPrompt){
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

    if($InteractiveLogonMessageText){
        SecurityOption 'SecurityRegistry(INF): Interactive_logon_Message_text_for_users_attempting_to_log_on'
        {
            Name = 'Interactive_logon_Message_text_for_users_attempting_to_log_on'
            Interactive_logon_Message_text_for_users_attempting_to_log_on = 'You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.,By using this IS (which includes any device attached to this IS)"," you consent to the following conditions:,-The USG routinely intercepts and monitors communications on this IS for purposes including"," but not limited to"," penetration testing"," COMSEC monitoring"," network operations and defense"," personnel misconduct (PM)"," law enforcement (LE)"," and counterintelligence (CI) investigations.,-At any time"," the USG may inspect and seize data stored on this IS.,-Communications using"," or data stored on"," this IS are not private"," are subject to routine monitoring"," interception"," and search"," and may be disclosed or used for any USG-authorized purpose.,-This IS includes security measures (e.g."," authentication and access controls) to protect USG interests--not for your personal benefit or privacy.,-Notwithstanding the above"," using this IS does not constitute consent to PM"," LE or CI investigative searching or monitoring of the content of privileged communications"," or work product"," related to personal representation or services by attorneys"," psychotherapists"," or clergy"," and their assistants. Such communications and work product are private and confidential. See User Agreement for details.'
        }
    }

    if($DomainMemberDigitallyEncryptOrSignDataAlways){
        SecurityOption 'SecurityRegistry(INF): Domain_member_Digitally_encrypt_or_sign_secure_channel_data_always'
        {
            Name = 'Domain_member_Digitally_encrypt_or_sign_secure_channel_data_always'
            Domain_member_Digitally_encrypt_or_sign_secure_channel_data_always = 'Enabled'
        }
    }

    if($NetworkSecurityAllowPKU2UAuthentication){
        SecurityOption 'SecurityRegistry(INF): Network_Security_Allow_PKU2U_authentication_requests_to_this_computer_to_use_online_identities'
        {
            Name = 'Network_Security_Allow_PKU2U_authentication_requests_to_this_computer_to_use_online_identities'
            Network_Security_Allow_PKU2U_authentication_requests_to_this_computer_to_use_online_identities = 'Disabled'
        }
    }

    if($DomainControllerRefuseMachineAccountPasswordChanges){
        SecurityOption 'SecurityRegistry(INF): Domain_controller_Refuse_machine_account_password_changes'
        {
            Name = 'Domain_controller_Refuse_machine_account_password_changes'
            Domain_controller_Refuse_machine_account_password_changes = 'Disabled'
        }
    }

    if($DomainMemberMaximumMachineAccountPasswordAge){
        SecurityOption 'SecurityRegistry(INF): Domain_member_Maximum_machine_account_password_age'
        {
            Name = 'Domain_member_Maximum_machine_account_password_age'
            Domain_member_Maximum_machine_account_password_age = '30'
        }
    }

    if($AccountsLimitBlankPasswordsToConsoleLogon){
        SecurityOption 'SecurityRegistry(INF): Accounts_Limit_local_account_use_of_blank_passwords_to_console_logon_only'
        {
            Name = 'Accounts_Limit_local_account_use_of_blank_passwords_to_console_logon_only'
            Accounts_Limit_local_account_use_of_blank_passwords_to_console_logon_only = 'Enabled'
        }
    }

    if($SystemObjectsStrengthenDefaultPermissions){
        SecurityOption 'SecurityRegistry(INF): System_objects_Strengthen_default_permissions_of_internal_system_objects_eg_Symbolic_Links'
        {
            Name = 'System_objects_Strengthen_default_permissions_of_internal_system_objects_eg_Symbolic_Links'
            System_objects_Strengthen_default_permissions_of_internal_system_objects_eg_Symbolic_Links = 'Enabled'
        }
    }

    if($AuditForceAuditPolicySubcategoryOverride){
        SecurityOption 'SecurityRegistry(INF): Audit_Force_audit_policy_subcategory_settings_Windows_Vista_or_later_to_override_audit_policy_category_settings'
        {
            Name = 'Audit_Force_audit_policy_subcategory_settings_Windows_Vista_or_later_to_override_audit_policy_category_settings'
            Audit_Force_audit_policy_subcategory_settings_Windows_Vista_or_later_to_override_audit_policy_category_settings = 'Enabled'
        }
    }

    if($NetworkSecurityLDAPClientSigningRequirements){
        SecurityOption 'SecurityRegistry(INF): Network_security_LDAP_client_signing_requirements'
        {
            Name = 'Network_security_LDAP_client_signing_requirements'
            Network_security_LDAP_client_signing_requirements = 'Negotiate Signing'
        }
    }

    if($InteractiveLogonMessageTitle){
        SecurityOption 'SecurityRegistry(INF): Interactive_logon_Message_title_for_users_attempting_to_log_on'
        {
            Name = 'Interactive_logon_Message_title_for_users_attempting_to_log_on'
            Interactive_logon_Message_title_for_users_attempting_to_log_on = 'US Department of Defense Warning Statement'
        }
    }

    if($UserAccountControlAllowUIAccessPrompt){
        SecurityOption 'SecurityRegistry(INF): User_Account_Control_Allow_UIAccess_applications_to_prompt_for_elevation_without_using_the_secure_desktop'
        {
            Name = 'User_Account_Control_Allow_UIAccess_applications_to_prompt_for_elevation_without_using_the_secure_desktop'
            User_Account_Control_Allow_UIAccess_applications_to_prompt_for_elevation_without_using_the_secure_desktop = 'Disabled'
        }
    }

    if($MicrosoftNetworkClientSendUnencryptedPassword){
        SecurityOption 'SecurityRegistry(INF): Microsoft_network_client_Send_unencrypted_password_to_third_party_SMB_servers'
        {
            Name = 'Microsoft_network_client_Send_unencrypted_password_to_third_party_SMB_servers'
            Microsoft_network_client_Send_unencrypted_password_to_third_party_SMB_servers = 'Disabled'
        }
    }

    if($InteractiveLogonSmartCardRemovalBehavior){
        SecurityOption 'SecurityRegistry(INF): Interactive_logon_Smart_card_removal_behavior'
        {
            Name = 'Interactive_logon_Smart_card_removal_behavior'
            Interactive_logon_Smart_card_removal_behavior = 'Lock workstation'
        }
    }

    if($UserAccountControlVirtualizeFileAndRegistryWriteFailures){
        SecurityOption 'SecurityRegistry(INF): User_Account_Control_Virtualize_file_and_registry_write_failures_to_per_user_locations'
        {
            Name = 'User_Account_Control_Virtualize_file_and_registry_write_failures_to_per_user_locations'
            User_Account_Control_Virtualize_file_and_registry_write_failures_to_per_user_locations = 'Enabled'
        }
    }

    if($UserAccountControlRunAllAdminsInAdminApprovalMode){
        SecurityOption 'SecurityRegistry(INF): User_Account_Control_Run_all_administrators_in_Admin_Approval_Mode'
        {
            Name = 'User_Account_Control_Run_all_administrators_in_Admin_Approval_Mode'
            User_Account_Control_Run_all_administrators_in_Admin_Approval_Mode = 'Enabled'
        }
    }

    if($NetworkAccessDoNotAllowAnonymousSAMEnumeration){
        SecurityOption 'SecurityRegistry(INF): Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts'
        {
            Name = 'Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts'
            Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts = 'Enabled'
        }
    }

    if($NetworkSecurityMinimumSessionSecurityNTLMSP){
        SecurityOption 'SecurityRegistry(INF): Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_clients'
        {
            Name = 'Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_clients'
            Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_clients = 'Both options checked'
        }
    }

    if($UserAccountControlAdminApprovalModeForBuiltInAdmin){
        SecurityOption 'SecurityRegistry(INF): User_Account_Control_Admin_Approval_Mode_for_the_Built_in_Administrator_account'
        {
            Name = 'User_Account_Control_Admin_Approval_Mode_for_the_Built_in_Administrator_account'
            User_Account_Control_Admin_Approval_Mode_for_the_Built_in_Administrator_account = 'Enabled'
        }
    }

    if($NetworkSecurityLANManagerAuthenticationLevel){
        SecurityOption 'SecurityRegistry(INF): Network_security_LAN_Manager_authentication_level'
        {
            Name = 'Network_security_LAN_Manager_authentication_level'
            Network_security_LAN_Manager_authentication_level = 'Send NTLMv2 responses only. Refuse LM & NTLM'
        }
    }

    if($UserAccountControlBehaviorOfElevationPromptForStandardUsers){
        SecurityOption 'SecurityRegistry(INF): User_Account_Control_Behavior_of_the_elevation_prompt_for_standard_users'
        {
            Name = 'User_Account_Control_Behavior_of_the_elevation_prompt_for_standard_users'
            User_Account_Control_Behavior_of_the_elevation_prompt_for_standard_users = 'Automatically deny elevation request'
        }
    }

    if($MicrosoftNetworkServerDigitallySignCommunicationsIfClientAgrees){
        SecurityOption 'SecurityRegistry(INF): Microsoft_network_server_Digitally_sign_communications_if_client_agrees'
        {
            Name = 'Microsoft_network_server_Digitally_sign_communications_if_client_agrees'
            Microsoft_network_server_Digitally_sign_communications_if_client_agrees = 'Enabled'
        }
    }

    if($DomainControllerLDAPServerSigningRequirements){
        SecurityOption 'SecurityRegistry(INF): Domain_controller_LDAP_server_signing_requirements'
        {
            Name = 'Domain_controller_LDAP_server_signing_requirements'
            Domain_controller_LDAP_server_signing_requirements = 'Require Signing'
        }
    }

    if($DomainMemberDigitallySignSecureChannelDataWhenPossible){
        SecurityOption 'SecurityRegistry(INF): Domain_member_Digitally_sign_secure_channel_data_when_possible'
        {
            Name = 'Domain_member_Digitally_sign_secure_channel_data_when_possible'
            Domain_member_Digitally_sign_secure_channel_data_when_possible = 'Enabled'
        }
    }

    if($DomainMemberRequireStrongSessionKey){
        SecurityOption 'SecurityRegistry(INF): Domain_member_Require_strong_Windows_2000_or_later_session_key'
        {
            Name = 'Domain_member_Require_strong_Windows_2000_or_later_session_key'
            Domain_member_Require_strong_Windows_2000_or_later_session_key = 'Enabled'
        }
    }

    if($MicrosoftNetworkClientDigitallySignCommunicationsIfServerAgrees){
        SecurityOption 'SecurityRegistry(INF): Microsoft_network_client_Digitally_sign_communications_if_server_agrees'
        {
            Name = 'Microsoft_network_client_Digitally_sign_communications_if_server_agrees'
            Microsoft_network_client_Digitally_sign_communications_if_server_agrees = 'Enabled'
        }
    }

    if($SystemCryptographyUseFIPSCompliantAlgorithms){
        SecurityOption 'SecurityRegistry(INF): System_cryptography_Use_FIPS_compliant_algorithms_for_encryption_hashing_and_signing'
        {
            Name = 'System_cryptography_Use_FIPS_compliant_algorithms_for_encryption_hashing_and_signing'
            System_cryptography_Use_FIPS_compliant_algorithms_for_encryption_hashing_and_signing = 'Enabled'
        }
    }

    if($NetworkSecurityAllowLocalSystemNullSessionFallback){
        SecurityOption 'SecurityRegistry(INF): Network_security_Allow_LocalSystem_NULL_session_fallback'
        {
            Name = 'Network_security_Allow_LocalSystem_NULL_session_fallback'
            Network_security_Allow_LocalSystem_NULL_session_fallback = 'Disabled'
        }
    }

    if($NetworkAccessDoNotAllowAnonymousEnumerationSAMAndShares){
        SecurityOption 'SecurityRegistry(INF): Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts_and_shares'
        {
            Name = 'Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts_and_shares'
            Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts_and_shares = 'Enabled'
        }
    }

    if($AddWorkstationsToDomain){
        UserRightsAssignment 'UserRightsAssignment(INF): Add_workstations_to_domain'
        {
            Force = $True
            Identity = @('*S-1-5-32-544')
            Policy = 'Add_workstations_to_domain'
        }
    }

    if($CreateGlobalObjects){
        UserRightsAssignment 'UserRightsAssignment(INF): Create_global_objects'
        {
            Force = $True
            Identity = @('*S-1-5-6', '*S-1-5-20', '*S-1-5-19', '*S-1-5-32-544')
            Policy = 'Create_global_objects'
        }
    }

    if($CreateAPagefile){
        UserRightsAssignment 'UserRightsAssignment(INF): Create_a_pagefile'
        {
            Force = $True
            Identity = @('*S-1-5-32-544')
            Policy = 'Create_a_pagefile'
        }
    }

    if($AllowLogOnLocally){
        UserRightsAssignment 'UserRightsAssignment(INF): Allow_log_on_locally'
        {
            Force = $True
            Identity = @('*S-1-5-32-544')
            Policy = 'Allow_log_on_locally'
        }
    }

    if($LockPagesInMemory){
        UserRightsAssignment 'UserRightsAssignment(INF): Lock_pages_in_memory'
        {
            Force = $True
            Identity = @('')
            Policy = 'Lock_pages_in_memory'
        }
    }

    if($DenyLogOnLocally){
        UserRightsAssignment 'UserRightsAssignment(INF): Deny_log_on_locally'
        {
            Force = $True
            Identity = @('*S-1-5-32-546')
            Policy = 'Deny_log_on_locally'
        }
    }

    if($DenyLogOnAsAService){
        UserRightsAssignment 'UserRightsAssignment(INF): Deny_log_on_as_a_service'
        {
            Force = $True
            Identity = @('')
            Policy = 'Deny_log_on_as_a_service'
        }
    }

    if($TakeOwnershipOfFilesOrOtherObjects){
        UserRightsAssignment 'UserRightsAssignment(INF): Take_ownership_of_files_or_other_objects'
        {
            Force = $True
            Identity = @('*S-1-5-32-544')
            Policy = 'Take_ownership_of_files_or_other_objects'
        }
    }

    if($PerformVolumeMaintenanceTasks){
        UserRightsAssignment 'UserRightsAssignment(INF): Perform_volume_maintenance_tasks'
        {
            Force = $True
            Identity = @('*S-1-5-32-544')
            Policy = 'Perform_volume_maintenance_tasks'
        }
    }

    if($CreateATokenObject){
        UserRightsAssignment 'UserRightsAssignment(INF): Create_a_token_object'
        {
            Force = $True
            Identity = @('')
            Policy = 'Create_a_token_object'
        }
    }
    if($AccessCredentialManagerAsTrustedCaller){
        UserRightsAssignment 'UserRightsAssignment(INF): Access_Credential_Manager_as_a_trusted_caller'
        {
            Force = $True
            Identity = @('')
            Policy = 'Access_Credential_Manager_as_a_trusted_caller'
        }
    }

    if($DebugPrograms){
        UserRightsAssignment 'UserRightsAssignment(INF): Debug_programs'
        {
            Force = $True
            Identity = @('*S-1-5-32-544')
            Policy = 'Debug_programs'
        }
    }

    if($ModifyFirmwareEnvironmentValues){
        UserRightsAssignment 'UserRightsAssignment(INF): Modify_firmware_environment_values'
        {
            Force = $True
            Identity = @('*S-1-5-32-544')
            Policy = 'Modify_firmware_environment_values'
        }
    }

    if($LoadAndUnloadDeviceDrivers){
        UserRightsAssignment 'UserRightsAssignment(INF): Load_and_unload_device_drivers'
        {
            Force = $True
            Identity = @('*S-1-5-32-544')
            Policy = 'Load_and_unload_device_drivers'
        }
    }

    if($DenyAccessToComputerFromNetwork){
        UserRightsAssignment 'UserRightsAssignment(INF): Deny_access_to_this_computer_from_the_network'
        {
            Force = $True
            Identity = @('*S-1-5-32-546')
            Policy = 'Deny_access_to_this_computer_from_the_network'
        }
    }

    if($AccessComputerFromNetwork){
        UserRightsAssignment 'UserRightsAssignment(INF): Access_this_computer_from_the_network'
        {
            Force = $True
            Identity = @('*S-1-5-32-544', '*S-1-5-11', '*S-1-5-9')
            Policy = 'Access_this_computer_from_the_network'
        }
    }

    if($RestoreFilesAndDirectories){
        UserRightsAssignment 'UserRightsAssignment(INF): Restore_files_and_directories'
        {
            Force = $True
            Identity = @('*S-1-5-32-544')
            Policy = 'Restore_files_and_directories'
        }
    }

    if($IncreaseSchedulingPriority){
        UserRightsAssignment 'UserRightsAssignment(INF): Increase_scheduling_priority'
        {
            Force = $True
            Identity = @('*S-1-5-32-544')
            Policy = 'Increase_scheduling_priority'
        }
    }

    if($EnableTrustedDelegation){
        UserRightsAssignment 'UserRightsAssignment(INF): Enable_computer_and_user_accounts_to_be_trusted_for_delegation'
        {
            Force = $True
            Identity = @('*S-1-5-32-544')
            Policy = 'Enable_computer_and_user_accounts_to_be_trusted_for_delegation'
        }
    }

    if($BackupFilesAndDirectories){
        UserRightsAssignment 'UserRightsAssignment(INF): Back_up_files_and_directories'
        {
            Force = $True
            Identity = @('*S-1-5-32-544')
            Policy = 'Back_up_files_and_directories'
        }
    }

    if($GenerateSecurityAudits){
        UserRightsAssignment 'UserRightsAssignment(INF): Generate_security_audits'
        {
            Force = $True
            Identity = @('*S-1-5-20', '*S-1-5-19')
            Policy = 'Generate_security_audits'
        }
    }

    if($ProfileSingleProcess){
        UserRightsAssignment 'UserRightsAssignment(INF): Profile_single_process'
        {
            Force = $True
            Identity = @('*S-1-5-32-544')
            Policy = 'Profile_single_process'
        }
    }

    if($DenyLogOnAsBatchJob){
        UserRightsAssignment 'UserRightsAssignment(INF): Deny_log_on_as_a_batch_job'
        {
            Force = $True
            Identity = @('*S-1-5-32-546')
            Policy = 'Deny_log_on_as_a_batch_job'
        }
    }

    if($ActAsPartOfOperatingSystem){
        UserRightsAssignment 'UserRightsAssignment(INF): Act_as_part_of_the_operating_system'
        {
            Force = $True
            Identity = @('')
            Policy = 'Act_as_part_of_the_operating_system'
        }
    }

    if($ForceShutdownFromRemoteSystem){
        UserRightsAssignment 'UserRightsAssignment(INF): Force_shutdown_from_a_remote_system'
        {
            Force = $True
            Identity = @('*S-1-5-32-544')
            Policy = 'Force_shutdown_from_a_remote_system'
        }
    }

    if($AllowLogOnThroughRemoteDesktop){
        UserRightsAssignment 'UserRightsAssignment(INF): Allow_log_on_through_Remote_Desktop_Services'
        {
            Force = $True
            Identity = @('*S-1-5-32-544')
            Policy = 'Allow_log_on_through_Remote_Desktop_Services'
        }
    }

    if($ImpersonateClientAfterAuthentication){
        UserRightsAssignment 'UserRightsAssignment(INF): Impersonate_a_client_after_authentication'
        {
            Force = $True
            Identity = @('*S-1-5-6', '*S-1-5-20', '*S-1-5-19', '*S-1-5-32-544')
            Policy = 'Impersonate_a_client_after_authentication'
        }
    }

    if($DenyLogOnThroughRemoteDesktop){
        UserRightsAssignment 'UserRightsAssignment(INF): Deny_log_on_through_Remote_Desktop_Services'
        {
            Force = $True
            Identity = @('*S-1-5-32-546')
            Policy = 'Deny_log_on_through_Remote_Desktop_Services'
        }
    }

    if($CreatePermanentSharedObjects){
        UserRightsAssignment 'UserRightsAssignment(INF): Create_permanent_shared_objects'
        {
            Force = $True
            Identity = @('')
            Policy = 'Create_permanent_shared_objects'
        }
    }

    if($ManageAuditingAndSecurityLog){
        UserRightsAssignment 'UserRightsAssignment(INF): Manage_auditing_and_security_log'
        {
            Force = $True
            Identity = @('*S-1-5-32-544')
            Policy = 'Manage_auditing_and_security_log'
        }
    }

    if($CreateSymbolicLinks){
        UserRightsAssignment 'UserRightsAssignment(INF): Create_symbolic_links'
        {
            Force = $True
            Identity = @('*S-1-5-32-544')
            Policy = 'Create_symbolic_links'
        }
    }

    if($RestrictClientsToMakeRemoteCallsToSAM){
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

    RefreshRegistryPolicy 'ActivateClientSideExtension'
    {
        IsSingleInstance = 'Yes'
    }
}

