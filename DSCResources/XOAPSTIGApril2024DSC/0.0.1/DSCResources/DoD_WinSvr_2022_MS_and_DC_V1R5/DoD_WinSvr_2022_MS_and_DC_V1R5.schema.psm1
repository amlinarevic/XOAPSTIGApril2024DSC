configuration DoD_WinSvr_2022_MS_and_DC_V1R5
{

    param(
        [System.String]$EnterpriseAdmins,
        [System.String]$DomianAdmins,
        [System.Boolean]$EnumerateAdministrators = $true,
        [System.Boolean]$NoAutorun = $true,
        [System.Boolean]$NoDriveTypeAutoRun = $true,
        [System.Boolean]$PreXPSP2ShellProtocolBehavior = $true,
        [System.Boolean]$PasswordLength = $true,
        [System.Boolean]$PasswordAgeDays = $true,
        [System.Boolean]$DisableAutomaticRestartSignOn = $true,
        [System.Boolean]$LocalAccountTokenFilterPolicy = $true,
        [System.Boolean]$ProcessCreationIncludeCmdLine_Enabled = $true,
        [System.Boolean]$DisableEnclosureDownload = $true,
        [System.Boolean]$AllowBasicAuthInClear = $true,
        [System.Boolean]$DCSettingIndex = $true,
        [System.Boolean]$ACSettingIndex = $true,
        [System.Boolean]$DisableInventory = $true,
        [System.Boolean]$AllowProtectedCreds = $true,
        [System.Boolean]$AllowTelemetry = $true,
        [System.Boolean]$DODownloadMode = $true,
        [System.Boolean]$EnableVirtualizationBasedSecurity = $true,
        [System.Boolean]$RequirePlatformSecurityFeatures = $true,
        [System.Boolean]$HypervisorEnforcedCodeIntegrity = $true,
        [System.Boolean]$HVCIMATRequired = $true,
        [System.Boolean]$LsaCfgFlags = $true,
        [System.Boolean]$ConfigureSystemGuardLaunch = $true,
        [System.Boolean]$ApplicationLogMaxSize = $true,
        [System.Boolean]$SecurityLogMaxSize = $true,
        [System.Boolean]$SystemLogMaxSize = $true,
        [System.Boolean]$NoAutoplayfornonVolume = $true,
        [System.Boolean]$NoDataExecutionPrevention = $true,
        [System.Boolean]$NoHeapTerminationOnCorruption = $true,
        [System.Boolean]$NoBackgroundPolicy = $true,
        [System.Boolean]$NoGPOListChanges = $true,
        [System.Boolean]$EnableUserControl = $true,
        [System.Boolean]$AlwaysInstallElevated = $true,
        [System.Boolean]$SafeForScripting = $true,
        [System.Boolean]$AllowInsecureGuestAuth = $true,
        [System.Boolean]$HardenedPathsSysvol = $true,
        [System.Boolean]$HardenedPathsNetlogon = $true,
        [System.Boolean]$NoLockScreenSlideshow = $true,
        [System.Boolean]$EnableScriptBlockLogging = $true,
        [System.Boolean]$EnableScriptBlockInvocationLogging = $true,
        [System.Boolean]$EnableTranscripting = $true,
        [System.Boolean]$OutputDirectory = $true,
        [System.Boolean]$EnableInvocationHeader = $true,
        [System.Boolean]$DontDisplayNetworkSelectionUI = $true,
        [System.Boolean]$EnableSmartScreen = $true,
        [System.Boolean]$ShellSmartScreenLevel = $true,
        [System.Boolean]$EnumerateLocalUsers = $true,
        [System.Boolean]$AllowIndexingEncryptedStoresOrItems = $true,
        [System.Boolean]$WinRMClientAllowBasic = $true,
        [System.Boolean]$WinRMClientAllowUnencryptedTraffic = $true,
        [System.Boolean]$WinRMClientAllowDigest = $true,
        [System.Boolean]$WinRMServiceAllowBasic = $true,
        [System.Boolean]$WinRMServiceAllowUnencryptedTraffic = $true,
        [System.Boolean]$WinRMServiceDisableRunAs = $true,
        [System.Boolean]$DisableWebPnPDownload = $true,
        [System.Boolean]$DisableHTTPPrinting = $true,
        [System.Boolean]$RestrictRemoteClients = $true,
        [System.Boolean]$DisablePasswordSaving = $true,
        [System.Boolean]$DisableCdm = $true,
        [System.Boolean]$PromptForPassword = $true,
        [System.Boolean]$MinEncryptionLevel = $true,
        [System.Boolean]$UseLogonCredential = $true,
        [System.Boolean]$DriverLoadPolicy = $true,
        [System.Boolean]$SMB1 = $true,
        [System.Boolean]$MrxSmb10Start = $true,
        [System.Boolean]$NoNameReleaseOnDemand = $true,
        [System.Boolean]$DisableIPSourceRouting = $true,
        [System.Boolean]$EnableICMPRedirect = $true,
        [System.Boolean]$DisableIPSourceRoutingV6 = $true,
        [System.Boolean]$EncryptRPCTraffic = $true,
        [System.Boolean]$AuditCredentialValidationSuccess = $true,
        [System.Boolean]$AuditCredentialValidationFailure = $true,
        [System.Boolean]$AuditOtherAccountManagementSuccess = $true,
        [System.Boolean]$AuditOtherAccountManagementFailure = $true,
        [System.Boolean]$AuditSecurityGroupManagementSuccess = $true,
        [System.Boolean]$AuditSecurityGroupManagementFailure = $true,
        [System.Boolean]$AuditUserAccountManagementSuccess = $true,
        [System.Boolean]$AuditUserAccountManagementFailure = $true,
        [System.Boolean]$AuditPNPActivitySuccess = $true,
        [System.Boolean]$AuditPNPActivityFailure = $true,
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
        [System.Boolean]$AuditComputerAccountManagementSuccess = $true,
        [System.Boolean]$AuditComputerAccountManagementFailure = $true,
        [System.Boolean]$AuditDirectoryServiceAccessSuccess = $true,
        [System.Boolean]$AuditDirectoryServiceAccessFailure = $true,
        [System.Boolean]$AuditDirectoryServiceChangesSuccess = $true,
        [System.Boolean]$AuditDirectoryServiceChangesFailure = $true,
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
        [System.Boolean]$NetworkSecurityDoNotStoreLMHash = $true,
        [System.Boolean]$MicrosoftServerDigiSignCommAlways = $true,
        [System.Boolean]$InteractiveLogonCacheLogons = $true,
        [System.Boolean]$InteractiveLogonInactivityLimit = $true,
        [System.Boolean]$StrongKeyProtection = $true,
        [System.Boolean]$InteractiveLogonMessageTitle = $true,
        [System.Boolean]$UserAccountControlElevateUIAccess = $true,
        [System.Boolean]$DomainMemberDigiEncryptSecureChannel = $true,
        [System.Boolean]$NetworkAccessRestrictRemoteCallsToSAM = $true,
        [System.Boolean]$MinSessionSecurityForNTLM = $true,
        [System.Boolean]$AllowLocalSystemNTLM = $true,
        [System.Boolean]$ConfigureKerberosEncryptionTypes = $true,
        [System.Boolean]$UACDetectAppInstallations = $true,
        [System.Boolean]$MicrosoftClientDigiSignCommAlways = $true,
        [System.Boolean]$UACBehaviorPromptElevateAdmin = $true,
        [System.Boolean]$RestrictAnonymousAccessNamedPipes = $true,
        [System.Boolean]$DisableMachineAccountPasswordChanges = $true,
        [System.Boolean]$DigiEncryptSignSecureChannelAlways = $true,
        [System.Boolean]$AllowPKU2UAuthentication = $true,
        [System.Boolean]$MaxMachineAccountPasswordAge = $true,
        [System.Boolean]$LimitLocalAccountBlankPasswords = $true,
        [System.Boolean]$StrengthenDefaultPermissions = $true,
        [System.Boolean]$ForceAuditPolicySubcategorySettings = $true,
        [System.Boolean]$LDAPClientSigningRequirements = $true,
        [System.Boolean]$AllowUIAccessElevationWithoutSecureDesktop = $true,
        [System.Boolean]$SendUnencryptedPasswordToThirdPartySMB = $true,
        [System.Boolean]$SmartCardRemovalBehavior = $true,
        [System.Boolean]$VirtualizeWriteFailuresToPerUser = $true,
        [System.Boolean]$RunAllAdminsInAdminApprovalMode = $true,
        [System.Boolean]$DontAllowAnonymousEnumerationOfSAMAccounts = $true,
        [System.Boolean]$MinSessionSecurityForNTLMSP = $true,
        [System.Boolean]$AdminApprovalModeForBuiltInAdmin = $true,
        [System.Boolean]$LetEveryonePermissionsApplyToAnonymous = $true,
        [System.Boolean]$LANManagerAuthenticationLevel = $true,
        [System.Boolean]$ElevationPromptForStandardUsers = $true,
        [System.Boolean]$SignCommunicationsIfClientAgrees = $true,
        [System.Boolean]$DigiSignSecureChannelDataWhenPossible = $true,
        [System.Boolean]$RequireStrongSessionKey = $true,
        [System.Boolean]$SignCommunicationsIfServerAgrees = $true,
        [System.Boolean]$UseFIPSCompliantAlgorithms = $true,
        [System.Boolean]$AllowLocalSystemNullSessionFallback = $true,
        [System.Boolean]$CreateGlobalObjects = $true,
        [System.Boolean]$CreatePagefile = $true,
        [System.Boolean]$AllowLogOnLocally = $true,
        [System.Boolean]$LockPagesInMemory = $true,
        [System.Boolean]$DenyLogOnLocally = $true,
        [System.Boolean]$DenyLogOnAsAService = $true,
        [System.Boolean]$TakeOwnershipOfFiles = $true,
        [System.Boolean]$PerformVolumeMaintenanceTasks = $true,
        [System.Boolean]$CreateTokenObject = $true,
        [System.Boolean]$AccessCredentialManager = $true,
        [System.Boolean]$DebugPrograms = $true,
        [System.Boolean]$ModifyFirmwareValues = $true,
        [System.Boolean]$LoadUnloadDeviceDrivers = $true,
        [System.Boolean]$DenyAccessToComputerFromNetwork = $true,
        [System.Boolean]$AccessComputerFromNetwork = $true,
        [System.Boolean]$RestoreFilesAndDirectories = $true,
        [System.Boolean]$IncreaseSchedulingPriority = $true,
        [System.Boolean]$EnableTrustForDelegation = $true,
        [System.Boolean]$BackUpFilesAndDirectories = $true,
        [System.Boolean]$GenerateSecurityAudits = $true,
        [System.Boolean]$ProfileSingleProcess = $true,
        [System.Boolean]$DenyLogOnAsBatchJob = $true,
        [System.Boolean]$ActAsPartOfOperatingSystem = $true,
        [System.Boolean]$ForceShutdownFromRemote = $true,
        [System.Boolean]$ImpersonateClientAfterAuth = $true,
        [System.Boolean]$DenyLogOnThroughRDS = $true,
        [System.Boolean]$CreatePermanentSharedObjects = $true,
        [System.Boolean]$ManageAuditingAndSecurityLog = $true,
        [System.Boolean]$CreateSymbolicLinks = $true,
        [System.Boolean]$AddWorkstationsToDomain = $true,
        [System.Boolean]$AllowLogOnThroughRDS = $true,
        [System.Boolean]$RefuseMachineAccountPasswordChanges = $true,
        [System.Boolean]$LDAPServerSigningRequirements = $true,
        [System.Boolean]$EnforceUserLogonRestrictions = $true,
        [System.Boolean]$MaxRenewAge = $true
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
    
    if($PasswordComplexity){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\LAPS\PasswordComplexity'
        {
            Key = 'Software\Microsoft\Windows\CurrentVersion\Policies\LAPS'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 4
            ValueName = 'PasswordComplexity'
        }
    }
    
    if($PasswordLength){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\LAPS\PasswordLength'
        {
            Key = 'Software\Microsoft\Windows\CurrentVersion\Policies\LAPS'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 14
            ValueName = 'PasswordLength'
        }
    }
    
    if($PasswordAgeDays){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\LAPS\PasswordAgeDays'
        {
            Key = 'Software\Microsoft\Windows\CurrentVersion\Policies\LAPS'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 60
            ValueName = 'PasswordAgeDays'
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
    
    if($AllowBasicAuthInClear){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Feeds\AllowBasicAuthInClear'
        {
            Key = 'Software\Policies\Microsoft\Internet Explorer\Feeds'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'AllowBasicAuthInClear'
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
    
    if($AllowProtectedCreds){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CredentialsDelegation\AllowProtectedCreds'
        {
            Key = 'Software\Policies\Microsoft\Windows\CredentialsDelegation'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'AllowProtectedCreds'
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
    
    if($DODownloadMode){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\DeliveryOptimization\DODownloadMode'
        {
            Key = 'Software\Policies\Microsoft\Windows\DeliveryOptimization'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 2
            ValueName = 'DODownloadMode'
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
            ValueData = 3
            ValueName = 'HypervisorEnforcedCodeIntegrity'
        }
    }
    
    if($HVCIMATRequired){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\DeviceGuard\HVCIMATRequired'
        {
            Key = 'Software\Policies\Microsoft\Windows\DeviceGuard'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'HVCIMATRequired'
        }
    }
    
    if($LsaCfgFlags){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\DeviceGuard\LsaCfgFlags'
        {
            Key = 'Software\Policies\Microsoft\Windows\DeviceGuard'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'LsaCfgFlags'
        }
    }
    
    if($ConfigureSystemGuardLaunch){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\DeviceGuard\ConfigureSystemGuardLaunch'
        {
            Key = 'Software\Policies\Microsoft\Windows\DeviceGuard'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'ConfigureSystemGuardLaunch'
        }
    }
    
    if($ApplicationLogMaxSize){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\EventLog\Application\MaxSize'
        {
            Key = 'Software\Policies\Microsoft\Windows\EventLog\Application'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 32768
            ValueName = 'MaxSize'
        }
    }
    
    if($SecurityLogMaxSize){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\EventLog\Security\MaxSize'
        {
            Key = 'Software\Policies\Microsoft\Windows\EventLog\Security'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 196608
            ValueName = 'MaxSize'
        }
    }
    
    if($SystemLogMaxSize){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\EventLog\System\MaxSize'
        {
            Key = 'Software\Policies\Microsoft\Windows\EventLog\System'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 32768
            ValueName = 'MaxSize'
        }
    }
    
    if($NoAutoplayfornonVolume){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\Explorer\NoAutoplayfornonVolume'
        {
            Key = 'Software\Policies\Microsoft\Windows\Explorer'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'NoAutoplayfornonVolume'
        }
    }
    
    if($NoDataExecutionPrevention){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\Explorer\NoDataExecutionPrevention'
        {
            Key = 'Software\Policies\Microsoft\Windows\Explorer'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'NoDataExecutionPrevention'
        }
    }
    
    if($NoHeapTerminationOnCorruption){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\Explorer\NoHeapTerminationOnCorruption'
        {
            Key = 'Software\Policies\Microsoft\Windows\Explorer'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'NoHeapTerminationOnCorruption'
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
    
    if($SafeForScripting){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\Installer\SafeForScripting'
        {
            Key = 'Software\Policies\Microsoft\Windows\Installer'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'SafeForScripting'
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
    
    if($HardenedPathsSysvol){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths\*\SYSVOL'
        {
            Key = 'Software\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths'
            TargetType = 'ComputerConfiguration'
            ValueType = 'String'
            ValueData = 'RequireMutualAuthentication=1, RequireIntegrity=1'
            ValueName = '\\*\SYSVOL'
        }
    }
    
    if($HardenedPathsNetlogon){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths\*\NETLOGON'
        {
            Key = 'Software\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths'
            TargetType = 'ComputerConfiguration'
            ValueType = 'String'
            ValueData = 'RequireMutualAuthentication=1, RequireIntegrity=1'
            ValueName = '\\*\NETLOGON'
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
    
    if($ShellSmartScreenLevel){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\System\ShellSmartScreenLevel'
        {
            Key = 'Software\Policies\Microsoft\Windows\System'
            TargetType = 'ComputerConfiguration'
            ValueType = 'String'
            ValueData = 'Block'
            ValueName = 'ShellSmartScreenLevel'
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
    
    if($RestrictRemoteClients){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows NT\Rpc\RestrictRemoteClients'
        {
            Key = 'Software\Policies\Microsoft\Windows NT\Rpc'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'RestrictRemoteClients'
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
    
    if($DisableCdm){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\fDisableCdm'
        {
            Key = 'Software\Policies\Microsoft\Windows NT\Terminal Services'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'fDisableCdm'
        }
    }
    
    if($PromptForPassword){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\fPromptForPassword'
        {
            Key = 'Software\Policies\Microsoft\Windows NT\Terminal Services'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'fPromptForPassword'
        }
    }
    if($EncryptRPCTraffic){
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
        RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential'
        {
            Key = 'SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'UseLogonCredential'
        }
    }
    
    if($DriverLoadPolicy){
        RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch\DriverLoadPolicy'
        {
            Key = 'SYSTEM\CurrentControlSet\Policies\EarlyLaunch'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 3
            ValueName = 'DriverLoadPolicy'
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
    
    if($MrxSmb10Start){
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
    
    if($DisableIPSourceRoutingV6){
        RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\DisableIPSourceRouting'
        {
            Key = 'SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 2
            ValueName = 'DisableIPSourceRouting'
        }
    }
    if($EncryptRPCTraffic){
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
        RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential'
        {
            Key = 'SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'UseLogonCredential'
        }
    }
    
    if($DriverLoadPolicy){
        RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch\DriverLoadPolicy'
        {
            Key = 'SYSTEM\CurrentControlSet\Policies\EarlyLaunch'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 3
            ValueName = 'DriverLoadPolicy'
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
    
    if($MrxSmb10Start){
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
    
    if($DisableIPSourceRoutingV6){
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
    
    if($AuditOtherAccountManagementSuccess){
        AuditPolicySubcategory 'Audit Other Account Management Events (Success) - Inclusion'
        {
            Name = 'Other Account Management Events'
            Ensure = 'Present'
            AuditFlag = 'Success'
        }
    }
    
    if($AuditOtherAccountManagementFailure){
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
    
    if($AuditPNPActivitySuccess){
        AuditPolicySubcategory 'Audit PNP Activity (Success) - Inclusion'
        {
            Name = 'Plug and Play Events'
            Ensure = 'Present'
            AuditFlag = 'Success'
        }
    }
    
    if($AuditPNPActivityFailure){
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
    
    if($NetworkSecurityDoNotStoreLMHash){
        SecurityOption 'SecurityRegistry(INF): Network_security_Do_not_store_LAN_Manager_hash_value_on_next_password_change'
        {
            Name = 'Network_security_Do_not_store_LAN_Manager_hash_value_on_next_password_change'
            Network_security_Do_not_store_LAN_Manager_hash_value_on_next_password_change = 'Enabled'
        }
    }
    
    if($MicrosoftServerDigiSignCommAlways){
        SecurityOption 'SecurityRegistry(INF): Microsoft_network_server_Digitally_sign_communications_always'
        {
            Name = 'Microsoft_network_server_Digitally_sign_communications_always'
            Microsoft_network_server_Digitally_sign_communications_always = 'Enabled'
        }
    }
    
    if($InteractiveLogonCacheLogons){
        SecurityOption 'SecurityRegistry(INF): Interactive_logon_Number_of_previous_logons_to_cache_in_case_domain_controller_is_not_available'
        {
            Name = 'Interactive_logon_Number_of_previous_logons_to_cache_in_case_domain_controller_is_not_available'
            Interactive_logon_Number_of_previous_logons_to_cache_in_case_domain_controller_is_not_available = '4'
        }
    }
    
    if($InteractiveLogonInactivityLimit){
        SecurityOption 'SecurityRegistry(INF): Interactive_logon_Machine_inactivity_limit'
        {
            Name = 'Interactive_logon_Machine_inactivity_limit'
            Interactive_logon_Machine_inactivity_limit = '900'
        }
    }
    
    if($StrongKeyProtection){
        SecurityOption 'SecurityRegistry(INF): System_cryptography_Force_strong_key_protection_for_user_keys_stored_on_the_computer'
        {
            Name = 'System_cryptography_Force_strong_key_protection_for_user_keys_stored_on_the_computer'
            System_cryptography_Force_strong_key_protection_for_user_keys_stored_on_the_computer = 'User must enter a password each time they use a key'
        }
    }
    
    if($InteractiveLogonMessageTitle){
        SecurityOption 'SecurityRegistry(INF): Interactive_logon_Message_title_for_users_attempting_to_log_on'
        {
            Name = 'Interactive_logon_Message_title_for_users_attempting_to_log_on'
            Interactive_logon_Message_title_for_users_attempting_to_log_on = 'US Department of Defense Warning Statement'
        }
    }
    
    if($UserAccountControlElevateUIAccess){
        SecurityOption 'SecurityRegistry(INF): User_Account_Control_Only_elevate_UIAccess_applications_that_are_installed_in_secure_locations'
        {
            Name = 'User_Account_Control_Only_elevate_UIAccess_applications_that_are_installed_in_secure_locations'
            User_Account_Control_Only_elevate_UIAccess_applications_that_are_installed_in_secure_locations = 'Enabled'
        }
    }
    
    if($DomainMemberDigiEncryptSecureChannel){
        SecurityOption 'SecurityRegistry(INF): Domain_member_Digitally_encrypt_secure_channel_data_when_possible'
        {
            Name = 'Domain_member_Digitally_encrypt_secure_channel_data_when_possible'
            Domain_member_Digitally_encrypt_secure_channel_data_when_possible = 'Enabled'
        }
    }
    
    if($NetworkAccessRestrictRemoteCallsToSAM){
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
    
    if($MinSessionSecurityForNTLM){
        SecurityOption 'SecurityRegistry(INF): Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_servers'
        {
            Name = 'Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_servers'
            Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_servers = 'Both options checked'
        }
    }
    
    if($AllowLocalSystemNTLM){
        SecurityOption 'SecurityRegistry(INF): Network_security_Allow_Local_System_to_use_computer_identity_for_NTLM'
        {
            Name = 'Network_security_Allow_Local_System_to_use_computer_identity_for_NTLM'
            Network_security_Allow_Local_System_to_use_computer_identity_for_NTLM = 'Enabled'
        }
    }
    
    if($ConfigureKerberosEncryptionTypes){
        SecurityOption 'SecurityRegistry(INF): Network_security_Configure_encryption_types_allowed_for_Kerberos'
        {
            Name = 'Network_security_Configure_encryption_types_allowed_for_Kerberos'
            Network_security_Configure_encryption_types_allowed_for_Kerberos = '2147483640'
        }
    }
    
    if($UACDetectAppInstallations){
        SecurityOption 'SecurityRegistry(INF): User_Account_Control_Detect_application_installations_and_prompt_for_elevation'
        {
            Name = 'User_Account_Control_Detect_application_installations_and_prompt_for_elevation'
            User_Account_Control_Detect_application_installations_and_prompt_for_elevation = 'Enabled'
        }
    }
    
    if($MicrosoftClientDigiSignCommAlways){
        SecurityOption 'SecurityRegistry(INF): Microsoft_network_client_Digitally_sign_communications_always'
        {
            Name = 'Microsoft_network_client_Digitally_sign_communications_always'
            Microsoft_network_client_Digitally_sign_communications_always = 'Enabled'
        }
    }
    
    if($UACBehaviorPromptElevateAdmin){
        SecurityOption 'SecurityRegistry(INF): User_Account_Control_Behavior_of_the_elevation_prompt_for_administrators_in_Admin_Approval_Mode'
        {
            Name = 'User_Account_Control_Behavior_of_the_elevation_prompt_for_administrators_in_Admin_Approval_Mode'
            User_Account_Control_Behavior_of_the_elevation_prompt_for_administrators_in_Admin_Approval_Mode = 'Prompt for consent on the secure desktop'
        }
    }
    
    if($RestrictAnonymousAccessNamedPipes){
        SecurityOption 'SecurityRegistry(INF): Network_access_Restrict_anonymous_access_to_Named_Pipes_and_Shares'
        {
            Name = 'Network_access_Restrict_anonymous_access_to_Named_Pipes_and_Shares'
            Network_access_Restrict_anonymous_access_to_Named_Pipes_and_Shares = 'Enabled'
        }
    }
    if($DisableMachineAccountPasswordChanges){
        SecurityOption 'SecurityRegistry(INF): Domain_member_Disable_machine_account_password_changes'
        {
            Name = 'Domain_member_Disable_machine_account_password_changes'
            Domain_member_Disable_machine_account_password_changes = 'Disabled'
        }
    }
    
    if($DigiEncryptSignSecureChannelAlways){
        SecurityOption 'SecurityRegistry(INF): Domain_member_Digitally_encrypt_or_sign_secure_channel_data_always'
        {
            Name = 'Domain_member_Digitally_encrypt_or_sign_secure_channel_data_always'
            Domain_member_Digitally_encrypt_or_sign_secure_channel_data_always = 'Enabled'
        }
    }
    
    if($AllowPKU2UAuthentication){
        SecurityOption 'SecurityRegistry(INF): Network_Security_Allow_PKU2U_authentication_requests_to_this_computer_to_use_online_identities'
        {
            Name = 'Network_Security_Allow_PKU2U_authentication_requests_to_this_computer_to_use_online_identities'
            Network_Security_Allow_PKU2U_authentication_requests_to_this_computer_to_use_online_identities = 'Disabled'
        }
    }
    
    if($MaxMachineAccountPasswordAge){
        SecurityOption 'SecurityRegistry(INF): Domain_member_Maximum_machine_account_password_age'
        {
            Name = 'Domain_member_Maximum_machine_account_password_age'
            Domain_member_Maximum_machine_account_password_age = '30'
        }
    }
    
    if($LimitLocalAccountBlankPasswords){
        SecurityOption 'SecurityRegistry(INF): Accounts_Limit_local_account_use_of_blank_passwords_to_console_logon_only'
        {
            Name = 'Accounts_Limit_local_account_use_of_blank_passwords_to_console_logon_only'
            Accounts_Limit_local_account_use_of_blank_passwords_to_console_logon_only = 'Enabled'
        }
    }
    
    if($StrengthenDefaultPermissions){
        SecurityOption 'SecurityRegistry(INF): System_objects_Strengthen_default_permissions_of_internal_system_objects_eg_Symbolic_Links'
        {
            Name = 'System_objects_Strengthen_default_permissions_of_internal_system_objects_eg_Symbolic_Links'
            System_objects_Strengthen_default_permissions_of_internal_system_objects_eg_Symbolic_Links = 'Enabled'
        }
    }
    
    if($ForceAuditPolicySubcategorySettings){
        SecurityOption 'SecurityRegistry(INF): Audit_Force_audit_policy_subcategory_settings_Windows_Vista_or_later_to_override_audit_policy_category_settings'
        {
            Name = 'Audit_Force_audit_policy_subcategory_settings_Windows_Vista_or_later_to_override_audit_policy_category_settings'
            Audit_Force_audit_policy_subcategory_settings_Windows_Vista_or_later_to_override_audit_policy_category_settings = 'Enabled'
        }
    }
    
    if($LDAPClientSigningRequirements){
        SecurityOption 'SecurityRegistry(INF): Network_security_LDAP_client_signing_requirements'
        {
            Name = 'Network_security_LDAP_client_signing_requirements'
            Network_security_LDAP_client_signing_requirements = 'Negotiate Signing'
        }
    }
    
    if($AllowUIAccessElevationWithoutSecureDesktop){
        SecurityOption 'SecurityRegistry(INF): User_Account_Control_Allow_UIAccess_applications_to_prompt_for_elevation_without_using_the_secure_desktop'
        {
            Name = 'User_Account_Control_Allow_UIAccess_applications_to_prompt_for_elevation_without_using_the_secure_desktop'
            User_Account_Control_Allow_UIAccess_applications_to_prompt_for_elevation_without_using_the_secure_desktop = 'Disabled'
        }
    }
    
    if($SendUnencryptedPasswordToThirdPartySMB){
        SecurityOption 'SecurityRegistry(INF): Microsoft_network_client_Send_unencrypted_password_to_third_party_SMB_servers'
        {
            Name = 'Microsoft_network_client_Send_unencrypted_password_to_third_party_SMB_servers'
            Microsoft_network_client_Send_unencrypted_password_to_third_party_SMB_servers = 'Disabled'
        }
    }
    
    if($SmartCardRemovalBehavior){
        SecurityOption 'SecurityRegistry(INF): Interactive_logon_Smart_card_removal_behavior'
        {
            Name = 'Interactive_logon_Smart_card_removal_behavior'
            Interactive_logon_Smart_card_removal_behavior = 'Lock workstation'
        }
    }
    
    if($VirtualizeWriteFailuresToPerUser){
        SecurityOption 'SecurityRegistry(INF): User_Account_Control_Virtualize_file_and_registry_write_failures_to_per_user_locations'
        {
            Name = 'User_Account_Control_Virtualize_file_and_registry_write_failures_to_per_user_locations'
            User_Account_Control_Virtualize_file_and_registry_write_failures_to_per_user_locations = 'Enabled'
        }
    }
    
    if($RunAllAdminsInAdminApprovalMode){
        SecurityOption 'SecurityRegistry(INF): User_Account_Control_Run_all_administrators_in_Admin_Approval_Mode'
        {
            Name = 'User_Account_Control_Run_all_administrators_in_Admin_Approval_Mode'
            User_Account_Control_Run_all_administrators_in_Admin_Approval_Mode = 'Enabled'
        }
    }
    
    if($DontAllowAnonymousEnumerationOfSAMAccounts){
        SecurityOption 'SecurityRegistry(INF): Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts'
        {
            Name = 'Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts'
            Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts = 'Enabled'
        }
    }
    
    if($MinSessionSecurityForNTLM){
        SecurityOption 'SecurityRegistry(INF): Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_clients'
        {
            Name = 'Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_clients'
            Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_clients = 'Both options checked'
        }
    }
    
    if($AdminApprovalModeForBuiltInAdmin){
        SecurityOption 'SecurityRegistry(INF): User_Account_Control_Admin_Approval_Mode_for_the_Built_in_Administrator_account'
        {
            Name = 'User_Account_Control_Admin_Approval_Mode_for_the_Built_in_Administrator_account'
            User_Account_Control_Admin_Approval_Mode_for_the_Built_in_Administrator_account = 'Enabled'
        }
    }
    
    if($LetEveryonePermissionsApplyToAnonymous){
        SecurityOption 'SecurityRegistry(INF): Network_access_Let_Everyone_permissions_apply_to_anonymous_users'
        {
            Name = 'Network_access_Let_Everyone_permissions_apply_to_anonymous_users'
            Network_access_Let_Everyone_permissions_apply_to_anonymous_users = 'Disabled'
        }
    }
    
    if($LANManagerAuthenticationLevel){
        SecurityOption 'SecurityRegistry(INF): Network_security_LAN_Manager_authentication_level'
        {
            Name = 'Network_security_LAN_Manager_authentication_level'
            Network_security_LAN_Manager_authentication_level = 'Send NTLMv2 responses only. Refuse LM & NTLM'
        }
    }
    
    if($ElevationPromptForStandardUsers){
        SecurityOption 'SecurityRegistry(INF): User_Account_Control_Behavior_of_the_elevation_prompt_for_standard_users'
        {
            Name = 'User_Account_Control_Behavior_of_the_elevation_prompt_for_standard_users'
            User_Account_Control_Behavior_of_the_elevation_prompt_for_standard_users = 'Automatically deny elevation request'
        }
    }
    if($SignCommunicationsIfClientAgrees){
        SecurityOption 'SecurityRegistry(INF): Microsoft_network_server_Digitally_sign_communications_if_client_agrees'
        {
            Name = 'Microsoft_network_server_Digitally_sign_communications_if_client_agrees'
            Microsoft_network_server_Digitally_sign_communications_if_client_agrees = 'Enabled'
        }
    }
    
    if($DigiSignSecureChannelDataWhenPossible){
        SecurityOption 'SecurityRegistry(INF): Domain_member_Digitally_sign_secure_channel_data_when_possible'
        {
            Name = 'Domain_member_Digitally_sign_secure_channel_data_when_possible'
            Domain_member_Digitally_sign_secure_channel_data_when_possible = 'Enabled'
        }
    }
    
    if($RequireStrongSessionKey){
        SecurityOption 'SecurityRegistry(INF): Domain_member_Require_strong_Windows_2000_or_later_session_key'
        {
            Name = 'Domain_member_Require_strong_Windows_2000_or_later_session_key'
            Domain_member_Require_strong_Windows_2000_or_later_session_key = 'Enabled'
        }
    }
    
    if($SignCommunicationsIfServerAgrees){
        SecurityOption 'SecurityRegistry(INF): Microsoft_network_client_Digitally_sign_communications_if_server_agrees'
        {
            Name = 'Microsoft_network_client_Digitally_sign_communications_if_server_agrees'
            Microsoft_network_client_Digitally_sign_communications_if_server_agrees = 'Enabled'
        }
    }
    
    if($UseFIPSCompliantAlgorithms){
        SecurityOption 'SecurityRegistry(INF): System_cryptography_Use_FIPS_compliant_algorithms_for_encryption_hashing_and_signing'
        {
            Name = 'System_cryptography_Use_FIPS_compliant_algorithms_for_encryption_hashing_and_signing'
            System_cryptography_Use_FIPS_compliant_algorithms_for_encryption_hashing_and_signing = 'Enabled'
        }
    }
    
    if($AllowLocalSystemNullSessionFallback){
        SecurityOption 'SecurityRegistry(INF): Network_security_Allow_LocalSystem_NULL_session_fallback'
        {
            Name = 'Network_security_Allow_LocalSystem_NULL_session_fallback'
            Network_security_Allow_LocalSystem_NULL_session_fallback = 'Disabled'
        }
    }
    
    if($DontAllowAnonymousEnumerationOfSAMAccounts){
        SecurityOption 'SecurityRegistry(INF): Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts_and_shares'
        {
            Name = 'Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts_and_shares'
            Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts_and_shares = 'Enabled'
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
    
    if($CreatePagefile){
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
            Identity = @('*S-1-5-32-546', $EnterpriseAdmins, $DomianAdmins)
            Policy = 'Deny_log_on_locally'
        }
    }
    
    if($DenyLogOnAsAService){
        UserRightsAssignment 'UserRightsAssignment(INF): Deny_log_on_as_a_service'
        {
            Force = $True
            Identity = @($EnterpriseAdmins, $DomianAdmins)
            Policy = 'Deny_log_on_as_a_service'
        }
    }
    
    if($TakeOwnershipOfFiles){
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
    
    if($CreateTokenObject){
        UserRightsAssignment 'UserRightsAssignment(INF): Create_a_token_object'
        {
            Force = $True
            Identity = @('')
            Policy = 'Create_a_token_object'
        }
    }
    
    if($AccessCredentialManager){
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
    
    if($ModifyFirmwareValues){
        UserRightsAssignment 'UserRightsAssignment(INF): Modify_firmware_environment_values'
        {
            Force = $True
            Identity = @('*S-1-5-32-544')
            Policy = 'Modify_firmware_environment_values'
        }
    }
    
    if($LoadUnloadDeviceDrivers){
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
            Identity = @('*S-1-5-114', '*S-1-5-32-546', $EnterpriseAdmins, $DomianAdmins)
            Policy = 'Deny_access_to_this_computer_from_the_network'
        }
    }
    
    if($AccessComputerFromNetwork){
        UserRightsAssignment 'UserRightsAssignment(INF): Access_this_computer_from_the_network'
        {
            Force = $True
            Identity = @('*S-1-5-32-544', '*S-1-5-11')
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
    
    if($EnableTrustForDelegation){
        UserRightsAssignment 'UserRightsAssignment(INF): Enable_computer_and_user_accounts_to_be_trusted_for_delegation'
        {
            Force = $True
            Identity = @('')
            Policy = 'Enable_computer_and_user_accounts_to_be_trusted_for_delegation'
        }
    }
    
    if($BackUpFilesAndDirectories){
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
            Identity = @('*S-1-5-19', '*S-1-5-20')
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
            Identity = @('*S-1-5-32-546', $EnterpriseAdmins, $DomianAdmins)
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
    
    if($ForceShutdownFromRemote){
        UserRightsAssignment 'UserRightsAssignment(INF): Force_shutdown_from_a_remote_system'
        {
            Force = $True
            Identity = @('*S-1-5-32-544')
            Policy = 'Force_shutdown_from_a_remote_system'
        }
    }
    
    if($ImpersonateClientAfterAuth){
        UserRightsAssignment 'UserRightsAssignment(INF): Impersonate_a_client_after_authentication'
        {
            Force = $True
            Identity = @('*S-1-5-32-544', '*S-1-5-19', '*S-1-5-20', '*S-1-5-6')
            Policy = 'Impersonate_a_client_after_authentication'
        }
    }
    
    if($DenyLogOnThroughRDS){
        UserRightsAssignment 'UserRightsAssignment(INF): Deny_log_on_through_Remote_Desktop_Services'
        {
            Force = $True
            Identity = @('*S-1-5-113', '*S-1-5-32-546', $EnterpriseAdmins, $DomianAdmins)
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
    
    if($AddWorkstationsToDomain){
        UserRightsAssignment 'UserRightsAssignment(INF): Add_workstations_to_domain'
        {
            Force = $True
            Identity = @('*S-1-5-32-544')
            Policy = 'Add_workstations_to_domain'
        }
    }
    if($AllowLogOnThroughRDS){
        UserRightsAssignment 'UserRightsAssignment(INF): Allow_log_on_through_Remote_Desktop_Services'
        {
            Force = $True
            Identity = @('*S-1-5-32-544')
            Policy = 'Allow_log_on_through_Remote_Desktop_Services'
        }
    }
    
    if($RefuseMachineAccountPasswordChanges){
        SecurityOption 'SecurityRegistry(INF): Domain_controller_Refuse_machine_account_password_changes'
        {
            Name = 'Domain_controller_Refuse_machine_account_password_changes'
            Domain_controller_Refuse_machine_account_password_changes = 'Disabled'
        }
    }
    
    if($LDAPServerSigningRequirements){
        SecurityOption 'SecurityRegistry(INF): Domain_controller_LDAP_server_signing_requirements'
        {
            Name = 'Domain_controller_LDAP_server_signing_requirements'
            Domain_controller_LDAP_server_signing_requirements = 'Require Signing'
        }
    }
    
    if($EnforceUserLogonRestrictions){
        AccountPolicy 'SecuritySetting(INF): TicketValidateClient'
        {
            Enforce_user_logon_restrictions = 'Enabled'
            Name = 'Enforce_user_logon_restrictions'
        }
    }
    
    if($MaxRenewAge){
        AccountPolicy 'SecuritySetting(INF): MaxRenewAge'
        {
            Maximum_lifetime_for_user_ticket_renewal = 8
            Name = 'Maximum_lifetime_for_user_ticket_renewal'
        }
    }
    RefreshRegistryPolicy 'ActivateClientSideExtension'
    {
        IsSingleInstance = 'Yes'
    }
}

