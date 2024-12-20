configuration DoD_Windows_10_V2R9
{

    param(
        [System.String]$DomainAdmins,
        [System.String]$EnterpriseAdmins,
        [System.Boolean]$IsBatFileRunAsUserSuppressionEnabled = $true,
        [System.Boolean]$IsCmdFileRunAsUserSuppressionEnabled = $true,
        [System.Boolean]$IsExeFileRunAsUserSuppressionEnabled = $true,
        [System.Boolean]$IsMscFileRunAsUserSuppressionEnabled = $true,
        [System.Boolean]$IsAutoConnectAllowedOEMEnabled = $true,
        [System.Boolean]$IsEnumerateAdministratorsEnabled = $true,
        [System.Boolean]$IsNoWebServicesEnabled = $true,
        [System.Boolean]$IsNoAutorunEnabled = $true,
        [System.Boolean]$IsNoDriveTypeAutoRunEnabled = $true,
        [System.Boolean]$IsNoStartBannerEnabled = $true,
        [System.Boolean]$IsPreXPSP2ShellProtocolBehaviorEnabled = $true,
        [System.Boolean]$IsLapsPasswordComplexityEnabled = $true,
        [System.Boolean]$IsLapsPasswordLengthEnabled = $true,
        [System.Boolean]$IsLapsPasswordAgeDaysEnabled = $true,
        [System.Boolean]$IsMsaOptionalEnabled = $true,
        [System.Boolean]$IsDisableAutomaticRestartSignOnEnabled = $true,
        [System.Boolean]$IsLocalAccountTokenFilterPolicyEnabled = $true,
        [System.Boolean]$IsProcessCreationIncludeCmdLineEnabled = $true,
        [System.Boolean]$IsDevicePKInitEnabled = $true,
        [System.Boolean]$IsDevicePKInitBehaviorEnabled = $true,
        [System.Boolean]$IsEnhancedAntiSpoofingEnabled = $true,
        [System.Boolean]$IsUseAdvancedStartupEnabled = $true,
        [System.Boolean]$IsEnableBDEWithNoTPMEnabled = $true,
        [System.Boolean]$IsUseTPMEnabled = $true,
        [System.Boolean]$IsUseTPMPINEnabled = $true,
        [System.Boolean]$IsUseTPMKeyEnabled = $true,
        [System.Boolean]$IsUseTPMKeyPINEnabled = $true,
        [System.Boolean]$IsMinimumPINEnabled = $true,
        [System.Boolean]$IsDisableEnclosureDownloadEnabled = $true,
        [System.Boolean]$IsAllowBasicAuthInClearEnabled = $true,
        [System.Boolean]$IsNotifyDisableIEOptionsEnabled = $true,
        [System.Boolean]$IsPreventCertErrorOverridesEnabled = $true,
        [System.Boolean]$FormSuggestPasswordsSetting = $true,
        [System.Boolean]$IsEnabledV9Enabled = $true,
        [System.Boolean]$IsPreventOverrideAppRepUnknownEnabled = $true,
        [System.Boolean]$IsPreventOverrideEnabled = $true,
        [System.Boolean]$IsRequireSecurityDeviceEnabled = $true,
        [System.Boolean]$IsTPM12Excluded = $true,
        [System.Boolean]$IsMinimumPINLengthEnabled = $true,
        [System.Boolean]$IsDCSettingIndexEnabled = $true,
        [System.Boolean]$IsACSettingIndexEnabled = $true,
        [System.Boolean]$IsDisableInventoryEnabled = $true,
        [System.Boolean]$IsLetAppsActivateWithVoiceAboveLockEnabled = $true,
        [System.Boolean]$IsDisableWindowsConsumerFeaturesEnabled = $true,
        [System.Boolean]$IsAllowProtectedCredsEnabled = $true,
        [System.Boolean]$IsAllowTelemetryEnabled = $true,
        [System.Boolean]$IsLimitEnhancedDiagnosticDataWindowsAnalyticsEnabled = $true,
        [System.Boolean]$IsDODownloadModeEnabled = $true,
        [System.Boolean]$IsEnableVirtualizationBasedSecurityEnabled = $true,
        [System.Boolean]$IsRequirePlatformSecurityFeaturesEnabled = $true,
        [System.Boolean]$IsHypervisorEnforcedCodeIntegrityEnabled = $true,
        [System.Boolean]$IsHVCIMATRequiredEnabled = $true,
        [System.Boolean]$IsLsaCfgFlagsEnabled = $true,
        [System.Boolean]$IsConfigureSystemGuardLaunchEnabled = $true,
        [System.Boolean]$IsMaxSizeApplicationLogEnabled = $true,
        [System.Boolean]$IsMaxSizeSecurityLogEnabled = $true,
        [System.Boolean]$IsMaxSizeSystemLogEnabled = $true,
        [System.Boolean]$IsNoAutoplayForNonVolumeEnabled = $true,
        [System.Boolean]$IsNoDataExecutionPreventionEnabled = $true,
        [System.Boolean]$IsNoHeapTerminationOnCorruptionEnabled = $true,
        [System.Boolean]$IsAllowGameDVREnabled = $true,
        [System.Boolean]$IsNoBackgroundPolicyEnabled = $true,
        [System.Boolean]$IsNoGPOListChangesEnabled = $true,
        [System.Boolean]$IsEnableUserControlEnabled = $true,
        [System.Boolean]$IsAlwaysInstallElevatedEnabled = $true,
        [System.Boolean]$IsSafeForScriptingEnabled = $true,
        [System.Boolean]$IsDeviceEnumerationPolicyEnabled = $true,
        [System.Boolean]$IsAllowInsecureGuestAuthEnabled = $true,
        [System.Boolean]$IsNCShowSharedAccessUIEnabled = $true,
        [System.Boolean]$IsBlockingNonDomainEnabled = $true,
        [System.Boolean]$IsMinimizeConnectionsEnabled = $true,
        [System.Boolean]$IsAllowIndexingEncryptedStoresEnabled = $true,
        [System.Boolean]$IsWinRMAllowBasicEnabled = $true,
        [System.Boolean]$IsWinRMAllowUnencryptedTrafficEnabled = $true,
        [System.Boolean]$IsWinRMAllowDigestEnabled = $true,
        [System.Boolean]$IsWinRMServiceAllowBasicEnabled = $true,
        [System.Boolean]$IsWinRMServiceAllowUnencryptedTrafficEnabled = $true,
        [System.Boolean]$IsDisableRunAsEnabled = $true,
        [System.Boolean]$IsDisableWebPnPDownloadEnabled = $true,
        [System.Boolean]$IsDisableHTTPPrintingEnabled = $true,
        [System.Boolean]$IsRestrictRemoteClientsEnabled = $true,
        [System.Boolean]$IsAllowToGetHelpEnabled = $true,
        [System.Boolean]$IsAllowFullControlEnabled = $true,
        [System.Boolean]$IsMaxTicketExpiryEnabled = $true,
        [System.Boolean]$IsMaxTicketExpiryUnitsEnabled = $true,
        [System.Boolean]$IsUseMailtoEnabled = $true,
        [System.Boolean]$IsDisablePasswordSavingEnabled = $true,
        [System.Boolean]$IsDisableCdmEnabled = $true,
        [System.Boolean]$IsPromptForPasswordEnabled = $true,
        [System.Boolean]$IsEncryptRPCTrafficEnabled = $true,
        [System.Boolean]$IsMinEncryptionLevelEnabled = $true,
        [System.Boolean]$IsAllowWindowsInkWorkspaceEnabled = $true,
        [System.Boolean]$IsUseLogonCredentialEnabled = $true,
        [System.Boolean]$IsDisableExceptionChainValidationEnabled = $true,
        [System.Boolean]$IsDriverLoadPolicyEnabled = $true,
        [System.Boolean]$IsSMB1Enabled = $true,
        [System.Boolean]$IsMrxSmb10StartEnabled = $true,
        [System.Boolean]$IsNoNameReleaseOnDemandEnabled = $true,
        [System.Boolean]$IsDisableIPSourceRoutingEnabled = $true,
        [System.Boolean]$IsEnableICMPRedirectEnabled = $true,
        [System.Boolean]$IsDisableIPSourceRoutingIPv6Enabled = $true,
        [System.Boolean]$IsCredentialValidationSuccessEnabled = $true,
        [System.Boolean]$IsCredentialValidationFailureEnabled = $true,
        [System.Boolean]$IsSecurityGroupManagementSuccessEnabled = $true,
        [System.Boolean]$IsSecurityGroupManagementFailureEnabled = $true,
        [System.Boolean]$IsUserAccountManagementSuccessEnabled = $true,
        [System.Boolean]$IsUserAccountManagementFailureEnabled = $true,
        [System.Boolean]$IsPnpActivitySuccessEnabled = $true,
        [System.Boolean]$IsPnpActivityFailureEnabled = $true,
        [System.Boolean]$IsProcessCreationSuccessEnabled = $true,
        [System.Boolean]$IsProcessCreationFailureEnabled = $true,
        [System.Boolean]$IsAccountLockoutFailureEnabled = $true,
        [System.Boolean]$IsAccountLockoutSuccessEnabled = $true,
        [System.Boolean]$IsGroupMembershipSuccessEnabled = $true,
        [System.Boolean]$IsGroupMembershipFailureEnabled = $true,
        [System.Boolean]$IsLogoffSuccessEnabled = $true,
        [System.Boolean]$IsLogoffFailureEnabled = $true,
        [System.Boolean]$IsLogonSuccessEnabled = $true,
        [System.Boolean]$IsLogonFailureEnabled = $true,
        [System.Boolean]$IsOtherLogonLogoffEventsSuccessEnabled = $true,
        [System.Boolean]$IsOtherLogonLogoffEventsFailureEnabled = $true,
        [System.Boolean]$IsSpecialLogonSuccessEnabled = $true,
        [System.Boolean]$IsSpecialLogonFailureEnabled = $true,
        [System.Boolean]$IsDetailedFileShareFailureEnabled = $true,
        [System.Boolean]$IsDetailedFileShareSuccessEnabled = $true,
        [System.Boolean]$IsFileShareSuccessEnabled = $true,
        [System.Boolean]$IsFileShareFailureEnabled = $true,
        [System.Boolean]$IsOtherObjectAccessEventsSuccessEnabled = $true,
        [System.Boolean]$IsOtherObjectAccessEventsFailureEnabled = $true,
        [System.Boolean]$IsRemovableStorageSuccessEnabled = $true,
        [System.Boolean]$IsRemovableStorageFailureEnabled = $true,
        [System.Boolean]$IsAuditPolicyChangeSuccessEnabled = $true,
        [System.Boolean]$IsAuditPolicyChangeFailureEnabled = $true,
        [System.Boolean]$IsAuthenticationPolicyChangeSuccessEnabled = $true,
        [System.Boolean]$IsAuthenticationPolicyChangeFailureEnabled = $true,
        [System.Boolean]$IsAuthorizationPolicyChangeSuccessEnabled = $true,
        [System.Boolean]$IsAuthorizationPolicyChangeFailureEnabled = $true,
        [System.Boolean]$IsMpssvcRuleLevelPolicyChangeSuccessEnabled = $true,
        [System.Boolean]$IsMpssvcRuleLevelPolicyChangeFailureEnabled = $true,
        [System.Boolean]$IsOtherPolicyChangeEventsFailureEnabled = $true,
        [System.Boolean]$IsOtherPolicyChangeEventsSuccessEnabled = $true,
        [System.Boolean]$IsSensitivePrivilegeUseSuccessEnabled = $true,
        [System.Boolean]$IsSensitivePrivilegeUseFailureEnabled = $true,
        [System.Boolean]$IsIpsecDriverFailureEnabled = $true,
        [System.Boolean]$IsIpsecDriverSuccessEnabled = $true,
        [System.Boolean]$IsOtherSystemEventsSuccessEnabled = $true,
        [System.Boolean]$IsOtherSystemEventsFailureEnabled = $true,
        [System.Boolean]$IsSecurityStateChangeSuccessEnabled = $true,
        [System.Boolean]$IsSecurityStateChangeFailureEnabled = $true,
        [System.Boolean]$IsSecuritySystemExtensionSuccessEnabled = $true,
        [System.Boolean]$IsSecuritySystemExtensionFailureEnabled = $true,
        [System.Boolean]$IsSystemIntegritySuccessEnabled = $true,
        [System.Boolean]$IsSystemIntegrityFailureEnabled = $true,
        [System.Boolean]$IsNetworkSecurityDoNotStoreLANManagerHashEnabled = $true,
        [System.Boolean]$IsMicrosoftNetworkServerDigitallySignCommunicationsEnabled = $true,
        [System.Boolean]$IsInteractiveLogonNumberOfPreviousLogonsEnabled = $true,
        [System.Boolean]$IsInteractiveLogonMachineInactivityLimitEnabled = $true,
        [System.Boolean]$IsNetworkAccessLetEveryonePermissionsApplyEnabled = $true,
        [System.Boolean]$IsUserAccountControlOnlyElevateUIAccessApplicationsEnabled = $true,
        [System.Boolean]$IsDomainMemberDigitallyEncryptSecureChannelDataEnabled = $true,
        [System.Boolean]$IsNetworkAccessRestrictClientsEnabled = $true,
        [System.Boolean]$IsNetworkSecurityMinimumSessionSecurityEnabled = $true,
        [System.Boolean]$IsNetworkSecurityConfigureEncryptionTypesEnabled = $true,
        [System.Boolean]$IsUserAccountControlDetectApplicationsEnabled = $true,
        [System.Boolean]$IsMicrosoftNetworkClientDigitallySignCommunicationsEnabled = $true,
        [System.Boolean]$IsUserAccountControlBehaviorOfTheElevationPromptEnabled = $true,
        [System.Boolean]$IsNetworkAccessRestrictAnonymousAccessEnabled = $true,
        [System.Boolean]$IsInteractiveLogonMessageTextEnabled = $true,
        [System.Boolean]$IsDomainMemberDisableMachineAccountPasswordChangesEnabled = $true,
        [System.Boolean]$IsDomainMemberDigitallyEncryptOrSignSecureChannelDataEnabled = $true,
        [System.Boolean]$IsRequireStrongWindows2000SessionKeyEnabled = $true,
        [System.Boolean]$IsUseFIPSCompliantAlgorithmsEnabled = $true,
        [System.Boolean]$IsAllowLocalSystemNullSessionFallbackEnabled = $true,
        [System.Boolean]$IsDoNotAllowAnonymousEnumerationOfSAMAccountsEnabled = $true,
        [System.Boolean]$IsPKU2UAuthenticationEnabled = $true,
        [System.Boolean]$IsDomainMemberMaxMachineAccountPasswordAgeEnabled = $true,
        [System.Boolean]$IsLimitLocalAccountUseEnabled = $true,
        [System.Boolean]$IsStrengthenInternalSystemObjectsEnabled = $true,
        [System.Boolean]$IsForceAuditPolicyOverrideEnabled = $true,
        [System.Boolean]$IsLDAPClientSigningEnabled = $true,
        [System.Boolean]$IsInteractiveLogonMessageTitleEnabled = $true,
        [System.Boolean]$IsSendUnencryptedPasswordEnabled = $true,
        [System.Boolean]$IsSmartCardRemovalBehaviorEnabled = $true,
        [System.Boolean]$IsVirtualizeWriteFailuresEnabled = $true,
        [System.Boolean]$IsRunAllAdministratorsInAdminApprovalEnabled = $true,
        [System.Boolean]$IsRestrictAnonymousAccessEnabled = $true,
        [System.Boolean]$IsMinimumSessionSecurityEnabled = $true,
        [System.Boolean]$IsAdminApprovalModeForBuiltInAdminEnabled = $true,
        [System.Boolean]$IsLANManagerAuthenticationEnabled = $true,
        [System.Boolean]$IsStandardUserPromptBehaviorEnabled = $true,
        [System.Boolean]$IsDigitallySignSecureChannelDataEnabled = $true,
        [System.Boolean]$IsCreateTokenObjectEnabled = $true,
        [System.Boolean]$IsChangeSystemTimeEnabled = $true,
        [System.Boolean]$IsAccessCredentialManagerEnabled = $true,
        [System.Boolean]$IsDebugProgramsEnabled = $true,
        [System.Boolean]$IsModifyFirmwareEnvironmentValuesEnabled = $true,
        [System.Boolean]$IsLoadUnloadDeviceDriversEnabled = $true,
        [System.Boolean]$IsDenyAccessToNetworkEnabled = $true,
        [System.Boolean]$IsAccessComputerFromNetworkEnabled = $true,
        [System.Boolean]$IsRestoreFilesAndDirectoriesEnabled = $true,
        [System.Boolean]$IsEnableTrustedDelegationEnabled = $true,
        [System.Boolean]$IsBackUpFilesAndDirectoriesEnabled = $true,
        [System.Boolean]$IsProfileSingleProcessEnabled = $true,
        [System.Boolean]$IsDenyLogOnAsBatchJobEnabled = $true,
        [System.Boolean]$IsActAsPartOfOperatingSystemEnabled = $true,
        [System.Boolean]$IsForceShutdownFromRemoteSystemEnabled = $true,
        [System.Boolean]$IsImpersonateClientAfterAuthenticationEnabled = $true,
        [System.Boolean]$IsDenyLogOnThroughRemoteDesktopEnabled = $true,
        [System.Boolean]$IsCreatePermanentSharedObjectsEnabled = $true,
        [System.Boolean]$IsManageAuditingAndSecurityLogEnabled = $true,
        [System.Boolean]$IsCreateSymbolicLinksEnabled = $true,
        [System.Boolean]$IsResetAccountLockoutCounterEnabled = $true,
        [System.Boolean]$IsAllowAnonymousSIDNameTranslationEnabled = $true,
        [System.Boolean]$IsAccountLockoutDurationEnabled = $true,
        [System.Boolean]$IsRenameAdministratorAccountEnabled = $true,
        [System.Boolean]$IsEnforcePasswordHistoryEnabled = $true,
        [System.Boolean]$IsMinimumPasswordLengthEnabled = $true,
        [System.Boolean]$IsMinimumPasswordAgeEnabled = $true,
        [System.Boolean]$IsStorePasswordsUsingReversibleEncryptionEnabled = $true,
        [System.Boolean]$IsRenameGuestAccountEnabled = $true,
        [System.Boolean]$IsGuestAccountStatusEnabled = $true,
        [System.Boolean]$IsAccountLockoutThresholdEnabled = $true,
        [System.Boolean]$IsPasswordComplexityEnabled = $true,
        [System.Boolean]$IsAdministratorAccountStatusEnabled = $true,
        [System.Boolean]$IsMaximumPasswordAgeEnabled = $true
    )

	Import-DSCResource -ModuleName 'GPRegistryPolicyDsc'
	Import-DSCResource -ModuleName 'AuditPolicyDSC'
	Import-DSCResource -ModuleName 'SecurityPolicyDSC'

    if($IsBatFileRunAsUserSuppressionEnabled){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Classes\batfile\shell\runasuser\SuppressionPolicy'
        {
            Key = 'Software\Classes\batfile\shell\runasuser'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 4096
            ValueName = 'SuppressionPolicy'
        }
    }
    
    if($IsCmdFileRunAsUserSuppressionEnabled){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Classes\cmdfile\shell\runasuser\SuppressionPolicy'
        {
            Key = 'Software\Classes\cmdfile\shell\runasuser'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 4096
            ValueName = 'SuppressionPolicy'
        }
    }
    
    if($IsExeFileRunAsUserSuppressionEnabled){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Classes\exefile\shell\runasuser\SuppressionPolicy'
        {
            Key = 'Software\Classes\exefile\shell\runasuser'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 4096
            ValueName = 'SuppressionPolicy'
        }
    }
    
    if($IsMscFileRunAsUserSuppressionEnabled){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Classes\mscfile\shell\runasuser\SuppressionPolicy'
        {
            Key = 'Software\Classes\mscfile\shell\runasuser'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 4096
            ValueName = 'SuppressionPolicy'
        }
    }
    
    if($IsAutoConnectAllowedOEMEnabled){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\wcmsvc\wifinetworkmanager\config\AutoConnectAllowedOEM'
        {
            Key = 'Software\Microsoft\wcmsvc\wifinetworkmanager\config'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'AutoConnectAllowedOEM'
        }
    }
    
    if($IsEnumerateAdministratorsEnabled){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\CredUI\EnumerateAdministrators'
        {
            Key = 'Software\Microsoft\Windows\CurrentVersion\Policies\CredUI'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'EnumerateAdministrators'
        }
    }
    
    if($IsNoWebServicesEnabled){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoWebServices'
        {
            Key = 'Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'NoWebServices'
        }
    }
    
    if($IsNoAutorunEnabled){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoAutorun'
        {
            Key = 'Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'NoAutorun'
        }
    }
    
    if($IsNoDriveTypeAutoRunEnabled){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoDriveTypeAutoRun'
        {
            Key = 'Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 255
            ValueName = 'NoDriveTypeAutoRun'
        }
    }
    
    if($IsNoStartBannerEnabled){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoStartBanner'
        {
            Key = 'Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'NoStartBanner'
        }
    }
    if($IsPreXPSP2ShellProtocolBehaviorEnabled){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\PreXPSP2ShellProtocolBehavior'
        {
            Key = 'Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'PreXPSP2ShellProtocolBehavior'
        }
    }
    
    if($IsLapsPasswordComplexityEnabled){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\LAPS\PasswordComplexity'
        {
            Key = 'Software\Microsoft\Windows\CurrentVersion\Policies\LAPS'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 4
            ValueName = 'PasswordComplexity'
        }
    }
    
    if($IsLapsPasswordLengthEnabled){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\LAPS\PasswordLength'
        {
            Key = 'Software\Microsoft\Windows\CurrentVersion\Policies\LAPS'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 14
            ValueName = 'PasswordLength'
        }
    }
    
    if($IsLapsPasswordAgeDaysEnabled){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\LAPS\PasswordAgeDays'
        {
            Key = 'Software\Microsoft\Windows\CurrentVersion\Policies\LAPS'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 60
            ValueName = 'PasswordAgeDays'
        }
    }
    
    if($IsMsaOptionalEnabled){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\MSAOptional'
        {
            Key = 'Software\Microsoft\Windows\CurrentVersion\Policies\System'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'MSAOptional'
        }
    }
    
    if($IsDisableAutomaticRestartSignOnEnabled){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\DisableAutomaticRestartSignOn'
        {
            Key = 'Software\Microsoft\Windows\CurrentVersion\Policies\System'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'DisableAutomaticRestartSignOn'
        }
    }
    
    if($IsLocalAccountTokenFilterPolicyEnabled){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\LocalAccountTokenFilterPolicy'
        {
            Key = 'Software\Microsoft\Windows\CurrentVersion\Policies\System'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'LocalAccountTokenFilterPolicy'
        }
    }
    
    if($IsProcessCreationIncludeCmdLineEnabled){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit\ProcessCreationIncludeCmdLine_Enabled'
        {
            Key = 'Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'ProcessCreationIncludeCmdLine_Enabled'
        }
    }
    
    if($IsDevicePKInitEnabled){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\DevicePKInitEnabled'
        {
            Key = 'Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'DevicePKInitEnabled'
        }
    }
    
    if($IsDevicePKInitBehaviorEnabled){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\DevicePKInitBehavior'
        {
            Key = 'Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'DevicePKInitBehavior'
        }
    }
    
    if($IsEnhancedAntiSpoofingEnabled){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Biometrics\FacialFeatures\EnhancedAntiSpoofing'
        {
            Key = 'Software\Policies\Microsoft\Biometrics\FacialFeatures'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'EnhancedAntiSpoofing'
        }
    }
    if($IsUseAdvancedStartupEnabled){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\FVE\UseAdvancedStartup'
        {
            Key = 'Software\Policies\Microsoft\FVE'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'UseAdvancedStartup'
        }
    }
    
    if($IsEnableBDEWithNoTPMEnabled){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\FVE\EnableBDEWithNoTPM'
        {
            Key = 'Software\Policies\Microsoft\FVE'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'EnableBDEWithNoTPM'
        }
    }
    
    if($IsUseTPMEnabled){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\FVE\UseTPM'
        {
            Key = 'Software\Policies\Microsoft\FVE'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 2
            ValueName = 'UseTPM'
        }
    }
    
    if($IsUseTPMPINEnabled){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\FVE\UseTPMPIN'
        {
            Key = 'Software\Policies\Microsoft\FVE'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'UseTPMPIN'
        }
    }
    
    if($IsUseTPMKeyEnabled){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\FVE\UseTPMKey'
        {
            Key = 'Software\Policies\Microsoft\FVE'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 2
            ValueName = 'UseTPMKey'
        }
    }
    
    if($IsUseTPMKeyPINEnabled){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\FVE\UseTPMKeyPIN'
        {
            Key = 'Software\Policies\Microsoft\FVE'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 2
            ValueName = 'UseTPMKeyPIN'
        }
    }
    
    if($IsMinimumPINEnabled){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\FVE\MinimumPIN'
        {
            Key = 'Software\Policies\Microsoft\FVE'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 6
            ValueName = 'MinimumPIN'
        }
    }
    
    if($IsDisableEnclosureDownloadEnabled){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Feeds\DisableEnclosureDownload'
        {
            Key = 'Software\Policies\Microsoft\Internet Explorer\Feeds'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'DisableEnclosureDownload'
        }
    }
    
    if($IsAllowBasicAuthInClearEnabled){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Feeds\AllowBasicAuthInClear'
        {
            Key = 'Software\Policies\Microsoft\Internet Explorer\Feeds'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'AllowBasicAuthInClear'
        }
    }
    
    if($IsNotifyDisableIEOptionsEnabled){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\NotifyDisableIEOptions'
        {
            Key = 'Software\Policies\Microsoft\Internet Explorer\Main'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'NotifyDisableIEOptions'
        }
    }
    
    if($IsPreventCertErrorOverridesEnabled){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\MicrosoftEdge\Internet Settings\PreventCertErrorOverrides'
        {
            Key = 'Software\Policies\Microsoft\MicrosoftEdge\Internet Settings'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'PreventCertErrorOverrides'
        }
    }
    
    if($FormSuggestPasswordsSetting -eq 'no'){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\MicrosoftEdge\Main\FormSuggest Passwords'
        {
            Key = 'Software\Policies\Microsoft\MicrosoftEdge\Main'
            TargetType = 'ComputerConfiguration'
            ValueType = 'String'
            ValueData = 'No'
            ValueName = 'FormSuggest Passwords'
        }
    }
    if($IsEnabledV9Enabled){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\MicrosoftEdge\PhishingFilter\EnabledV9'
        {
            Key = 'Software\Policies\Microsoft\MicrosoftEdge\PhishingFilter'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'EnabledV9'
        }
    }
    
    if($IsPreventOverrideAppRepUnknownEnabled){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\MicrosoftEdge\PhishingFilter\PreventOverrideAppRepUnknown'
        {
            Key = 'Software\Policies\Microsoft\MicrosoftEdge\PhishingFilter'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'PreventOverrideAppRepUnknown'
        }
    }
    
    if($IsPreventOverrideEnabled){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\MicrosoftEdge\PhishingFilter\PreventOverride'
        {
            Key = 'Software\Policies\Microsoft\MicrosoftEdge\PhishingFilter'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'PreventOverride'
        }
    }
    
    if($IsRequireSecurityDeviceEnabled){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\PassportForWork\RequireSecurityDevice'
        {
            Key = 'Software\Policies\Microsoft\PassportForWork'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'RequireSecurityDevice'
        }
    }
    
    if($IsTPM12Excluded){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\PassportForWork\ExcludeSecurityDevices\TPM12'
        {
            Key = 'Software\Policies\Microsoft\PassportForWork\ExcludeSecurityDevices'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'TPM12'
        }
    }
    
    if($IsMinimumPINLengthEnabled){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\PassportForWork\PINComplexity\MinimumPINLength'
        {
            Key = 'Software\Policies\Microsoft\PassportForWork\PINComplexity'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 6
            ValueName = 'MinimumPINLength'
        }
    }
    
    if($IsDCSettingIndexEnabled){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\DCSettingIndex'
        {
            Key = 'Software\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'DCSettingIndex'
        }
    }
    
    if($IsACSettingIndexEnabled){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\ACSettingIndex'
        {
            Key = 'Software\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'ACSettingIndex'
        }
    }
    
    if($IsDisableInventoryEnabled){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\AppCompat\DisableInventory'
        {
            Key = 'Software\Policies\Microsoft\Windows\AppCompat'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'DisableInventory'
        }
    }
    if($IsLetAppsActivateWithVoiceAboveLockEnabled){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\AppPrivacy\LetAppsActivateWithVoiceAboveLock'
        {
            Key = 'Software\Policies\Microsoft\Windows\AppPrivacy'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 2
            ValueName = 'LetAppsActivateWithVoiceAboveLock'
        }
    }
    
    if($IsDisableWindowsConsumerFeaturesEnabled){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CloudContent\DisableWindowsConsumerFeatures'
        {
            Key = 'Software\Policies\Microsoft\Windows\CloudContent'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'DisableWindowsConsumerFeatures'
        }
    }
    
    if($IsAllowProtectedCredsEnabled){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CredentialsDelegation\AllowProtectedCreds'
        {
            Key = 'Software\Policies\Microsoft\Windows\CredentialsDelegation'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'AllowProtectedCreds'
        }
    }
    
    if($IsAllowTelemetryEnabled){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\DataCollection\AllowTelemetry'
        {
            Key = 'Software\Policies\Microsoft\Windows\DataCollection'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 2
            ValueName = 'AllowTelemetry'
        }
    }
    
    if($IsLimitEnhancedDiagnosticDataWindowsAnalyticsEnabled){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\DataCollection\LimitEnhancedDiagnosticDataWindowsAnalytics'
        {
            Key = 'Software\Policies\Microsoft\Windows\DataCollection'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'LimitEnhancedDiagnosticDataWindowsAnalytics'
        }
    }
    
    if($IsDODownloadModeEnabled){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\DeliveryOptimization\DODownloadMode'
        {
            Key = 'Software\Policies\Microsoft\Windows\DeliveryOptimization'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 2
            ValueName = 'DODownloadMode'
        }
    }
    
    if($IsEnableVirtualizationBasedSecurityEnabled){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\DeviceGuard\EnableVirtualizationBasedSecurity'
        {
            Key = 'Software\Policies\Microsoft\Windows\DeviceGuard'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'EnableVirtualizationBasedSecurity'
        }
    }
    
    if($IsRequirePlatformSecurityFeaturesEnabled){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\DeviceGuard\RequirePlatformSecurityFeatures'
        {
            Key = 'Software\Policies\Microsoft\Windows\DeviceGuard'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'RequirePlatformSecurityFeatures'
        }
    }
    
    if($IsHypervisorEnforcedCodeIntegrityEnabled){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\DeviceGuard\HypervisorEnforcedCodeIntegrity'
        {
            Key = 'Software\Policies\Microsoft\Windows\DeviceGuard'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'HypervisorEnforcedCodeIntegrity'
        }
    }
    if($IsHVCIMATRequiredEnabled){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\DeviceGuard\HVCIMATRequired'
        {
            Key = 'Software\Policies\Microsoft\Windows\DeviceGuard'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'HVCIMATRequired'
        }
    }
    
    if($IsLsaCfgFlagsEnabled){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\DeviceGuard\LsaCfgFlags'
        {
            Key = 'Software\Policies\Microsoft\Windows\DeviceGuard'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'LsaCfgFlags'
        }
    }
    
    if($IsConfigureSystemGuardLaunchEnabled){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\DeviceGuard\ConfigureSystemGuardLaunch'
        {
            Key = 'Software\Policies\Microsoft\Windows\DeviceGuard'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'ConfigureSystemGuardLaunch'
        }
    }
    
    if($IsMaxSizeApplicationLogEnabled){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\EventLog\Application\MaxSize'
        {
            Key = 'Software\Policies\Microsoft\Windows\EventLog\Application'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 32768
            ValueName = 'MaxSize'
        }
    }
    
    if($IsMaxSizeSecurityLogEnabled){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\EventLog\Security\MaxSize'
        {
            Key = 'Software\Policies\Microsoft\Windows\EventLog\Security'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1024000
            ValueName = 'MaxSize'
        }
    }
    
    if($IsMaxSizeSystemLogEnabled){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\EventLog\System\MaxSize'
        {
            Key = 'Software\Policies\Microsoft\Windows\EventLog\System'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 32768
            ValueName = 'MaxSize'
        }
    }
    
    if($IsNoAutoplayForNonVolumeEnabled){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\Explorer\NoAutoplayfornonVolume'
        {
            Key = 'Software\Policies\Microsoft\Windows\Explorer'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'NoAutoplayfornonVolume'
        }
    }
    
    if($IsNoDataExecutionPreventionEnabled){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\Explorer\NoDataExecutionPrevention'
        {
            Key = 'Software\Policies\Microsoft\Windows\Explorer'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'NoDataExecutionPrevention'
        }
    }
    
    if($IsNoHeapTerminationOnCorruptionEnabled){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\Explorer\NoHeapTerminationOnCorruption'
        {
            Key = 'Software\Policies\Microsoft\Windows\Explorer'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'NoHeapTerminationOnCorruption'
        }
    }
    if($IsAllowGameDVREnabled){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\GameDVR\AllowGameDVR'
        {
            Key = 'Software\Policies\Microsoft\Windows\GameDVR'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'AllowGameDVR'
        }
    }
    
    if($IsNoBackgroundPolicyEnabled){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}\NoBackgroundPolicy'
        {
            Key = 'Software\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'NoBackgroundPolicy'
        }
    }
    
    if($IsNoGPOListChangesEnabled){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}\NoGPOListChanges'
        {
            Key = 'Software\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'NoGPOListChanges'
        }
    }
    
    if($IsEnableUserControlEnabled){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\Installer\EnableUserControl'
        {
            Key = 'Software\Policies\Microsoft\Windows\Installer'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'EnableUserControl'
        }
    }
    
    if($IsAlwaysInstallElevatedEnabled){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated'
        {
            Key = 'Software\Policies\Microsoft\Windows\Installer'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'AlwaysInstallElevated'
        }
    }
    
    if($IsSafeForScriptingEnabled){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\Installer\SafeForScripting'
        {
            Key = 'Software\Policies\Microsoft\Windows\Installer'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'SafeForScripting'
        }
    }
    
    if($IsDeviceEnumerationPolicyEnabled){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\Kernel DMA Protection\DeviceEnumerationPolicy'
        {
            Key = 'Software\Policies\Microsoft\Windows\Kernel DMA Protection'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'DeviceEnumerationPolicy'
        }
    }
    
    if($IsAllowInsecureGuestAuthEnabled){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\LanmanWorkstation\AllowInsecureGuestAuth'
        {
            Key = 'Software\Policies\Microsoft\Windows\LanmanWorkstation'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'AllowInsecureGuestAuth'
        }
    }
    
    if($IsNCShowSharedAccessUIEnabled){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\Network Connections\NC_ShowSharedAccessUI'
        {
            Key = 'Software\Policies\Microsoft\Windows\Network Connections'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'NC_ShowSharedAccessUI'
        }
    }

    if($IsBlockingNonDomainEnabled){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WcmSvc\GroupPolicy\fBlockNonDomain'
        {
            Key = 'Software\Policies\Microsoft\Windows\WcmSvc\GroupPolicy'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'fBlockNonDomain'
        }
    }
    
    if($IsMinimizeConnectionsEnabled){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WcmSvc\GroupPolicy\fMinimizeConnections'
        {
            Key = 'Software\Policies\Microsoft\Windows\WcmSvc\GroupPolicy'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 3
            ValueName = 'fMinimizeConnections'
        }
    }
    
    if($IsAllowIndexingEncryptedStoresEnabled){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\Windows Search\AllowIndexingEncryptedStoresOrItems'
        {
            Key = 'Software\Policies\Microsoft\Windows\Windows Search'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'AllowIndexingEncryptedStoresOrItems'
        }
    }
    
    if($IsWinRMAllowBasicEnabled){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WinRM\Client\AllowBasic'
        {
            Key = 'Software\Policies\Microsoft\Windows\WinRM\Client'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'AllowBasic'
        }
    }
    
    if($IsWinRMAllowUnencryptedTrafficEnabled){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WinRM\Client\AllowUnencryptedTraffic'
        {
            Key = 'Software\Policies\Microsoft\Windows\WinRM\Client'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'AllowUnencryptedTraffic'
        }
    }
    
    if($IsWinRMAllowDigestEnabled){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WinRM\Client\AllowDigest'
        {
            Key = 'Software\Policies\Microsoft\Windows\WinRM\Client'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'AllowDigest'
        }
    }
    
    if($IsWinRMServiceAllowBasicEnabled){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service\AllowBasic'
        {
            Key = 'Software\Policies\Microsoft\Windows\WinRM\Service'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'AllowBasic'
        }
    }
    
    if($IsWinRMServiceAllowUnencryptedTrafficEnabled){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service\AllowUnencryptedTraffic'
        {
            Key = 'Software\Policies\Microsoft\Windows\WinRM\Service'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'AllowUnencryptedTraffic'
        }
    }

    if($IsDisableRunAsEnabled){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service\DisableRunAs'
        {
            Key = 'Software\Policies\Microsoft\Windows\WinRM\Service'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'DisableRunAs'
        }
    }
    
    if($IsDisableWebPnPDownloadEnabled){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows NT\Printers\DisableWebPnPDownload'
        {
            Key = 'Software\Policies\Microsoft\Windows NT\Printers'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'DisableWebPnPDownload'
        }
    }
    
    if($IsDisableHTTPPrintingEnabled){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows NT\Printers\DisableHTTPPrinting'
        {
            Key = 'Software\Policies\Microsoft\Windows NT\Printers'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'DisableHTTPPrinting'
        }
    }
    
    if($IsRestrictRemoteClientsEnabled){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows NT\Rpc\RestrictRemoteClients'
        {
            Key = 'Software\Policies\Microsoft\Windows NT\Rpc'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'RestrictRemoteClients'
        }
    }
    
    if($IsAllowToGetHelpEnabled){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\fAllowToGetHelp'
        {
            Key = 'Software\Policies\Microsoft\Windows NT\Terminal Services'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'fAllowToGetHelp'
        }
    }
    
    if($IsAllowFullControlEnabled){
        RegistryPolicyFile 'DEL_\Software\Policies\Microsoft\Windows NT\Terminal Services\fAllowFullControl'
        {
            Key = 'Software\Policies\Microsoft\Windows NT\Terminal Services'
            TargetType = 'ComputerConfiguration'
            ValueType = 'String'
            ValueData = ''
            ValueName = 'fAllowFullControl'
            Ensure = 'Absent'
        }
    }
    
    if($IsMaxTicketExpiryEnabled){
        RegistryPolicyFile 'DEL_\Software\Policies\Microsoft\Windows NT\Terminal Services\MaxTicketExpiry'
        {
            Key = 'Software\Policies\Microsoft\Windows NT\Terminal Services'
            TargetType = 'ComputerConfiguration'
            ValueType = 'String'
            ValueData = ''
            ValueName = 'MaxTicketExpiry'
            Ensure = 'Absent'
        }
    }
    
    if($IsMaxTicketExpiryUnitsEnabled){
        RegistryPolicyFile 'DEL_\Software\Policies\Microsoft\Windows NT\Terminal Services\MaxTicketExpiryUnits'
        {
            Key = 'Software\Policies\Microsoft\Windows NT\Terminal Services'
            TargetType = 'ComputerConfiguration'
            ValueType = 'String'
            ValueData = ''
            ValueName = 'MaxTicketExpiryUnits'
            Ensure = 'Absent'
        }
    }
    if($IsUseMailtoEnabled){
        RegistryPolicyFile 'DEL_\Software\Policies\Microsoft\Windows NT\Terminal Services\fUseMailto'
        {
            Key = 'Software\Policies\Microsoft\Windows NT\Terminal Services'
            TargetType = 'ComputerConfiguration'
            ValueType = 'String'
            ValueData = ''
            ValueName = 'fUseMailto'
            Ensure = 'Absent'
        }
    }
    
    if($IsDisablePasswordSavingEnabled){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\DisablePasswordSaving'
        {
            Key = 'Software\Policies\Microsoft\Windows NT\Terminal Services'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'DisablePasswordSaving'
        }
    }
    
    if($IsDisableCdmEnabled){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\fDisableCdm'
        {
            Key = 'Software\Policies\Microsoft\Windows NT\Terminal Services'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'fDisableCdm'
        }
    }
    
    if($IsPromptForPasswordEnabled){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\fPromptForPassword'
        {
            Key = 'Software\Policies\Microsoft\Windows NT\Terminal Services'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'fPromptForPassword'
        }
    }
    
    if($IsEncryptRPCTrafficEnabled){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\fEncryptRPCTraffic'
        {
            Key = 'Software\Policies\Microsoft\Windows NT\Terminal Services'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'fEncryptRPCTraffic'
        }
    }
    
    if($IsMinEncryptionLevelEnabled){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\MinEncryptionLevel'
        {
            Key = 'Software\Policies\Microsoft\Windows NT\Terminal Services'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 3
            ValueName = 'MinEncryptionLevel'
        }
    }
    
    if($IsAllowWindowsInkWorkspaceEnabled){
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\WindowsInkWorkspace\AllowWindowsInkWorkspace'
        {
            Key = 'Software\Policies\Microsoft\WindowsInkWorkspace'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'AllowWindowsInkWorkspace'
        }
    }
    
    if($IsUseLogonCredentialEnabled){
        RegistryPolicyFile 'Registry(POL): HKLM:\System\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential'
        {
            Key = 'System\CurrentControlSet\Control\SecurityProviders\WDigest'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'UseLogonCredential'
        }
    }
    
    if($IsDisableExceptionChainValidationEnabled){
        RegistryPolicyFile 'Registry(POL): HKLM:\System\CurrentControlSet\Control\Session Manager\kernel\DisableExceptionChainValidation'
        {
            Key = 'System\CurrentControlSet\Control\Session Manager\kernel'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'DisableExceptionChainValidation'
        }
    }
    
    if($IsDriverLoadPolicyEnabled){
        RegistryPolicyFile 'Registry(POL): HKLM:\System\CurrentControlSet\Policies\EarlyLaunch\DriverLoadPolicy'
        {
            Key = 'System\CurrentControlSet\Policies\EarlyLaunch'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 3
            ValueName = 'DriverLoadPolicy'
        }
    }
    
    if($IsSMB1Enabled){
        RegistryPolicyFile 'Registry(POL): HKLM:\System\CurrentControlSet\Services\LanmanServer\Parameters\SMB1'
        {
            Key = 'System\CurrentControlSet\Services\LanmanServer\Parameters'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'SMB1'
        }
    }
    
    if($IsMrxSmb10StartEnabled){
        RegistryPolicyFile 'Registry(POL): HKLM:\System\CurrentControlSet\Services\MrxSmb10\Start'
        {
            Key = 'System\CurrentControlSet\Services\MrxSmb10'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 4
            ValueName = 'Start'
        }
    }
    
    if($IsNoNameReleaseOnDemandEnabled){
        RegistryPolicyFile 'Registry(POL): HKLM:\System\CurrentControlSet\Services\Netbt\Parameters\NoNameReleaseOnDemand'
        {
            Key = 'System\CurrentControlSet\Services\Netbt\Parameters'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'NoNameReleaseOnDemand'
        }
    }
    if($IsDisableIPSourceRoutingEnabled){
        RegistryPolicyFile 'Registry(POL): HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters\DisableIPSourceRouting'
        {
            Key = 'System\CurrentControlSet\Services\Tcpip\Parameters'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 2
            ValueName = 'DisableIPSourceRouting'
        }
    }
    
    if($IsEnableICMPRedirectEnabled){
        RegistryPolicyFile 'Registry(POL): HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters\EnableICMPRedirect'
        {
            Key = 'System\CurrentControlSet\Services\Tcpip\Parameters'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'EnableICMPRedirect'
        }
    }
    
    if($IsDisableIPSourceRoutingIPv6Enabled){
        RegistryPolicyFile 'Registry(POL): HKLM:\System\CurrentControlSet\Services\Tcpip6\Parameters\DisableIPSourceRouting'
        {
            Key = 'System\CurrentControlSet\Services\Tcpip6\Parameters'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 2
            ValueName = 'DisableIPSourceRouting'
        }
    }
    
    if($IsCredentialValidationSuccessEnabled){
        AuditPolicySubcategory 'Audit Credential Validation (Success) - Inclusion'
        {
            Name = 'Credential Validation'
            Ensure = 'Present'
            AuditFlag = 'Success'
        }
    }
    
    if($IsCredentialValidationFailureEnabled){
        AuditPolicySubcategory 'Audit Credential Validation (Failure) - Inclusion'
        {
            Name = 'Credential Validation'
            Ensure = 'Present'
            AuditFlag = 'Failure'
        }
    }
    
    if($IsSecurityGroupManagementSuccessEnabled){
        AuditPolicySubcategory 'Audit Security Group Management (Success) - Inclusion'
        {
            Name = 'Security Group Management'
            Ensure = 'Present'
            AuditFlag = 'Success'
        }
    }
    
    if($IsSecurityGroupManagementFailureEnabled){
        AuditPolicySubcategory 'Audit Security Group Management (Failure) - Inclusion'
        {
            Name = 'Security Group Management'
            Ensure = 'Absent'
            AuditFlag = 'Failure'
        }
    }
    
    if($IsUserAccountManagementSuccessEnabled){
        AuditPolicySubcategory 'Audit User Account Management (Success) - Inclusion'
        {
            Name = 'User Account Management'
            Ensure = 'Present'
            AuditFlag = 'Success'
        }
    }
    
    if($IsUserAccountManagementFailureEnabled){
        AuditPolicySubcategory 'Audit User Account Management (Failure) - Inclusion'
        {
            Name = 'User Account Management'
            Ensure = 'Present'
            AuditFlag = 'Failure'
        }
    }
    
    if($IsPnpActivitySuccessEnabled){
        AuditPolicySubcategory 'Audit PNP Activity (Success) - Inclusion'
        {
            Name = 'Plug and Play Events'
            Ensure = 'Present'
            AuditFlag = 'Success'
        }
    }
    
    if($IsPnpActivityFailureEnabled){
        AuditPolicySubcategory 'Audit PNP Activity (Failure) - Inclusion'
        {
            Name = 'Plug and Play Events'
            Ensure = 'Absent'
            AuditFlag = 'Failure'
        }
    }
    
    if($IsProcessCreationSuccessEnabled){
        AuditPolicySubcategory 'Audit Process Creation (Success) - Inclusion'
        {
            Name = 'Process Creation'
            Ensure = 'Present'
            AuditFlag = 'Success'
        }
    }
    
    if($IsProcessCreationFailureEnabled){
        AuditPolicySubcategory 'Audit Process Creation (Failure) - Inclusion'
        {
            Name = 'Process Creation'
            Ensure = 'Present'
            AuditFlag = 'Failure'
        }
    }
    
    if($IsAccountLockoutFailureEnabled){
        AuditPolicySubcategory 'Audit Account Lockout (Failure) - Inclusion'
        {
            Name = 'Account Lockout'
            Ensure = 'Present'
            AuditFlag = 'Failure'
        }
    }

    if($IsAccountLockoutSuccessEnabled){
        AuditPolicySubcategory 'Audit Account Lockout (Success) - Inclusion'
        {
            Name = 'Account Lockout'
            Ensure = 'Absent'
            AuditFlag = 'Success'
        }
    }
    
    if($IsGroupMembershipSuccessEnabled){
        AuditPolicySubcategory 'Audit Group Membership (Success) - Inclusion'
        {
            Name = 'Group Membership'
            Ensure = 'Present'
            AuditFlag = 'Success'
        }
    }
    
    if($IsGroupMembershipFailureEnabled){
        AuditPolicySubcategory 'Audit Group Membership (Failure) - Inclusion'
        {
            Name = 'Group Membership'
            Ensure = 'Absent'
            AuditFlag = 'Failure'
        }
    }
    
    if($IsLogoffSuccessEnabled){
        AuditPolicySubcategory 'Audit Logoff (Success) - Inclusion'
        {
            Name = 'Logoff'
            Ensure = 'Present'
            AuditFlag = 'Success'
        }
    }
    
    if($IsLogoffFailureEnabled){
        AuditPolicySubcategory 'Audit Logoff (Failure) - Inclusion'
        {
            Name = 'Logoff'
            Ensure = 'Absent'
            AuditFlag = 'Failure'
        }
    }
    
    if($IsLogonSuccessEnabled){
        AuditPolicySubcategory 'Audit Logon (Success) - Inclusion'
        {
            Name = 'Logon'
            Ensure = 'Present'
            AuditFlag = 'Success'
        }
    }
    
    if($IsLogonFailureEnabled){
        AuditPolicySubcategory 'Audit Logon (Failure) - Inclusion'
        {
            Name = 'Logon'
            Ensure = 'Present'
            AuditFlag = 'Failure'
        }
    }
    
    if($IsOtherLogonLogoffEventsSuccessEnabled){
        AuditPolicySubcategory 'Audit Other Logon/Logoff Events (Success) - Inclusion'
        {
            Name = 'Other Logon/Logoff Events'
            Ensure = 'Present'
            AuditFlag = 'Success'
        }
    }
    
    if($IsOtherLogonLogoffEventsFailureEnabled){
        AuditPolicySubcategory 'Audit Other Logon/Logoff Events (Failure) - Inclusion'
        {
            Name = 'Other Logon/Logoff Events'
            Ensure = 'Present'
            AuditFlag = 'Failure'
        }
    }
    
    if($IsSpecialLogonSuccessEnabled){
        AuditPolicySubcategory 'Audit Special Logon (Success) - Inclusion'
        {
            Name = 'Special Logon'
            Ensure = 'Present'
            AuditFlag = 'Success'
        }
    }
    
    if($IsSpecialLogonFailureEnabled){
        AuditPolicySubcategory 'Audit Special Logon (Failure) - Inclusion'
        {
            Name = 'Special Logon'
            Ensure = 'Absent'
            AuditFlag = 'Failure'
        }
    }
    
    if($IsDetailedFileShareFailureEnabled){
        AuditPolicySubcategory 'Audit Detailed File Share (Failure) - Inclusion'
        {
            Name = 'Detailed File Share'
            Ensure = 'Present'
            AuditFlag = 'Failure'
        }
    }
    
    if($IsDetailedFileShareSuccessEnabled){
        AuditPolicySubcategory 'Audit Detailed File Share (Success) - Inclusion'
        {
            Name = 'Detailed File Share'
            Ensure = 'Absent'
            AuditFlag = 'Success'
        }
    }
    
    if($IsFileShareSuccessEnabled){
        AuditPolicySubcategory 'Audit File Share (Success) - Inclusion'
        {
            Name = 'File Share'
            Ensure = 'Present'
            AuditFlag = 'Success'
        }
    }
    
    if($IsFileShareFailureEnabled){
        AuditPolicySubcategory 'Audit File Share (Failure) - Inclusion'
        {
            Name = 'File Share'
            Ensure = 'Present'
            AuditFlag = 'Failure'
        }
    }
    if($IsOtherObjectAccessEventsSuccessEnabled){
        AuditPolicySubcategory 'Audit Other Object Access Events (Success) - Inclusion'
        {
            Name = 'Other Object Access Events'
            Ensure = 'Present'
            AuditFlag = 'Success'
        }
    }
    
    if($IsOtherObjectAccessEventsFailureEnabled){
        AuditPolicySubcategory 'Audit Other Object Access Events (Failure) - Inclusion'
        {
            Name = 'Other Object Access Events'
            Ensure = 'Present'
            AuditFlag = 'Failure'
        }
    }
    
    if($IsRemovableStorageSuccessEnabled){
        AuditPolicySubcategory 'Audit Removable Storage (Success) - Inclusion'
        {
            Name = 'Removable Storage'
            Ensure = 'Present'
            AuditFlag = 'Success'
        }
    }
    
    if($IsRemovableStorageFailureEnabled){
        AuditPolicySubcategory 'Audit Removable Storage (Failure) - Inclusion'
        {
            Name = 'Removable Storage'
            Ensure = 'Present'
            AuditFlag = 'Failure'
        }
    }
    
    if($IsAuditPolicyChangeSuccessEnabled){
        AuditPolicySubcategory 'Audit Audit Policy Change (Success) - Inclusion'
        {
            Name = 'Audit Policy Change'
            Ensure = 'Present'
            AuditFlag = 'Success'
        }
    }
    
    if($IsAuditPolicyChangeFailureEnabled){
        AuditPolicySubcategory 'Audit Audit Policy Change (Failure) - Inclusion'
        {
            Name = 'Audit Policy Change'
            Ensure = 'Absent'
            AuditFlag = 'Failure'
        }
    }
    
    if($IsAuthenticationPolicyChangeSuccessEnabled){
        AuditPolicySubcategory 'Audit Authentication Policy Change (Success) - Inclusion'
        {
            Name = 'Authentication Policy Change'
            Ensure = 'Present'
            AuditFlag = 'Success'
        }
    }
    
    if($IsAuthenticationPolicyChangeFailureEnabled){
        AuditPolicySubcategory 'Audit Authentication Policy Change (Failure) - Inclusion'
        {
            Name = 'Authentication Policy Change'
            Ensure = 'Absent'
            AuditFlag = 'Failure'
        }
    }
    
    if($IsAuthorizationPolicyChangeSuccessEnabled){
        AuditPolicySubcategory 'Audit Authorization Policy Change (Success) - Inclusion'
        {
            Name = 'Authorization Policy Change'
            Ensure = 'Present'
            AuditFlag = 'Success'
        }
    }
    
    if($IsAuthorizationPolicyChangeFailureEnabled){
        AuditPolicySubcategory 'Audit Authorization Policy Change (Failure) - Inclusion'
        {
            Name = 'Authorization Policy Change'
            Ensure = 'Absent'
            AuditFlag = 'Failure'
        }
    }
    
    if($IsMpssvcRuleLevelPolicyChangeSuccessEnabled){
        AuditPolicySubcategory 'Audit MPSSVC Rule-Level Policy Change (Success) - Inclusion'
        {
            Name = 'MPSSVC Rule-Level Policy Change'
            Ensure = 'Present'
            AuditFlag = 'Success'
        }
    }
    
    if($IsMpssvcRuleLevelPolicyChangeFailureEnabled){
        AuditPolicySubcategory 'Audit MPSSVC Rule-Level Policy Change (Failure) - Inclusion'
        {
            Name = 'MPSSVC Rule-Level Policy Change'
            Ensure = 'Present'
            AuditFlag = 'Failure'
        }
    }

    if($IsOtherPolicyChangeEventsFailureEnabled){
        AuditPolicySubcategory 'Audit Other Policy Change Events (Failure) - Inclusion'
        {
            Name = 'Other Policy Change Events'
            Ensure = 'Present'
            AuditFlag = 'Failure'
        }
    }
    
    if($IsOtherPolicyChangeEventsSuccessEnabled){
        AuditPolicySubcategory 'Audit Other Policy Change Events (Success) - Inclusion'
        {
            Name = 'Other Policy Change Events'
            Ensure = 'Absent'
            AuditFlag = 'Success'
        }
    }
    
    if($IsSensitivePrivilegeUseSuccessEnabled){
        AuditPolicySubcategory 'Audit Sensitive Privilege Use (Success) - Inclusion'
        {
            Name = 'Sensitive Privilege Use'
            Ensure = 'Present'
            AuditFlag = 'Success'
        }
    }
    
    if($IsSensitivePrivilegeUseFailureEnabled){
        AuditPolicySubcategory 'Audit Sensitive Privilege Use (Failure) - Inclusion'
        {
            Name = 'Sensitive Privilege Use'
            Ensure = 'Present'
            AuditFlag = 'Failure'
        }
    }
    
    if($IsIpsecDriverFailureEnabled){
        AuditPolicySubcategory 'Audit IPsec Driver (Failure) - Inclusion'
        {
            Name = 'IPsec Driver'
            Ensure = 'Present'
            AuditFlag = 'Failure'
        }
    }
    
    if($IsIpsecDriverSuccessEnabled){
        AuditPolicySubcategory 'Audit IPsec Driver (Success) - Inclusion'
        {
            Name = 'IPsec Driver'
            Ensure = 'Absent'
            AuditFlag = 'Success'
        }
    }
    
    if($IsOtherSystemEventsSuccessEnabled){
        AuditPolicySubcategory 'Audit Other System Events (Success) - Inclusion'
        {
            Name = 'Other System Events'
            Ensure = 'Present'
            AuditFlag = 'Success'
        }
    }
    
    if($IsOtherSystemEventsFailureEnabled){
        AuditPolicySubcategory 'Audit Other System Events (Failure) - Inclusion'
        {
            Name = 'Other System Events'
            Ensure = 'Present'
            AuditFlag = 'Failure'
        }
    }
    
    if($IsSecurityStateChangeSuccessEnabled){
        AuditPolicySubcategory 'Audit Security State Change (Success) - Inclusion'
        {
            Name = 'Security State Change'
            Ensure = 'Present'
            AuditFlag = 'Success'
        }
    }
    
    if($IsSecurityStateChangeFailureEnabled){
        AuditPolicySubcategory 'Audit Security State Change (Failure) - Inclusion'
        {
            Name = 'Security State Change'
            Ensure = 'Absent'
            AuditFlag = 'Failure'
        }
    }
    
    if($IsSecuritySystemExtensionSuccessEnabled){
        AuditPolicySubcategory 'Audit Security System Extension (Success) - Inclusion'
        {
            Name = 'Security System Extension'
            Ensure = 'Present'
            AuditFlag = 'Success'
        }
    }
    
    if($IsSecuritySystemExtensionFailureEnabled){
        AuditPolicySubcategory 'Audit Security System Extension (Failure) - Inclusion'
        {
            Name = 'Security System Extension'
            Ensure = 'Absent'
            AuditFlag = 'Failure'
        }
    }
    
    if($IsSystemIntegritySuccessEnabled){
        AuditPolicySubcategory 'Audit System Integrity (Success) - Inclusion'
        {
            Name = 'System Integrity'
            Ensure = 'Present'
            AuditFlag = 'Success'
        }
    }
    
    if($IsSystemIntegrityFailureEnabled){
        AuditPolicySubcategory 'Audit System Integrity (Failure) - Inclusion'
        {
            Name = 'System Integrity'
            Ensure = 'Present'
            AuditFlag = 'Failure'
        }
    }
    if($IsNetworkSecurityDoNotStoreLANManagerHashEnabled){
        SecurityOption 'SecurityRegistry(INF): Network_security_Do_not_store_LAN_Manager_hash_value_on_next_password_change'
        {
            Name = 'Network_security_Do_not_store_LAN_Manager_hash_value_on_next_password_change'
            Network_security_Do_not_store_LAN_Manager_hash_value_on_next_password_change = 'Enabled'
        }
    }
    
    if($IsMicrosoftNetworkServerDigitallySignCommunicationsEnabled){
        SecurityOption 'SecurityRegistry(INF): Microsoft_network_server_Digitally_sign_communications_always'
        {
            Name = 'Microsoft_network_server_Digitally_sign_communications_always'
            Microsoft_network_server_Digitally_sign_communications_always = 'Enabled'
        }
    }
    
    if($IsInteractiveLogonNumberOfPreviousLogonsEnabled){
        SecurityOption 'SecurityRegistry(INF): Interactive_logon_Number_of_previous_logons_to_cache_in_case_domain_controller_is_not_available'
        {
            Name = 'Interactive_logon_Number_of_previous_logons_to_cache_in_case_domain_controller_is_not_available'
            Interactive_logon_Number_of_previous_logons_to_cache_in_case_domain_controller_is_not_available = '10'
        }
    }
    
    if($IsInteractiveLogonMachineInactivityLimitEnabled){
        SecurityOption 'SecurityRegistry(INF): Interactive_logon_Machine_inactivity_limit'
        {
            Name = 'Interactive_logon_Machine_inactivity_limit'
            Interactive_logon_Machine_inactivity_limit = '900'
        }
    }
    
    if($IsNetworkAccessLetEveryonePermissionsApplyEnabled){
        SecurityOption 'SecurityRegistry(INF): Network_access_Let_Everyone_permissions_apply_to_anonymous_users'
        {
            Name = 'Network_access_Let_Everyone_permissions_apply_to_anonymous_users'
            Network_access_Let_Everyone_permissions_apply_to_anonymous_users = 'Disabled'
        }
    }
    
    if($IsUserAccountControlOnlyElevateUIAccessApplicationsEnabled){
        SecurityOption 'SecurityRegistry(INF): User_Account_Control_Only_elevate_UIAccess_applications_that_are_installed_in_secure_locations'
        {
            Name = 'User_Account_Control_Only_elevate_UIAccess_applications_that_are_installed_in_secure_locations'
            User_Account_Control_Only_elevate_UIAccess_applications_that_are_installed_in_secure_locations = 'Enabled'
        }
    }
    
    if($IsDomainMemberDigitallyEncryptSecureChannelDataEnabled){
        SecurityOption 'SecurityRegistry(INF): Domain_member_Digitally_encrypt_secure_channel_data_when_possible'
        {
            Name = 'Domain_member_Digitally_encrypt_secure_channel_data_when_possible'
            Domain_member_Digitally_encrypt_secure_channel_data_when_possible = 'Enabled'
        }
    }
    
    if($IsNetworkAccessRestrictClientsEnabled){
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
    
    if($IsNetworkSecurityMinimumSessionSecurityEnabled){
        SecurityOption 'SecurityRegistry(INF): Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_servers'
        {
            Name = 'Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_servers'
            Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_servers = 'Both options checked'
        }
    }
    
    if($IsNetworkSecurityConfigureEncryptionTypesEnabled){
        SecurityOption 'SecurityRegistry(INF): Network_security_Configure_encryption_types_allowed_for_Kerberos'
        {
            Name = 'Network_security_Configure_encryption_types_allowed_for_Kerberos'
            Network_security_Configure_encryption_types_allowed_for_Kerberos = '2147483640'
        }
    }
    
    if($IsUserAccountControlDetectApplicationsEnabled){
        SecurityOption 'SecurityRegistry(INF): User_Account_Control_Detect_application_installations_and_prompt_for_elevation'
        {
            Name = 'User_Account_Control_Detect_application_installations_and_prompt_for_elevation'
            User_Account_Control_Detect_application_installations_and_prompt_for_elevation = 'Enabled'
        }
    }
    
    if($IsMicrosoftNetworkClientDigitallySignCommunicationsEnabled){
        SecurityOption 'SecurityRegistry(INF): Microsoft_network_client_Digitally_sign_communications_always'
        {
            Name = 'Microsoft_network_client_Digitally_sign_communications_always'
            Microsoft_network_client_Digitally_sign_communications_always = 'Enabled'
        }
    }
    
    if($IsUserAccountControlBehaviorOfTheElevationPromptEnabled){
        SecurityOption 'SecurityRegistry(INF): User_Account_Control_Behavior_of_the_elevation_prompt_for_administrators_in_Admin_Approval_Mode'
        {
            Name = 'User_Account_Control_Behavior_of_the_elevation_prompt_for_administrators_in_Admin_Approval_Mode'
            User_Account_Control_Behavior_of_the_elevation_prompt_for_administrators_in_Admin_Approval_Mode = 'Prompt for consent on the secure desktop'
        }
    }
    
    if($IsNetworkAccessRestrictAnonymousAccessEnabled){
        SecurityOption 'SecurityRegistry(INF): Network_access_Restrict_anonymous_access_to_Named_Pipes_and_Shares'
        {
            Name = 'Network_access_Restrict_anonymous_access_to_Named_Pipes_and_Shares'
            Network_access_Restrict_anonymous_access_to_Named_Pipes_and_Shares = 'Enabled'
        }
    }
    
    if($IsInteractiveLogonMessageTextEnabled){
        SecurityOption 'SecurityRegistry(INF): Interactive_logon_Message_text_for_users_attempting_to_log_on'
        {
            Name = 'Interactive_logon_Message_text_for_users_attempting_to_log_on'
            Interactive_logon_Message_text_for_users_attempting_to_log_on = 'You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.,By using this IS (which includes any device attached to this IS)"," you consent to the following conditions:,-The USG routinely intercepts and monitors communications on this IS for purposes including"," but not limited to"," penetration testing"," COMSEC monitoring"," network operations and defense"," personnel misconduct (PM)"," law enforcement (LE)"," and counterintelligence (CI) investigations.,-At any time"," the USG may inspect and seize data stored on this IS.,-Communications using"," or data stored on"," this IS are not private"," are subject to routine monitoring"," interception"," and search"," and may be disclosed or used for any USG-authorized purpose.,-This IS includes security measures (e.g."," authentication and access controls) to protect USG interests--not for your personal benefit or privacy.,-Notwithstanding the above"," using this IS does not constitute consent to PM"," LE or CI investigative searching or monitoring of the content of privileged communications"," or work product"," related to personal representation or services by attorneys"," psychotherapists"," or clergy"," and their assistants. Such communications and work product are private and confidential. See User Agreement for details.'
        }
    }
    
    if($IsDomainMemberDisableMachineAccountPasswordChangesEnabled){
        SecurityOption 'SecurityRegistry(INF): Domain_member_Disable_machine_account_password_changes'
        {
            Name = 'Domain_member_Disable_machine_account_password_changes'
            Domain_member_Disable_machine_account_password_changes = 'Disabled'
        }
    }
    
    if($IsDomainMemberDigitallyEncryptOrSignSecureChannelDataEnabled){
        SecurityOption 'SecurityRegistry(INF): Domain_member_Digitally_encrypt_or_sign_secure_channel_data_always'
        {
            Name = 'Domain_member_Digitally_encrypt_or_sign_secure_channel_data_always'
            Domain_member_Digitally_encrypt_or_sign_secure_channel_data_always = 'Enabled'
        }
    }
    if($IsRequireStrongWindows2000SessionKeyEnabled){
        SecurityOption 'SecurityRegistry(INF): Domain_member_Require_strong_Windows_2000_or_later_session_key'
        {
            Name = 'Domain_member_Require_strong_Windows_2000_or_later_session_key'
            Domain_member_Require_strong_Windows_2000_or_later_session_key = 'Enabled'
        }
    }
    
    if($IsUseFIPSCompliantAlgorithmsEnabled){
        SecurityOption 'SecurityRegistry(INF): System_cryptography_Use_FIPS_compliant_algorithms_for_encryption_hashing_and_signing'
        {
            Name = 'System_cryptography_Use_FIPS_compliant_algorithms_for_encryption_hashing_and_signing'
            System_cryptography_Use_FIPS_compliant_algorithms_for_encryption_hashing_and_signing = 'Enabled'
        }
    }
    
    if($IsAllowLocalSystemNullSessionFallbackEnabled){
        SecurityOption 'SecurityRegistry(INF): Network_security_Allow_LocalSystem_NULL_session_fallback'
        {
            Name = 'Network_security_Allow_LocalSystem_NULL_session_fallback'
            Network_security_Allow_LocalSystem_NULL_session_fallback = 'Disabled'
        }
    }
    
    if($IsDoNotAllowAnonymousEnumerationOfSAMAccountsEnabled){
        SecurityOption 'SecurityRegistry(INF): Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts_and_shares'
        {
            Name = 'Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts_and_shares'
            Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts_and_shares = 'Enabled'
        }
    }

    if($IsRequireStrongWindows2000SessionKeyEnabled){
        SecurityOption 'SecurityRegistry(INF): Domain_member_Require_strong_Windows_2000_or_later_session_key'
        {
            Name = 'Domain_member_Require_strong_Windows_2000_or_later_session_key'
            Domain_member_Require_strong_Windows_2000_or_later_session_key = 'Enabled'
        }
    }
    
    if($IsUseFIPSCompliantAlgorithmsEnabled){
        SecurityOption 'SecurityRegistry(INF): System_cryptography_Use_FIPS_compliant_algorithms_for_encryption_hashing_and_signing'
        {
            Name = 'System_cryptography_Use_FIPS_compliant_algorithms_for_encryption_hashing_and_signing'
            System_cryptography_Use_FIPS_compliant_algorithms_for_encryption_hashing_and_signing = 'Enabled'
        }
    }
    
    if($IsAllowLocalSystemNullSessionFallbackEnabled){
        SecurityOption 'SecurityRegistry(INF): Network_security_Allow_LocalSystem_NULL_session_fallback'
        {
            Name = 'Network_security_Allow_LocalSystem_NULL_session_fallback'
            Network_security_Allow_LocalSystem_NULL_session_fallback = 'Disabled'
        }
    }
    
    if($IsDoNotAllowAnonymousEnumerationOfSAMAccountsEnabled){
        SecurityOption 'SecurityRegistry(INF): Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts_and_shares'
        {
            Name = 'Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts_and_shares'
            Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts_and_shares = 'Enabled'
        }
    }
    
    if($IsCreateTokenObjectEnabled){
        UserRightsAssignment 'UserRightsAssignment(INF): Create_a_token_object'
        {
            Force = $True
            Identity = @('')
            Policy = 'Create_a_token_object'
        }
    }
    
    if($IsChangeSystemTimeEnabled){
        UserRightsAssignment 'UserRightsAssignment(INF): Change_the_system_time'
        {
            Force = $True
            Identity = @('*S-1-5-32-544', '*S-1-5-19', '*S-1-5-80-3169285310-278349998-1452333686-3865143136-4212226833')
            Policy = 'Change_the_system_time'
        }
    }
    
    if($IsAccessCredentialManagerEnabled){
        UserRightsAssignment 'UserRightsAssignment(INF): Access_Credential_Manager_as_a_trusted_caller'
        {
            Force = $True
            Identity = @('')
            Policy = 'Access_Credential_Manager_as_a_trusted_caller'
        }
    }
    
    if($IsDebugProgramsEnabled){
        UserRightsAssignment 'UserRightsAssignment(INF): Debug_programs'
        {
            Force = $True
            Identity = @('*S-1-5-32-544')
            Policy = 'Debug_programs'
        }
    }
    
    if($IsModifyFirmwareEnvironmentValuesEnabled){
        UserRightsAssignment 'UserRightsAssignment(INF): Modify_firmware_environment_values'
        {
            Force = $True
            Identity = @('*S-1-5-32-544')
            Policy = 'Modify_firmware_environment_values'
        }
    }
    
    if($IsLoadUnloadDeviceDriversEnabled){
        UserRightsAssignment 'UserRightsAssignment(INF): Load_and_unload_device_drivers'
        {
            Force = $True
            Identity = @('*S-1-5-32-544')
            Policy = 'Load_and_unload_device_drivers'
        }
    }
    
    if($IsDenyAccessToNetworkEnabled){
        UserRightsAssignment 'UserRightsAssignment(INF): Deny_access_to_this_computer_from_the_network'
        {
            Force = $True
            Identity = @($DomainAdmins, $EnterpriseAdmins, '*S-1-5-32-546', '*S-1-5-113')
            Policy = 'Deny_access_to_this_computer_from_the_network'
        }
    }
    
    if($IsAccessComputerFromNetworkEnabled){
        UserRightsAssignment 'UserRightsAssignment(INF): Access_this_computer_from_the_network'
        {
            Force = $True
            Identity = @('*S-1-5-32-544', '*S-1-5-32-555')
            Policy = 'Access_this_computer_from_the_network'
        }
    }
    
    if($IsRestoreFilesAndDirectoriesEnabled){
        UserRightsAssignment 'UserRightsAssignment(INF): Restore_files_and_directories'
        {
            Force = $True
            Identity = @('*S-1-5-32-544')
            Policy = 'Restore_files_and_directories'
        }
    }
    
    if($IsEnableTrustedDelegationEnabled){
        UserRightsAssignment 'UserRightsAssignment(INF): Enable_computer_and_user_accounts_to_be_trusted_for_delegation'
        {
            Force = $True
            Identity = @('')
            Policy = 'Enable_computer_and_user_accounts_to_be_trusted_for_delegation'
        }
    }
    
    if($IsBackUpFilesAndDirectoriesEnabled){
        UserRightsAssignment 'UserRightsAssignment(INF): Back_up_files_and_directories'
        {
            Force = $True
            Identity = @('*S-1-5-32-544')
            Policy = 'Back_up_files_and_directories'
        }
    }
    
    if($IsProfileSingleProcessEnabled){
        UserRightsAssignment 'UserRightsAssignment(INF): Profile_single_process'
        {
            Force = $True
            Identity = @('*S-1-5-32-544')
            Policy = 'Profile_single_process'
        }
    }
    
    if($IsDenyLogOnAsBatchJobEnabled){
        UserRightsAssignment 'UserRightsAssignment(INF): Deny_log_on_as_a_batch_job'
        {
            Force = $True
            Identity = @($DomainAdmins, $EnterpriseAdmins)
            Policy = 'Deny_log_on_as_a_batch_job'
        }
    }
    
    if($IsActAsPartOfOperatingSystemEnabled){
        UserRightsAssignment 'UserRightsAssignment(INF): Act_as_part_of_the_operating_system'
        {
            Force = $True
            Identity = @('')
            Policy = 'Act_as_part_of_the_operating_system'
        }
    }
    
    if($IsForceShutdownFromRemoteSystemEnabled){
        UserRightsAssignment 'UserRightsAssignment(INF): Force_shutdown_from_a_remote_system'
        {
            Force = $True
            Identity = @('*S-1-5-32-544')
            Policy = 'Force_shutdown_from_a_remote_system'
        }
    }
    
    if($IsImpersonateClientAfterAuthenticationEnabled){
        UserRightsAssignment 'UserRightsAssignment(INF): Impersonate_a_client_after_authentication'
        {
            Force = $True
            Identity = @('*S-1-5-32-544', '*S-1-5-19', '*S-1-5-20', '*S-1-5-6')
            Policy = 'Impersonate_a_client_after_authentication'
        }
    }
    
    if($IsDenyLogOnThroughRemoteDesktopEnabled){
        UserRightsAssignment 'UserRightsAssignment(INF): Deny_log_on_through_Remote_Desktop_Services'
        {
            Force = $True
            Identity = @($DomainAdmins, $EnterpriseAdmins, '*S-1-5-32-546', '*S-1-5-113')
            Policy = 'Deny_log_on_through_Remote_Desktop_Services'
        }
    }
    
    if($IsCreatePermanentSharedObjectsEnabled){
        UserRightsAssignment 'UserRightsAssignment(INF): Create_permanent_shared_objects'
        {
            Force = $True
            Identity = @('')
            Policy = 'Create_permanent_shared_objects'
        }
    }
    
    if($IsManageAuditingAndSecurityLogEnabled){
        UserRightsAssignment 'UserRightsAssignment(INF): Manage_auditing_and_security_log'
        {
            Force = $True
            Identity = @('*S-1-5-32-544')
            Policy = 'Manage_auditing_and_security_log'
        }
    }
    
    if($IsCreateSymbolicLinksEnabled){
        UserRightsAssignment 'UserRightsAssignment(INF): Create_symbolic_links'
        {
            Force = $True
            Identity = @('*S-1-5-32-544')
            Policy = 'Create_symbolic_links'
        }
    }
    
    if($IsResetAccountLockoutCounterEnabled){
        AccountPolicy 'SecuritySetting(INF): ResetLockoutCount'
        {
            Name = 'Reset_account_lockout_counter_after'
            Reset_account_lockout_counter_after = 15
        }
    }
    
    if($IsAllowAnonymousSIDNameTranslationEnabled){
        SecurityOption 'SecuritySetting(INF): LSAAnonymousNameLookup'
        {
            Network_access_Allow_anonymous_SID_Name_translation = 'Disabled'
            Name = 'Network_access_Allow_anonymous_SID_Name_translation'
        }
    }
    
    if($IsAccountLockoutDurationEnabled){
        AccountPolicy 'SecuritySetting(INF): LockoutDuration'
        {
            Account_lockout_duration = 15
            Name = 'Account_lockout_duration'
        }
    }
    
    if($IsRenameAdministratorAccountEnabled){
        SecurityOption 'SecuritySetting(INF): NewAdministratorName'
        {
            Name = 'Accounts_Rename_administrator_account'
            Accounts_Rename_administrator_account = 'X_Admin'
        }
    }
    
    if($IsEnforcePasswordHistoryEnabled){
        AccountPolicy 'SecuritySetting(INF): PasswordHistorySize'
        {
            Name = 'Enforce_password_history'
            Enforce_password_history = 24
        }
    }
    
    if($IsMinimumPasswordLengthEnabled){
        AccountPolicy 'SecuritySetting(INF): MinimumPasswordLength'
        {
            Minimum_Password_Length = 14
            Name = 'Minimum_Password_Length'
        }
    }
    
    if($IsMinimumPasswordAgeEnabled){
        AccountPolicy 'SecuritySetting(INF): MinimumPasswordAge'
        {
            Minimum_Password_Age = 1
            Name = 'Minimum_Password_Age'
        }
    }
    
    if($IsStorePasswordsUsingReversibleEncryptionEnabled){
        AccountPolicy 'SecuritySetting(INF): ClearTextPassword'
        {
            Store_passwords_using_reversible_encryption = 'Disabled'
            Name = 'Store_passwords_using_reversible_encryption'
        }
    }
    
    if($IsRenameGuestAccountEnabled){
        SecurityOption 'SecuritySetting(INF): NewGuestName'
        {
            Accounts_Rename_guest_account = 'Visitor'
            Name = 'Accounts_Rename_guest_account'
        }
    }
    
    if($IsGuestAccountStatusEnabled){
        SecurityOption 'SecuritySetting(INF): EnableGuestAccount'
        {
            Accounts_Guest_account_status = 'Disabled'
            Name = 'Accounts_Guest_account_status'
        }
    }
    
    if($IsAccountLockoutThresholdEnabled){
        AccountPolicy 'SecuritySetting(INF): LockoutBadCount'
        {
            Account_lockout_threshold = 3
            Name = 'Account_lockout_threshold'
        }
    }
    
    if($IsPasswordComplexityEnabled){
        AccountPolicy 'SecuritySetting(INF): PasswordComplexity'
        {
            Password_must_meet_complexity_requirements = 'Enabled'
            Name = 'Password_must_meet_complexity_requirements'
        }
    }
    
    if($IsAdministratorAccountStatusEnabled){
        SecurityOption 'SecuritySetting(INF): EnableAdminAccount'
        {
            Accounts_Administrator_account_status = 'Disabled'
            Name = 'Accounts_Administrator_account_status'
        }
    }
    
    if($IsMaximumPasswordAgeEnabled){
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

