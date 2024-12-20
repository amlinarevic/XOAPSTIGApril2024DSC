configuration DoD_Windows_Defender_Firewall_V2R2
{

    param(
        [System.Boolean]$SetPolicyVersion = $true,
        [System.Boolean]$EnableFirewallDomainProfile = $true,
        [System.Boolean]$DefaultOutboundActionDomainProfile = $true,
        [System.Boolean]$DefaultInboundActionDomainProfile = $true,
        [System.Boolean]$LogFileSizeDomainProfile = $true,
        [System.Boolean]$LogDroppedPacketsDomainProfile = $true,
        [System.Boolean]$LogSuccessfulConnectionsDomainProfile = $true,
        [System.Boolean]$EnableFirewallPrivateProfile = $true,
        [System.Boolean]$DefaultOutboundActionPrivateProfile = $true,
        [System.Boolean]$DefaultInboundActionPrivateProfile = $true,
        [System.Boolean]$LogFileSizePrivateProfile = $true,
        [System.Boolean]$LogDroppedPacketsPrivateProfile = $true,
        [System.Boolean]$LogSuccessfulConnectionsPrivateProfile = $true,
        [System.Boolean]$EnableFirewallPublicProfile = $true,
        [System.Boolean]$DefaultOutboundActionPublicProfile = $true,
        [System.Boolean]$DefaultInboundActionPublicProfile = $true,
        [System.Boolean]$AllowLocalPolicyMergePublicProfile = $true,
        [System.Boolean]$AllowLocalIPsecPolicyMergePublicProfile = $true,
        [System.Boolean]$LogFileSizePublicProfile = $true,
        [System.Boolean]$LogDroppedPacketsPublicProfile = $true,
        [System.Boolean]$LogSuccessfulConnectionsPublicProfile = $true
    )

	Import-DSCResource -ModuleName 'GPRegistryPolicyDsc'
	Import-DSCResource -ModuleName 'AuditPolicyDSC'
	Import-DSCResource -ModuleName 'SecurityPolicyDSC'

    if($SetPolicyVersion){
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PolicyVersion'
        {
            Key = 'SOFTWARE\Policies\Microsoft\WindowsFirewall'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 539
            ValueName = 'PolicyVersion'
        }
    }
    
    if($EnableFirewallDomainProfile){
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\EnableFirewall'
        {
            Key = 'SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'EnableFirewall'
        }
    }
    
    if($DefaultOutboundActionDomainProfile){
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\DefaultOutboundAction'
        {
            Key = 'SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'DefaultOutboundAction'
        }
    }
    
    if($DefaultInboundActionDomainProfile){
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\DefaultInboundAction'
        {
            Key = 'SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'DefaultInboundAction'
        }
    }
    
    if($LogFileSizeDomainProfile){
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging\LogFileSize'
        {
            Key = 'SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 16384
            ValueName = 'LogFileSize'
        }
    }
    
    if($LogDroppedPacketsDomainProfile){
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging\LogDroppedPackets'
        {
            Key = 'SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'LogDroppedPackets'
        }
    }
    
    if($LogSuccessfulConnectionsDomainProfile){
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging\LogSuccessfulConnections'
        {
            Key = 'SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'LogSuccessfulConnections'
        }
    }
    
    if($EnableFirewallPrivateProfile){
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\EnableFirewall'
        {
            Key = 'SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'EnableFirewall'
        }
    }
    
    if($DefaultOutboundActionPrivateProfile){
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\DefaultOutboundAction'
        {
            Key = 'SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'DefaultOutboundAction'
        }
    }
    
    if($DefaultInboundActionPrivateProfile){
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\DefaultInboundAction'
        {
            Key = 'SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'DefaultInboundAction'
        }
    }
    
    if($LogFileSizePrivateProfile){
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging\LogFileSize'
        {
            Key = 'SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 16384
            ValueName = 'LogFileSize'
        }
    }
    
    if($LogDroppedPacketsPrivateProfile){
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging\LogDroppedPackets'
        {
            Key = 'SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'LogDroppedPackets'
        }
    }
    
    if($LogSuccessfulConnectionsPrivateProfile){
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging\LogSuccessfulConnections'
        {
            Key = 'SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'LogSuccessfulConnections'
        }
    }
    
    if($EnableFirewallPublicProfile){
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\EnableFirewall'
        {
            Key = 'SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'EnableFirewall'
        }
    }
    
    if($DefaultOutboundActionPublicProfile){
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\DefaultOutboundAction'
        {
            Key = 'SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'DefaultOutboundAction'
        }
    }
    
    if($DefaultInboundActionPublicProfile){
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\DefaultInboundAction'
        {
            Key = 'SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'DefaultInboundAction'
        }
    }
    
    if($AllowLocalPolicyMergePublicProfile){
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\AllowLocalPolicyMerge'
        {
            Key = 'SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'AllowLocalPolicyMerge'
        }
    }
    
    if($AllowLocalIPsecPolicyMergePublicProfile){
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\AllowLocalIPsecPolicyMerge'
        {
            Key = 'SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'AllowLocalIPsecPolicyMerge'
        }
    }
    
    if($LogFileSizePublicProfile){
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging\LogFileSize'
        {
            Key = 'SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 16384
            ValueName = 'LogFileSize'
        }
    }
    
    if($LogDroppedPacketsPublicProfile){
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging\LogDroppedPackets'
        {
            Key = 'SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'LogDroppedPackets'
        }
    }
    
    if($LogSuccessfulConnectionsPublicProfile){
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging\LogSuccessfulConnections'
        {
            Key = 'SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'LogSuccessfulConnections'
        }
    }
    
    RefreshRegistryPolicy 'ActivateClientSideExtension'
    {
        IsSingleInstance = 'Yes'
    }
}

