configuration DoD_Office_2019-M365_Apps_V2R12
{

    param(
        [System.Boolean]$fileextensionsremovelevel1 = $true,
        [System.Boolean]$fileextensionsremovelevel2 = $true,
        [System.Boolean]$groove = $true,
        [System.Boolean]$excel = $true,
        [System.Boolean]$mspub = $true,
        [System.Boolean]$powerpnt = $true,
        [System.Boolean]$pptview = $true,
        [System.Boolean]$visio = $true,
        [System.Boolean]$winproj = $true,
        [System.Boolean]$winword = $true,
        [System.Boolean]$outlook = $true,
        [System.Boolean]$spdesign = $true,
        [System.Boolean]$exprwd = $true,
        [System.Boolean]$msaccess = $true,
        [System.Boolean]$onenote = $true,
        [System.Boolean]$mse7 = $true,
        [System.Boolean]$groove_http = $true,
        [System.Boolean]$excel_http = $true,
        [System.Boolean]$mspub_http = $true,
        [System.Boolean]$powerpnt_http = $true,
        [System.Boolean]$pptview_http = $true,
        [System.Boolean]$visio_http = $true,
        [System.Boolean]$winproj_http = $true,
        [System.Boolean]$winword_http = $true,
        [System.Boolean]$outlook_http = $true,
        [System.Boolean]$spdesign_http = $true,
        [System.Boolean]$exprwd_http = $true,    
        [System.Boolean]$msaccess_http = $true,
        [System.Boolean]$onenote_http = $true,
        [System.Boolean]$mse7_http = $true,
        [System.Boolean]$groove_lockdown = $true,
        [System.Boolean]$excel_lockdown = $true,
        [System.Boolean]$mspub_lockdown = $true,
        [System.Boolean]$powerpnt_lockdown = $true,
        [System.Boolean]$pptview_lockdown = $true,
        [System.Boolean]$visio_lockdown = $true,
        [System.Boolean]$winproj_lockdown = $true,
        [System.Boolean]$winword_lockdown = $true,
        [System.Boolean]$outlook_lockdown = $true,
        [System.Boolean]$spdesign_lockdown = $true,
        [System.Boolean]$exprwd_lockdown = $true,
        [System.Boolean]$onenote_lockdown = $true,
        [System.Boolean]$mse7_lockdown = $true,
        [System.Boolean]$groove_mime = $true,
        [System.Boolean]$excel_mime = $true,
        [System.Boolean]$mspub_mime = $true,
        [System.Boolean]$powerpnt_mime = $true,
        [System.Boolean]$pptview_mime = $true,
        [System.Boolean]$visio_mime = $true,
        [System.Boolean]$winproj_mime = $true,
        [System.Boolean]$winword_mime = $true,
        [System.Boolean]$outlook_mime = $true,
        [System.Boolean]$spdesign_mime = $true,
        [System.Boolean]$exprwd_mime = $true,
        [System.Boolean]$msaccess_mime = $true,
        [System.Boolean]$onenote_mime = $true,
        [System.Boolean]$mse7_mime = $true,
        [System.Boolean]$groove_sniffing = $true,
        [System.Boolean]$excel_sniffing = $true,
        [System.Boolean]$mspub_sniffing = $true,
        [System.Boolean]$powerpnt_sniffing = $true,
        [System.Boolean]$pptview_sniffing = $true,
        [System.Boolean]$visio_sniffing = $true,
        [System.Boolean]$winproj_sniffing = $true,
        [System.Boolean]$winword_sniffing = $true,
        [System.Boolean]$outlook_sniffing = $true,
        [System.Boolean]$spdesign_sniffing = $true,
        [System.Boolean]$exprwd_sniffing = $true,
        [System.Boolean]$msaccess_sniffing = $true,
        [System.Boolean]$onenote_sniffing = $true,
        [System.Boolean]$mse7_sniffing = $true,
        [System.Boolean]$groove_caching = $true,
        [System.Boolean]$excel_caching = $true,
        [System.Boolean]$mspub_caching = $true,
        [System.Boolean]$powerpnt_caching = $true,
        [System.Boolean]$pptview_caching = $true,
        [System.Boolean]$visio_caching = $true,
        [System.Boolean]$winproj_caching = $true,
        [System.Boolean]$winword_caching = $true,
        [System.Boolean]$outlook_caching = $true,
        [System.Boolean]$spdesign_caching = $true,
        [System.Boolean]$exprwd_caching = $true,
        [System.Boolean]$msaccess_caching = $true,
        [System.Boolean]$onenote_caching = $true,
        [System.Boolean]$mse7_caching = $true,
        [System.Boolean]$groove_restrict = $true,
        [System.Boolean]$excel_restrict = $true,
        [System.Boolean]$mspub_restrict = $true,
        [System.Boolean]$powerpnt_restrict = $true,
        [System.Boolean]$pptview_restrict = $true,
        [System.Boolean]$visio_restrict = $true,
        [System.Boolean]$winproj_restrict = $true,
        [System.Boolean]$winword_restrict = $true,
        [System.Boolean]$outlook_restrict = $true,
        [System.Boolean]$spdesign_restrict = $true,
        [System.Boolean]$exprwd_restrict = $true,
        [System.Boolean]$msaccess_restrict = $true,
        [System.Boolean]$onenote_restrict = $true,
        [System.Boolean]$mse7_restrict = $true,
        [System.Boolean]$groove_filedownload = $true,
        [System.Boolean]$excel_filedownload = $true,
        [System.Boolean]$mspub_filedownload = $true,
        [System.Boolean]$powerpnt_filedownload = $true,
        [System.Boolean]$pptview_filedownload = $true,
        [System.Boolean]$visio_filedownload = $true,
        [System.Boolean]$winproj_filedownload = $true,
        [System.Boolean]$winword_filedownload = $true,
        [System.Boolean]$outlook_filedownload = $true,
        [System.Boolean]$spdesign_filedownload = $true,
        [System.Boolean]$exprwd_filedownload = $true,
        [System.Boolean]$msaccess_filedownload = $true,
        [System.Boolean]$onenote_filedownload = $true,
        [System.Boolean]$mse7_filedownload = $true,
        [System.Boolean]$groove_security = $true,
        [System.Boolean]$excel_security = $true,
        [System.Boolean]$mspub_security = $true,
        [System.Boolean]$powerpnt_security = $true,
        [System.Boolean]$pptview_security = $true,
        [System.Boolean]$visio_security = $true,
        [System.Boolean]$winproj_security = $true,
        [System.Boolean]$winword_security = $true,
        [System.Boolean]$outlook_security = $true,
        [System.Boolean]$spdesign_security = $true,
        [System.Boolean]$exprwd_security = $true,
        [System.Boolean]$msaccess_security = $true,
        [System.Boolean]$onenote_security = $true,
        [System.Boolean]$mse7_security = $true,
        [System.Boolean]$groove_unc = $true,
        [System.Boolean]$excel_unc = $true,
        [System.Boolean]$mspub_unc = $true,
        [System.Boolean]$powerpnt_unc = $true,
        [System.Boolean]$pptview_unc = $true,
        [System.Boolean]$visio_unc = $true,
        [System.Boolean]$winproj_unc = $true,
        [System.Boolean]$winword_unc = $true,
        [System.Boolean]$outlook_unc = $true,
        [System.Boolean]$spdesign_unc = $true,
        [System.Boolean]$exprwd_unc = $true,
        [System.Boolean]$msaccess_unc = $true,
        [System.Boolean]$onenote_unc = $true,
        [System.Boolean]$mse7_unc = $true,
        [System.Boolean]$groove_navigate = $true,
        [System.Boolean]$excel_navigate = $true,
        [System.Boolean]$mspub_navigate = $true,
        [System.Boolean]$powerpnt_navigate = $true,
        [System.Boolean]$pptview_navigate = $true,
        [System.Boolean]$visio_navigate = $true,
        [System.Boolean]$winproj_navigate = $true,
        [System.Boolean]$winword_navigate = $true,
        [System.Boolean]$outlook_navigate = $true,
        [System.Boolean]$spdesign_navigate = $true,
        [System.Boolean]$exprwd_navigate = $true,
        [System.Boolean]$msaccess_navigate = $true,
        [System.Boolean]$onenote_navigate = $true,
        [System.Boolean]$mse7_navigate = $true,
        [System.Boolean]$groove_window = $true,
        [System.Boolean]$excel_window = $true,
        [System.Boolean]$mspub_window = $true,
        [System.Boolean]$powerpnt_window = $true,
        [System.Boolean]$pptview_window = $true,
        [System.Boolean]$visio_window = $true,
        [System.Boolean]$mse7_zone = $true,
        [System.Boolean]$groove_zone = $true,
        [System.Boolean]$excel_zone = $true,
        [System.Boolean]$mspub_zone = $true,
        [System.Boolean]$powerpnt_zone = $true,
        [System.Boolean]$pptview_zone = $true,
        [System.Boolean]$visio_zone = $true,
        [System.Boolean]$winproj_zone = $true,
        [System.Boolean]$winword_zone = $true,
        [System.Boolean]$outlook_zone = $true,
        [System.Boolean]$spdesign_zone = $true

    )

	Import-DSCResource -ModuleName 'GPRegistryPolicyDsc'
	Import-DSCResource -ModuleName 'AuditPolicyDSC'
	Import-DSCResource -ModuleName 'SecurityPolicyDSC'

    if($fileextensionsremovelevel1){
        RegistryPolicyFile 'DEL_CU:\software\policies\microsoft\office\16.0\outlook\security\fileextensionsremovelevel1'
        {
            Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
            TargetType = 'ComputerConfiguration'
            ValueType = 'String'
            ValueData = ''
            ValueName = 'fileextensionsremovelevel1'
            Ensure = 'Absent'
        }
    }
    
    if($fileextensionsremovelevel2){
        RegistryPolicyFile 'DEL_CU:\software\policies\microsoft\office\16.0\outlook\security\fileextensionsremovelevel2'
        {
            Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
            TargetType = 'ComputerConfiguration'
            ValueType = 'String'
            ValueData = ''
            ValueName = 'fileextensionsremovelevel2'
            Ensure = 'Absent'
        }
    }
    
    if($groove){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\groove.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'groove.exe'
        }
    }
    
    if($excel){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\excel.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'excel.exe'
        }
    }
    
    if($mspub){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\mspub.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'mspub.exe'
        }
    }
    
    if($powerpnt){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\powerpnt.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'powerpnt.exe'
        }
    }
    
    if($pptview){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\pptview.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'pptview.exe'
        }
    }
    
    if($visio){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\visio.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'visio.exe'
        }
    }
    
    if($winproj){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\winproj.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'winproj.exe'
        }
    }
    if($winword){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\winword.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'winword.exe'
        }
    }
    
    if($outlook){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\outlook.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'outlook.exe'
        }
    }
    
    if($spdesign){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\spdesign.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'spdesign.exe'
        }
    }
    
    if($exprwd){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\exprwd.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'exprwd.exe'
        }
    }
    
    if($msaccess){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\msaccess.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'msaccess.exe'
        }
    }
    
    if($onenote){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\onenote.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'onenote.exe'
        }
    }
    if($mse7){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\mse7.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'mse7.exe'
        }
    }
    
    if($groove_http){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\groove.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'groove.exe'
        }
    }
    
    if($excel_http){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\excel.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'excel.exe'
        }
    }
    
    if($mspub_http){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\mspub.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'mspub.exe'
        }
    }
    
    if($powerpnt_http){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\powerpnt.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'powerpnt.exe'
        }
    }
    
    if($pptview_http){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\pptview.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'pptview.exe'
        }
    }
    
    if($visio_http){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\visio.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'visio.exe'
        }
    }
    
    if($winproj_http){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\winproj.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'winproj.exe'
        }
    }
    
    if($winword_http){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\winword.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'winword.exe'
        }
    }
    
    if($outlook_http){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\outlook.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'outlook.exe'
        }
    }
    
    if($spdesign_http){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\spdesign.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'spdesign.exe'
        }
    }
    
    if($exprwd_http){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\exprwd.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'exprwd.exe'
        }
    }

    if($msaccess_http){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\msaccess.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'msaccess.exe'
        }
    }
    
    if($onenote_http){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\onenote.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'onenote.exe'
        }
    }
    
    if($mse7_http){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\mse7.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'mse7.exe'
        }
    }
    
    if($groove_lockdown){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown\groove.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'groove.exe'
        }
    }
    
    if($excel_lockdown){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown\excel.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'excel.exe'
        }
    }
    
    if($mspub_lockdown){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown\mspub.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'mspub.exe'
        }
    }
    
    if($powerpnt_lockdown){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown\powerpnt.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'powerpnt.exe'
        }
    }
    
    if($pptview_lockdown){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown\pptview.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'pptview.exe'
        }
    }
    
    if($visio_lockdown){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown\visio.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'visio.exe'
        }
    }
    
    if($winproj_lockdown){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown\winproj.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'winproj.exe'
        }
    }
    
    if($winword_lockdown){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown\winword.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'winword.exe'
        }
    }
    
    if($outlook_lockdown){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown\outlook.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'outlook.exe'
        }
    }
    
    if($spdesign_lockdown){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown\spdesign.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'spdesign.exe'
        }
    }
    
    if($exprwd_lockdown){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown\exprwd.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'exprwd.exe'
        }
    }
    
    if($msaccess_lockdown){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown\msaccess.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'msaccess.exe'
        }
    }

    if($onenote_lockdown){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown\onenote.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'onenote.exe'
        }
    }
    
    if($mse7_lockdown){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown\mse7.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'mse7.exe'
        }
    }
    
    if($groove_mime){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling\groove.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'groove.exe'
        }
    }
    
    if($excel_mime){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling\excel.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'excel.exe'
        }
    }
    
    if($mspub_mime){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling\mspub.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'mspub.exe'
        }
    }
    
    if($powerpnt_mime){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling\powerpnt.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'powerpnt.exe'
        }
    }
    
    if($pptview_mime){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling\pptview.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'pptview.exe'
        }
    }
    
    if($visio_mime){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling\visio.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'visio.exe'
        }
    }
    
    if($winproj_mime){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling\winproj.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'winproj.exe'
        }
    }
    
    if($winword_mime){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling\winword.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'winword.exe'
        }
    }
    
    if($outlook_mime){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling\outlook.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'outlook.exe'
        }
    }
    
    if($spdesign_mime){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling\spdesign.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'spdesign.exe'
        }
    }

    if($exprwd_mime){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling\exprwd.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'exprwd.exe'
        }
    }
    
    if($msaccess_mime){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling\msaccess.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'msaccess.exe'
        }
    }
    
    if($onenote_mime){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling\onenote.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'onenote.exe'
        }
    }
    
    if($mse7_mime){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling\mse7.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'mse7.exe'
        }
    }
    
    if($groove_sniffing){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing\groove.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'groove.exe'
        }
    }
    
    if($excel_sniffing){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing\excel.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'excel.exe'
        }
    }
    
    if($mspub_sniffing){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing\mspub.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'mspub.exe'
        }
    }
    
    if($powerpnt_sniffing){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing\powerpnt.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'powerpnt.exe'
        }
    }
    
    if($pptview_sniffing){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing\pptview.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'pptview.exe'
        }
    }
    
    if($visio_sniffing){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing\visio.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'visio.exe'
        }
    }
    
    if($winproj_sniffing){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing\winproj.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'winproj.exe'
        }
    }
    
    if($winword_sniffing){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing\winword.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'winword.exe'
        }
    }
    
    if($outlook_sniffing){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing\outlook.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'outlook.exe'
        }
    }
    
    if($spdesign_sniffing){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing\spdesign.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'spdesign.exe'
        }
    }
    
    if($exprwd_sniffing){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing\exprwd.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'exprwd.exe'
        }
    }
    
    if($msaccess_sniffing){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing\msaccess.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'msaccess.exe'
        }
    }
    
    if($onenote_sniffing){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing\onenote.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'onenote.exe'
        }
    }
    
    if($mse7_sniffing){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing\mse7.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'mse7.exe'
        }
    }
    
    if($groove_caching){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_object_caching\groove.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_object_caching'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'groove.exe'
        }
    }
    
    if($excel_caching){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_object_caching\excel.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_object_caching'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'excel.exe'
        }
    }

    if($mspub_caching){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_object_caching\mspub.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_object_caching'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'mspub.exe'
        }
    }
    
    if($powerpnt_caching){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_object_caching\powerpnt.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_object_caching'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'powerpnt.exe'
        }
    }
    
    if($pptview_caching){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_object_caching\pptview.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_object_caching'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'pptview.exe'
        }
    }
    
    if($visio_caching){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_object_caching\visio.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_object_caching'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'visio.exe'
        }
    }
    
    if($winproj_caching){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_object_caching\winproj.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_object_caching'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'winproj.exe'
        }
    }
    
    if($winword_caching){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_object_caching\winword.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_object_caching'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'winword.exe'
        }
    }
    
    if($outlook_caching){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_object_caching\outlook.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_object_caching'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'outlook.exe'
        }
    }
    
    if($spdesign_caching){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_object_caching\spdesign.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_object_caching'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'spdesign.exe'
        }
    }
    
    if($exprwd_caching){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_object_caching\exprwd.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_object_caching'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'exprwd.exe'
        }
    }
    
    if($msaccess_caching){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_object_caching\msaccess.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_object_caching'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'msaccess.exe'
        }
    }
    
    if($onenote_caching){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_object_caching\onenote.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_object_caching'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'onenote.exe'
        }
    }
    
    if($mse7_caching){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_object_caching\mse7.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_object_caching'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'mse7.exe'
        }
    }
    
    if($groove_restrict){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\groove.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'groove.exe'
        }
    }
    
    if($excel_restrict){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\excel.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'excel.exe'
        }
    }
    
    if($mspub_restrict){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\mspub.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'mspub.exe'
        }
    }
    if($powerpnt_restrict){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\powerpnt.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'powerpnt.exe'
        }
    }
    
    if($pptview_restrict){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\pptview.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'pptview.exe'
        }
    }
    
    if($visio_restrict){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\visio.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'visio.exe'
        }
    }
    
    if($winproj_restrict){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\winproj.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'winproj.exe'
        }
    }
    
    if($winword_restrict){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\winword.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'winword.exe'
        }
    }
    
    if($outlook_restrict){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\outlook.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'outlook.exe'
        }
    }
    
    if($spdesign_restrict){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\spdesign.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'spdesign.exe'
        }
    }
    
    if($exprwd_restrict){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\exprwd.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'exprwd.exe'
        }
    }
    
    if($msaccess_restrict){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\msaccess.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'msaccess.exe'
        }
    }
    
    if($onenote_restrict){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\onenote.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'onenote.exe'
        }
    }
    
    if($mse7_restrict){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\mse7.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'mse7.exe'
        }
    }
    
    if($groove_filedownload){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\groove.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'groove.exe'
        }
    }
    
    if($excel_filedownload){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\excel.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'excel.exe'
        }
    }
    if($mspub_filedownload){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\mspub.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'mspub.exe'
        }
    }
    
    if($powerpnt_filedownload){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\powerpnt.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'powerpnt.exe'
        }
    }
    
    if($pptview_filedownload){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\pptview.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'pptview.exe'
        }
    }
    
    if($visio_filedownload){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\visio.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'visio.exe'
        }
    }
    
    if($winproj_filedownload){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\winproj.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'winproj.exe'
        }
    }
    
    if($winword_filedownload){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\winword.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'winword.exe'
        }
    }
    
    if($outlook_filedownload){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\outlook.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'outlook.exe'
        }
    }
    
    if($spdesign_filedownload){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\spdesign.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'spdesign.exe'
        }
    }
    
    if($exprwd_filedownload){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\exprwd.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'exprwd.exe'
        }
    }
    
    if($msaccess_filedownload){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\msaccess.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'msaccess.exe'
        }
    }
    
    if($onenote_filedownload){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\onenote.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'onenote.exe'
        }
    }
    if($mse7_filedownload){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\mse7.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'mse7.exe'
        }
    }
    
    if($groove_security){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_securityband\groove.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_securityband'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'groove.exe'
        }
    }
    
    if($excel_security){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_securityband\excel.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_securityband'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'excel.exe'
        }
    }
    
    if($mspub_security){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_securityband\mspub.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_securityband'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'mspub.exe'
        }
    }
    
    if($powerpnt_security){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_securityband\powerpnt.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_securityband'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'powerpnt.exe'
        }
    }
    
    if($pptview_security){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_securityband\pptview.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_securityband'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'pptview.exe'
        }
    }
    
    if($visio_security){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_securityband\visio.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_securityband'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'visio.exe'
        }
    }
    
    if($winproj_security){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_securityband\winproj.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_securityband'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'winproj.exe'
        }
    }
    
    if($winword_security){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_securityband\winword.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_securityband'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'winword.exe'
        }
    }
    
    if($outlook_security){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_securityband\outlook.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_securityband'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'outlook.exe'
        }
    }
    
    if($spdesign_security){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_securityband\spdesign.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_securityband'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'spdesign.exe'
        }
    }
    if($exprwd_security){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_securityband\exprwd.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_securityband'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'exprwd.exe'
        }
    }
    
    if($msaccess_security){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_securityband\msaccess.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_securityband'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'msaccess.exe'
        }
    }
    
    if($onenote_security){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_securityband\onenote.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_securityband'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'onenote.exe'
        }
    }
    
    if($mse7_security){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_securityband\mse7.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_securityband'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'mse7.exe'
        }
    }
    
    if($groove_unc){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\groove.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'groove.exe'
        }
    }
    
    if($excel_unc){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\excel.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'excel.exe'
        }
    }
    
    if($mspub_unc){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\mspub.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'mspub.exe'
        }
    }
    
    if($powerpnt_unc){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\powerpnt.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'powerpnt.exe'
        }
    }
    
    if($pptview_unc){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\pptview.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'pptview.exe'
        }
    }
    
    if($visio_unc){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\visio.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'visio.exe'
        }
    }

    if($winproj_unc){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\winproj.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'winproj.exe'
        }
    }
    
    if($winword_unc){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\winword.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'winword.exe'
        }
    }
    
    if($outlook_unc){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\outlook.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'outlook.exe'
        }
    }
    
    if($spdesign_unc){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\spdesign.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'spdesign.exe'
        }
    }
    
    if($exprwd_unc){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\exprwd.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'exprwd.exe'
        }
    }
    
    if($msaccess_unc){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\msaccess.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'msaccess.exe'
        }
    }
    
    if($onenote_unc){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\onenote.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'onenote.exe'
        }
    }
    
    if($mse7_unc){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\mse7.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'mse7.exe'
        }
    }
    
    if($groove_navigate){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\groove.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'groove.exe'
        }
    }
    
    if($excel_navigate){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\excel.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'excel.exe'
        }
    }
    
    if($mspub_navigate){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\mspub.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'mspub.exe'
        }
    }
    
    if($powerpnt_navigate){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\powerpnt.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'powerpnt.exe'
        }
    }
    
    if($pptview_navigate){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\pptview.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'pptview.exe'
        }
    }
    
    if($visio_navigate){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\visio.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'visio.exe'
        }
    }

    if($winproj_navigate){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\winproj.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'winproj.exe'
        }
    }
    
    if($winword_navigate){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\winword.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'winword.exe'
        }
    }
    
    if($outlook_navigate){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\outlook.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'outlook.exe'
        }
    }
    
    if($spdesign_navigate){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\spdesign.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'spdesign.exe'
        }
    }
    
    if($exprwd_navigate){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\exprwd.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'exprwd.exe'
        }
    }
    
    if($msaccess_navigate){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\msaccess.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'msaccess.exe'
        }
    }
    
    if($onenote_navigate){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\onenote.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'onenote.exe'
        }
    }
    
    if($mse7_navigate){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\mse7.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'mse7.exe'
        }
    }
    
    if($groove_window){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\groove.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'groove.exe'
        }
    }
    
    if($excel_window){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\excel.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'excel.exe'
        }
    }
    
    if($mspub_window){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\mspub.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'mspub.exe'
        }
    }
    
    if($powerpnt_window){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\powerpnt.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'powerpnt.exe'
        }
    }
    
    if($pptview_window){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\pptview.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'pptview.exe'
        }
    }
    
    if($visio_window){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\visio.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'visio.exe'
        }
    }

    if($mse7_zone){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\mse7.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'mse7.exe'
        }
    }
    
    if($groove_zone){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\groove.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'groove.exe'
        }
    }
    
    if($excel_zone){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\excel.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'excel.exe'
        }
    }
    
    if($mspub_zone){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\mspub.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'mspub.exe'
        }
    }
    
    if($powerpnt_zone){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\powerpnt.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'powerpnt.exe'
        }
    }
    
    if($pptview_zone){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\pptview.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'pptview.exe'
        }
    }
    
    if($visio_zone){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\visio.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'visio.exe'
        }
    }
    
    if($winproj_zone){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\winproj.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'winproj.exe'
        }
    }
    
    if($winword_zone){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\winword.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'winword.exe'
        }
    }
    
    if($outlook_zone){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\outlook.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'outlook.exe'
        }
    }
    
    if($spdesign_zone){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\spdesign.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'spdesign.exe'
        }
    }
    
    if($exprwd_zone){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\exprwd.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'exprwd.exe'
        }
    }
    
    if($msaccess_zone){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\msaccess.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'msaccess.exe'
        }
    }
    
    if($onenote_zone){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\onenote.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'onenote.exe'
        }
    }

    RefreshRegistryPolicy 'ActivateClientSideExtension'
    {
        IsSingleInstance = 'Yes'
    }
}

