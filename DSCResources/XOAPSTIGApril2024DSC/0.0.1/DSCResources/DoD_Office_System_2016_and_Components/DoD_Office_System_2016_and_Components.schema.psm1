configuration DoD_Office_System_2016_and_Components
{

    param(
        [System.Boolean]$groove_addon = $true,
        [System.Boolean]$excel_addon = $true,
        [System.Boolean]$mspub_addon = $true,
        [System.Boolean]$powerpnt_addon = $true,
        [System.Boolean]$pptview_addon = $true,
        [System.Boolean]$visio_addon = $true,
        [System.Boolean]$winproj_addon = $true,
        [System.Boolean]$winword_addon = $true,
        [System.Boolean]$outlook_addon = $true,
        [System.Boolean]$spdesign_addon = $false,
        [System.Boolean]$exprwd_addon = $false,
        [System.Boolean]$msaccess_addon = $true,
        [System.Boolean]$onenote_addon = $true,
        [System.Boolean]$mse7_addon = $false,
        [System.Boolean]$groove_http = $true,
        [System.Boolean]$excel_http = $true,
        [System.Boolean]$mspub_http = $true,
        [System.Boolean]$powerpnt_http = $true,
        [System.Boolean]$pptview_http = $true,
        [System.Boolean]$visio_http = $true,
        [System.Boolean]$winproj_http = $true,
        [System.Boolean]$winword_http = $true,
        [System.Boolean]$outlook_http = $true,
        [System.Boolean]$spdesign_http = $false,
        [System.Boolean]$exprwd_http = $false,
        [System.Boolean]$msaccess_http = $true,
        [System.Boolean]$onenote_http = $true,
        [System.Boolean]$mse7_http = $false,
        [System.Boolean]$groove_restrict = $true,
        [System.Boolean]$excel_restrict = $true,
        [System.Boolean]$mspub_restrict = $true,
        [System.Boolean]$powerpnt_restrict = $true,
        [System.Boolean]$pptview_restrict = $true,
        [System.Boolean]$visio_restrict = $true,
        [System.Boolean]$winproj_restrict = $true,
        [System.Boolean]$winword_restrict = $true,
        [System.Boolean]$outlook_restrict = $true,
        [System.Boolean]$spdesign_restrict = $false,
        [System.Boolean]$exprwd_restrict = $false,
        [System.Boolean]$msaccess_restrict = $true,
        [System.Boolean]$onenote_restrict = $true,
        [System.Boolean]$mse7_restrict = $false,
        [System.Boolean]$groove_filedownload = $true,
        [System.Boolean]$excel_filedownload = $true,
        [System.Boolean]$mspub_filedownload = $true,
        [System.Boolean]$powerpnt_filedownload = $true,
        [System.Boolean]$pptview_filedownload = $true,
        [System.Boolean]$visio_filedownload = $true,
        [System.Boolean]$winproj_filedownload = $true,
        [System.Boolean]$winword_filedownload = $true,
        [System.Boolean]$outlook_filedownload = $true,
        [System.Boolean]$spdesign_filedownload = $false,
        [System.Boolean]$exprwd_filedownload = $false,
        [System.Boolean]$msaccess_filedownload = $true,
        [System.Boolean]$onenote_filedownload = $true,
        [System.Boolean]$mse7_filedownload = $false,
        [System.Boolean]$groove_safe = $true,
        [System.Boolean]$excel_safe = $true,
        [System.Boolean]$mspub_safe = $true,
        [System.Boolean]$powerpnt_safe = $true,
        [System.Boolean]$pptview_safe = $true,
        [System.Boolean]$visio_safe = $true,
        [System.Boolean]$winwordExe = $true,
        [System.Boolean]$outlookExe = $true,
        [System.Boolean]$spdesignExe = $true,
        [System.Boolean]$exprwdExe = $true,
        [System.Boolean]$msaccessExe = $true,
        [System.Boolean]$onenoteExe = $true,
        [System.Boolean]$mse7Exe = $true,
        [System.Boolean]$grooveExe = $true,
        [System.Boolean]$excelExe = $true,
        [System.Boolean]$mspubExe = $true,
        [System.Boolean]$powerpntExe = $true,
        [System.Boolean]$pptviewExe = $true,
        [System.Boolean]$visioExe = $true,
        [System.Boolean]$winprojExe = $true,
        [System.Boolean]$winwordExe1 = $true,
        [System.Boolean]$outlookExe1 = $true,
        [System.Boolean]$spdesignExe1 = $true,
        [System.Boolean]$exprwdExe1 = $true,
        [System.Boolean]$msaccessExe1 = $true,
        [System.Boolean]$onenoteExe1 = $true,
        [System.Boolean]$mse7Exe1 = $true,
        [System.Boolean]$grooveExe1 = $true,
        [System.Boolean]$excelExe1 = $true,
        [System.Boolean]$mspub_popupManagement = $true,
        [System.Boolean]$powerpoint_popupManagement = $true,
        [System.Boolean]$pptviewer_popupManagement = $true,
        [System.Boolean]$visio_popupManagement = $true,
        [System.Boolean]$project_popupManagement = $true,
        [System.Boolean]$word_popupManagement = $true,
        [System.Boolean]$outlook_popupManagement = $true,
        [System.Boolean]$spdesign_popupManagement = $false,
        [System.Boolean]$excel_popupManagement = $false,
        [System.Boolean]$access_popupManagement = $true,
        [System.Boolean]$onenote_popupManagement = $true,
        [System.Boolean]$mse7_popupManagement = $false,
        [System.Boolean]$groove_windowRestrictions = $true,
        [System.Boolean]$excel_windowRestriction = $true,
        [System.Boolean]$mspub_windowRestriction = $true,
        [System.Boolean]$powerpoint_windowRestriction = $true,
        [System.Boolean]$pptviewer_windowRestriction = $true,
        [System.Boolean]$visio_windowRestriction = $true,
        [System.Boolean]$project_windowRestriction = $true,
        [System.Boolean]$word_windowRestriction = $true,
        [System.Boolean]$outlook_windowRestriction = $true,
        [System.Boolean]$spdesign_windowRestriction = $false,
        [System.Boolean]$excel_exprwdRestriction = $false,
        [System.Boolean]$msaccess_windowRestriction = $true,
        [System.Boolean]$onenote_windowRestriction = $true,
        [System.Boolean]$mse7_windowRestriction = $false,
        [System.Boolean]$groove_zoneElevation = $true,
        [System.Boolean]$excel_zoneElevation = $true,
        [System.Boolean]$mspub_zoneElevation = $true,
        [System.Boolean]$powerpoint_zoneElevation = $true,
        [System.Boolean]$pptviewer_zoneElevation = $true,
        [System.Boolean]$visio_zoneElevation = $true,
        [System.Boolean]$project_zoneElevation = $true,
        [System.Boolean]$word_zoneElevation = $true,
        [System.Boolean]$outlook_zoneElevation = $true,
        [System.Boolean]$spdesign_zoneElevation = $false,
        [System.Boolean]$exprwd_zoneElevation = $false,
        [System.Boolean]$msaccess_zoneElevation = $true,
        [System.Boolean]$onenote_zoneElevation = $true,
        [System.Boolean]$mse7_zoneElevation = $false,
        [System.Boolean]$groove_safeBind = $true,
        [System.Boolean]$excel_safeBind = $true,
        [System.Boolean]$mspub_safeBind = $true,
        [System.Boolean]$powerpoint_safeBind = $true,
        [System.Boolean]$pptviewer_safeBind = $true,
        [System.Boolean]$visio_safeBind = $true,
        [System.Boolean]$project_safeBind = $true,
        [System.Boolean]$word_safeBind = $true,
        [System.Boolean]$lync_savePassword = $false,
        [System.Boolean]$lync_enableSipHighSecurity = $true,
        [System.Boolean]$lync_disableHttpConnect = $true
        )

	Import-DSCResource -ModuleName 'GPRegistryPolicyDsc'
	Import-DSCResource -ModuleName 'AuditPolicyDSC'
	Import-DSCResource -ModuleName 'SecurityPolicyDSC'

    if($groove_addon){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\groove.exe'
        {
            Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'groove.exe'
        }
    }
    
    if($excel_addon){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\excel.exe'
        {
            Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'excel.exe'
        }
    }
    
    if($mspub_addon){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\mspub.exe'
        {
            Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'mspub.exe'
        }
    }
    
    if($powerpnt_addon){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\powerpnt.exe'
        {
            Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'powerpnt.exe'
        }
    }
    
    if($pptview_addon){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\pptview.exe'
        {
            Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'pptview.exe'
        }
    }
    
    if($visio_addon){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\visio.exe'
        {
            Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'visio.exe'
        }
    }
    
    if($winproj_addon){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\winproj.exe'
        {
            Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'winproj.exe'
        }
    }
    
    if($winword_addon){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\winword.exe'
        {
            Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'winword.exe'
        }
    }
    
    if($outlook_addon){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\outlook.exe'
        {
            Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'outlook.exe'
        }
    }
    
    if($spdesign_addon -eq $false){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\spdesign.exe'
        {
            Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'spdesign.exe'
        }
    }
    
    if($exprwd_addon -eq $false){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\exprwd.exe'
        {
            Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'exprwd.exe'
        }
    }
    
    if($msaccess_addon){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\msaccess.exe'
        {
            Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'msaccess.exe'
        }
    }
    
    if($onenote_addon){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\onenote.exe'
        {
            Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'onenote.exe'
        }
    }
    
    if($mse7_addon -eq $false){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\mse7.exe'
        {
            Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'mse7.exe'
        }
    }
    
    if($groove_http){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\groove.exe'
        {
            Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'groove.exe'
        }
    }
    if($excel_http){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\excel.exe'
        {
            Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'excel.exe'
        }
    }
    
    if($mspub_http){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\mspub.exe'
        {
            Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'mspub.exe'
        }
    }
    
    if($powerpnt_http){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\powerpnt.exe'
        {
            Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'powerpnt.exe'
        }
    }
    
    if($pptview_http){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\pptview.exe'
        {
            Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'pptview.exe'
        }
    }
    
    if($visio_http){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\visio.exe'
        {
            Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'visio.exe'
        }
    }
    
    if($winproj_http){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\winproj.exe'
        {
            Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'winproj.exe'
        }
    }
    
    if($winword_http){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\winword.exe'
        {
            Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'winword.exe'
        }
    }
    
    if($outlook_http){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\outlook.exe'
        {
            Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'outlook.exe'
        }
    }
    
    if($spdesign_http -eq $false){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\spdesign.exe'
        {
            Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'spdesign.exe'
        }
    }
    
    if($exprwd_http -eq $false){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\exprwd.exe'
        {
            Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'exprwd.exe'
        }
    }
    
    if($msaccess_http){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\msaccess.exe'
        {
            Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'msaccess.exe'
        }
    }
    
    if($onenote_http){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\onenote.exe'
        {
            Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'onenote.exe'
        }
    }
    
    if($mse7_http -eq $false){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\mse7.exe'
        {
            Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'mse7.exe'
        }
    }
    
    if($groove_restrict){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\groove.exe'
        {
            Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'groove.exe'
        }
    }
    
    if($excel_restrict){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\excel.exe'
        {
            Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'excel.exe'
        }
    }
    
    if($mspub_restrict){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\mspub.exe'
        {
            Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'mspub.exe'
        }
    }

    if($powerpnt_restrict){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\powerpnt.exe'
        {
            Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'powerpnt.exe'
        }
    }
    
    if($pptview_restrict){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\pptview.exe'
        {
            Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'pptview.exe'
        }
    }
    
    if($visio_restrict){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\visio.exe'
        {
            Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'visio.exe'
        }
    }
    
    if($winproj_restrict){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\winproj.exe'
        {
            Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'winproj.exe'
        }
    }
    
    if($winword_restrict){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\winword.exe'
        {
            Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'winword.exe'
        }
    }
    
    if($outlook_restrict){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\outlook.exe'
        {
            Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'outlook.exe'
        }
    }
    
    if($spdesign_restrict -eq $false){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\spdesign.exe'
        {
            Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'spdesign.exe'
        }
    }
    
    if($exprwd_restrict -eq $false){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\exprwd.exe'
        {
            Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'exprwd.exe'
        }
    }
    
    if($msaccess_restrict){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\msaccess.exe'
        {
            Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'msaccess.exe'
        }
    }
    
    if($onenote_restrict){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\onenote.exe'
        {
            Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'onenote.exe'
        }
    }
    
    if($mse7_restrict -eq $false){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\mse7.exe'
        {
            Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'mse7.exe'
        }
    }
    
    if($groove_filedownload){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\groove.exe'
        {
            Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'groove.exe'
        }
    }
    
    if($excel_filedownload){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\excel.exe'
        {
            Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'excel.exe'
        }
    }
    
    if($mspub_filedownload){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\mspub.exe'
        {
            Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'mspub.exe'
        }
    }
    
    if($powerpnt_filedownload){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\powerpnt.exe'
        {
            Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'powerpnt.exe'
        }
    }
    
    if($pptview_filedownload){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\pptview.exe'
        {
            Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'pptview.exe'
        }
    }
    
    if($visio_filedownload){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\visio.exe'
        {
            Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'visio.exe'
        }
    }
    
    if($winproj_filedownload){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\winproj.exe'
        {
            Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'winproj.exe'
        }
    }
    
    if($winword_filedownload){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\winword.exe'
        {
            Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'winword.exe'
        }
    }
    if($outlook_filedownload){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\outlook.exe'
        {
            Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'outlook.exe'
        }
    }
    
    if($spdesign_filedownload -eq $false){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\spdesign.exe'
        {
            Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'spdesign.exe'
        }
    }
    
    if($exprwd_filedownload -eq $false){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\exprwd.exe'
        {
            Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'exprwd.exe'
        }
    }
    
    if($msaccess_filedownload){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\msaccess.exe'
        {
            Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'msaccess.exe'
        }
    }
    
    if($onenote_filedownload){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\onenote.exe'
        {
            Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'onenote.exe'
        }
    }
    
    if($mse7_filedownload -eq $false){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\mse7.exe'
        {
            Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'mse7.exe'
        }
    }
    
    if($groove_safe){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\groove.exe'
        {
            Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'groove.exe'
        }
    }
    
    if($excel_safe){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\excel.exe'
        {
            Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'excel.exe'
        }
    }
    
    if($mspub_safe){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\mspub.exe'
        {
            Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'mspub.exe'
        }
    }
    
    if($powerpnt_safe){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\powerpnt.exe'
        {
            Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'powerpnt.exe'
        }
    }
    
    if($pptview_safe){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\pptview.exe'
        {
            Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'pptview.exe'
        }
    }
    
    if($visio_safe){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\visio.exe'
        {
            Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'visio.exe'
        }
    }
    if($winwordExe){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\winword.exe'
        {
            Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'winword.exe'
        }
    }
    
    if($outlookExe){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\outlook.exe'
        {
            Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'outlook.exe'
        }
    }
    
    if($spdesignExe){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\spdesign.exe'
        {
            Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'spdesign.exe'
        }
    }
    
    if($exprwdExe){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\exprwd.exe'
        {
            Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'exprwd.exe'
        }
    }
    
    if($msaccessExe){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\msaccess.exe'
        {
            Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'msaccess.exe'
        }
    }
    
    if($onenoteExe){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\onenote.exe'
        {
            Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'onenote.exe'
        }
    }
    
    if($mse7Exe){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\mse7.exe'
        {
            Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'mse7.exe'
        }
    }
    
    if($grooveExe){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\groove.exe'
        {
            Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'groove.exe'
        }
    }
    
    if($excelExe){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\excel.exe'
        {
            Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'excel.exe'
        }
    }
    
    if($mspubExe){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\mspub.exe'
        {
            Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'mspub.exe'
        }
    }
    
    if($powerpntExe){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\powerpnt.exe'
        {
            Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'powerpnt.exe'
        }
    }
    if($pptviewExe){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\pptview.exe'
        {
            Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'pptview.exe'
        }
    }
    
    if($visioExe){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\visio.exe'
        {
            Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'visio.exe'
        }
    }
    
    if($winprojExe){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\winproj.exe'
        {
            Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'winproj.exe'
        }
    }
    
    if($winwordExe){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\winword.exe'
        {
            Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'winword.exe'
        }
    }
    
    if($outlookExe){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\outlook.exe'
        {
            Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'outlook.exe'
        }
    }
    
    if($spdesignExe){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\spdesign.exe'
        {
            Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'spdesign.exe'
        }
    }
    
    if($exprwdExe){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\exprwd.exe'
        {
            Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'exprwd.exe'
        }
    }
    
    if($msaccessExe){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\msaccess.exe'
        {
            Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'msaccess.exe'
        }
    }
    
    if($onenoteExe){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\onenote.exe'
        {
            Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'onenote.exe'
        }
    }
    
    if($mse7Exe){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\mse7.exe'
        {
            Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'mse7.exe'
        }
    }
    
    if($grooveExe){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement\groove.exe'
        {
            Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'groove.exe'
        }
    }
    
    if($excelExe){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement\excel.exe'
        {
            Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'excel.exe'
        }
    }
    if($pptviewExe){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\pptview.exe'
        {
            Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'pptview.exe'
        }
    }
    
    if($visioExe){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\visio.exe'
        {
            Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'visio.exe'
        }
    }
    
    if($winprojExe){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\winproj.exe'
        {
            Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'winproj.exe'
        }
    }
    
    if($winwordExe1){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\winword.exe'
        {
            Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'winword.exe'
        }
    }
    
    if($outlookExe1){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\outlook.exe'
        {
            Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'outlook.exe'
        }
    }
    
    if($spdesignExe1){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\spdesign.exe'
        {
            Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'spdesign.exe'
        }
    }
    
    if($exprwdExe1){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\exprwd.exe'
        {
            Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'exprwd.exe'
        }
    }
    
    if($msaccessExe1){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\msaccess.exe'
        {
            Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'msaccess.exe'
        }
    }
    
    if($onenoteExe1){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\onenote.exe'
        {
            Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'onenote.exe'
        }
    }
    
    if($mse7Exe1){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\mse7.exe'
        {
            Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'mse7.exe'
        }
    }
    
    if($grooveExe1){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement\groove.exe'
        {
            Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'groove.exe'
        }
    }
    
    if($excelExe1){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement\excel.exe'
        {
            Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'excel.exe'
        }
    }
    if($mspub_popupManagement){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement\mspub.exe'
        {
            Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'mspub.exe'
        }
    }
    
    if($powerpoint_popupManagement){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement\powerpnt.exe'
        {
            Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'powerpnt.exe'
        }
    }
    
    if($pptviewer_popupManagement){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement\pptview.exe'
        {
            Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'pptview.exe'
        }
    }
    
    if($visio_popupManagement){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement\visio.exe'
        {
            Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'visio.exe'
        }
    }
    
    if($project_popupManagement){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement\winproj.exe'
        {
            Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'winproj.exe'
        }
    }
    
    if($word_popupManagement){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement\winword.exe'
        {
            Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'winword.exe'
        }
    }
    
    if($outlook_popupManagement){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement\outlook.exe'
        {
            Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'outlook.exe'
        }
    }
    
    if($spdesign_popupManagement){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement\spdesign.exe'
        {
            Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'spdesign.exe'
        }
    }
    
    if($excel_popupManagement){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement\exprwd.exe'
        {
            Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'exprwd.exe'
        }
    }
    
    if($access_popupManagement){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement\msaccess.exe'
        {
            Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'msaccess.exe'
        }
    }
    
    if($onenote_popupManagement){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement\onenote.exe'
        {
            Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'onenote.exe'
        }
    }
    
    if($mse7_popupManagement){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement\mse7.exe'
        {
            Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'mse7.exe'
        }
    }
    
    if($groove_windowRestrictions){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\groove.exe'
        {
            Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'groove.exe'
        }
    }
    if($excel_windowRestriction){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\excel.exe'
        {
            Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'excel.exe'
        }
    }
    
    if($mspub_windowRestriction){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\mspub.exe'
        {
            Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'mspub.exe'
        }
    }
    
    if($powerpoint_windowRestriction){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\powerpnt.exe'
        {
            Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'powerpnt.exe'
        }
    }
    
    if($pptviewer_windowRestriction){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\pptview.exe'
        {
            Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'pptview.exe'
        }
    }
    
    if($visio_windowRestriction){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\visio.exe'
        {
            Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'visio.exe'
        }
    }
    
    if($project_windowRestriction){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\winproj.exe'
        {
            Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'winproj.exe'
        }
    }
    
    if($word_windowRestriction){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\winword.exe'
        {
            Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'winword.exe'
        }
    }
    
    if($outlook_windowRestriction){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\outlook.exe'
        {
            Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'outlook.exe'
        }
    }
    
    if($spdesign_windowRestriction){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\spdesign.exe'
        {
            Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'spdesign.exe'
        }
    }
    
    if($excel_exprwdRestriction){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\exprwd.exe'
        {
            Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'exprwd.exe'
        }
    }
    if($msaccess_windowRestriction){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\msaccess.exe'
        {
            Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'msaccess.exe'
        }
    }
    
    if($onenote_windowRestriction){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\onenote.exe'
        {
            Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'onenote.exe'
        }
    }
    
    if($mse7_windowRestriction){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\mse7.exe'
        {
            Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'mse7.exe'
        }
    }
    
    if($groove_zoneElevation){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\groove.exe'
        {
            Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'groove.exe'
        }
    }
    
    if($excel_zoneElevation){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\excel.exe'
        {
            Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'excel.exe'
        }
    }
    
    if($mspub_zoneElevation){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\mspub.exe'
        {
            Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'mspub.exe'
        }
    }
    
    if($powerpoint_zoneElevation){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\powerpnt.exe'
        {
            Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'powerpnt.exe'
        }
    }
    
    if($pptviewer_zoneElevation){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\pptview.exe'
        {
            Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'pptview.exe'
        }
    }
    
    if($visio_zoneElevation){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\visio.exe'
        {
            Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'visio.exe'
        }
    }
    
    if($project_zoneElevation){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\winproj.exe'
        {
            Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'winproj.exe'
        }
    }
    
    if($word_zoneElevation){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\winword.exe'
        {
            Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'winword.exe'
        }
    }
    if($outlook_zoneElevation){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\outlook.exe'
        {
            Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'outlook.exe'
        }
    }
    
    if($spdesign_zoneElevation){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\spdesign.exe'
        {
            Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'spdesign.exe'
        }
    }
    
    if($exprwd_zoneElevation){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\exprwd.exe'
        {
            Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'exprwd.exe'
        }
    }
    
    if($msaccess_zoneElevation){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\msaccess.exe'
        {
            Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'msaccess.exe'
        }
    }
    
    if($onenote_zoneElevation){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\onenote.exe'
        {
            Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'onenote.exe'
        }
    }
    
    if($mse7_zoneElevation){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\mse7.exe'
        {
            Key = 'HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'mse7.exe'
        }
    }
    
    if($groove_safeBind){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\groove.exe'
        {
            Key = 'HKLM:\software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'groove.exe'
        }
    }
    
    if($excel_safeBind){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\excel.exe'
        {
            Key = 'HKLM:\software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'excel.exe'
        }
    }
    
    if($mspub_safeBind){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\mspub.exe'
        {
            Key = 'HKLM:\software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'mspub.exe'
        }
    }
    
    if($powerpoint_safeBind){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\powerpnt.exe'
        {
            Key = 'HKLM:\software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'powerpnt.exe'
        }
    }
    
    if($pptviewer_safeBind){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\pptview.exe'
        {
            Key = 'HKLM:\software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'pptview.exe'
        }
    }
    
    if($visio_safeBind){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\visio.exe'
        {
            Key = 'HKLM:\software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'visio.exe'
        }
    }
    
    if($project_safeBind){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\winproj.exe'
        {
            Key = 'HKLM:\software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'winproj.exe'
        }
    }
    
    if($word_safeBind){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\winword.exe'
        {
            Key = 'HKLM:\software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'winword.exe'
        }
    }
    
    if($outlook_safeBind){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\outlook.exe'
        {
            Key = 'HKLM:\software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'outlook.exe'
        }
    }
    
    if($spdesign_safeBind){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\spdesign.exe'
        {
            Key = 'HKLM:\software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'spdesign.exe'
        }
    }
    
    if($exprwd_safeBind){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\exprwd.exe'
        {
            Key = 'HKLM:\software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'exprwd.exe'
        }
    }
    
    if($msaccess_safeBind){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\msaccess.exe'
        {
            Key = 'HKLM:\software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'msaccess.exe'
        }
    }
    
    if($onenote_safeBind){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\onenote.exe'
        {
            Key = 'HKLM:\software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'onenote.exe'
        }
    }
    
    if($mse7_safeBind){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\mse7.exe'
        {
            Key = 'HKLM:\software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'mse7.exe'
        }
    }
    if($lync_savePassword){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\policies\microsoft\office\16.0\lync\savepassword'
        {
            Key = 'HKLM:\software\policies\microsoft\office\16.0\lync'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'savepassword'
        }
    }
    
    if($lync_enableSipHighSecurity){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\policies\microsoft\office\16.0\lync\enablesiphighsecuritymode'
        {
            Key = 'HKLM:\software\policies\microsoft\office\16.0\lync'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'enablesiphighsecuritymode'
        }
    }
    
    if($lync_disableHttpConnect){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\policies\microsoft\office\16.0\lync\disablehttpconnect'
        {
            Key = 'HKLM:\software\policies\microsoft\office\16.0\lync'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'disablehttpconnect'
        }
    }
    RefreshRegistryPolicy 'ActivateClientSideExtension'
    {
        IsSingleInstance = 'Yes'
    }
}

