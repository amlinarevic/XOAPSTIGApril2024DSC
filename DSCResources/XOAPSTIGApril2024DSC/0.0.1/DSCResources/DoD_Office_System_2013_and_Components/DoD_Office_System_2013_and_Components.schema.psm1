configuration DoD_Office_System_2013_and_Components
{

    param(
        [System.Boolean]$aptca_allowlist = $true,
        [System.Boolean]$groove_addon = $true,
        [System.Boolean]$excel_addon = $true,
        [System.Boolean]$mspub_addon = $true,
        [System.Boolean]$powerpnt_addon = $true,
        [System.Boolean]$pptview_addon = $true,
        [System.Boolean]$visio_addon = $true,
        [System.Boolean]$winproj_addon = $true,
        [System.Boolean]$winword_addon = $true,
        [System.Boolean]$outlook_addon = $true,
        [System.Boolean]$spdesign_addon = $true,
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
        [System.Boolean]$spdesign_http = $true,
        [System.Boolean]$exprwd_http = $false,
        [System.Boolean]$msaccess_http = $true,
        [System.Boolean]$onenote_http = $true,
        [System.Boolean]$mse7_http = $false,
        [System.Boolean]$groove_restrict = $true,
        [System.Boolean]$excel_restrict = $true,
        [System.Boolean]$mspub_restrict = $true,
        [System.Boolean]$powerpnt_restrict = $true,
        [System.Boolean]$pptview_restrict = $true,
        [System.Boolean]$outlook_restrict = $true,
        [System.Boolean]$spdesign_restrict = $true,
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
        [System.Boolean]$spdesign_filedownload = $true,
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
        [System.Boolean]$winproj_safe = $true,
        [System.Boolean]$winword_safe = $true,
        [System.Boolean]$outlook_safe = $true,
        [System.Boolean]$spdesign_safe = $true,
        [System.Boolean]$exprwd_safe = $false,
        [System.Boolean]$msaccess_safe = $true,
        [System.Boolean]$onenote_safe = $true,
        [System.Boolean]$mse7_safe = $false,
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
        [System.Boolean]$exprwd_unc = $false,
        [System.Boolean]$msaccess_unc = $true,
        [System.Boolean]$onenote_unc = $true,
        [System.Boolean]$mse7_unc = $false,
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
        [System.Boolean]$exprwd_navigate = $false,
        [System.Boolean]$msaccess_navigate = $true,
        [System.Boolean]$onenote_navigate = $true,
        [System.Boolean]$mse7_navigate = $false,
        [System.Boolean]$excel_weboc = $true,
        [System.Boolean]$mse7_weboc = $false,
        [System.Boolean]$groove_weboc = $true,
        [System.Boolean]$mspub_weboc = $true,
        [System.Boolean]$powerpnt_weboc = $true,
        [System.Boolean]$pptview_weboc = $true,
        [System.Boolean]$visio_weboc = $true,
        [System.Boolean]$winproj_weboc = $true,
        [System.Boolean]$winword_weboc = $true,
        [System.Boolean]$outlook_weboc = $true,
        [System.Boolean]$spdesign_weboc = $true,
        [System.Boolean]$exprwd_weboc = $false,
        [System.Boolean]$msaccess_weboc = $true,
        [System.Boolean]$onenote_weboc = $true,
        [System.Boolean]$groove_window = $true,
        [System.Boolean]$excel_window = $true,
        [System.Boolean]$mspub_window = $true,
        [System.Boolean]$powerpnt_window = $true,
        [System.Boolean]$pptview_window = $true,
        [System.Boolean]$visio_window = $true,
        [System.Boolean]$winproj_window = $true,
        [System.Boolean]$winword_window = $true,
        [System.Boolean]$outlook_window = $true,
        [System.Boolean]$spdesign_window = $true,
        [System.Boolean]$exprwd_window = $false,
        [System.Boolean]$msaccess_window = $true,
        [System.Boolean]$onenote_window = $true,
        [System.Boolean]$mse7_window = $false,
        [System.Boolean]$mspub_zone = $true,
        [System.Boolean]$powerpnt_zone = $true,
        [System.Boolean]$pptview_zone = $true,
        [System.Boolean]$visio_zone = $true,
        [System.Boolean]$winproj_zone = $true,
        [System.Boolean]$winword_zone = $true,
        [System.Boolean]$outlook_zone = $true,
        [System.Boolean]$spdesign_zone = $true,
        [System.Boolean]$exprwd_zone = $false,
        [System.Boolean]$msaccess_zone = $true,
        [System.Boolean]$onenote_zone = $true,
        [System.Boolean]$mse7_zone = $false,
        [System.Boolean]$enableautomaticupdates = $true,
        [System.Boolean]$hideenabledisableupdates = $true,
        [System.Boolean]$groove_safe_32bit = $true,
        [System.Boolean]$excel_safe_32bit = $true,
        [System.Boolean]$mspub_safe_32bit = $true,
        [System.Boolean]$powerpnt_safe_32bit = $true,
        [System.Boolean]$pptview_safe_32bit = $true,
        [System.Boolean]$visio_safe_32bit = $true,
        [System.Boolean]$winproj_safe_32bit = $true,
        [System.Boolean]$winword_safe_32bit = $true,
        [System.Boolean]$outlook_safe_32bit = $true,
        [System.Boolean]$spdesign_safe_32bit = $true,
        [System.Boolean]$exprwd_safe_32bit = $false,
        [System.Boolean]$msaccess_safe_32bit = $true,
        [System.Boolean]$onenote_safe_32bit = $true,
        [System.Boolean]$mse7_safe_32bit = $false,
        [System.Boolean]$savepassword = $false,
        [System.Boolean]$enablesiphighsecuritymode = $true,
        [System.Boolean]$disablehttpconnect = $true,
        [System.Boolean]$outlooksecuretempfolder_absent = $true,
        [System.Boolean]$fileextensionsremovelevel1_absent = $true,
        [System.Boolean]$fileextensionsremovelevel2_absent = $true,
        [System.Boolean]$loadcontrolsinforms_absent = $true,
        [System.Boolean]$uficontrols_absent = $true
    )

    Import-DSCResource -ModuleName 'GPRegistryPolicyDsc'
	Import-DSCResource -ModuleName 'AuditPolicyDSC'
	Import-DSCResource -ModuleName 'SecurityPolicyDSC'

    
    if($aptca_allowlist){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\policies\microsoft\office\15.0\infopath\security\aptca_allowlist'
        {
            Key = 'software\policies\microsoft\office\15.0\infopath\security'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'aptca_allowlist'
        }
    }
    
    if($groove_addon){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\groove.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'groove.exe'
        }
    }
    
    if($excel_addon){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\excel.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'excel.exe'
        }
    }
    
    if($mspub_addon){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\mspub.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'mspub.exe'
        }
    }
    
    if($powerpnt_addon){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\powerpnt.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'powerpnt.exe'
        }
    }
    
    if($pptview_addon){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\pptview.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'pptview.exe'
        }
    }
    
    if($visio_addon){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\visio.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'visio.exe'
        }
    }
    
    if($winproj_addon){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\winproj.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'winproj.exe'
        }
    }
    
    if($winword_addon){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\winword.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'winword.exe'
        }
    }
    
    if($outlook_addon){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\outlook.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'outlook.exe'
        }
    }
    if($spdesign_addon){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\spdesign.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'spdesign.exe'
        }
    }
    
    if($exprwd_addon -eq $false){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\exprwd.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'exprwd.exe'
        }
    }
    
    if($msaccess_addon){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\msaccess.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'msaccess.exe'
        }
    }
    
    if($onenote_addon){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\onenote.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'onenote.exe'
        }
    }
    
    if($mse7_addon -eq $false){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\mse7.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
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
    
    if($exprwd_http -eq $false){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\exprwd.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
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
    
    if($mse7_http -eq $false){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\mse7.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
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
    
    if($exprwd_restrict -eq $false){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\exprwd.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
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
    
    if($mse7_restrict -eq $false){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\mse7.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
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
    
    if($exprwd_filedownload -eq $false){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\exprwd.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
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
    
    if($mse7_filedownload -eq $false){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\mse7.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'mse7.exe'
        }
    }
    
    if($groove_safe){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\groove.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'groove.exe'
        }
    }
    
    if($excel_safe){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\excel.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'excel.exe'
        }
    }
    
    if($mspub_safe){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\mspub.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'mspub.exe'
        }
    }
    
    if($powerpnt_safe){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\powerpnt.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'powerpnt.exe'
        }
    }
    
    if($pptview_safe){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\pptview.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'pptview.exe'
        }
    }
    
    if($visio_safe){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\visio.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'visio.exe'
        }
    }

    if($winword_safe){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\winword.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'winword.exe'
        }
    }
    
    if($outlook_safe){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\outlook.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'outlook.exe'
        }
    }
    
    if($spdesign_safe){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\spdesign.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'spdesign.exe'
        }
    }
    
    if($exprwd_safe -eq $false){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\exprwd.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'exprwd.exe'
        }
    }
    
    if($msaccess_safe){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\msaccess.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'msaccess.exe'
        }
    }
    
    if($onenote_safe){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\onenote.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'onenote.exe'
        }
    }
    
    if($mse7_safe -eq $false){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\mse7.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
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
    
    if($exprwd_unc -eq $false){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\exprwd.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
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
    
    if($mse7_unc -eq $false){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\mse7.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
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
    
    if($exprwd_navigate -eq $false){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\exprwd.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
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
    
    if($mse7_navigate -eq $false){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\mse7.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'mse7.exe'
        }
    }
    
    
    if($excel_weboc){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement\excel.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'excel.exe'
        }
    }
    if($mse7_weboc -eq $false){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement\mse7.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'mse7.exe'
        }
    }
    
    if($groove_weboc){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement\groove.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'groove.exe'
        }
    }
    
    if($mspub_weboc){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement\mspub.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'mspub.exe'
        }
    }
    
    if($powerpnt_weboc){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement\powerpnt.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'powerpnt.exe'
        }
    }
    
    if($pptview_weboc){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement\pptview.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'pptview.exe'
        }
    }
    
    if($visio_weboc){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement\visio.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'visio.exe'
        }
    }
    
    if($winproj_weboc){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement\winproj.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'winproj.exe'
        }
    }
    
    if($winword_weboc){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement\winword.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'winword.exe'
        }
    }
    
    if($outlook_weboc){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement\outlook.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'outlook.exe'
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
    
    if($winproj_window){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\winproj.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'winproj.exe'
        }
    }
    
    if($winword_window){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\winword.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'winword.exe'
        }
    }
    
    if($outlook_window){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\outlook.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'outlook.exe'
        }
    }
    
    if($spdesign_window){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\spdesign.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'spdesign.exe'
        }
    }
    
    if($exprwd_window -eq $false){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\exprwd.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'exprwd.exe'
        }
    }
    
    if($msaccess_window){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\msaccess.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'msaccess.exe'
        }
    }
    
    if($onenote_window){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\onenote.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'onenote.exe'
        }
    }
    
    if($mse7_window -eq $false){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\mse7.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'mse7.exe'
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
    
    if($exprwd_zone -eq $false){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\exprwd.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
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
    
    if($mse7_zone -eq $false){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\mse7.exe'
        {
            Key = 'software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'mse7.exe'
        }
    }
    
    if($enableautomaticupdates){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\policies\microsoft\office\15.0\common\officeupdate\enableautomaticupdates'
        {
            Key = 'software\policies\microsoft\office\15.0\common\officeupdate'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'enableautomaticupdates'
        }
    }
    
    if($hideenabledisableupdates){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\policies\microsoft\office\15.0\common\officeupdate\hideenabledisableupdates'
        {
            Key = 'software\policies\microsoft\office\15.0\common\officeupdate'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'hideenabledisableupdates'
        }
    }
    
    if($groove_safe_32bit){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\wow6432node\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\groove.exe'
        {
            Key = 'software\wow6432node\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'groove.exe'
        }
    }

    if($excel_safe_32bit){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\wow6432node\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\excel.exe'
        {
            Key = 'software\wow6432node\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'excel.exe'
        }
    }
    
    if($mspub_safe_32bit){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\wow6432node\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\mspub.exe'
        {
            Key = 'software\wow6432node\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'mspub.exe'
        }
    }
    
    if($powerpnt_safe_32bit){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\wow6432node\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\powerpnt.exe'
        {
            Key = 'software\wow6432node\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'powerpnt.exe'
        }
    }
    
    if($pptview_safe_32bit){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\wow6432node\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\pptview.exe'
        {
            Key = 'software\wow6432node\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'pptview.exe'
        }
    }
    
    if($visio_safe_32bit){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\wow6432node\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\visio.exe'
        {
            Key = 'software\wow6432node\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'visio.exe'
        }
    }
    
    if($winproj_safe_32bit){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\wow6432node\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\winproj.exe'
        {
            Key = 'software\wow6432node\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'winproj.exe'
        }
    }
    
    if($winword_safe_32bit){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\wow6432node\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\winword.exe'
        {
            Key = 'software\wow6432node\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'winword.exe'
        }
    }
    
    if($outlook_safe_32bit){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\wow6432node\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\outlook.exe'
        {
            Key = 'software\wow6432node\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'outlook.exe'
        }
    }
    
    if($spdesign_safe_32bit){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\wow6432node\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\spdesign.exe'
        {
            Key = 'software\wow6432node\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'spdesign.exe'
        }
    }
    
    if($exprwd_safe_32bit -eq $false){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\wow6432node\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\exprwd.exe'
        {
            Key = 'software\wow6432node\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'exprwd.exe'
        }
    }
    
    if($msaccess_safe_32bit){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\wow6432node\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\msaccess.exe'
        {
            Key = 'software\wow6432node\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'msaccess.exe'
        }
    }
    
    if($onenote_safe_32bit){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\wow6432node\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\onenote.exe'
        {
            Key = 'software\wow6432node\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'onenote.exe'
        }
    }
    if($mse7_safe_32bit -eq $false){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\wow6432node\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\mse7.exe'
        {
            Key = 'software\wow6432node\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'mse7.exe'
        }
    }
    
    if($savepassword -eq $false){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\policies\microsoft\office\15.0\lync\savepassword'
        {
            Key = 'software\policies\microsoft\office\15.0\lync'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 0
            ValueName = 'savepassword'
        }
    }
    
    if($enablesiphighsecuritymode){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\policies\microsoft\office\15.0\lync\enablesiphighsecuritymode'
        {
            Key = 'software\policies\microsoft\office\15.0\lync'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'enablesiphighsecuritymode'
        }
    }
    
    if($disablehttpconnect){
        RegistryPolicyFile 'Registry(POL): HKLM:\software\policies\microsoft\office\15.0\lync\disablehttpconnect'
        {
            Key = 'software\policies\microsoft\office\15.0\lync'
            TargetType = 'ComputerConfiguration'
            ValueType = 'Dword'
            ValueData = 1
            ValueName = 'disablehttpconnect'
        }
    }
    
    if($outlooksecuretempfolder_absent){
        RegistryPolicyFile 'DEL_CU:\software\policies\microsoft\office\15.0\outlook\security\outlooksecuretempfolder'
        {
            Key = 'HKCU:\software\policies\microsoft\office\15.0\outlook\security'
            TargetType = 'ComputerConfiguration'
            ValueType = 'String'
            ValueData = ''
            ValueName = 'outlooksecuretempfolder'
            Ensure = 'Absent'
        }
    }
    
    if($fileextensionsremovelevel1_absent){
        RegistryPolicyFile 'DEL_CU:\software\policies\microsoft\office\15.0\outlook\security\fileextensionsremovelevel1'
        {
            Key = 'HKCU:\software\policies\microsoft\office\15.0\outlook\security'
            TargetType = 'ComputerConfiguration'
            ValueType = 'String'
            ValueData = ''
            ValueName = 'fileextensionsremovelevel1'
            Ensure = 'Absent'
        }
    }
    
    if($fileextensionsremovelevel2_absent){
        RegistryPolicyFile 'DEL_CU:\software\policies\microsoft\office\15.0\outlook\security\fileextensionsremovelevel2'
        {
            Key = 'HKCU:\software\policies\microsoft\office\15.0\outlook\security'
            TargetType = 'ComputerConfiguration'
            ValueType = 'String'
            ValueData = ''
            ValueName = 'fileextensionsremovelevel2'
            Ensure = 'Absent'
        }
    }
    
    if($loadcontrolsinforms_absent){
        RegistryPolicyFile 'DEL_CU:\keycupoliciesmsvbasecurity\loadcontrolsinforms'
        {
            Key = 'HKCU:\keycupoliciesmsvbasecurity'
            TargetType = 'ComputerConfiguration'
            ValueType = 'String'
            ValueData = ''
            ValueName = 'loadcontrolsinforms'
            Ensure = 'Absent'
        }
    }
    
    if($uficontrols_absent){
        RegistryPolicyFile 'DEL_CU:\software\policies\microsoft\office\common\security\uficontrols'
        {
            Key = 'HKCU:\software\policies\microsoft\office\common\security'
            TargetType = 'ComputerConfiguration'
            ValueType = 'String'
            ValueData = ''
            ValueName = 'uficontrols'
            Ensure = 'Absent'
        }
    }
    RefreshRegistryPolicy 'ActivateClientSideExtension'
    {
        IsSingleInstance = 'Yes'
    }
}

