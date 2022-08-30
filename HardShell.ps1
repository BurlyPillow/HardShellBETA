"▄         ▄  ▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄        ▄▄▄▄▄▄▄▄▄▄▄  ▄         ▄  ▄▄▄▄▄▄▄▄▄▄▄  ▄            ▄           
▐░▌       ▐░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░▌      ▐░░░░░░░░░░░▌▐░▌       ▐░▌▐░░░░░░░░░░░▌▐░▌          ▐░▌          
▐░▌       ▐░▌▐░█▀▀▀▀▀▀▀█░▌▐░█▀▀▀▀▀▀▀█░▌▐░█▀▀▀▀▀▀▀█░▌     ▐░█▀▀▀▀▀▀▀▀▀ ▐░▌       ▐░▌▐░█▀▀▀▀▀▀▀▀▀ ▐░▌          ▐░▌          
▐░▌       ▐░▌▐░▌       ▐░▌▐░▌       ▐░▌▐░▌       ▐░▌     ▐░▌          ▐░▌       ▐░▌▐░▌          ▐░▌          ▐░▌          
▐░█▄▄▄▄▄▄▄█░▌▐░█▄▄▄▄▄▄▄█░▌▐░█▄▄▄▄▄▄▄█░▌▐░▌       ▐░▌     ▐░█▄▄▄▄▄▄▄▄▄ ▐░█▄▄▄▄▄▄▄█░▌▐░█▄▄▄▄▄▄▄▄▄ ▐░▌          ▐░▌          
▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░▌       ▐░▌     ▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░▌          ▐░▌          
▐░█▀▀▀▀▀▀▀█░▌▐░█▀▀▀▀▀▀▀█░▌▐░█▀▀▀▀█░█▀▀ ▐░▌       ▐░▌      ▀▀▀▀▀▀▀▀▀█░▌▐░█▀▀▀▀▀▀▀█░▌▐░█▀▀▀▀▀▀▀▀▀ ▐░▌          ▐░▌          
▐░▌       ▐░▌▐░▌       ▐░▌▐░▌     ▐░▌  ▐░▌       ▐░▌               ▐░▌▐░▌       ▐░▌▐░▌          ▐░▌          ▐░▌          
▐░▌       ▐░▌▐░▌       ▐░▌▐░▌      ▐░▌ ▐░█▄▄▄▄▄▄▄█░▌      ▄▄▄▄▄▄▄▄▄█░▌▐░▌       ▐░▌▐░█▄▄▄▄▄▄▄▄▄ ▐░█▄▄▄▄▄▄▄▄▄ ▐░█▄▄▄▄▄▄▄▄▄ 
▐░▌       ▐░▌▐░▌       ▐░▌▐░▌       ▐░▌▐░░░░░░░░░░▌      ▐░░░░░░░░░░░▌▐░▌       ▐░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌
 ▀         ▀  ▀         ▀  ▀         ▀  ▀▀▀▀▀▀▀▀▀▀        ▀▀▀▀▀▀▀▀▀▀▀  ▀         ▀  ▀▀▀▀▀▀▀▀▀▀▀  ▀▀▀▀▀▀▀▀▀▀▀  ▀▀▀▀▀▀▀▀▀▀▀ "


 #<< = Anything you can edit within the value

Set-ExecutionPolicy Unrestricted

ipconfig /flushdns


 "For most optional prompts, 1 = yes, and 2 = no"

"."


Disable-LocalUser -Name "Guest" #<<


"Guest Disabled"
$Groupname = Read-host "Change the Admin and guest group names?"

if($Groupname -eq 1){

Rename-LocalGroup -Name "Guests" -NewName "ScriptKiddies" #<<

Rename-LocalGroup -Name "Adminstrators" -NewName "CyberTeam" #<<

"Opening netplwiz to verify the changes"

netplwiz
}

if($Groupname -eq 2){

"Skipping name change"


}
reg add “HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server” /v fDenyTSConnections /t REG_DWORD /d 1 /f


"."

"RPD Disabled"


$TLS = Read-Host "Install TLS?"

if($TLS -eq 1){

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 
Install-Module PowerShellGet -RequiredVersion 2.2.4 -SkipPublisherCheck

"TLS Installed"
}



if($TLS -eq 2){

"TLS Skipped..."
}



Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True 

"Firewall Enabled"
{
pause


"Enabling logging for the firewall"

reg add HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\EnableFirewall /v EnableFirewall /t REG_DWORD /d 1 /f
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\DefaultInboundAction /v DefaultInboundAction /t REG_DWORD /d 1 /f
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\DefaultOutboundAction /v DefaultOutboundAction /t REG_DWORD /d 0 /f
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\DisableNotifications /v DisableNotifications /t REG_DWORD /d 0 /f
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging\LogFilePath /v DisableNotifications /t REG_SZ /d %windir%\system32\logfiles\firewall\domainfirewall.log /f
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging\LogFileSize /v LogFileSize /t REG_DWORD /d 16384 /f 
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging\LogDroppedPackets /v LogDroppedPackets /t REG_DWORD /d 1 /f 
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging\LogSuccessfulConnections /v LogSuccessfulConnections /t REG_DWORD /d 1 /f 
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile /v EnableFirewall /t REG_DWORD /d 1 /f 
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile /v DefaultInboundAction /t REG_DWORD /d 1 /f
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile /v DefaultOutboundAction /t REG_DWORD /d 0 /f 
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile /v DisableNotifcations /t REG_DWORD /d 0 /f 
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging /v LogFilePath /t  REG_SZ /d %windir%\system32\logfiles\firewall\privatefirewall.log /f 
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging /v LogFileSize /t REG_DWORD /d 16384 /f 
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging /v LogDroppedPackets /t REG_DWORD /d 1 /f 
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging /v LogSuccessfulConnections /t REG_DWORD /d 1 /f 
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile /v EnableFirewall /t REG_DWORD /d 1 /f 
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile /v DefaultInboundAction /t REG_DWORD /d 1 /f
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile /v DefaultOutboundAction /t REG_DWORD /d 0 /f 
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile /v DisableNotifications /t REG_DWORD /d 0 /f 
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile /v AllowLocalPolicyMerge /t REG_DWORD /d 0 /f
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile /v AllowLocalIPsecPolicyMerge /t REG_DWORD /d 0 /f 
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging /v LogFilePath /t REG_SZ /d %windir%\system32\logfiles\firewall\publicfirewall.log /f 
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging /v LogFIleSize /t REG_DWORD /d 16384 /f 
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging /v LogDroppedPackets /t REG_DWORD /d 1 /f 
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging /v LogSuccessfulConnections /t REG_DWORD /d 1 /f 

 "Firewall logging enabled"
}


$FolderName = "C:\temp\HardShell" #<< Location where notes output
if (Test-Path $FolderName) {
Write-Host "HardFolder Already exists"
}
else
{
 "Creating Hardshell Directory"
New-Item -Path 'C:\temp\HardShell' -ItemType "Directory"
}
pause

$ClearContent = Read-host "Clear contents of Hardshell logs? 1 = auto / 2 = manual"
if ($ClearContent -eq 1){
Clear-Content C:\temp\HardShell\*.txt
"Automatically wiped files"
}

if($ClearContent -eq 2){
"Opening up confirmation panel...."
"."
Clear-Content -Confirm C:\temp\HardShell\*.txt
}

$notes = Read-Host "Take PC notes?"


if ($notes -eq 1){

[System.Environment]::OSVersion.Version | Out-File -FilePath 'C:\temp\Hard Shell\OS.txt'

 "OS Version Noted"



Get-Process | Out-File -FilePath 'C:\temp\HardShell\Process.txt'

 "Processes Noted"



ipconfig /all | Out-File -FilePath 'C:\temp\HardShell\IPs.txt' 

 "IPs Noted"



getmac | Out-File -FilePath 'C:\temp\HardShell\MAC.txt'

 "MAC Noted"


get-computerinfo | Out-File -FilePath 'C:\temp\HardShell\PCINFO.txt'

 "PC Info Noted"




Get-LocalUser | Select * | Out-File -FilePath 'C:\temp\HardShell\Users.txt'

 "Local User Noted"



chkdsk | Out-File 'C:\temp\HardShell\DSK.txt'

 "CHKDSK Noted"


Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct | Out-File -FilePath 'C:\temp\HardShell\AntiVirus.txt'

 Anti-Virus Noted



netstat | Out-File -FilePath 'C:\temp\HardShell\NETSTAT.txt'

 "NETSTAT Noted"

}
 
 if ($notes -eq 2){

 "Skipping notes..."}





$quicksc = Read-Host "Initiate a quickscan?"
if ($quicksc -eq 1){

Start-MpScan -ScanType QuickScan

 "Scan Complete"
}

if ($quicksc -eq 2){
 "Skipping quickscan..."
}


$dsc = Read-Host "Install DSC?"

if ($dsc -eq 1){

install-module AuditPolicyDSC

install-module ComputerManagementDsc

install-module SecurityPolicyDsc
}

if ($dsc -eq 2){

 "Cancelling DSC..."
}



$psswdP = Read-Host "Initiate Password Policies?"

if ($psswdP -eq 1) {



AccountPolicy AccountPolicies
 "Enforcing Password Polices....."

Name = 'PasswordPolicies'
# 1.1.1 (L1) Ensure 'Enforce password history' is set to '24 or more password(s)'
Enforce_password_history = 24 #<< INSERT VALUE
# 1.1.2 (L1) Ensure 'Maximum password age' is set to '60 or fewer days, but not 0'
Maximum_Password_Age = 60 #<< INSERT VALUE
# 1.1.3 (L1) Ensure 'Minimum password age' is set to '1 or more day(s)'
Minimum_Password_Age = 1 #<< INSERT VALUE
# 1.1.4 (L1) Ensure 'Minimum password length' is set to '14 or more character(s)'
Minimum_Password_Length = 14 #<< INSERT VALUE
# 1.1.5 (L1) Ensure 'Password must meet complexity requirements' is set to 'Enabled'
Password_must_meet_complexity_requirements = 'Enabled' #<< Enabled / Disabled
# 1.1.6 (L1) Ensure 'Store passwords using reversible encryption' is set to 'Disabled'
Store_passwords_using_reversible_encryption = 'Disabled' #<< Enabled/ Disabled
# 1.2.1 (L1) Ensure 'Account lockout duration' is set to '15 or more minute(s)'
Account_lockout_duration = 15 
# 1.2.2 (L1) Ensure 'Account lockout threshold' is set to '10 or fewer invalid logon attempt(s), but not 0'
Account_lockout_threshold = 10
# 1.2.3 (L1) Ensure 'Reset account lockout counter after' is set to '15 or more minute(s)'
Reset_account_lockout_counter_after = 15
        
 Echo "Password Polices Enforced"}

 
 echo "Optimizing Local Security Policies...."
configuration SecurityOption_Config
{
     
        
        SecurityOption AccountSecurityOptions {

            Name = 'AccountSecurityOptions'
            # 2.3.1.1 (L1) Ensure 'Accounts: Administrator account status' is set to 'Disabled'
            Accounts_Administrator_account_status  = 'Disabled' #<<
            # 2.3.1.2 (L1) Ensure 'Accounts: Block Microsoft accounts' is set to 'Users can't add or log on with Microsoft accounts'
            Accounts_Block_Microsoft_accounts = 'Users cant add or log on with Microsoft accounts' 
            # 2.3.1.3 (L1) Ensure 'Accounts: Guest account status' is set to 'Disabled'
            Accounts_Guest_account_status = 'Disabled' #<<
            # 2.3.1.4 (L1) Ensure 'Accounts: Limit local account use of blank passwords to console logon only' is set to 'Enabled'
            Accounts_Limit_local_account_use_of_blank_passwords_to_console_logon_only = 'Enabled'
            # 2.3.1.5 (L1) Configure 'Accounts: Rename administrator account'
            Accounts_Rename_administrator_account = 'User_Adm' # WARNING! Any value different from Administrator
            # 2.3.1.6 (L1) Configure 'Accounts: Rename guest account'
            Accounts_Rename_guest_account = 'User_Guest' # WARNING! Any value different from Guest
            # 2.3.2.1 (L1) Ensure 'Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings' is set to 'Enabled'
            Audit_Force_audit_policy_subcategory_settings_Windows_Vista_or_later_to_override_audit_policy_category_settings = 'Enabled' #<< Enabled / Disabled
            # 2.3.2.2 (L1) Ensure 'Audit: Shut down system immediately if unable to log security audits' is set to 'Disabled'
            Audit_Shut_down_system_immediately_if_unable_to_log_security_audits = 'Disabled' #<< Enabled / Disabled
            # 2.3.4.1 (L1) Ensure 'Devices: Allowed to format and eject removable media' is set to 'Administrators'
            Devices_Allowed_to_format_and_eject_removable_media = 'Administrators' 
            # 2.3.4.2 (L1) Ensure 'Devices: Prevent users from installing printer drivers' is set to 'Enabled'
            Devices_Prevent_users_from_installing_printer_drivers = 'Enabled' #<< Enabled / Disabled
            # 2.3.6.1 (L1) Ensure 'Domain member: Digitally encrypt or sign secure channel data (always)' is set to 'Enabled'
            Domain_member_Digitally_encrypt_or_sign_secure_channel_data_always = 'Enabled' #<< Enabled / Disabled
            # 2.3.6.2 (L1) Ensure 'Domain member: Digitally encrypt secure channel data (when possible)' is set to 'Enabled'
            Domain_member_Digitally_encrypt_secure_channel_data_when_possible = 'Enabled'#<< Enabled / Disabled
            # 2.3.6.3 (L1) Ensure 'Domain member: Digitally sign secure channel data (when possible)' is set to 'Enabled' 
            Domain_member_Digitally_sign_secure_channel_data_when_possible = 'Enabled' #<< Enabled / Disabled
            # 2.3.6.4 (L1) Ensure 'Domain member: Disable machine account password changes' is set to 'Disabled'
            Domain_member_Disable_machine_account_password_changes = 'Disabled' #<< Enabled / Disabled
            # 2.3.6.5 (L1) Ensure 'Domain member: Maximum machine account password age' is set to '30 or fewer days, but not 0'
            Domain_member_Maximum_machine_account_password_age = '30'
            # 2.3.6.6 (L1) Ensure 'Domain member: Require strong (Windows 2000 or later) session key' is set to 'Enabled'
            Domain_member_Require_strong_Windows_2000_or_later_session_key = 'Enabled' #<< Enabled / Disabled
            # 2.3.7.1 (L1) Ensure 'Interactive logon: Do not require CTRL+ALT+DEL' is set to 'Disabled'
            Interactive_logon_Do_not_require_CTRL_ALT_DEL = 'Disabled' #<< Enabled / Disabled
            # 2.3.7.2 (L1) Ensure 'Interactive logon: Do not display last user name' is set to 'Enabled'
            Interactive_logon_Do_not_display_last_user_name = 'Enabled' #<< Enabled / Disabled
            # 2.3.7.3 (BL) Ensure 'Interactive logon: Machine account lockout threshold' is set to '10 or fewer invalid logon attempts, but not 0'
            Interactive_logon_Machine_account_lockout_threshold = '10'  #<< Insert value less than 10          
            # 2.3.7.4 (L1) Ensure 'Interactive logon: Machine inactivity limit' is set to '900 or fewer second(s), but not 0'
            Interactive_logon_Machine_inactivity_limit = '900' 
            # 2.3.7.5 (L1) Configure 'Interactive logon: Message text for users attempting to log on' 
            Interactive_logon_Message_text_for_users_attempting_to_log_on = 'This computer system is the property of Acme Corporation and is for authorised use by employees and designated contractors only. By continuing to use this system you indicate your awareness of and consent to these terms and conditions of use.It is the users responsibility to LOG OFF IMMEDIATELY if you do not agree to the conditions stated in this notice.' #<<
            # 2.3.7.6 (L1) Configure 'Interactive logon: Message title for users attempting to log on'
            Interactive_logon_Message_title_for_users_attempting_to_log_on = 'Logon Warning'
            # 2.3.7.7 (L2) Ensure 'Interactive logon: Number of previous logons to cache (in case domain controller is not available)' is set to '4 or fewer logon(s)'
            Interactive_logon_Number_of_previous_logons_to_cache_in_case_domain_controller_is_not_available = '4'
            # 2.3.7.8 (L1) Ensure 'Interactive logon: Prompt user to change password before expiration' is set to 'between 5 and 14 days'
            Interactive_logon_Prompt_user_to_change_password_before_expiration = '14' #<< set value 5 - 14
            # 2.3.7.9 (L1) Ensure 'Interactive logon: Smart card removal behavior' is set to 'Lock Workstation' or higher
            Interactive_logon_Smart_card_removal_behavior = 'Lock Workstation'
            # 2.3.8.1 (L1) Ensure 'Microsoft network client: Digitally sign communications (always)' is set to 'Enabled' 
            Microsoft_network_client_Digitally_sign_communications_always = 'Enabled' #<< Enabled / Disabled
            # 2.3.8.2 (L1) Ensure 'Microsoft network client: Digitally sign communications (if server agrees)' is set to 'Enabled' 
            Microsoft_network_client_Digitally_sign_communications_if_server_agrees = 'Enabled' #<< Enabled / Disabled
            # 2.3.8.3 (L1) Ensure 'Microsoft network client: Send unencrypted password to third-party SMB servers' is set to 'Disabled' 
            Microsoft_network_client_Send_unencrypted_password_to_third_party_SMB_servers = 'Disabled' #<< Enabled / Disabled
            # 2.3.9.1 (L1) Ensure 'Microsoft network server: Amount of idle time required before suspending session' is set to '15 or fewer minute(s), but not 0'
            Microsoft_network_server_Amount_of_idle_time_required_before_suspending_session = '15' 
            # 2.3.9.2 (L1) Ensure 'Microsoft network server: Digitally sign communications (always)' is set to 'Enabled' 
            Microsoft_network_server_Digitally_sign_communications_always = 'Enabled' #<< Enabled / Disabled
            # 2.3.9.3 (L1) Ensure 'Microsoft network server: Digitally sign communications (if client agrees)' is set to 'Enabled' 
            Microsoft_network_server_Digitally_sign_communications_if_client_agrees = 'Enabled' #<< Enabled / Disabled
            # 2.3.9.4 (L1) Ensure 'Microsoft network server: Disconnect clients when logon hours expire' is set to 'Enabled'
            Microsoft_network_server_Disconnect_clients_when_logon_hours_expire = 'Enabled' #<< Enabled / Disabled
            # 2.3.9.5 (L1) Ensure 'Microsoft network server: Server SPN target name validation level' is set to 'Accept if provided by client' or higher
            Microsoft_network_server_Server_SPN_target_name_validation_level = 'Accept if provided by client'
            #Microsoft_network_server_Server_SPN_target_name_validation_level = 'Required from client'
            # 2.3.10.1 (L1) Ensure 'Network access: Allow anonymous SID/Name translation' is set to 'Disabled'
            Network_access_Allow_anonymous_SID_Name_translation = 'Disabled' #<< Enabled / Disabled
            # 2.3.10.2 (L1) Ensure 'Network access: Do not allow anonymous enumeration of SAM accounts' is set to 'Enabled'
            Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts = 'Enabled' #<< Enabled / Disabled
            # 2.3.10.3 (L1) Ensure 'Network access: Do not allow anonymous enumeration of SAM accounts and shares' is set to 'Enabled'
            Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts_and_shares = 'Enabled' #<< Enabled / Disabled
            # 2.3.10.4 (L2) Ensure 'Network access: Do not allow storage of passwords and credentials for network authentication' is set to 'Enabled'
            Network_access_Do_not_allow_storage_of_passwords_and_credentials_for_network_authentication = 'Enabled' #<< Enabled / Disabled
            # 2.3.10.5 (L1) Ensure 'Network access: Let Everyone permissions apply to anonymous users' is set to 'Disabled'
            Network_access_Let_Everyone_permissions_apply_to_anonymous_users = 'Disabled' #<< Enabled / Disabled 
            # 2.3.10.6 (L1) Configure 'Network access: Named Pipes that can be accessed anonymously'
            Network_access_Named_Pipes_that_can_be_accessed_anonymously = ''
            # 2.3.10.7 (L1) Configure 'Network access: Remotely accessible registry paths' 
            # Commented out because of bug in SecurityPolicyDSC Module https://github.com/dsccommunity/SecurityPolicyDSC/issues/83
            #Network_access_Remotely_accessible_registry_paths = 'System\CurrentControlSet\Control\ProductOptions, System\CurrentControlSet\Control\Server Applications, SOFTWARE\Microsoft\Windows NT\CurrentVersion'
            # 2.3.10.8 (L1) Configure 'Network access: Remotely accessible registry paths and sub-paths' 
            # Commented out because of bug in SecurityPolicyDSC Module https://github.com/dsccommunity/SecurityPolicyDSC/issues/83
            #Network_access_Remotely_accessible_registry_paths_and_subpaths = 'System\CurrentControlSet\Control\Print\Printers, System\CurrentControlSet\Services\Eventlog, Software\Microsoft\OLAP Server, Software\Microsoft\Windows NT\CurrentVersion\Print, Software\Microsoft\Windows NT\CurrentVersion\Windows, System\CurrentControlSet\Control\ContentIndex, System\CurrentControlSet\Control\Terminal Server, System\CurrentControlSet\Control\Terminal Server\UserConfig, System\CurrentControlSet\Control\Terminal Server\DefaultUserConfiguration, Software\Microsoft\Windows NT\CurrentVersion\Perflib, System\CurrentControlSet\Services\SysmonLog'
            # 2.3.10.9 (L1) Ensure 'Network access: Restrict anonymous access to Named Pipes and Shares' is set to 'Enabled' 
            Network_access_Restrict_anonymous_access_to_Named_Pipes_and_Shares = 'Enabled' #<< Enabled / Disabled
            # 2.3.10.10 (L1) Ensure 'Network access: Restrict clients allowed to make remote calls to SAM' is set to 'Administrators: Remote Access: Allow'
            Network_access_Restrict_clients_allowed_to_make_remote_calls_to_SAM = @(
               MSFT_RestrictedRemoteSamSecurityDescriptor
               {
                  Permission = 'Allow' #<< Allow/Disable
                  Identity   = 'Administrators'#<< Insert any group name
               }
            )
            # 2.3.10.11 (L1) Ensure 'Network access: Shares that can be accessed anonymously' is set to 'None' 
            Network_access_Shares_that_can_be_accessed_anonymously = ''
            # 2.3.10.12 (L1) Ensure 'Network access: Sharing and security model for local accounts' is set to 'Classic - local users authenticate as themselves' 
            Network_access_Sharing_and_security_model_for_local_accounts = 'Classic - local users authenticate as themselves'
            # 2.3.11.1 (L1) Ensure 'Network security: Allow Local System to use computer identity for NTLM' is set to 'Enabled' 
            Network_security_Allow_Local_System_to_use_computer_identity_for_NTLM = 'Enabled' #<< Enabled / Disabled 
            # 2.3.11.2 (L1) Ensure 'Network security: Allow LocalSystem NULL session fallback' is set to 'Disabled' 
            Network_security_Allow_LocalSystem_NULL_session_fallback = 'Disabled' #<< Enabled / Disabled 
            # 2.3.11.3 (L1) Ensure 'Network Security: Allow PKU2U authentication requests to this computer to use online identities' is set to 'Disabled' 
            Network_security_Allow_PKU2U_authentication_requests_to_this_computer_to_use_online_identities = 'Disabled' #<< Enabled / Disabled 
            # 2.3.11.4 (L1) Ensure 'Network security: Configure encryption types allowed for Kerberos' is set to 'AES128_HMAC_SHA1, AES256_HMAC_SHA1, Future encryption types' 
            Network_security_Configure_encryption_types_allowed_for_Kerberos = 'AES128_HMAC_SHA1','AES256_HMAC_SHA1','FUTURE' 
            # 2.3.11.5 (L1) Ensure 'Network security: Do not store LAN Manager hash value on next password change' is set to 'Enabled' 
            Network_security_Do_not_store_LAN_Manager_hash_value_on_next_password_change = 'Enabled' #<< Enabled / Disabled 
            # 2.3.11.6 (L1) Ensure 'Network security: Force logoff when logon hours expire' is set to 'Enabled' 
            Network_security_Force_logoff_when_logon_hours_expire = 'Enabled' #<< Enabled / Disabled 
            # 2.3.11.7 (L1) Ensure 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM & NTLM'
            Network_security_LAN_Manager_authentication_level = 'Send NTLMv2 responses only. Refuse LM & NTLM' 
            # 2.3.11.8 (L1) Ensure 'Network security: LDAP client signing requirements' is set to 'Negotiate signing' or higher
            Network_security_LDAP_client_signing_requirements = 'Negotiate signing' 
            # 2.3.11.9 (L1) Ensure 'Network security: Minimum session security for NTLM SSP based (including secure RPC) clients' is set to 'Require NTLMv2 session security, Require 128-bit encryption' 
            Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_clients = 'Both options checked'
            # 2.3.11.10 (L1) Ensure 'Network security: Minimum session security for NTLM SSP based (including secure RPC) servers' is set to 'Require NTLMv2 session security, Require 128-bit encryption' 
            Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_servers = 'Both options checked' 
            # 2.3.13.1 (L1) Ensure 'Shutdown: Allow system to be shut down without having to log on' is set to 'Disabled'
            Shutdown_Allow_system_to_be_shut_down_without_having_to_log_on = 'Disabled' #<< Enabled / Disabled 
            # 2.3.14.1 (L2) Ensure 'System cryptography: Force strong key protection for user keys stored on the computer' is set to 'User is prompted when the key is first used' or higher
            System_cryptography_Force_strong_key_protection_for_user_keys_stored_on_the_computer = 'User is prompted when the key is first used'
            # 2.3.15.1 (L1) Ensure 'System objects: Require case insensitivity for non-Windows subsystems' is set to 'Enabled'
            System_objects_Require_case_insensitivity_for_non_Windows_subsystems = 'Enabled' #<< Enabled / Disabled 
            # 2.3.15.2 (L1) Ensure 'System objects: Strengthen default permissions of internal system objects (e.g. Symbolic Links)' is set to 'Enabled'
            System_objects_Strengthen_default_permissions_of_internal_system_objects_eg_Symbolic_Links = 'Enabled' #<< Enabled / Disabled 
            # 2.3.17.1 (L1) Ensure 'User Account Control: Admin Approval Mode for the Built-in Administrator account' is set to 'Enabled' 
            User_Account_Control_Admin_Approval_Mode_for_the_Built_in_Administrator_account = 'Enabled' #<< Enabled / Disabled 
            # 2.3.17.2 (L1) Ensure 'User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode' is set to 'Prompt for consent on the secure desktop' 
            User_Account_Control_Behavior_of_the_elevation_prompt_for_administrators_in_Admin_Approval_Mode = 'Prompt for consent on the secure desktop'
            # 2.3.17.3 (L1) Ensure 'User Account Control: Behavior of the elevation prompt for standard users' is set to 'Automatically deny elevation requests' 
            User_Account_Control_Behavior_of_the_elevation_prompt_for_standard_users = 'Automatically deny elevation request'
            # 2.3.17.4 (L1) Ensure 'User Account Control: Detect application installations and prompt for elevation' is set to 'Enabled' 
            User_Account_Control_Detect_application_installations_and_prompt_for_elevation = 'Enabled' #<< Enabled / Disabled 
            # 2.3.17.5 (L1) Ensure 'User Account Control: Only elevate UIAccess applications that are installed in secure locations' is set to 'Enabled' 
            User_Account_Control_Only_elevate_UIAccess_applications_that_are_installed_in_secure_locations = 'Enabled'
            # 2.3.17.6 (L1) Ensure 'User Account Control: Run all administrators in Admin Approval Mode' is set to 'Enabled'
            User_Account_Control_Run_all_administrators_in_Admin_Approval_Mode = 'Enabled' #<< Enabled / Disabled 
            # 2.3.17.7 (L1) Ensure 'User Account Control: Switch to the secure desktop when prompting for elevation' is set to 'Enabled' 
            User_Account_Control_Switch_to_the_secure_desktop_when_prompting_for_elevation = 'Enabled' #<< Enabled / Disabled 
            # 2.3.17.8 (L1) Ensure 'User Account Control: Virtualize file and registry write failures to per-user locations' is set to 'Enabled'
            User_Account_Control_Virtualize_file_and_registry_write_failures_to_per_user_locations = 'Enabled' #<< Enabled / Disabled 
        }
    }

 "Local Security Policy updated"

 "Managing User Rights"

Configuration UserRightsAssignment_Basic_Config
{
   

    Node localhost
    {
       UserRightsAssignment AccessCredentialManagerasatrustedcaller {
            Policy       = 'Access_Credential_Manager_as_a_trusted_caller'
            Identity     = ''
        }

        # 2.2.2 (L1) Ensure 'Access this computer from the network' is set to 'Administrators, Authenticated Users, ENTERPRISE DOMAIN CONTROLLERS' (DC only)
        UserRightsAssignment Accessthiscomputerfromthenetwork {
            Policy       = 'Access_this_computer_from_the_network'
            Identity     = 'Administrators, Authenticated Users, ENTERPRISE DOMAIN CONTROLLERS'
        }

        # 2.2.3 (L1) Ensure 'Act as part of the operating system' is set to 'No One'
        UserRightsAssignment Actaspartoftheoperatingsystem {
            Policy       = 'Act_as_part_of_the_operating_system'
            Identity     = ''
        }

        # 2.2.4 (L1) Ensure 'Adjust memory quotas for a process' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE'
        UserRightsAssignment Adjustmemoryquotasforaprocess {
            Policy       = 'Adjust_memory_quotas_for_a_process'
            Identity     = 'Administrators, LOCAL SERVICE, NETWORK SERVICE'
        }

        # 2.2.5 (L1) Ensure 'Allow log on locally' is set to 'Administrators, Users'
        UserRightsAssignment Allowlogonlocally {
            Policy       = 'Allow_log_on_locally'
            Identity     = 'Administrators, Users'
        }

        # 2.2.6 (L1) Ensure 'Allow log on through Remote Desktop Services' is set to 'Administrators, Remote Desktop Users'
        UserRightsAssignment AllowlogonthroughRemoteDesktopServices {
            Policy       = 'Allow_log_on_through_Remote_Desktop_Services'
            Identity     = 'Administrators, Remote Desktop Users'
        }

        # 2.2.7 (L1) Ensure 'Back up files and directories' is set to 'Administrators'
        UserRightsAssignment Backupfilesanddirectories {
            Policy       = 'Back_up_files_and_directories'
            Identity     = 'Administrators'
        }

        # 2.2.8 (L1) Ensure 'Change the system time' is set to 'Administrators, LOCAL SERVICE'
        UserRightsAssignment Changethesystemtime {
            Policy       = 'Change_the_system_time'
            Identity     = 'Administrators, LOCAL SERVICE'
        }

        # 2.2.9 (L1) Ensure 'Change the time zone' is set to 'Administrators, LOCAL SERVICE, Users'
        UserRightsAssignment Changethetimezone {
            Policy       = 'Change_the_time_zone'
            Identity     = 'Administrators, LOCAL SERVICE, Users'
        }

        # 2.2.10 (L1) Ensure 'Create a pagefile' is set to 'Administrators'
        UserRightsAssignment Createapagefile {
            Policy       = 'Create_a_pagefile'
            Identity     = 'Administrators'
        }

        # 2.2.11 (L1) Ensure 'Create a token object' is set to 'No One'
        UserRightsAssignment Createatokenobject {
            Policy       = 'Create_a_token_object'
            Identity     = ''
        }

        # 2.2.12 (L1) Ensure 'Create global objects' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE'
        UserRightsAssignment Createglobalobjects {
            Policy       = 'Create_global_objects'
            Identity     = 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE'
        }

        # 2.2.13 (L1) Ensure 'Create permanent shared objects' is set to 'No One'
        UserRightsAssignment Createpermanentsharedobjects {
            Policy       = 'Create_permanent_shared_objects'
            Identity     = ''
        }

        # 2.2.14 (L1) Configure 'Create symbolic links'
        UserRightsAssignment Createsymboliclinks {
            Policy       = 'Create_symbolic_links'
            Identity     = 'Administrators, NT VIRTUAL MACHINE\Virtual Machines'
        }

        # 2.2.15 (L1) Ensure 'Debug programs' is set to 'Administrators'
        UserRightsAssignment Debugprograms {
            Policy       = 'Debug_programs'
            Identity     = 'Administrators'
        }        

        # 2.2.16 (L1) Ensure 'Deny access to this computer from the network' is set to 'Guests, Local account'
        UserRightsAssignment Denyaccesstothiscomputerfromthenetwork {
            Policy       = 'Deny_access_to_this_computer_from_the_network'
            Identity     = 'Guests, Local account'
        }

        # 2.2.17 (L1) Ensure 'Deny log on as a batch job' to include 'Guests'
        UserRightsAssignment Denylogonasabatchjob {
            Policy       = 'Deny_log_on_as_a_batch_job'
            Identity     = 'Guests'
        }

        # 2.2.18 (L1) Ensure 'Deny log on as a service' to include 'Guests'
        UserRightsAssignment Denylogonasaservice {
            Policy       = 'Deny_log_on_as_a_service'
            Identity     = 'Guests'
        }

        # 2.2.19 (L1) Ensure 'Deny log on locally' to include 'Guests'
        UserRightsAssignment Denylogonlocally {
            Policy       = 'Deny_log_on_locally'
            Identity     = 'Guests'
        }

        # 2.2.20 (L1) Ensure 'Deny log on through Remote Desktop Services' is set to 'Guests, Local account'
        UserRightsAssignment DenylogonthroughRemoteDesktopServices {
            Policy       = 'Deny_log_on_through_Remote_Desktop_Services'
            Identity     = 'Guests, Local account'
        }

        # 2.2.21 (L1) Ensure 'Enable computer and user accounts to be trusted for delegation' is set to 'No One'
        UserRightsAssignment Enablecomputeranduseraccountstobetrustedfordelegation {
            Policy       = 'Enable_computer_and_user_accounts_to_be_trusted_for_delegation'
            Identity     = ''
        }

        # 2.2.22 (L1) Ensure 'Force shutdown from a remote system' is set to 'Administrators'
        UserRightsAssignment Forceshutdownfromaremotesystem {
            Policy       = 'Force_shutdown_from_a_remote_system'
            Identity     = 'Administrators'
        }

        # 2.2.23 (L1) Ensure 'Generate security audits' is set to 'LOCAL SERVICE, NETWORK SERVICE'
        UserRightsAssignment Generatesecurityaudits {
            Policy       = 'Generate_security_audits'
            Identity     = 'LOCAL SERVICE, NETWORK SERVICE'
        }

        # 2.2.24 (L1) Ensure 'Impersonate a client after authentication' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE'
        UserRightsAssignment Impersonateaclientafterauthentication {
            Policy       = 'Impersonate_a_client_after_authentication'
            Identity     = 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE'
        }

        # 2.2.25 (L1) Ensure 'Increase scheduling priority' is set to 'Administrators, Windows Manager\Windows Manager Group'
        UserRightsAssignment Increaseschedulingpriority {
            Policy       = 'Increase_scheduling_priority'
            Identity     = 'Administrators, Windows Manager\Windows Manager Group'
        }

        # 2.2.26 (L1) Ensure 'Load and unload device drivers' is set to 'Administrators'
        UserRightsAssignment Loadandunloaddevicedrivers {
            Policy       = 'Load_and_unload_device_drivers'
            Identity     = 'Administrators'
        }

        # 2.2.27 (L1) Ensure 'Lock pages in memory' is set to 'No One'
        UserRightsAssignment Lockpagesinmemory {
            Policy       = 'Lock_pages_in_memory'
            Identity     = ''
        }

        # 2.2.28 (L2) Ensure 'Log on as a batch job' is set to 'Administrators'
        UserRightsAssignment Logonasabatchjob {
            Policy       = 'Log_on_as_a_batch_job'
            Identity     = 'Administrators'
        }

        # 2.2.29 (L2) Configure 'Log on as a service'
        
        
        UserRightsAssignment Logonasaservice {
            Policy       = 'Log_on_as_a_service'
            Identity     = 'NT VIRTUAL MACHINE\Virtual Machines'
        }

        # 2.2.30 (L1) Ensure 'Manage auditing and security log' is set to 'Administrators'
        UserRightsAssignment Manageauditingandsecuritylog {
            Policy       = 'Manage_auditing_and_security_log'
            Identity     = 'Administrators'
        }

        # 2.2.31 (L1) Ensure 'Modify an object label' is set to 'No One'
        UserRightsAssignment Modifyanobjectlabel {
            Policy       = 'Modify_an_object_label'
            Identity     = ''
        }

        # 2.2.32 (L1) Ensure 'Modify firmware environment values' is set to 'Administrators'
        UserRightsAssignment Modifyfirmwareenvironmentvalues {
            Policy       = 'Modify_firmware_environment_values'
            Identity     = 'Administrators'
        }

        # 2.2.33 (L1) Ensure 'Perform volume maintenance tasks' is set to 'Administrators'
        UserRightsAssignment Performvolumemaintenancetasks {
            Policy       = 'Perform_volume_maintenance_tasks'
            Identity     = 'Administrators'
        }

        # 2.2.34 (L1) Ensure 'Profile single process' is set to 'Administrators'
        UserRightsAssignment Profilesingleprocess {
            Policy       = 'Profile_single_process'
            Identity     = 'Administrators'
        }

        # 2.2.35 (L1) Ensure 'Profile system performance' is set to 'Administrators, NT SERVICE\WdiServiceHost'
        UserRightsAssignment Profilesystemperformance {
            Policy       = 'Profile_system_performance'
            Identity     = 'Administrators, NT SERVICE\WdiServiceHost'
        }

        # 2.2.36 (L1) Ensure 'Replace a process level token' is set to 'LOCAL SERVICE, NETWORK SERVICE'
        UserRightsAssignment Replaceaprocessleveltoken {
            Policy       = 'Replace_a_process_level_token'
            Identity     = 'LOCAL SERVICE, NETWORK SERVICE'
        }

        # 2.2.37 (L1) Ensure 'Restore files and directories' is set to 'Administrators'
        UserRightsAssignment Restorefilesanddirectories {
            Policy       = 'Restore_files_and_directories'
            Identity     = 'Administrators'
        }

        # 2.2.38 (L1) Ensure 'Shut down the system' is set to 'Administrators, Users'
        UserRightsAssignment Shutdownthesystem {
            Policy       = 'Shut_down_the_system'
            Identity     = 'Administrators'
        }

        # 2.2.39 (L1) Ensure 'Take ownership of files or other objects' is set to 'Administrators'
        UserRightsAssignment Takeownershipoffilesorotherobjects {
            Policy       = 'Take_ownership_of_files_or_other_objects'
            Identity     = 'Administrators'
        }
     }
  }
   "Managed User Rights"



 if ($psswdP -eq 2) {


  "Cancelling Passowrd Policies..."}




                                                
 "searching for hacking tool..."
$echooff
#looks for common hacking tool names'

Get-ChildItem -Path 'C:\Program Files' -Filter "npcap" -Recurse -ErrorAction SilentlyContinue -Force | Out-File -FilePath 'C:\temp\HardShell\UnautorizedSoftware.txt'
Get-ChildItem -Path 'C:\Program Files' -Filter "Shellter" -Recurse -ErrorAction SilentlyContinue -Force | Out-File -FilePath 'C:\temp\HardShell\UnautorizedSoftware.txt'
Get-ChildItem -Path 'C:\Program Files' -Filter "Armitage" -Recurse -ErrorAction SilentlyContinue -Force | Out-File -FilePath 'C:\temp\HardShell\UnautorizedSoftware.txt'
Get-ChildItem -Path 'C:\Program Files' -Filter "keylogger" -Recurse -ErrorAction SilentlyContinue -Force | Out-File -FilePath 'C:\temp\HardShell\UnautorizedSoftware.txt'
Get-ChildItem -Path 'C:\Program Files' -Filter "nmap" -Recurse -ErrorAction SilentlyContinue -Force | Out-File -FilePath 'C:\temp\HardShell\UnautorizedSoftware.txt'
Get-ChildItem -Path 'C:\Program Files' -Filter "Cain" -Recurse -ErrorAction SilentlyContinue -Force | Out-File -FilePath 'C:\temp\HardShell\UnautorizedSoftware.txt'
Get-ChildItem -Path 'C:\Program Files' -Filter "nmap" -Recurse -ErrorAction SilentlyContinue -Force | Out-File -FilePath 'C:\temp\HardShell\UnautorizedSoftware.txt'

 "Check the output file for results!"

pause

#Searches for media 

$media = read-host "Scan for media?"

if ($media -eq 1){
"Finding unauthorized media files in C:\Users and/or C:\Documents and Settings..."
Get-ChildItem -Path 'C:\Users' -include *.mp3,*.*ac3,*.aiff,*.flac,*.m4a,*.m4p,*.midi,*.mp2,*.m3u,*.ogg,*.vqf,*.wav -Recurse -ErrorAction SilentlyContinue -Force | Out-File -FilePath 'C:\temp\HardShell\UnautorizedSoftware.txt'
Get-ChildItem -Path 'C:\Users' -include *.wma,*.mp4,*.avi,*.mpeg4 -Recurse -ErrorAction SilentlyContinue -Force | Out-File -FilePath 'C:\temp\HardShell\Unautorizedmedia.txt'
Get-ChildItem -Path 'C:\Users' -include *.gif,*.png,*.bmp,*.jpg,.*jpeg -Recurse -ErrorAction SilentlyContinue -Force | Out-File -FilePath 'C:\temp\HardShell\Unautorizedmedia.txt'
"Completed, check the output file"
}

if ($media -eq 2) {
"Skipping media check"
}
"ENABLING AUTO-UPDATES"{
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /v AUOptions /t REG_DWORD /d 3 /f

"Enabling firewall make sure group policy is allowing modifications to the firewall"
netsh advfirewall set allprofiles state on
"Firewall enabled"
"Setting basic firewall rules.."
netsh advfirewall firewall set rule name="Remote Assistance DCOM-In" new enable=no 
netsh advfirewall firewall set rule name="Remote Assistance PNRP-In" new enable=no 
netsh advfirewall firewall set rule name="Remote Assistance RA Server TCP-In" new enable=no 
netsh advfirewall firewall set rule name="Remote Assistance SSDP TCP-In" new enable=no 
netsh advfirewall firewall set rule name="Remote Assistance SSDP UDP-In" new enable=no 
netsh advfirewall firewall set rule name="Remote Assistance TCP-In" new enable=no 
netsh advfirewall firewall set rule name="Telnet Server" new enable=no 
netsh advfirewall firewall set rule name="netcat" new enable=no
netsh advifrewall firewall set rule name="nmap" new enable=no
"Set basic firewall rules"
}
"Setting auditing success and failure for all categories"{
auditpol /set /category:* /success:enable
auditpol /set /category:* /failure:enable
 Set auditing success and failure
}
 "Managing registry keys..."{

reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU /v AutoInstallMinorUpdates /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU /v NoAutoUpdate /t REG_DWORD /d 0 /f
reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU /v AUOptions /t REG_DWORD /d 4 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /v AUOptions /t REG_DWORD /d 4 /f
reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate /v DisableWindowsUpdateAccess /t REG_DWORD /d 0 /f
reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate /v ElevateNonAdmins /t REG_DWORD /d 0 /f
reg add HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer /v NoWindowsUpdate /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\Internet Communication Management\Internet Communication" /v DisableWindowsUpdateAccess /t REG_DWORD /d 0 /f
reg add HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\WindowsUpdate /v DisableWindowsUpdateAccess /t REG_DWORD /d 0 /f

reg ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AllocateCDRoms /t REG_DWORD /d 1 /f

reg ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AllocateFloppies /t REG_DWORD /d 1 /f

reg ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AutoAdminLogon /t REG_DWORD /d 0 /f

reg ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v ClearPageFileAtShutdown /t REG_DWORD /d 1 /f
 
reg ADD "HKLM\SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers" /v AddPrinterDrivers /t REG_DWORD /d 1 /f

reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LSASS.exe" /v AuditLevel /t REG_DWORD /d 00000008 /f

reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 00000001 /f

reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v LimitBlankPasswordUse /t REG_DWORD /d 1 /f

reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v auditbaseobjects /t REG_DWORD /d 1 /f

reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v fullprivilegeauditing /t REG_DWORD /d 1 /f

reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v restrictanonymous /t REG_DWORD /d 1 /f

reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v restrictanonymoussam /t REG_DWORD /d 1 /f

reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v disabledomaincreds /t REG_DWORD /d 1 /f

reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v everyoneincludesanonymous /t REG_DWORD /d 0 /f

reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v UseMachineId /t REG_DWORD /d 0 /f
reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v dontdisplaylastusername /t REG_DWORD /d 1 /f
reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA /t REG_DWORD /d 1 /f
reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v PromptOnSecureDesktop /t REG_DWORD /d 1 /f
reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableInstallerDetection /t REG_DWORD /d 1 /f
reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v undockwithoutlogon /t REG_DWORD /d 0 /f
reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v DisableCAD /t REG_DWORD /d 0 /f
reg ADD HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters /v MaximumPasswordAge /t REG_DWORD /d 15 /f
reg ADD HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters /v DisablePasswordChange /t REG_DWORD /d 1 /f
reg ADD HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters /v RequireStrongKey /t REG_DWORD /d 1 /f
reg ADD HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters /v RequireSignOrSeal /t REG_DWORD /d 1 /f
reg ADD HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters /v SignSecureChannel /t REG_DWORD /d 1 /f
reg ADD HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters /v SealSecureChannel /t REG_DWORD /d 1 /f
reg ADD HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters /v autodisconnect /t REG_DWORD /d 45 /f
reg ADD HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters /v enablesecuritysignature /t REG_DWORD /d 0 /f
reg ADD HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters /v NullSessionPipes /t REG_MULTI_SZ /d "HKCU\Software\Microsoft\Internet Explorer\TempCache" /f
reg ADD HKLM\SYSTEM\CurrentControlSet\services\LanmanWorkstation\Parameters /v EnablePlainTextPassword /t REG_DWORD /d 0 /f
reg ADD HKLM\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg\AllowedExactPaths /v Machine /t REG_MULTI_SZ /d "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\ScriptletsRestricted" /f
reg ADD HKLM\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg\AllowedPaths /v Machine /t REG_MULTI_SZ /d "HKCU\Software\Microsoft\Internet Explorer\PhishingFilter" /f
reg ADD "HKCU\Software\Microsoft\Internet Explorer\PhishingFilter" /v EnabledV8 /t REG_DWORD /d 1 /f
reg ADD "HKCU\Software\Microsoft\Internet Explorer\PhishingFilter" /v EnabledV9 /t REG_DWORD /d 1 /f
reg ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v DisablePasswordCaching /t REG_DWORD /d 1 /f
reg ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v WarnonBadCertRecving /t REG_DWORD /d 1 /f
reg ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v WarnOnPostRedirect /t REG_DWORD /d 1 /f
reg ADD "HKCU\Software\Microsoft\Internet Explorer\Main" /v DoNotTrack /t REG_DWORD /d 1 /f
reg ADD "HKCU\Software\Microsoft\Internet Explorer\Download" /v RunInvalidSignatures /t REG_DWORD /d 1 /f
reg ADD "HKCU\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_LOCALMACHINE_LOCKDOWN\Settings" /v LOCALMACHINE_CD_UNLOCK /t REG_DWORD /d 1 /f
reg ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v WarnonZoneCrossing /t REG_DWORD /d 1 /f
reg ADD HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced /v Hidden /t REG_DWORD /d 1 /f
reg ADD "HKU\.DEFAULT\Control Panel\Accessibility\StickyKeys" /v Flags /t REG_SZ /d 506 /f
reg ADD HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced /v ShowSuperHidden /t REG_DWORD /d 1 /f
reg ADD HKLM\SYSTEM\CurrentControlSet\Control\CrashControl /v CrashDumpEnabled /t REG_DWORD /d 0 /f
reg ADD HKCU\SYSTEM\CurrentControlSet\Services\CDROM /v AutoRun /t REG_DWORD /d 1 /f


}

 "Managed registry keys"


$rdpChk = Read-host "Enable remote desktop"
if ($rdpChk -eq 1){
	 Enabling remote desktop...
	reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v AllowTSConnections /t REG_DWORD /d 1 /f
	reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fAllowToGetHelp /t REG_DWORD /d 1 /f
	reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication /t REG_DWORD /d 1 /f
	REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
	netsh advfirewall firewall set rule group="remote desktop" new enable=yes
	echo Please select "Allow connections only from computers running Remote Desktop with Network Level Authentication (more secure)"
	start SystemPropertiesRemote.exe /wait
	"Enabled remote desktop"
	goto:EOF
}
if ($rdpChk -eq 2){
	"Disabling remote desktop..."
	reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 1 /f
	reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v AllowTSConnections /t REG_DWORD /d 0 /f
	reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fAllowToGetHelp /t REG_DWORD /d 0 /f
	reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication /t REG_DWORD /d 0 /f
	netsh advfirewall firewall set rule group="remote desktop" new enable=no
	 "Disabled remote desktop"
}
 "Disabling Weak Services..."{
dism /online /disable-feature /featurename:IIS-WebServerRole
dism /online /disable-feature /featurename:IIS-WebServer
dism /online /disable-feature /featurename:IIS-CommonHttpFeatures
dism /online /disable-feature /featurename:IIS-HttpErrors
dism /online /disable-feature /featurename:IIS-HttpRedirect
dism /online /disable-feature /featurename:IIS-ApplicationDevelopment
dism /online /disable-feature /featurename:IIS-NetFxExtensibility
dism /online /disable-feature /featurename:IIS-NetFxExtensibility45
dism /online /disable-feature /featurename:IIS-HealthAndDiagnostics
dism /online /disable-feature /featurename:IIS-HttpLogging
dism /online /disable-feature /featurename:IIS-LoggingLibraries
dism /online /disable-feature /featurename:IIS-RequestMonitor
dism /online /disable-feature /featurename:IIS-HttpTracing
dism /online /disable-feature /featurename:IIS-Security
dism /online /disable-feature /featurename:IIS-URLAuthorization
dism /online /disable-feature /featurename:IIS-RequestFiltering
dism /online /disable-feature /featurename:IIS-IPSecurity
dism /online /disable-feature /featurename:IIS-Performance
dism /online /disable-feature /featurename:IIS-HttpCompressionDynamic
dism /online /disable-feature /featurename:IIS-WebServerManagementTools
dism /online /disable-feature /featurename:IIS-ManagementScriptingTools
dism /online /disable-feature /featurename:IIS-IIS6ManagementCompatibility
dism /online /disable-feature /featurename:IIS-Metabase
dism /online /disable-feature /featurename:IIS-HostableWebCore
dism /online /disable-feature /featurename:IIS-StaticContent
dism /online /disable-feature /featurename:IIS-DefaultDocument
dism /online /disable-feature /featurename:IIS-DirectoryBrowsing
dism /online /disable-feature /featurename:IIS-WebDAV
dism /online /disable-feature /featurename:IIS-WebSockets
dism /online /disable-feature /featurename:IIS-ApplicationInit
dism /online /disable-feature /featurename:IIS-ASPNET
dism /online /disable-feature /featurename:IIS-ASPNET45
dism /online /disable-feature /featurename:IIS-ASP
dism /online /disable-feature /featurename:IIS-CGI
dism /online /disable-feature /featurename:IIS-ISAPIExtensions
dism /online /disable-feature /featurename:IIS-ISAPIFilter
dism /online /disable-feature /featurename:IIS-ServerSideIncludes
dism /online /disable-feature /featurename:IIS-CustomLogging
dism /online /disable-feature /featurename:IIS-BasicAuthentication
dism /online /disable-feature /featurename:IIS-HttpCompressionStatic
dism /online /disable-feature /featurename:IIS-ManagementConsole
dism /online /disable-feature /featurename:IIS-ManagementService
dism /online /disable-feature /featurename:IIS-WMICompatibility
dism /online /disable-feature /featurename:IIS-LegacyScripts
dism /online /disable-feature /featurename:IIS-LegacySnapIn
dism /online /disable-feature /featurename:IIS-FTPServer
dism /online /disable-feature /featurename:IIS-FTPSvc
dism /online /disable-feature /featurename:IIS-FTPExtensibility
dism /online /disable-feature /featurename:TFTP
dism /online /disable-feature /featurename:TelnetClient
dism /online /disable-feature /featurename:TelnetServer
echo "finshed disabling weak services" 
pause
}

echo "A second run of disabling weak services"{

reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BTAGService /v Start /t REG_DWORD /d 4 /f
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MapsBroker /v Start /t REG_DWORD /d 4 /f
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\bthserv /v Start /t REG_DWORD /d 4 /f
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\lfsvc /v Start /t REG_DWORD /d 4 /f
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\IISADMIN /v Start /t REG_DWORD /d 4 /f
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Browser /v Start /t REG_DWORD /d 4 /f
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\irmon /v Start /t REG_DWORD /d 4 /f
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SharedAccess /v Start /t REG_DWORD /d 4 /f
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\lltdsvc /v Start /t REG_DWORD /d 4 /f
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LxssManager /v Start /t REG_DWORD /d 4 /f
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\FTPSVC /v Start /t REG_DWORD /d 4 /f
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MSiSCSI /v Start /t REG_DWORD /d 4 /f
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\InstallService /v Start /t REG_DWORD /d 4 /f
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\sshd /v Start /t REG_DWORD /d 4 /f
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PNRPsvc /v Start /t REG_DWORD /d 4 /f
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\p2psvc /v Start /t REG_DWORD /d 4 /f
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\p2pimsvc /v Start /t REG_DWORD /d 4 /f
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PNRPAutoReg /v Start /t REG_DWORD /d 4 /f
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wercplsupport /v Start /t REG_DWORD /d 4 /f
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RasAuto /v Start /t REG_DWORD /d 4 /f
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RemoteRegistry /v Start /t REG_DWORD /d 4 /f
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RemoteAccess /v Start /t REG_DWORD /d 4 /f
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer /v Start /t REG_DWORD /d 4 /f
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\simptcp /v Start /t REG_DWORD /d 4 /f
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SNMP /v Start /t REG_DWORD /d 4 /f
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SSDPSRV /v Start /t REG_DWORD /d 4 /f
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WMSvc /v Start /t REG_DWORD /d 4 /f
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WerSvc /v Start /t REG_DWORD /d 4 /f
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Wecsvc /v Start /t REG_DWORD /d 4 /f
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WMPNetworkSvc /v Start /t REG_DWORD /d 4 /f
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\icssvc /v Start /t REG_DWORD /d 4 /f
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PushToInstall /v Start /t REG_DWORD /d 4 /f
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WinRM /v Start /t REG_DWORD /d 4 /f
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\W3SVC /v Start /t REG_DWORD /d 4 /f
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\XboxGipSvc /v Start /t REG_DWORD /d 4 /f
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\XblAuthManager /v Start /t REG_DWORD /d 4 /f
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\XblGameSave /v Start /t REG_DWORD /d 4 /f
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\XboxNetApiSvc /v Start /t REG_DWORD /d 4 /f

echo "verified weak services are disabled"

pause 

echo "Opening services to verify changes"

services.msc
}


 "turning on UAC..."{
reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA /t REG_DWORD /d 1 /f
}
 "Checking for network shares..."
net share | Out-File -FilePath 'C:\temp\HardShell\Netshares.txt'

 "NOTE: ASR Rules only work for enterprise version of windows"

$manual = Read-Host "(1 for Auto, 2 for Manual ASR configuration)"
if (2 -eq $manual)
{
    #XAML Code kann zwischen @" und "@ ersetzt werden:
Write-Host "Opening ASR HardShell GUI... "
[xml]$XAML = @"
<Window x:Class="ASR_GUI_Radio.MainWindow"
        xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        xmlns:d="http://schemas.microsoft.com/expression/blend/2008"
        xmlns:mc="http://schemas.openxmlformats.org/markup-compatibility/2006"
        xmlns:local="clr-namespace:ASR_GUI_Radio"
        mc:Ignorable="d"
        Title="ASR HardShell GUI" Width="800" Height="580" MaxHeight="580" MaxWidth="800" MinHeight="580" MinWidth="800">
    <StackPanel>
        <Menu  IsMainMenu="true">
            <MenuItem Header="_File">
                <MenuItem x:name="btnReport" Header="Report" ToolTip="A Report will be created in same Directory as File."/>
            </MenuItem>
            <MenuItem Header="_Edit">
                <MenuItem x:Name="btnClear" Header="Remove all configured ASR Rules from Device" ToolTip="CAUTION! Any ASR Rule Configuration will be set to &quot;Not configured&quot;."/>
            </MenuItem>
            <MenuItem x:Name="btnHelp" Header="_Help">
                <MenuItem x:Name="btnDocs" Header="Documentation of ASR Rules"/>
                <MenuItem x:Name="btnInfo" Header="Info"/>
            </MenuItem>
        </Menu>
        <Grid Height="50">
            <Label Content="Attack Surface Reduction Rules" VerticalAlignment="Center" HorizontalAlignment="Left" FontSize="16" FontWeight="Bold"/>
        </Grid>
        <Grid x:Name="OfficeAppsChildProcess">
            <Grid.ColumnDefinitions>
                <ColumnDefinition Width="5*"/>
                <ColumnDefinition Width="*"/>
                <ColumnDefinition Width="*"/>
                <ColumnDefinition/>
            </Grid.ColumnDefinitions>
            <Label Content="Block all Office applications from creating child processes"  Grid.Column="0" />
            <RadioButton x:Name="OAppChildProcD" Content="Disabled" VerticalAlignment="Center"  Grid.Column="1" HorizontalAlignment="Left" Grid.IsSharedSizeScope="True" Panel.ZIndex="2" />
            <RadioButton x:Name="OAppChildProcA" Content="Audit" VerticalAlignment="Center"  Grid.Column="2" HorizontalAlignment="Left" Grid.IsSharedSizeScope="True" Panel.ZIndex="2" />
            <RadioButton x:Name="OAppChildProcB" Content="Enabled" VerticalAlignment="Center"  Grid.Column="3" HorizontalAlignment="Left" Grid.IsSharedSizeScope="True" Panel.ZIndex="2" />
        </Grid>
        <Grid>
            <Grid.ColumnDefinitions>
                <ColumnDefinition Width="5*"/>
                <ColumnDefinition Width="*"/>
                <ColumnDefinition Width="*"/>
                <ColumnDefinition/>
            </Grid.ColumnDefinitions>
            <Label Content="Block execution of potentially obfuscated scripts" Grid.Column="0" />
            <RadioButton x:Name="ObfusScriptD" Content="Disabled" VerticalAlignment="Center"  Grid.Column="1" HorizontalAlignment="Left" Grid.IsSharedSizeScope="True" Panel.ZIndex="2" />
            <RadioButton x:Name="ObfusScriptA" Content="Audit" VerticalAlignment="Center"  Grid.Column="2" HorizontalAlignment="Left" Grid.IsSharedSizeScope="True" Panel.ZIndex="2" />
            <RadioButton x:Name="ObfusScriptB" Content="Enabled" VerticalAlignment="Center" Grid.Column="3" HorizontalAlignment="Left" Grid.IsSharedSizeScope="True" Panel.ZIndex="2" />
        </Grid>
        <Grid>
            <Grid.ColumnDefinitions>
                <ColumnDefinition Width="5*"/>
                <ColumnDefinition Width="*"/>
                <ColumnDefinition Width="*"/>
                <ColumnDefinition/>
            </Grid.ColumnDefinitions>
            <Label Content="Block Win32 API calls from Office macro" Grid.Column="0" />
            <RadioButton x:Name="MacroAPID" Content="Disabled" VerticalAlignment="Center"  Grid.Column="1" HorizontalAlignment="Left" Grid.IsSharedSizeScope="True" Panel.ZIndex="2" />
            <RadioButton x:Name="MacroAPIA" Content="Audit" VerticalAlignment="Center"  Grid.Column="2" HorizontalAlignment="Left" Grid.IsSharedSizeScope="True" Panel.ZIndex="2" />
            <RadioButton x:Name="MacroAPIB" Content="Enabled" VerticalAlignment="Center" Grid.Column="3" HorizontalAlignment="Left" Grid.IsSharedSizeScope="True" Panel.ZIndex="2" />
        </Grid>
        <Grid>
            <Grid.ColumnDefinitions>
                <ColumnDefinition Width="5*"/>
                <ColumnDefinition Width="*"/>
                <ColumnDefinition Width="*"/>
                <ColumnDefinition/>
            </Grid.ColumnDefinitions>
            <Label Content="Block Office applications from creating executable content" Grid.Column="0" />
            <RadioButton x:Name="OfficeCreateExeD" Content="Disabled" VerticalAlignment="Center"  Grid.Column="1" HorizontalAlignment="Left" Grid.IsSharedSizeScope="True" Panel.ZIndex="2" />
            <RadioButton x:Name="OfficeCreateExeA" Content="Audit" VerticalAlignment="Center"  Grid.Column="2" HorizontalAlignment="Left" Grid.IsSharedSizeScope="True" Panel.ZIndex="2" />
            <RadioButton x:Name="OfficeCreateExeB" Content="Enabled" VerticalAlignment="Center" Grid.Column="3" HorizontalAlignment="Left" Grid.IsSharedSizeScope="True" Panel.ZIndex="2" />
        </Grid>
        <Grid>
            <Grid.ColumnDefinitions>
                <ColumnDefinition Width="5*"/>
                <ColumnDefinition Width="*"/>
                <ColumnDefinition Width="*"/>
                <ColumnDefinition/>
            </Grid.ColumnDefinitions>
            <Label Content="Block Office applications from injecting code into other processes" Grid.Column="0" />
            <RadioButton x:Name="OfficeCodeInjD" Content="Disabled" VerticalAlignment="Center"  Grid.Column="1" HorizontalAlignment="Left" Grid.IsSharedSizeScope="True" Panel.ZIndex="2" />
            <RadioButton x:Name="OfficeCodeInjA" Content="Audit" VerticalAlignment="Center"  Grid.Column="2" HorizontalAlignment="Left" Grid.IsSharedSizeScope="True" Panel.ZIndex="2" />
            <RadioButton x:Name="OfficeCodeInjB" Content="Enabled" VerticalAlignment="Center" Grid.Column="3" HorizontalAlignment="Left" Grid.IsSharedSizeScope="True" Panel.ZIndex="2" />
        </Grid>
        <Grid>
            <Grid.ColumnDefinitions>
                <ColumnDefinition Width="5*"/>
                <ColumnDefinition Width="*"/>
                <ColumnDefinition Width="*"/>
                <ColumnDefinition/>
            </Grid.ColumnDefinitions>
            <Label Content="Block JavaScript or VBScript from launching downloaded executable content" Grid.Column="0" />
            <RadioButton x:Name="ScriptDwnlExeD" Content="Disabled" VerticalAlignment="Center"  Grid.Column="1" HorizontalAlignment="Left" Grid.IsSharedSizeScope="True" Panel.ZIndex="2" />
            <RadioButton x:Name="ScriptDwnlExeA" Content="Audit" VerticalAlignment="Center"  Grid.Column="2" HorizontalAlignment="Left" Grid.IsSharedSizeScope="True" Panel.ZIndex="2" />
            <RadioButton x:Name="ScriptDwnlExeB" Content="Enabled" VerticalAlignment="Center" Grid.Column="3" HorizontalAlignment="Left" Grid.IsSharedSizeScope="True" Panel.ZIndex="2" />
        </Grid>
        <Grid>
            <Grid.ColumnDefinitions>
                <ColumnDefinition Width="5*"/>
                <ColumnDefinition Width="*"/>
                <ColumnDefinition Width="*"/>
                <ColumnDefinition/>
            </Grid.ColumnDefinitions>
            <Label Content="Block executable content from email client and webmail" Grid.Column="0" />
            <RadioButton x:Name="MailExeD" Content="Disabled" VerticalAlignment="Center"  Grid.Column="1" HorizontalAlignment="Left" Grid.IsSharedSizeScope="True" Panel.ZIndex="2" />
            <RadioButton x:Name="MailExeA" Content="Audit" VerticalAlignment="Center"  Grid.Column="2" HorizontalAlignment="Left" Grid.IsSharedSizeScope="True" Panel.ZIndex="2" />
            <RadioButton x:Name="MailExeB" Content="Enabled" VerticalAlignment="Center" Grid.Column="3" HorizontalAlignment="Left" Grid.IsSharedSizeScope="True" Panel.ZIndex="2" />
        </Grid>
        <Grid>
            <Grid.ColumnDefinitions>
                <ColumnDefinition Width="5*"/>
                <ColumnDefinition Width="*"/>
                <ColumnDefinition Width="*"/>
                <ColumnDefinition/>
            </Grid.ColumnDefinitions>
            <Label Content="Block executable files from running unless they meet a prevalence, age, or trusted list criteria" Grid.Column="0" />
            <RadioButton x:Name="FileCriteriaD" Content="Disabled" VerticalAlignment="Center"  Grid.Column="1" HorizontalAlignment="Left" Grid.IsSharedSizeScope="True" Panel.ZIndex="2" />
            <RadioButton x:Name="FileCriteriaA" Content="Audit" VerticalAlignment="Center"  Grid.Column="2" HorizontalAlignment="Left" Grid.IsSharedSizeScope="True" Panel.ZIndex="2" />
            <RadioButton x:Name="FileCriteriaB" Content="Enabled" VerticalAlignment="Center" Grid.Column="3" HorizontalAlignment="Left" Grid.IsSharedSizeScope="True" Panel.ZIndex="2" />
        </Grid>
        <Grid>
            <Grid.ColumnDefinitions>
                <ColumnDefinition Width="5*"/>
                <ColumnDefinition Width="*"/>
                <ColumnDefinition Width="*"/>
                <ColumnDefinition/>
            </Grid.ColumnDefinitions>
            <Label Content="Use advanced protection against ransomware" Grid.Column="0" />
            <RadioButton x:Name="RansomwareD" Content="Disabled" VerticalAlignment="Center"  Grid.Column="1" HorizontalAlignment="Left" Grid.IsSharedSizeScope="True" Panel.ZIndex="2" />
            <RadioButton x:Name="RansomwareA" Content="Audit" VerticalAlignment="Center"  Grid.Column="2" HorizontalAlignment="Left" Grid.IsSharedSizeScope="True" Panel.ZIndex="2" />
            <RadioButton x:Name="RansomwareB" Content="Enabled" VerticalAlignment="Center" Grid.Column="3" HorizontalAlignment="Left" Grid.IsSharedSizeScope="True" Panel.ZIndex="2" />
        </Grid>
        <Grid>
            <Grid.ColumnDefinitions>
                <ColumnDefinition Width="5*"/>
                <ColumnDefinition Width="*"/>
                <ColumnDefinition Width="*"/>
                <ColumnDefinition/>
            </Grid.ColumnDefinitions>
            <Label Content="Block credential stealing from the Windows local security authority subsystem (lsass.exe)" Grid.Column="0" />
            <RadioButton x:Name="lsassD" Content="Disabled" VerticalAlignment="Center"  Grid.Column="1" HorizontalAlignment="Left" Grid.IsSharedSizeScope="True" Panel.ZIndex="2" />
            <RadioButton x:Name="lsassA" Content="Audit" VerticalAlignment="Center"  Grid.Column="2" HorizontalAlignment="Left" Grid.IsSharedSizeScope="True" Panel.ZIndex="2" />
            <RadioButton x:Name="lsassB" Content="Enabled" VerticalAlignment="Center" Grid.Column="3" HorizontalAlignment="Left" Grid.IsSharedSizeScope="True" Panel.ZIndex="2" />
        </Grid>
        <Grid>
            <Grid.ColumnDefinitions>
                <ColumnDefinition Width="5*"/>
                <ColumnDefinition Width="*"/>
                <ColumnDefinition Width="*"/>
                <ColumnDefinition/>
            </Grid.ColumnDefinitions>
            <Label Content="Block process creations originating from PSExec and WMI commands" Grid.Column="0" />
            <RadioButton x:Name="prcCreateD" Content="Disabled" VerticalAlignment="Center"  Grid.Column="1" HorizontalAlignment="Left" Grid.IsSharedSizeScope="True" Panel.ZIndex="2" />
            <RadioButton x:Name="prcCreateA" Content="Audit" VerticalAlignment="Center"  Grid.Column="2" HorizontalAlignment="Left" Grid.IsSharedSizeScope="True" Panel.ZIndex="2" />
            <RadioButton x:Name="prcCreateB" Content="Enabled" VerticalAlignment="Center" Grid.Column="3" HorizontalAlignment="Left" Grid.IsSharedSizeScope="True" Panel.ZIndex="2" />
        </Grid>
        <Grid>
            <Grid.ColumnDefinitions>
                <ColumnDefinition Width="5*"/>
                <ColumnDefinition Width="*"/>
                <ColumnDefinition Width="*"/>
                <ColumnDefinition/>
            </Grid.ColumnDefinitions>
            <Label Content="Block untrusted and unsigned processes that run from USB" Grid.Column="0" />
            <RadioButton x:Name="USBD" Content="Disabled" VerticalAlignment="Center"  Grid.Column="1" HorizontalAlignment="Left" Grid.IsSharedSizeScope="True" Panel.ZIndex="2" />
            <RadioButton x:Name="USBA" Content="Audit" VerticalAlignment="Center"  Grid.Column="2" HorizontalAlignment="Left" Grid.IsSharedSizeScope="True" Panel.ZIndex="2" />
            <RadioButton x:Name="USBB" Content="Enabled" VerticalAlignment="Center" Grid.Column="3" HorizontalAlignment="Left" Grid.IsSharedSizeScope="True" Panel.ZIndex="2" />
        </Grid>
        <Grid>
            <Grid.ColumnDefinitions>
                <ColumnDefinition Width="5*"/>
                <ColumnDefinition Width="*"/>
                <ColumnDefinition Width="*"/>
                <ColumnDefinition/>
            </Grid.ColumnDefinitions>
            <Label Content="Block Office communication applications from creating child processes" Grid.Column="0" />
            <RadioButton x:Name="OCommChildProcD" Content="Disabled" VerticalAlignment="Center"  Grid.Column="1" HorizontalAlignment="Left" Grid.IsSharedSizeScope="True" Panel.ZIndex="2" />
            <RadioButton x:Name="OCommChildProcA" Content="Audit" VerticalAlignment="Center"  Grid.Column="2" HorizontalAlignment="Left" Grid.IsSharedSizeScope="True" Panel.ZIndex="2" />
            <RadioButton x:Name="OCommChildProcB" Content="Enabled" VerticalAlignment="Center" Grid.Column="3" HorizontalAlignment="Left" Grid.IsSharedSizeScope="True" Panel.ZIndex="2" />
        </Grid>
        <Grid>
            <Grid.ColumnDefinitions>
                <ColumnDefinition Width="5*"/>
                <ColumnDefinition Width="*"/>
                <ColumnDefinition Width="*"/>
                <ColumnDefinition/>
            </Grid.ColumnDefinitions>
            <Label Content="Block Adobe Reader from creating child processes" Grid.Column="0" />
            <RadioButton x:Name="PDFChildProcD" Content="Disabled" VerticalAlignment="Center"  Grid.Column="1" HorizontalAlignment="Left" Grid.IsSharedSizeScope="True" Panel.ZIndex="2" />
            <RadioButton x:Name="PDFChildProcA" Content="Audit" VerticalAlignment="Center"  Grid.Column="2" HorizontalAlignment="Left" Grid.IsSharedSizeScope="True" Panel.ZIndex="2" />
            <RadioButton x:Name="PDFChildProcB" Content="Enabled" VerticalAlignment="Center" Grid.Column="3" HorizontalAlignment="Left" Grid.IsSharedSizeScope="True" Panel.ZIndex="2" />
        </Grid>
        <Grid>
            <Grid.ColumnDefinitions>
                <ColumnDefinition Width="5*"/>
                <ColumnDefinition Width="*"/>
                <ColumnDefinition Width="*"/>
                <ColumnDefinition/>
            </Grid.ColumnDefinitions>
            <Label Content="Block persistence through WMI event subscription" Grid.Column="0" />
            <RadioButton x:Name="WMIPersD" Content="Disabled" VerticalAlignment="Center"  Grid.Column="1" HorizontalAlignment="Left" Grid.IsSharedSizeScope="True" Panel.ZIndex="2" />
            <RadioButton x:Name="WMIPersA" Content="Audit" VerticalAlignment="Center"  Grid.Column="2" HorizontalAlignment="Left" Grid.IsSharedSizeScope="True" Panel.ZIndex="2" />
            <RadioButton x:Name="WMIPersB" Content="Enabled" VerticalAlignment="Center" Grid.Column="3" HorizontalAlignment="Left" Grid.IsSharedSizeScope="True" Panel.ZIndex="2" />
        </Grid>
        <Grid Height="40" VerticalAlignment="Center">
            <Grid.ColumnDefinitions>
                <ColumnDefinition Width="5*"/>
                <ColumnDefinition Width="*"/>
                <ColumnDefinition Width="*"/>
                <ColumnDefinition/>
            </Grid.ColumnDefinitions>
            <Label x:Name="lblTotal" Content="Total Numbers:" Grid.Column="0" VerticalAlignment="Center" />
            <Label x:Name="lblTotalDisabled" Content="0 Disabled" Grid.Column="1" VerticalAlignment="Center"/>
            <Label x:Name="lblTotalAudit" Content="0 Audit" Grid.Column="2" VerticalAlignment="Center"/>
            <Label x:Name="lblTotalEnabled" Content="0 Enabled" Grid.Column="3" VerticalAlignment="Center"/>
        </Grid>
        <Grid>
            <Grid.ColumnDefinitions>
                <ColumnDefinition Width="3*"/>
                <ColumnDefinition Width="*"/>
                <ColumnDefinition Width="*"/>
                <ColumnDefinition/>
            </Grid.ColumnDefinitions>
            <Button x:Name="btnSave" Content="Save Changes" Grid.Column="2" Padding="1,3,1,3" Margin="10,10,10,10" ToolTip="This will set the new configuration based on the selection."/>
            <Button x:Name="btnReset" Content="Reset" Grid.Column="4" Margin="10,10,10,10" ToolTip="This will reset the selection to the current configuration."/>
        </Grid>
    </StackPanel>
</Window>
"@ -replace 'mc:Ignorable="d"','' -replace "x:N",'N' -replace '^<Win.*', '<Window' #-replace wird benötigt, wenn XAML aus Visual Studio kopiert wird.
#XAML laden
[void][System.Reflection.Assembly]::LoadWithPartialName('presentationframework')
try{
   $Form=[Windows.Markup.XamlReader]::Load( (New-Object System.Xml.XmlNodeReader $XAML) )
} catch {
   Write-Host "Windows.Markup.XamlReader konnte nicht geladen werden. Mögliche Ursache: ungültige Syntax oder fehlendes .net"
}

#Write-Host ====================================== ASR RUles Powershell GUI Live Log ======================================

$xaml.SelectNodes("//*[@Name]") | %{Set-Variable -Name "ASR$($_.Name)" -Value $Form.FindName($_.Name)}

########## GUI Reset Function ###########
function ASRReset {
    $RulesIds = Get-MpPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Ids
    $RulesActions = Get-MpPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Actions
    $RulesExclusions = Get-MpPreference | Select-Object -ExpandProperty AttackSurfaceReductionOnlyExclusions

    $RulesIdsArray = @()
    $RulesIdsArray += $RulesIds

    ##Uncheck RadioButtons
    $RadioArray = "OAppChildProc", "ObfusScript", "MacroAPI", "OfficeCreateExe", "OfficeCodeInj", "ScriptDwnlExe", "MailExe", "FileCriteria", "Ransomware", "lsass", "prcCreate", "USB", "OCommChildProc", "PDFChildProc", "WMIPers"
    for ($i=0; $i -lt $RadioArray.Length; $i++){
        $RadioCheckA = $RadioArray[$i]+"A"
        $RadioCheckD = $RadioArray[$i]+"D"
        $RadioCheckB = $RadioArray[$i]+"B"

        $Form.FindName($RadioCheckA).isChecked = 0
        $Form.FindName($RadioCheckD).isChecked = 0
        $Form.FindName($RadioCheckB).isChecked = 0
    }
    
    ##Total Counter
    $counter = 0
    $TotalDisabled = 0
    $TotalAudit = 0
    $TotalEnabled = 0

    ForEach ($i in $RulesActions){
        If ($RulesActions[$counter] -eq 0){$TotalDisabled++}
        ElseIf ($RulesActions[$counter] -eq 2){$TotalAudit++}
        ElseIf ($RulesActions[$counter] -eq 1){$TotalEnabled++}
        $counter++
    }
    $Form.FindName("lblTotalDisabled").Content =  $TotalDisabled
    $Form.FindName("lblTotalAudit").Content = $TotalAudit
    $Form.FindName("lblTotalEnabled").Content = $TotalEnabled

    $counter = 0

    ForEach ($j in $RulesIds){
        ## Converting GUID to RadioButtonGroup
        If ($RulesIdsArray[$counter] -eq "D4F940AB-401B-4EFC-AADC-AD5F3C50688A"){$ASR = "OAppChildProc"}
        ElseIf ($RulesIdsArray[$counter] -eq "5BEB7EFE-FD9A-4556-801D-275E5FFC04CC"){$ASR = "ObfusScript"}
        ElseIf ($RulesIdsArray[$counter] -eq "92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B"){$ASR = "MacroAPI"}
        ElseIf ($RulesIdsArray[$counter] -eq "3B576869-A4EC-4529-8536-B80A7769E899"){$ASR = "OfficeCreateExe"}
        ElseIf ($RulesIdsArray[$counter] -eq "75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84"){$ASR = "OfficeCodeInj"}
        ElseIf ($RulesIdsArray[$counter] -eq "D3E037E1-3EB8-44C8-A917-57927947596D"){$ASR = "ScriptDwnlExe"}
        ElseIf ($RulesIdsArray[$counter] -eq "BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550"){$ASR = "MailExe"}
        ElseIf ($RulesIdsArray[$counter] -eq "01443614-cd74-433a-b99e-2ecdc07bfc25"){$ASR = "FileCriteria"}
        ElseIf ($RulesIdsArray[$counter] -eq "c1db55ab-c21a-4637-bb3f-a12568109d35"){$ASR = "Ransomware"}
        ElseIf ($RulesIdsArray[$counter] -eq "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2"){$ASR = "lsass"}
        ElseIf ($RulesIdsArray[$counter] -eq "d1e49aac-8f56-4280-b9ba-993a6d77406c"){$ASR = "prcCreate"}
        ElseIf ($RulesIdsArray[$counter] -eq "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4"){$ASR = "USB"}
        ElseIf ($RulesIdsArray[$counter] -eq "26190899-1602-49e8-8b27-eb1d0a1ce869"){$ASR = "OCommChildProc"}
        ElseIf ($RulesIdsArray[$counter] -eq "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c"){$ASR = "PDFChildProc"}
        ElseIf ($RulesIdsArray[$counter] -eq "e6db77e5-3df2-4cf1-b95a-636979351e5b"){$ASR = "WMIPers"}
        ## Checking the Action Mode/Radio Button
        If ($RulesActions[$counter] -eq 0){$Radio = $ASR+"D" }
        ElseIf ($RulesActions[$counter] -eq 1){ $Radio = $ASR+"B"}
        ElseIf ($RulesActions[$counter] -eq 2){$Radio = $ASR+"A"}
        $Form.FindName($Radio).isChecked = 1
        $counter++        
    }
}


ASRReset
#Write-Host "Loading Successful"




######## Resetting GUI ##############
$btnReset = $Form.FindName("btnReset")
$btnReset.Add_Click({
    ASRReset    
})



############ Set New ASR Rules ###########
$btnSave = $Form.FindName("btnSave")
$btnSave.Add_Click({

    #Write-Host ====================================== Set ASR Rules ======================================
    #Write-Host 
    $RadioArray = "OAppChildProc", "ObfusScript", "MacroAPI", "OfficeCreateExe", "OfficeCodeInj", "ScriptDwnlExe", "MailExe", "FileCriteria", "Ransomware", "lsass", "prcCreate", "USB", "OCommChildProc", "PDFChildProc", "WMIPers"
    $ASRGUIDArray = "D4F940AB-401B-4EFC-AADC-AD5F3C50688A", "5BEB7EFE-FD9A-4556-801D-275E5FFC04CC", "92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B", "3B576869-A4EC-4529-8536-B80A7769E899", "75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84", "D3E037E1-3EB8-44C8-A917-57927947596D", "BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550", "01443614-cd74-433a-b99e-2ecdc07bfc25", "c1db55ab-c21a-4637-bb3f-a12568109d35", "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2", "d1e49aac-8f56-4280-b9ba-993a6d77406c", "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4", "26190899-1602-49e8-8b27-eb1d0a1ce869", "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c", "e6db77e5-3df2-4cf1-b95a-636979351e5b"
    $ASRGUIDString = ""
    
    for ($i=0; $i -lt $RadioArray.Length; $i++){
        $RadioCheckA = $RadioArray[$i]+"A"
        $RadioCheckD = $RadioArray[$i]+"D"
        $RadioCheckB = $RadioArray[$i]+"B"
        $ASRGUID = $ASRGUIDArray[$i]
        $RadioEmpty = 0
        
        If ($Form.FindName($RadioCheckA).isChecked -eq 1){$ASRAction = "AuditMode"}
        ElseIf ($Form.FindName($RadioCheckB).isChecked -eq 1){$ASRAction = "Enabled"}
        ElseIf ($Form.FindName($RadioCheckD).isChecked -eq 1){$ASRAction = "Disabled"}
        Else{$RadioEmpty = 1}
        
        If ($RadioEmpty -eq 0){
           
            If ($ASRGUIDString -eq ""){
                $ASRGUIDString = $ASRGUID
                $ASRActions = $ASRAction
                #Write-Host "Set-MpPreference -AttackSurfaceReductionRules_Ids $ASRGUID -AttackSurfaceReductionRules_Actions $ASRAction"
                Set-MpPreference -AttackSurfaceReductionRules_Ids $ASRGUID -AttackSurfaceReductionRules_Actions $ASRAction
            }Else{
                $ASRGUIDString = $ASRGUIDString+", "+$ASRGUID
                $ASRActions = $ASRActions+", "+$ASRAction
                #Write-Host "Add-MpPreference -AttackSurfaceReductionRules_Ids $ASRGUID -AttackSurfaceReductionRules_Actions $ASRAction"
                Add-MpPreference -AttackSurfaceReductionRules_Ids $ASRGUID -AttackSurfaceReductionRules_Actions $ASRAction
            }
        }
    } 
    
    ASRReset
    #Write-Host
    #Write-Host "Setting Successfull"
    #Write-Host ============================================================================
    #Write-Host
    
})





########## Removing All ASR Rules ###########
$btnClear = $Form.FindName("btnClear")
$btnClear.Add_Click({

    #Write-Host ====================================== Clearing ASR Rules ======================================
    #Write-Host 
    
    $RulesIds = Get-MpPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Ids
    $RulesIdsArray = @()
    $RulesIdsArray += $RulesIds

    $counter = 0

    ForEach ($j in $RulesIds){

        $ASR = $RulesIdsArray[$counter]
        
        Remove-MpPreference -AttackSurfaceReductionRules_Ids $ASR
        
        #Write-Host "Removing "$ASR

        $counter++

    }
    ASRReset
    #Write-Host
    #Write-Host "Clearing Successfull"
    #Write-Host ============================================================================
    #Write-Host
})


$btnDocs = $Form.FindName("btnDocs")
$btnDocs.Add_Click({
    Start-Process ‘https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/attack-surface-reduction’
})

$btnInfo = $Form.FindName("btnInfo")
$btnInfo.Add_Click({
    [System.Windows.Forms.MessageBox]::Show("Version 1.0 - 18th May 2020$([System.Environment]::NewLine)Created by Hermann Maurer $([System.Environment]::NewLine)Inspired by Antonio Vasconcelos","Info")
})


    

    ForEach ($i in $RulesActions){
        If ($RulesActions[$counter] -eq 0){$TotalDisabled++}
        ElseIf ($RulesActions[$counter] -eq 1){$TotalBlock++}
        ElseIf ($RulesActions[$counter] -eq 2){$TotalAudit++}
        $counter++
    }
 
    Set-Content -Path .\$ReportName.txt "====================================== ASR Summary ===================================="
    
    Add-Content -Path .\$ReportName.txt -value (Get-Date)
    Add-Content -Path .\$ReportName.txt -value ("Hostname: " + $env:COMPUTERNAME)
    Add-Content -Path .\$ReportName.txt -value ("=> " + ($RulesIds).Count + " Attack Surface Reduction rules configured")
    Add-Content -Path .\$ReportName.txt -value ("=> "+$TotalDisabled + " in Disabled Mode ** " + $TotalAudit + " in Audit Mode ** " + $TotalBlock + " in Block Mode")

    Add-Content -Path .\$ReportName.txt "" 
    Add-Content -Path .\$ReportName.txt "====================================== ASR Rules ======================================"
    Add-Content -Path .\$ReportName.txt -value ("=> GUID`t`t`t`t`t`tAction Mode`t`tDescription")
    $counter = 0

    ForEach ($j in $RulesIds){
        ## Convert GUID into Rule Name
        If ($RulesIdsArray[$counter] -eq "D4F940AB-401B-4EFC-AADC-AD5F3C50688A"){$RuleName = "Block all Office applications from creating child processes"}
        ElseIf ($RulesIdsArray[$counter] -eq "5BEB7EFE-FD9A-4556-801D-275E5FFC04CC"){$RuleName = "Block execution of potentially obfuscated scripts"}
        ElseIf ($RulesIdsArray[$counter] -eq "92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B"){$RuleName = "Block Win32 API calls from Office macro"}
        ElseIf ($RulesIdsArray[$counter] -eq "3B576869-A4EC-4529-8536-B80A7769E899"){$RuleName = "Block Office applications from creating executable content"}
        ElseIf ($RulesIdsArray[$counter] -eq "75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84"){$RuleName = "Block Office applications from injecting code into other processes"}
        ElseIf ($RulesIdsArray[$counter] -eq "D3E037E1-3EB8-44C8-A917-57927947596D"){$RuleName = "Block JavaScript or VBScript from launching downloaded executable content"}
        ElseIf ($RulesIdsArray[$counter] -eq "BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550"){$RuleName = "Block executable content from email client and webmail"}
        ElseIf ($RulesIdsArray[$counter] -eq "01443614-cd74-433a-b99e-2ecdc07bfc25"){$RuleName = "Block executable files from running unless they meet a prevalence, age, or trusted list criteria"}
        ElseIf ($RulesIdsArray[$counter] -eq "c1db55ab-c21a-4637-bb3f-a12568109d35"){$RuleName = "Use advanced protection against ransomware"}
        ElseIf ($RulesIdsArray[$counter] -eq "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2"){$RuleName = "Block credential stealing from the Windows local security authority subsystem (lsass.exe)"}
        ElseIf ($RulesIdsArray[$counter] -eq "d1e49aac-8f56-4280-b9ba-993a6d77406c"){$RuleName = "Block process creations originating from PSExec and WMI commands"}
        ElseIf ($RulesIdsArray[$counter] -eq "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4"){$RuleName = "Block untrusted and unsigned processes that run from USB"}
        ElseIf ($RulesIdsArray[$counter] -eq "26190899-1602-49e8-8b27-eb1d0a1ce869"){$RuleName = "Block Office communication applications from creating child processes"}
        ElseIf ($RulesIdsArray[$counter] -eq "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c"){$RuleName = "Block Adobe Reader from creating child processes"}
        ElseIf ($RulesIdsArray[$counter] -eq "e6db77e5-3df2-4cf1-b95a-636979351e5b"){$RuleName = "Block persistence through WMI event subscription"}
        ## Check the Action type
        If ($RulesActions[$counter] -eq 0){$RuleAction = "Disabled"}
        ElseIf ($RulesActions[$counter] -eq 1){$RuleAction = "Block   "}
        ElseIf ($RulesActions[$counter] -eq 2){$RuleAction = "Audit   "}
        ## Output Rule Id, Name and Action
        Add-Content -Path .\$ReportName.txt -value ("=> " + $RulesIdsArray[$counter]+ "`t`t" + "Action: " + $RuleAction + "`t" + $RuleName )
        $counter++
    }
 
}
Set-ExecutionPolicy Restricted{

Write-Host "Hard Shell Completed"


}