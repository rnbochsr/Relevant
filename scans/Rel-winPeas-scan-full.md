c:\inetpub\wwwroot\nt4wrksv>winPEAS.exe         
winPEAS.exe
ANSI color bit for Windows is not set. If you are execcuting this from a Windows terminal inside the host you should run 'REG ADD HKCU\Console /v VirtualTerminalLevel /t REG_DWORD /d 1' and then start a new CMD
   Creating Dynamic lists, this could take a while, please wait...
   - Checking if domain...
   - Getting Win32_UserAccount info...
   - Creating current user groups list...
  [X] Exception: Object reference not set to an instance of an object.
  [X] Exception: The server could not be contacted.
   - Creating active users list...
   - Creating disabled users list...
   - Admin users list...
     
             *((,.,/((((((((((((((((((((/,  */                                             
      ,/*,..*((((((((((((((((((((((((((((((((((,                                           
    ,*/((((((((((((((((((/,  .*//((//**, .*(((((((*                                        
    ((((((((((((((((**********/########## .(* ,(((((((                                     
    (((((((((((/********************/####### .(. (((((((                                   
    ((((((..******************/@@@@@/***/###### ./(((((((                                  
    ,,....********************@@@@@@@@@@(***,#### .//((((((                                
    , ,..********************/@@@@@%@@@@/********##((/ /((((                               
    ..((###########*********/%@@@@@@@@@/************,,..((((                               
    .(##################(/******/@@@@@/***************.. /((                               
    .(#########################(/**********************..*((                               
    .(##############################(/*****************.,(((                               
    .(###################################(/************..(((                               
    .(#######################################(*********..(((                               
    .(#######(,.***.,(###################(..***.*******..(((                               
    .(#######*(#####((##################((######/(*****..(((                               
    .(###################(/***********(##############(...(((                               
    .((#####################/*******(################.((((((                               
    .(((############################################(..((((                                
    ..(((##########################################(..(((((                                
    ....((########################################( .(((((                                 
    ......((####################################( .((((((                                  
    (((((((((#################################(../((((((                                   
        (((((((((/##########################(/..((((((                                     
              (((((((((/,.  ,*//////*,. ./(((((((((((((((.                                 
                 (((((((((((((((((((((((((((((/                                            

ADVISORY: winpeas should be used for authorized penetration testing and/or educational purposes only. Any misuse of this software will not be the responsibility of the author or of any other collaborator. Use it at your own networks and/or with the network owner's permission.                                                                                         
                                                                                           
  WinPEAS vBETA VERSION, Please if you find any issue let me know in https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/issues by carlospolop                  

  [+] Leyend:
         Red                Indicates a special privilege over an object or something is misconfigured                                                                                
         Green              Indicates that some protection is enabled or something is well configured                                                                                 
         Cyan               Indicates active users
         Blue               Indicates disabled users
         LightYellow        Indicates links

   [?] You can find a Windows local PE Checklist here: https://book.hacktricks.xyz/windows/checklist-windows-privilege-escalation                                                     


  ==========================================(System Information)==========================================                                                                            

  [+] Basic System Information(T1082&T1124&T1012&T1497&T1212)
   [?] Check if the Windows versions is vulnerable to some known exploit https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#kernel-exploits                       
    Hostname: Relevant
    ProductName: Windows Server 2016 Standard Evaluation
    EditionID: ServerStandardEval
    ReleaseId: 1607
    BuildBranch: rs1_release
    CurrentMajorVersionNumber: 10
    CurrentVersion: 6.3
    Architecture: AMD64
    ProcessorCount: 1
    SystemLang: en-US
    KeyboardLang: English (United States)
    TimeZone: (UTC-08:00) Pacific Time (US & Canada)
    IsVirtualMachine: False
    Current Time: 9/24/2022 12:55:44 PM
    HighIntegrity: False
    PartOfDomain: False
    Hotfixes: KB3192137, KB3211320, KB3213986, 

  [?] Windows vulns search powered by Watson(https://github.com/rasta-mouse/Watson)
    OS Build Number: 14393
       [!] CVE-2019-0836 : VULNERABLE
        [>] https://exploit-db.com/exploits/46718
        [>] https://decoder.cloud/2019/04/29/combinig-luafv-postluafvpostreadwrite-race-condition-pe-with-diaghub-collector-exploit-from-standard-user-to-system/                     

       [!] CVE-2019-0841 : VULNERABLE
        [>] https://github.com/rogue-kdc/CVE-2019-0841
        [>] https://rastamouse.me/tags/cve-2019-0841/

       [!] CVE-2019-1064 : VULNERABLE
        [>] https://www.rythmstick.net/posts/cve-2019-1064/

       [!] CVE-2019-1130 : VULNERABLE
        [>] https://github.com/S3cur3Th1sSh1t/SharpByeBear

       [!] CVE-2019-1253 : VULNERABLE
        [>] https://github.com/padovah4ck/CVE-2019-1253

       [!] CVE-2019-1315 : VULNERABLE
        [>] https://offsec.almond.consulting/windows-error-reporting-arbitrary-file-move-eop.html                                                                                     

       [!] CVE-2019-1385 : VULNERABLE
        [>] https://www.youtube.com/watch?v=K6gHnr-VkAg

       [!] CVE-2019-1388 : VULNERABLE
        [>] https://github.com/jas502n/CVE-2019-1388

       [!] CVE-2019-1405 : VULNERABLE
        [>] https://www.nccgroup.trust/uk/about-us/newsroom-and-events/blogs/2019/november/cve-2019-1405-and-cve-2019-1322-elevation-to-system-via-the-upnp-device-host-service-and-the-update-orchestrator-service/                                                             

    Finished. Found 9 potential vulnerabilities.

  [+] PowerShell Settings()
    PowerShell v2 Version: 2.0
    PowerShell v5 Version: 5.1.14393.0
    Transcription Settings: 
    Module Logging Settings: 
    Scriptblock Logging Settings: 

  [+] Audit Settings(T1012)
   [?] Check what is being logged 
    Not Found

  [+] WEF Settings(T1012)
   [?] Windows Event Forwarding, is interesting to know were are sent the logs 
    Not Found

  [+] LAPS Settings(T1012)
   [?] If installed, local administrator password is changed frequently and is restricted by ACL                                                                                      
    LAPS Enabled: LAPS not installed

  [+] Wdigest()
   [?] If enabled, plain-text crds could be stored in LSASS https://book.hacktricks.xyz/windows/stealing-credentials/credentials-protections#wdigest                                  
    Wdigest is not enabled

  [+] LSA Protection()
   [?] If enabled, a driver is needed to read LSASS memory (If Secure Boot or UEFI, RunAsPPL cannot be disabled by deleting the registry key) https://book.hacktricks.xyz/windows/stealing-credentials/credentials-protections#lsa-protection                                    
    LSA Protection is not enabled

  [+] Credentials Guard()
   [?] If enabled, a driver is needed to read LSASS memory https://book.hacktricks.xyz/windows/stealing-credentials/credentials-protections#credential-guard                          
    CredentialGuard is not enabled

  [+] Cached Creds()
   [?] If > 0, credentials will be cached in the registry and accessible by SYSTEM user https://book.hacktricks.xyz/windows/stealing-credentials/credentials-protections#cached-credentials                                                                                      
    cachedlogonscount is 10

  [+] User Environment Variables()
   [?] Check for some passwords or keys in the env variables 
    COMPUTERNAME: RELEVANT
    PUBLIC: C:\Users\Public
    LOCALAPPDATA: C:\Windows\system32\config\systemprofile\AppData\Local
    PSModulePath: C:\Program Files\WindowsPowerShell\Modules;C:\Windows\system32\WindowsPowerShell\v1.0\Modules
    PROCESSOR_ARCHITECTURE: AMD64
    Path: C:\Windows\system32;C:\Windows;C:\Windows\System32\Wbem;C:\Windows\System32\WindowsPowerShell\v1.0\;C:\Windows\system32\config\systemprofile\AppData\Local\Microsoft\WindowsApps
    CommonProgramFiles(x86): C:\Program Files (x86)\Common Files
    ProgramFiles(x86): C:\Program Files (x86)
    PROCESSOR_LEVEL: 6
    ProgramFiles: C:\Program Files
    PATHEXT: .COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC
    USERPROFILE: C:\Windows\system32\config\systemprofile
    SystemRoot: C:\Windows
    APP_POOL_ID: DefaultAppPool
    ALLUSERSPROFILE: C:\ProgramData
    APP_POOL_CONFIG: C:\inetpub\temp\apppools\DefaultAppPool\DefaultAppPool.config
    ProgramData: C:\ProgramData
    PROCESSOR_REVISION: 3f02
    USERNAME: RELEVANT$
    CommonProgramW6432: C:\Program Files\Common Files
    CommonProgramFiles: C:\Program Files\Common Files
    OS: Windows_NT
    PROCESSOR_IDENTIFIER: Intel64 Family 6 Model 63 Stepping 2, GenuineIntel
    ComSpec: C:\Windows\system32\cmd.exe
    PROMPT: $P$G
    SystemDrive: C:
    TEMP: C:\Windows\TEMP
    NUMBER_OF_PROCESSORS: 1
    APPDATA: C:\Windows\system32\config\systemprofile\AppData\Roaming
    TMP: C:\Windows\TEMP
    ProgramW6432: C:\Program Files
    windir: C:\Windows
    USERDOMAIN: WORKGROUP

  [+] System Environment Variables()
   [?] Check for some passwords or keys in the env variables 
    ComSpec: C:\Windows\system32\cmd.exe
    OS: Windows_NT
    Path: C:\Windows\system32;C:\Windows;C:\Windows\System32\Wbem;C:\Windows\System32\WindowsPowerShell\v1.0\
    PATHEXT: .COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC
    PROCESSOR_ARCHITECTURE: AMD64
    PSModulePath: C:\Program Files\WindowsPowerShell\Modules;C:\Windows\system32\WindowsPowerShell\v1.0\Modules
    TEMP: C:\Windows\TEMP
    TMP: C:\Windows\TEMP
    USERNAME: SYSTEM
    windir: C:\Windows
    NUMBER_OF_PROCESSORS: 1
    PROCESSOR_LEVEL: 6
    PROCESSOR_IDENTIFIER: Intel64 Family 6 Model 63 Stepping 2, GenuineIntel
    PROCESSOR_REVISION: 3f02

  [+] HKCU Internet Settings(T1012)
    User Agent: Mozilla/4.0 (compatible; MSIE 8.0; Win32)
    IE5_UA_Backup_Flag: 5.0
    ZonesSecurityUpgrade: System.Byte[]

  [+] HKLM Internet Settings(T1012)
    ActiveXCache: C:\Windows\Downloaded Program Files
    CodeBaseSearchPath: CODEBASE
    EnablePunycode: 1
    MinorVersion: 0
    WarnOnIntranet: 1

  [+] Drives Information(T1120)
   [?] Remember that you should search more info inside the other drives 
    C:\ (Type: Fixed)(Filesystem: NTFS)(Available space: 19 GB)(Permissions: Users [AppendData/CreateDirectories])                                                                    

  [+] AV Information(T1063)
  [X] Exception: Invalid namespace 
    No AV was detected!!
    Not Found

  [+] UAC Status(T1012)
   [?] If you are in the Administrators group check how to bypass the UAC https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#basic-uac-bypass-full-file-system-access                                                                                        
    ConsentPromptBehaviorAdmin: 5 - PromptForNonWindowsBinaries
    EnableLUA: 1
    LocalAccountTokenFilterPolicy: 
    FilterAdministratorToken: 
      [*] LocalAccountTokenFilterPolicy set to 0 and FilterAdministratorToken != 1.
      [-] Only the RID-500 local admin account can be used for lateral movement.           


  ===========================================(Users Information)===========================================                                                                           

  [+] Users(T1087&T1069&T1033)
   [?] Check if you have some admin equivalent privileges https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#users-and-groups                                     
  Current user: 35mDefaultAppPool
  Current groups: Everyone, Users, Service, Console Logon, Authenticated Users, This Organization, IIS_IUSRS, Local, S-1-5-82-0
   =================================================================================================                                                                                  

    RELEVANT\Administrator: Built-in account for administering the computer/domain
        |->Password: CanChange-NotExpi-Req

    RELEVANT\Bob
        |->Password: NotChange-NotExpi-Req

    RELEVANT\DefaultAccount(Disabled): A user account managed by the system.
        |->Password: CanChange-NotExpi-NotReq

    RELEVANT\Guest: Built-in account for guest access to the computer/domain
        |->Password: NotChange-NotExpi-NotReq


  [+] Current Token privileges(T1134)
   [?] Check if you can escalate privilege using some enabled token https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#token-manipulation                         
    SeAssignPrimaryTokenPrivilege: DISABLED
    SeIncreaseQuotaPrivilege: DISABLED
    SeAuditPrivilege: DISABLED
    SeChangeNotifyPrivilege: SE_PRIVILEGE_ENABLED_BY_DEFAULT, SE_PRIVILEGE_ENABLED
    SeImpersonatePrivilege: SE_PRIVILEGE_ENABLED_BY_DEFAULT, SE_PRIVILEGE_ENABLED
    SeCreateGlobalPrivilege: SE_PRIVILEGE_ENABLED_BY_DEFAULT, SE_PRIVILEGE_ENABLED
    SeIncreaseWorkingSetPrivilege: DISABLED

  [+] Clipboard text(T1134)


  [+] Logged users(T1087&T1033)
    Not Found

  [+] RDP Sessions(T1087&T1033)
    Not Found

  [+] Ever logged users(T1087&T1033)
    35mIIS APPPOOL\.NET v4.5 Classic
    35mIIS APPPOOL\.NET v4.5
    RELEVANT\Administrator

  [+] Looking for AutoLogon credentials(T1012)
    Not Found

  [+] Home folders found(T1087&T1083&T1033)
    C:\Users\.NET v4.5
    C:\Users\.NET v4.5 Classic
    C:\Users\Administrator
    C:\Users\All Users
    C:\Users\Bob : Everyone [AllAccess]
    C:\Users\Default : Users [AppendData/CreateDirectories WriteData/CreateFiles]
    C:\Users\Default User
    C:\Users\Public : Service [WriteData/CreateFiles]

  [+] Password Policies(T1201)
   [?] Check for a possible brute-force 
    Domain: Builtin
    SID: S-1-5-32
    MaxPasswordAge: 42.22:47:31.7437440
    MinPasswordAge: 00:00:00
    MinPasswordLength: 0
    PasswordHistoryLength: 0
    PasswordProperties: 0
   =================================================================================================                                                                                  

    Domain: RELEVANT
    SID: S-1-5-21-3981879597-1135670737-2718083060
    MaxPasswordAge: 42.00:00:00
    MinPasswordAge: 00:00:00
    MinPasswordLength: 0
    PasswordHistoryLength: 0
    PasswordProperties: DOMAIN_PASSWORD_COMPLEX
   =================================================================================================                                                                                  



  =======================================(Processes Information)=======================================                                                                               

  [+] Interesting Processes -non Microsoft-(T1010&T1057&T1007)
   [?] Check if any interesting proccesses for memmory dump or if you could overwrite some binary running https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#running-processes                                                                               
    cmd(3324)[C:\Windows\SYSTEM32\cmd.exe] -- POwn:35m DefaultAppPool
    Command Line: cmd
   =================================================================================================                                                                                  

    conhost(3304)[C:\Windows\system32\conhost.exe] -- POwn:35m DefaultAppPool
    Command Line: \??\C:\Windows\system32\conhost.exe 0x4
   =================================================================================================                                                                                  

    winPEAS(4024)[c:\inetpub\wwwroot\nt4wrksv\winPEAS.exe] -- POwn:35m DefaultAppPool -- isDotNet
    Permissions: Everyone [AllAccess]
    Possible DLL Hijacking folder: c:\inetpub\wwwroot\nt4wrksv (Everyone [AllAccess])
    Command Line: winPEAS.exe
   =================================================================================================                                                                                  



  ========================================(Services Information)========================================                                                                              

  [+] Interesting Services -non Microsoft-(T1007)
   [?] Check if you can overwrite some service binary or perform a DLL hijacking, also check for unquoted paths https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#services                                                                                  
    AmazonSSMAgent(Amazon SSM Agent)["C:\Program Files\Amazon\SSM\amazon-ssm-agent.exe"] - Auto - Running
    Amazon SSM Agent
   =================================================================================================                                                                                  

    AWSLiteAgent(Amazon Inc. - AWS Lite Guest Agent)[C:\Program Files\Amazon\XenTools\LiteAgent.exe] - Auto - Running - No quotes and Space detected                                  
    AWS Lite Guest Agent
   =================================================================================================                                                                                  

    PsShutdownSvc(Systems Internals - PsShutdown)[C:\Windows\PSSDNSVC.EXE] - Manual - Stopped
   =================================================================================================                                                                                  

    VBoxService(Oracle Corporation - VirtualBox Guest Additions Service)[C:\Windows\System32\VBoxService.exe] - Auto - Stopped                                                        
    Manages VM runtime information, time synchronization, remote sysprep execution and miscellaneous utilities for guest operating systems.                                           
   =================================================================================================                                                                                  


  [+] Modifiable Services(T1007)
   [?] Check if you can modify any service https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#services                                                            
    You cannot modify any service

  [+] Looking if you can modify any service registry()
   [?] Check if you can modify the registry of a service https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#services-registry-permissions                         
    [-] Looks like you cannot change the registry of any service...

  [+] Checking write permissions in PATH folders (DLL Hijacking)()
   [?] Check for DLL Hijacking in PATH folders https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#dll-hijacking                                                   
    C:\Windows\system32
    C:\Windows
    C:\Windows\System32\Wbem
    C:\Windows\System32\WindowsPowerShell\v1.0\


  ====================================(Applications Information)====================================                                                                                  

  [+] Current Active Window Application(T1010&T1518)
System.NullReferenceException: Object reference not set to an instance of an object.
   at winPEAS.MyUtils.GetPermissionsFile(String path, Dictionary`2 SIDs)                   
   at winPEAS.Program.<PrintInfoApplications>g__PrintActiveWindow|44_0()                   

  [+] Installed Applications --Via Program Files/Uninstall registry--(T1083&T1012&T1010&T1518)                                                                                        
   [?] Check if you can modify installed software https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#software                                                     
    C:\Program Files\Amazon
    C:\Program Files\Common Files
    C:\Program Files\desktop.ini
    C:\Program Files\Internet Explorer
    C:\Program Files\Oracle
    C:\Program Files\Uninstall Information
    C:\Program Files\Windows Defender
    C:\Program Files\Windows Mail
    C:\Program Files\Windows Media Player
    C:\Program Files\Windows Multimedia Platform
    C:\Program Files\Windows NT
    C:\Program Files\Windows Photo Viewer
    C:\Program Files\Windows Portable Devices
    C:\Program Files\Windows Sidebar
    C:\Program Files\WindowsApps
    C:\Program Files\WindowsPowerShell


  [+] Autorun Applications(T1010)
   [?] Check if you can modify other users AutoRuns binaries https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#run-at-startup                                    
System.IO.DirectoryNotFoundException: Could not find a part of the path 'C:\Windows\system32\config\systemprofile\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup'.     
   at System.IO.__Error.WinIOError(Int32 errorCode, String maybeFullPath)                  
   at System.IO.FileSystemEnumerableIterator`1.CommonInit()                                
   at System.IO.Directory.GetFiles(String path, String searchPattern, SearchOption searchOption)                                                                                      
   at winPEAS.ApplicationInfo.GetAutoRunsFolder()                                          
   at winPEAS.ApplicationInfo.GetAutoRuns(Dictionary`2 NtAccountNames)                     
   at winPEAS.Program.<PrintInfoApplications>g__PrintAutoRuns|44_2()                       

  [+] Scheduled Applications --Non Microsoft--(T1010)
   [?] Check if you can modify other users scheduled binaries https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#run-at-startup                                   
System.IO.FileNotFoundException: Could not load file or assembly 'Microsoft.Win32.TaskScheduler, Version=2.8.16.0, Culture=neutral, PublicKeyToken=c416bc1b32d97233' or one of its dependencies. The system cannot find the file specified.                                      
File name: 'Microsoft.Win32.TaskScheduler, Version=2.8.16.0, Culture=neutral, PublicKeyToken=c416bc1b32d97233'                                                                        
   at winPEAS.ApplicationInfo.GetScheduledAppsNoMicrosoft()                                
   at winPEAS.Program.<PrintInfoApplications>g__PrintScheduled|44_3()                      
                                                                                           
WRN: Assembly binding logging is turned OFF.                                               
To enable assembly bind failure logging, set the registry value [HKLM\Software\Microsoft\Fusion!EnableLog] (DWORD) to 1.                                                              
Note: There is some performance penalty associated with assembly bind failure logging.     
To turn this feature off, remove the registry value [HKLM\Software\Microsoft\Fusion!EnableLog].                                                                                       
                                                                                           


  =========================================(Network Information)=========================================                                                                             

  [+] Network Shares(T1135)
    ADMIN$ (Path: C:\Windows)
    C$ (Path: C:\)
    IPC$ (Path: )
    nt4wrksv (Path: C:\inetpub\wwwroot\nt4wrksv) -- Permissions: AllAccess

  [+] Host File(T1016)

  [+] Network Ifaces and known hosts(T1016)
   [?] The masks are only for the IPv4 addresses 
  [X] Exception: The requested protocol has not been configured into the system, or no implementation for it exists                                                                   
    Ethernet 2[02:E6:A8:BA:42:DF]: 10.10.113.238, fe80::31c2:7935:9899:ade7%4 / 255.255.0.0
        Gateways: 10.10.0.1
        DNSs: 10.0.0.2
    Loopback Pseudo-Interface 1[]: 127.0.0.1, ::1 / 255.0.0.0
        DNSs: fec0:0:0:ffff::1%1, fec0:0:0:ffff::2%1, fec0:0:0:ffff::3%1

  [+] Current Listening Ports(T1049&T1049)
   [?] Check for services restricted from the outside 
    Proto     Local Address          Foreing Address        State
    TCP       0.0.0.0:80                                    Listening
    TCP       0.0.0.0:135                                   Listening
    TCP       0.0.0.0:445                                   Listening
    TCP       0.0.0.0:3389                                  Listening
    TCP       0.0.0.0:5985                                  Listening
    TCP       0.0.0.0:47001                                 Listening
    TCP       0.0.0.0:49663                                 Listening
    TCP       0.0.0.0:49664                                 Listening
    TCP       0.0.0.0:49665                                 Listening
    TCP       0.0.0.0:49666                                 Listening
    TCP       0.0.0.0:49667                                 Listening
    TCP       0.0.0.0:49668                                 Listening
    TCP       0.0.0.0:49670                                 Listening
    TCP       10.10.113.238:139                             Listening
    TCP       [::]:80                                       Listening
    TCP       [::]:135                                      Listening
    TCP       [::]:445                                      Listening
    TCP       [::]:3389                                     Listening
    TCP       [::]:5985                                     Listening
    TCP       [::]:47001                                    Listening
    TCP       [::]:49663                                    Listening
    TCP       [::]:49664                                    Listening
    TCP       [::]:49665                                    Listening
    TCP       [::]:49666                                    Listening
    TCP       [::]:49667                                    Listening
    TCP       [::]:49668                                    Listening
    TCP       [::]:49670                                    Listening
    UDP       0.0.0.0:123                                   Listening
    UDP       0.0.0.0:3389                                  Listening
    UDP       0.0.0.0:5050                                  Listening
    UDP       0.0.0.0:5353                                  Listening
    UDP       0.0.0.0:5355                                  Listening
    UDP       10.10.113.238:137                             Listening
    UDP       10.10.113.238:138                             Listening
    UDP       10.10.113.238:1900                            Listening
    UDP       10.10.113.238:63564                           Listening
    UDP       127.0.0.1:1900                                Listening
    UDP       127.0.0.1:58026                               Listening
    UDP       127.0.0.1:63565                               Listening
    UDP       [::]:123                                      Listening
    UDP       [::1]:1900                                    Listening
    UDP       [::1]:63563                                   Listening
    UDP       [fe80::31c2:7935:9899:ade7%4]:1900                       Listening
    UDP       [fe80::31c2:7935:9899:ade7%4]:63562                       Listening

  [+] Firewall Rules(T1016)
   [?] Showing only DENY rules (too many ALLOW rules always) 
    Current Profiles: PUBLIC
    FirewallEnabled (Domain):    True
    FirewallEnabled (Private):    True
    FirewallEnabled (Public):    True
    DENY rules:

  [+] DNS cached --limit 70--(T1016)
    Entry                                 Name                                  Data
    _ldap._tcp.dc._msdcs.relevant                                               
    sls.update.microsoft.com              sls.update.microsoft.com              ...prod.dcat.dsp.trafficmanager.net
    sls.update.microsoft.com              ...prod.dcat.dsp.trafficmanager.net   52.242.101.226
    wpad                                                                        


  =========================================(Windows Credentials)=========================================                                                                             

  [+] Checking Windows Vault()
   [?]  https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#credentials-manager-windows-vault                                                                      
    Not Found

  [+] Checking Credential manager()
   [?]  https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#credentials-manager-windows-vault                                                                      
    This function is not yet implemented.
    [i] If you want to list credentials inside Credential Manager use 'cmdkey /list'

  [+] Saved RDP connections()
    Not Found

  [+] Recently run commands()
    Not Found

  [+] PS default transcripts history()
    [i] Read the PS histpry inside these files (if any)

  [+] Checking for DPAPI Master Keys()
   [?]  https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#dpapi
    Not Found

  [+] Checking for Credential Files()
   [?]  https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#dpapi
    Not Found

  [+] Checking for RDCMan Settings Files()
   [?] Dump credentials from Remote Desktop Connection Manager https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#remote-desktop-credential-manager               
    Not Found

  [+] Looking for kerberos tickets()
   [?]  https://book.hacktricks.xyz/pentesting/pentesting-kerberos-88
  [X] Exception: Object reference not set to an instance of an object.
    Not Found

  [+] Looking saved Wifis()
    This function is not yet implemented.
    [i] If you want to list saved Wifis connections you can list the using 'netsh wlan show profile'                                                                                  
    [i] If you want to get the clear-text password use 'netsh wlan show profile <SSID> key=clear'                                                                                     

  [+] Looking AppCmd.exe()
   [?]  https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#appcmd-exe
    AppCmd.exe was found in C:\Windows\system32\inetsrv\appcmd.exe You should try to search for credentials                                                                           

  [+] Looking SSClient.exe()
   [?]  https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#scclient-sccm                                                                                          
    Not Found

  [+] Checking AlwaysInstallElevated(T1012)
   [?]  https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#alwaysinstallelevated                                                                                  
    AlwaysInstallElevated isn't available

  [+] Checking WSUS(T1012)
   [?]  https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#wsus
    Not Found


  ========================================(Browsers Information)========================================                                                                              

  [+] Looking for Firefox DBs(T1503)
   [?]  https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#browsers-history                                                                                       
    Not Found

  [+] Looking for GET credentials in Firefox history(T1503)
   [?]  https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#browsers-history                                                                                       
    Not Found

  [+] Looking for Chrome DBs(T1503)
   [?]  https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#browsers-history                                                                                       
    Not Found

  [+] Looking for GET credentials in Chrome history(T1503)
   [?]  https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#browsers-history                                                                                       
    Not Found

  [+] Chrome bookmarks(T1217)
    Not Found

  [+] Current IE tabs(T1503)
   [?]  https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#browsers-history                                                                                       
  [X] Exception: System.Reflection.TargetInvocationException: Exception has been thrown by the target of an invocation. ---> System.Runtime.InteropServices.COMException: The server process could not be started because the configured identity is incorrect. Check the username and password. (Exception from HRESULT: 0x8000401A)                                       
   --- End of inner exception stack trace ---                                              
   at System.RuntimeType.InvokeDispMethod(String name, BindingFlags invokeAttr, Object target, Object[] args, Boolean[] byrefModifiers, Int32 culture, String[] namedParameters)      
   at System.RuntimeType.InvokeMember(String name, BindingFlags bindingFlags, Binder binder, Object target, Object[] providedArgs, ParameterModifier[] modifiers, CultureInfo culture, String[] namedParams)                                                                     
   at winPEAS.KnownFileCredsInfo.GetCurrentIETabs()                                        
    Not Found

  [+] Looking for GET credentials in IE history(T1503)
   [?]  https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#browsers-history                                                                                       
  [X] Exception: System.IO.DirectoryNotFoundException: Could not find a part of the path 'C:\Windows\system32\config\systemprofile\Favorites'.                                        
   at System.IO.__Error.WinIOError(Int32 errorCode, String maybeFullPath)                  
   at System.IO.FileSystemEnumerableIterator`1.CommonInit()                                
   at System.IO.Directory.GetFiles(String path, String searchPattern, SearchOption searchOption)                                                                                      
   at winPEAS.KnownFileCredsInfo.GetIEHistFav()                                            

  [+] IE favorites(T1217)
    Not Found


  ==============================(Interesting files and registry)==============================                                                                                        

  [+] Putty Sessions()
    Not Found

  [+] Putty SSH Host keys()
    Not Found

  [+] SSH keys in registry()
   [?] If you find anything here, follow the link to learn how to decrypt the SSH keys https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#ssh-keys-in-registry    
    Not Found

  [+] Cloud Credentials(T1538&T1083&T1081)
   [?]  https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#credentials-inside-files                                                                               
    Not Found

  [+] Unnattend Files()

  [+] Looking for common SAM & SYSTEM backups()

  [+] Looking for McAfee Sitelist.xml Files()

  [+] Cached GPP Passwords()
  [X] Exception: Could not find a part of the path 'C:\ProgramData\Microsoft\Group Policy\History'.

  [+] Looking for possible regs with creds(T1012&T1214)
   [?]  https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#inside-the-registry                                                                                    
    Not Found
    Not Found
    Not Found
    Not Found

  [+] Looking for possible password files in users homes(T1083&T1081)
   [?]  https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#credentials-inside-files                                                                               
    C:\Users\All Users\Microsoft\UEV\InboxTemplates\RoamingCredentialSettings.xml

  [+] Looking inside the Recycle Bin for creds files(T1083&T1081&T1145)
   [?]  https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#credentials-inside-files                                                                               
    Not Found

  [+] Searching known files that can contain creds in home(T1083&T1081)
   [?]  https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#credentials-inside-files                                                                               

  [+] Looking for documents --limit 100--(T1083)
    Not Found

  [+] Recent files --limit 70--(T1083&T1081)
  [X] Exception: System.IO.DirectoryNotFoundException: Could not find a part of the path 'C:\Windows\system32\config\systemprofile\AppData\Roaming\Microsoft\Windows\Recent'.         
   at System.IO.__Error.WinIOError(Int32 errorCode, String maybeFullPath)                  
   at System.IO.FileSystemEnumerableIterator`1.CommonInit()                                
   at System.IO.Directory.GetFiles(String path, String searchPattern, SearchOption searchOption)                                                                                      
   at winPEAS.KnownFileCredsInfo.GetRecentFiles()                                          
    Not Found

c:\inetpub\wwwroot\nt4wrksv>
