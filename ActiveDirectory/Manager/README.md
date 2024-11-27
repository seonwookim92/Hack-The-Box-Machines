---
tags:
---
![manager](https://labs.hackthebox.com/storage/avatars/5ca8f0c721a9eca6f1aeb9ff4b4bac60.png)

- Machine : https://app.hackthebox.com/machines/Manager
- Reference : https://0xdf.gitlab.io/2024/03/16/htb-manager.html
- Solved : 2024.11.28. (Thu) (Takes 2days)
### Summary
---


### Key Techniques:



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

