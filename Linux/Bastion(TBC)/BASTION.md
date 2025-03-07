---
tags: 
group: Windows
---
![](https://labs.hackthebox.com/storage/avatars/5ca8f0c721a9eca6f1aeb9ff4b4bac60.png)

- Machine : https://app.hackthebox.com/machines/Bastion
- Reference : https://0xdf.gitlab.io/2019/09/07/htb-bastion.html
- Solved : 2024.00.00. (Thu) (Takes 0days)

## Summary
---


### Key Techniques:


---

# Reconnaissance

### Port Scanning

```bash
┌──(kali㉿kali)-[~/htb]
└─$ ./port-scan.sh 10.10.10.134
Performing quick port scan on 10.10.10.134...
Found open ports: 22,135,139,445,5985,47001,49664,49665,49666,49667,49668,49669,49670
Performing detailed scan on 10.10.10.134...
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-12-24 15:38 EST
Nmap scan report for 10.10.10.134
Host is up (0.13s latency).

PORT      STATE SERVICE      VERSION
22/tcp    open  ssh          OpenSSH for_Windows_7.9 (protocol 2.0)
| ssh-hostkey: 
|   2048 3a:56:ae:75:3c:78:0e:c8:56:4d:cb:1c:22:bf:45:8a (RSA)
|   256 cc:2e:56:ab:19:97:d5:bb:03:fb:82:cd:63:da:68:01 (ECDSA)
|_  256 93:5f:5d:aa:ca:9f:53:e7:f2:82:e6:64:a8:a3:a0:18 (ED25519)
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds Windows Server 2016 Standard 14393 microsoft-ds
5985/tcp  open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
47001/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc        Microsoft Windows RPC
49665/tcp open  msrpc        Microsoft Windows RPC
49666/tcp open  msrpc        Microsoft Windows RPC
49667/tcp open  msrpc        Microsoft Windows RPC
49668/tcp open  msrpc        Microsoft Windows RPC
49669/tcp open  msrpc        Microsoft Windows RPC
49670/tcp open  msrpc        Microsoft Windows RPC
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Host script results:
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb-os-discovery: 
|   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
|   Computer name: Bastion
|   NetBIOS computer name: BASTION\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2024-12-24T21:39:15+01:00
| smb2-time: 
|   date: 2024-12-24T20:39:16
|_  start_date: 2024-12-24T20:12:40
|_clock-skew: mean: -19m59s, deviation: 34m35s, median: -1s
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 68.07 seconds
```

- 4 Ports are open : ssh(22), rpc(135), smb(139,445)
- OS is Windows.

### smb(445)

```bash
┌──(kali㉿kali)-[~/htb]
└─$ smbclient -L 10.10.10.134
Password for [WORKGROUP\kali]:

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        Backups         Disk      
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.10.10.134 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```

There's one non-default share : `Backups`
Let's take a look at this share.

```bash
┌──(kali㉿kali)-[~/htb/smb_backups]
└─$ smbclient \\\\10.10.10.134\\Backups
Password for [WORKGROUP\kali]:

Try "help" to get a list of possible commands.
smb: \> 
smb: \> recurse on
smb: \> prompt off
smb: \> mget *
getting file \note.txt of size 116 as note.txt (0.2 KiloBytes/sec) (average 0.2 KiloBytes/sec)
getting file \SDT65CB.tmp of size 0 as SDT65CB.tmp (0.0 KiloBytes/sec) (average 0.1 KiloBytes/sec)
getting file \WindowsImageBackup\L4mpje-PC\MediaId of size 16 as WindowsImageBackup/L4mpje-PC/MediaId (0.0 KiloBytes/sec) (average 0.1 KiloBytes/sec)
<SNIP>
smb: \> getting file \WindowsImageBackup\L4mpje-PC\Backup 2019-02-22 124351\9b9cfbc3-369e-11e9-a17c-806e6f6e6963.vhd of size 37761024 as WindowsImageBackup/L4mpje-PC/Backup 2019-02-22 124351/9b9cfbc3-369e-11e9-a17c-806e6f6e6963.vhd SMBecho failed (NT_STATUS_CONNECTION_DISCONNECTED). The connection is disconnected now
```

I downloaded all files in the share.

```bash
┌──(kali㉿kali)-[~/htb/smb_backups]
└─$ tree                                                    
.
├── SDT65CB.tmp
├── WindowsImageBackup
│   └── L4mpje-PC
│       ├── Backup 2019-02-22 124351
│       │   └── 9b9cfbc3-369e-11e9-a17c-806e6f6e6963.vhd
│       ├── Catalog
│       ├── MediaId
│       └── SPPMetadataCache
└── note.txt

6 directories, 4 files
```

The file size is too big, so I mounted the share instead.

```bash
┌──(kali㉿kali)-[~/htb]
└─$ sudo mount -t cifs -o username=guest //10.10.10.134/Backups /mnt/smb_share
Password for guest@//10.10.10.134/Backups: 
```

> Revisit it later, after resolving vhd guestmount share issue.
















# Shell as `user`

### Whatever




# Shell as `user2`

### Whatever



# Shell as `admin`

### Whatever
