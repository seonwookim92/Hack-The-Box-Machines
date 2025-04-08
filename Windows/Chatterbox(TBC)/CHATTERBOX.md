---
tags: 
group: Windows
---
![](https://labs.hackthebox.com/storage/avatars/0d153f144af7b3b7213787c7e42df7d2.png)

- Machine : https://app.hackthebox.com/machines/Chatterbox
- Reference : https://0xdf.gitlab.io/2018/06/18/htb-chatterbox.html
- Solved : 2025.00.00. (Thu) (Takes 0days)

## Summary
---


### Key Techniques:


---

# Reconnaissance

### Port Scanning

```bash
┌──(kali㉿kali)-[~/htb/chatterbox]
└─$ /opt/custom-scripts/port-scan.sh 10.10.10.74 
Performing quick port scan on 10.10.10.74...
Found open ports: 135,139,445,9255,9256,49152,49153,49154,49155,49156,49157
Performing detailed scan on 10.10.10.74...
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-03-20 09:58 MDT
Nmap scan report for 10.10.10.74
Host is up (0.28s latency).

PORT      STATE SERVICE      VERSION
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds Windows 7 Professional 7601 Service Pack 1 microsoft-ds (workgroup: WORKGROUP)
9255/tcp  open  http         AChat chat system httpd
|_http-title: Site doesn't have a title.
|_http-server-header: AChat
9256/tcp  open  achat        AChat chat system
49152/tcp open  msrpc        Microsoft Windows RPC
49153/tcp open  msrpc        Microsoft Windows RPC
49154/tcp open  msrpc        Microsoft Windows RPC
49155/tcp open  msrpc        Microsoft Windows RPC
49156/tcp open  msrpc        Microsoft Windows RPC
49157/tcp open  msrpc        Microsoft Windows RPC
Service Info: Host: CHATTERBOX; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb-os-discovery: 
|   OS: Windows 7 Professional 7601 Service Pack 1 (Windows 7 Professional 6.1)
|   OS CPE: cpe:/o:microsoft:windows_7::sp1:professional
|   Computer name: Chatterbox
|   NetBIOS computer name: CHATTERBOX\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2025-03-20T16:59:55-04:00
| smb2-security-mode: 
|   2:1:0: 
|_    Message signing enabled but not required
|_clock-skew: mean: 6h20m00s, deviation: 2h18m36s, median: 4h59m59s
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-time: 
|   date: 2025-03-20T20:59:56
|_  start_date: 2025-03-20T20:54:21

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 83.28 seconds
```

On port 9255, 9256, "AChat" service is running which needs some study.

### smb(139,445)

```bash
┌──(kali㉿kali)-[~/htb/chatterbox]
└─$ smbclient -L 10.10.10.74                       
Password for [WORKGROUP\kali]:
Anonymous login successful

        Sharename       Type      Comment
        ---------       ----      -------
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.10.10.74 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```

It doesn't list any share.
I don't think I can do much things to do without valid credential.

### AChat(9255, 9256)

> It requires Windows VM to run AChat client.
> Let's visit it later.