---
tags: 
group: EnterpriseNetwork
---
![](https://app.hackthebox.com/images/icons/ic-prolabs/ic-dante-overview.svg)

- Machine : https://app.hackthebox.com/prolabs/dante


# Summary

### Credentials

| Idx | Int/Ext | User      | Password                    | Type  | Where to find | Where to use | Link                                                  |
| --- | ------- | --------- | --------------------------- | ----- | ------------- | ------------ | ----------------------------------------------------- |
| 1   | Ext     | james     | Toyota                      | plain | NIX01         | Wordpress    | [Link](DANTE.md#Find%20credential%20using%20`wpscan`) |
| 2   | Ext     | shaun     | password                    | plain | NIX01         | mysql        | [Link](DANTE.md#Find%20DB%20Credential)               |
| 3   | Ext     | balthazar | TheJoker12345!              | plain | NIX01         | mysql, ssh   |                                                       |
| 4   | Int     | margaret  | Welcome1!2@3#               | plain | NIX02         | ssh          |                                                       |
| 5   | Int     | frank     | TractorHeadtorchDeskmat     | plain | NIX02         | ssh          |                                                       |
| 6   | Int     | admin     | admin                       | plain | NIX04         | blog         |                                                       |
| 7   | Int     | ben       | Welcometomyblog             | plain | NIX04         | blog, ssh    |                                                       |
| 8   | Int     | admin     | password6543                | plain | NIX03         | Webmin       |                                                       |
| 9   | Int     | xadmin    | Peacemaker!                 | plain | DC01          | ssh          |                                                       |
| 10  | Int     | katwamba  | DishonestSupermanDiablo5679 | plain | DC01          | ssh          |                                                       |
|     |         |           |                             |       |               |              |                                                       |
|     |         |           |                             |       |               |              |                                                       |
|     |         |           |                             |       |               |              |                                                       |


### Target overview

| Idx | Host       | Status | Vuln                                                                                                                                                                                                            | Link                                                  |
| --- | ---------- | ------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------- |
| 1   | NIX01(100) | Owned  | - Wordpress Login brute forcing to find credential<br>- Wordpress Plugin to open a reverse shell<br>- Find credential in command line from `.bash_history`<br>- (privesc#1) PwnKit<br>- (privesc#2) SUID `find` | [Link](DANTE.md#Shell%20as%20`www-data`%20on%20NIX01) |
| 2   | SQL01(5)   | Pass   | - Just identified services                                                                                                                                                                                      | [Link](DANTE.md#172.16.1.5(SQL01))                    |
| 3   | NIX02(10)  | Owned  | - LFI to read `wp-config.php`<br>- Exploiting `vim` to escape from restricted shell<br>- Retrieve `Slack` exported data to obtain credential<br>- Python library Injection                                      | [Link](DANTE.md#172.16.1.10(NIX02))                   |
| 4   | NIX04(12)  | Owned  | - SQL Injection on Responsive Online Blog<br>- Exploit outdated `sudo`(1.8.27)                                                                                                                                  | [Link](DANTE.md#172.16.1.12(NIX04))                   |
| 5   | WS01(13)   | User   | - Obtain credential from `sql` file<br>- Exploit File Upload vulnerability in Sign-up page                                                                                                                      | [Link](DANTE.md#172.16.1.13(WS01))                    |
| 6   | NIX03(17)  | Owned  | - Webmin 1.900 Package Update exploit                                                                                                                                                                           | [Link](DANTE.md#172.16.1.17(NIX03))                   |
| 7   | ???(19)    | Pass   | - No valid credential yet...                                                                                                                                                                                    |                                                       |
|     |            |        |                                                                                                                                                                                                                 |                                                       |
|     |            |        |                                                                                                                                                                                                                 |                                                       |


### Vulnerability



---

### Details
- [External Penetration Testing](Details/External%20Penetration%20Testing.md)
- [Shell as www-data on NIX01](Details/Shell%20as%20www-data%20on%20NIX01.md)
- [172.16.1.100(NIX01)](Details/172.16.1.100(NIX01).md)
- [Pivotting](Details/Pivotting.md)
- [Internal Penetration Testing](Details/Internal%20Penetration%20Testing.md)
- [172.16.1.1(FW)](Details/172.16.1.1(FW).md)
- [172.16.1.5(SQL01)](Details/172.16.1.5(SQL01).md)
- [172.16.1.10(NIX02)](Details/172.16.1.10(NIX02).md)
- [172.16.1.12(NIX04)](Details/172.16.1.12(NIX04).md)
- [172.16.1.13(WS01)](Details/172.16.1.13(WS01).md)
- [172.16.1.17(NIX03)](Details/172.16.1.17(NIX03).md)
- [172.16.1.19](Details/172.16.1.19.md)
- [172.16.1.101(WS02)](Details/172.16.1.101(WS02).md)
- [172.16.1.20(DC01)](Details/172.16.1.20(DC01).md)


# 172.16.1.102(WS03)

### Reconnaissance

##### Port Scanning

```bash
┌──(kali㉿kali)-[~/htb/WS02]
└─$ nmap -Pn -sCV 172.16.1.102
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-07 07:53 EST
Nmap scan report for 172.16.1.102
Host is up (0.13s latency).
Not shown: 993 closed tcp ports (conn-refused)
PORT     STATE SERVICE       VERSION
80/tcp   open  http          Apache httpd 2.4.54 ((Win64) OpenSSL/1.1.1p PHP/7.4.0)
|_http-server-header: Apache/2.4.54 (Win64) OpenSSL/1.1.1p PHP/7.4.0
|_http-title: Dante Marriage Registration System :: Home Page
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
443/tcp  open  ssl/http      Apache httpd 2.4.54 ((Win64) OpenSSL/1.1.1p PHP/7.4.0)
| tls-alpn: 
|   h2
|_  http/1.1
|_ssl-date: TLS randomness does not represent time
|_http-title: Dante Marriage Registration System :: Home Page
| ssl-cert: Subject: commonName=localhost/organizationName=TESTING CERTIFICATE
| Subject Alternative Name: DNS:localhost
| Not valid before: 2022-06-24T01:07:25
|_Not valid after:  2022-12-24T01:07:25
|_http-server-header: Apache/2.4.54 (Win64) OpenSSL/1.1.1p PHP/7.4.0
445/tcp  open  microsoft-ds?
3306/tcp open  tcpwrapped
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| ssl-cert: Subject: commonName=DANTE-WS03
| Not valid before: 2025-01-06T03:28:04
|_Not valid after:  2025-07-08T03:28:04
| rdp-ntlm-info: 
|   Target_Name: DANTE-WS03
|   NetBIOS_Domain_Name: DANTE-WS03
|   NetBIOS_Computer_Name: DANTE-WS03
|   DNS_Domain_Name: DANTE-WS03
|   DNS_Computer_Name: DANTE-WS03
|   Product_Version: 10.0.19041
|_  System_Time: 2025-01-07T12:54:21+00:00
|_ssl-date: 2025-01-07T12:54:32+00:00; +26s from scanner time.
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2025-01-07T12:54:21
|_  start_date: N/A
|_nbstat: NetBIOS name: DANTE-WS03, NetBIOS user: <unknown>, NetBIOS MAC: 00:50:56:94:c7:49 (VMware)
|_clock-skew: mean: 25s, deviation: 0s, median: 25s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 47.67 seconds
```

- http(80)/https(443) : Dante Marriage Registration System which might be existing application.
- rpc(135)
- smb(139,445)
- mysql(3306)
- rdp(3389)

##### http(80) / https(443)

![](attachments/dante_30.png)

I found a banner that it's running on "© 2020 Online Marriage Registration System".
Let me google if it has any vulnerability.
Luckily, I was able to find RCE exploit from exploit-db :
https://www.exploit-db.com/exploits/49557

