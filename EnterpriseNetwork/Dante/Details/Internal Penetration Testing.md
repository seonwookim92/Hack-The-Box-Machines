### Ping Sweep

Let's find what hosts are existing in the network.

```bash
root@DANTE-WEB-NIX01:/var/www/html# 
*for i in {1..254}; do (ping -c 1 172.16.1.${i} | grep "bytes from" | grep -v "Unreachable" &); done;*

64 bytes from 172.16.1.5: icmp_seq=1 ttl=128 time=0.997 ms
64 bytes from 172.16.1.10: icmp_seq=1 ttl=64 time=0.423 ms
64 bytes from 172.16.1.12: icmp_seq=1 ttl=64 time=0.411 ms
64 bytes from 172.16.1.13: icmp_seq=1 ttl=128 time=0.548 ms
64 bytes from 172.16.1.17: icmp_seq=1 ttl=64 time=0.424 ms
64 bytes from 172.16.1.19: icmp_seq=1 ttl=64 time=0.402 ms
64 bytes from 172.16.1.20: icmp_seq=1 ttl=128 time=0.292 ms
64 bytes from 172.16.1.100: icmp_seq=1 ttl=64 time=0.014 ms
64 bytes from 172.16.1.101: icmp_seq=1 ttl=128 time=0.654 ms
64 bytes from 172.16.1.102: icmp_seq=1 ttl=128 time=0.460 ms
```

Except `NIX01` in 172.16.1.100, there are 9 hosts more.

Let me double check with `nmap` command.

```bash
┌──(kali㉿kali)-[~]
└─$ nmap -sn --disable-arp-ping 172.16.1.0/24
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-04 08:35 EST
Nmap scan report for 172.16.1.1
Host is up (0.26s latency).
Nmap scan report for 172.16.1.5
Host is up (0.38s latency).
Nmap scan report for 172.16.1.10
Host is up (0.26s latency).
Nmap scan report for 172.16.1.12
Host is up (0.41s latency).
Nmap scan report for 172.16.1.13
Host is up (0.25s latency).
Nmap scan report for 172.16.1.17
Host is up (0.38s latency).
Nmap scan report for 172.16.1.19
Host is up (0.18s latency).
Nmap scan report for 172.16.1.20
Host is up (0.18s latency).
Nmap scan report for 172.16.1.100
Host is up (0.25s latency).
Nmap scan report for 172.16.1.101
Host is up (0.25s latency).
Nmap scan report for 172.16.1.102
Host is up (0.30s latency).
Nmap done: 256 IP addresses (11 hosts up) scanned in 12.52 seconds
```

Only one host (172.16.1.1) is found additionally.
Given it's blocking ICMP packet, I guess this is a firewall.