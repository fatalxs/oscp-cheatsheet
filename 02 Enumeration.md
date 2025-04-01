
| [[02 Enumeration#Port Scanning\|Port Scanning]] | [[02 Enumeration#DNS\|DNS]]   | [[02 Enumeration#SMB\|SMB]] | [[02 Enumeration#FTP\|FTP]] |
| ----------------------------------------------- | ----------------------------- | --------------------------- | --------------------------- |
| [[02 Enumeration#SMTP\| SMTP]]                  | [[02 Enumeration#SNMP\|SNMP]] |                             |                             |
## Port Scanning
```shell
# Use -Pn if you're getting nothing in scan
# Use -oG for greppable output

# Basic Nmap Scan
kali@kali:~$ nmap -sC -sV <IP> -v

# Complete Nmap Scan
kali@kali:~$ nmap -T4 -A -p- <IP> -v

# Complete UDP Scan
kali@kali:~$ sudo nmap -F -sU -sV 192.168.158.149 

# Running vuln category scripts
kali@kali:~$ sudo nmap -sV -p 443 --script "vuln" <IP>

# Nmap Scripting Engine
# Located in /usr/share/nmap/scripts
kali@kali:~$ updatedb
kali@kali:~$ locate .nse | grep <name>
kali@kali:~$ sudo nmap --script="name" <IP>

# PowerShell Port Scanning
PS C:\Users\offsec> Test-NetConnection -Port <port> <IP>

# Automated Port Scan (first 1024 ports)
1..1024 | % {echo ((New-Object Net.Sockets.TcpClient).Connect("IP", $_)) "TCP port $_ is open"} 2>$null
```
## DNS
```shell
# Can use SecLists wordlist for better enumeration
kali@kali:~$ host www.megacorpone.com

kali@kali:~$ host -t mx megacorpone.com # Mail Exchange Record
kali@kali:~$ host -t txt megacorpone.com # Text Record

# DNS Recon
kali@kali:~$ dnsrecon -d megacorpone.com -t std # Standard recon
kali@kali:~$ dnsrecon -d megacorpone.com -D ~/list.txt -t brt # Bruteforce
# -d for domain name, -D filename with subdomain strings

# DNS Enum
kali@kali:~$ dnsenum megacorpone.com # Bruteforce

# NSLookup
kali@kali:~$ nslookup mail.megacorptwo.com
kali@kali:~$ nslookup -type=TXT info.megacorptwo.com <DNS Server IP>
```
## SMB 
```shell
# Focus on ports 139, 445

# nbtscan
kali@kali:~$ sudo nbtscan -r 192.168.50.0/24 

# Nmap script
kali@kali:~$ nmap -v -p 139,445 --script smb-os-discovery <IP>

# Net View (Windows)
# /all to list administrative shares
C:\Users\offsec> net view \\<ComputerName/IP> /all

# Enum4Linux
# -U to get userlist and -O to get OS information
kali@kali:~$ enum4linux -U -o <IP>

# Crackmapexec
kali@kali:~$ crackmapexec smb <IP/Range>
kali@kali:~$ crackmapexec smb <IP> -u <username> -p <password>
kali@kali:~$ crackmapexec smb <IP> -u <username> -p <password> --shares # Lists all available shares
kali@kali:~$ crackmapexec smb <IP> -u <username> -p <password>--users # Lists users
kali@kali:~$ crackmapexec smb <IP> -u <username> -p <password> --all # All information
# Use -p for specific port, -d for specific domain
# Use -windows-auth for domain users if needed
# Use --local-auth for local accounts
# Use --continue-on-success to "spray"

#NetExec (better crackmapexec)
kali@kali:~$ nxc smb <ip> -u <username> -p <password>
# Can also use for WinRM, FTP, MSSQL, SSH
# Use --local-auth for local accounts
# Use --continue-on-success to "spray"

# SMBClient
kali@kali:~$ smbclient -L //<IP>
kali@kali:~$ smbclient //server/share (-U <username/domain>)

# SMBMap
kali@kali:~$ smbmap -H <IP> -u <username> -p <password> (-d <domain> -r <share_name>)

# If have read/write access on ADMIN$, can PsExec in
kali@kali:~$ impacket-psexec '<username>:<password>@<IP>'

smb> put <file> # Upload
smb> get <file> # Download
```
## FTP
```shell
# Init FTP connection
kali@kali:~$ ftp

# Login with anonymous:anonymous
ftp> USER anonymous
ftp> PASS anonymous

# List all files (incl. hidden)
ftp> ls -a

# Download all files from FTP
kali@kali:~$ wget -m ftp://anonymous:anonymous@<IP>

# NSE
kali@kali:~$ locate .nse | grep ftp
nmap -p21 --script=<name> <IP>

# Bruteforce
kali@kali:~$ hydra -L users.txt -P passwords.txt <IP> ftp
```
## SMTP
```shell
# Netcat (checks for version too)
kali@kali:~$ nc -nv <IP> 25

# Identify/Verify existing users
VRFY root
VRFY idontexist

# Script for user verifying
smtp-user-enum -M VRFY -U username.txt -t <IP>
smtp-user-enum -M VRFY -U /usr/share/wordlists/metasploit/namelist.txt -t <IP>
smtp-user-enum -M VRFY -D postfish.off -U username.txt -t <IP>

# Mostly used to send phishing email via swaks
sudo swaks -t daniela@beyond.com -t marcus@beyond.com --from john@beyond.com --attach @config.Library-ms --server 192.168.50.242 --body @body.txt --header "Subject: Staging Script" --suppress-data -ap
```
## SNMP
```shell
# Nmap UDP Scan
kali@kali:~$ sudo nmap <IP> -A -T4 -p- -sU -v

# SNMPCheck
kali@kali:~$ snmpcheck -t <IP> -c public

# Onesixtyone
kali@kali:~$ onesixtyone -c community -i ips
# community is a txt file with "public", "private", "manager"
# ips is a txt file with the target IPs

# Check for valid SNMP Strings
kali@kali:~$ hydra -P /usr/share/wordlists/SecLists/Discovery/SNMP/common-snmp-community-strings-onesixtyone.txt <IP> snmp
kali@kali:~$ sudo nmap -sU -p 161 --script snmp-brute 192.168.209.156 --script-args snmp-brute.communitiesdb=/usr/share/wordlists/SecLists/Discovery/SNMP/common-snmp-community-strings-onesixtyone.txt

# SNMPWalk
kali@kali:~$ snmpwalk -c public -v1 -t 10 <IP> # Displays the entire MIB tree
kali@kali:~$ snmpwalk -c public -v1 <IP> 1.3.6.1.4.1.77.1.2.25 #Windows User enumeration
kali@kali:~$ snmpwalk -c public -v1 <IP> 1.3.6.1.2.1.25.4.2.1.2 #Windows Processes enumeration
kali@kali:~$ snmpwalk -c public -v1 <IP> 1.3.6.1.2.1.25.6.3.1.2 #Installed software enumeraion
kali@kali:~$ snmpwalk -c public -v1 <IP> 1.3.6.1.2.1.6.13.1.3 #Opened TCP Ports

#Windows MIB values
1.3.6.1.2.1.25.1.6.0 - System Processes
1.3.6.1.2.1.25.4.2.1.2 - Running Programs
1.3.6.1.2.1.25.4.2.1.4 - Processes Path
1.3.6.1.2.1.25.2.3.1.4 - Storage Units
1.3.6.1.2.1.25.6.3.1.2 - Software Name
1.3.6.1.4.1.77.1.2.25 - User Accounts
1.3.6.1.2.1.6.13.1.3 - TCP Local Ports

# Extended SNMPWalk
kali@kali:~$ snmpwalk -v 2c -c public <IP> NET-SNMP-EXTEND-MIB::nsExtendOutputFull

# SNMPBulkWalk
kali@kali:~$ snmpbulkwalk -c public -v2c 192.168.209.156 .
# Try out other combinations if needed

```