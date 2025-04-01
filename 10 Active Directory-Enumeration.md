
| [[10 Active Directory-Enumeration#Manual Enumeration\|Manual Enumeration]] | [[10 Active Directory-Enumeration#Automated Enumeration\|Automated Enumeration]] | [[10 Active Directory-Enumeration#BloodHound Raw Queries\|BloodHound Raw Queries]] |
| ----------------------------------------------------------------------- | ----------------------------------------------------------------------------- | ------------------------------------------------------------------------------- |
## Manual Enumeration
```shell
# Domain User & Group Enumeration
C:\Users\stephanie> net user /domain # list users in domain
C:\Users\stephanie> net user jeffadmin /domain # inspect specific user
C:\Users\stephanie> net group /domain # list groups in domain

# User & Group Enumeration with PowerView
PS C:\Users\stephanie> powershell -ep bypass
PS C:\Users\stephanie> Import-Module .\PowerView.ps1 # load powerview into memory
PS C:\Users\stephanie> Get-NetDomain # view basic info about domain
PS C:\Users\stephanie> Get-NetUser | select cn # list all users in domain
PS C:\Users\stephanie> Get-NetUser jeffadmin # inspect specific user
PS C:\Users\stephanie> Get-NetGroup | select cn # enumerate groups
PS C:\Users\stephanie> Get-NetGroup "Sales Department" | select member # view members in group

# OS Enumeration
PS C:\Users\stephanie> Get-NetComputer # view all properties
PS C:\Users\stephanie> Get-NetComputer | select cn,operatingsystem,dnshostname # OS and DNS hostname only

# Permissions and Logged Users Enumeration
PS C:\Users\stephanie> Find-LocalAdminAccess # find out which machine where the current user is local admin
PS C:\Users\stephanie> Get-NetSession -ComputerName files04 -Verbose # find logged in users
# If access is denied, may not have permissions

# Use PSLoggedon.exe from SysInternalsSuite
PS C:\Users\stephanie> .\PsLoggedon.exe \\client74 # view logged on users
# User credentials are stored in memory upon login!!

# Enumerating Service Principal Names
PS C:\Users\stephanie> setspn -L iis_service # enumerate SPNs in the domain
PS C:\Users\stephanie> Get-NetUser -SPN | select samaccountname,serviceprincipalname # enumerate SPNs using powerview

# Enumerating Object Permissions
PS C:\Users\stephanie> Get-ObjectAcl -Identity stephanie # enumerate access control entries on user with powerview, focus on Object SID, ADRights and SID
PS C:\Users\stephanie> Convert-SidToName <SID> # convert SID to domain object name
PS C:\Users\stephanie> Get-ObjectAcl -Identity "Management Department" | ? {$_.ActiveDirectoryRights -eq "GenericAll"} | select SecurityIdentifier,ActiveDirectoryRights # list SIDs with GenericAll permissions
PS C:\Users\stephanie> "<SID>","<SID>"... | Convert-SidToName # convert all SIDs to Object Names
PS C:\Users\stephanie> net group "Management Department" stephanie /add /domain # test object permissions by adding current user to group

# Enumerating Domain Shares
PS C:\Users\stephanie> Find-DomainShare (-CheckShareAccess) # find shares in the domain using powerview, with flag only displays shares available to us
# Can try to just ls the share e.g.:
PS C:\Users\stephanie> ls \\dc1.corp.com\sysvol\corp.com\
```
## Automated Enumeration
```shell
# Import SharpHound PowerShell script into memory (after transfer)
PS C:\Users\stephanie> powershell -ep bypass
PS C:\Users\stephanie> Import-Module .\Sharphound.ps1

# Run Sharphound to collect all data (RUN MULTIPLE TIMES)
PS C:\Users\stephanie> Invoke-BloodHound -CollectionMethod All -OutputDirectory C:\Users\stephanie\Desktop -Outputprefix "audit"

# Start neo4j graphing service on Kali
kali@kali:~$ sudo neo4j start
# creds is neo4j:kali

# Run BloodHound after neo4j server is up
kali@kali:~$ bloodhound
# Mark compromised users/machines as Owned Principals
# Usually just Find Shortest Path to Domain Admins
# Remember to look at user permissions if have GenericAll against other user accounts
```
## BloodHound Raw Queries
```cypher
// Displays all computers
MATCH (m:Computer) RETURN m

// Display all users
MATCH (u:User) RETURN u

// View all active sessions
MATCH p = (c:Computer)-[:HasSession]->(m:User) RETURN p
```