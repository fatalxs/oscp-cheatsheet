
```shell
# Nmap 7.95 scan initiated Sat Feb  8 09:58:03 2025 as: /usr/lib/nmap/nmap --privileged -p- -A -oN nmap_95.txt 192.168.197.95
Nmap scan report for 192.168.197.95
Host is up (0.017s latency).
Not shown: 65511 closed tcp ports (reset)
PORT      STATE SERVICE         VERSION
135/tcp   open  msrpc           Microsoft Windows RPC
139/tcp   open  netbios-ssn     Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
5001/tcp  open  commplex-link?
| fingerprint-strings: 
|   SIPOptions: 
|     HTTP/1.1 200 OK
|     Content-Type: text/html; charset=ISO-8859-1
|     Content-Length: 132
|_    MAINSERVER_RESPONSE:<serverinfo method="setserverinfo" mainserver="5001" webserver="44444" pxyname="192.168.45.221" startpage=""/>
5040/tcp  open  unknown
5985/tcp  open  http            Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
7680/tcp  open  pando-pub?
8443/tcp  open  ssl/https-alt   AppManager
|_ssl-date: 2025-02-08T02:02:47+00:00; 0s from scanner time.
|_http-title: Site doesn't have a title (text/plain;charset=ISO-8859-1).
|_http-server-header: AppManager
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.1 404 
|     Set-Cookie: JSESSIONID_APM_44444=3AFBCC534262249BD31B7DD8BD195497; Path=/; Secure; HttpOnly
|     Content-Type: text/html;charset=UTF-8
|     Content-Length: 973
|     Date: Sat, 08 Feb 2025 01:58:31 GMT
|     Connection: close
|     Server: AppManager
|     <!DOCTYPE html>
|     <meta http-equiv="X-UA-Compatible" content="IE=edge">
|     <html>
|     <head>
|     <title>Applications Manager</title>
|     <link REL="SHORTCUT ICON" HREF="/favicon.ico">
|     <!-- Includes commonstyle CSS and dynamic style sheet bases on user selection -->
|     <link href="/images/commonstyle.css?rev=14440" rel="stylesheet" type="text/css">
|     <link href="/images/newUI/newCommonstyle.css?rev=14260" rel="stylesheet" type="text/css">
|     <link href="/images/Grey/style.css?rev=14030" rel="stylesheet" type="text/css">
|     <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1">
|     </head>
|     <body bgcolor="#FFFFFF" leftmarg
|   GetRequest: 
|     HTTP/1.1 200 
|     Set-Cookie: JSESSIONID_APM_44444=CB4E940B20295D17889A53DB1DA320AF; Path=/; Secure; HttpOnly
|     Accept-Ranges: bytes
|     ETag: W/"261-1591621693000"
|     Last-Modified: Mon, 08 Jun 2020 13:08:13 GMT
|     Content-Type: text/html
|     Content-Length: 261
|     Date: Sat, 08 Feb 2025 01:58:31 GMT
|     Connection: close
|     Server: AppManager
|     <!-- $Id$ -->
|     <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">
|     <html>
|     <head>
|     <!-- This comment is for Instant Gratification to work applications.do -->
|     <script>
|     window.open("/webclient/common/jsp/home.jsp", "_top");
|     </script>
|     </head>
|     </html>
|   HTTPOptions: 
|     HTTP/1.1 403 
|     Set-Cookie: JSESSIONID_APM_44444=57D5FDDD2001D951FC8F4031D606DF8F; Path=/; Secure; HttpOnly
|     Cache-Control: private
|     Expires: Thu, 01 Jan 1970 00:00:00 GMT
|     Content-Type: text/html;charset=UTF-8
|     Content-Length: 1810
|     Date: Sat, 08 Feb 2025 01:58:31 GMT
|     Connection: close
|     Server: AppManager
|     <meta http-equiv="X-UA-Compatible" content="IE=edge">
|     <meta http-equiv="Content-Type" content="UTF-8">
|     <!--$Id$-->
|     <html>
|     <head>
|     <title>Applications Manager</title>
|     <link REL="SHORTCUT ICON" HREF="/favicon.ico">
|     </head>
|     <body style="background-color:#fff;">
|     <style type="text/css">
|     #container-error
|     border:1px solid #c1c1c1;
|     background: #fff; font:11px Arial, Helvetica, sans-serif; width:90%; margin:80px;
|     #header-error
|     background: #ededed; line-height:18px;
|     padding: 15px; color:#000; font-size:8px;
|     #header-error h1
|_    margin: 0; color:#000;
| ssl-cert: Subject: commonName=APPLICATIONSMANAGER/organizationName=WebNMS/stateOrProvinceName=Pleasanton/countryName=US
| Not valid before: 2019-02-27T11:03:03
|_Not valid after:  2050-02-27T11:03:03
12000/tcp open  cce4x?
| fingerprint-strings: 
|   Kerberos, SMBProgNeg: 
|_    RECONNECT
44444/tcp open  cognex-dataman?
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 200 
|     Set-Cookie: JSESSIONID_APM_44444=ABCF0F5D32B193E6F8309302F076869A; Path=/; HttpOnly
|     Accept-Ranges: bytes
|     ETag: W/"261-1591621693000"
|     Last-Modified: Mon, 08 Jun 2020 13:08:13 GMT
|     Content-Type: text/html
|     Content-Length: 261
|     Date: Sat, 08 Feb 2025 01:58:30 GMT
|     Connection: close
|     Server: AppManager
|     <!-- $Id$ -->
|     <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">
|     <html>
|     <head>
|     <!-- This comment is for Instant Gratification to work applications.do -->
|     <script>
|     window.open("/webclient/common/jsp/home.jsp", "_top");
|     </script>
|     </head>
|     </html>
|   HTTPOptions: 
|     HTTP/1.1 403 
|     Set-Cookie: JSESSIONID_APM_44444=59B92462073583EDE85748ABF6BBC5C3; Path=/; HttpOnly
|     Cache-Control: private
|     Expires: Thu, 01 Jan 1970 00:00:00 GMT
|     Content-Type: text/html;charset=UTF-8
|     Content-Length: 1810
|     Date: Sat, 08 Feb 2025 01:58:30 GMT
|     Connection: close
|     Server: AppManager
|     <meta http-equiv="X-UA-Compatible" content="IE=edge">
|     <meta http-equiv="Content-Type" content="UTF-8">
|     <!--$Id$-->
|     <html>
|     <head>
|     <title>Applications Manager</title>
|     <link REL="SHORTCUT ICON" HREF="/favicon.ico">
|     </head>
|     <body style="background-color:#fff;">
|     <style type="text/css">
|     #container-error
|     border:1px solid #c1c1c1;
|     background: #fff; font:11px Arial, Helvetica, sans-serif; width:90%; margin:80px;
|     #header-error
|     background: #ededed; line-height:18px;
|     padding: 15px; color:#000; font-size:8px;
|     #header-error h1
|     margin: 0; color:#000;
|     font-
|   RTSPRequest: 
|     HTTP/1.1 505 
|     vary: accept-encoding
|     Content-Type: text/html;charset=utf-8
|     Content-Language: en
|     Content-Length: 2142
|     Date: Sat, 08 Feb 2025 01:58:30 GMT
|     Server: AppManager
|     <!doctype html><html lang="en"><head><title>HTTP Status 505 
|_    HTTP Version Not Supported</title><style type="text/css">h1 {font-family:Tahoma,Arial,sans-serif;color:white;background-color:#525D76;font-size:22px;} h2 {font-family:Tahoma,Arial,sans-serif;color:white;background-color:#525D76;font-size:16px;} h3 {font-family:Tahoma,Arial,sans-serif;color:white;background-color:#525D76;font-size:14px;} body {font-family:Tahoma,Arial,sans-serif;color:black;background-color:white;} b {font-family:Tahoma,Arial,sans-serif;color:white;background-color:#525D76;} p {font-family:Tahoma,Arial,sans-serif;background:white;color:black;font-size:12px;} a {color:black;} a.name {color:black;} .line {height:1px;background-color:#
47001/tcp open  http            Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc           Microsoft Windows RPC
49665/tcp open  msrpc           Microsoft Windows RPC
49666/tcp open  msrpc           Microsoft Windows RPC
49667/tcp open  msrpc           Microsoft Windows RPC
49668/tcp open  msrpc           Microsoft Windows RPC
49669/tcp open  msrpc           Microsoft Windows RPC
49670/tcp open  msrpc           Microsoft Windows RPC
49671/tcp open  msrpc           Microsoft Windows RPC
49672/tcp open  tcpwrapped
57297/tcp open  java-rmi        Java RMI
57323/tcp open  unknown
62662/tcp open  unknown
| fingerprint-strings: 
|   Kerberos, SMBProgNeg, X11Probe: 
|_    CLOSE_SESSION
62663/tcp open  unknown
| fingerprint-strings: 
|   Kerberos, SMBProgNeg, X11Probe: 
|_    CLOSE_SESSION

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2025-02-08T02:01:08
|_  start_date: N/A
```
