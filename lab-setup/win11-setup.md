# WIN11 Setup

## Overview

WIN11 is a domain-joined Windows 11 Enterprise workstation serving as the dual-homed pivot point between the DMZ segment and the AD segment. It contains a low-privilege local user as the initial foothold target, multiple privilege escalation paths, and cached domain credentials for the post-escalation AD attack phase.

---

## Specs

| Property | Value |
|---|---|
| OS | Windows 11 Enterprise Evaluation |
| RAM | 3GB |
| Disk | 60GB |
| IP (DMZ) | 192.168.60.20 (NIC1, static) |
| IP (AD) | 192.168.56.20 (NIC2, static) |
| Domain | lab.local |
| Computer name | WIN11 |

---

## Network Configuration

Two network adapters:
- **NIC1** → VMnet3 DMZ (`192.168.60.20`) — reachable from LNX and VPN clients
- **NIC2** → VMnet2 AD segment (`192.168.56.20`) — reaches DC01 directly

IP forwarding enabled:
```powershell
Set-NetIPInterface -Forwarding Enabled
```

SMB enumeration loosened (intentional misconfiguration):
```powershell
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RestrictAnonymous /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RestrictAnonymousSAM /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
```

---

## Services

| Service | Port | Status |
|---|---|---|
| RDP | 3389 | Enabled |
| WinRM | 5985 | Enabled |
| SMB | 445 | Enabled |

RDP enabled:
```powershell
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name "fDenyTSConnections" -Value 0
Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
```

WinRM enabled:
```powershell
Enable-PSRemoting -Force
Set-Item WSMan:\localhost\Client\TrustedHosts -Value "*" -Force
```

---

## Users

| Username | Password | Group | Notes |
|---|---|---|---|
| localadmin | (set during OOBE) | Administrators | Default setup account |
| starboy | Str0ngP@ss99! | Administrators | Local account, different password from LNX (intentional) |
| labuser | Welcome1 | Users, Remote Desktop Users | Low-priv initial foothold target |

`labuser` is deliberately NOT in the Administrators group. `Welcome1` exists in rockyou.txt for brute-force practice.

---

## Domain

WIN11 is joined to `lab.local`. Domain Admins group is automatically a member of local Administrators (default Windows behavior).

`jdoe` (domain user) logged in once via `runas` to cache credentials in LSASS:
```powershell
runas /user:LAB\jdoe cmd
```

---

## Vulnerabilities Seeded

### Initial Access (from attacker's perspective via pivot through LNX)

**T1110 — Brute Force (RDP)**
`labuser:Welcome1` is brute-forceable via Hydra against RDP (port 3389):
```bash
proxychains hydra -l labuser -P /usr/share/wordlists/rockyou.txt rdp://192.168.60.20 -t 4
```

**T1087 — Account Discovery (SMB)**
SMB enumeration reveals local usernames due to loosened RestrictAnonymous settings:
```bash
proxychains crackmapexec smb 192.168.60.20 --users
```

### Privilege Escalation

**T1548.002 — AlwaysInstallElevated**
Both registry keys set, allowing any user to install MSI packages as SYSTEM:
```
HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer → AlwaysInstallElevated = 1
HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer → AlwaysInstallElevated = 1
```

**T1574.009 — Unquoted Service Path**
`LabBackup` service binary path is unquoted and contains spaces:
```
C:\Program Files\Lab Tools\Backup Service\service.exe
```
`labuser` has full write access to `C:\Program Files\Lab Tools\`, allowing binary planting.

**T1574.011 — Weak Service Permissions**
`LabUpdate` service has a permissive DACL granting world-writable permissions, allowing `labuser` to modify the service binary path.

### Post-Escalation Credential Discovery

**T1003.001 — LSASS Memory**
`jdoe` (domain user) has a cached session in LSASS. Mimikatz run as local admin/SYSTEM will extract the NTLM hash or cleartext password:
```
sekurlsa::logonpasswords
```

**T1552.001 — Credentials In Files**
`db.config` at `C:\inetpub\wwwroot\config\db.config` contains jdoe's credentials in plaintext:
```ini
[Database]
server=dc01.lab.local
username=jdoe
password=Password123!
domain=lab.local
```
Readable by `labuser`.

---

## Flags

| Flag | Path | Readable by |
|---|---|---|
| user.txt | C:\Users\labuser\Desktop\user.txt | labuser |
| admin.txt | C:\Users\Administrator\Desktop\admin.txt | Administrators only |
