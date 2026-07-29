# DC01 Setup

## Overview

DC01 is a Windows Server 2022 domain controller for `lab.local`. It sits exclusively on the AD segment and is unreachable directly from the attacker — only accessible via WIN11's second NIC. The domain is intentionally seeded with five realistic misconfigurations covering the most common Active Directory attack techniques.

---

## Specs

| Property | Value |
|---|---|
| OS | Windows Server 2022 Evaluation |
| RAM | 3GB |
| Disk | 60GB |
| IP | 192.168.56.10 (static) |
| DNS | 127.0.0.1 (self) |
| Domain | lab.local |
| NetBIOS | LAB |
| Computer name | DC01 |

---

## Domain Setup

AD DS role installed and forest promoted via PowerShell:

```powershell
Install-WindowsFeature AD-Domain-Services -IncludeManagementTools

Install-ADDSForest `
  -DomainName "lab.local" `
  -DomainNetbiosName "LAB" `
  -InstallDNS `
  -CreateDnsDelegation:$false `
  -DatabasePath "C:\Windows\NTDS" `
  -LogPath "C:\Windows\NTDS" `
  -SysvolPath "C:\Windows\SYSVOL" `
  -Force:$true
```

---

## Domain Users

| Username | Password | Notes |
|---|---|---|
| Administrator | (set during setup) | Domain Admin |
| svc_sql | Summer2024! | Kerberoastable service account |
| svc_backup | Backup2024! | AS-REP roastable account |
| jdoe | Password123! | Low-priv domain user, password in Description field |

---

## Misconfigurations Seeded

### T1558.003 — Kerberoasting

`svc_sql` has a Service Principal Name (SPN) set and uses a weak, crackable password:

```powershell
New-ADUser -Name "svc_sql" -SamAccountName "svc_sql" `
  -AccountPassword (ConvertTo-SecureString "Summer2024!" -AsPlainText -Force) `
  -Enabled $true -PasswordNeverExpires $true

Set-ADUser -Identity svc_sql `
  -ServicePrincipalNames @{Add="MSSQLSvc/dc01.lab.local:1433"}
```

Any authenticated domain user can request a TGS for `svc_sql` and crack it offline.

---

### T1558.004 — AS-REP Roasting

`svc_backup` has Kerberos pre-authentication disabled:

```powershell
New-ADUser -Name "svc_backup" -SamAccountName "svc_backup" `
  -AccountPassword (ConvertTo-SecureString "Backup2024!" -AsPlainText -Force) `
  -Enabled $true -PasswordNeverExpires $true

Set-ADAccountControl -Identity svc_backup -DoesNotRequirePreAuth $true
```

An AS-REP hash is requestable without any credentials and crackable offline.

---

### T1552 — Credentials In AD Description Field

`jdoe`'s account has the password stored in the Description attribute, readable by any domain user:

```powershell
New-ADUser -Name "jdoe" -SamAccountName "jdoe" `
  -AccountPassword (ConvertTo-SecureString "Password123!" -AsPlainText -Force) `
  -Enabled $true `
  -Description "Temp password: Password123!"
```

Discoverable via:
```powershell
Get-ADUser -Filter * -Properties Description | Select Name, Description
```

---

### T1098 — ACL Abuse (GenericAll)

`jdoe` has `GenericAll` rights over `svc_backup`, allowing full account takeover (password reset, SPN modification, etc.):

```powershell
$acl = Get-Acl "AD:\$((Get-ADUser svc_backup).DistinguishedName)"
$sid = New-Object System.Security.Principal.SecurityIdentifier((Get-ADUser jdoe).SID)
$ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
  $sid,
  [System.DirectoryServices.ActiveDirectoryRights]::GenericAll,
  [System.Security.AccessControl.AccessControlType]::Allow,
  [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None
)
$acl.AddAccessRule($ace)
Set-Acl -Path "AD:\$((Get-ADUser svc_backup).DistinguishedName)" -AclObject $acl
```

Discoverable via BloodHound as a `GenericAll` edge from `jdoe` to `svc_backup`.

---

### T1003.006 — DCSync

`jdoe` has both DCSync extended rights on the domain object:
- `1131f6aa` — Replicating Directory Changes
- `1131f6ab` — Replicating Directory Changes All

This allows `jdoe` to replicate all password hashes from DC01 using `impacket-secretsdump`, without needing to be a Domain Admin:

```bash
impacket-secretsdump lab.local/jdoe:Password123!@192.168.56.10
```

---

## Intended Attack Chain Against DC01

```
Gain jdoe credentials (via WIN11 LSASS dump or db.config)
 │
 ├─► Enumerate AD → find Description password, SPNs, AS-REP accounts
 │
 ├─► Kerberoast svc_sql → crack hash → Summer2024!
 │
 ├─► AS-REP roast svc_backup → crack hash → Backup2024!
 │
 ├─► Abuse GenericAll → reset svc_backup password → take over account
 │
 └─► DCSync as jdoe → dump all domain hashes including krbtgt + Administrator
      └─► Pass-the-Hash as Administrator → SYSTEM on DC01
```

---

## Verification Commands

```powershell
# Kerberoastable accounts
Get-ADUser -Filter * -Properties ServicePrincipalNames |
  Where-Object {$_.ServicePrincipalNames} |
  Select Name, ServicePrincipalNames

# AS-REP roastable accounts
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} |
  Select Name, SamAccountName

# Description field passwords
Get-ADUser jdoe -Properties Description | Select Name, Description

# GenericAll ACL
(Get-Acl "AD:\$((Get-ADUser svc_backup).DistinguishedName)").Access |
  Where-Object {$_.IdentityReference -like "*jdoe*"} | Format-List

# DCSync rights
(Get-Acl "AD:\$((Get-ADDomain).DistinguishedName)").Access |
  Where-Object {$_.IdentityReference -like "*jdoe*"} | Format-List
```
