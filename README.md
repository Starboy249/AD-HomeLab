# AD-HomeLab

A home Active Directory lab built on VMware Workstation to practice offensive security techniques mapped to the MITRE ATT&CK framework. Covers the full attack chain from initial access on a Linux foothold through network pivoting, Windows privilege escalation, and Active Directory compromise.

---

## Network Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                         ATTACKER                                  │
│                      Kali Linux                                   │
│                   192.168.1.150 (Home LAN)                       │
└───────────────────────────┬──────────────────────────────────────┘
                            │ OpenVPN (UDP 1194)
                            ▼
┌──────────────────────────────────────────────────────────────────┐
│                  INTERNET-FACING — VMnet8 NAT                    │
│                    192.168.254.0/24                               │
│                                                                   │
│   ┌───────────────────────────────────────────────────────────┐  │
│   │                    LNX (dual-homed)                       │  │
│   │         ens33 → 192.168.254.x (NAT, VPN server)          │  │
│   │         ens37 → 192.168.60.10 (DMZ)                      │  │
│   └───────────────────────────┬───────────────────────────────┘  │
└───────────────────────────────┼──────────────────────────────────┘
                                │ ens37
                                ▼
┌──────────────────────────────────────────────────────────────────┐
│                   DMZ SEGMENT — VMnet3                           │
│                    192.168.60.0/24                               │
│                                                                   │
│   ┌───────────────────────────────────────────────────────────┐  │
│   │                  WIN11 (dual-homed)                       │  │
│   │         NIC1 → 192.168.60.20 (DMZ)                       │  │
│   │         NIC2 → 192.168.56.20 (AD segment)                │  │
│   └───────────────────────────┬───────────────────────────────┘  │
└───────────────────────────────┼──────────────────────────────────┘
                                │ NIC2
                                ▼
┌──────────────────────────────────────────────────────────────────┐
│                   AD SEGMENT — VMnet2                            │
│                    192.168.56.0/24                               │
│                                                                   │
│              ┌────────────────────────────┐                      │
│              │           DC01             │                      │
│              │      192.168.56.10         │                      │
│              │    Domain Controller       │                      │
│              │        lab.local           │                      │
│              └────────────────────────────┘                      │
└──────────────────────────────────────────────────────────────────┘
```

---

## Machines

| Host | OS | IP | Role |
|---|---|---|---|
| LNX | Debian 13 | 192.168.60.10 | External foothold, VPN server, pivot point |
| WIN11 | Windows 11 Enterprise | 192.168.60.20 / 192.168.56.20 | Dual-homed pivot, AD springboard |
| DC01 | Windows Server 2022 | 192.168.56.10 | Domain controller (lab.local) |

---

## Full Attack Chain

```
Kali
 └─► OpenVPN tunnel → LNX (192.168.60.10)
      ├─► DVWA File Upload → webshell (www-data)
      ├─► discover /opt/scripts/backup.sh → starboy:summer2024
      ├─► SSH as starboy → user flag
      └─► Privilege Escalation → root flag
           └─► Chisel SOCKS tunnel → DMZ segment
                └─► discover WIN11 (192.168.60.20)
                     ├─► RDP brute force / SMB enumeration → labuser
                     ├─► RDP in as labuser → user flag
                     └─► Privilege Escalation → local admin / SYSTEM → admin flag
                          ├─► Mimikatz → dump jdoe from LSASS
                          └─► find db.config → jdoe:Password123!
                               └─► domain foothold as jdoe
                                    ├─► Kerberoast svc_sql
                                    ├─► AS-REP roast svc_backup
                                    ├─► GenericAll → reset svc_backup password
                                    └─► DCSync → dump all domain hashes
                                         └─► Pass-the-Hash as Administrator
                                              └─► SYSTEM on DC01 → full domain compromise
```

---

## MITRE ATT&CK Technique Index

| Technique ID | Name | Phase | Writeup |
|---|---|---|---|
| T1190 | Exploit Public-Facing Application | Initial Access | [01-initial-access.md](writeups/01-initial-access.md) |
| T1552.001 | Credentials In Files | Credential Access | [01-initial-access.md](writeups/01-initial-access.md) |
| T1078 | Valid Accounts | Initial Access | [01-initial-access.md](writeups/01-initial-access.md) |
| T1548.001 | Setuid and Setgid | Privilege Escalation | [02-lnx-privesc.md](writeups/02-lnx-privesc.md) |
| T1053.003 | Cron | Privilege Escalation | [02-lnx-privesc.md](writeups/02-lnx-privesc.md) |
| T1548.003 | Sudo and Sudo Caching | Privilege Escalation | [02-lnx-privesc.md](writeups/02-lnx-privesc.md) |
| T1090 | Proxy (Chisel pivot) | Command and Control | [03-pivot.md](writeups/03-pivot.md) |
| T1110 | Brute Force | Credential Access | [04-win11-access.md](writeups/04-win11-access.md) |
| T1087 | Account Discovery | Discovery | [04-win11-access.md](writeups/04-win11-access.md) |
| T1548.002 | AlwaysInstallElevated | Privilege Escalation | [05-win11-privesc.md](writeups/05-win11-privesc.md) |
| T1574.009 | Unquoted Service Path | Privilege Escalation | [05-win11-privesc.md](writeups/05-win11-privesc.md) |
| T1574.011 | Services Registry Weak Permissions | Privilege Escalation | [05-win11-privesc.md](writeups/05-win11-privesc.md) |
| T1003.001 | LSASS Memory | Credential Access | [06-credential-access.md](writeups/06-credential-access.md) |
| T1558.003 | Kerberoasting | Credential Access | [06-credential-access.md](writeups/06-credential-access.md) |
| T1558.004 | AS-REP Roasting | Credential Access | [06-credential-access.md](writeups/06-credential-access.md) |
| T1098 | Account Manipulation (GenericAll) | Privilege Escalation | [07-ad-attack-chain.md](writeups/07-ad-attack-chain.md) |
| T1003.006 | DCSync | Credential Access | [07-ad-attack-chain.md](writeups/07-ad-attack-chain.md) |
| T1550.002 | Pass the Hash | Lateral Movement | [07-ad-attack-chain.md](writeups/07-ad-attack-chain.md) |

---

## Tools Used

| Tool | Purpose |
|---|---|
| Kali Linux | Attacker machine |
| VMware Workstation | Hypervisor |
| OpenVPN | Remote VPN access into lab |
| Nmap | Port scanning / host discovery |
| Hydra | RDP brute force |
| CrackMapExec | SMB enumeration and spraying |
| Chisel | SOCKS pivot tunnel |
| Impacket | Kerberoasting, AS-REP roasting, DCSync, PtH |
| Mimikatz | LSASS credential dumping |
| BloodHound / SharpHound | AD attack path visualization |
| WinPEAS / LinPEAS | Local privilege escalation enumeration |
| Hashcat | Offline hash cracking |

---

## Lab Setup Docs

- [Architecture](lab-setup/architecture.md)
- [LNX Setup](lab-setup/lnx-setup.md)
- [WIN11 Setup](lab-setup/win11-setup.md)
- [DC01 Setup](lab-setup/dc01-setup.md)


---

*Built for MITRE ATT&CK practice and portfolio development. All activity performed in an isolated lab environment.*
