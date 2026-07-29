# Lab Architecture

## Overview

A three-machine Active Directory lab running on VMware Workstation with 16GB host RAM. The lab is intentionally segmented across two isolated virtual networks to simulate realistic network boundaries and force proper pivoting technique.

---

## Network Segments

| VMnet | Subnet | Type | Purpose |
|---|---|---|---|
| VMnet2 | 192.168.56.0/24 | Host-only | AD segment — internal corporate network |
| VMnet3 | 192.168.60.0/24 | Host-only | DMZ segment — between attacker and AD |
| VMnet8 | 192.168.254.0/24 | NAT | LNX internet-facing leg (VPN server) |

DHCP is disabled on all lab segments — all IPs are statically assigned.

---

## Machines

### LNX — 192.168.60.10
- OS: Debian 13 (Trixie), GUI desktop
- RAM: 1GB
- Role: External-facing foothold, OpenVPN VPN server, DMZ pivot point
- Network adapters:
  - ens33 → VMnet8 NAT (internet-facing, DHCP, ~192.168.254.x)
  - ens37 → VMnet3 DMZ (static, 192.168.60.10)
- Services: Apache/DVWA (port 80), OpenVPN (UDP 1194), SSH (port 22)

### WIN11 — 192.168.60.20 / 192.168.56.20
- OS: Windows 11 Enterprise Evaluation
- RAM: 3GB
- Role: Domain-joined workstation, dual-homed pivot point between DMZ and AD segment
- Network adapters:
  - NIC1 → VMnet3 DMZ (static, 192.168.60.20)
  - NIC2 → VMnet2 AD segment (static, 192.168.56.20)
- Services: RDP (3389), WinRM (5985), SMB (445)
- Domain: lab.local

### DC01 — 192.168.56.10
- OS: Windows Server 2022 Evaluation
- RAM: 3GB
- Role: Domain controller for lab.local
- Network adapters:
  - NIC1 → VMnet2 AD segment only (static, 192.168.56.10)
- Services: DNS, LDAP, Kerberos, SMB
- Domain: lab.local / LAB

---

## VPN Access

OpenVPN server runs on LNX (UDP 1194). VMware NAT port-forwards host port 1194 UDP to LNX's NAT IP (192.168.254.x). External clients connect via the host's LAN IP and get tunneled into the DMZ segment (192.168.60.0/24).

```
External Client (Kali)
 └─► host LAN IP:1194 (UDP)
      └─► VMware NAT port-forward
           └─► LNX:1194 (OpenVPN server)
                └─► routed into 192.168.60.0/24
```

---

## Design Rationale

- **Kali cannot reach DC01 directly** — it only gets a VPN IP in the DMZ segment range. Reaching DC01 requires compromising LNX first, then pivoting through WIN11 (which has a NIC on both segments).
- **WIN11 is the only dual-homed host** — it is the natural pivot point in the attack chain, mirroring how real environments often have a workstation sitting between a DMZ and an internal network.
- **DC01 is isolated on its own segment** — only reachable from WIN11 or other hosts on VMnet2, never directly from the attacker.
- **DHCP disabled** — static IPs throughout for predictable DNS resolution and stable AD communication.
