# Pivoting — SSH Dynamic Port Forwarding through LNX

**ATT&CK Techniques:** T1090 · T1083

---

## Objective

Establish a pivot tunnel from Kali through the compromised LNX machine into the DMZ segment (`192.168.60.0/24`) to reach WIN11 (`192.168.60.20`), which is not directly accessible from Kali.

---

## Environment

| Property | Value |
|---|---|
| Attacker | Kali Linux — 10.8.0.2 (VPN tunnel IP) |
| Pivot host | LNX — 10.8.0.1 / 192.168.60.10 |
| Target | WIN11 — 192.168.60.20 (not directly reachable from Kali) |
| Method | SSH Dynamic Port Forwarding (SOCKS5 proxy) |

---

## Tools Used

- SSH (dynamic port forwarding)
- proxychains
- netcat (nc)
- xfreerdp

---

## Steps

### 1. Network Enumeration from LNX (T1083)

After gaining SSH access to LNX as `starboy`, enumerated network interfaces to identify connected segments:

```bash
ip a
ip route
```

**Key findings:**
- `ens33` → `192.168.254.129` (NAT, internet-facing)
- `ens37` → `192.168.60.10` (DMZ segment — internal network Kali cannot reach directly)
- `tun0` → `10.8.0.1` (OpenVPN server)
- `docker0` → `172.17.0.1` (Docker)

The `192.168.60.0/24` segment is a previously unknown internal network reachable only through LNX.

---

### 2. Host Discovery on the Internal Segment

Performed a ping sweep from LNX to discover live hosts on `192.168.60.0/24`:

```bash
for i in $(seq 1 254); do (ping -c 1 -W 1 192.168.60.$i &>/dev/null && echo "192.168.60.$i is up") & done; wait
```

**Output:**
```
192.168.60.10 is up
192.168.60.20 is up
```

Unknown host discovered at `192.168.60.20`.

---

### 3. Port Scan of 192.168.60.20 from LNX

Used netcat (no nmap available) to identify open ports:

```bash
for port in 21 22 80 135 139 443 445 3389 5985 8080; do
  nc -zw1 192.168.60.20 $port 2>/dev/null && echo "$port open"
done
```

**Output:**
```
3389 open
```

Port 3389 (RDP) open — strong indicator of a Windows machine.

---

### 4. SSH Dynamic Port Forwarding (T1090)

Established a SOCKS5 proxy through LNX using SSH dynamic port forwarding:

```bash
ssh -D 9050 -f -N starboy@10.8.0.1
```

- `-D 9050` — opens SOCKS5 proxy on Kali at `127.0.0.1:9050`
- `-f` — runs in background
- `-N` — no command, forwarding only

Enabled TCP forwarding on LNX (`/etc/ssh/sshd_config`):
```
AllowTcpForwarding yes
GatewayPorts yes
```

Added iptables forwarding rules on LNX:
```bash
iptables -A FORWARD -i tun0 -o ens37 -j ACCEPT
iptables -A FORWARD -i ens37 -o tun0 -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o ens37 -j MASQUERADE
```

Configured proxychains to use the SOCKS5 proxy:
```
# /etc/proxychains4.conf
socks5 127.0.0.1 9050
```

---

### 5. Verify Tunnel — RDP to WIN11

Confirmed tunnel working by connecting to WIN11 via RDP through proxychains:

```bash
proxychains xfreerdp /u:labuser /p:Welcome1 /v:192.168.60.20 2>/dev/null
```

RDP session established — tunnel confirmed working end to end.

---

## ATT&CK Mapping

| Technique ID | Name | Description |
|---|---|---|
| T1083 | File and Directory Discovery | Enumerated network interfaces and routes on LNX to identify hidden internal segment |
| T1090 | Proxy | SSH dynamic port forwarding established SOCKS5 proxy through LNX into DMZ segment |

---

## Key Takeaways

- After compromising a host, always run `ip a` and `ip route` — multi-homed machines reveal previously unknown network segments
- SSH dynamic port forwarding (`-D`) is one of the most reliable pivot techniques since it uses a protocol (SSH) that is almost always allowed outbound and requires no additional tooling on the pivot host
- nmap through SOCKS proxies is unreliable for raw port scanning — use netcat or application-layer tools (xfreerdp, crackmapexec, evil-winrm) instead for more accurate results
- proxychains works best with TCP application traffic — avoid using it with tools that rely on ICMP or UDP
