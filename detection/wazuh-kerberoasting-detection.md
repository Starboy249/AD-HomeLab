# Detection Engineering: Kerberoasting (T1558.003)

**MITRE ATT&CK:** T1558.003 — Steal or Forge Kerberos Tickets: Kerberoasting  
**Detection stack:** Wazuh 4.7 · Sysmon (SwiftOnSecurity config) · Windows Audit Policy  
**Environment:** Active Directory home lab (lab.local)  
**Outcome:** Custom Wazuh rule firing on real Kerberoasting attempt with MITRE mapping

---

## Lab Architecture

| Host | Role | IP | OS |
|---|---|---|---|
| DC01 | Domain Controller | 192.168.56.10 | Windows Server 2022 |
| WIN11 | Domain workstation | 192.168.56.20 | Windows 11 Enterprise |
| LNX (Wazuh) | SIEM / detection server | 192.168.56.50 | Debian 13 |
| Kali | Attacker | 192.168.56.x | Kali Linux |

All machines on VMnet2 (192.168.56.0/24, isolated host-only network).

---

## Detection Stack Setup

### Wazuh All-in-One Install (on LNX)

```bash
curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh
sudo bash wazuh-install.sh -a
```

Services confirmed running:
- `wazuh-manager` — receives and processes agent logs
- `wazuh-indexer` — stores and indexes events (OpenSearch)
- `wazuh-dashboard` — web UI at `https://192.168.56.50`

### Wazuh Agents

Agents deployed on DC01 and WIN11 via the dashboard deploy wizard, pointing at `192.168.56.50`. Both confirmed **Active** in the dashboard.

### Sysmon (SwiftOnSecurity config)

Installed on DC01 and WIN11:

```powershell
# Download Sysmon and config
Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile "$env:TEMP\Sysmon.zip"
Expand-Archive "$env:TEMP\Sysmon.zip" -DestinationPath "$env:TEMP\Sysmon"
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml" -OutFile "$env:TEMP\sysmonconfig.xml"

# Install
.\Sysmon64.exe -accepteula -i $env:TEMP\sysmonconfig.xml
```

Wazuh agent configured to collect Sysmon events via eventchannel (`ossec.conf`):

```xml
<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```

### Windows Audit Policy — Kerberos Events

Enabled on DC01 to generate Event ID 4769 (Kerberos Service Ticket Request):

```powershell
auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:enable /failure:enable
```

---

## The Attack — Kerberoasting (T1558.003)

### What is Kerberoasting?

Any authenticated domain user can request a Kerberos Service Ticket (TGS) for any account with a Service Principal Name (SPN). The ticket is encrypted with the service account's password hash. Attackers request the ticket, extract it, and crack it offline — no elevated privileges required, no account lockout risk.

### Lab precondition

`svc_sql` was configured as a Kerberoastable service account:
```powershell
New-ADUser -Name "svc_sql" -AccountPassword (ConvertTo-SecureString "Summer2024!" -AsPlainText -Force) -Enabled $true
Set-ADUser -Identity svc_sql -ServicePrincipalNames @{Add="MSSQLSvc/dc01.lab.local:1433"}
```

### Attack execution

Run from Kali as `jdoe` (low-privilege domain user):

```bash
impacket-GetUserSPNs lab.local/jdoe:Password123! \
  -dc-ip 192.168.56.10 \
  -request \
  -outputfile /tmp/kerberoast.txt
```

TGS hash returned for `svc_sql` in hashcat format (`$krb5tgs$23$*`) — crackable offline:

```bash
hashcat -m 13100 /tmp/kerberoast.txt /usr/share/wordlists/rockyou.txt
# Result: svc_sql:Summer2024!
```

---

## Detection — Windows Event ID 4769

### Why 4769?

Every Kerberos service ticket request generates Event ID 4769 on the domain controller. Kerberoasting is detectable because:

1. Tools like Impacket request tickets using **RC4-HMAC encryption (type 0x17 / decimal 23)** — older and weaker than AES, but required to produce a crackable hash
2. Legitimate services predominantly use AES (type 0x12 / decimal 18)
3. RC4 ticket requests for non-machine, non-krbtgt accounts are anomalous in modern environments

### Raw event observed in Wazuh

```json
{
  "data.win.system.eventID": "4769",
  "data.win.eventdata.targetUserName": "jdoe",
  "data.win.eventdata.serviceName": "svc_sql",
  "data.win.eventdata.ticketEncryptionType": "23",
  "agent.name": "DC01",
  "rule.id": "60105"
}
```

Event confirmed visible in Wazuh dashboard under **Modules → Security Events**, filtered by `data.win.system.eventID: 4769`.

---

## Custom Wazuh Detection Rule

Default Wazuh rule 60105 catches all 4769 events — too noisy for a real alert. The custom rule below filters specifically for the Kerberoasting signature: RC4 encryption on a non-machine, non-krbtgt account.

### Rule (`/var/ossec/etc/rules/local_rules.xml`)

```xml
<group name="kerberoasting,attack,">

  <rule id="100001" level="12">
    <if_sid>60105</if_sid>
    <field name="win.eventdata.serviceName" negate="yes">.*\$$</field>
    <field name="win.eventdata.serviceName" negate="yes">krbtgt</field>
    <field name="win.eventdata.ticketEncryptionType">23</field>
    <description>Possible Kerberoasting: RC4 ticket requested for $(win.eventdata.serviceName) by $(win.eventdata.targetUserName)</description>
    <mitre>
      <id>T1558.003</id>
    </mitre>
    <group>kerberoasting,credential_access,</group>
  </rule>

</group>
```

### Rule logic explained

| Condition | Purpose |
|---|---|
| `if_sid: 60105` | Triggers only on Event ID 4769 events already parsed by Wazuh |
| `serviceName` negate `.*\$$` | Excludes machine accounts (end in `$`) — normal Kerberos traffic |
| `serviceName` negate `krbtgt` | Excludes krbtgt — normal DC-to-DC traffic |
| `ticketEncryptionType: 23` | Matches RC4-HMAC only — the Kerberoasting signature |
| `level: 12` | High severity — warrants immediate analyst attention |
| `mitre T1558.003` | Tags the alert with the correct ATT&CK technique |

### Alert confirmed firing

After restarting the Wazuh manager and re-running the attack:

```
rule.id: 100001
rule.level: 12
rule.description: Possible Kerberoasting: RC4 ticket requested for svc_sql by jdoe
rule.mitre.technique: T1558.003
agent.name: DC01
```

---

## What an Analyst Does Next

When rule 100001 fires, a SOC analyst should:

1. **Confirm the requesting account** — is `jdoe` expected to be requesting service tickets for `svc_sql`? Check if jdoe is a developer, DBA, or service account.

2. **Check for volume** — a single 4769 is suspicious; multiple 4769 events in a short window for different SPNs is almost certainly a tool-based Kerberoasting sweep. Filter by `targetUserName` and count unique `serviceName` values in the last 5 minutes.

3. **Check the source IP** — the 4769 event includes the client address. Is it a known workstation? A server? An IP that doesn't map to any asset?

4. **Correlate with Sysmon** — check for Sysmon Event ID 1 (process creation) or Event ID 3 (network connection) from the same host around the same timestamp. Look for `lsass.exe` access or unusual PowerShell/Python processes.

5. **Check for lateral movement** — if Kerberoasting succeeded and the hash was cracked, the attacker will use the credentials next. Look for new logon events (4624) for `svc_sql` from unexpected hosts.

6. **Contain** — if confirmed malicious, disable the requesting account (`jdoe`) immediately and reset `svc_sql`'s password to a strong random string.

---

## Defensive Recommendations

| Recommendation | Why |
|---|---|
| Set `svc_sql` (and all service accounts) to use AES-only encryption | RC4 ticket requests become impossible — Kerberoasting fails at step 1 |
| Enable "Protected Users" security group for service accounts | Prevents RC4 negotiation entirely for members |
| Audit all accounts with SPNs quarterly | Reduce the attack surface — remove SPNs from accounts that don't need them |
| Alert on any RC4 (type 23) ticket request in the environment | In an AES-only environment, any RC4 request is an immediate IOC |
| Use Group Managed Service Accounts (gMSA) | Automatic 120-character password rotation — cracking becomes infeasible |

---

## Files in This Write-up

- `local_rules.xml` — custom Wazuh rule 100001

---

*Detection performed in an isolated lab environment. All credentials and hashes are simulated.*
