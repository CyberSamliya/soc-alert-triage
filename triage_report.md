# SOC Alert Triage Report

Generated: 2026-09-22T15:16:42Z
Source: Wazuh/Security Onion alert export (25 alerts)

## Severity Breakdown

| Severity | Count |
|---|---|
| CRITICAL | 5 |
| HIGH | 5 |
| MEDIUM | 4 |
| LOW | 11 |

## Correlated Incidents (10)

Alerts from the same source IP within 30 minutes of each other were grouped into a single incident, ranked by severity, worst first.

### Incident 1: CRITICAL — source 10.10.10.40

- **Time window:** 2026-09-22T00:13:02+00:00 to 2026-09-22T00:13:02+00:00
- **Alert count:** 1
- **Affected host(s):** ubuntu-srv-01
- **MITRE ATT&CK tactics:** Command and Control
- **MITRE ATT&CK techniques:** Application Layer Protocol
- **Alert timeline:**
  - `2026-09-22T00:13:02+00:00` — Web attack: outbound reverse shell connection detected. (level 14)

- **Recommended action:** Isolate the affected host immediately, preserve memory/disk for forensics, and treat as a confirmed compromise (webshell/C2 activity observed).

### Incident 2: CRITICAL — source 10.10.10.21

- **Time window:** 2026-09-20T02:16:45+00:00 to 2026-09-20T02:16:45+00:00
- **Alert count:** 1
- **Affected host(s):** win-client-01
- **MITRE ATT&CK tactics:** Persistence
- **MITRE ATT&CK techniques:** Create Account
- **Alert timeline:**
  - `2026-09-20T02:16:45+00:00` — Windows: New local administrator account created. (level 13)

- **Recommended action:** Escalate to Tier 2/IR — privileged account or group changes should be verified against a legitimate change ticket before being dismissed.

### Incident 3: CRITICAL — source 89.44.9.201

- **Time window:** 2026-09-22T00:11:19+00:00 to 2026-09-22T00:12:40+00:00
- **Alert count:** 3
- **Affected host(s):** ubuntu-srv-01
- **MITRE ATT&CK tactics:** Initial Access, Persistence
- **MITRE ATT&CK techniques:** Exploit Public-Facing Application, Web Shell
- **Alert timeline:**
  - `2026-09-22T00:11:19+00:00` — Web attack: SQL injection attempt detected. (level 11)
  - `2026-09-22T00:11:26+00:00` — Web attack: SQL injection attempt detected. (level 11)
  - `2026-09-22T00:12:40+00:00` — Web attack: webshell upload detected. (level 13)

- **Recommended action:** Isolate the affected host immediately, preserve memory/disk for forensics, and treat as a confirmed compromise (webshell/C2 activity observed).

### Incident 4: CRITICAL — source 185.220.101.34

- **Time window:** 2026-09-20T02:14:03+00:00 to 2026-09-20T02:16:02+00:00
- **Alert count:** 6
- **Affected host(s):** win-client-01
- **MITRE ATT&CK tactics:** Credential Access, Execution
- **MITRE ATT&CK techniques:** Brute Force, PowerShell
- **Alert timeline:**
  - `2026-09-20T02:14:03+00:00` — SSHD authentication failed. (level 5)
  - `2026-09-20T02:14:09+00:00` — SSHD authentication failed. (level 5)
  - `2026-09-20T02:14:14+00:00` — SSHD authentication failed. (level 5)
  - `2026-09-20T02:14:20+00:00` — SSHD authentication failed. (level 5)
  - `2026-09-20T02:14:31+00:00` — Multiple authentication failures followed by a success. (level 10)
  - `2026-09-20T02:16:02+00:00` — Windows: Suspicious process - powershell.exe with encoded command. (level 12)

- **Recommended action:** Escalate immediately for investigation; do not close without Tier 2 review.

### Incident 5: CRITICAL — source 10.10.10.21

- **Time window:** 2026-09-21T14:40:02+00:00 to 2026-09-21T14:45:10+00:00
- **Alert count:** 3
- **Affected host(s):** dc01
- **MITRE ATT&CK tactics:** Credential Access, Persistence
- **MITRE ATT&CK techniques:** Account Manipulation, Kerberoasting
- **Alert timeline:**
  - `2026-09-21T14:40:02+00:00` — Windows: Logon success. (level 4)
  - `2026-09-21T14:41:55+00:00` — Windows: Kerberoasting activity detected (abnormal TGS request pattern). (level 9)
  - `2026-09-21T14:45:10+00:00` — Windows: Privileged group membership change (Domain Admins). (level 12)

- **Recommended action:** Escalate to Tier 2/IR — privileged account or group changes should be verified against a legitimate change ticket before being dismissed.

### Incident 6: HIGH — source 45.155.204.12

- **Time window:** 2026-09-20T09:02:11+00:00 to 2026-09-20T09:02:21+00:00
- **Alert count:** 5
- **Affected host(s):** pfsense-fw
- **MITRE ATT&CK tactics:** Discovery
- **MITRE ATT&CK techniques:** Network Service Scanning
- **Alert timeline:**
  - `2026-09-20T09:02:11+00:00` — Firewall: connection blocked. (level 3)
  - `2026-09-20T09:02:13+00:00` — Firewall: connection blocked. (level 3)
  - `2026-09-20T09:02:15+00:00` — Firewall: connection blocked. (level 3)
  - `2026-09-20T09:02:18+00:00` — Firewall: connection blocked. (level 3)
  - `2026-09-20T09:02:21+00:00` — Firewall: possible port scan detected. (level 8)

- **Recommended action:** Investigate within the shift; correlate with other logs before closing.

### Incident 7: LOW — source 10.10.10.21

- **Time window:** 2026-09-22T08:15:22+00:00 to 2026-09-22T08:20:11+00:00
- **Alert count:** 2
- **Affected host(s):** win-client-01
- **Alert timeline:**
  - `2026-09-22T08:15:22+00:00` — Windows: Logon success. (level 4)
  - `2026-09-22T08:20:11+00:00` — Windows: Scheduled task created. (level 3)

- **Recommended action:** Log only; no action required unless volume increases.

### Incident 8: LOW — source 185.220.101.34

- **Time window:** 2026-09-22T09:00:00+00:00 to 2026-09-22T09:00:00+00:00
- **Alert count:** 1
- **Affected host(s):** pfsense-fw
- **Alert timeline:**
  - `2026-09-22T09:00:00+00:00` — Firewall: connection blocked. (level 3)

- **Recommended action:** Log only; no action required unless volume increases.

### Incident 9: LOW — source 10.10.10.40

- **Time window:** 2026-09-21T18:02:44+00:00 to 2026-09-21T18:03:01+00:00
- **Alert count:** 2
- **Affected host(s):** ubuntu-srv-01
- **Alert timeline:**
  - `2026-09-21T18:02:44+00:00` — Cron job started. (level 2)
  - `2026-09-21T18:03:01+00:00` — Sudo: command executed. (level 3)

- **Recommended action:** Log only; no action required unless volume increases.

### Incident 10: LOW — source unknown

- **Time window:** 2026-09-22T07:30:00+00:00 to 2026-09-22T07:30:00+00:00
- **Alert count:** 1
- **Affected host(s):** kali-attacker
- **Alert timeline:**
  - `2026-09-22T07:30:00+00:00` — Log rotated. (level 2)

- **Recommended action:** Log only; no action required unless volume increases.
