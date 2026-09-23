# SOC Alert Triage Tool

A Python script that takes a raw Wazuh/Security Onion alert export and turns it into a triage report a Tier 1 analyst could actually hand off: alerts grouped into incidents, ranked by severity, mapped to MITRE ATT&CK, with a recommended next action for each.

Built as a portfolio piece for my [cybersecurity home lab](../) project (pfSense + Windows AD + Ubuntu + Wazuh/Security Onion + Kali, isolated network), covering the Week 8 goal of taking one case end-to-end from alert to report.

## What it does

1. Loads a JSON alert export (`data.srcip`, `rule.level`, `rule.mitre.*`, etc. — the same shape Wazuh produces).
2. Buckets each alert into a severity band (LOW / MEDIUM / HIGH / CRITICAL) from the Wazuh rule level.
3. Correlates alerts from the same source IP within a 30-minute window into a single "incident," instead of showing twenty separate lines for one brute-force attempt.
4. Pulls MITRE ATT&CK tactics/techniques out of each alert where present.
5. Applies a small set of rule-of-thumb recommendations (isolate host, escalate to Tier 2, monitor, log only) based on severity and technique.
6. Writes everything out as a Markdown report (`triage_report.md`).

## Usage

```bash
python3 triage.py sample_data/wazuh_alerts.json -o triage_report.md
```

No dependencies outside the Python standard library.

## Sample data

`sample_data/wazuh_alerts.json` is synthetic data modeled on realistic Wazuh alert output, covering a few different attack patterns:

- An SSH brute-force attempt that succeeds, followed by a suspicious encoded PowerShell command (credential access → execution).
- A new local administrator account created right after (persistence).
- A port scan against the firewall.
- Kerberoasting followed by a Domain Admins group change on the domain controller.
- A SQL injection → webshell upload → outbound reverse shell chain against the Ubuntu web server.
- Normal background noise (successful logons, cron jobs, sudo commands) to show the tool doesn't just flag everything.

## Known limitation (worth knowing for an interview)

Correlation is currently by **source IP only**. In the sample data, the SQL injection/webshell chain (attacker IP → web server) and the resulting outbound reverse shell (web server → attacker IP) get split into two separate incidents, because the source IP flips once the compromised host starts talking back out. A real correlation engine would also group by destination host, or track a host as "compromised" once escalation-worthy activity is seen on it. That's the natural next feature to add, and it's a good thing to be able to explain if asked about the tool's design tradeoffs.

## Analyst investigation walkthrough

Automated triage only gets you so far. `analyst_notes.md` goes one level deeper on the CRITICAL PowerShell alert in Incident 4: decoding the base64 `-enc` payload in [CyberChef](https://gchq.github.io/CyberChef/) (`From Base64` → `Decode text` set to UTF-16LE, since PowerShell encodes `-EncodedCommand` as UTF-16LE before base64), identifying it as a download-cradle pattern (`IEX (New-Object Net.WebClient).DownloadString(...)`), and reasoning about why it's credible as malicious rather than dismissing it. This is meant to show the two-layer SOC workflow: automated detection catches and ranks the alert, a human analyst confirms what it means and why it matters.

It's kept in its own file rather than inside `triage_report.md`, because `triage.py` regenerates that report from scratch on every run, which would silently wipe out any hand-written analysis living inside it.

## Possible next steps

- Correlate by destination host as well as source IP, to catch attack chains like the one above.
- Add a `--severity-floor` flag to only report HIGH/CRITICAL incidents.
- Swap the synthetic data for a real export once the Wazuh/Security Onion box in the lab is live.
- Add unit tests for `severity_label()` and `build_incidents()`.
