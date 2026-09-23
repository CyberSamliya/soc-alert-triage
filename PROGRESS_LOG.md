# Home Lab Progress Log

Tracking milestones against the 8-week cybersecurity home lab build (pfSense, Windows AD/DNS, Ubuntu, Wazuh/Security Onion, Kali, isolated networks). Add a new dated entry below each time something ships.

---

## 2026-09-22 — SOC Alert Triage Tool (portfolio artifact, built ahead of full lab deployment)

**What shipped:** A Python triage tool (`triage.py`) that ingests Wazuh/Security Onion-style alert exports, correlates them into incidents, maps them to MITRE ATT&CK, and produces a Markdown triage report — plus a manual investigation write-up (`analyst_notes.md`) decoding a malicious PowerShell payload in CyberChef.

**Why it's out of sequence:** The lab plan calls for logging infrastructure (Wazuh/Security Onion) before this kind of tooling gets built. This tool was built against realistic synthetic data first, so there's already a working, tested artifact ready to point at real alert exports the moment the Wazuh/Security Onion box is live — no lost time waiting on the tool once the logging pipeline exists.

**Maps to lab goal:** Directly supports the Week 8 target of "one end-to-end case from alert to report" — this is that case, built on synthetic data as a stand-in until real lab telemetry is available.

**Next tie-in:** Once the firewall, Windows Server, and first Windows client are up and logging into Wazuh/Security Onion (per the "build firewall + Windows Server + one client first, add logging before more machines" build order), re-run `triage.py` against a real export and compare against this synthetic baseline. Update `sample_data/` or add a `real_data/` folder at that point.

**Artifacts:** `triage.py`, `sample_data/wazuh_alerts.json`, `triage_report.md`, `analyst_notes.md`, `README.md`, `PORTFOLIO_WRITEUP.md`.
