#!/usr/bin/env python3
"""
triage.py — SOC Alert Triage Tool

Reads a Wazuh/Security Onion-style JSON alert export, scores and groups
alerts, correlates activity by source IP into rough "incidents", and
produces a Markdown triage report that reads like something a Tier 1
analyst would hand off to Tier 2.

Usage:
    python3 triage.py sample_data/wazuh_alerts.json -o report.md

Author: Samra Ayele — SOC home lab portfolio project
"""

import argparse
import json
from collections import defaultdict
from datetime import datetime, timedelta


# Wazuh rule levels: 0-4 informational/low, 5-7 medium, 8-11 high, 12-15 critical
SEVERITY_BANDS = [
    (12, "CRITICAL"),
    (8, "HIGH"),
    (5, "MEDIUM"),
    (0, "LOW"),
]

# How close together (in minutes) alerts from the same source IP need to be
# to get grouped into one "incident" for the report.
CORRELATION_WINDOW_MIN = 30


def severity_label(level: int) -> str:
    for threshold, label in SEVERITY_BANDS:
        if level >= threshold:
            return label
    return "LOW"


def load_alerts(path: str) -> list:
    with open(path, "r") as f:
        alerts = json.load(f)
    for a in alerts:
        a["_ts"] = datetime.fromisoformat(a["timestamp"].replace("Z", "+00:00"))
        a["_severity"] = severity_label(a["rule"].get("level", 0))
    return alerts


def group_by_source(alerts: list) -> dict:
    """Group alerts by source IP so repeated noise (e.g. failed logins)
    reads as one line instead of twenty."""
    groups = defaultdict(list)
    for a in alerts:
        src = a.get("data", {}).get("srcip", "unknown")
        groups[src].append(a)
    return groups


def build_incidents(alerts: list) -> list:
    """Very simple time-based correlation: alerts from the same source IP
    within CORRELATION_WINDOW_MIN of each other are treated as one incident.
    This is the same idea behind real correlation rules, just simplified."""
    by_src = group_by_source(alerts)
    incidents = []

    for src, src_alerts in by_src.items():
        src_alerts.sort(key=lambda a: a["_ts"])
        current = [src_alerts[0]]

        for a in src_alerts[1:]:
            if a["_ts"] - current[-1]["_ts"] <= timedelta(minutes=CORRELATION_WINDOW_MIN):
                current.append(a)
            else:
                incidents.append((src, current))
                current = [a]
        incidents.append((src, current))

    # Sort incidents by their highest rule level, worst first
    incidents.sort(key=lambda inc: max(a["rule"]["level"] for a in inc[1]), reverse=True)
    return incidents


def incident_summary(src: str, group: list) -> dict:
    max_level = max(a["rule"]["level"] for a in group)
    tactics = sorted({t for a in group for t in a["rule"].get("mitre", {}).get("tactic", [])})
    techniques = sorted({t for a in group for t in a["rule"].get("mitre", {}).get("technique", [])})
    agents = sorted({a["agent"]["name"] for a in group})
    start = min(a["_ts"] for a in group)
    end = max(a["_ts"] for a in group)

    return {
        "src": src,
        "severity": severity_label(max_level),
        "max_level": max_level,
        "count": len(group),
        "start": start,
        "end": end,
        "agents": agents,
        "tactics": tactics,
        "techniques": techniques,
        "descriptions": [a["rule"]["description"] for a in group],
    }


def render_report(alerts: list, incidents: list) -> str:
    total = len(alerts)
    by_sev = defaultdict(int)
    for a in alerts:
        by_sev[a["_severity"]] += 1

    lines = []
    lines.append("# SOC Alert Triage Report")
    lines.append("")
    lines.append(f"Generated: {datetime.utcnow().isoformat(timespec='seconds')}Z")
    lines.append(f"Source: Wazuh/Security Onion alert export ({total} alerts)")
    lines.append("")
    lines.append("## Severity Breakdown")
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("|---|---|")
    for _, label in SEVERITY_BANDS:
        lines.append(f"| {label} | {by_sev.get(label, 0)} |")
    lines.append("")
    lines.append(f"## Correlated Incidents ({len(incidents)})")
    lines.append("")
    lines.append(
        f"Alerts from the same source IP within {CORRELATION_WINDOW_MIN} minutes of each "
        "other were grouped into a single incident, ranked by severity, worst first."
    )
    lines.append("")

    for i, (src, group) in enumerate(incidents, start=1):
        s = incident_summary(src, group)
        lines.append(f"### Incident {i}: {s['severity']} — source {s['src']}")
        lines.append("")
        lines.append(f"- **Time window:** {s['start'].isoformat()} to {s['end'].isoformat()}")
        lines.append(f"- **Alert count:** {s['count']}")
        lines.append(f"- **Affected host(s):** {', '.join(s['agents'])}")
        if s["tactics"]:
            lines.append(f"- **MITRE ATT&CK tactics:** {', '.join(s['tactics'])}")
        if s["techniques"]:
            lines.append(f"- **MITRE ATT&CK techniques:** {', '.join(s['techniques'])}")
        lines.append("- **Alert timeline:**")
        for a in group:
            lines.append(f"  - `{a['_ts'].isoformat()}` — {a['rule']['description']} (level {a['rule']['level']})")

        lines.append("")
        lines.append(f"- **Recommended action:** {recommend_action(s)}")
        lines.append("")

    return "\n".join(lines)


def recommend_action(summary: dict) -> str:
    """Very lightweight rule-of-thumb recommendations, meant to show
    triage reasoning rather than replace a real analyst's judgment."""
    sev = summary["severity"]
    techniques = summary["techniques"]

    if "Web Shell" in techniques or "Application Layer Protocol" in techniques:
        return (
            "Isolate the affected host immediately, preserve memory/disk for forensics, "
            "and treat as a confirmed compromise (webshell/C2 activity observed)."
        )
    if "Account Manipulation" in techniques or "Create Account" in techniques:
        return (
            "Escalate to Tier 2/IR — privileged account or group changes should be verified "
            "against a legitimate change ticket before being dismissed."
        )
    if sev == "CRITICAL":
        return "Escalate immediately for investigation; do not close without Tier 2 review."
    if sev == "HIGH":
        return "Investigate within the shift; correlate with other logs before closing."
    if sev == "MEDIUM":
        return "Monitor; close as benign if source is expected and no follow-on activity appears."
    return "Log only; no action required unless volume increases."


def main():
    parser = argparse.ArgumentParser(description="SOC alert triage tool")
    parser.add_argument("input", help="Path to Wazuh/Security Onion JSON alert export")
    parser.add_argument("-o", "--output", default="triage_report.md", help="Output Markdown report path")
    args = parser.parse_args()

    alerts = load_alerts(args.input)
    incidents = build_incidents(alerts)
    report = render_report(alerts, incidents)

    with open(args.output, "w") as f:
        f.write(report)

    print(f"Parsed {len(alerts)} alerts into {len(incidents)} incidents.")
    print(f"Report written to {args.output}")


if __name__ == "__main__":
    main()
