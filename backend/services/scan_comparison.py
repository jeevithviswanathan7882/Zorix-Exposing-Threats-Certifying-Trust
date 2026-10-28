"""Compare recorded scanner findings without claiming exploit confirmation."""

import json
from collections import Counter


def compare_findings(current: dict, baseline: dict) -> dict:
    if current.get("status") != "completed" or baseline.get("status") != "completed":
        raise ValueError("Both scans must have completed successfully")
    current_rules, baseline_rules = current.get("rules_sha256"), baseline.get("rules_sha256")
    if current_rules and baseline_rules and current_rules != baseline_rules:
        raise ValueError("Scans used different rule sets; rescan with the same rules before comparing")
    current_findings = current.get("findings", [])
    baseline_findings = baseline.get("findings", [])
    current_counts = Counter(json.dumps(finding, sort_keys=True) for finding in current_findings)
    baseline_counts = Counter(json.dumps(finding, sort_keys=True) for finding in baseline_findings)
    introduced = [json.loads(item) for item in (current_counts - baseline_counts).elements()]
    resolved = [json.loads(item) for item in (baseline_counts - current_counts).elements()]
    return {
        "introduced": introduced,
        "resolved": resolved,
        "unchanged_count": sum((current_counts & baseline_counts).values()),
        "introduced_count": len(introduced),
        "resolved_count": len(resolved),
        "note": "Changes in static findings require manual review; they do not prove a vulnerability was fixed or introduced."
        + (" Rule fingerprints were not recorded for one or both scans; rule consistency could not be checked."
           if not current_rules or not baseline_rules else ""),
    }
