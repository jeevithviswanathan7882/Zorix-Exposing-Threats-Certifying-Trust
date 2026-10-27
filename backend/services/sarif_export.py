"""Convert verified scanner output into a SARIF 2.1.0 artifact."""

from urllib.parse import quote


def build_sarif(evidence: dict) -> dict:
    if evidence.get("status") != "completed":
        raise ValueError("Only completed scans can be exported as SARIF")
    findings = evidence.get("findings", [])
    rule_ids = sorted({str(finding["rule_id"]) for finding in findings})
    rules = [{"id": rule_id, "name": rule_id} for rule_id in rule_ids]
    levels = {"ERROR": "error", "WARNING": "warning", "INFO": "note"}
    results = []
    for finding in findings:
        path = str(finding["file"])
        line = finding.get("line")
        if not isinstance(line, int) or line < 1:
            continue
        results.append({
            "ruleId": str(finding["rule_id"]),
            "level": levels.get(str(finding.get("severity", "INFO")).upper(), "note"),
            "message": {"text": str(finding.get("message", ""))},
            "properties": {"verification_status": "unverified"},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": quote(path, safe="/"), "uriBaseId": "%SRCROOT%"},
                "region": {"startLine": line},
            }}],
        })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "Zorix Semgrep", "rules": rules}},
            "originalUriBaseIds": {"%SRCROOT%": {"uri": "file:///repo/"}},
            "results": results,
            "properties": {"commit_sha": evidence.get("commit_sha")},
        }],
    }
