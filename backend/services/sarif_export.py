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
        result = {
            "ruleId": str(finding["rule_id"]),
            "level": levels.get(str(finding.get("severity", "INFO")).upper(), "note"),
            "message": {"text": str(finding.get("message", ""))},
            "properties": {"verification_status": "unverified",
                           **{key: finding[key] for key in ("source_tool", "source_severity", "package") if key in finding}},
        }
        if isinstance(line, int) and not isinstance(line, bool) and line > 0:
            result['locations'] = [{'physicalLocation': {
                'artifactLocation': {'uri': quote(path, safe='/'), 'uriBaseId': '%SRCROOT%'},
                'region': {'startLine': line},
            }}]
        results.append(result)
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "Zorix imported evidence" if evidence.get("imported") else "Zorix Semgrep", "rules": rules}},
            "originalUriBaseIds": {"%SRCROOT%": {"uri": "file:///repo/"}},
            "results": results,
            "properties": {"commit_sha": evidence.get("commit_sha"),
                           "rules_sha256": evidence.get("rules_sha256"),
                           "imported": evidence.get("imported", False),
                           "source_tools": evidence.get("source_tools", ["Semgrep"]),
                           "artifact_sha256": evidence.get("artifact_sha256")},
        }],
    }
