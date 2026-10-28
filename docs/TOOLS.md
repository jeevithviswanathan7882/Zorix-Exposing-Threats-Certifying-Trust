# Security tool integrations

Zorix executes its bundled Semgrep rules on bounded GitHub snapshots. CI executes dependency audits and Trivy image/configuration checks. The following **import adapters** normalize external reports; importing a report does not execute that tool or independently attest the uploader's repository/commit association.

| Import selection | Input | Preserved evidence | Discarded fields |
| --- | --- | --- | --- |
| SARIF 2.1.0 | JSON object with runs and tool driver names | Tool, rule, message, severity, first source location | Code snippets, unselected tool properties |
| Trivy | SchemaVersion 2 JSON object with Results | Advisory, target, package name/ID/path, installed/fixed version, original severity | Secret matches and unrelated scanner data |
| Bandit | JSON object with results and no errors | Test ID, Python file/line, issue text and severity | Source code snippets |
| Gitleaks | JSON array in UI; API wraps it in `findings` | Rule, file/line, description | Secret, Match, raw credential values |
| Checkov | JSON object or report array in UI; API wraps arrays in `reports` | Failed check ID/name, file/first line, supplied severity | Code blocks and unrelated runner output |
| OWASP ZAP | Traditional JSON with site/alerts/instances | Plugin ID, alert name, risk, URL origin/path | Query strings, credentials, fragments, attack/evidence and HTTP bodies |
| Nuclei | JSONL in UI; API wraps parsed records in `results` | Template ID, name, original severity, matched URL origin/path | Query strings, credentials, request/response bodies |

SARIF can represent evidence from CodeQL, Semgrep and other producers that emit the supported SARIF structure. Tool editions and output formats vary; adapters validate the contracts above rather than claiming compatibility with every tool/version. The adapters have deterministic schema, bounds, redaction, ownership, and export tests. Selected descriptions and paths may themselves contain sensitive information; review reports before upload.

Each request is bounded to 1 MB and 1,000 normalized findings, with at most 50 SARIF runs. The UI caps source files at 900 KB to leave room for metadata. SHA-256 fingerprints use canonical JSON (sorted keys), not the original file's whitespace. ERROR/WARNING/INFO are normalized review levels; original package/tool severities are retained where supplied. Missing Checkov severity becomes WARNING and is labeled UNSPECIFIED. No CVSS value or exploit confirmation is invented.

Imported reports join the same private review history, comparisons, policy export, and HTML/SARIF/security-JSON download workflows. Package and URL findings are exported without fabricated source lines. The application never follows imported URLs, launches imported commands, or stores full HTTP evidence bodies. Controls protect normal report ingestion; they do not make an externally supplied report truthful.
