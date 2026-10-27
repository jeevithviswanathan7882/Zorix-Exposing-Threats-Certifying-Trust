# Security policy and known exceptions

Zorix only accepts HTTPS `github.com` repository URLs and relative source paths for its current static scan. Only scan repositories you are authorized to review. API results and reports are scoped to the authenticated account. The Docker Compose setup is for local development and uses development credentials; it must not be exposed to the internet as configured.

## Dependency review

The API dependency lock (`backend/requirements.txt`) and frontend lock currently pass `pip-audit` and `npm audit` checks. Semgrep runs from a separate Python environment (`backend/scanner-requirements.txt`) to keep its dependency constraints out of the API interpreter.

As of 2026-10-27, Semgrep 1.182.1 pins two dependencies with advisories that cannot be upgraded within its declared constraints:

| Dependency | Advisory | Pinned version | Patched version | Current use |
| --- | --- | --- | --- | --- |
| `mcp` | `CVE-2026-59951` | 1.29.0 | 1.30.0 | Zorix does not start an MCP server |
| `opentelemetry-api` | `CVE-2026-114603` | 1.37.0 | 1.45.1 | Scanner metrics and version checks are disabled |

CI ignores only these two advisory IDs in the scanner lock and fails on new findings. The scanner process reads one bounded local source file and has a 90-second timeout. The separate Python environment reduces dependency conflict with the API; it is **not** a network or operating-system sandbox. These exceptions need reassessment when Semgrep updates its pins.

## Reporting a vulnerability

For a sensitive finding, use GitHub's private vulnerability reporting feature for this repository if it is enabled. Avoid posting exploit details or secrets in a public issue. For ordinary bugs, open an issue with reproduction steps and the affected version.
