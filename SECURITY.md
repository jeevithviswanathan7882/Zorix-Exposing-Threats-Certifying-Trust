# Security policy and known exceptions

Zorix only accepts HTTPS `github.com` repository URLs and relative source paths for its current static scan. Only scan repositories you are authorized to review. API results and reports are scoped to the authenticated account. The Docker Compose setup is for local development and uses development credentials; it must not be exposed to the internet as configured.

## Dependency review

The API dependency lock (`backend/requirements.txt`) and frontend lock currently pass `pip-audit` and `npm audit` checks. Semgrep runs from a separate Python environment (`backend/scanner-requirements.txt`) to keep its dependency constraints out of the API interpreter.

Reviewed on 2026-10-28: Semgrep 1.182.1 pins two dependencies with five advisories that cannot be upgraded within its declared constraints. The current published Semgrep release still requires `mcp==1.29.0` and `opentelemetry-api~=1.37.0`.

| Dependency | Advisory | Pinned version | Patched version | Current use |
| --- | --- | --- | --- | --- |
| `mcp` | `CVE-2026-59951` | 1.29.0 | 1.30.0 | Zorix does not start an MCP server |
| `mcp` | [CVE-2026-116684](https://github.com/modelcontextprotocol/python-sdk/security/advisories/GHSA-w4fh-qvv9-3v23) | 1.29.0 | 1.30.0 | Server bearer authentication; Zorix does not start an MCP server |
| `mcp` | [CVE-2026-116685](https://github.com/modelcontextprotocol/python-sdk/security/advisories/GHSA-5h93-6whr-6q8j) | 1.29.0 | 1.30.0 | HTTP client redirects; Zorix does not create an MCP client |
| `mcp` | [CVE-2026-116686](https://github.com/modelcontextprotocol/python-sdk/security/advisories/GHSA-rwrf-2pqf-9j8j) | 1.29.0 | 1.30.0 | Client tool-result schema resolution; Zorix does not call MCP tools |
| `opentelemetry-api` | `CVE-2026-114603` | 1.37.0 | 1.45.1 | Scanner metrics and version checks are disabled |

CI ignores only these five advisory IDs in the scanner lock and fails on new findings. The active code invokes the fixed `semgrep scan` subcommand with bundled local rules; it accepts no arbitrary Semgrep commands and starts no MCP HTTP transport or client session. This is a reachability assessment of Zorix's current use, not a claim that the pinned packages are patched. Any future MCP integration must remove these exceptions and use a patched SDK. Reassess the pins when Semgrep updates, and review these exceptions again by 2026-11-28.

The scanner reads a bounded local source snapshot and has a 90-second timeout for one file or 120 seconds for a repository. The separate Python environment reduces dependency conflict with the API; it is **not** a network or operating-system sandbox.

## Container vulnerability evidence

CI scans both built application images with a digest-pinned Trivy image. The `image-security-evidence` artifact contains a CycloneDX SBOM and a full vulnerability JSON report for each image. The image gate fails on high or critical vulnerabilities with an available fixed version (`--ignore-unfixed`), except for the same five reviewed scanner advisory IDs in [`security/trivy-image-exceptions`](security/trivy-image-exceptions). Full reports apply no ignore file and retain both accepted and unfixed findings. This gate does not mean the images have no vulnerabilities.

The frontend build applies available Alpine updates. The backend removes build-only compiler, Git, and PostgreSQL development packages, and updates setuptools in both Python environments to remove vulnerable vendored dependencies. The local application containers do not mount the Docker socket; only the CI scanner uses it to inspect images.

## Reporting a vulnerability

For a sensitive finding, use GitHub's private vulnerability reporting feature for this repository if it is enabled. Avoid posting exploit details or secrets in a public issue. For ordinary bugs, open an issue with reproduction steps and the affected version.
