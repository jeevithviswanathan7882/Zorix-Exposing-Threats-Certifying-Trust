# Zorix

**Evidence-based repository security review**

Zorix is a FastAPI and React project for reviewing GitHub source code. It can scan a bounded repository snapshot at a pinned commit or one selected source file. It runs local Semgrep rules, stores the findings for the signed-in user, and generates an HTML report. Findings are **potential issues requiring manual review**. Zorix does not currently prove exploitability or calculate a CVSS score.

## Current capabilities

- GitHub repository scans pinned to the default branch's commit SHA, plus individual file scans
- Python, JavaScript, and TypeScript source (`.py`, `.js`, `.jsx`, `.ts`, `.tsx`)
- Repository limits: 100 supported files, 200 KB per file, 2 MB total; oversized or truncated scans fail explicitly
- Semgrep findings with rule ID, file, line, severity, and message
- Authenticated HTML and SARIF 2.1.0 exports for completed scans
- User registration, JWT sign-in, and per-user access to scan results and reports
- Input checks for GitHub URLs and repository paths, a 200 KB file limit, and escaped HTML reports
- Python integration tests, frontend unit tests, TypeScript checking, npm audit, and Docker builds in CI

The active application is in `backend/` and `frontend/`. `security/semgrep_rules.yaml` contains the current detection rules. `tests/` contains backend and scanner tests. The Docker configuration runs PostgreSQL, the API, and the frontend. The CI workflow is in `.github/workflows/ci.yml`.

## Quick start

Requirements: Python 3.11, Node.js 22 or newer, npm, and access to the GitHub API. Docker is optional for local development.

1. Clone and configure the backend:

   ```bash
   git clone https://github.com/rj-karan/Zorix-Exposing-Threats-Certifying-Trust.git
   cd Zorix-Exposing-Threats-Certifying-Trust
   cp .env.example .env
   ```

   Set `SECRET_KEY` in `.env` to a unique random value. Keep `ALLOWED_ORIGINS` as a JSON list. The default local database is SQLite. Set `GITHUB_TOKEN` if you need private repository access or higher GitHub API limits. You can also provide a token for one scan in the UI; it is sent to the API for that request and is not stored in the scan record.

2. Start the API from the repository root:

   ```bash
   python3.11 -m venv .venv
   source .venv/bin/activate
   python -m pip install -r backend/requirements.txt
   python3.11 -m venv .scanner-venv
   .scanner-venv/bin/python -m pip install -r backend/scanner-requirements.txt
   export SEMGREP_PATH=.scanner-venv/bin/semgrep
   uvicorn backend.main:app --reload --port 8000
   ```

3. In another terminal, start the frontend:

   ```bash
   cd frontend
   npm ci
   npm run dev
   ```

Open <http://localhost:3000>, register, sign in, and enter an HTTPS GitHub repository URL. Choose a repository scan or a relative file path such as `src/app.py`. The frontend proxies `/api` requests to <http://localhost:8000>. API documentation is at <http://localhost:8000/docs>; health status is at <http://localhost:8000/health>.

### Docker Compose

```bash
docker compose up --build
```

The frontend is available at <http://localhost:3000> and the API at <http://localhost:8000>. Compose uses `backend/.env.dev`, which contains **development credentials**. Change these before any deployment outside a trusted local environment. The current Compose file does not mount the Docker socket and does not start Ollama or execute exploit payloads.

If those host ports are already in use, set `ZORIX_FRONTEND_PORT`, `ZORIX_API_PORT`, or `ZORIX_DB_PORT` before running Compose. For example: `ZORIX_FRONTEND_PORT=13000 ZORIX_API_PORT=18000 docker compose up --build`.

## API example

Register and log in through `/api/auth/register` and `/api/auth/login`, then submit a repository scan with the returned bearer token:

```bash
curl -X POST http://localhost:8000/api/analysis/repository \
  -H 'Authorization: Bearer YOUR_TOKEN' \
  -H 'Content-Type: application/json' \
  -d '{
    "repo_url": "https://github.com/owner/repository"
  }'
```

A successful response includes an `analysis_id`, commit SHA, file count, scanner status, and findings. For one file, use `POST /api/analysis/analyze` with `repo_url` and `affected_file`. Retrieve your history with `GET /api/analysis/results`, a single result with `GET /api/analysis/results/{analysis_id}`, and its report with `GET /api/analysis/reports/{analysis_id}/html` or `/sarif`. Results and reports require authentication and are scoped to their owner. SARIF is available only after a completed scan; failed scans cannot be exported as clean results.

## Verification

Run these checks before opening a pull request:

```bash
python -m pip install pytest
python -m pytest -q tests
cd frontend
npm ci
npm test
npm run build
npm audit --audit-level=high
```

The backend tests cover target validation, commit-pinned repository fetching, truncated-tree rejection, real Semgrep rule matches, account roles, authentication, scan evidence, and cross-user isolation. The frontend tests cover sign-in and the evidence view. GitHub Actions also compiles Python, audits dependencies, and builds the backend and frontend container images. The Semgrep dependency exceptions are documented in [SECURITY.md](SECURITY.md).

## Interpreting findings

A Semgrep match identifies code that fits a rule. It is not a confirmed vulnerability. Review the source and its data flow, reproduce the issue in an authorized test environment, and retest after a fix. Zorix deliberately reports no exploit confirmation and no CVSS value at this stage. A clean scan also does not prove that a file is secure.

Repository scans resolve the default branch to a commit SHA, enumerate its Git tree, and fetch each selected file by blob SHA. They reject truncated trees and limit violations instead of silently reporting partial coverage. Generated and dependency directories are excluded. Individual file scans still fetch the default branch at request time; their blob SHA identifies the content, but they are not pinned to a commit. Dynamic testing, dependency and container scanning, formal CVSS vectors, and AI-assisted review are planned work, not current features.

## Next milestones

1. Normalize findings from additional tools into one evidence model, starting with dependency and container scanning.
2. Add review states, false-positive handling, and fix-and-rescan comparisons.
3. Add authenticated, opt-in dynamic testing against explicitly allowlisted local targets.
4. Add CI policy gates and export formats for security workflows.

This project is intended as a practical security engineering and DevSecOps portfolio piece. Claims in reports and documentation should follow what the tests and recorded evidence can support.
