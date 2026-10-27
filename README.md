# Zorix

**Evidence-based repository security review**

Zorix is a FastAPI and React project for reviewing source files in GitHub repositories. It fetches a selected file through the GitHub API, runs local Semgrep rules, stores the findings for the signed-in user, and generates an HTML report. Findings are **potential issues requiring manual review**. Zorix does not currently prove exploitability or calculate a CVSS score.

## Current capabilities

- GitHub file analysis for Python, JavaScript, and TypeScript (`.py`, `.js`, `.jsx`, `.ts`, `.tsx`)
- Semgrep findings with rule ID, file, line, severity, and message
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

   Set `SECRET_KEY` in `.env` to a unique random value. Keep `ALLOWED_ORIGINS` as a JSON list. The default local database is SQLite. Set `GITHUB_TOKEN` if you need private repository access or higher GitHub API limits.

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

Open <http://localhost:3000>, register, sign in, and enter an HTTPS GitHub repository URL and a relative file path, such as `src/app.py`. The frontend proxies `/api` requests to <http://localhost:8000>. API documentation is at <http://localhost:8000/docs>; health status is at <http://localhost:8000/health>.

### Docker Compose

```bash
docker compose up --build
```

The frontend is available at <http://localhost:3000> and the API at <http://localhost:8000>. Compose uses `backend/.env.dev`, which contains **development credentials**. Change these before any deployment outside a trusted local environment. The current Compose file does not mount the Docker socket and does not start Ollama or execute exploit payloads.

If those host ports are already in use, set `ZORIX_FRONTEND_PORT`, `ZORIX_API_PORT`, or `ZORIX_DB_PORT` before running Compose. For example: `ZORIX_FRONTEND_PORT=13000 ZORIX_API_PORT=18000 docker compose up --build`.

## API example

Register and log in through `/api/auth/register` and `/api/auth/login`, then submit a scan with the returned bearer token:

```bash
curl -X POST http://localhost:8000/api/analysis/analyze \
  -H 'Authorization: Bearer YOUR_TOKEN' \
  -H 'Content-Type: application/json' \
  -d '{
    "repo_url": "https://github.com/owner/repository",
    "affected_file": "src/app.py"
  }'
```

A successful response includes an `analysis_id`, scanner status, and the findings. Retrieve your history with `GET /api/analysis/results`, a single result with `GET /api/analysis/results/{analysis_id}`, and its HTML report with `GET /api/analysis/reports/{analysis_id}/html`. Results and reports require authentication and are scoped to their owner.

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

The backend tests cover target validation, a real Semgrep rule match and clean file, account roles, authentication, scan evidence, and cross-user isolation. The frontend tests cover sign-in and the evidence view. GitHub Actions also compiles Python, audits dependencies, and builds the backend and frontend container images. The Semgrep dependency exceptions are documented in [SECURITY.md](SECURITY.md).

## Interpreting findings

A Semgrep match identifies code that fits a rule. It is not a confirmed vulnerability. Review the source and its data flow, reproduce the issue in an authorized test environment, and retest after a fix. Zorix deliberately reports no exploit confirmation and no CVSS value at this stage. A clean scan also does not prove that a file is secure.

The current scan covers **one selected file on the repository's default branch**, not the whole repository. The GitHub blob SHA in the report identifies the fetched file content. Dynamic testing, whole-repository coverage, dependency and container scanning, formal CVSS vectors, and AI-assisted review are planned work, not current features.

## Next milestones

1. Scan complete repositories at a pinned commit with resource limits and reproducible artifacts.
2. Normalize findings from additional tools into one evidence model, starting with dependency and container scanning.
3. Add review states, false-positive handling, and fix-and-rescan comparisons.
4. Add authenticated, opt-in dynamic testing against explicitly allowlisted local targets.
5. Add CI policy gates and export formats for security workflows.

This project is intended as a practical security engineering and DevSecOps portfolio piece. Claims in reports and documentation should follow what the tests and recorded evidence can support.
