# HTTPS deployment and operator runbook

This stack runs PostgreSQL, one API process with two scan workers, the red React UI, and Caddy for automatic HTTPS. Only ports 80 and 443 are published. Database and frontend networks are internal; the API has a separate outbound network for GitHub access. Public deployment requires a server you control, a domain pointing to it, and inbound 80/443 connectivity. Do not run multiple API replicas: the queue and admission lock belong to one process.

## Configure secrets and start

From the repository root, choose an absolute directory outside the build context, or use the ignored `.secrets/` directory:

```bash
export ZORIX_DOMAIN=zorix.example.com
export ZORIX_SECRETS_DIR="$PWD/.secrets"
python3 - <<'PY'
import os, secrets
from pathlib import Path
folder = Path(os.environ['ZORIX_SECRETS_DIR'])
folder.mkdir(mode=0o700, parents=True, exist_ok=True)
folder.chmod(0o700)
paths = [folder / name for name in ('api_key', 'db_password')]
if any(path.exists() for path in paths):
    raise SystemExit('Existing secrets found: preserve them or rotate deliberately')
for path in paths:
    path.write_text(secrets.token_urlsafe(48))
    path.chmod(0o444)
PY
docker compose -f deploy/compose.yml config --quiet
docker compose -f deploy/compose.yml up --build -d --wait
```

The host directory is private (0700). File readability permits the distinct container UIDs to read their explicitly mounted secrets; other host users cannot traverse the parent directory. Keep the directory and backups private. The API reads `SECRET_KEY_FILE` and `POSTGRES_PASSWORD_FILE`; secret values do not appear in Compose environment entries. Debug mode is off. Caddy keeps certificates in its named data volume. API and database ports are not published.

Use a GitHub token supplied for one scan in the UI when necessary. It stays in process memory and is not replayed after a restart. Global GitHub-token provisioning is intentionally not included in this deployment recipe.

## Upgrade and verify

Back up before changing images or schema. Keep the same project name, secrets, and volume names across upgrades:

```bash
docker compose -f deploy/compose.yml build
docker compose -f deploy/compose.yml up -d --wait
docker compose -f deploy/compose.yml exec backend alembic -c backend/alembic.ini check
curl --fail "https://$ZORIX_DOMAIN/api/health"
```

The API applies migrations and checks for schema drift before serving. On restart, queued/running jobs are marked interrupted; resubmit them. The API secret controls JWT signatures: rotating it signs users out. Changing the secret file for an existing PostgreSQL volume does not rotate the database role password; coordinate the SQL role change with the API file update during a maintenance window.

## Backups and restore

Stop the API while taking a consistent database/report backup. Store backups outside the repository with restricted permissions:

```bash
umask 077
docker compose -f deploy/compose.yml stop backend
docker compose -f deploy/compose.yml exec -T postgres pg_dump -U zorix_user -d zorix > zorix-backup.sql
docker compose -f deploy/compose.yml cp backend:/app/reports ./zorix-report-backup
docker compose -f deploy/compose.yml start backend
```

Also preserve the secret directory and Caddy data volume. For restore, use an empty database and restore SQL before starting the API, then copy reports into the reports volume and give UID 10001 access. Test the restore in an isolated project first; do not load a backup over an active database. Do not run `down --volumes` against a deployment whose data you need.

## Retention

Preview the plan first:

```bash
docker compose -f deploy/compose.yml exec backend python -m backend.tools.maintenance --job-days 30 --report-days 90
```

Add `--apply` to delete the planned terminal job records and generated HTML reports. The command rejects unsafe report paths, preserves active jobs, and retains scan evidence, current reviews, and append-only review history. SARIF and security JSON remain available from stored evidence after HTML removal. This is artifact/job retention, not complete erasure of account or audit data. Schedule the command with your host scheduler after choosing an appropriate policy and verifying backups.

## Policy and SIEM handoff

Download **security JSON** for an analysis. It uses `zorix.security_event/v1`, includes source provenance, package evidence where available, review/severity counts, and an explicit policy result. Feed it into your SIEM's JSON ingestion workflow; Zorix does not send it to an external service automatically.

```bash
python3 -m backend.tools.check_policy zorix-analysis.json
```

Exit codes: 0 means no blocking matches under the stated policy, 1 means attention required or incomplete scanning, and 2 means invalid input. ERROR findings block unless reviewed as false positives; accepted risks remain blocking. Use artifacts from a trusted authenticated export. This policy neither attests artifact authenticity nor proves exploitability or compliance.

## Verified boundary

The deployment configuration has been smoke-tested on loopback ports with temporary secrets, PostgreSQL migrations, a Caddy local CA, certificate-verified HTTPS, real browser registration, a queued scan of the owner's GitHub repository, and JSON download. A public-domain ACME certificate and a remote-server deployment require your actual domain and server; local validation does not establish those outcomes.
