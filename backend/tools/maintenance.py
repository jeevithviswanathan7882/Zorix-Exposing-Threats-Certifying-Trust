"""Plan or apply bounded retention for completed job metadata and generated HTML."""
import argparse
import asyncio
import json
from datetime import datetime, timedelta
from pathlib import Path
from sqlalchemy import select, delete
from backend.config import get_settings
from backend.database import AsyncSessionLocal, engine
from backend.models import ScanJob, Report


async def maintain(db, report_root, job_days=30, report_days=90, apply=False):
    if job_days < 1 or report_days < 1:
        raise ValueError('Retention must be at least one day')
    now = datetime.utcnow()
    jobs = (await db.execute(select(ScanJob.id).where(
        ScanJob.state.in_(['completed', 'failed', 'cancelled', 'interrupted']),
        ScanJob.updated_at < now - timedelta(days=job_days)))).scalars().all()
    reports = (await db.execute(select(Report).where(Report.generated_at < now - timedelta(days=report_days)))).scalars().all()
    root = Path(report_root).resolve()
    safe, skipped = [], 0
    for report in reports:
        candidate = Path(report.file_path)
        expected = root / f'analysis_{report.analysis_result_id}.html'
        if candidate.is_symlink() or candidate.resolve() != expected:
            skipped += 1
            continue
        safe.append((report, candidate))
    if apply:
        for report, candidate in safe:
            candidate.unlink(missing_ok=True)
            await db.delete(report)
        if jobs:
            await db.execute(delete(ScanJob).where(ScanJob.id.in_(jobs)))
        await db.commit()
    return {'apply': apply, 'terminal_jobs': len(jobs), 'html_artifacts': len(safe), 'unsafe_paths_skipped': skipped,
            'retained': 'scan evidence, review decisions, append-only review events'}


async def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apply', action='store_true', help='Delete planned terminal jobs and HTML artifacts; default is dry run')
    parser.add_argument('--job-days', type=int, default=30)
    parser.add_argument('--report-days', type=int, default=90)
    args = parser.parse_args()
    try:
        async with AsyncSessionLocal() as db:
            print(json.dumps(await maintain(db, get_settings().REPORTS_DIR, args.job_days, args.report_days, args.apply)))
    finally:
        await engine.dispose()


if __name__ == '__main__':
    asyncio.run(main())
