import asyncio
from datetime import datetime, timedelta
from types import SimpleNamespace
from uuid import uuid4
from sqlalchemy import select
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
from backend.database import Base
from backend.models import ScanJob, Report
from backend.services.security_event import build_security_event
from backend.tools.check_policy import check
from backend.tools.maintenance import maintain
from backend.config import Settings


def test_policy_keeps_accepted_risk_blocking_and_rejects_incomplete_scan():
    evidence = {'status': 'completed', 'findings': [{'severity': 'ERROR', 'rule_id': 'demo'}]}
    review = SimpleNamespace(finding_index=0, status='accepted_risk')
    event = build_security_event('id', 'repo', evidence, [review])
    assert check(event) == 1
    review.status = 'false_positive'
    assert check(build_security_event('id', 'repo', evidence, [review])) == 0
    evidence['status'] = 'error'
    assert check(build_security_event('id', 'repo', evidence, [review])) == 1


def test_secret_files_override_environment_values(tmp_path):
    api_secret, db_secret = tmp_path / 'api', tmp_path / 'db'
    api_secret.write_text('a' * 48 + '\n')
    db_secret.write_text('password@with:symbols\n')
    settings = Settings(_env_file=None, SECRET_KEY='environment-value', SECRET_KEY_FILE=str(api_secret),
                        POSTGRES_PASSWORD_FILE=str(db_secret))
    assert settings.SECRET_KEY == 'a' * 48
    assert settings.POSTGRES_PASSWORD == 'password@with:symbols'


def test_retention_dry_run_and_apply_preserve_active_jobs_and_unsafe_paths(tmp_path):
    async def scenario():
        engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'retention.db'}")
        async with engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)
        sessions = async_sessionmaker(engine, expire_on_commit=False)
        root = tmp_path / 'reports'
        root.mkdir()
        analysis_id = uuid4()
        safe = root / f'analysis_{analysis_id}.html'
        safe.write_text('generated')
        outside = tmp_path / 'keep.txt'
        outside.write_text('must remain')
        old = datetime.utcnow() - timedelta(days=100)
        async with sessions() as db:
            db.add_all([
                ScanJob(user_id=uuid4(), repository='repo', affected_file='app.py', state='completed', updated_at=old),
                ScanJob(user_id=uuid4(), repository='repo', affected_file='app.py', state='running', updated_at=old),
                Report(analysis_result_id=analysis_id, report_format='html', file_path=str(safe), file_size=9, generated_at=old),
                Report(analysis_result_id=uuid4(), report_format='html', file_path=str(outside), file_size=11, generated_at=old),
            ])
            await db.commit()
            plan = await maintain(db, root)
            assert plan['terminal_jobs'] == plan['html_artifacts'] == plan['unsafe_paths_skipped'] == 1
            assert safe.exists()
            await maintain(db, root, apply=True)
            assert not safe.exists() and outside.exists()
            remaining = (await db.execute(select(ScanJob))).scalars().all()
            assert len(remaining) == 1 and remaining[0].state == 'running'
        await engine.dispose()
    asyncio.run(scenario())
