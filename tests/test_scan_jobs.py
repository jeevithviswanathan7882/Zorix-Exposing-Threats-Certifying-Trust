import asyncio
from uuid import uuid4
import httpx
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
from backend.database import Base, get_db
from backend.main import app
from backend.models import User, ScanJob
from backend.core.security import create_access_token
from backend.api.routes import jobs as routes
from backend.services.scan_jobs import ScanJobManager


def test_queue_ownership_cancellation_limits_and_worker(tmp_path, monkeypatch):
    async def scenario():
        engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'jobs.db'}")
        async with engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)
        sessions = async_sessionmaker(engine, expire_on_commit=False)
        manager = ScanJobManager(sessions, queue_size=2, daily_limit=2)
        monkeypatch.setattr(routes, 'manager', manager)
        ids = [uuid4(), uuid4()]
        async with sessions() as db:
            db.add_all([User(id=value, email=f'{value}@example.com', password_hash='unused', role='user') for value in ids])
            await db.commit()
        async def override_db():
            async with sessions() as db:
                yield db
        app.dependency_overrides[get_db] = override_db
        seen_tokens = []
        class Pipeline:
            async def run_repository_pipeline(self, repository, token, db, user_id):
                seen_tokens.append(token)
                return {'analysis_id': str(uuid4()), 'status': 'completed'}
        manager.pipeline = Pipeline()
        headers = [{'Authorization': f"Bearer {create_access_token({'sub': str(value)})}"} for value in ids]
        payload = {'repo_url': 'https://github.com/example/project', 'github_token': 'memory-only-token'}
        try:
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url='http://test') as client:
                first = await client.post('/api/jobs', json=payload, headers=headers[0])
                second = await client.post('/api/jobs', json=payload, headers=headers[0])
                assert first.status_code == second.status_code == 202
                assert 'memory-only-token' not in first.text
                assert (await client.post('/api/jobs', json=payload, headers=headers[0])).status_code == 429
                assert (await client.post('/api/jobs', json=payload, headers=headers[1])).status_code == 429
                first_id, second_id = first.json()['id'], second.json()['id']
                assert (await client.get(f'/api/jobs/{first_id}', headers=headers[1])).status_code == 404
                assert (await client.post(f'/api/jobs/{first_id}/cancel', headers=headers[0])).status_code == 200
                manager.tasks = [asyncio.create_task(manager.worker())]
                await asyncio.wait_for(manager.queue.join(), timeout=3)
                assert (await client.get(f'/api/jobs/{first_id}', headers=headers[0])).json()['state'] == 'cancelled'
                assert (await client.get(f'/api/jobs/{second_id}', headers=headers[0])).json()['state'] == 'completed'
                assert seen_tokens == ['memory-only-token']
                assert (await client.post(f'/api/jobs/{second_id}/cancel', headers=headers[0])).status_code == 409
                assert (await client.post('/api/jobs', json=payload, headers=headers[0])).status_code == 429
        finally:
            await manager.stop()
            app.dependency_overrides.clear()
            await engine.dispose()
    asyncio.run(scenario())


def test_restart_marks_unreplayable_jobs_interrupted(tmp_path):
    async def scenario():
        engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'restart.db'}")
        async with engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)
        sessions = async_sessionmaker(engine, expire_on_commit=False)
        user_id = uuid4()
        async with sessions() as db:
            db.add(User(id=user_id, email='restart@example.com', password_hash='unused', role='user'))
            job = ScanJob(user_id=user_id, repository='https://github.com/example/project', affected_file='app.py', state='running')
            db.add(job)
            await db.commit()
            job_id = job.id
        manager = ScanJobManager(sessions)
        await manager.start()
        try:
            async with sessions() as db:
                job = await db.get(ScanJob, job_id)
                assert job.state == 'interrupted'
                assert 'resubmit' in job.error
        finally:
            await manager.stop()
            await engine.dispose()
    asyncio.run(scenario())
