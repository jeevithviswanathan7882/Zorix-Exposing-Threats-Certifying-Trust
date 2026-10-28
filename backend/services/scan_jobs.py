"""Bounded single-process scan queue with durable status and memory-only tokens."""
import asyncio
import logging
from datetime import datetime, timedelta
from uuid import UUID

from sqlalchemy import select, update, func
from backend.database import AsyncSessionLocal
from backend.models import ScanJob, AnalysisResult, BugReport, Project
from backend.services.pipeline_orchestrator import VulnerabilityPipeline, validate_target

logger = logging.getLogger(__name__)
scan_slots = asyncio.Semaphore(2)


class JobLimitError(ValueError):
    pass


class ScanJobManager:
    def __init__(self, sessions=AsyncSessionLocal, queue_size=20, daily_limit=20):
        self.sessions = sessions
        self.queue = asyncio.Queue(maxsize=queue_size)
        self.daily_limit = daily_limit
        self.tasks = []
        self.admission = asyncio.Lock()
        self.pipeline = VulnerabilityPipeline()

    async def start(self):
        # Supported topology: one API process. Restarted jobs fail explicitly;
        # credentials are intentionally not persisted for replay.
        async with self.sessions() as db:
            await db.execute(update(ScanJob).where(ScanJob.state.in_(['queued', 'running'])).values(
                state='interrupted', error='Service restarted; resubmit the scan', updated_at=datetime.utcnow()))
            await db.commit()
        self.tasks = [asyncio.create_task(self.worker()) for _ in range(2)]

    async def stop(self):
        for task in self.tasks:
            task.cancel()
        await asyncio.gather(*self.tasks, return_exceptions=True)
        self.tasks = []
        async with self.sessions() as db:
            await db.execute(update(ScanJob).where(ScanJob.state.in_(['queued', 'running'])).values(
                state='interrupted', error='Service stopped; resubmit the scan', updated_at=datetime.utcnow()))
            await db.commit()
        while not self.queue.empty():
            self.queue.get_nowait()
            self.queue.task_done()

    async def check_quota(self, db, user_id):
        recent = (await db.execute(select(func.count()).select_from(ScanJob).where(
            ScanJob.user_id == user_id, ScanJob.created_at >= datetime.utcnow() - timedelta(days=1)))).scalar_one()
        pending = (await db.execute(select(func.count()).select_from(ScanJob).where(
            ScanJob.user_id == user_id, ScanJob.state.in_(['queued', 'running'])))).scalar_one()
        imported = (await db.execute(select(func.count()).select_from(AnalysisResult).join(BugReport).join(Project).where(
            Project.user_id == user_id, BugReport.source == 'imported',
            AnalysisResult.created_at >= datetime.utcnow() - timedelta(days=1)))).scalar_one()
        if recent + imported >= self.daily_limit or pending >= 2:
            raise JobLimitError(f'Job quota reached: at most 2 pending jobs and {self.daily_limit} submissions per rolling day')

    async def submit(self, db, user_id, repository, affected_file, github_token=None, enqueue=True):
        validate_target(repository, affected_file if affected_file != '(repository)' else 'scan.py')
        async with self.admission:
            await self.check_quota(db, user_id)
            if enqueue and self.queue.full():
                raise JobLimitError('Job queue is full; retry later')
            job = ScanJob(user_id=user_id, repository=repository, affected_file=affected_file, state='queued')
            db.add(job)
            await db.commit()
            if enqueue:
                self.queue.put_nowait((job.id, github_token))
            return job

    async def run_sync(self, db, user_id, repository, affected_file, github_token=None,
                       vulnerability_type='UNSPECIFIED', affected_line=None):
        job = await self.submit(db, user_id, repository, affected_file, github_token, enqueue=False)
        job_id = job.id
        job.state = 'running'
        await db.commit()
        try:
            if affected_file == '(repository)':
                result = await self.pipeline.run_repository_pipeline(repository, github_token, db, user_id)
            else:
                result = await self.pipeline.run_full_pipeline(repository, vulnerability_type, affected_file,
                    affected_line, github_token, db, user_id)
        except BaseException:
            await db.rollback()
            job = await db.get(ScanJob, job_id)
            job.state = 'failed'
            job.error = 'Repository fetch or scan failed'
            job.updated_at = datetime.utcnow()
            await db.commit()
            raise
        job.analysis_id = UUID(result['analysis_id'])
        job.state = 'completed' if result['status'] == 'completed' else 'failed'
        job.error = result.get('error')
        job.updated_at = datetime.utcnow()
        await db.commit()
        return result

    async def worker(self):
        while True:
            job_id, token = await self.queue.get()
            try:
                async with scan_slots:
                    async with self.sessions() as db:
                        claimed = (await db.execute(update(ScanJob).where(ScanJob.id == job_id,
                            ScanJob.state == 'queued').values(state='running', updated_at=datetime.utcnow())
                            .returning(ScanJob.id))).scalar_one_or_none()
                        await db.commit()
                        if claimed is None:
                            continue
                        job = await db.get(ScanJob, job_id)
                        try:
                            if job.affected_file == '(repository)':
                                result = await self.pipeline.run_repository_pipeline(job.repository, token, db, job.user_id)
                            else:
                                result = await self.pipeline.run_full_pipeline(job.repository, 'UNSPECIFIED', job.affected_file,
                                    github_token=token, db=db, user_id=job.user_id)
                            job.analysis_id = UUID(result['analysis_id'])
                            job.state = 'completed' if result['status'] == 'completed' else 'failed'
                            job.error = result.get('error')
                        except Exception:
                            await db.rollback()
                            logger.exception('Background scan failed: %s', job_id)
                            job = await db.get(ScanJob, job_id)
                            job.state = 'failed'
                            job.error = 'Repository fetch or scan failed; check target, access, and scanner availability'
                        job.updated_at = datetime.utcnow()
                        await db.commit()
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception('Worker database operation failed: %s', job_id)
                # Preserve the worker and release the account's pending slot
                # once the database recovers; shutdown can cancel this retry.
                while True:
                    try:
                        async with self.sessions() as recovery:
                            await recovery.execute(update(ScanJob).where(ScanJob.id == job_id,
                                ScanJob.state.in_(['queued', 'running'])).values(state='failed',
                                error='Worker storage operation failed; resubmit', updated_at=datetime.utcnow()))
                            await recovery.commit()
                        break
                    except Exception:
                        await asyncio.sleep(1)
            finally:
                token = None
                self.queue.task_done()


manager = ScanJobManager()
