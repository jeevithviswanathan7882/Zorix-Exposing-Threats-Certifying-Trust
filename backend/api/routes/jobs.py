"""Owner-scoped background scan submissions and status."""
from uuid import UUID
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, HttpUrl, Field
from sqlalchemy import select, update
from backend.api.deps import get_current_user
from backend.database import get_db
from backend.models import ScanJob
from backend.services.scan_jobs import manager, JobLimitError

router = APIRouter(prefix='/jobs', tags=['scan jobs'])


class SubmitJob(BaseModel):
    repo_url: HttpUrl
    affected_file: str = Field(default='(repository)', max_length=1024)
    github_token: str | None = Field(default=None, max_length=512)


def serialize(job):
    return {'id': str(job.id), 'repository': job.repository, 'affected_file': job.affected_file,
            'state': job.state, 'analysis_id': str(job.analysis_id) if job.analysis_id else None,
            'error': job.error, 'created_at': job.created_at.isoformat()}


@router.post('', status_code=202)
async def submit_job(request: SubmitJob, db=Depends(get_db), user=Depends(get_current_user)):
    try:
        return serialize(await manager.submit(db, user.id, str(request.repo_url), request.affected_file, request.github_token))
    except JobLimitError as exc:
        raise HTTPException(status_code=429, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get('')
async def list_jobs(db=Depends(get_db), user=Depends(get_current_user)):
    rows = (await db.execute(select(ScanJob).where(ScanJob.user_id == user.id)
                            .order_by(ScanJob.created_at.desc()).limit(50))).scalars().all()
    return {'jobs': [serialize(job) for job in rows]}


@router.get('/{job_id}')
async def get_job(job_id: UUID, db=Depends(get_db), user=Depends(get_current_user)):
    job = (await db.execute(select(ScanJob).where(ScanJob.id == job_id, ScanJob.user_id == user.id))).scalar_one_or_none()
    if not job:
        raise HTTPException(status_code=404, detail='Job not found')
    return serialize(job)


@router.post('/{job_id}/cancel')
async def cancel_job(job_id: UUID, db=Depends(get_db), user=Depends(get_current_user)):
    await get_job(job_id, db, user)
    result = await db.execute(update(ScanJob).where(ScanJob.id == job_id, ScanJob.user_id == user.id,
        ScanJob.state == 'queued').values(state='cancelled', updated_at=datetime.utcnow()))
    if not result.rowcount:
        raise HTTPException(status_code=409, detail='Only queued jobs can be cancelled')
    await db.commit()
    return {'state': 'cancelled'}
