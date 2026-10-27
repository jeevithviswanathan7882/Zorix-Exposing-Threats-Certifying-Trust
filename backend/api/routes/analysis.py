"""Authenticated repository analysis and evidence retrieval routes."""

import asyncio
import json
import logging
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel, HttpUrl
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.api.deps import get_current_user
from backend.database import get_db
from backend.models import AnalysisResult, BugReport, Project, Report, ScanResult, User
from backend.services.pipeline_orchestrator import VulnerabilityPipeline

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/analysis", tags=["analysis"])
pipeline = VulnerabilityPipeline()
_scan_slots = asyncio.Semaphore(2)


class AnalyzeRequest(BaseModel):
    repo_url: HttpUrl
    vulnerability_type: str = "UNSPECIFIED"
    affected_file: str
    affected_line: int | None = None
    github_token: str | None = None


async def _owned_analysis(db: AsyncSession, user: User, analysis_id: UUID) -> AnalysisResult:
    query = (
        select(AnalysisResult)
        .join(BugReport, AnalysisResult.bug_report_id == BugReport.id)
        .join(Project, BugReport.project_id == Project.id)
        .where(AnalysisResult.id == analysis_id, Project.user_id == user.id)
    )
    result = (await db.execute(query)).scalar_one_or_none()
    if result is None:
        raise HTTPException(status_code=404, detail="Analysis not found")
    return result


@router.get("/health")
async def analysis_health():
    return {"status": "ok"}


@router.post("/analyze")
async def analyze_vulnerability(
    request: AnalyzeRequest,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    try:
        try:
            await asyncio.wait_for(_scan_slots.acquire(), timeout=0.1)
        except TimeoutError as exc:
            raise HTTPException(status_code=429, detail="Scanner is busy; retry later") from exc
        try:
            return await pipeline.run_full_pipeline(
                repo_url=str(request.repo_url),
                vulnerability_type=request.vulnerability_type,
                affected_file=request.affected_file,
                affected_line=request.affected_line,
                github_token=request.github_token,
                db=db,
                user_id=user.id,
            )
        finally:
            _scan_slots.release()
    except HTTPException:
        raise
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except Exception:
        logger.exception("Analysis failed")
        raise HTTPException(status_code=502, detail="Repository fetch or scan failed")


@router.get("/results")
async def get_all_results(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    query = (
        select(AnalysisResult, BugReport, ScanResult)
        .join(BugReport, AnalysisResult.bug_report_id == BugReport.id)
        .join(Project, BugReport.project_id == Project.id)
        .outerjoin(ScanResult, ScanResult.analysis_result_id == AnalysisResult.id)
        .where(Project.user_id == user.id)
        .order_by(AnalysisResult.created_at.desc())
    )
    rows = (await db.execute(query)).all()
    results = []
    for analysis, bug, scan in rows:
        evidence = json.loads(scan.scan_output) if scan and scan.scan_output else {}
        results.append({
            "id": str(analysis.id),
            "repository": bug.repository_url,
            "affected_file": bug.affected_file,
            "vulnerability_type": bug.vulnerability_type,
            "status": evidence.get("status", "unknown"),
            "scanner_status": evidence.get("status", "unknown"),
            "verification_status": "unverified",
            "finding_count": scan.finding_count if scan else 0,
            "findings": evidence.get("findings", []),
            "cvss_score": None,
            "severity": "UNVERIFIED" if scan and scan.finding_count else "UNKNOWN",
            "root_cause": analysis.root_cause,
            "confidence_score": None,
            "created_at": analysis.created_at.isoformat(),
        })
    return {"results": results, "total": len(results)}


@router.get("/results/{analysis_id}")
async def get_analysis_results(
    analysis_id: UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    analysis = await _owned_analysis(db, user, analysis_id)
    scan = (await db.execute(select(ScanResult).where(
        ScanResult.analysis_result_id == analysis_id
    ))).scalar_one_or_none()
    evidence = json.loads(scan.scan_output) if scan and scan.scan_output else {}
    return {
        "analysis_id": str(analysis_id),
        "root_cause": analysis.root_cause,
        "scanner_status": evidence.get("status", "unknown"),
        "verification_status": "unverified",
        "findings": evidence.get("findings", []),
        "finding_count": scan.finding_count if scan else 0,
        "cvss_score": None,
        "report_url": f"/api/analysis/reports/{analysis_id}/html",
        "created_at": analysis.created_at.isoformat(),
    }


@router.get("/reports/{analysis_id}/{format}")
async def get_report(
    analysis_id: UUID,
    format: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    await _owned_analysis(db, user, analysis_id)
    if format != "html":
        raise HTTPException(status_code=404, detail="Only HTML reports are available")
    report = (await db.execute(select(Report).where(
        Report.analysis_result_id == analysis_id, Report.report_format == "html"
    ))).scalar_one_or_none()
    if report is None:
        raise HTTPException(status_code=404, detail="Report not found")
    return FileResponse(report.file_path, media_type="text/html",
                        filename=f"zorix_{analysis_id}.html")


@router.get("/exploit-results/{analysis_id}")
async def get_exploit_results(
    analysis_id: UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    await _owned_analysis(db, user, analysis_id)
    return {"results": [], "total": 0,
            "message": "Exploit validation is not part of the current static scan"}


@router.get("/ai-health")
async def ai_health():
    return {"status": "not_used", "message": "AI is not used in the current static scan"}
