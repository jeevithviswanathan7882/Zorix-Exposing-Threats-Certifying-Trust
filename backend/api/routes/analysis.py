"""Authenticated repository analysis and evidence retrieval routes."""

import asyncio
import json
import logging
from uuid import UUID
from typing import Literal
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, Field, HttpUrl
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.api.deps import get_current_user
from backend.database import get_db
from backend.models import AnalysisResult, BugReport, FindingReview, FindingReviewEvent, Project, Report, ScanResult, User
from backend.services.pipeline_orchestrator import VulnerabilityPipeline
from backend.services.sarif_export import build_sarif
from backend.services.scan_comparison import compare_findings

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


class RepositoryScanRequest(BaseModel):
    repo_url: HttpUrl
    github_token: str | None = None


class FindingReviewRequest(BaseModel):
    status: Literal["open", "investigating", "false_positive", "accepted_risk"]
    note: str = Field(default="", max_length=2000)


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


@router.post("/repository")
async def analyze_repository(
    request: RepositoryScanRequest,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    try:
        try:
            await asyncio.wait_for(_scan_slots.acquire(), timeout=0.1)
        except TimeoutError as exc:
            raise HTTPException(status_code=429, detail="Scanner is busy; retry later") from exc
        try:
            return await pipeline.run_repository_pipeline(
                repo_url=str(request.repo_url), github_token=request.github_token,
                db=db, user_id=user.id,
            )
        finally:
            _scan_slots.release()
    except HTTPException:
        raise
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except Exception:
        logger.exception("Repository scan failed")
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
            "commit_sha": evidence.get("commit_sha"),
            "rules_sha256": evidence.get("rules_sha256"),
            "file_count": evidence.get("file_count", 1),
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
    reviews = (await db.execute(select(FindingReview).where(
        FindingReview.analysis_result_id == analysis_id,
        FindingReview.user_id == user.id,
    ).order_by(FindingReview.finding_index))).scalars().all()
    return {
        "analysis_id": str(analysis_id),
        "root_cause": analysis.root_cause,
        "scanner_status": evidence.get("status", "unknown"),
        "verification_status": "unverified",
        "findings": evidence.get("findings", []),
        "finding_count": scan.finding_count if scan else 0,
        "reviews": [{"finding_index": review.finding_index, "status": review.status,
                     "note": review.note, "updated_at": review.updated_at.isoformat()}
                    for review in reviews],
        "commit_sha": evidence.get("commit_sha"),
        "rules_sha256": evidence.get("rules_sha256"),
        "file_count": evidence.get("file_count", 1),
        "cvss_score": None,
        "report_url": f"/api/analysis/reports/{analysis_id}/html",
        "created_at": analysis.created_at.isoformat(),
    }


@router.put("/results/{analysis_id}/findings/{finding_index}/review")
async def review_finding(
    analysis_id: UUID,
    finding_index: int,
    request: FindingReviewRequest,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    await _owned_analysis(db, user, analysis_id)
    scan = (await db.execute(select(ScanResult).where(
        ScanResult.analysis_result_id == analysis_id
    ))).scalar_one_or_none()
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan evidence not found")
    evidence = json.loads(scan.scan_output)
    if evidence.get("status") != "completed":
        raise HTTPException(status_code=409, detail="Only completed scans can be reviewed")
    findings = evidence.get("findings", [])
    if finding_index < 0 or finding_index >= len(findings):
        raise HTTPException(status_code=404, detail="Finding not found")
    note = request.note.strip()
    if request.status in ("false_positive", "accepted_risk") and not note:
        raise HTTPException(status_code=422, detail="A justification is required for this review status")
    review = (await db.execute(select(FindingReview).where(
        FindingReview.analysis_result_id == analysis_id,
        FindingReview.finding_index == finding_index,
    ))).scalar_one_or_none()
    if review is None:
        review = FindingReview(
            analysis_result_id=analysis_id, user_id=user.id,
            finding_index=finding_index, status=request.status, note=note,
        )
        db.add(review)
    else:
        review.status = request.status
        review.note = note
        review.updated_at = datetime.utcnow()
    db.add(FindingReviewEvent(
        analysis_result_id=analysis_id, user_id=user.id, finding_index=finding_index,
        status=request.status, note=note,
    ))
    await db.commit()
    return {"finding_index": finding_index, "status": review.status,
            "note": review.note, "updated_at": review.updated_at.isoformat()}


@router.get("/results/{analysis_id}/findings/{finding_index}/history")
async def finding_review_history(
    analysis_id: UUID, finding_index: int,
    db: AsyncSession = Depends(get_db), user: User = Depends(get_current_user),
):
    await _owned_analysis(db, user, analysis_id)
    events = (await db.execute(select(FindingReviewEvent).where(
        FindingReviewEvent.analysis_result_id == analysis_id,
        FindingReviewEvent.finding_index == finding_index,
        FindingReviewEvent.user_id == user.id,
    ).order_by(FindingReviewEvent.created_at, FindingReviewEvent.id))).scalars().all()
    return {"events": [{"id": str(event.id), "status": event.status, "note": event.note,
                        "event_type": event.event_type, "created_at": event.created_at.isoformat()}
                       for event in events]}


@router.get("/results/{analysis_id}/compare/{baseline_id}")
async def compare_analysis_results(
    analysis_id: UUID,
    baseline_id: UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    current = await _owned_analysis(db, user, analysis_id)
    baseline = await _owned_analysis(db, user, baseline_id)
    scopes = (await db.execute(select(BugReport.id, BugReport.repository_url, BugReport.affected_file).where(
        BugReport.id.in_([current.bug_report_id, baseline.bug_report_id])
    ))).all()
    if len({(repository, affected_file) for _, repository, affected_file in scopes}) != 1:
        raise HTTPException(status_code=422, detail="Scans must cover the same repository and scope")
    scans = (await db.execute(select(ScanResult).where(
        ScanResult.analysis_result_id.in_([analysis_id, baseline_id])
    ))).scalars().all()
    evidence = {scan.analysis_result_id: json.loads(scan.scan_output) for scan in scans}
    if analysis_id not in evidence or baseline_id not in evidence:
        raise HTTPException(status_code=404, detail="Scan evidence not found")
    try:
        changes = compare_findings(evidence[analysis_id], evidence[baseline_id])
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return {
        "analysis_id": str(analysis_id), "baseline_id": str(baseline_id),
        "commit_sha": evidence[analysis_id].get("commit_sha"),
        "baseline_commit_sha": evidence[baseline_id].get("commit_sha"),
        **changes,
    }


@router.get("/reports/{analysis_id}/{format}")
async def get_report(
    analysis_id: UUID,
    format: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    await _owned_analysis(db, user, analysis_id)
    if format == "sarif":
        scan = (await db.execute(select(ScanResult).where(
            ScanResult.analysis_result_id == analysis_id
        ))).scalar_one_or_none()
        if scan is None:
            raise HTTPException(status_code=404, detail="Scan evidence not found")
        try:
            artifact = build_sarif(json.loads(scan.scan_output))
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        return JSONResponse(
            artifact, media_type="application/sarif+json",
            headers={"Content-Disposition": f'attachment; filename="zorix_{analysis_id}.sarif"'},
        )
    if format != "html":
        raise HTTPException(status_code=404, detail="Available formats: html, sarif")
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
