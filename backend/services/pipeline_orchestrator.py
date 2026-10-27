"""Evidence-based repository analysis.

This pipeline performs static analysis only. It never labels a finding as an
exploitable vulnerability without a separate validation step.
"""

import asyncio
import base64
import html
import json
import logging
import re
import subprocess
import tempfile
from pathlib import Path, PurePosixPath
from urllib.parse import quote, urlparse

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.config import get_settings
from backend.models import AnalysisResult, BugReport, Project, Report, ScanResult
from backend.services.repository_scanner import fetch_repository_snapshot, scan_files

logger = logging.getLogger(__name__)
settings = get_settings()
RULES_PATH = Path(__file__).resolve().parents[2] / "security" / "semgrep_rules.yaml"
SUPPORTED_SUFFIXES = {".py", ".js", ".jsx", ".ts", ".tsx"}
MAX_SOURCE_BYTES = 200_000

# Kept for the WebSocket route; scan results are currently returned by HTTP.
_ws_connections: dict[str, set] = {}


def register_ws(analysis_id: str, websocket) -> None:
    _ws_connections.setdefault(analysis_id, set()).add(websocket)


def unregister_ws(analysis_id: str, websocket) -> None:
    connections = _ws_connections.get(analysis_id)
    if connections:
        connections.discard(websocket)
        if not connections:
            _ws_connections.pop(analysis_id, None)


def validate_target(repo_url: str, affected_file: str) -> tuple[str, str, str]:
    """Allow GitHub repository files only; reject traversal and arbitrary URLs."""
    url = urlparse(repo_url)
    if url.scheme != "https" or url.netloc.lower() != "github.com" or url.query or url.fragment:
        raise ValueError("Use an HTTPS github.com repository URL")
    segments = url.path.strip("/").split("/")
    if len(segments) != 2:
        raise ValueError("Repository URL must be https://github.com/owner/repository")
    owner, repo = segments
    repo = repo.removesuffix(".git")
    if any(part in (".", "..") for part in (owner, repo)) or not all(
        re.fullmatch(r"[A-Za-z0-9_.-]+", part) for part in (owner, repo)
    ):
        raise ValueError("Invalid GitHub owner or repository name")
    path = PurePosixPath(affected_file)
    if not affected_file or path.is_absolute() or any(part in (".", "..") for part in affected_file.split("/")):
        raise ValueError("Affected file must be a relative repository path")
    if "\\" in affected_file or any(ord(ch) < 32 for ch in affected_file):
        raise ValueError("Invalid affected file path")
    if path.suffix.lower() not in SUPPORTED_SUFFIXES:
        raise ValueError("Supported files: Python, JavaScript, and TypeScript")
    return owner, repo, str(path)


async def fetch_source(owner: str, repo: str, path: str, token: str | None = None) -> tuple[str, str]:
    headers = {"Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    api_url = f"https://api.github.com/repos/{owner}/{repo}/contents/{quote(path, safe='/')}"
    async with httpx.AsyncClient(timeout=20) as client:
        response = await client.get(api_url, headers=headers)
        response.raise_for_status()
        data = response.json()
    if data.get("type") != "file" or data.get("encoding") != "base64":
        raise ValueError("GitHub did not return a regular file")
    source = base64.b64decode(data.get("content", ""), validate=False)
    if len(source) > MAX_SOURCE_BYTES:
        raise ValueError("Affected file exceeds the 200 KB analysis limit")
    return source.decode("utf-8", errors="replace"), data.get("sha", "")


def run_semgrep(source: str, filename: str) -> dict:
    """Run local Semgrep rules and return only evidence the tool emitted."""
    with tempfile.TemporaryDirectory(prefix="zorix-scan-") as tmp:
        target = Path(tmp) / Path(filename).name
        target.write_text(source, encoding="utf-8")
        try:
            process = subprocess.run(
                [settings.SEMGREP_PATH, "scan", "--config", str(RULES_PATH),
                 "--json", "--metrics=off", "--disable-version-check", "--quiet", str(target)],
                capture_output=True, text=True, timeout=90, check=False,
            )
        except FileNotFoundError:
            return {"status": "unavailable", "error": "Semgrep is not installed", "findings": []}
        except subprocess.TimeoutExpired:
            return {"status": "error", "error": "Semgrep timed out", "findings": []}
        try:
            data = json.loads(process.stdout)
        except json.JSONDecodeError:
            return {"status": "error", "error": process.stderr[-500:] or "Invalid Semgrep output", "findings": []}
        if process.returncode not in (0, 1) or data.get("errors"):
            return {"status": "error", "error": "Semgrep reported a scan error", "findings": []}
        findings = []
        for item in data.get("results", []):
            extra = item.get("extra", {})
            findings.append({
                "rule_id": item.get("check_id", ""),
                "file": filename,
                "line": item.get("start", {}).get("line"),
                "severity": extra.get("severity", "INFO"),
                "message": extra.get("message", ""),
            })
        return {"status": "completed", "findings": findings}


class VulnerabilityPipeline:
    async def run_full_pipeline(
        self, repo_url: str, vulnerability_type: str, affected_file: str,
        affected_line: int | None = None, github_token: str | None = None,
        db: AsyncSession | None = None, user_id=None,
    ) -> dict:
        if db is None or user_id is None:
            raise ValueError("A database session and authenticated user are required")
        owner, repo, path = validate_target(repo_url, affected_file)
        source, blob_sha = await fetch_source(owner, repo, path, github_token or settings.GITHUB_TOKEN)
        scan = await asyncio.to_thread(run_semgrep, source, path)
        return await self._record_scan(
            db, user_id, owner, repo, path, vulnerability_type, affected_line,
            scan, {"blob_sha": blob_sha, "file_count": 1},
        )

    async def run_repository_pipeline(
        self, repo_url: str, github_token: str | None = None,
        db: AsyncSession | None = None, user_id=None,
    ) -> dict:
        if db is None or user_id is None:
            raise ValueError("A database session and authenticated user are required")
        owner, repo, _ = validate_target(repo_url, "placeholder.py")
        commit_sha, files, blob_shas = await fetch_repository_snapshot(
            owner, repo, github_token or settings.GITHUB_TOKEN
        )
        scan = await asyncio.to_thread(scan_files, files)
        return await self._record_scan(
            db, user_id, owner, repo, "(repository)", "REPOSITORY_SCAN", None,
            scan, {"commit_sha": commit_sha, "blob_shas": blob_shas, "file_count": len(files)},
        )

    async def _record_scan(
        self, db: AsyncSession, user_id, owner: str, repo: str, path: str,
        vulnerability_type: str, affected_line: int | None, scan: dict, metadata: dict,
    ) -> dict:
        findings = scan["findings"]
        canonical_url = f"https://github.com/{owner}/{repo}"

        project = (await db.execute(select(Project).where(
            Project.user_id == user_id, Project.repository_url == canonical_url
        ))).scalar_one_or_none()
        if project is None:
            project = Project(user_id=user_id, name=repo, repository_url=canonical_url)
            db.add(project)
            await db.flush()

        bug = BugReport(
            project_id=project.id, title=f"Static scan: {path}",
            description="Semgrep static analysis; findings require review",
            repository_url=canonical_url, vulnerability_type=vulnerability_type,
            affected_file=path, affected_line=affected_line, source="semgrep",
            severity="UNVERIFIED" if findings else "UNKNOWN",
        )
        db.add(bug)
        await db.flush()
        result = AnalysisResult(
            bug_report_id=bug.id,
            root_cause=f"Semgrep reported {len(findings)} potential issue(s) in {path}. Manual review required."
            if scan["status"] == "completed" else f"Static scan unavailable: {scan.get('error', 'unknown error')}",
            confidence_score=0.0,
        )
        db.add(result)
        await db.flush()
        evidence = {"status": scan["status"], **metadata,
                    "findings": findings, "error": scan.get("error")}
        db.add(ScanResult(
            analysis_result_id=result.id, scan_type="static", scanner_name="semgrep",
            finding_count=len(findings),
            high_count=sum(f["severity"] == "ERROR" for f in findings),
            medium_count=sum(f["severity"] == "WARNING" for f in findings),
            low_count=sum(f["severity"] == "INFO" for f in findings),
            scan_output=json.dumps(evidence),
        ))
        report_path = Path(settings.REPORTS_DIR) / f"analysis_{result.id}.html"
        report_path.parent.mkdir(parents=True, exist_ok=True)
        rows = "".join(
            f"<tr><td>{html.escape(str(f['rule_id']))}</td><td>{html.escape(str(f['file']))}:{f['line']}</td>"
            f"<td>{html.escape(str(f['severity']))}</td><td>{html.escape(str(f['message']))}</td></tr>"
            for f in findings
        )
        report_path.write_text(
            "<!doctype html><meta charset='utf-8'><title>Zorix static scan</title>"
            "<h1>Zorix static scan</h1><p>Potential findings require manual review. "
            "No exploit validation or CVSS scoring was performed.</p>"
            f"<p>Repository: {html.escape(canonical_url)}<br>Scope: {html.escape(path)}"
            f"<br>Commit SHA: {html.escape(metadata.get('commit_sha', 'not pinned for single-file scan'))}"
            f"<br>GitHub blob SHA: {html.escape(metadata.get('blob_sha', 'see stored scan evidence'))}"
            f"<br>Files scanned: {metadata['file_count']}<br>Scanner: {html.escape(scan['status'])}</p>"
            "<table border='1'><tr><th>Rule</th><th>Location</th><th>Severity</th><th>Message</th></tr>"
            f"{rows}</table>", encoding="utf-8",
        )
        db.add(Report(
            analysis_result_id=result.id, report_format="html",
            file_path=str(report_path), file_size=report_path.stat().st_size,
        ))
        await db.commit()
        return {
            "status": scan["status"], "analysis_id": str(result.id),
            "scanner_status": scan["status"], "verification_status": "unverified",
            "score": None, "severity": "UNVERIFIED" if findings else "UNKNOWN",
            "report_url": f"/api/analysis/reports/{result.id}/html",
            "vulnerable": None, "exploits_tested": 0, "vulnerabilities_confirmed": 0,
            "confidence_score": None, "findings": findings, "error": scan.get("error"),
            "commit_sha": metadata.get("commit_sha"), "file_count": metadata["file_count"],
        }
