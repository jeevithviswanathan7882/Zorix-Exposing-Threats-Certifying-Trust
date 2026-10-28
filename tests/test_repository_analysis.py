"""Tests for scan evidence, input validation, and user isolation."""

import asyncio
import base64
import hashlib
import os
import sqlite3
import subprocess
import sys
from pathlib import Path

import httpx
import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.dialects import postgresql, sqlite
from sqlalchemy.engine import make_url

from backend.api.routes import analysis as analysis_routes
from backend.database import Base, get_db
from backend.main import app
from backend import main as main_module
from backend.services import pipeline_orchestrator as pipeline_module
from backend.models import GUID
from backend.config import Settings
from backend.core.security import create_access_token


def test_uuid_type_uses_the_database_dialect():
    assert str(GUID().compile(dialect=sqlite.dialect())) == 'CHAR(36)'
    assert str(GUID().compile(dialect=postgresql.dialect())) == 'UUID'


def test_database_password_is_url_encoded():
    password = 'test@password:with/slashes%and#symbols'
    settings = Settings(_env_file=None, DATABASE_TYPE='postgres', POSTGRES_PASSWORD=password)
    assert make_url(settings.DATABASE_URL).password == password


def test_production_refuses_development_secret(monkeypatch):
    monkeypatch.setattr(main_module.settings, 'DEBUG', False)
    monkeypatch.setattr(main_module.settings, 'SECRET_KEY',
                        'your-super-secret-key-change-this-in-production-12345')
    with pytest.raises(RuntimeError, match='unique SECRET_KEY'):
        main_module.validate_runtime_secret()


def test_database_migrations_create_current_schema(tmp_path):
    database_url = f"sqlite+aiosqlite:///{tmp_path / 'migrated.db'}"
    env = {**os.environ, "ALEMBIC_DATABASE_URL": database_url}
    root = Path(__file__).resolve().parents[1]
    for command in ("upgrade", "check"):
        args = [sys.executable, "-m", "alembic", "-c", "backend/alembic.ini", command]
        if command == "upgrade":
            args.append("head")
        result = subprocess.run(args, cwd=root, env=env, capture_output=True, text=True, check=False)
        assert result.returncode == 0, result.stderr or result.stdout

    with sqlite3.connect(tmp_path / 'migrated.db') as connection:
        connection.execute("INSERT INTO finding_review_events VALUES ('event', 'scan', 'user', 0, 'open', 'Original', 'review_saved', '2026-10-28')")
        for statement in ("UPDATE finding_review_events SET note='Changed'", "DELETE FROM finding_review_events"):
            with pytest.raises(sqlite3.IntegrityError, match='append-only'):
                connection.execute(statement)

    # A database initialized by the previous create_all flow is adopted only
    # when it already has the exact current table and column set.
    legacy_url = f"sqlite+aiosqlite:///{tmp_path / 'legacy.db'}"
    async def create_legacy_schema():
        engine = create_async_engine(legacy_url)
        async with engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)
        await engine.dispose()
    asyncio.run(create_legacy_schema())
    with sqlite3.connect(tmp_path / 'legacy.db') as connection:
        connection.execute('DROP TABLE finding_review_events')
        connection.execute('DROP TABLE finding_reviews')
    env["ALEMBIC_DATABASE_URL"] = legacy_url
    for command in ("upgrade", "check"):
        args = [sys.executable, "-m", "alembic", "-c", "backend/alembic.ini", command]
        if command == "upgrade":
            args.append("head")
        result = subprocess.run(args, cwd=root, env=env, capture_output=True, text=True, check=False)
        assert result.returncode == 0, result.stderr or result.stdout

    with sqlite3.connect(tmp_path / 'legacy.db') as connection:
        connection.execute('DROP TABLE finding_review_events')
        connection.execute('DELETE FROM alembic_version')
        connection.execute('ALTER TABLE users ADD COLUMN unexpected TEXT')
    result = subprocess.run(
        [sys.executable, '-m', 'alembic', '-c', 'backend/alembic.ini', 'upgrade', 'head'],
        cwd=root, env=env, capture_output=True, text=True, check=False,
    )
    assert result.returncode != 0
    assert 'columns differ' in result.stderr


def test_target_validation_rejects_arbitrary_hosts_and_traversal():
    valid = pipeline_module.validate_target("https://github.com/example/project", "src/app.py")
    assert valid == ("example", "project", "src/app.py")
    for repo_url, path in (
        ("https://github.com.evil.test/example/project", "src/app.py"),
        ("http://github.com/example/project", "src/app.py"),
        ("https://github.com/example/project", "../secrets.py"),
        ("https://github.com/example/project", "/etc/passwd.py"),
        ("https://github.com/example/project", "src\\app.py"),
    ):
        with pytest.raises(ValueError):
            pipeline_module.validate_target(repo_url, path)


def test_github_fetch_deadline_covers_both_scan_modes(monkeypatch):
    async def slow_fetch(*args, **kwargs):
        await asyncio.sleep(10)
    monkeypatch.setattr(pipeline_module, 'FETCH_DEADLINE_SECONDS', 0.001)
    monkeypatch.setattr(pipeline_module, 'fetch_source', slow_fetch)
    monkeypatch.setattr(pipeline_module, 'fetch_repository_snapshot', slow_fetch)

    async def scenario():
        pipeline = pipeline_module.VulnerabilityPipeline()
        with pytest.raises(ValueError, match='time limit'):
            await pipeline.run_full_pipeline(
                'https://github.com/example/project', 'UNSPECIFIED', 'app.py',
                db=object(), user_id='test-user',
            )
        with pytest.raises(ValueError, match='time limit'):
            await pipeline.run_repository_pipeline(
                'https://github.com/example/project', db=object(), user_id='test-user',
            )
    asyncio.run(scenario())


def test_semgrep_reports_real_rule_and_clean_file(monkeypatch):
    monkeypatch.setattr(pipeline_module.settings, "SEMGREP_PATH", os.environ.get(
        "SEMGREP_PATH", str(Path(sys.executable).parent / "semgrep")
    ))
    if not Path(pipeline_module.settings.SEMGREP_PATH).exists():
        pytest.skip("Local Semgrep executable is unavailable")
    flagged = pipeline_module.run_semgrep("import os\nos.system(user_input)\n", "app.py")
    clean = pipeline_module.run_semgrep("print('hello')\n", "app.py")
    assert flagged["status"] == clean["status"] == "completed"
    assert any(item["rule_id"].endswith("os-system-call") for item in flagged["findings"])
    assert clean["findings"] == []
    assert flagged["rules_sha256"] == clean["rules_sha256"] == hashlib.sha256(pipeline_module.RULES_PATH.read_bytes()).hexdigest()
    assert any(item["rule_id"] == "os-system-call" for item in flagged["findings"])


def test_single_file_fetch_uses_pinned_commit(monkeypatch):
    commit_sha = "a" * 40
    blob_sha = "b" * 40
    requested_ref = []
    source_bytes = b"print('hello')\n"

    def handler(request):
        if request.url.path == "/repos/example/project":
            return httpx.Response(200, json={"default_branch": "main"})
        if request.url.path.endswith("/commits/main"):
            return httpx.Response(200, json={"sha": commit_sha})
        if request.url.path.endswith("/contents/src/app.py"):
            requested_ref.append(request.url.params.get("ref"))
            return httpx.Response(200, json={"type": "file", "encoding": "base64",
                                             "sha": blob_sha,
                                             "content": base64.b64encode(source_bytes).decode() + "\n"})
        return httpx.Response(404)

    client_type = httpx.AsyncClient
    monkeypatch.setattr(pipeline_module.httpx, "AsyncClient",
                        lambda **kwargs: client_type(transport=httpx.MockTransport(handler), **kwargs))
    source, blob, commit = asyncio.run(pipeline_module.fetch_source("example", "project", "src/app.py"))
    assert (source, blob, commit) == ("print('hello')\n", blob_sha, commit_sha)
    assert requested_ref == [commit_sha]
    source_bytes = b"\xff\xfe"
    with pytest.raises(ValueError, match="UTF-8"):
        asyncio.run(pipeline_module.fetch_source("example", "project", "src/app.py"))


def test_repository_snapshot_is_commit_pinned_and_rejects_incomplete_trees(monkeypatch):
    from backend.services import repository_scanner

    commit_sha = "a" * 40
    blob_sha = "b" * 40
    requested = []
    truncated = False
    rate_limited = False
    blob_content = b"print('hello')\n"

    def handler(request):
        requested.append(str(request.url))
        if request.url.path == "/repos/example/project":
            if rate_limited:
                return httpx.Response(403, headers={"X-RateLimit-Remaining": "0"})
            return httpx.Response(200, json={"default_branch": "main"})
        if request.url.path.endswith("/commits/main"):
            return httpx.Response(200, json={"sha": commit_sha})
        if request.url.path.endswith(f"/git/trees/{commit_sha}"):
            return httpx.Response(200, json={"truncated": truncated, "tree": [
                {"type": "blob", "path": "src/app.py", "sha": blob_sha, "size": 17},
                {"type": "blob", "path": "node_modules/noise.py", "sha": blob_sha, "size": 17},
            ]})
        if request.url.path.endswith(f"/git/blobs/{blob_sha}"):
            return httpx.Response(200, json={"sha": blob_sha, "encoding": "base64",
                                             "content": base64.b64encode(blob_content).decode() + "\n"})
        return httpx.Response(404)

    client_type = httpx.AsyncClient
    transport = httpx.MockTransport(handler)
    monkeypatch.setattr(repository_scanner.httpx, "AsyncClient",
                        lambda **kwargs: client_type(transport=transport, **kwargs))

    async def scenario():
        nonlocal truncated, rate_limited, blob_content
        sha, files, blob_shas = await repository_scanner.fetch_repository_snapshot("example", "project")
        assert sha == commit_sha
        assert files == {"src/app.py": "print('hello')\n"}
        assert blob_shas == {"src/app.py": blob_sha}
        assert any(f"/git/trees/{commit_sha}" in url for url in requested)
        assert all("/contents/" not in url for url in requested)
        truncated = True
        with pytest.raises(ValueError, match="truncated"):
            await repository_scanner.fetch_repository_snapshot("example", "project")
        truncated = False
        monkeypatch.setattr(repository_scanner, "MAX_FILES", 0)
        with pytest.raises(ValueError, match="more than 0"):
            await repository_scanner.fetch_repository_snapshot("example", "project")
        monkeypatch.setattr(repository_scanner, "MAX_FILES", 100)
        blob_content = b"\xff\xfe"
        with pytest.raises(ValueError, match="UTF-8"):
            await repository_scanner.fetch_repository_snapshot("example", "project")
        blob_content = b"print('hello')\n"
        rate_limited = True
        with pytest.raises(ValueError, match="rate limit"):
            await repository_scanner.fetch_repository_snapshot("example", "project")

    asyncio.run(scenario())


def test_repository_semgrep_preserves_relative_paths(monkeypatch):
    from backend.services import repository_scanner

    monkeypatch.setattr(pipeline_module.settings, "SEMGREP_PATH", os.environ.get(
        "SEMGREP_PATH", str(Path(sys.executable).parent / "semgrep")
    ))
    if not Path(pipeline_module.settings.SEMGREP_PATH).exists():
        pytest.skip("Local Semgrep executable is unavailable")
    result = repository_scanner.scan_files({"src/app.py": "import os\nos.system(user_input)\n"})
    assert result["status"] == "completed"
    assert result["rules_sha256"] == hashlib.sha256(pipeline_module.RULES_PATH.read_bytes()).hexdigest()
    assert any(item["file"] == "src/app.py" for item in result["findings"])


def test_sarif_rejects_failed_scan():
    from backend.services.sarif_export import build_sarif

    with pytest.raises(ValueError, match="completed"):
        build_sarif({"status": "error", "findings": []})


def test_scan_comparison_tracks_duplicate_findings_and_failed_scans():
    from backend.services.scan_comparison import compare_findings

    finding = {"rule_id": "rule", "file": "app.py", "line": 2, "severity": "WARNING", "message": "Review"}
    changes = compare_findings(
        {"status": "completed", "findings": [finding, finding]},
        {"status": "completed", "findings": [finding]},
    )
    assert changes["introduced_count"] == 1
    assert changes["resolved_count"] == 0
    assert changes["unchanged_count"] == 1
    assert "could not be checked" in changes["note"]
    with pytest.raises(ValueError, match="different rule sets"):
        compare_findings(
            {"status": "completed", "findings": [finding], "rules_sha256": "a" * 64},
            {"status": "completed", "findings": [finding], "rules_sha256": "b" * 64},
        )
    with pytest.raises(ValueError, match="completed"):
        compare_findings({"status": "error", "findings": []}, {"status": "completed", "findings": []})


def test_authentication_and_scan_ownership(tmp_path, monkeypatch):
    async def scenario():
        engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'test.db'}")
        async with engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)
        sessions = async_sessionmaker(engine, expire_on_commit=False)

        async def override_db():
            async with sessions() as session:
                yield session

        async def fake_fetch(owner, repo, path, token=None):
            return "import os\nos.system(user_input)\n", "b" * 40, "a" * 40

        monkeypatch.setattr(pipeline_module, "fetch_source", fake_fetch)
        monkeypatch.setattr(pipeline_module, "run_semgrep", lambda source, filename: {
            "status": "completed", "rules_sha256": "c" * 64,
            "findings": [{"rule_id": "os-system-call", "file": filename, "line": 2,
                          "severity": "ERROR", "message": "Potential <script>alert(1)</script>"}],
        })
        monkeypatch.setattr(pipeline_module, "fetch_repository_snapshot",
                            lambda *args, **kwargs: asyncio.sleep(0, result=("a" * 40, {"src/app.py": "print(1)"}, {"src/app.py": "b" * 40})))
        monkeypatch.setattr(pipeline_module, "scan_files", lambda files: {
            "status": "completed", "findings": [],
        })
        monkeypatch.setattr(pipeline_module.settings, "REPORTS_DIR", str(tmp_path / "reports"))
        app.dependency_overrides[get_db] = override_db
        try:
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as client:
                malformed_subject = create_access_token({"sub": "not-a-user-id"})
                assert (await client.get('/api/analysis/results', headers={
                    'Authorization': f'Bearer {malformed_subject}',
                })).status_code == 401
                tokens = []
                for address in ("alice@example.com", "bob@example.com"):
                    register = await client.post("/api/auth/register", json={
                        "email": address, "password": "ExamplePassword123!"})
                    assert register.status_code == 201, register.text
                    assert register.json()["role"] == "user"
                    login = await client.post("/api/auth/login", json={
                        "email": address, "password": "ExamplePassword123!"})
                    assert login.status_code == 200, login.text
                    tokens.append(login.json()["access_token"])
                request = {"repo_url": "https://github.com/example/project",
                           "affected_file": "app.py", "vulnerability_type": "COMMAND_INJECTION"}
                assert (await client.post("/api/analysis/analyze", json=request)).status_code in (401, 403)
                alice = {"Authorization": f"Bearer {tokens[0]}"}
                bob = {"Authorization": f"Bearer {tokens[1]}"}
                available_slots = analysis_routes._scan_slots
                monkeypatch.setattr(analysis_routes, "_scan_slots", asyncio.Semaphore(0))
                assert (await client.post("/api/analysis/analyze", json=request, headers=alice)).status_code == 429
                monkeypatch.setattr(analysis_routes, "_scan_slots", available_slots)
                scan = await client.post("/api/analysis/analyze", json=request, headers=alice)
                assert scan.status_code == 200, scan.text
                body = scan.json()
                assert body["vulnerable"] is None
                assert body["score"] is None
                assert body["findings"][0]["rule_id"] == "os-system-call"
                assert body["commit_sha"] == "a" * 40
                assert body["rules_sha256"] == "c" * 64
                scan_id = body["analysis_id"]
                repository_scan = await client.post("/api/analysis/repository", json={
                    "repo_url": "https://github.com/example/project"}, headers=alice)
                assert repository_scan.status_code == 200, repository_scan.text
                assert repository_scan.json()["commit_sha"] == "a" * 40
                assert repository_scan.json()["file_count"] == 1
                own_results = await client.get("/api/analysis/results", headers=alice)
                other_results = await client.get("/api/analysis/results", headers=bob)
                assert own_results.json()["total"] == 2
                assert own_results.json()["results"][0]["commit_sha"] == "a" * 40
                assert other_results.json()["total"] == 0
                review_path = f"/api/analysis/results/{scan_id}/findings/0/review"
                assert (await client.put(review_path, headers=bob, json={
                    "status": "false_positive", "note": "Reviewed"})).status_code == 404
                assert (await client.put(review_path, headers=alice, json={
                    "status": "false_positive", "note": ""})).status_code == 422
                assert (await client.put(f"/api/analysis/results/{scan_id}/findings/9/review",
                                         headers=alice, json={"status": "open"})).status_code == 404
                reviewed = await client.put(review_path, headers=alice, json={
                    "status": "false_positive", "note": "Reviewed the source and confirmed safe input"})
                assert reviewed.status_code == 200, reviewed.text
                detail = await client.get(f"/api/analysis/results/{scan_id}", headers=alice)
                assert detail.json()["reviews"][0]["status"] == "false_positive"
                history_path = f"/api/analysis/results/{scan_id}/findings/0/history"
                assert (await client.get(history_path, headers=bob)).status_code == 404
                await client.put(review_path, headers=alice, json={"status": "investigating", "note": "Reopened"})
                history = (await client.get(history_path, headers=alice)).json()["events"]
                assert [event["status"] for event in history] == ["false_positive", "investigating"]
                assert history[0]["note"] == "Reviewed the source and confirmed safe input"
                assert detail.json()["verification_status"] == "unverified"
                repository_scan_id = repository_scan.json()["analysis_id"]
                assert (await client.get(
                    f"/api/analysis/results/{repository_scan_id}/compare/{scan_id}", headers=alice
                )).status_code == 422
                monkeypatch.setattr(pipeline_module, "scan_files", lambda files: {
                    "status": "completed", "findings": [{"rule_id": "new-rule", "file": "src/app.py",
                                                         "line": 1, "severity": "WARNING", "message": "Review"}],
                })
                newer = await client.post("/api/analysis/repository", json={
                    "repo_url": "https://github.com/example/project"}, headers=alice)
                assert newer.status_code == 200, newer.text
                comparison_path = f"/api/analysis/results/{newer.json()['analysis_id']}/compare/{repository_scan_id}"
                assert (await client.get(comparison_path, headers=bob)).status_code == 404
                comparison = await client.get(comparison_path, headers=alice)
                assert comparison.status_code == 200
                assert comparison.json()["resolved_count"] == 0
                assert comparison.json()["introduced_count"] == 1
                assert (await client.get(f"/api/analysis/results/{scan_id}", headers=bob)).status_code == 404
                assert (await client.get(f"/api/analysis/reports/{scan_id}/html", headers=bob)).status_code == 404
                assert (await client.get(f"/api/analysis/reports/{scan_id}/sarif", headers=bob)).status_code == 404
                report = await client.get(f"/api/analysis/reports/{scan_id}/html", headers=alice)
                assert report.status_code == 200
                assert b"Manual review" in report.content or b"manual review" in report.content
                assert ("c" * 64).encode() in report.content
                assert b"&lt;script&gt;" in report.content
                assert b"<script>" not in report.content
                sarif = await client.get(f"/api/analysis/reports/{scan_id}/sarif", headers=alice)
                assert sarif.status_code == 200
                assert sarif.json()["version"] == "2.1.0"
                assert sarif.json()["runs"][0]["properties"]["rules_sha256"] == "c" * 64
                sarif_result = sarif.json()["runs"][0]["results"][0]
                assert sarif_result["ruleId"] == "os-system-call"
                assert sarif_result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "app.py"
                assert (await client.get(f"/api/analysis/reports/{repository_scan.json()['analysis_id']}/sarif", headers=alice)).json()["runs"][0]["results"] == []
                assert (await client.get("/api/admin/ollama-prompts", headers=alice)).status_code == 404
        finally:
            app.dependency_overrides.clear()
            await engine.dispose()

    asyncio.run(scenario())
