"""Bounded, commit-pinned GitHub repository snapshots and Semgrep scans."""

import base64
import json
import re
import subprocess
import tempfile
from pathlib import Path, PurePosixPath
from urllib.parse import quote

import httpx

from backend.config import get_settings

RULES_PATH = Path(__file__).resolve().parents[2] / "security" / "semgrep_rules.yaml"
SUPPORTED_SUFFIXES = {".py", ".js", ".jsx", ".ts", ".tsx"}
EXCLUDED_PARTS = {"node_modules", ".venv", "venv", "dist", "build", ".git", "vendor"}
MAX_FILES = 100
MAX_FILE_BYTES = 200_000
MAX_TOTAL_BYTES = 2_000_000
SHA_PATTERN = re.compile(r"[a-fA-F0-9]{40}\Z")


def _safe_source_path(path: str) -> bool:
    parts = PurePosixPath(path).parts
    return (bool(parts) and not path.startswith("/") and "\\" not in path
            and all(part not in (".", "..") and not any(ord(ch) < 32 for ch in part)
                    for part in parts)
            and not any(part in EXCLUDED_PARTS for part in parts)
            and PurePosixPath(path).suffix.lower() in SUPPORTED_SUFFIXES)


async def fetch_repository_snapshot(owner: str, repo: str, token: str | None = None) -> tuple[str, dict[str, str], dict[str, str]]:
    """Resolve the default branch once, then fetch every selected blob by SHA."""
    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    root = f"https://api.github.com/repos/{owner}/{repo}"
    async with httpx.AsyncClient(timeout=20, follow_redirects=False) as client:
        async def get_json(url: str) -> dict:
            response = await client.get(url, headers=headers)
            if response.status_code == 403 and response.headers.get("X-RateLimit-Remaining") == "0":
                raise ValueError("GitHub API rate limit reached; provide a GitHub token and retry")
            if response.status_code == 401:
                raise ValueError("GitHub rejected the provided token")
            response.raise_for_status()
            data = response.json()
            if not isinstance(data, dict):
                raise ValueError("Unexpected GitHub API response")
            return data

        metadata = await get_json(root)
        branch = metadata.get("default_branch")
        if not isinstance(branch, str) or not branch:
            raise ValueError("Repository has no default branch")
        commit = await get_json(f"{root}/commits/{quote(branch, safe='')}")
        commit_sha = commit.get("sha", "")
        if not isinstance(commit_sha, str) or not SHA_PATTERN.fullmatch(commit_sha):
            raise ValueError("GitHub did not return a valid commit SHA")
        tree = await get_json(f"{root}/git/trees/{commit_sha}?recursive=1")
        if tree.get("truncated"):
            raise ValueError("Repository tree is truncated; complete coverage cannot be guaranteed")
        entries = tree.get("tree")
        if not isinstance(entries, list):
            raise ValueError("GitHub did not return a repository tree")
        candidates = []
        for item in entries:
            if not isinstance(item, dict) or item.get("type") != "blob":
                continue
            path, sha, size = item.get("path"), item.get("sha"), item.get("size")
            if not isinstance(path, str) or not _safe_source_path(path):
                continue
            if not isinstance(size, int) or size > MAX_FILE_BYTES:
                raise ValueError(f"Supported file exceeds the {MAX_FILE_BYTES} byte limit: {path}")
            if not isinstance(sha, str) or not SHA_PATTERN.fullmatch(sha):
                raise ValueError("GitHub returned an invalid blob SHA")
            candidates.append((path, sha, size))
        if len(candidates) > MAX_FILES:
            raise ValueError(f"Repository has more than {MAX_FILES} supported source files")
        if sum(size for _, _, size in candidates) > MAX_TOTAL_BYTES:
            raise ValueError("Supported source files exceed the 2 MB repository limit")
        if not candidates:
            raise ValueError("Repository has no supported source files")

        files, blob_shas = {}, {}
        for path, sha, _ in sorted(candidates):
            blob = await get_json(f"{root}/git/blobs/{sha}")
            if blob.get("encoding") != "base64" or blob.get("sha") != sha:
                raise ValueError("GitHub returned an unexpected blob")
            content = base64.b64decode(blob.get("content", ""), validate=True)
            if len(content) > MAX_FILE_BYTES:
                raise ValueError("GitHub blob exceeds the file limit")
            files[path] = content.decode("utf-8", errors="replace")
            blob_shas[path] = sha
        if sum(len(content.encode("utf-8")) for content in files.values()) > MAX_TOTAL_BYTES:
            raise ValueError("Downloaded source exceeds the repository limit")
        return commit_sha, files, blob_shas


def scan_files(files: dict[str, str]) -> dict:
    """Run one local Semgrep process over a bounded source snapshot."""
    with tempfile.TemporaryDirectory(prefix="zorix-repo-") as tmp:
        root = Path(tmp)
        for name, source in files.items():
            if not _safe_source_path(name):
                raise ValueError("Unsafe repository source path")
            target = root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(source, encoding="utf-8")
        try:
            process = subprocess.run(
                [get_settings().SEMGREP_PATH, "scan", "--config", str(RULES_PATH), "--json",
                 "--metrics=off", "--disable-version-check", "--quiet", str(root)],
                capture_output=True, text=True, timeout=120, check=False,
            )
        except FileNotFoundError:
            return {"status": "unavailable", "error": "Semgrep is not installed", "findings": []}
        except subprocess.TimeoutExpired:
            return {"status": "error", "error": "Semgrep timed out", "findings": []}
        try:
            data = json.loads(process.stdout)
        except json.JSONDecodeError:
            return {"status": "error", "error": "Invalid Semgrep output", "findings": []}
        if process.returncode not in (0, 1) or data.get("errors"):
            return {"status": "error", "error": "Semgrep reported a scan error", "findings": []}
        findings = []
        for item in data.get("results", []):
            path = Path(item.get("path", ""))
            try:
                relative = path.resolve().relative_to(root.resolve()).as_posix()
            except ValueError:
                return {"status": "error", "error": "Unexpected scanner result path", "findings": []}
            if relative not in files:
                return {"status": "error", "error": "Unexpected scanner result file", "findings": []}
            extra = item.get("extra", {})
            findings.append({"rule_id": item.get("check_id", ""), "file": relative,
                             "line": item.get("start", {}).get("line"),
                             "severity": extra.get("severity", "INFO"),
                             "message": extra.get("message", "")})
        return {"status": "completed", "findings": findings}
