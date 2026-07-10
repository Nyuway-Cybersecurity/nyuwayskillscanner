"""Source resolution for local paths, archives, and Git repositories."""

from __future__ import annotations

import subprocess
import tempfile
import urllib.parse
import urllib.request
import zipfile
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path


@dataclass
class ResolvedSource:
    original: str
    path: Path
    source_type: str


@contextmanager
def resolve_source(target: str):
    """Yield a local path for a scan target, cleaning temp dirs afterward."""
    temp_dir: tempfile.TemporaryDirectory[str] | None = None
    try:
        path = Path(target)
        if path.exists():
            if path.is_file() and path.suffix.lower() == ".zip":
                temp_dir = tempfile.TemporaryDirectory(prefix="nyuway-skill-zip-")
                extracted = _extract_zip(path, Path(temp_dir.name))
                yield ResolvedSource(target, extracted, "zip")
            else:
                yield ResolvedSource(target, path, "local")
            return

        if target.startswith("github:"):
            temp_dir = tempfile.TemporaryDirectory(prefix="nyuway-skill-git-")
            repo_url = _github_shorthand_to_url(target)
            cloned = _clone_git(repo_url, Path(temp_dir.name))
            yield ResolvedSource(target, cloned, "git")
            return

        if target.startswith("git+"):
            temp_dir = tempfile.TemporaryDirectory(prefix="nyuway-skill-git-")
            cloned = _clone_git(target.removeprefix("git+"), Path(temp_dir.name))
            yield ResolvedSource(target, cloned, "git")
            return

        if _looks_like_git_url(target) or _looks_like_github_repo_url(target):
            temp_dir = tempfile.TemporaryDirectory(prefix="nyuway-skill-git-")
            cloned = _clone_git(_normalize_git_url(target), Path(temp_dir.name))
            yield ResolvedSource(target, cloned, "git")
            return

        if _looks_like_http_zip(target):
            temp_dir = tempfile.TemporaryDirectory(prefix="nyuway-skill-urlzip-")
            archive = _download(target, Path(temp_dir.name))
            extracted = _extract_zip(archive, Path(temp_dir.name) / "extracted")
            yield ResolvedSource(target, extracted, "url_zip")
            return

        raise FileNotFoundError(f"Path or supported source not found: {target}")
    finally:
        if temp_dir is not None:
            temp_dir.cleanup()


def _extract_zip(archive: Path, destination: Path) -> Path:
    destination.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(archive) as zf:
        _safe_extract(zf, destination)
    return _collapse_single_top_level_dir(destination)


def _safe_extract(zf: zipfile.ZipFile, destination: Path) -> None:
    destination = destination.resolve()
    for member in zf.infolist():
        target = (destination / member.filename).resolve()
        if destination not in target.parents and target != destination:
            raise ValueError(f"Unsafe zip member path: {member.filename}")
    zf.extractall(destination)


def _collapse_single_top_level_dir(path: Path) -> Path:
    entries = [p for p in path.iterdir() if p.name != "__MACOSX"]
    if len(entries) == 1 and entries[0].is_dir():
        return entries[0]
    return path


def _download(url: str, directory: Path) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    parsed = urllib.parse.urlparse(url)
    name = Path(parsed.path).name or "download.zip"
    archive = directory / name
    urllib.request.urlretrieve(url, archive)
    return archive


def _clone_git(url: str, directory: Path) -> Path:
    destination = directory / "repo"
    try:
        subprocess.run(
            ["git", "clone", "--depth", "1", url, str(destination)],
            check=True,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError) as e:
        detail = getattr(e, "stderr", "") or str(e)
        raise ValueError(f"Could not clone Git source {url!r}: {detail}") from e
    return destination


def _github_shorthand_to_url(spec: str) -> str:
    repo = spec.removeprefix("github:").strip("/")
    if repo.count("/") < 1:
        raise ValueError("github: target must be github:owner/repo")
    return f"https://github.com/{repo}.git"


def _looks_like_git_url(target: str) -> bool:
    lowered = target.lower()
    return (
        lowered.endswith(".git")
        or lowered.startswith("ssh://")
        or lowered.startswith("git@")
    )


def _looks_like_github_repo_url(target: str) -> bool:
    parsed = urllib.parse.urlparse(target)
    if parsed.scheme not in {"http", "https"} or parsed.netloc.lower() != "github.com":
        return False
    parts = [p for p in parsed.path.strip("/").split("/") if p]
    return len(parts) >= 2 and not parsed.path.lower().endswith(".zip")


def _normalize_git_url(target: str) -> str:
    if _looks_like_github_repo_url(target) and not target.endswith(".git"):
        parsed = urllib.parse.urlparse(target)
        owner, repo = parsed.path.strip("/").split("/")[:2]
        return f"https://github.com/{owner}/{repo}.git"
    return target


def _looks_like_http_zip(target: str) -> bool:
    parsed = urllib.parse.urlparse(target)
    return parsed.scheme in {"http", "https"} and parsed.path.lower().endswith(".zip")
