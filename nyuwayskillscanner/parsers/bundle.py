"""Skill bundle parser: SKILL.md frontmatter, body, and file classification."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

import yaml

SKILL_MD_NAME = "SKILL.md"

SCRIPT_SUFFIXES = {
    ".py",
    ".sh",
    ".bash",
    ".zsh",
    ".ps1",
    ".psm1",
    ".js",
    ".ts",
    ".mjs",
    ".cjs",
    ".rb",
}
DEPENDENCY_MANIFEST_NAMES = {
    "requirements.txt",
    "requirements-dev.txt",
    "requirements-test.txt",
    "package.json",
    "package-lock.json",
    "pyproject.toml",
    "pipfile",
    "pipfile.lock",
    "gemfile",
    "poetry.lock",
}
SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build"}


class FileKind(str, Enum):
    METADATA = "metadata"
    SCRIPT = "script"
    DEPENDENCY_MANIFEST = "dependency_manifest"
    BINARY_OTHER = "binary_other"


@dataclass
class SkillBundle:
    root: Path
    skill_md_path: Path | None
    frontmatter: dict
    body: str
    frontmatter_valid: bool
    files_by_kind: dict[FileKind, list[Path]] = field(default_factory=dict)
    parse_issues: list[dict] = field(default_factory=list)


def classify_file(path: Path) -> FileKind:
    if path.name.lower() == SKILL_MD_NAME.lower():
        return FileKind.METADATA
    if path.name.lower() in DEPENDENCY_MANIFEST_NAMES:
        return FileKind.DEPENDENCY_MANIFEST
    if path.suffix.lower() in SCRIPT_SUFFIXES:
        return FileKind.SCRIPT
    return FileKind.BINARY_OTHER


def _split_frontmatter(text: str) -> tuple[dict | None, str, str | None]:
    """Return (frontmatter dict or None, body, error message or None)."""
    if not text.startswith("---"):
        return None, text, "missing YAML frontmatter delimiter"

    parts = text.split("---", 2)
    if len(parts) < 3:
        return None, text, "unclosed YAML frontmatter block"

    raw_yaml = parts[1].strip()
    body = parts[2].lstrip("\n")
    if not raw_yaml:
        return {}, body, "empty YAML frontmatter"

    try:
        data = yaml.safe_load(raw_yaml)
    except yaml.YAMLError as e:
        return None, body, f"invalid YAML frontmatter: {e}"

    if data is None:
        return {}, body, None
    if not isinstance(data, dict):
        return None, body, f"frontmatter must be a mapping, got {type(data).__name__}"
    return data, body, None


def parse_skill_md(path: Path) -> tuple[dict, str, bool, list[dict]]:
    """Parse a SKILL.md file. Returns frontmatter, body, valid flag, parse findings."""
    text = path.read_text(encoding="utf-8", errors="replace").lstrip("\ufeff")
    frontmatter, body, error = _split_frontmatter(text)

    findings: list[dict] = []
    valid = error is None and frontmatter is not None

    if error:
        findings.append(
            {
                "type": "malformed_skill_metadata",
                "severity": "medium",
                "weight": 10,
                "file": str(path),
                "line": 1,
                "category": "metadata",
                "description": error,
                "evidence": text.splitlines()[0][:200] if text else "",
                "source": "bundle_parser",
            }
        )
        return frontmatter or {}, body, False, findings

    return frontmatter, body, valid, findings


def _iter_bundle_files(root: Path):
    if root.is_file():
        yield root
        return

    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        yield path


def _find_skill_md(root: Path) -> Path | None:
    direct = root / SKILL_MD_NAME
    if direct.is_file():
        return direct
    for candidate in root.iterdir():
        if candidate.is_file() and candidate.name.lower() == SKILL_MD_NAME.lower():
            return candidate
    return None


def parse_skill_bundle(path: str | Path) -> SkillBundle:
    """Walk a skill directory (or single SKILL.md) and return a parsed bundle."""
    root = Path(path).resolve()
    if not root.exists():
        raise FileNotFoundError(f"Path not found: {path}")

    if root.is_file():
        if root.name.lower() != SKILL_MD_NAME.lower():
            raise ValueError(f"Single-file target must be SKILL.md, got: {root.name}")
        skill_md = root
        bundle_root = root.parent
    else:
        skill_md = _find_skill_md(root)
        bundle_root = root
        if skill_md is None:
            raise FileNotFoundError(f"No SKILL.md found under {root}")

    frontmatter, body, valid, parse_issues = parse_skill_md(skill_md)

    files_by_kind: dict[FileKind, list[Path]] = {kind: [] for kind in FileKind}
    for file_path in _iter_bundle_files(bundle_root):
        kind = classify_file(file_path)
        files_by_kind[kind].append(file_path)

    return SkillBundle(
        root=bundle_root,
        skill_md_path=skill_md,
        frontmatter=frontmatter,
        body=body,
        frontmatter_valid=valid,
        files_by_kind=files_by_kind,
        parse_issues=parse_issues,
    )


def script_scan_roots(bundle: SkillBundle) -> list[str]:
    """Return paths to scan with code-level engines (scripts + manifests)."""
    roots: list[str] = []
    for script in bundle.files_by_kind.get(FileKind.SCRIPT, []):
        roots.append(str(script))
    for manifest in bundle.files_by_kind.get(FileKind.DEPENDENCY_MANIFEST, []):
        roots.append(str(manifest))
    if not roots:
        return [str(bundle.root)]
    return roots
