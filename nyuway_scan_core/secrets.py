"""Shared credential detection engine."""

from __future__ import annotations

import re
from pathlib import Path

PATTERNS: list[tuple[str, re.Pattern, str]] = [
    ("aws_access_key_id", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "high"),
    (
        "aws_secret_access_key",
        re.compile(
            r"\baws[_-]?secret[_-]?access[_-]?key\b\s*[:=]\s*['\"]([A-Za-z0-9/+=]{40})['\"]",
            re.IGNORECASE,
        ),
        "high",
    ),
    ("github_pat", re.compile(r"\bghp_[A-Za-z0-9]{36}\b"), "high"),
    ("openai_api_key", re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"), "high"),
    ("anthropic_api_key", re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}\b"), "high"),
    ("slack_token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"), "high"),
    (
        "generic_jwt",
        re.compile(
            r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"
        ),
        "medium",
    ),
]

SKIP_SUFFIXES = {".png", ".jpg", ".jpeg", ".gif", ".pdf", ".zip", ".pyc", ".dll", ".exe"}
SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build"}
MAX_FILE_BYTES = 2 * 1024 * 1024


def scan_secrets(path: str) -> list[dict]:
    root = Path(path)
    if not root.exists():
        raise FileNotFoundError(f"Path not found: {path}")
    files = [root] if root.is_file() else list(_iter_files(root))
    findings: list[dict] = []
    for file_path in files:
        try:
            if file_path.stat().st_size > MAX_FILE_BYTES:
                continue
            text = file_path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for line_num, line in enumerate(text.splitlines(), start=1):
            for label, pattern, severity in PATTERNS:
                if pattern.search(line) and not _is_placeholder(line):
                    findings.append(
                        {
                            "type": "hardcoded_secret",
                            "category": "credential_collection",
                            "label": label,
                            "severity": severity,
                            "weight": 25,
                            "file": str(file_path),
                            "line": line_num,
                            "evidence": line.strip()[:200],
                            "source": "secrets_scanner",
                        }
                    )
    return findings


def _iter_files(root: Path):
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.suffix.lower() in SKIP_SUFFIXES:
            continue
        yield path


def _is_placeholder(line: str) -> bool:
    lowered = line.lower()
    return any(token in lowered for token in ("your-", "replace-me", "example", "xxxx"))
