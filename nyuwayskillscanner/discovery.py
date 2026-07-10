"""Local skill auto-discovery for common agent environments."""

from __future__ import annotations

import fnmatch
import os
from dataclasses import dataclass
from pathlib import Path


@dataclass
class DiscoveredSkill:
    path: Path
    source: str


def default_skill_roots() -> list[tuple[str, Path]]:
    home = Path.home()
    roots = [
        ("claude-code", home / ".claude" / "skills"),
        ("cursor", home / ".cursor" / "skills"),
        ("codex", home / ".codex" / "skills"),
        ("gemini-cli", home / ".gemini" / "skills"),
    ]
    if os.name == "nt":
        appdata = Path(os.environ.get("APPDATA", ""))
        local = Path(os.environ.get("LOCALAPPDATA", ""))
        roots.extend(
            [
                ("cursor", appdata / "Cursor" / "User" / "skills"),
                ("claude", appdata / "Claude" / "skills"),
                ("gemini-cli", local / "Google" / "Gemini" / "skills"),
            ]
        )
    return roots


def discover_skills(
    *,
    extra_roots: list[str] | None = None,
    include: list[str] | None = None,
    exclude: list[str] | None = None,
) -> list[DiscoveredSkill]:
    include = include or ["*"]
    exclude = exclude or []
    roots = default_skill_roots()
    for root in extra_roots or []:
        roots.append(("custom", Path(root).expanduser()))

    found: dict[Path, DiscoveredSkill] = {}
    for source, root in roots:
        if not root.exists():
            continue
        candidates = []
        if root.is_file() and root.name.lower() == "skill.md":
            candidates = [root.parent]
        elif root.is_dir():
            candidates = [p.parent for p in root.rglob("*") if p.is_file() and p.name.lower() == "skill.md"]
        for candidate in candidates:
            normalized = candidate.resolve()
            as_posix = normalized.as_posix()
            if not any(fnmatch.fnmatch(as_posix, pat) for pat in include):
                continue
            if any(fnmatch.fnmatch(as_posix, pat) for pat in exclude):
                continue
            found.setdefault(normalized, DiscoveredSkill(path=normalized, source=source))
    return sorted(found.values(), key=lambda s: str(s.path))
