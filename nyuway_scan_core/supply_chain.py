"""Shared dependency parsing, typosquat checks, and OSV.dev lookup."""

from __future__ import annotations

import json
import re
from pathlib import Path

import requests

OSV_API_URL = "https://api.osv.dev/v1/query"
REQUEST_TIMEOUT = 10

POPULAR_PYPI = {"requests", "numpy", "pandas", "django", "flask", "fastapi", "pydantic", "click", "rich"}
POPULAR_NPM = {"express", "react", "lodash", "axios", "vue", "next", "typescript", "webpack", "eslint", "jest"}


def scan_supply_chain(path: str, offline: bool = False) -> list[dict]:
    root = Path(path)
    if not root.exists():
        raise FileNotFoundError(f"Path not found: {path}")
    findings: list[dict] = []
    for name, version, ecosystem, file_path in _enumerate_dependencies(root):
        squat = _check_typosquatting(name, ecosystem)
        if squat:
            findings.append(
                {
                    "type": "typosquatting_risk",
                    "category": "supply_chain",
                    "severity": "medium",
                    "weight": 15,
                    "package": name,
                    "ecosystem": ecosystem,
                    "file": str(file_path),
                    "description": f"Package name '{name}' is one edit from popular '{squat}'",
                    "source": "supply_chain",
                }
            )
        if offline:
            continue
        for vuln in _query_osv(name, version, ecosystem):
            findings.append(
                {
                    "type": "dependency_cve",
                    "category": "supply_chain",
                    "severity": "high",
                    "weight": 20,
                    "package": name,
                    "version": version,
                    "ecosystem": ecosystem,
                    "file": str(file_path),
                    "cve_id": vuln.get("id", "UNKNOWN"),
                    "description": (vuln.get("summary") or "")[:300],
                    "source": "osv",
                }
            )
    return findings


def _enumerate_dependencies(root: Path) -> list[tuple[str, str | None, str, Path]]:
    candidates = [root] if root.is_file() else list(root.rglob("requirements*.txt")) + list(root.rglob("package.json"))
    found: list[tuple[str, str | None, str, Path]] = []
    for path in candidates:
        if any(part in {".git", "node_modules", ".venv", "venv"} for part in path.parts):
            continue
        if path.name.startswith("requirements") and path.suffix == ".txt":
            found.extend((name, version, "PyPI", path) for name, version in _parse_requirements(path))
        elif path.name == "package.json":
            found.extend((name, version, "npm", path) for name, version in _parse_package_json(path))
    return found


def _parse_requirements(path: Path) -> list[tuple[str, str | None]]:
    deps: list[tuple[str, str | None]] = []
    for raw in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        match = re.match(r"^([A-Za-z0-9_.\-]+)\s*(==)?\s*([A-Za-z0-9_.\-]+)?", line)
        if match:
            deps.append((match.group(1).lower(), match.group(3) if match.group(2) else None))
    return deps


def _parse_package_json(path: Path) -> list[tuple[str, str | None]]:
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
    except json.JSONDecodeError:
        return []
    deps: list[tuple[str, str | None]] = []
    for key in ("dependencies", "devDependencies"):
        for name, version in (data.get(key) or {}).items():
            deps.append((name.lower(), re.sub(r"^[\^~>=<]+\s*", "", str(version)) or None))
    return deps


def _query_osv(name: str, version: str | None, ecosystem: str) -> list[dict]:
    payload: dict = {"package": {"name": name, "ecosystem": ecosystem}}
    if version:
        payload["version"] = version
    try:
        resp = requests.post(OSV_API_URL, json=payload, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        return (resp.json().get("vulns") or [])
    except (requests.RequestException, ValueError):
        return []


def _check_typosquatting(name: str, ecosystem: str) -> str | None:
    popular = POPULAR_PYPI if ecosystem == "PyPI" else POPULAR_NPM
    if name in popular:
        return None
    for target in popular:
        if _levenshtein(name, target) == 1:
            return target
    return None


def _levenshtein(a: str, b: str) -> int:
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        curr = [i] + [0] * len(b)
        for j, cb in enumerate(b, start=1):
            curr[j] = min(curr[j - 1] + 1, prev[j] + 1, prev[j - 1] + (ca != cb))
        prev = curr
    return prev[-1]
