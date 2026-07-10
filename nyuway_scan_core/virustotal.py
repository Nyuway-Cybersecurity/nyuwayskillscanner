"""Shared VirusTotal hash lookup helpers."""

from __future__ import annotations

import hashlib
import os
import time
from pathlib import Path

import requests

VT_API_URL = "https://www.virustotal.com/api/v3/files/{hash}"
REQUEST_TIMEOUT = 15
BINARY_SUFFIXES = {".exe", ".dll", ".so", ".dylib", ".whl", ".egg", ".tar", ".gz", ".tgz", ".zip", ".bin"}
SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build"}


class VTKeyMissing(Exception):
    pass


def resolve_api_key(cli_key: str | None) -> str | None:
    return cli_key or os.environ.get("VIRUSTOTAL_API_KEY") or None


def count_binaries(path: str) -> int:
    root = Path(path)
    if not root.exists():
        return 0
    if root.is_file():
        return 1 if root.suffix.lower() in BINARY_SUFFIXES else 0
    return sum(1 for _ in _iter_binaries(root))


def scan_virustotal(path: str, api_key: str) -> list[dict]:
    if not api_key:
        raise VTKeyMissing("No VirusTotal API key provided")
    root = Path(path)
    files = [root] if root.is_file() and root.suffix.lower() in BINARY_SUFFIXES else list(_iter_binaries(root))
    findings: list[dict] = []
    for idx, file_path in enumerate(files):
        if idx:
            time.sleep(15)
        sha = _sha256(file_path)
        report = _query_vt(sha, api_key)
        if not report:
            continue
        malicious = report.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("malicious", 0)
        if malicious:
            findings.append(
                {
                    "type": "malware_detected",
                    "category": "malware",
                    "severity": "critical" if malicious >= 5 else "high",
                    "weight": 35 if malicious >= 5 else 25,
                    "file": str(file_path),
                    "sha256": sha,
                    "description": f"VirusTotal reported {malicious} malicious detections",
                    "source": "virustotal",
                }
            )
    return findings


def _iter_binaries(root: Path):
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.suffix.lower() in BINARY_SUFFIXES:
            yield path


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _query_vt(sha256: str, api_key: str) -> dict | None:
    try:
        resp = requests.get(VT_API_URL.format(hash=sha256), headers={"x-apikey": api_key}, timeout=REQUEST_TIMEOUT)
        if resp.status_code == 404:
            return None
        resp.raise_for_status()
        return resp.json()
    except (requests.RequestException, ValueError):
        return None
