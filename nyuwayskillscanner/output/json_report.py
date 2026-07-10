"""JSON report writer."""

import json
from datetime import datetime, timezone

from nyuwayskillscanner import __version__
from nyuway_scan_core.findings import install_verdict


def build_report(
    target: str,
    score: int,
    verdict: str,
    findings: list[dict],
    metadata: dict | None = None,
) -> dict:
    return {
        "tool": "nyuwayskillscanner",
        "version": __version__,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "target": target,
        "risk_score": score,
        "verdict": verdict,
        "install_verdict": install_verdict(score, verdict),
        "metadata": metadata or {},
        "finding_count": len(findings),
        "active_finding_count": len([f for f in findings if not f.get("suppressed")]),
        "suppressed_finding_count": len([f for f in findings if f.get("suppressed")]),
        "findings": findings,
    }


def render_json(
    target: str,
    score: int,
    verdict: str,
    findings: list[dict],
    metadata: dict | None = None,
) -> str:
    return json.dumps(build_report(target, score, verdict, findings, metadata), indent=2)
