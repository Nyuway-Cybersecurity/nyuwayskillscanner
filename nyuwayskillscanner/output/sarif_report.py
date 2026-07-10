"""SARIF 2.1.0 output."""

from __future__ import annotations

import json

from nyuwayskillscanner import __version__
from nyuway_scan_core.findings import install_verdict

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
TOOL_NAME = "nyuwayskillscanner"
INFORMATION_URI = "https://nyuway.ai"

SEVERITY_TO_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
}


def _rule_id_for(finding: dict) -> str:
    base = finding.get("type", "finding")
    sub = finding.get("category") or finding.get("label") or finding.get("rule")
    return f"{base}/{sub}" if sub else base


def _location_for(finding: dict) -> dict | None:
    file_path = finding.get("file")
    if not file_path:
        return None
    uri = str(file_path).replace("\\", "/")
    region: dict = {}
    if finding.get("line") is not None:
        try:
            region["startLine"] = int(finding["line"])
        except (TypeError, ValueError):
            pass
    physical: dict = {"artifactLocation": {"uri": uri}}
    if region:
        physical["region"] = region
    return {"physicalLocation": physical}


def _collect_rules(findings: list[dict]) -> list[dict]:
    rules: dict[str, dict] = {}
    for f in findings:
        rid = _rule_id_for(f)
        if rid in rules:
            continue
        rules[rid] = {
            "id": rid,
            "name": rid.replace("/", "_"),
            "shortDescription": {"text": f.get("description") or rid},
            "fullDescription": {
                "text": f.get("rationale") or f.get("description") or rid,
            },
            "help": {
                "text": f.get("recommendation")
                or "Review the finding evidence and remediate or suppress with justification.",
            },
            "defaultConfiguration": {
                "level": SEVERITY_TO_LEVEL.get(f.get("severity", "low"), "note"),
            },
            "properties": {
                "category": f.get("category") or f.get("type") or "uncategorized",
                "severity": f.get("severity", "low"),
            },
        }
    return list(rules.values())


def _result_for(finding: dict) -> dict:
    rid = _rule_id_for(finding)
    message_text = (
        finding.get("rationale")
        or finding.get("description")
        or finding.get("evidence")
        or rid
    )
    result: dict = {
        "ruleId": rid,
        "level": SEVERITY_TO_LEVEL.get(finding.get("severity", "low"), "note"),
        "message": {"text": str(message_text)[:1000]},
    }
    loc = _location_for(finding)
    if loc:
        result["locations"] = [loc]
    extra = {
        k: finding[k]
        for k in (
            "severity",
            "weight",
            "confidence",
            "evidence",
            "category",
            "source",
            "recommendation",
            "fingerprint",
            "suppressed",
            "suppression_reason",
        )
        if k in finding and finding[k] is not None
    }
    if extra:
        result["properties"] = extra
    return result


def build_sarif(
    target: str,
    score: int,
    verdict: str,
    findings: list[dict],
    metadata: dict | None = None,
) -> dict:
    metadata = metadata or {}
    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": TOOL_NAME,
                        "version": __version__,
                        "informationUri": INFORMATION_URI,
                        "rules": _collect_rules(findings),
                    }
                },
                "results": [_result_for(f) for f in findings],
                "properties": {
                    "target": target,
                    "risk_score": score,
                    "verdict": verdict,
                    "install_verdict": install_verdict(score, verdict),
                    "metadata": metadata,
                    "finding_count": len(findings),
                    "active_finding_count": len(
                        [f for f in findings if not f.get("suppressed")]
                    ),
                    "suppressed_finding_count": len(
                        [f for f in findings if f.get("suppressed")]
                    ),
                },
            }
        ],
    }


def render_sarif(
    target: str,
    score: int,
    verdict: str,
    findings: list[dict],
    metadata: dict | None = None,
) -> str:
    return json.dumps(build_sarif(target, score, verdict, findings, metadata), indent=2)
