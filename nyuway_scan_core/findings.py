"""Finding normalization, stable fingerprints, and install verdict helpers."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}

RECOMMENDATIONS = {
    "instruction_override": "Remove instructions that override system, safety, or user guidance.",
    "role_impersonation": "Do not impersonate system/developer messages or trusted authorities in skill text.",
    "hidden_instruction": "Make instructions explicit and remove hidden or conditional behavior.",
    "encoded_instruction": "Remove encoded, invisible, or obfuscated instruction payloads.",
    "covert_exfiltration": "Remove external collection endpoints or document and gate them behind explicit user consent.",
    "credential_collection": "Do not request, print, store, or transmit credentials from agent context.",
    "privilege_escalation": "Remove elevated-permission requests unless they are essential and user-approved.",
    "persistence": "Remove persistence hooks such as shell profile, cron, or startup modifications.",
    "excessive_agency": "Narrow file, environment, and network access to the skill's stated purpose.",
    "dangerous_code": "Replace dynamic code execution and shell-out behavior with constrained APIs.",
    "output_injection": "Do not emit hidden instructions or agent-control text in generated output.",
    "memory_poisoning": "Remove attempts to modify persistent agent memory or instruction stores.",
    "trigger_abuse": "Narrow activation criteria so the skill only runs for its documented purpose.",
    "data_destruction": "Remove destructive file operations or require explicit user confirmation and scope limits.",
    "untrusted_content_fetch": "Do not treat remote content as trusted instructions; sanitize and summarize instead.",
    "sandbox_escape": "Remove host mounts, privileged container flags, and sandbox escape mechanisms.",
    "resource_abuse": "Add bounded runtime, memory, process, and network limits.",
    "unsafe_deserialization": "Use safe parsers and never deserialize untrusted or remote objects.",
    "tool_misuse": "Remove dangerous tool flags and enforce allowlisted parameters.",
    "supply_chain_inline_install": "Move dependency installation into audited manifests with pinned versions.",
    "metadata": "Fix malformed or incomplete SKILL.md metadata before distribution.",
}


def rule_id_for(finding: dict) -> str:
    """Return a stable rule id for a finding."""
    base = finding.get("type", "finding")
    sub = finding.get("category") or finding.get("label") or finding.get("rule")
    return f"{base}/{sub}" if sub else str(base)


def _normalize_evidence(value: str) -> str:
    return re.sub(r"\s+", " ", value.strip().lower())[:300]


def fingerprint_for(finding: dict) -> str:
    """Compute a deterministic fingerprint suitable for baselines."""
    payload = "|".join(
        [
            rule_id_for(finding),
            str(Path(str(finding.get("file", ""))).as_posix()).lower(),
            _normalize_evidence(str(finding.get("evidence", ""))),
        ]
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]


def add_fingerprints(findings: list[dict]) -> list[dict]:
    for finding in findings:
        finding.setdefault("rule_id", rule_id_for(finding))
        finding.setdefault("fingerprint", fingerprint_for(finding))
    return findings


def normalize_findings(findings: list[dict]) -> list[dict]:
    """Normalize common fields so all report formats and policy gates agree."""
    for finding in findings:
        finding["severity"] = str(finding.get("severity", "low")).lower()
        finding["weight"] = int(finding.get("weight", 5))
        category = finding.get("category") or finding.get("label") or finding.get("rule")
        if category:
            finding["category"] = str(category)
        finding.setdefault("source", "unknown")
        finding.setdefault("recommendation", recommendation_for(finding))
    return add_fingerprints(findings)


def recommendation_for(finding: dict) -> str:
    category = str(finding.get("category") or "").lower()
    return RECOMMENDATIONS.get(
        category,
        "Review the evidence and either remediate the behavior or suppress it with documented justification.",
    )


def install_verdict(score: int, verdict: str) -> dict:
    """Return enterprise-friendly install decision fields."""
    if verdict in {"CRITICAL", "HIGH"}:
        return {
            "decision": "BLOCK",
            "safe_to_install": False,
            "requires_review": True,
            "block_install": True,
            "recommendation": "Block installation until high-impact findings are remediated.",
        }
    if verdict == "MEDIUM":
        return {
            "decision": "REVIEW",
            "safe_to_install": False,
            "requires_review": True,
            "block_install": False,
            "recommendation": "Require security review or documented risk acceptance.",
        }
    return {
        "decision": "ALLOW",
        "safe_to_install": True,
        "requires_review": False,
        "block_install": False,
        "recommendation": "No blocking findings detected by the enabled scan layers.",
    }
