"""Baseline suppression and policy-pack support."""

from __future__ import annotations

import json
import re
from pathlib import Path

import yaml

SEVERITY_WEIGHT = {"low": 5, "medium": 15, "high": 25, "critical": 35}

_INSTALL_BLOCKING_OVERRIDES = {
    "credential_collection": "critical",
    "covert_exfiltration": "critical",
    "data_destruction": "critical",
    "sandbox_escape": "critical",
    "persistence": "critical",
    "memory_poisoning": "critical",
    "output_injection": "high",
    "instruction_override": "high",
    "role_impersonation": "high",
    "dangerous_code": "high",
    "unsafe_deserialization": "high",
    "tool_misuse": "high",
}

POLICY_PACKS = {
    "personal": {
        "minimum_severity": "medium",
        "severity_overrides": {},
    },
    "audit": {"minimum_severity": "critical", "severity_overrides": {}},
    "default": {"minimum_severity": "low", "severity_overrides": {}},
    "enterprise": {
        "minimum_severity": "low",
        "severity_overrides": {
            **_INSTALL_BLOCKING_OVERRIDES,
            "excessive_agency": "high",
            "untrusted_content_fetch": "high",
        },
    },
    "marketplace": {
        "minimum_severity": "medium",
        "severity_overrides": {
            **_INSTALL_BLOCKING_OVERRIDES,
            "self_elevation": "high",
            "secrecy_concealment": "high",
            "trigger_abuse": "high",
            "resource_abuse": "high",
            "supply_chain_inline_install": "high",
        },
    },
    "strict": {
        "minimum_severity": "low",
        "severity_overrides": {
            **_INSTALL_BLOCKING_OVERRIDES,
            "self_elevation": "high",
            "secrecy_concealment": "high",
            "excessive_agency": "high",
            "supply_chain_inline_install": "high",
            "trigger_abuse": "high",
            "untrusted_content_fetch": "high",
            "resource_abuse": "high",
        },
    },
}


def load_baseline(path: str | None) -> set[str]:
    if not path:
        return set()
    p = Path(path)
    if not p.is_file():
        raise FileNotFoundError(f"Baseline file not found: {path}")
    data = json.loads(p.read_text(encoding="utf-8"))
    if isinstance(data, dict):
        entries = data.get("findings", [])
    else:
        entries = data
    fingerprints: set[str] = set()
    for entry in entries:
        if isinstance(entry, str):
            fingerprints.add(entry)
        elif isinstance(entry, dict) and entry.get("fingerprint"):
            fingerprints.add(str(entry["fingerprint"]))
    return fingerprints


def load_policy(policy_pack: str, policy_file: str | None = None) -> dict:
    if policy_pack not in POLICY_PACKS:
        raise ValueError(f"Unknown policy pack: {policy_pack}")
    policy = {
        "minimum_severity": POLICY_PACKS[policy_pack]["minimum_severity"],
        "severity_overrides": dict(POLICY_PACKS[policy_pack]["severity_overrides"]),
    }
    if policy_file:
        p = Path(policy_file)
        if not p.is_file():
            raise FileNotFoundError(f"Policy file not found: {policy_file}")
        data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
        if not isinstance(data, dict):
            raise ValueError("Policy file must contain a YAML mapping")
        if data.get("minimum_severity"):
            policy["minimum_severity"] = str(data["minimum_severity"]).lower()
        overrides = data.get("severity_overrides") or {}
        if isinstance(overrides, dict):
            policy["severity_overrides"].update(
                {str(k): str(v).lower() for k, v in overrides.items()}
            )
    return policy


def apply_policy_and_baseline(
    findings: list[dict],
    *,
    baseline: set[str],
    policy: dict,
    inline_suppressions: dict[str, list[dict]] | None = None,
) -> list[dict]:
    """Apply severity overrides and suppression metadata in place."""
    inline_suppressions = inline_suppressions or {}
    minimum = _rank(str(policy.get("minimum_severity", "low")))
    overrides = policy.get("severity_overrides", {})

    for finding in findings:
        category = str(finding.get("category", ""))
        if category in overrides:
            severity = str(overrides[category]).lower()
            finding["severity"] = severity
            finding["weight"] = max(int(finding.get("weight", 0)), SEVERITY_WEIGHT[severity])

        if finding.get("fingerprint") in baseline:
            finding["suppressed"] = True
            finding["suppression_reason"] = "baseline"
            continue

        if _matches_inline_suppression(finding, inline_suppressions):
            finding["suppressed"] = True
            finding["suppression_reason"] = "inline"
            continue

        if _rank(str(finding.get("severity", "low"))) < minimum:
            finding["suppressed"] = True
            finding["suppression_reason"] = "policy_minimum_severity"

    return findings


def _rank(severity: str) -> int:
    return {"low": 1, "medium": 2, "high": 3, "critical": 4}.get(severity, 1)


def _matches_inline_suppression(
    finding: dict, inline_suppressions: dict[str, list[dict]]
) -> bool:
    path = str(finding.get("file", ""))
    physical_path = path.split("#", 1)[0]
    rule_id = str(finding.get("rule_id", ""))
    candidates = (
        inline_suppressions.get(path, [])
        + inline_suppressions.get(physical_path, [])
        + inline_suppressions.get("*", [])
    )
    for suppression in candidates:
        wanted = suppression["rule_id"]
        if wanted in {rule_id, rule_id.split("/", 1)[0], "*"}:
            finding["suppression_justification"] = suppression.get("justification", "")
            return True
    return False


SUPPRESSION_RE = re.compile(
    r"nyuway:\s*ignore\s+(?P<rule>[A-Za-z0-9_\-/*]+)(?:\s+because\s+(?P<why>.+))?",
    re.IGNORECASE,
)


def collect_inline_suppressions(root: Path) -> dict[str, list[dict]]:
    """Collect `nyuway: ignore <rule> because <reason>` comments from a tree."""
    suppressions: dict[str, list[dict]] = {}
    files = [root] if root.is_file() else [p for p in root.rglob("*") if p.is_file()]
    for path in files:
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for line in text.splitlines():
            match = SUPPRESSION_RE.search(line)
            if not match:
                continue
            entry = {
                "rule_id": match.group("rule"),
                "justification": _clean_suppression_justification(match.group("why") or ""),
            }
            suppressions.setdefault(str(path), []).append(entry)
    return suppressions


def _clean_suppression_justification(value: str) -> str:
    return value.strip().removesuffix("-->").removesuffix("*/").strip()
