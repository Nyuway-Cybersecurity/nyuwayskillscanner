"""Markdown report writer for human security review."""

from __future__ import annotations

from datetime import datetime, timezone

from nyuwayskillscanner import __version__
from nyuway_scan_core.findings import install_verdict


def render_markdown(
    target: str,
    score: int,
    verdict: str,
    findings: list[dict],
    metadata: dict | None = None,
) -> str:
    metadata = metadata or {}
    decision = install_verdict(score, verdict)
    lines = [
        "# nyuwayskillscanner Report",
        "",
        f"- Tool version: `{__version__}`",
        f"- Target: `{target}`",
        f"- Scanned at: `{datetime.now(timezone.utc).isoformat()}`",
        f"- Risk score: `{score} / 100`",
        f"- Verdict: `{verdict}`",
        f"- Marketplace decision: `{decision['decision']}`",
        f"- Safe to install: `{decision['safe_to_install']}`",
        f"- Requires review: `{decision['requires_review']}`",
        f"- Block install: `{decision['block_install']}`",
    ]
    for key, value in metadata.items():
        lines.append(f"- {key.replace('_', ' ').title()}: `{value}`")
    lines.extend(["", "## Findings", ""])
    active = [f for f in findings if not f.get("suppressed")]
    suppressed = [f for f in findings if f.get("suppressed")]
    if not active:
        lines.append("No active findings.")
    else:
        for idx, finding in enumerate(active, start=1):
            lines.extend(
                [
                    f"### {idx}. {finding.get('rule_id', finding.get('type', 'finding'))}",
                    "",
                    f"- Severity: `{finding.get('severity')}`",
                    f"- File: `{finding.get('file', '')}`",
                    f"- Evidence: `{finding.get('evidence', '')}`",
                    f"- Description: {finding.get('description', '')}",
                    f"- Recommendation: {finding.get('recommendation', '')}",
                    f"- Fingerprint: `{finding.get('fingerprint', '')}`",
                    "",
                ]
            )
    if suppressed:
        lines.extend(["## Suppressed Findings", ""])
        for finding in suppressed:
            lines.append(
                f"- `{finding.get('fingerprint')}` `{finding.get('rule_id')}` "
                f"({finding.get('suppression_reason')})"
            )
    return "\n".join(lines).rstrip() + "\n"
