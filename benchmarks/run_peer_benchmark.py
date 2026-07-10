"""Run normalized peer benchmarks on the skill corpus.

The runner compares nyuwayskillscanner with optional competitors using a common
schema. It emits a publication-ready JSON scorecard and Markdown report with
tool versions, corpus hash, runtimes, false positives, false negatives, and
category recall.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from nyuwayskillscanner import __version__ as NYUWAY_VERSION

ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "benchmarks" / "corpus"
EXPECTED = ROOT / "benchmarks" / "expected.json"
DEFAULT_REPORT_DIR = ROOT / "benchmarks" / "reports"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--skillspector", default="skillspector", help="Path to SkillSpector CLI")
    parser.add_argument("--skip-skillspector", action="store_true")
    parser.add_argument("--output-dir", default=str(DEFAULT_REPORT_DIR))
    parser.add_argument("--json-out", default=None, help="Optional JSON scorecard path")
    parser.add_argument("--markdown-out", default=None, help="Optional Markdown report path")
    args = parser.parse_args()

    expected = json.loads(EXPECTED.read_text(encoding="utf-8"))
    report_dir = Path(args.output_dir)
    json_out = Path(args.json_out) if args.json_out else report_dir / "peer_scorecard.json"
    markdown_out = (
        Path(args.markdown_out) if args.markdown_out else report_dir / "peer_scorecard.md"
    )

    rows = []
    for rel_path, labels in expected.items():
        target = CORPUS / rel_path
        nyuway = _run_nyuway(target)
        skillspector = (
            None if args.skip_skillspector else _run_skillspector(target, args.skillspector)
        )
        rows.append(
            {
                "fixture": rel_path,
                "expected": labels,
                "nyuwayskillscanner": nyuway,
                "skillspector": skillspector,
            }
        )

    scorecard = {
        "metadata": {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "corpus_root": str(CORPUS),
            "corpus_hash": _corpus_hash(),
            "fixture_count": len(rows),
            "tools": {
                "nyuwayskillscanner": {"version": NYUWAY_VERSION},
                "skillspector": None
                if args.skip_skillspector
                else {"version": _tool_version(args.skillspector)},
            },
        },
        "summary": _summarize(rows),
        "results": rows,
    }

    report_dir.mkdir(parents=True, exist_ok=True)
    json_out.parent.mkdir(parents=True, exist_ok=True)
    markdown_out.parent.mkdir(parents=True, exist_ok=True)
    json_out.write_text(json.dumps(scorecard, indent=2), encoding="utf-8")
    markdown_out.write_text(_render_markdown(scorecard), encoding="utf-8")
    print(json.dumps({"json": str(json_out), "markdown": str(markdown_out), "summary": scorecard["summary"]}, indent=2))
    return 0


def _run_nyuway(target: Path) -> dict:
    cmd = [
        sys.executable,
        "-m",
        "nyuwayskillscanner.cli.main",
        "scan",
        str(target),
        "--static-only",
        "--offline",
        "--output",
        "json",
    ]
    started = time.perf_counter()
    proc = subprocess.run(cmd, text=True, capture_output=True, check=False)
    elapsed_ms = round((time.perf_counter() - started) * 1000, 2)
    if proc.returncode != 0:
        return _error_result(proc, elapsed_ms)
    data = json.loads(proc.stdout)
    return _normalize_result(
        tool="nyuwayskillscanner",
        score=data["risk_score"],
        verdict=data["verdict"],
        decision=data["install_verdict"]["decision"],
        categories=sorted({f.get("category") for f in data["findings"] if f.get("category")}),
        finding_count=data["active_finding_count"],
        runtime_ms=elapsed_ms,
    )


def _run_skillspector(target: Path, executable: str) -> dict:
    cmd = [executable, "scan", str(target), "--no-llm", "--format", "json"]
    started = time.perf_counter()
    try:
        proc = subprocess.run(cmd, text=True, capture_output=True, check=False)
    except OSError as e:
        return _error_result(e, round((time.perf_counter() - started) * 1000, 2))
    elapsed_ms = round((time.perf_counter() - started) * 1000, 2)
    if proc.returncode != 0:
        return _error_result(proc, elapsed_ms)
    data = json.loads(proc.stdout)
    assessment = data.get("risk_assessment", {})
    recommendation = str(assessment.get("recommendation", "UNKNOWN")).upper()
    decision = {
        "SAFE": "ALLOW",
        "CAUTION": "REVIEW",
        "REVIEW": "REVIEW",
        "UNSAFE": "BLOCK",
        "BLOCK": "BLOCK",
    }.get(recommendation, "UNKNOWN")
    return _normalize_result(
        tool="skillspector",
        score=assessment.get("score"),
        verdict=assessment.get("severity", "UNKNOWN"),
        decision=decision,
        categories=sorted({issue.get("category") for issue in data.get("issues", []) if issue.get("category")}),
        finding_count=len(data.get("issues", [])),
        runtime_ms=elapsed_ms,
        raw_recommendation=recommendation,
    )


def _normalize_result(
    *,
    tool: str,
    score,
    verdict: str,
    decision: str,
    categories: list[str],
    finding_count: int,
    runtime_ms: float,
    **extra,
) -> dict:
    result = {
        "tool": tool,
        "status": "ok",
        "score": score,
        "verdict": verdict,
        "decision": decision,
        "block_install": decision == "BLOCK",
        "categories": categories,
        "finding_count": finding_count,
        "runtime_ms": runtime_ms,
    }
    result.update(extra)
    return result


def _error_result(error, runtime_ms: float) -> dict:
    stderr = getattr(error, "stderr", "") or str(error)
    return {
        "status": "error",
        "decision": "UNKNOWN",
        "block_install": False,
        "categories": [],
        "finding_count": 0,
        "runtime_ms": runtime_ms,
        "error": stderr.strip()[:1000],
    }


def _summarize(rows: list[dict]) -> dict:
    tools = ["nyuwayskillscanner"]
    if any(row.get("skillspector") for row in rows):
        tools.append("skillspector")
    return {tool: _summarize_tool(rows, tool) for tool in tools}


def _summarize_tool(rows: list[dict], tool: str) -> dict:
    comparable = [row for row in rows if row.get(tool)]
    expected_decisions = [_expected_decision(row["expected"]["expected_verdict"]) for row in comparable]
    actual_decisions = [row[tool].get("decision") for row in comparable]
    malicious = [row for row in comparable if row["fixture"].startswith("malicious/")]
    clean = [row for row in comparable if row["fixture"].startswith("clean/")]
    benign = [row for row in comparable if row["fixture"].startswith("benign_suspicious/")]
    missed_categories = {
        row["fixture"]: sorted(
            set(row["expected"].get("expected_categories", [])) - set(row[tool].get("categories", []))
        )
        for row in comparable
    }
    missed_categories = {k: v for k, v in missed_categories.items() if v}
    expected_category_count = sum(len(row["expected"].get("expected_categories", [])) for row in comparable)
    matched_category_count = sum(
        len(set(row["expected"].get("expected_categories", [])) & set(row[tool].get("categories", [])))
        for row in comparable
    )
    false_positives = [
        row["fixture"]
        for row in clean
        if row[tool].get("decision") != _expected_decision(row["expected"]["expected_verdict"])
    ]
    false_negatives = [
        row["fixture"]
        for row in malicious
        if row[tool].get("decision") != "BLOCK"
    ]
    return {
        "fixtures_evaluated": len(comparable),
        "decision_accuracy": _rate(
            actual == expected for actual, expected in zip(actual_decisions, expected_decisions)
        ),
        "malicious_block_rate": _rate(row[tool].get("decision") == "BLOCK" for row in malicious),
        "clean_allow_rate": _rate(row[tool].get("decision") == "ALLOW" for row in clean),
        "benign_review_rate": _rate(row[tool].get("decision") == "REVIEW" for row in benign),
        "category_recall": round(matched_category_count / expected_category_count, 3)
        if expected_category_count
        else 1.0,
        "false_positives": false_positives,
        "false_negatives": false_negatives,
        "missed_categories": missed_categories,
        "avg_runtime_ms": round(
            sum(row[tool].get("runtime_ms", 0) for row in comparable) / len(comparable), 2
        )
        if comparable
        else 0,
        "errors": [row["fixture"] for row in comparable if row[tool].get("status") == "error"],
    }


def _expected_decision(verdict: str) -> str:
    verdict = verdict.upper()
    if verdict == "PASS":
        return "ALLOW"
    if verdict in {"LOW", "MEDIUM"}:
        return "REVIEW"
    return "BLOCK"


def _rate(values) -> float:
    values = list(values)
    if not values:
        return 0.0
    return round(sum(bool(v) for v in values) / len(values), 3)


def _corpus_hash() -> str:
    digest = hashlib.sha256()
    for path in sorted(CORPUS.rglob("*")) + [EXPECTED]:
        if not path.is_file():
            continue
        digest.update(str(path.relative_to(ROOT)).replace("\\", "/").encode("utf-8"))
        digest.update(path.read_bytes())
    return digest.hexdigest()[:16]


def _tool_version(executable: str) -> str:
    try:
        proc = subprocess.run(
            [executable, "--version"],
            text=True,
            capture_output=True,
            check=False,
            timeout=10,
        )
    except OSError:
        return "unavailable"
    return (proc.stdout or proc.stderr or "unknown").strip().splitlines()[0][:120]


def _render_markdown(scorecard: dict) -> str:
    lines = [
        "# Peer Benchmark Scorecard",
        "",
        f"- Generated at: `{scorecard['metadata']['generated_at']}`",
        f"- Corpus hash: `{scorecard['metadata']['corpus_hash']}`",
        f"- Fixtures: `{scorecard['metadata']['fixture_count']}`",
        "",
        "## Summary",
        "",
        "| Tool | Decision Accuracy | Malicious Block Rate | Clean Allow Rate | Benign Review Rate | Category Recall | Avg Runtime (ms) |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    for tool, summary in scorecard["summary"].items():
        lines.append(
            "| {tool} | {accuracy} | {block} | {clean} | {benign} | {recall} | {runtime} |".format(
                tool=tool,
                accuracy=summary["decision_accuracy"],
                block=summary["malicious_block_rate"],
                clean=summary["clean_allow_rate"],
                benign=summary["benign_review_rate"],
                recall=summary["category_recall"],
                runtime=summary["avg_runtime_ms"],
            )
        )
    lines.extend(["", "## Per-Fixture Results", ""])
    lines.append("| Fixture | Expected | Nyuway Decision | Nyuway Categories | SkillSpector Decision |")
    lines.append("|---|---|---|---|---|")
    for row in scorecard["results"]:
        skillspector = row.get("skillspector") or {}
        nyuway = row["nyuwayskillscanner"]
        lines.append(
            "| {fixture} | {expected} | {nyuway_decision} | {categories} | {skillspector_decision} |".format(
                fixture=row["fixture"],
                expected=_expected_decision(row["expected"]["expected_verdict"]),
                nyuway_decision=nyuway.get("decision", "UNKNOWN"),
                categories=", ".join(nyuway.get("categories", [])) or "-",
                skillspector_decision=skillspector.get("decision", "SKIPPED"),
            )
        )
    lines.extend(["", "## Miss Analysis", ""])
    for tool, summary in scorecard["summary"].items():
        lines.append(f"### {tool}")
        lines.append("")
        lines.append(f"- False positives: `{len(summary['false_positives'])}`")
        lines.append(f"- False negatives: `{len(summary['false_negatives'])}`")
        lines.append(f"- Errors: `{len(summary['errors'])}`")
        if summary["missed_categories"]:
            lines.append("- Missed categories:")
            for fixture, categories in summary["missed_categories"].items():
                lines.append(f"  - `{fixture}`: {', '.join(categories)}")
        else:
            lines.append("- Missed categories: none")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


if __name__ == "__main__":
    raise SystemExit(main())
