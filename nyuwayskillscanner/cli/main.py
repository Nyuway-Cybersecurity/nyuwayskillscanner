from contextlib import ExitStack
from pathlib import Path

import click

from nyuway_scan_core.findings import normalize_findings
from nyuway_scan_core.policy import (
    apply_policy_and_baseline,
    collect_inline_suppressions,
    load_baseline,
    load_policy,
)
from nyuway_scan_core.scoring import calculate_score
from nyuway_scan_core.secrets import scan_secrets
from nyuway_scan_core.supply_chain import scan_supply_chain
from nyuway_scan_core.virustotal import (
    VTKeyMissing,
    count_binaries,
    resolve_api_key,
    scan_virustotal,
)
from nyuwayskillscanner.discovery import discover_skills
from nyuwayskillscanner.output.json_report import render_json
from nyuwayskillscanner.output.markdown_report import render_markdown
from nyuwayskillscanner.output.sarif_report import render_sarif
from nyuwayskillscanner.output.terminal import render_summary
from nyuwayskillscanner.parsers.bundle import FileKind, parse_skill_bundle
from nyuwayskillscanner.scanners.code_static import scan_script_risks
from nyuwayskillscanner.scanners.injection import scan_instruction_manipulation
from nyuwayskillscanner.scanners.llm_safety import (
    DEFAULT_MODEL,
    OllamaUnavailable,
    run_local_llm_analysis,
)
from nyuwayskillscanner.sources import resolve_source

try:
    from nyuwaymcpscanner.scanners.yara_engine import run_yara
except Exception:  # pragma: no cover - optional compatibility layer
    run_yara = None

SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}
_YARA_WARNING_EMITTED = False


@click.group()
def cli():
    """nyuwayskillscanner - static security scanner for AI agent skill bundles."""
    pass


@cli.command()
@click.argument("target")
@click.option(
    "--recursive",
    is_flag=True,
    help="Treat TARGET as a parent directory and scan each child skill bundle.",
)
@click.option("--discover", is_flag=True, help="Auto-discover installed agent skills.")
@click.option(
    "--skill-root",
    multiple=True,
    help="Additional root to search when --discover is used.",
)
@click.option("--include", "include_globs", multiple=True, help="Include glob for discovery.")
@click.option("--exclude", "exclude_globs", multiple=True, help="Exclude glob for discovery.")
@click.option(
    "--static-only",
    is_flag=True,
    help="Skip local LLM layer; run static analysis only.",
)
@click.option(
    "--offline",
    is_flag=True,
    help="Skip network calls (OSV.dev CVE lookup and VirusTotal).",
)
@click.option(
    "--fail-on",
    type=click.Choice(["low", "medium", "high", "critical"]),
    default=None,
    help="Exit non-zero when any finding meets or exceeds this severity.",
)
@click.option(
    "--output",
    type=click.Choice(["summary", "json", "sarif", "markdown"]),
    default="summary",
)
@click.option("--baseline", default=None, help="JSON baseline file of accepted fingerprints.")
@click.option(
    "--policy-pack",
    type=click.Choice(["personal", "audit", "default", "enterprise", "marketplace", "strict"]),
    default="default",
    help="Built-in policy pack controlling severities and suppressions.",
)
@click.option("--policy-file", default=None, help="Custom YAML policy override file.")
@click.option(
    "--model",
    default=DEFAULT_MODEL,
    help="Ollama model for the local LLM layer.",
)
@click.option(
    "--vt-key",
    default=None,
    envvar="VIRUSTOTAL_API_KEY",
    help="VirusTotal API key for binary hash lookup.",
)
def scan(
    target,
    recursive,
    discover,
    skill_root,
    include_globs,
    exclude_globs,
    static_only,
    offline,
    fail_on,
    output,
    baseline,
    policy_pack,
    policy_file,
    model,
    vt_key,
):
    """Scan a skill bundle or directory of skill bundles."""
    baseline_fingerprints = load_baseline(baseline)
    policy = load_policy(policy_pack, policy_file)
    aggregate: list[dict] = []

    try:
        with ExitStack() as stack:
            source = stack.enter_context(resolve_source(target))
            targets = _resolve_targets(
                str(source.path),
                recursive,
                discover=discover,
                skill_roots=list(skill_root),
                include_globs=list(include_globs),
                exclude_globs=list(exclude_globs),
            )

            for tgt in targets:
                try:
                    findings, metadata = _scan_one_skill(
                        tgt,
                        static_only=static_only,
                        offline=offline,
                        baseline=baseline_fingerprints,
                        policy=policy,
                        policy_pack=policy_pack,
                        model=model,
                        vt_key=vt_key,
                        source_type=source.source_type,
                        original_target=source.original,
                    )
                except (FileNotFoundError, ValueError) as e:
                    click.echo(f"Error scanning {tgt!r}: {e}", err=True)
                    raise SystemExit(2)

                display_target = _display_target(source.original, tgt, targets)
                score, verdict = calculate_score(findings)
                if output == "json":
                    click.echo(render_json(display_target, score, verdict, findings, metadata))
                elif output == "sarif":
                    click.echo(render_sarif(display_target, score, verdict, findings, metadata))
                elif output == "markdown":
                    click.echo(render_markdown(display_target, score, verdict, findings, metadata))
                else:
                    render_summary(display_target, score, verdict, findings, metadata)
                aggregate.extend(findings)
    except (FileNotFoundError, ValueError) as e:
        click.echo(f"Error resolving source {target!r}: {e}", err=True)
        raise SystemExit(2)

    if fail_on:
        threshold = SEVERITY_RANK[fail_on]
        for finding in aggregate:
            if SEVERITY_RANK.get(finding.get("severity", "low"), 0) >= threshold:
                raise SystemExit(1)


def _display_target(original: str, local_target: str, all_targets: list[str]) -> str:
    if len(all_targets) == 1 and Path(original).suffix.lower() == ".zip":
        return original
    try:
        if Path(original).exists() and Path(original).resolve() != Path(local_target).resolve():
            return f"{original}::{Path(local_target).name}"
    except OSError:
        pass
    if len(all_targets) == 1:
        return original
    return f"{original}::{Path(local_target).name}"


def _resolve_targets(
    target: str,
    recursive: bool,
    *,
    discover: bool,
    skill_roots: list[str],
    include_globs: list[str],
    exclude_globs: list[str],
) -> list[str]:
    if discover:
        discovered = discover_skills(
            extra_roots=skill_roots or [target],
            include=include_globs or None,
            exclude=exclude_globs or None,
        )
        if not discovered:
            raise ValueError("No skill bundles discovered")
        return [str(skill.path) for skill in discovered]

    path = Path(target)
    if not path.exists():
        raise FileNotFoundError(f"Path not found: {target}")

    if not recursive:
        return [target]

    if not path.is_dir():
        raise ValueError("--recursive requires TARGET to be a directory")

    targets: list[str] = []
    for skill_md in sorted(
        p for p in path.rglob("*") if p.is_file() and p.name.lower() == "skill.md"
    ):
        targets.append(str(skill_md.parent))
    if not targets:
        raise ValueError(f"No skill bundles (SKILL.md) found under {target}")
    return targets


def _scan_one_skill(
    target: str,
    *,
    static_only: bool,
    offline: bool,
    baseline: set[str],
    policy: dict,
    policy_pack: str,
    model: str,
    vt_key: str | None,
    source_type: str,
    original_target: str,
) -> tuple[list[dict], dict]:
    bundle = parse_skill_bundle(target)
    findings: list[dict] = list(bundle.parse_issues)
    metadata = {
        "mode": "static-only" if static_only else "baseline",
        "offline": offline,
        "policy_pack": policy_pack,
        "llm_used": not static_only,
        "skipped_layers": [],
        "source_type": source_type,
        "original_target": original_target,
    }

    findings.extend(
        scan_instruction_manipulation(
            frontmatter=bundle.frontmatter,
            body=bundle.body,
            skill_md_path=bundle.skill_md_path,
        )
    )

    script_paths = bundle.files_by_kind.get(FileKind.SCRIPT, [])
    findings.extend(scan_script_risks(script_paths))
    findings.extend(scan_secrets(str(bundle.root)))
    findings.extend(scan_supply_chain(str(bundle.root), offline=offline))

    for script_path in script_paths:
        findings.extend(_safe_run_yara(str(script_path)))

    if not offline:
        vt_api_key = resolve_api_key(vt_key)
        if vt_api_key:
            try:
                findings.extend(scan_virustotal(str(bundle.root), vt_api_key))
            except VTKeyMissing:
                pass
        else:
            binary_count = count_binaries(str(bundle.root))
            if binary_count:
                click.echo(
                    f"Note: {binary_count} binary file(s) not checked - "
                    "set VIRUSTOTAL_API_KEY for hash-based detection.",
                    err=True,
                )
                metadata["skipped_layers"].append("virustotal")

    findings = normalize_findings(findings)
    if not static_only:
        try:
            llm_decisions = run_local_llm_analysis(
                frontmatter=bundle.frontmatter,
                body=bundle.body,
                skill_md_path=str(bundle.skill_md_path),
                static_findings=findings,
                model=model,
            )
            findings = _merge_llm_decisions(findings, llm_decisions)
        except OllamaUnavailable as e:
            click.echo(f"Warning: local LLM layer skipped - {e}", err=True)
            click.echo("Use --static-only to suppress this warning.", err=True)
            metadata["llm_used"] = False
            metadata["skipped_layers"].append("local_llm")

    findings = normalize_findings(findings)
    inline_suppressions = collect_inline_suppressions(bundle.root)
    findings = apply_policy_and_baseline(
        findings,
        baseline=baseline,
        policy=policy,
        inline_suppressions=inline_suppressions,
    )
    return findings, metadata


def _merge_llm_decisions(findings: list[dict], llm_decisions: list[dict]) -> list[dict]:
    """Apply LLM confirm/downgrade actions and append new semantic findings."""
    by_fingerprint = {f.get("fingerprint"): f for f in findings if f.get("fingerprint")}
    for decision in llm_decisions:
        action = decision.get("llm_action", "new")
        fingerprint = decision.get("confirmed_fingerprint")
        target = by_fingerprint.get(fingerprint)
        if action == "confirm" and target:
            target["llm_confirmed"] = True
            target["llm_rationale"] = decision.get("rationale", "")
            target["confidence"] = max(
                float(target.get("confidence", 0) or 0),
                float(decision.get("confidence", 0) or 0),
            )
        elif action == "downgrade" and target:
            target["llm_downgraded"] = True
            target["llm_rationale"] = decision.get("rationale", "")
            target["severity"] = "low"
            target["weight"] = min(int(target.get("weight", 5)), 5)
        elif action == "new":
            findings.append(decision)
    return findings


def _safe_run_yara(path: str) -> list[dict]:
    """Run shared YARA rules, but do not fail the whole scan if rules are absent."""
    global _YARA_WARNING_EMITTED
    if run_yara is None:
        if not _YARA_WARNING_EMITTED:
            click.echo("Warning: YARA layer skipped because nyuwaymcpscanner is not installed.", err=True)
            _YARA_WARNING_EMITTED = True
        return []
    try:
        return run_yara(path)
    except FileNotFoundError as e:
        if not _YARA_WARNING_EMITTED:
            click.echo(
                f"Warning: YARA layer skipped because shared rules are unavailable: {e}",
                err=True,
            )
            _YARA_WARNING_EMITTED = True
        return []


if __name__ == "__main__":
    cli()
