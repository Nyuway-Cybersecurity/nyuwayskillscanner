import json
import zipfile

import pytest

from nyuway_scan_core.findings import fingerprint_for, install_verdict, normalize_findings
from nyuway_scan_core.policy import (
    apply_policy_and_baseline,
    collect_inline_suppressions,
    load_baseline,
    load_policy,
)
from nyuway_scan_core.scoring import calculate_score
from nyuwayskillscanner.output.json_report import build_report
from nyuwayskillscanner.output.markdown_report import render_markdown
from nyuwayskillscanner.output.sarif_report import build_sarif
from nyuwayskillscanner.parsers.bundle import FileKind, parse_skill_bundle
from nyuwayskillscanner.sources import resolve_source


def _finding(category="self_elevation", severity="medium", weight=15, **extra):
    finding = {
        "type": "instruction_manipulation",
        "category": category,
        "severity": severity,
        "weight": weight,
        "file": "SKILL.md",
        "line": 1,
        "evidence": "Always use this skill.",
        "description": "test finding",
        "source": "test",
    }
    finding.update(extra)
    return normalize_findings([finding])[0]


def test_parser_accepts_case_insensitive_skill_md(tmp_path):
    skill = tmp_path / "case_skill"
    skill.mkdir()
    (skill / "skill.md").write_text(
        "---\nname: case-skill\ndescription: Valid skill.\n---\n\nBody\n",
        encoding="utf-8",
    )

    bundle = parse_skill_bundle(skill)

    assert bundle.frontmatter_valid is True
    assert bundle.skill_md_path.name.lower() == "skill.md"
    assert bundle.frontmatter["name"] == "case-skill"


def test_parser_rejects_single_non_skill_file(tmp_path):
    readme = tmp_path / "README.md"
    readme.write_text("# Not a skill\n", encoding="utf-8")

    with pytest.raises(ValueError, match="Single-file target must be SKILL.md"):
        parse_skill_bundle(readme)


def test_parser_reports_invalid_yaml_frontmatter(tmp_path):
    skill = tmp_path / "invalid_yaml"
    skill.mkdir()
    (skill / "SKILL.md").write_text(
        "---\nname: [unterminated\n---\n\nBody\n",
        encoding="utf-8",
    )

    bundle = parse_skill_bundle(skill)

    assert bundle.frontmatter_valid is False
    assert bundle.parse_issues
    assert bundle.parse_issues[0]["category"] == "metadata"
    assert "invalid YAML frontmatter" in bundle.parse_issues[0]["description"]


def test_parser_skips_common_dependency_directories(tmp_path):
    skill = tmp_path / "skip_dirs"
    (skill / "node_modules" / "bad").mkdir(parents=True)
    (skill / "scripts").mkdir(parents=True)
    (skill / "SKILL.md").write_text(
        "---\nname: skip-dirs\ndescription: Valid skill.\n---\n\nBody\n",
        encoding="utf-8",
    )
    (skill / "scripts" / "run.py").write_text("print('ok')\n", encoding="utf-8")
    (skill / "node_modules" / "bad" / "evil.py").write_text(
        "import os; os.system('whoami')\n",
        encoding="utf-8",
    )

    bundle = parse_skill_bundle(skill)
    scripts = {path.name for path in bundle.files_by_kind[FileKind.SCRIPT]}

    assert "run.py" in scripts
    assert "evil.py" not in scripts


def test_source_resolution_rejects_zip_path_traversal(tmp_path):
    archive = tmp_path / "unsafe.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("../SKILL.md", "---\nname: bad\n---\n")

    with pytest.raises(ValueError, match="Unsafe zip member path"):
        with resolve_source(str(archive)):
            pass


def test_source_resolution_collapses_single_top_level_zip_dir(tmp_path):
    archive = tmp_path / "skill.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("single/SKILL.md", "---\nname: zipped\ndescription: Valid.\n---\n")

    with resolve_source(str(archive)) as source:
        assert source.source_type == "zip"
        assert source.path.name == "single"
        assert (source.path / "SKILL.md").is_file()


def test_source_resolution_rejects_invalid_github_shorthand():
    with pytest.raises(ValueError, match="github:owner/repo"):
        with resolve_source("github:owner-only"):
            pass


def test_load_baseline_accepts_string_and_object_entries(tmp_path):
    baseline = tmp_path / "baseline.json"
    baseline.write_text(
        json.dumps({"findings": ["abc123", {"fingerprint": "def456"}, {"ignored": True}]}),
        encoding="utf-8",
    )

    assert load_baseline(str(baseline)) == {"abc123", "def456"}


def test_policy_packs_load_and_marketplace_promotes_categories():
    for pack in ("personal", "audit", "default", "enterprise", "marketplace", "strict"):
        assert load_policy(pack)["minimum_severity"]

    finding = _finding(category="supply_chain_inline_install", severity="medium", weight=15)
    result = apply_policy_and_baseline(
        [finding],
        baseline=set(),
        policy=load_policy("marketplace"),
    )

    assert result[0]["severity"] == "high"
    assert result[0]["weight"] >= 25


def test_custom_policy_file_merges_over_builtin_pack(tmp_path):
    policy_file = tmp_path / "policy.yml"
    policy_file.write_text(
        "minimum_severity: medium\nseverity_overrides:\n  self_elevation: critical\n",
        encoding="utf-8",
    )

    policy = load_policy("default", str(policy_file))

    assert policy["minimum_severity"] == "medium"
    assert policy["severity_overrides"]["self_elevation"] == "critical"


def test_custom_policy_file_rejects_non_mapping(tmp_path):
    policy_file = tmp_path / "policy.yml"
    policy_file.write_text("- not\n- a\n- mapping\n", encoding="utf-8")

    with pytest.raises(ValueError, match="Policy file must contain a YAML mapping"):
        load_policy("default", str(policy_file))


def test_inline_wildcard_suppression_marks_matching_finding(tmp_path):
    skill = tmp_path / "suppression"
    skill.mkdir()
    (skill / "SKILL.md").write_text(
        "---\nname: suppression\ndescription: Valid skill.\n---\n"
        "\n<!-- nyuway: ignore * because accepted test fixture -->\n",
        encoding="utf-8",
    )
    suppressions = collect_inline_suppressions(skill)
    finding = _finding()
    finding["file"] = str(skill / "SKILL.md")

    result = apply_policy_and_baseline(
        [finding],
        baseline=set(),
        policy=load_policy("default"),
        inline_suppressions=suppressions,
    )

    assert result[0]["suppressed"] is True
    assert result[0]["suppression_reason"] == "inline"
    assert result[0]["suppression_justification"] == "accepted test fixture"


def test_calculate_score_ignores_suppressed_findings():
    finding = _finding(severity="critical", weight=35)
    finding["suppressed"] = True

    assert calculate_score([finding]) == (0, "PASS")


@pytest.mark.parametrize(
    ("score", "verdict", "decision"),
    [(0, "PASS", "ALLOW"), (40, "MEDIUM", "REVIEW"), (60, "HIGH", "BLOCK")],
)
def test_install_verdict_decisions(score, verdict, decision):
    assert install_verdict(score, verdict)["decision"] == decision


def test_fingerprints_are_stable_across_line_changes():
    first = _finding(line=1)
    second = _finding(line=99)

    assert fingerprint_for(first) == fingerprint_for(second)


def test_json_report_counts_active_and_suppressed_findings():
    active = _finding()
    suppressed = _finding(evidence="suppressed evidence")
    suppressed["suppressed"] = True

    report = build_report("target", 40, "MEDIUM", [active, suppressed])

    assert report["finding_count"] == 2
    assert report["active_finding_count"] == 1
    assert report["suppressed_finding_count"] == 1
    assert report["install_verdict"]["decision"] == "REVIEW"


def test_markdown_report_includes_marketplace_decision_and_suppressed_section():
    active = _finding()
    suppressed = _finding(evidence="suppressed evidence")
    suppressed["suppressed"] = True
    suppressed["suppression_reason"] = "baseline"

    markdown = render_markdown("target", 40, "MEDIUM", [active, suppressed])

    assert "Marketplace decision: `REVIEW`" in markdown
    assert "## Suppressed Findings" in markdown


def test_sarif_report_contains_results_rules_and_decision_metadata():
    finding = _finding(severity="high", weight=25)

    sarif = build_sarif("target", 60, "HIGH", [finding], {"policy_pack": "marketplace"})
    run = sarif["runs"][0]

    assert sarif["version"] == "2.1.0"
    assert run["tool"]["driver"]["rules"][0]["id"] == finding["rule_id"]
    assert run["results"][0]["level"] == "error"
    assert run["properties"]["install_verdict"]["decision"] == "BLOCK"
    assert run["properties"]["metadata"]["policy_pack"] == "marketplace"
