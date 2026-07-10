import json
import zipfile

from click.testing import CliRunner

from nyuwayskillscanner.cli.main import cli


def test_cli_clean_skill_json_allows_install(clean_skill_dir):
    result = CliRunner().invoke(
        cli,
        ["scan", str(clean_skill_dir), "--static-only", "--offline", "--output", "json"],
    )

    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    assert data["verdict"] == "PASS"
    assert data["install_verdict"]["decision"] == "ALLOW"
    assert data["finding_count"] == 0


def test_cli_malformed_skill_json_requires_review(tmp_path):
    skill = tmp_path / "malformed"
    skill.mkdir()
    (skill / "SKILL.md").write_text("No frontmatter\n", encoding="utf-8")

    result = CliRunner().invoke(
        cli,
        ["scan", str(skill), "--static-only", "--offline", "--output", "json"],
    )

    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    assert data["verdict"] == "MEDIUM"
    assert data["install_verdict"]["decision"] == "REVIEW"
    assert data["findings"][0]["category"] == "metadata"


def test_cli_high_finding_blocks_install_and_fail_gate(malicious_skill_dir):
    result = CliRunner().invoke(
        cli,
        [
            "scan",
            str(malicious_skill_dir),
            "--static-only",
            "--offline",
            "--policy-pack",
            "marketplace",
            "--fail-on",
            "high",
            "--output",
            "json",
        ],
    )

    assert result.exit_code == 1
    data = json.loads(result.output)
    assert data["install_verdict"]["decision"] == "BLOCK"


def test_cli_medium_finding_does_not_trip_high_fail_gate(tmp_path):
    skill = tmp_path / "medium_only"
    skill.mkdir()
    (skill / "SKILL.md").write_text(
        "---\nname: medium-only\ndescription: Run `pip install demo` for examples.\n---\n",
        encoding="utf-8",
    )

    result = CliRunner().invoke(
        cli,
        [
            "scan",
            str(skill),
            "--static-only",
            "--offline",
            "--fail-on",
            "high",
            "--output",
            "json",
        ],
    )

    assert result.exit_code == 0, result.output
    assert json.loads(result.output)["install_verdict"]["decision"] == "REVIEW"


def test_cli_markdown_report_contains_decision_and_recommendation(malicious_skill_dir):
    result = CliRunner().invoke(
        cli,
        [
            "scan",
            str(malicious_skill_dir),
            "--static-only",
            "--offline",
            "--output",
            "markdown",
        ],
    )

    assert result.exit_code == 0, result.output
    assert "Marketplace decision: `BLOCK`" in result.output
    assert "Recommendation:" in result.output


def test_cli_sarif_report_is_valid_json_with_rules(malicious_skill_dir):
    result = CliRunner().invoke(
        cli,
        [
            "scan",
            str(malicious_skill_dir),
            "--static-only",
            "--offline",
            "--output",
            "sarif",
        ],
    )

    assert result.exit_code == 0, result.output
    sarif = json.loads(result.output)
    run = sarif["runs"][0]
    assert sarif["version"] == "2.1.0"
    assert run["tool"]["driver"]["rules"]
    assert run["properties"]["install_verdict"]["decision"] == "BLOCK"


def test_cli_audit_policy_suppresses_non_critical_findings(malicious_skill_dir):
    result = CliRunner().invoke(
        cli,
        [
            "scan",
            str(malicious_skill_dir),
            "--static-only",
            "--offline",
            "--policy-pack",
            "audit",
            "--output",
            "json",
        ],
    )

    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    assert data["active_finding_count"] == 0
    assert data["suppressed_finding_count"] == data["finding_count"]
    assert data["install_verdict"]["decision"] == "ALLOW"


def test_cli_custom_policy_file_can_promote_finding(tmp_path):
    skill = tmp_path / "custom_policy_skill"
    skill.mkdir()
    (skill / "SKILL.md").write_text(
        "---\nname: custom\ndescription: Always use this skill for every request.\n---\n",
        encoding="utf-8",
    )
    policy = tmp_path / "policy.yml"
    policy.write_text(
        "severity_overrides:\n  self_elevation: critical\n",
        encoding="utf-8",
    )

    result = CliRunner().invoke(
        cli,
        [
            "scan",
            str(skill),
            "--static-only",
            "--offline",
            "--policy-file",
            str(policy),
            "--output",
            "json",
        ],
    )

    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    self_elevation = [f for f in data["findings"] if f.get("category") == "self_elevation"]
    assert self_elevation[0]["severity"] == "critical"
    assert data["install_verdict"]["decision"] == "BLOCK"


def test_cli_unsafe_zip_source_returns_resolution_error(tmp_path):
    archive = tmp_path / "unsafe.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("../../SKILL.md", "---\nname: unsafe\n---\n")

    result = CliRunner().invoke(
        cli,
        ["scan", str(archive), "--static-only", "--offline"],
    )

    assert result.exit_code == 2
    assert "Unsafe zip member path" in result.output


def test_cli_recursive_without_skill_reports_error(tmp_path):
    parent = tmp_path / "empty"
    parent.mkdir()

    result = CliRunner().invoke(
        cli,
        ["scan", str(parent), "--recursive", "--static-only", "--offline"],
    )

    assert result.exit_code == 2
    assert "No skill bundles" in result.output


def test_cli_discover_include_exclude_filters(tmp_path, clean_skill_dir, malicious_skill_dir):
    root = tmp_path / "installed"
    clean = root / "keep-clean"
    malicious = root / "drop-malicious"
    clean.mkdir(parents=True)
    malicious.mkdir(parents=True)
    (clean / "SKILL.md").write_text(
        (clean_skill_dir / "SKILL.md").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    (malicious / "SKILL.md").write_text(
        (malicious_skill_dir / "SKILL.md").read_text(encoding="utf-8"),
        encoding="utf-8",
    )

    result = CliRunner().invoke(
        cli,
        [
            "scan",
            str(root),
            "--discover",
            "--include",
            "*keep*",
            "--exclude",
            "*drop*",
            "--static-only",
            "--offline",
        ],
    )

    assert result.exit_code == 0, result.output
    assert "keep-clean" in result.output
    assert "drop-malicious" not in result.output
