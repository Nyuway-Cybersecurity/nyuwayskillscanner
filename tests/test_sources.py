import shutil
import subprocess
import zipfile

import pytest
from click.testing import CliRunner

from nyuwayskillscanner.cli.main import cli


def test_scan_single_skill_md_file(clean_skill_dir):
    runner = CliRunner()
    result = runner.invoke(
        cli,
        ["scan", str(clean_skill_dir / "SKILL.md"), "--static-only", "--offline"],
    )
    assert result.exit_code == 0, result.output


def test_scan_zip_archive(tmp_path, clean_skill_dir):
    archive = tmp_path / "skill.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.write(clean_skill_dir / "SKILL.md", "SKILL.md")

    runner = CliRunner()
    result = runner.invoke(
        cli,
        ["scan", str(archive), "--static-only", "--offline"],
    )
    assert result.exit_code == 0, result.output
    assert "Risk Score" in result.output


def test_scan_nested_zip_archive_recursive(tmp_path, clean_skill_dir, malicious_skill_dir):
    archive = tmp_path / "skills.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        for src in (clean_skill_dir, malicious_skill_dir):
            zf.write(src / "SKILL.md", f"group/{src.name}/SKILL.md")

    runner = CliRunner()
    result = runner.invoke(
        cli,
        ["scan", str(archive), "--recursive", "--static-only", "--offline"],
    )
    assert result.exit_code == 0, result.output
    assert "clean_skill" in result.output
    assert "malicious_skill" in result.output


def test_scan_git_source_from_local_repo(tmp_path, clean_skill_dir):
    if not shutil.which("git"):
        pytest.skip("git not installed")

    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "SKILL.md").write_text(
        (clean_skill_dir / "SKILL.md").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    subprocess.run(["git", "init"], cwd=repo, check=True, capture_output=True, text=True)
    subprocess.run(["git", "add", "."], cwd=repo, check=True, capture_output=True, text=True)
    subprocess.run(
        [
            "git",
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.com",
            "commit",
            "-m",
            "init",
        ],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    )

    runner = CliRunner()
    result = runner.invoke(
        cli,
        ["scan", f"git+{repo}", "--static-only", "--offline"],
    )
    assert result.exit_code == 0, result.output
