from pathlib import Path

from nyuwayskillscanner.parsers.bundle import (
    FileKind,
    classify_file,
    parse_skill_bundle,
)


def test_classify_file_kinds():
    assert classify_file(Path("SKILL.md")) == FileKind.METADATA
    assert classify_file(Path("scripts/run.py")) == FileKind.SCRIPT
    assert classify_file(Path("scripts/setup.ps1")) == FileKind.SCRIPT
    assert classify_file(Path("requirements.txt")) == FileKind.DEPENDENCY_MANIFEST


def test_parse_clean_skill_bundle(clean_skill_dir):
    bundle = parse_skill_bundle(clean_skill_dir)
    assert bundle.frontmatter_valid is True
    assert bundle.frontmatter["name"] == "pdf-helper"
    assert "Convert office documents" in bundle.frontmatter["description"]
    assert len(bundle.parse_issues) == 0
    assert any(p.name == "convert.py" for p in bundle.files_by_kind[FileKind.SCRIPT])


def test_parse_malformed_frontmatter(tmp_path):
    skill = tmp_path / "bad_skill"
    skill.mkdir()
    (skill / "SKILL.md").write_text("No frontmatter here\n", encoding="utf-8")

    bundle = parse_skill_bundle(skill)
    assert bundle.frontmatter_valid is False
    assert len(bundle.parse_issues) == 1
    assert bundle.parse_issues[0]["type"] == "malformed_skill_metadata"


def test_parse_skill_md_with_utf8_bom(tmp_path):
    skill = tmp_path / "bom_skill"
    skill.mkdir()
    (skill / "SKILL.md").write_text(
        "\ufeff---\nname: bom\ndescription: Valid skill.\n---\n\nBody\n",
        encoding="utf-8",
    )

    bundle = parse_skill_bundle(skill)
    assert bundle.frontmatter_valid is True
    assert bundle.frontmatter["name"] == "bom"
    assert bundle.parse_issues == []
