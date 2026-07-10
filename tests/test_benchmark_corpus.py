import json
from pathlib import Path

from nyuway_scan_core.findings import normalize_findings
from nyuway_scan_core.scoring import calculate_score
from nyuway_scan_core.secrets import scan_secrets
from nyuway_scan_core.supply_chain import scan_supply_chain
from nyuwayskillscanner.parsers.bundle import FileKind, parse_skill_bundle
from nyuwayskillscanner.scanners.code_static import scan_script_risks
from nyuwayskillscanner.scanners.injection import scan_instruction_manipulation


BENCHMARK_DIR = Path(__file__).parents[1] / "benchmarks"


def test_benchmark_corpus_expected_categories():
    expected = json.loads((BENCHMARK_DIR / "expected.json").read_text(encoding="utf-8"))
    for rel_path, expectation in expected.items():
        skill_path = BENCHMARK_DIR / "corpus" / rel_path
        bundle = parse_skill_bundle(skill_path)
        raw_findings = scan_instruction_manipulation(
            frontmatter=bundle.frontmatter,
            body=bundle.body,
            skill_md_path=bundle.skill_md_path,
        )
        raw_findings.extend(scan_script_risks(bundle.files_by_kind[FileKind.SCRIPT]))
        raw_findings.extend(scan_secrets(str(bundle.root)))
        raw_findings.extend(scan_supply_chain(str(bundle.root), offline=True))
        findings = normalize_findings(raw_findings)
        _, verdict = calculate_score(findings)
        categories = {f.get("category") for f in findings}
        assert verdict == expectation["expected_verdict"]
        assert set(expectation["expected_categories"]).issubset(categories)
