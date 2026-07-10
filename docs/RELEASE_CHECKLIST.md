# Release Checklist

Use this checklist before publishing `nyuwayskillscanner` to PyPI or cutting a
GitHub release.

## Pre-Release Validation

```powershell
.\.venv\Scripts\python.exe -m pytest tests/ -q
.\.venv\Scripts\nyuwayskillscanner.exe scan benchmarks\corpus --recursive --static-only --offline
.\.venv\Scripts\nyuwayskillscanner.exe scan benchmarks\corpus --recursive --static-only --offline --policy-pack marketplace --fail-on high
```

The marketplace command should fail on the benchmark corpus because it contains
malicious fixtures. That is expected.

Current expected baseline:

- full suite: `77 passed`
- benchmark fixtures: `22`
- `--skip-skillspector` scorecard: 100% decision accuracy, 0 false positives, 0 false negatives, 100% category recall

## Packaging Validation

Install build tooling in the virtual environment:

```powershell
.\.venv\Scripts\python.exe -m pip install --upgrade build twine
```

Build the package:

```powershell
.\.venv\Scripts\python.exe -m build
```

Validate package metadata:

```powershell
.\.venv\Scripts\python.exe -m twine check dist\*
```

Install the wheel into a clean environment and smoke test:

```powershell
python -m venv %TEMP%\nyuwayskillscanner-release-test
%TEMP%\nyuwayskillscanner-release-test\Scripts\python.exe -m pip install dist\*.whl
%TEMP%\nyuwayskillscanner-release-test\Scripts\nyuwayskillscanner.exe scan benchmarks\corpus\clean\note-summarizer --static-only --offline
```

## Benchmark Report

Generate the normalized local benchmark report:

```powershell
.\.venv\Scripts\python.exe benchmarks\run_peer_benchmark.py --skip-skillspector
```

If SkillSpector is available:

```powershell
.\.venv\Scripts\python.exe benchmarks\run_peer_benchmark.py --skillspector C:\path\to\skillspector.exe
```

Review:

- `benchmarks/reports/peer_scorecard.json`
- `benchmarks/reports/peer_scorecard.md`

Do not commit generated reports unless publishing a specific benchmark snapshot.

## Release Notes Checklist

Include:

- New rule categories.
- New policy-pack behavior.
- New input support.
- Benchmark corpus hash.
- Benchmark fixture count and scorecard summary.
- Known limitations.
- Upgrade notes for suppressions, baselines, and policy files.

## Publish

Use trusted publishing or a scoped PyPI token. Do not store PyPI credentials in
the repository.

```powershell
.\.venv\Scripts\python.exe -m twine upload dist\*
```
