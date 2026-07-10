# Benchmark Corpus

This corpus is used to measure `nyuwayskillscanner` precision and recall against
peer scanners such as SkillSpector. It is intentionally deterministic so scanner
changes can be tested in CI and compared across tool versions.

## Sets

- `clean/`: skills that should produce `PASS` / `ALLOW`.
- `malicious/`: skills that should produce `HIGH` or `CRITICAL` / `BLOCK`.
- `benign_suspicious/`: skills that contain security-sensitive behavior that is
  documented and should be reviewed rather than automatically treated as
  malicious.

The current corpus contains 22 fixtures:

- clean false-positive checks for documentation, code review, table formatting, and summarization.
- benign-suspicious review fixtures for inline installs, remote content handling, workspace indexing, and typosquat dependencies.
- malicious fixtures for credential forwarding, persistence, memory/output poisoning, sandbox escape, unsafe deserialization, hardcoded secrets, obfuscation, semantic exfiltration/scope creep, PowerShell, shell, JavaScript, and Python destructive scripts.

All credentials, endpoints, and package names in the corpus are synthetic
security fixtures. They are included only to validate scanner behavior and must
not be used as real configuration.

## Usage

```powershell
nyuwayskillscanner scan benchmarks\corpus --recursive --static-only --offline --output json
```

The `expected.json` file lists expected categories per fixture. The benchmark is
not meant to replace unit tests; it is a repeatable product-quality corpus for
false-positive and false-negative tracking.

## Peer Scorecard

Generate normalized JSON and Markdown scorecards:

```powershell
python benchmarks\run_peer_benchmark.py --skip-skillspector
python benchmarks\run_peer_benchmark.py --skillspector C:\path\to\skillspector.exe
```

Generated files:

- `benchmarks/reports/peer_scorecard.json`
- `benchmarks/reports/peer_scorecard.md`

Generated reports include:

- corpus hash,
- fixture count,
- tool versions,
- runtime,
- decision accuracy,
- malicious block rate,
- clean allow rate,
- benign review rate,
- category recall,
- false positives,
- false negatives,
- missed categories.

`benchmarks/reports/` is ignored by git. Commit only deliberate benchmark
snapshots or curated summaries.
