# Examples

## Local Developer Scan

```bash
nyuwayskillscanner scan ./my-skill --static-only --offline
```

Use this while authoring a skill. It avoids network and LLM calls.

## Marketplace Gate

```bash
nyuwayskillscanner scan ./skills \
  --recursive \
  --static-only \
  --offline \
  --policy-pack marketplace \
  --fail-on high
```

Use this before listing or installing shared skills. `BLOCK` means the skill
should not be published or installed until fixed.

## Enterprise CI With SARIF

```bash
nyuwayskillscanner scan ./skills \
  --recursive \
  --static-only \
  --offline \
  --policy-pack enterprise \
  --output sarif > nyuwayskillscanner.sarif
```

Upload the SARIF file to GitHub code scanning or another SARIF consumer.

## JSON Install Decision

```bash
nyuwayskillscanner scan ./skill --static-only --offline --output json
```

Read:

```json
{
  "install_verdict": {
    "decision": "ALLOW"
  }
}
```

Decision values are `ALLOW`, `REVIEW`, and `BLOCK`.

## Baseline Accepted Findings

```bash
nyuwayskillscanner scan ./skills \
  --recursive \
  --static-only \
  --offline \
  --baseline baseline.json
```

Baselines should be reviewed like risk acceptances.

## Benchmark Against Peers

```bash
python benchmarks/run_peer_benchmark.py --skip-skillspector
python benchmarks/run_peer_benchmark.py --skillspector /path/to/skillspector
```

Outputs are written to `benchmarks/reports/`.

The generated scorecard includes decision accuracy, false positives, false
negatives, category recall, corpus hash, and per-fixture runtime.

## Validate the Built-In Corpus

```bash
nyuwayskillscanner scan benchmarks/corpus --recursive --static-only --offline
```

For marketplace policy validation, this command should fail because the corpus
contains malicious fixtures:

```bash
nyuwayskillscanner scan benchmarks/corpus \
  --recursive \
  --static-only \
  --offline \
  --policy-pack marketplace \
  --fail-on high
```
