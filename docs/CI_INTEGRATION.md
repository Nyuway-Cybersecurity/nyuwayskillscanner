# CI Integration

Use `nyuwayskillscanner` in CI to block risky skills before they are merged,
published, or installed into an agent environment.

## Recommended Gate

For repositories that publish or host skills, use the marketplace policy pack:

```bash
nyuwayskillscanner scan ./skills \
  --recursive \
  --static-only \
  --offline \
  --policy-pack marketplace \
  --fail-on high
```

This exits non-zero when active findings are `high` or `critical`.

Use `--static-only --offline` for deterministic CI. Enable OSV.dev,
VirusTotal, or local LLM analysis only when those services are available and
their latency is acceptable for the pipeline.

## SARIF Upload

Generate SARIF for GitHub code scanning:

```bash
nyuwayskillscanner scan ./skills \
  --recursive \
  --static-only \
  --offline \
  --policy-pack marketplace \
  --output sarif > nyuwayskillscanner.sarif
```

See `docs/ci/github-action-skill-scan.yml` for a complete GitHub Actions
workflow.

## JSON Policy Gate

For custom CI systems, use JSON and read `install_verdict.decision`:

```bash
nyuwayskillscanner scan ./skills --recursive --static-only --offline --output json
```

Decision values:

- `ALLOW`: no blocking findings detected.
- `REVIEW`: risk acceptance or security review required.
- `BLOCK`: do not install or publish until findings are fixed.

## Baselines

Use baselines only for accepted findings with a written reason:

```bash
nyuwayskillscanner scan ./skills \
  --recursive \
  --static-only \
  --offline \
  --baseline baseline.json \
  --fail-on high
```

Baseline files contain fingerprints from prior JSON, Markdown, or terminal
reports. Revisit baselines regularly; they are risk acceptances, not fixes.

## Benchmark Job

For scanner development, add a separate non-production benchmark job:

```bash
python benchmarks/run_peer_benchmark.py --skip-skillspector
```

The generated scorecard under `benchmarks/reports/` should show no false
positives, no false negatives, and complete category recall for the expected
corpus. Do not use the intentionally malicious corpus as a publish gate for
customer skills.
