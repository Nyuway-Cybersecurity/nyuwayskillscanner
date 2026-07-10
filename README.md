# nyuwayskillscanner

[![Python](https://img.shields.io/badge/python-3.11%2B-blue)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-Apache--2.0-green)](LICENSE)
[![Security](https://img.shields.io/badge/focus-agent%20skill%20security-red)](#what-it-detects)
[![SARIF](https://img.shields.io/badge/output-SARIF%20%7C%20JSON%20%7C%20Markdown-informational)](#reports)

Enterprise-ready static security scanner for AI agent skill bundles.

`nyuwayskillscanner` scans `SKILL.md` packages and bundled scripts before they
are installed into agent environments, CI pipelines, or shared skill
marketplaces. It turns skill security findings into operational decisions:
`ALLOW`, `REVIEW`, or `BLOCK`.

```text
scan -> explain -> score -> enforce -> monitor
```

## Why This Exists

AI agent skills are installable instruction bundles. They can contain benign
workflow guidance, but they can also hide prompt injection, credential
collection, exfiltration endpoints, persistence instructions, destructive
scripts, unsafe dependency behavior, and obfuscated payloads.

`nyuwayskillscanner` gives developers and security teams a deterministic,
CI-friendly way to inspect those skills before trust is granted.

## Highlights

- Static scanner for `SKILL.md` plus bundled scripts.
- Supports local folders, single `SKILL.md` files, zip archives, Git URLs,
  GitHub shorthand, recursive scans, and installed-skill discovery.
- Detects instruction manipulation, output injection, memory poisoning,
  exfiltration, obfuscation, persistence, sandbox escape, destructive actions,
  unsafe deserialization, secrets, and supply-chain risk.
- Provides enterprise controls: stable fingerprints, baselines, inline
  suppressions, policy packs, SARIF, JSON, Markdown, and CI fail gates.
- Emits install decisions: `ALLOW`, `REVIEW`, `BLOCK`.
- Includes a repeatable 22-fixture benchmark corpus and normalized peer
  scorecard runner.
- Runs fully offline with `--static-only --offline` for deterministic CI.

## Install

### From Source

```bash
git clone https://github.com/Nyuway-Cybersecurity/nyuwayskillscanner.git
cd nyuwayskillscanner
python -m pip install -e ".[dev]"
```

### From PyPI

```bash
pip install nyuwayskillscanner
```

## Quick Start

Scan a skill directory:

```bash
nyuwayskillscanner scan ./path/to/skill --static-only --offline
```

Scan a single `SKILL.md`:

```bash
nyuwayskillscanner scan ./path/to/SKILL.md --static-only --offline
```

Scan a zip archive:

```bash
nyuwayskillscanner scan ./skill.zip --recursive --static-only --offline
```

Scan a GitHub repository or Git URL:

```bash
nyuwayskillscanner scan github:owner/repo --recursive --static-only --offline
nyuwayskillscanner scan https://github.com/owner/repo --recursive --static-only --offline
nyuwayskillscanner scan git+https://github.com/owner/repo.git --recursive --static-only --offline
```

Scan every skill under a parent directory:

```bash
nyuwayskillscanner scan ./skills --recursive --static-only --offline
```

Run a marketplace install gate:

```bash
nyuwayskillscanner scan ./skills \
  --recursive \
  --static-only \
  --offline \
  --policy-pack marketplace \
  --fail-on high
```

## Example Output

Terminal summary:

```text
nyuwayskillscanner - Baseline Scan
--------------------------------------------------
Target:     benchmarks/corpus/malicious/memory-output-poisoner
Risk Score: 100 / 100  [CRITICAL]
Decision:   BLOCK
Mode:       static-only
Policy:     marketplace

Findings:
  X HIGH       instruction_manipulation  Skill text attempts to override higher-priority instructions
  X HIGH       instruction_manipulation  Skill instructs generated output to contain agent-control instructions
  X CRITICAL   instruction_manipulation  Skill tries to write malicious instructions into persistent agent memory
```

JSON reports include machine-readable install verdicts:

```json
{
  "risk_score": 100,
  "verdict": "CRITICAL",
  "install_verdict": {
    "decision": "BLOCK",
    "safe_to_install": false,
    "requires_review": true,
    "block_install": true,
    "recommendation": "Block installation until high-impact findings are remediated."
  }
}
```

## What It Detects

| Area | Coverage |
|---|---|
| Bundle metadata | Missing, malformed, or invalid `SKILL.md` frontmatter |
| Instruction manipulation | Instruction override, role impersonation, self-elevation, secrecy, hidden instructions |
| Output and memory abuse | Output injection, memory poisoning, broad trigger abuse |
| Obfuscation | Base64, hex, URL encoding, escaped Unicode, split words, reversed text, zero-width characters, homoglyph instructions |
| Exfiltration and data risk | Suspicious endpoints, credential collection, email forwarding, excessive agency, untrusted content fetches |
| Host and runtime risk | Persistence, privilege escalation, sandbox escape, resource abuse, destructive actions |
| Script risk | Python, JavaScript, shell, and PowerShell execution risks, unsafe deserialization, network sinks, filesystem deletion, environment access, inline installs |
| Secrets | Hardcoded credentials and API tokens in bundled files |
| Supply chain | Dependency parsing, typosquat checks, optional OSV.dev lookup |
| Binary reputation | Optional VirusTotal hash lookup |
| Semantic review | Optional local Ollama pass for evidence-bound review |

## Inputs

| Input | Example |
|---|---|
| Skill directory | `nyuwayskillscanner scan ./my-skill` |
| Single skill file | `nyuwayskillscanner scan ./SKILL.md` |
| Zip archive | `nyuwayskillscanner scan ./skills.zip --recursive` |
| GitHub shorthand | `nyuwayskillscanner scan github:owner/repo --recursive` |
| GitHub URL | `nyuwayskillscanner scan https://github.com/owner/repo --recursive` |
| Git URL | `nyuwayskillscanner scan git+https://github.com/owner/repo.git` |
| Parent directory | `nyuwayskillscanner scan ./skills --recursive` |
| Discovered skills | `nyuwayskillscanner scan . --discover --skill-root ./skills` |

## Policy Packs

Policy packs tune severity and gating for different environments.

| Pack | Use Case |
|---|---|
| `personal` | Local experimentation with lower noise |
| `audit` | Critical-only triage |
| `default` | General local and CI scanning |
| `enterprise` | Internal enterprise agent environments |
| `marketplace` | Shared catalogs, publish gates, install gates |
| `strict` | High-assurance review |

Example:

```bash
nyuwayskillscanner scan ./skills \
  --recursive \
  --static-only \
  --offline \
  --policy-pack enterprise \
  --output sarif > nyuwayskillscanner.sarif
```

Custom policy files are supported:

```yaml
minimum_severity: medium
severity_overrides:
  self_elevation: high
  supply_chain_inline_install: high
```

```bash
nyuwayskillscanner scan ./skill --policy-pack default --policy-file policy.yml
```

## Reports

| Format | Use |
|---|---|
| `summary` | Human-readable terminal output |
| `json` | CI, installer, marketplace, or backend integration |
| `sarif` | GitHub code scanning and SARIF-compatible systems |
| `markdown` | Human security review and audit artifacts |

```bash
nyuwayskillscanner scan ./skill --static-only --offline --output json
nyuwayskillscanner scan ./skill --static-only --offline --output sarif > report.sarif
nyuwayskillscanner scan ./skill --static-only --offline --output markdown > report.md
```

## CI and Marketplace Gates

Recommended deterministic CI gate:

```bash
nyuwayskillscanner scan ./skills \
  --recursive \
  --static-only \
  --offline \
  --policy-pack marketplace \
  --fail-on high
```

The command exits non-zero when any active finding is `high` or `critical`.

GitHub Actions example:

```yaml
- name: Scan agent skills
  run: |
    nyuwayskillscanner scan ./skills \
      --recursive \
      --static-only \
      --offline \
      --policy-pack marketplace \
      --fail-on high \
      --output sarif > nyuwayskillscanner.sarif
```

See `docs/ci/github-action-skill-scan.yml` for a complete workflow.

## Suppressions and Baselines

Every finding has a stable fingerprint for baseline suppression:

```bash
nyuwayskillscanner scan ./skills --recursive --baseline baseline.json
```

Inline suppressions require an explicit justification:

```html
<!-- nyuway: ignore instruction_manipulation/self_elevation because approved internal fixture -->
```

Suppressions should be treated as documented risk acceptances, not fixes.

## Benchmarking

The benchmark corpus currently contains 22 fixtures:

- clean false-positive fixtures,
- benign-suspicious review fixtures,
- malicious natural-language attacks,
- obfuscated instruction attacks,
- script-heavy Python, JavaScript, shell, and PowerShell attacks,
- hardcoded secret and supply-chain fixtures.

Run Nyuway against the corpus:

```bash
python benchmarks/run_peer_benchmark.py --skip-skillspector
```

Run a peer comparison if SkillSpector is installed:

```bash
python benchmarks/run_peer_benchmark.py --skillspector /path/to/skillspector
```

Generated scorecards are written to `benchmarks/reports/`:

- `peer_scorecard.json`
- `peer_scorecard.md`

Current local validation:

| Metric | Result |
|---|---:|
| Tests | `77 passed` |
| Benchmark fixtures | `22` |
| Expected decision accuracy | `100%` |
| Malicious block rate | `100%` |
| Clean allow rate | `100%` |
| Benign review rate | `100%` |
| Category recall | `100%` |
| False positives | `0` |
| False negatives | `0` |

See `benchmarks/README.md` and `benchmarks/PEER_COMPARISON.md` for details.

## CLI Reference

```text
nyuwayskillscanner scan TARGET [OPTIONS]

TARGET
  ./path/to/skill        Skill directory containing SKILL.md
  ./path/to/SKILL.md     Single skill file
  ./skill.zip            Zip archive containing one or more skills
  github:owner/repo      GitHub repository shorthand
  https://github.com/... GitHub repository URL
  git+URL                Explicit Git URL
  ./skills/parent        Parent directory, use --recursive

Options
  --recursive            Scan each child directory that contains SKILL.md
  --discover             Auto-discover installed skills
  --skill-root PATH      Additional root for discovery
  --include GLOB         Include glob for discovery
  --exclude GLOB         Exclude glob for discovery
  --static-only          Skip local LLM layer
  --offline              Skip OSV.dev and VirusTotal network calls
  --output FORMAT        summary, json, sarif, markdown
  --fail-on LEVEL        Exit non-zero when any finding meets severity
  --baseline PATH        Suppress accepted finding fingerprints
  --policy-pack PACK     personal, audit, default, enterprise, marketplace, strict
  --policy-file PATH     Custom YAML severity/policy overrides
  --model MODEL          Ollama model for the local LLM pass
  --vt-key KEY           VirusTotal API key
```

## Project Layout

```text
nyuwayskillscanner/
  cli/main.py                 CLI entry point
  discovery.py                Installed skill discovery
  sources.py                  Local, zip, Git, GitHub source resolution
  parsers/bundle.py           SKILL.md parser and file classifier
  scanners/injection.py       Instruction and prose risk detector
  scanners/code_static.py     Bundled script risk detector
  scanners/llm_safety.py      Optional local LLM semantic pass
  output/                     JSON, SARIF, Markdown, terminal reports

nyuway_scan_core/
  findings.py                 Normalization, fingerprints, install decisions
  policy.py                   Policy packs, baselines, inline suppressions
  scoring.py                  Severity-weighted 0-100 scoring
  secrets.py                  Shared secret detection
  supply_chain.py             Dependency parsing, OSV.dev, typosquat checks
  virustotal.py               Optional binary hash lookup

benchmarks/
  corpus/                     Clean, benign-suspicious, malicious fixtures
  expected.json               Expected verdict and category map
  run_peer_benchmark.py       Normalized peer scorecard runner
```

## Documentation

- `docs/CI_INTEGRATION.md`: CI gates, SARIF upload, benchmark jobs.
- `docs/POLICY_PACKS.md`: policy pack behavior and custom policies.
- `docs/MARKETPLACE_DECISIONS.md`: `ALLOW`, `REVIEW`, `BLOCK` decision model.
- `docs/EXAMPLES.md`: local, CI, marketplace, and benchmark examples.
- `docs/RELEASE_CHECKLIST.md`: PyPI and packaging validation.

## License

Apache 2.0. See [LICENSE](LICENSE).
