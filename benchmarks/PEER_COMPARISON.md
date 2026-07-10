# Peer Comparison: SkillSpector Static Baseline

This document records the checked-in SkillSpector comparison notes. The benchmark
runner has since been upgraded to generate normalized JSON and Markdown
scorecards under `benchmarks/reports/`.

Use this command for the current repeatable benchmark:

```powershell
python benchmarks\run_peer_benchmark.py --skillspector <path-to-skillspector.exe>
```

Use this command to validate only `nyuwayskillscanner` against the corpus:

```powershell
python benchmarks\run_peer_benchmark.py --skip-skillspector
```

The runner reports corpus hash, fixture count, tool versions, runtime, decision
accuracy, false positives, false negatives, and category recall.

## Tool Versions

- `nyuwayskillscanner`: local development version `0.1.0`
- `SkillSpector`: `2.3.11`, installed from `NVIDIA/SkillSpector`

## Historical Command

```powershell
python benchmarks\run_peer_benchmark.py --skillspector <path-to-skillspector.exe>
```

## Results

These rows are from the original static/no-LLM comparison snapshot. The corpus is
now larger than this table; use generated scorecards for current numbers.

| Fixture | Expected | nyuwayskillscanner | SkillSpector |
|---|---|---|---|
| `clean/note-summarizer` | PASS | PASS, score 0, no findings | SAFE, score 0, no findings |
| `benign_suspicious/dependency-installer` | MEDIUM review | MEDIUM, score 40, `supply_chain_inline_install` | SAFE, score 17, reports `Privilege Escalation` from the phrase "do not access secrets" |
| `malicious/credential-forwarder` | CRITICAL block | CRITICAL, score 100, blocks install | SAFE, score 0, no findings |
| `malicious/persistence-installer` | CRITICAL block | CRITICAL, score 80, blocks install | CAUTION, score 31, does not block install |
| `malicious/memory-output-poisoner` | CRITICAL block | Detects output injection, memory poisoning, trigger abuse | Not evaluated in historical SkillSpector snapshot |
| `malicious/sandbox-resource-abuser` | CRITICAL block | Detects sandbox escape, resource abuse, tool misuse | Not evaluated in historical SkillSpector snapshot |
| `malicious/script-exfil-deserializer` | CRITICAL block | Detects exfiltration, unsafe deserialization, dangerous code, data destruction | Not evaluated in historical SkillSpector snapshot |

## Summary

| Metric | nyuwayskillscanner | SkillSpector |
|---|---:|---:|
| Malicious block rate | 100% | 0% |
| Clean safe/pass rate | 100% | 100% |

## Current Nyuway Corpus Validation

Latest local `--skip-skillspector` scorecard against the expanded corpus:

| Metric | Result |
|---|---:|
| Fixtures evaluated | 22 |
| Decision accuracy | 100% |
| Malicious block rate | 100% |
| Clean allow rate | 100% |
| Benign review rate | 100% |
| Category recall | 100% |
| False positives | 0 |
| False negatives | 0 |

This validates our expected corpus behavior. It is not a peer comparison until
SkillSpector is run with the same corpus and command.

## Interpretation

On this targeted static corpus, `nyuwayskillscanner` is stronger at detecting
natural-language skill attacks:

- It catches role impersonation, instruction override, self-elevation,
  credential collection, covert exfiltration, secrecy, persistence, and
  privilege escalation in `SKILL.md` prose.
- It assigns enterprise install decisions (`block_install`, `requires_review`,
  `safe_to_install`) instead of only a score/recommendation.
- It treats a documented inline dependency install as reviewable MEDIUM risk,
  while SkillSpector reports a less relevant privilege-escalation issue from the
  phrase "do not access secrets."

This is not a claim that `nyuwayskillscanner` is universally better than
SkillSpector yet. SkillSpector may still have a larger research corpus, mature
rules in areas we have not benchmarked, or different LLM-enabled behavior. The
current evidence supports a narrower claim:

> In static/no-LLM analysis of the included benchmark corpus,
> `nyuwayskillscanner` catches and blocks natural-language malicious skills that
> SkillSpector `2.3.11` misses or under-severitizes.

## Remaining Benchmark Expansion

To make the comparison publication-grade, continue expanding the corpus toward:

- At least 50 clean real-world skills.
- At least 25 malicious natural-language attack fixtures.
- At least 25 script-heavy malicious fixtures.
- At least 25 benign-but-sensitive fixtures to measure false positives.
- Optional LLM-enabled runs for both tools where credentials/providers are
  available.
