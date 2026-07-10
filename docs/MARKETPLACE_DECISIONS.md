# Marketplace Decisions

`nyuwayskillscanner` emits a simple install decision in every JSON, Markdown,
and terminal report.

## Decision Values

| Decision | Meaning | Typical Action |
|---|---|---|
| `ALLOW` | No active findings require review. | Skill can be installed or listed. |
| `REVIEW` | Medium-risk findings exist. | Security or marketplace reviewer should approve, reject, or baseline with justification. |
| `BLOCK` | High or critical findings exist. | Do not install, publish, or list until remediated. |

The JSON field is:

```json
{
  "install_verdict": {
    "decision": "BLOCK",
    "safe_to_install": false,
    "requires_review": true,
    "block_install": true,
    "recommendation": "Block installation until high-impact findings are remediated."
  }
}
```

## Marketplace Gate

Recommended command for marketplace review:

```bash
nyuwayskillscanner scan ./skills \
  --recursive \
  --static-only \
  --offline \
  --policy-pack marketplace \
  --fail-on high \
  --output json
```

## Reviewer Workflow

1. Run the scan with `--policy-pack marketplace`.
2. Block all `BLOCK` skills until findings are fixed.
3. Route `REVIEW` skills to human review.
4. Accept `ALLOW` skills for listing, subject to normal quality checks.
5. Use baselines only for documented risk acceptances.

## Why This Matters

Agent skills are installable instruction bundles. Marketplace users need a
clear answer, not only a list of warnings. The decision field converts scanner
evidence into an operational outcome that CI, install scripts, and marketplace
backends can enforce.
