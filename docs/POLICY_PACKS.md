# Policy Packs

Policy packs tune severity and suppression behavior for different deployment
contexts. They do not change what the scanner can detect; they change how
findings are prioritized and gated.

## Packs

| Pack | Intended Use | Minimum Active Severity | Notes |
|---|---|---:|---|
| `personal` | Local experimentation and personal skill libraries | `medium` | Suppresses low-risk noise while keeping review-worthy findings visible. |
| `audit` | Narrow audit mode | `critical` | Shows only critical findings. Useful for quick triage, not for publishing gates. |
| `default` | General local and CI scanning | `low` | Preserves all active findings with original severity. |
| `enterprise` | Organization-controlled agent environments | `low` | Promotes install-blocking categories such as exfiltration, persistence, memory poisoning, destructive actions, and sandbox escape. |
| `marketplace` | Shared skill marketplace review | `medium` | Promotes marketplace-sensitive issues such as inline installs, trigger abuse, secrecy, and self-elevation. |
| `strict` | High-assurance review | `low` | Most aggressive built-in policy. Use for sensitive environments and release candidates. |

## Recommended Defaults

Use `default` while developing a detector or skill.

Use `enterprise` for organization-controlled skill repositories.

Use `marketplace` when deciding whether a skill can be published, listed, or
installed from a shared catalog.

Use `strict` before a high-trust distribution channel, release candidate, or
security review.

## Custom Policy Files

Custom YAML files can override the built-in settings:

```yaml
minimum_severity: medium
severity_overrides:
  self_elevation: high
  supply_chain_inline_install: high
  untrusted_content_fetch: high
```

Run with:

```bash
nyuwayskillscanner scan ./skill --policy-pack default --policy-file policy.yml
```

The custom file is merged on top of the selected built-in pack.
