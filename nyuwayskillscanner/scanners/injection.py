"""Static prompt-injection and agent-skill risk detection.

This module intentionally stays deterministic. The local LLM pass can refine or
confirm findings later, but CI users need a fast offline layer with stable rule
ids and evidence.
"""

from __future__ import annotations

import base64
import re
import urllib.parse
from pathlib import Path

_ENCODED_BLOCK = re.compile(r"\b[A-Za-z0-9+/]{40,}={0,2}\b")
_HEX_BLOCK = re.compile(r"\b(?:0x)?[0-9a-fA-F]{48,}\b")
_ZERO_WIDTH = re.compile(r"[\u200b-\u200f\ufeff]")
_EXTERNAL_URL = re.compile(r"https?://[^\s\)\]\"']+", re.IGNORECASE)
_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_URL_ENCODED = re.compile(r"(?:%[0-9a-fA-F]{2}){4,}")
_UNICODE_ESCAPE = re.compile(r"(?:\\u[0-9a-fA-F]{4}){4,}")
_SPLIT_WORD = re.compile(r"\b(?:i[\s'\"`+._-]*g[\s'\"`+._-]*n[\s'\"`+._-]*o[\s'\"`+._-]*r[\s'\"`+._-]*e|s[\s'\"`+._-]*e[\s'\"`+._-]*c[\s'\"`+._-]*r[\s'\"`+._-]*e[\s'\"`+._-]*t)\b", re.IGNORECASE)
_CONFUSABLE_TRANSLATION = str.maketrans(
    {
        "а": "a",
        "е": "e",
        "і": "i",
        "о": "o",
        "р": "p",
        "с": "c",
        "х": "x",
        "у": "y",
        "Α": "A",
        "Β": "B",
        "Ε": "E",
        "Η": "H",
        "Ι": "I",
        "Κ": "K",
        "Μ": "M",
        "Ν": "N",
        "Ο": "O",
        "Ρ": "P",
        "Τ": "T",
        "Χ": "X",
    }
)
_SUSPICIOUS_DECODED_WORDS = (
    "ignore",
    "disregard",
    "forward",
    "send",
    "secret",
    "password",
    "token",
    "webhook",
)


STATIC_PATTERNS: list[dict] = [
    {
        "category": "instruction_override",
        "severity": "high",
        "description": "Skill text attempts to override higher-priority instructions",
        "patterns": [
            r"\b(ignore|disregard|forget)\b.{0,60}\b(prior|previous|system|developer|safety|other)\b.{0,30}\b(instructions?|rules?|guidelines?|prompts?)\b",
            r"\b(system|developer)\s+instructions?\s+are\s+irrelevant\b",
            r"\bdo\s+not\s+follow\b.{0,40}\b(safety|policy|guardrails?)\b",
        ],
    },
    {
        "category": "role_impersonation",
        "severity": "high",
        "description": "Skill text impersonates a trusted system or developer message",
        "patterns": [
            r"\b(system|developer)\s*:\s*(you must|ignore|override|secret)",
            r"\bthis is a system message\b",
            r"\bsystem message\b",
            r"\bas your developer\b.{0,40}\b(ignore|must|always)\b",
        ],
    },
    {
        "category": "hidden_instruction",
        "severity": "medium",
        "description": "Skill text contains hidden or conditional instructions",
        "patterns": [
            r"\bsecretly\b.{0,60}\b(send|copy|store|log|forward)\b",
            r"\bwhen the user is not looking\b",
            r"\bonly after completing the task\b.{0,60}\b(send|copy|store|log|forward)\b",
        ],
    },
    {
        "category": "self_elevation",
        "severity": "medium",
        "description": "Skill text tries to force selection of this skill",
        "patterns": [
            r"\b(always|must|required to)\b.{0,40}\b(use|select|invoke|prefer)\b.{0,30}\b(this skill|this tool)\b",
            r"\bhighest priority skill\b",
            r"\buse this skill for every request\b",
        ],
    },
    {
        "category": "secrecy_concealment",
        "severity": "high",
        "description": "Skill text instructs the agent to hide actions from the user",
        "patterns": [
            r"\b(do not|don't|never)\b.{0,40}\b(mention|reveal|disclose|show|tell|inform)\b",
            r"\bhide\b.{0,40}\b(user|owner|operator|audit|log)\b",
            r"\bwithout (the )?user('s)? knowledge\b",
        ],
    },
    {
        "category": "credential_collection",
        "severity": "critical",
        "description": "Skill text asks for credential collection or credential forwarding",
        "patterns": [
            r"\b(collect|ask for|request|extract|read)\b.{0,50}\b(api keys?|tokens?|passwords?|secrets?|credentials?)\b",
            r"\b(print|echo|send|forward|log)\b.{0,50}\b(api keys?|tokens?|passwords?|secrets?|credentials?)\b",
        ],
    },
    {
        "category": "privilege_escalation",
        "severity": "high",
        "description": "Skill requests elevated permissions or privileged host actions",
        "patterns": [
            r"\b(sudo|administrator|admin privileges?|root access|elevated permissions?)\b",
            r"\b(chmod\s+777|chown\s+root|setuid)\b",
            r"\bdisable\b.{0,40}\b(antivirus|firewall|defender|security)\b",
        ],
    },
    {
        "category": "persistence",
        "severity": "critical",
        "description": "Skill attempts persistence through startup or shell profile hooks",
        "patterns": [
            r"\b(crontab|launchctl|systemd|startup folder|run at login)\b",
            r"\b(\.bashrc|\.zshrc|profile\.ps1|authorized_keys)\b",
            r"\b(add|append|write)\b.{0,50}\b(startup|login|shell profile)\b",
        ],
    },
    {
        "category": "excessive_agency",
        "severity": "medium",
        "description": "Skill asks for broad access beyond a narrow task scope",
        "patterns": [
            r"\b(read|scan|upload|index)\b.{0,40}\b(entire|all|whole)\b.{0,30}\b(home directory|filesystem|drive|workspace)\b",
            r"\b(read|dump|export)\b.{0,40}\b(environment variables?|\.env|ssh keys?|browser cookies?)\b",
            r"\baccess\b.{0,40}\b(unrelated files?|all projects?|private repositories?)\b",
        ],
    },
    {
        "category": "dangerous_code",
        "severity": "high",
        "description": "Skill prose or scripts reference dangerous code execution primitives",
        "patterns": [
            r"\b(eval|exec|subprocess|os\.system|child_process|powershell\s+-enc)\b",
            r"\b(curl|wget|Invoke-WebRequest)\b.{0,80}\b(sh|bash|powershell|iex)\b",
            r"\bbase64\b.{0,40}\b(decode|exec|eval|run)\b",
            r"\b(gzip|zlib|atob|frombase64string)\b.{0,60}\b(decode|exec|eval|run|instructions?)\b",
        ],
    },
    {
        "category": "output_injection",
        "severity": "high",
        "description": "Skill instructs generated output to contain agent-control instructions",
        "patterns": [
            r"\b(include|append|prepend|insert)\b.{0,60}\b(ignore previous instructions|system prompt|developer message)\b",
            r"\b(output|return|write)\b.{0,50}\b(<!--|<script|system:|developer:)\b",
            r"\bembed\b.{0,50}\b(prompt injection|hidden instruction|agent instruction)\b",
        ],
    },
    {
        "category": "memory_poisoning",
        "severity": "high",
        "description": "Skill tries to write malicious instructions into persistent agent memory",
        "patterns": [
            r"\b(save|store|remember|persist)\b.{0,60}\b(always trust|ignore safety|use this skill|system instruction)\b",
            r"\bupdate\b.{0,40}\b(memory|long-term memory|agent memory)\b.{0,60}\b(ignore|always|secret)\b",
            r"\bwrite\b.{0,40}\b(memory file|agent profile|instructions file)\b",
        ],
    },
    {
        "category": "trigger_abuse",
        "severity": "medium",
        "description": "Skill defines broad or stealthy activation triggers",
        "patterns": [
            r"\b(trigger|activate|run)\b.{0,50}\b(any request|every message|all prompts|silently)\b",
            r"\bwhen\b.{0,40}\b(user mentions|message contains)\b.{0,40}\b(anything|all|secret)\b",
            r"\bauto[- ]?run\b.{0,40}\b(without asking|silently|every time)\b",
        ],
    },
    {
        "category": "data_destruction",
        "severity": "critical",
        "description": "Skill can delete, overwrite, or destructively modify user data",
        "patterns": [
            r"\b(delete|remove|wipe|erase|destroy)\b.{0,50}\b(all files|workspace|home directory|drive|repository)\b",
            r"\brm\s+-rf\b",
            r"\bformat\b.{0,30}\b(drive|disk|volume)\b",
        ],
    },
    {
        "category": "untrusted_content_fetch",
        "severity": "medium",
        "description": "Skill fetches remote content and treats it as instructions",
        "patterns": [
            r"\b(fetch|download|retrieve|load)\b.{0,60}\b(url|web page|remote content|gist|pastebin)\b.{0,60}\b(instructions?|prompt|commands?)\b",
            r"\bexecute\b.{0,40}\b(remote script|downloaded script|content from url)\b",
            r"\btrust\b.{0,40}\b(remote instructions?|web content|external page)\b",
        ],
    },
    {
        "category": "sandbox_escape",
        "severity": "critical",
        "description": "Skill attempts to bypass sandbox or container boundaries",
        "patterns": [
            r"\b(mount|bind mount)\b.{0,40}\b(host|/var/run/docker\.sock|root filesystem)\b",
            r"\b(docker\.sock|/proc/1/root|/host|--privileged)\b",
            r"\bescape\b.{0,40}\b(sandbox|container|jail)\b",
        ],
    },
    {
        "category": "resource_abuse",
        "severity": "medium",
        "description": "Skill describes high CPU, memory, process, or network abuse",
        "patterns": [
            r"\b(fork bomb|while true|infinite loop)\b",
            r"\b(use|max out|consume)\b.{0,40}\b(all cpu|all memory|gpu|bandwidth)\b",
            r"\b(mine|mining|cryptominer|xmrig)\b",
        ],
    },
    {
        "category": "unsafe_deserialization",
        "severity": "high",
        "description": "Skill references unsafe deserialization of untrusted data",
        "patterns": [
            r"\b(pickle\.loads|pickle\.load|yaml\.load|marshal\.loads)\b",
            r"\bdeserialize\b.{0,50}\b(untrusted|user-provided|remote)\b",
            r"\bload\b.{0,40}\b(pickle|serialized object)\b.{0,40}\b(from url|from user|remote)\b",
        ],
    },
    {
        "category": "tool_misuse",
        "severity": "high",
        "description": "Skill uses tool parameters that bypass safety constraints",
        "patterns": [
            r"(--force|--no-verify|--unsafe|--allow-root|--disable-sandbox|--privileged)\b",
            r"\bshell\s*=\s*true\b",
            r"\b(skip|bypass|disable)\b.{0,40}\b(validation|approval|confirmation|safety check)\b",
        ],
    },
    {
        "category": "supply_chain_inline_install",
        "severity": "medium",
        "description": "Skill installs dependencies inline rather than through auditable manifests",
        "patterns": [
            r"\b(pip|pip3|uv|npm|pnpm|yarn|curl)\s+install\b",
            r"\bnpx\b\s+[^`\s]+",
            r"\bpython\s+-m\s+pip\s+install\b",
        ],
    },
]

_CATEGORY_WEIGHT = {
    "instruction_override": 30,
    "role_impersonation": 30,
    "hidden_instruction": 20,
    "covert_exfiltration": 25,
    "credential_collection": 35,
    "encoded_instruction": 20,
    "self_elevation": 15,
    "secrecy_concealment": 25,
    "scope_creep": 10,
    "privilege_escalation": 25,
    "persistence": 35,
    "excessive_agency": 15,
    "dangerous_code": 25,
    "output_injection": 25,
    "memory_poisoning": 25,
    "trigger_abuse": 15,
    "data_destruction": 35,
    "untrusted_content_fetch": 15,
    "sandbox_escape": 35,
    "resource_abuse": 15,
    "unsafe_deserialization": 25,
    "tool_misuse": 25,
    "supply_chain_inline_install": 15,
}


def _finding(
    *,
    category: str,
    severity: str,
    file: str,
    line: int,
    evidence: str,
    description: str,
) -> dict:
    return {
        "type": "instruction_manipulation",
        "category": category,
        "severity": severity,
        "weight": _CATEGORY_WEIGHT.get(category, 10),
        "file": file,
        "line": line,
        "evidence": evidence[:200],
        "description": description,
        "source": "injection_detector",
    }


def _scan_text_block(
    text: str,
    file_label: str,
    line_offset: int = 1,
) -> list[dict]:
    findings: list[dict] = []
    lines = text.splitlines()

    for line_num, raw_line in enumerate(lines, start=line_offset):
        line = raw_line.lstrip("\ufeff")
        for rule in STATIC_PATTERNS:
            for raw_pattern in rule["patterns"]:
                if re.search(raw_pattern, line, re.IGNORECASE):
                    findings.append(
                        _finding(
                            category=rule["category"],
                            severity=rule["severity"],
                            file=file_label,
                            line=line_num,
                            evidence=line.strip(),
                            description=rule["description"],
                        )
                    )
                    break

        for match in _EXTERNAL_URL.finditer(line):
            url = match.group(0)
            if any(
                token in url.lower()
                for token in (
                    "webhook",
                    "requestbin",
                    "pipedream",
                    "log.",
                    "collect",
                    "discord.com/api/webhooks",
                    "slack.com/api",
                    "pastebin",
                    "ngrok",
                )
            ):
                findings.append(
                    _finding(
                        category="covert_exfiltration",
                        severity="high",
                        file=file_label,
                        line=line_num,
                        evidence=line.strip(),
                        description="Suspicious external endpoint referenced in skill prose",
                    )
                )

        for match in _EMAIL.finditer(line):
            local_context = line.lower()
            if any(word in local_context for word in ("send", "forward", "email", "exfil", "secret")):
                findings.append(
                    _finding(
                        category="covert_exfiltration",
                        severity="high",
                        file=file_label,
                        line=line_num,
                        evidence=line.strip(),
                        description="Skill prose directs data to an email address",
                    )
                )

        if _ZERO_WIDTH.search(line):
            findings.append(
                _finding(
                    category="encoded_instruction",
                    severity="medium",
                    file=file_label,
                    line=line_num,
                    evidence=line.strip()[:120],
                    description="Zero-width or invisible Unicode characters in instructions",
                )
            )

        if _HEX_BLOCK.search(line):
            findings.append(
                _finding(
                    category="encoded_instruction",
                    severity="medium",
                    file=file_label,
                    line=line_num,
                    evidence=line.strip()[:120],
                    description="Long hex-like encoded block appears in instructions",
                )
            )

        if _SPLIT_WORD.search(line):
            findings.append(
                _finding(
                    category="encoded_instruction",
                    severity="medium",
                    file=file_label,
                    line=line_num,
                    evidence=line.strip()[:120],
                    description="Suspicious instruction word appears split across characters",
                )
            )

        confusable_text = line.translate(_CONFUSABLE_TRANSLATION)
        if confusable_text != line and _contains_suspicious_decoded_text(confusable_text):
            findings.append(
                _finding(
                    category="encoded_instruction",
                    severity="medium",
                    file=file_label,
                    line=line_num,
                    evidence=line.strip()[:120],
                    description="Homoglyph text normalizes to suspicious instruction content",
                )
            )

        for encoded in _URL_ENCODED.finditer(line):
            decoded = urllib.parse.unquote(encoded.group(0))
            if _contains_suspicious_decoded_text(decoded):
                findings.append(
                    _finding(
                        category="encoded_instruction",
                        severity="high",
                        file=file_label,
                        line=line_num,
                        evidence=encoded.group(0)[:120],
                        description="URL-encoded text decodes to suspicious instruction content",
                    )
                )

        for encoded in _UNICODE_ESCAPE.finditer(line):
            try:
                decoded = encoded.group(0).encode("utf-8").decode("unicode_escape")
            except UnicodeDecodeError:
                continue
            if _contains_suspicious_decoded_text(decoded):
                findings.append(
                    _finding(
                        category="encoded_instruction",
                        severity="high",
                        file=file_label,
                        line=line_num,
                        evidence=encoded.group(0)[:120],
                        description="Escaped Unicode text decodes to suspicious instruction content",
                    )
                )

        reversed_line = line[::-1]
        if _contains_suspicious_decoded_text(reversed_line):
            findings.append(
                _finding(
                    category="encoded_instruction",
                    severity="medium",
                    file=file_label,
                    line=line_num,
                    evidence=line.strip()[:120],
                    description="Reversed text contains suspicious instruction content",
                )
            )

        for match in _ENCODED_BLOCK.finditer(line):
            blob = match.group(0)
            try:
                decoded = base64.b64decode(blob, validate=True).decode(
                    "utf-8", errors="ignore"
                )
            except (ValueError, UnicodeDecodeError):
                continue
            if len(decoded) >= 12 and _contains_suspicious_decoded_text(decoded):
                findings.append(
                    _finding(
                        category="encoded_instruction",
                        severity="high",
                        file=file_label,
                        line=line_num,
                        evidence=blob[:80],
                        description="Base64-encoded block decodes to suspicious instruction text",
                    )
                )

    return findings


def _contains_suspicious_decoded_text(text: str) -> bool:
    lowered = text.lower()
    return any(word in lowered for word in _SUSPICIOUS_DECODED_WORDS)


def scan_instruction_manipulation(
    *,
    frontmatter: dict,
    body: str,
    skill_md_path: Path,
) -> list[dict]:
    """Run the static instruction-manipulation detector on skill metadata and body."""
    findings: list[dict] = []
    skill_file = str(skill_md_path)

    for field in ("name", "description", "license", "version"):
        value = frontmatter.get(field)
        if isinstance(value, str) and value.strip():
            findings.extend(
                _scan_text_block(value, f"{skill_file}#frontmatter.{field}", line_offset=1)
            )

    if body.strip():
        findings.extend(_scan_text_block(body, skill_file, line_offset=1))

    return findings
