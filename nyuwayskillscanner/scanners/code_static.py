"""Skill-specific static checks for bundled scripts."""

from __future__ import annotations

import ast
import re
from pathlib import Path

MAX_FILE_BYTES = 2 * 1024 * 1024

SCRIPT_PATTERNS: list[dict] = [
    {
        "category": "covert_exfiltration",
        "severity": "high",
        "weight": 25,
        "description": "Script sends data to suspicious external endpoint",
        "pattern": re.compile(
            r"(webhook\.site|requestbin\.com|pipedream\.net|discord\.com/api/webhooks|slack\.com/api|pastebin|ngrok|/collect|log\.)",
            re.IGNORECASE,
        ),
    },
    {
        "category": "covert_exfiltration",
        "severity": "high",
        "weight": 25,
        "description": "Script posts local data to an external service",
        "pattern": re.compile(
            r"\b(requests\.post|httpx\.post|urllib\.request\.urlopen|fetch\s*\(|axios\.post|curl\s+(-X\s+)?POST|Invoke-WebRequest|Net\.WebClient|DownloadString)\b",
            re.IGNORECASE,
        ),
    },
    {
        "category": "dangerous_code",
        "severity": "high",
        "weight": 25,
        "description": "Script uses dynamic code execution or shell execution",
        "pattern": re.compile(
            r"\b(eval|exec|compile|os\.system|os\.popen|subprocess\.(run|Popen|call)|child_process\.(exec|spawn|execSync|spawnSync)|\w+\.(execSync|spawnSync)|new Function|powershell\s+-(enc|encodedcommand)|Invoke-Expression|\biex\b|bash\s+-c|sh\s+-c)\b",
            re.IGNORECASE,
        ),
    },
    {
        "category": "privilege_escalation",
        "severity": "high",
        "weight": 25,
        "description": "Script attempts privileged host changes",
        "pattern": re.compile(
            r"\b(sudo|chmod\s+777|chown\s+root|setcap|Set-ExecutionPolicy|runas|administrator|--allow-root|Start-Process\s+.*-Verb\s+RunAs)\b",
            re.IGNORECASE,
        ),
    },
    {
        "category": "persistence",
        "severity": "critical",
        "weight": 35,
        "description": "Script modifies startup, shell profile, or persistence paths",
        "pattern": re.compile(
            r"(\.bashrc|\.zshrc|profile\.ps1|authorized_keys|crontab|launchctl|systemd|Startup|RunOnce|schtasks|New-Service|Set-ItemProperty\s+.*\\Run)",
            re.IGNORECASE,
        ),
    },
    {
        "category": "excessive_agency",
        "severity": "medium",
        "weight": 15,
        "description": "Script reads broad local state such as environment, SSH, or home directories",
        "pattern": re.compile(
            r"(os\.environ|process\.env|Get-ChildItem\s+Env:|\.env|\.ssh|\.aws|\.config|id_rsa|expanduser\(['\"]~|USERPROFILE|HOME)",
            re.IGNORECASE,
        ),
    },
    {
        "category": "data_destruction",
        "severity": "critical",
        "weight": 35,
        "description": "Script deletes or overwrites broad user data",
        "pattern": re.compile(
            r"(rm\s+-rf|shutil\.rmtree|Path\([^)]*\)\.rmdir|fs\.rmSync|fs\.remove|Remove-Item\s+.*-Recurse|del\s+/s|format\s+[A-Z]:)",
            re.IGNORECASE,
        ),
    },
    {
        "category": "unsafe_deserialization",
        "severity": "high",
        "weight": 25,
        "description": "Script deserializes untrusted data using unsafe primitives",
        "pattern": re.compile(
            r"(pickle\.loads?|yaml\.load\s*\(|marshal\.loads|node-serialize|serialize-javascript|eval\s*\(\s*JSON)",
            re.IGNORECASE,
        ),
    },
    {
        "category": "sandbox_escape",
        "severity": "critical",
        "weight": 35,
        "description": "Script references host mounts or sandbox escape vectors",
        "pattern": re.compile(
            r"(/var/run/docker\.sock|--privileged|/proc/1/root|/host\b|docker\s+run.*-v\s+/:|nsenter\b|kubectl\s+exec|hostPath)",
            re.IGNORECASE,
        ),
    },
    {
        "category": "resource_abuse",
        "severity": "medium",
        "weight": 15,
        "description": "Script can consume unbounded CPU, memory, processes, or miner resources",
        "pattern": re.compile(
            r"(fork bomb|:\(\)\s*\{|\bwhile\s+true\b|for\s*\(\s*;\s*;\s*\)|xmrig|cryptominer|minerd)",
            re.IGNORECASE,
        ),
    },
    {
        "category": "tool_misuse",
        "severity": "high",
        "weight": 25,
        "description": "Script uses dangerous flags or disables validation/sandboxing",
        "pattern": re.compile(
            r"(--force|--no-verify|--unsafe|--disable-sandbox|shell\s*=\s*(True|true)|verify\s*=\s*False|check_hostname\s*=\s*False|rejectUnauthorized\s*:\s*false)",
            re.IGNORECASE,
        ),
    },
    {
        "category": "dangerous_code",
        "severity": "high",
        "weight": 25,
        "description": "Script decodes obfuscated commands before execution",
        "pattern": re.compile(
            r"(FromBase64String|base64\s+-d|atob\s*\(|Buffer\.from\s*\([^)]*base64|zlib\.decompress|gzip\s+-d)",
            re.IGNORECASE,
        ),
    },
    {
        "category": "supply_chain_inline_install",
        "severity": "medium",
        "weight": 15,
        "description": "Script performs inline dependency installation",
        "pattern": re.compile(
            r"\b(pip|pip3|python\s+-m\s+pip|npm|pnpm|yarn|uv)\s+install\b",
            re.IGNORECASE,
        ),
    },
]


def scan_script_risks(paths: list[Path]) -> list[dict]:
    findings: list[dict] = []
    for path in paths:
        findings.extend(_scan_text_patterns(path))
        if path.suffix.lower() == ".py":
            findings.extend(_scan_python_ast(path))
    return findings


def _scan_text_patterns(path: Path) -> list[dict]:
    try:
        if path.stat().st_size > MAX_FILE_BYTES:
            return []
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return []

    findings: list[dict] = []
    for line_num, line in enumerate(text.splitlines(), start=1):
        for rule in SCRIPT_PATTERNS:
            if rule["pattern"].search(line):
                findings.append(
                    {
                        "type": "script_risk",
                        "category": rule["category"],
                        "severity": rule["severity"],
                        "weight": rule["weight"],
                        "file": str(path),
                        "line": line_num,
                        "evidence": line.strip()[:200],
                        "description": rule["description"],
                        "source": "script_static",
                    }
                )
    return findings


def _scan_python_ast(path: Path) -> list[dict]:
    try:
        tree = ast.parse(path.read_text(encoding="utf-8", errors="ignore"))
    except (OSError, SyntaxError):
        return []

    findings: list[dict] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            name = _call_name(node.func)
            if name in {
                "eval",
                "exec",
                "compile",
                "os.system",
                "os.popen",
                "subprocess.run",
                "subprocess.Popen",
                "subprocess.call",
            }:
                findings.append(
                    {
                        "type": "script_risk",
                        "category": "dangerous_code",
                        "severity": "high",
                        "weight": 25,
                        "file": str(path),
                        "line": getattr(node, "lineno", 1),
                        "evidence": name,
                        "description": "Python AST contains dangerous execution primitive",
                        "source": "python_ast",
                    }
                )
            if name in {"pickle.load", "pickle.loads", "yaml.load", "marshal.loads"}:
                findings.append(
                    {
                        "type": "script_risk",
                        "category": "unsafe_deserialization",
                        "severity": "high",
                        "weight": 25,
                        "file": str(path),
                        "line": getattr(node, "lineno", 1),
                        "evidence": name,
                        "description": "Python AST contains unsafe deserialization primitive",
                        "source": "python_ast",
                    }
                )
            if name in {"requests.post", "httpx.post", "urllib.request.urlopen"}:
                findings.append(
                    {
                        "type": "script_risk",
                        "category": "covert_exfiltration",
                        "severity": "high",
                        "weight": 25,
                        "file": str(path),
                        "line": getattr(node, "lineno", 1),
                        "evidence": name,
                        "description": "Python AST contains outbound network sink",
                        "source": "python_ast",
                    }
                )
            if name in {"shutil.rmtree", "Path.rmdir", "os.remove", "os.unlink"}:
                findings.append(
                    {
                        "type": "script_risk",
                        "category": "data_destruction",
                        "severity": "critical",
                        "weight": 35,
                        "file": str(path),
                        "line": getattr(node, "lineno", 1),
                        "evidence": name,
                        "description": "Python AST contains destructive filesystem primitive",
                        "source": "python_ast",
                    }
                )
    return findings


def _call_name(func: ast.expr) -> str:
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        parent = _call_name(func.value)
        return f"{parent}.{func.attr}" if parent else func.attr
    return ""
