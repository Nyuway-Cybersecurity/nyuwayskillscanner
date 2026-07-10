"""Rich terminal renderer for scan results."""

from nyuway_scan_core.findings import install_verdict
from rich.console import Console

SEVERITY_SYMBOL = {
    "critical": "[bold red]X CRITICAL[/]",
    "high": "[red]X HIGH[/]",
    "medium": "[yellow]! MEDIUM[/]",
    "low": "[blue]i LOW[/]",
}


def render_summary(
    target: str,
    score: int,
    verdict: str,
    findings: list[dict],
    metadata: dict | None = None,
) -> None:
    console = Console()
    metadata = metadata or {}
    active = [f for f in findings if not f.get("suppressed")]
    suppressed = [f for f in findings if f.get("suppressed")]
    console.print()
    console.print("[bold]nyuwayskillscanner[/] - Baseline Scan")
    console.print("-" * 50)
    console.print(f"Target:     {target}")
    console.print(f"Risk Score: {score} / 100  [{verdict}]")
    decision = install_verdict(score, verdict)
    console.print(f"Decision:   {decision['decision']}")
    if metadata:
        console.print(f"Mode:       {metadata.get('mode', 'baseline')}")
        console.print(f"Policy:     {metadata.get('policy_pack', 'default')}")
    if suppressed:
        console.print(f"Suppressed: {len(suppressed)} finding(s)")
    console.print()

    if not active:
        console.print("[green]+ PASS[/]   No findings.")
    else:
        console.print("Findings:")
        for f in active:
            sev = SEVERITY_SYMBOL.get(
                f.get("severity", "low"), f.get("severity", "low")
            )
            label = f.get("type", "finding")
            location = f.get("file") or f.get("package") or ""
            description = (
                f.get("description")
                or f.get("category")
                or f.get("label")
                or f.get("rule")
                or ""
            )
            fingerprint = f.get("fingerprint", "")
            console.print(
                f"  {sev}   {label}  {description}  {location}  [dim]{fingerprint}[/]"
            )

    console.print()
    console.print("[dim]Powered by nyuwayskillscanner - nyuway.ai[/]")
