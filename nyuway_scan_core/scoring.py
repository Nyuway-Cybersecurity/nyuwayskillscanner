"""0-100 severity-weighted scoring shared by Nyuway scanners."""

SEVERITY_FLOOR = {
    "critical": 80,
    "high": 60,
    "medium": 40,
    "low": 20,
}

VERDICTS = [
    (80, "CRITICAL"),
    (60, "HIGH"),
    (40, "MEDIUM"),
    (20, "LOW"),
    (0, "PASS"),
]


def _verdict_for(score: int) -> str:
    for threshold, label in VERDICTS:
        if score >= threshold:
            return label
    return "PASS"


def calculate_score(findings: list[dict]) -> tuple[int, str]:
    """Return (score 0-100, verdict string) from unsuppressed findings."""
    active = [f for f in findings if not f.get("suppressed")]
    if not active:
        return 0, "PASS"

    weight_sum = sum(int(f.get("weight", 0)) for f in active)
    severity_floor = max(
        (SEVERITY_FLOOR.get(str(f.get("severity", "")).lower(), 0) for f in active),
        default=0,
    )
    score = max(0, min(100, max(weight_sum, severity_floor)))
    return score, _verdict_for(score)
