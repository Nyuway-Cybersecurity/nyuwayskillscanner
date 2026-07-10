from nyuwayskillscanner.cli.main import _merge_llm_decisions


def test_llm_confirm_marks_existing_finding():
    findings = [{"fingerprint": "abc", "severity": "high", "weight": 25}]
    merged = _merge_llm_decisions(
        findings,
        [
            {
                "llm_action": "confirm",
                "confirmed_fingerprint": "abc",
                "confidence": 0.91,
                "rationale": "Evidence confirms exfiltration.",
            }
        ],
    )
    assert merged[0]["llm_confirmed"] is True
    assert merged[0]["confidence"] == 0.91


def test_llm_downgrade_lowers_existing_finding():
    findings = [{"fingerprint": "abc", "severity": "high", "weight": 25}]
    merged = _merge_llm_decisions(
        findings,
        [
            {
                "llm_action": "downgrade",
                "confirmed_fingerprint": "abc",
                "confidence": 0.88,
                "rationale": "Benign documented behavior.",
            }
        ],
    )
    assert merged[0]["llm_downgraded"] is True
    assert merged[0]["severity"] == "low"
    assert merged[0]["weight"] == 5


def test_llm_new_appends_semantic_finding():
    findings = []
    decision = {"llm_action": "new", "category": "scope_creep", "severity": "medium"}
    assert _merge_llm_decisions(findings, [decision]) == [decision]
