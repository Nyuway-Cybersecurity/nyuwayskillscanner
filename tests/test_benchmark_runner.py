from benchmarks.run_peer_benchmark import _render_markdown, _summarize


def test_benchmark_runner_summarizes_decisions_and_categories():
    rows = [
        {
            "fixture": "clean/good",
            "expected": {"expected_verdict": "PASS", "expected_categories": []},
            "nyuwayskillscanner": {
                "decision": "ALLOW",
                "categories": [],
                "runtime_ms": 10,
                "status": "ok",
            },
        },
        {
            "fixture": "benign_suspicious/review",
            "expected": {"expected_verdict": "MEDIUM", "expected_categories": ["excessive_agency"]},
            "nyuwayskillscanner": {
                "decision": "REVIEW",
                "categories": ["excessive_agency"],
                "runtime_ms": 20,
                "status": "ok",
            },
        },
        {
            "fixture": "malicious/bad",
            "expected": {"expected_verdict": "CRITICAL", "expected_categories": ["covert_exfiltration"]},
            "nyuwayskillscanner": {
                "decision": "BLOCK",
                "categories": ["covert_exfiltration"],
                "runtime_ms": 30,
                "status": "ok",
            },
        },
    ]

    summary = _summarize(rows)["nyuwayskillscanner"]

    assert summary["decision_accuracy"] == 1.0
    assert summary["malicious_block_rate"] == 1.0
    assert summary["clean_allow_rate"] == 1.0
    assert summary["benign_review_rate"] == 1.0
    assert summary["category_recall"] == 1.0
    assert summary["avg_runtime_ms"] == 20


def test_benchmark_runner_markdown_includes_miss_analysis():
    scorecard = {
        "metadata": {
            "generated_at": "2026-01-01T00:00:00+00:00",
            "corpus_hash": "abc123",
            "fixture_count": 1,
        },
        "summary": {
            "nyuwayskillscanner": {
                "decision_accuracy": 0.0,
                "malicious_block_rate": 0.0,
                "clean_allow_rate": 0.0,
                "benign_review_rate": 0.0,
                "category_recall": 0.0,
                "avg_runtime_ms": 5,
                "false_positives": [],
                "false_negatives": ["malicious/bad"],
                "errors": [],
                "missed_categories": {"malicious/bad": ["covert_exfiltration"]},
            }
        },
        "results": [
            {
                "fixture": "malicious/bad",
                "expected": {"expected_verdict": "CRITICAL"},
                "nyuwayskillscanner": {"decision": "REVIEW", "categories": []},
                "skillspector": None,
            }
        ],
    }

    markdown = _render_markdown(scorecard)

    assert "Peer Benchmark Scorecard" in markdown
    assert "malicious/bad" in markdown
    assert "covert_exfiltration" in markdown
