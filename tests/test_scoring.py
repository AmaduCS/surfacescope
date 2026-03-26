from surfacescope.modules.scoring import score_target, severity_from_score


def test_severity_thresholds():
    assert severity_from_score(0) == "info"
    assert severity_from_score(2) == "low"
    assert severity_from_score(5) == "medium"
    assert severity_from_score(9) == "high"


def test_score_target_detects_multiple_risks():
    record = {
        "http": {
            "scheme": "http",
            "likely_login": True,
            "missing_security_headers": ["a", "b", "c"],
        },
        "tls": {"expires_in_days": 10},
        "ports": [{"port": 22}, {"port": 3306}],
    }
    score, findings, severity = score_target(record)
    assert score >= 8
    assert any("Missing multiple web security headers" in f for f in findings)
    assert severity == "high"
