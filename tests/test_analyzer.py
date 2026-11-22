"""Offline tests for the analyzer; the Anthropic client is always mocked."""
import json
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from scamshield import analyzer

GOOD = {
    "verdict": "SCAM", "scam_type": "phishing", "risk_score": 90,
    "red_flags": ["a", "b"], "what_to_do": ["1", "2", "3", "4"],
    "explanation": "Looks fake.",
}


def reply(raw: str) -> SimpleNamespace:
    """Build a fake API response carrying raw text."""
    return SimpleNamespace(
        content=[SimpleNamespace(type="text", text=raw)],
        usage=SimpleNamespace(input_tokens=10, output_tokens=5))


def run(raws: list[str], text: str = "hello there", **kw) -> tuple[dict, MagicMock]:
    """Run analyze with a mocked client returning raws in order."""
    client = MagicMock()
    client.messages.create.side_effect = [reply(r) for r in raws]
    with patch.object(analyzer, "get_client", return_value=client):
        return analyzer.analyze(text, **kw), client


@pytest.fixture(autouse=True)
def clear_cache() -> None:
    """Start every test with an empty cache."""
    analyzer._CACHE.clear()


def test_valid_json_parses() -> None:
    """Plain JSON is parsed and trimmed."""
    res, client = run([json.dumps(GOOD)])
    assert res["verdict"] == "SCAM" and res["risk_score"] == 90
    assert res["what_to_do"] == ["1", "2", "3"]
    assert res["usage"] == {"input_tokens": 10, "output_tokens": 5}
    assert client.messages.create.call_count == 1


def test_fenced_json_parses() -> None:
    """JSON inside ```json fences is parsed."""
    res, _ = run(["```json\n" + json.dumps(GOOD) + "\n```"])
    assert res["verdict"] == "SCAM" and "error" not in res


def test_bad_then_good_makes_two_calls() -> None:
    """One bad reply is retried exactly once."""
    res, client = run(["not json", json.dumps(GOOD)])
    assert client.messages.create.call_count == 2
    assert res["verdict"] == "SCAM" and "error" not in res


def test_bad_twice_returns_rules_fallback() -> None:
    """Two bad replies give the rule-based fallback with an error key."""
    res, client = run(["nope", "still nope"], text="Share your OTP at https://example.com now")
    assert client.messages.create.call_count == 2
    assert "error" in res
    assert res["risk_score"] == res["rule_score"] > 0
    assert res["explanation"] == "AI analysis unavailable; showing rule-based result."
    assert len(res["what_to_do"]) == 3


@pytest.mark.parametrize("given,expected", [(150, 100), (-5, 0), ("42", 42)])
def test_score_clamping(given: object, expected: int) -> None:
    """risk_score is coerced to int and clamped to 0-100."""
    assert analyzer.validate_result({**GOOD, "risk_score": given})["risk_score"] == expected


def test_invalid_verdict_rejected() -> None:
    """An unknown verdict fails validation."""
    with pytest.raises(ValueError):
        analyzer.validate_result({**GOOD, "verdict": "MAYBE"})


def test_hybrid_escalation_true() -> None:
    """High rule score upgrades LIKELY SAFE to SUSPICIOUS."""
    assert analyzer.hybrid_verdict("LIKELY SAFE", 60) == "SUSPICIOUS"
    safe = json.dumps({**GOOD, "verdict": "LIKELY SAFE"})
    text = "CBI officer: digital arrest case, install AnyDesk, share your OTP"
    res, _ = run([safe], text=text)
    assert res["verdict"] == "SUSPICIOUS" and res["escalated"] is True


def test_hybrid_escalation_false() -> None:
    """Low rule score or non-safe verdicts are left alone."""
    assert analyzer.hybrid_verdict("LIKELY SAFE", 59) == "LIKELY SAFE"
    assert analyzer.hybrid_verdict("SCAM", 100) == "SCAM"
    safe = json.dumps({**GOOD, "verdict": "LIKELY SAFE"})
    res, _ = run([safe], text="see you at dinner")
    assert res["verdict"] == "LIKELY SAFE" and res["escalated"] is False


def test_cache_makes_one_call() -> None:
    """Identical text-only requests hit the API once."""
    client = MagicMock()
    client.messages.create.return_value = reply(json.dumps(GOOD))
    with patch.object(analyzer, "get_client", return_value=client):
        first = analyzer.analyze("same text")
        second = analyzer.analyze("same text")
    assert client.messages.create.call_count == 1
    assert first == second


def test_oversize_image_skips_api() -> None:
    """An image over 5 MB returns the fallback without any API call."""
    client = MagicMock()
    big = b"0" * (analyzer.MAX_IMAGE_BYTES + 1)
    with patch.object(analyzer, "get_client", return_value=client):
        res = analyzer.analyze("hi", image_bytes=big, media_type="image/png")
    assert "error" in res
    assert client.messages.create.call_count == 0


def test_user_message_is_wrapped_and_image_first() -> None:
    """The API call wraps text in <message> and puts the image block first."""
    _, client = run([json.dumps(GOOD)], image_bytes=b"abc", media_type="image/png")
    kwargs = client.messages.create.call_args.kwargs
    content = kwargs["messages"][0]["content"]
    assert content[0]["type"] == "image"
    assert "<message>" in content[-1]["text"]
    assert kwargs["temperature"] == 0 and kwargs["max_tokens"] == 700
    assert kwargs["system"] == analyzer.SYSTEM_PROMPT


def test_missing_key_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    """A missing API key reaches the caller as ValueError."""
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    with patch.object(analyzer.os, "getenv", side_effect=lambda k, d=None: d):
        with pytest.raises(ValueError, match="ANTHROPIC_API_KEY not set"):
            analyzer.analyze("hello")
