"""Offline tests for the ScamShield rule engine (all data is fake)."""
import pytest

from scamshield.rules import RULES, rule_flags, rule_score, rule_verdict


def ids(text: str) -> set[str]:
    """Return the set of rule ids triggered by text."""
    return {f["id"] for f in rule_flags(text)}


POSITIVES = {
    "LINK": "Check your status at https://example.com/status",
    "SHORT_LINK": "Claim now: bit.ly/fake123",
    "OTP_REQUEST": "Please share your OTP now to continue",
    "URGENCY": "Act immediately, offer expires today",
    "KYC_ID": "Your KYC will expire, please update your PAN",
    "UPI_COLLECT": "Approve the collect request from fakeuser@ybl",
    "PRIZE_BAIT": "Congratulations, you have won a lucky draw",
    "REMOTE_ACCESS": "Download AnyDesk so we can fix your account",
    "DIGITAL_ARREST": "This is the CBI officer, a case is filed against you",
    "ELECTRICITY_BILL": "Your electricity connection will be disconnected tonight, call 9000000000",
    "INVESTMENT_BAIT": "Join our VIP trading group for guaranteed returns",
}


@pytest.mark.parametrize("rule_id,text", POSITIVES.items())
def test_each_rule_fires(rule_id: str, text: str) -> None:
    """Each rule matches its fake positive example."""
    assert rule_id in ids(text)


def test_every_rule_has_a_positive_example() -> None:
    """No rule is left without a positive test."""
    assert {r["id"] for r in RULES} == set(POSITIVES)


def test_hinglish_urgency() -> None:
    """Hinglish urgency words are detected."""
    assert "URGENCY" in ids("Turant verify karo warna account band ho jayega")


GENUINE = [
    "Rs 500.00 debited from A/c XX0000 on 01-Jan-25. Avl bal Rs 1000.00. "
    "If not you, call your bank branch.",
    "123456 is your OTP for login. Do not share this OTP with anyone.",
    "Your parcel is out for delivery today between 2 PM and 6 PM. Thanks for shopping.",
    "Hey, are we still meeting for dinner at 8? Let me know what you want to eat.",
]


@pytest.mark.parametrize("text", GENUINE)
def test_genuine_messages_score_low(text: str) -> None:
    """Genuine messages score below 30."""
    assert rule_score(rule_flags(text)) < 30


def test_otp_negation() -> None:
    """Negated OTP sentences do not trigger; direct requests do."""
    assert "OTP_REQUEST" not in ids("Never share your OTP")
    assert "OTP_REQUEST" not in ids("We ask you not to share your OTP")
    assert "OTP_REQUEST" not in ids("Don't share your PIN with anyone")
    assert "OTP_REQUEST" in ids("Please share your OTP now")


def test_empty_text() -> None:
    """Empty or whitespace text yields no flags."""
    assert rule_flags("") == []
    assert rule_flags("   \n ") == []


def test_flags_in_rules_order() -> None:
    """Flags come back in RULES order."""
    order = [r["id"] for r in RULES]
    got = [f["id"] for f in rule_flags(" ".join(POSITIVES.values()))]
    assert got == sorted(got, key=order.index)


def test_score_caps_at_100() -> None:
    """rule_score never exceeds 100."""
    flags = [{"id": "X", "label": "x", "weight": 60}] * 3
    assert rule_score(flags) == 100


@pytest.mark.parametrize(
    "score,verdict",
    [(0, "LIKELY SAFE"), (29, "LIKELY SAFE"), (30, "SUSPICIOUS"),
     (59, "SUSPICIOUS"), (60, "SCAM"), (100, "SCAM")],
)
def test_verdict_boundaries(score: int, verdict: str) -> None:
    """Verdict thresholds sit at 30 and 60."""
    assert rule_verdict(score) == verdict
