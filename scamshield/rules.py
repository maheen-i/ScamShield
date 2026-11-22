"""Offline regex rule engine for spotting common Indian scam messages."""
import re

SCAM_THRESHOLD = 60
SUSPICIOUS_THRESHOLD = 30

# Verbs that, within 6 words of OTP/CVV/PIN/password, indicate a request.
# The lookbehinds skip negated forms: "do not share", "never share", "not to share".
_OTP = (
    r"\b(?<!not )(?<!not to )(?<!n't )(?<!n’t )(?<!never )"
    r"(?:share|send|tell|give|enter|forward|reply|read)\b"
    r"(?:\W+\w+){0,5}\W+(?:otp|cvv|pin|password)\b"
)

_UPI_HANDLE = r"[\w.\-]+@(?:ybl|okaxis|oksbi|okhdfcbank|okicici|paytm|ibl|axl|upi)\b"


def _rule(rule_id: str, label: str, weight: int, pattern: str) -> dict:
    """Build one rule dict with a case-insensitive compiled pattern."""
    flags = re.IGNORECASE | re.DOTALL
    return {"id": rule_id, "label": label, "weight": weight,
            "pattern": re.compile(pattern, flags)}


RULES: list[dict] = [
    _rule("LINK", "Contains a link", 10, r"https?://|\bwww\."),
    _rule("SHORT_LINK", "Uses a URL shortener", 20,
          r"(?<![\w.])(?:bit\.ly|tinyurl(?:\.com)?|cutt\.ly|rb\.gy|is\.gd|t\.co"
          r"|goo\.gl|ow\.ly|shorturl\.at|t\.ly)(?![\w])"),
    _rule("OTP_REQUEST", "Asks you to share an OTP/PIN/CVV/password", 35, _OTP),
    _rule("URGENCY", "Creates false urgency", 15,
          r"\burgent(?:ly)?\b|\bimmediately\b"
          r"|\bwithin\s+\d+\s*(?:hours?|hrs?|minutes?|mins?)\b"
          r"|\blast chance\b|\bexpires?\s+today\b"
          r"|\baccount\s+(?:will\s+be|is\s+being|has\s+been)\s+"
          r"(?:blocked|suspended|closed)\b"
          r"|\bturant\b|\bjaldi\b|\bband\s+ho\s+jayega\b"),
    _rule("KYC_ID", "KYC/PAN/Aadhaar update pressure", 20,
          r"^(?=.*\b(?:kyc|pan|aadhaar|aadhar)\b)"
          r"(?=.*\b(?:updat\w*|verif\w*|expire[sd]?|link(?:ed)?|suspend\w*)\b)"),
    _rule("UPI_COLLECT", "UPI ID with a payment/collect request", 25,
          rf"^(?=.*\b{_UPI_HANDLE})(?=.*\b(?:request|collect|approve|accept|pay)\w*)"),
    _rule("PRIZE_BAIT", "Prize, cashback or easy-job bait", 25,
          r"\blottery\b|\byou have won\b|\blucky draw\b|\bcashback\b"
          r"|\breward points\b|\bwork from home\b"
          r"|\bearn\s+(?:rs\.?|inr|₹)?\s*\d[\d,]*\s*(?:per|/|a)\s*day\b"
          r"|\bpart[- ]time job\b"),
    _rule("REMOTE_ACCESS", "Asks for remote access to your device", 35,
          r"\banydesk\b|\bteamviewer\b|\bquick\s?support\b"
          r"|\bscreen\s?shar\w*|\binstall this app\b"),
    _rule("DIGITAL_ARREST", "Digital-arrest / fake authority threat", 40,
          r"^(?=.*(?:digital arrest|\bcbi\b|\bcustoms\b|\bnarcotics\b"
          r"|\b(?:courier|parcel)\W+(?:\w+\W+){0,3}seized"
          r"|\bseized\W+(?:\w+\W+){0,3}(?:courier|parcel)))"
          r"(?=.*\b(?:police|officer|case|arrest\w*)\b)"),
    _rule("ELECTRICITY_BILL", "Fake electricity disconnection notice", 20,
          r"^(?=.*\b(?:electricity|power)\b.{0,60}\bdisconnect\w*)"
          r"(?=.*(?:\+?91[\s-]?)?(?<!\d)[6-9]\d{9}(?!\d))"),
    _rule("INVESTMENT_BAIT", "Investment / trading-group bait", 25,
          r"\bguaranteed returns?\b|\bdouble your money\b"
          r"|\b(?:crypto|stock)\s+tips?\b|\bvip\s+(?:trading|stock|crypto)\s+group\b"),
]


def rule_flags(text: str) -> list[dict]:
    """Return id/label/weight for every rule matching the text, in RULES order."""
    if not text or not text.strip():
        return []
    return [
        {"id": r["id"], "label": r["label"], "weight": r["weight"]}
        for r in RULES
        if r["pattern"].search(text)
    ]


def rule_score(flags: list[dict]) -> int:
    """Sum flag weights, capped at 100."""
    return min(100, sum(f["weight"] for f in flags))


def rule_verdict(score: int) -> str:
    """Map a score to SCAM, SUSPICIOUS or LIKELY SAFE."""
    if score >= SCAM_THRESHOLD:
        return "SCAM"
    if score >= SUSPICIOUS_THRESHOLD:
        return "SUSPICIOUS"
    return "LIKELY SAFE"
