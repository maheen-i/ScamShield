"""ScamShield Streamlit UI: check an SMS/WhatsApp message for scams."""
import hmac
import os

import streamlit as st

from scamshield.analyzer import analyze

MAX_CHECKS = 20
MAX_IMAGE_BYTES = 5 * 1024 * 1024
VERDICT_COLORS = {"SCAM": "red", "SUSPICIOUS": "orange", "LIKELY SAFE": "green"}

st.set_page_config(page_title="ScamShield", page_icon="\U0001f6e1️")


def passcode_gate() -> None:
    """Stop the app until the passcode matches, if one is configured."""
    try:
        expected = st.secrets["APP_PASSCODE"]
    except Exception:  # secret or secrets file not present
        return
    entered = st.text_input("Passcode", type="password")
    if not hmac.compare_digest(str(entered), str(expected)):
        st.stop()


def render_sidebar() -> tuple[bool, "st.delta_generator.DeltaGenerator"]:
    """Draw the sidebar; return the rules toggle and the counter slot."""
    st.sidebar.write(f"Model: `{os.getenv('SCAMSHIELD_MODEL', 'claude-haiku-5-5')}`")
    use_rules = st.sidebar.checkbox("Use rule engine", value=True)
    slot = st.sidebar.empty()
    return use_rules, slot


def show_counter(slot: "st.delta_generator.DeltaGenerator") -> None:
    """Show the session check counter in the sidebar slot."""
    slot.write(f"Checks this session: {st.session_state['checks']} / {MAX_CHECKS}")


def forward_warning(result: dict) -> str:
    """Build a plain-text 3-line warning to forward to family."""
    flags = result.get("red_flags") or ["suspicious content"]
    return (
        f"Scam alert: this message looks like a {result.get('scam_type', 'scam')} scam.\n"
        f"Red flag: {flags[0]}\n"
        "Do not click links or share OTP/PIN. Verify via the official app or call 1930."
    )


def render_result(result: dict) -> None:
    """Render the analysis result."""
    if "error" in result:
        st.warning(result["error"])
    verdict = result["verdict"]
    color = VERDICT_COLORS.get(verdict, "gray")
    st.header(f":{color}[{verdict}] {result['risk_score']}/100")
    st.progress(max(0, min(100, result["risk_score"])) / 100)
    st.write(result["explanation"])
    st.caption(f"Scam type: {result['scam_type']}")
    if result.get("escalated"):
        st.caption("Raised by rules")
    st.subheader("Red flags")
    st.markdown("\n".join(f"- {f}" for f in result["red_flags"]) or "- None")
    if result.get("code_flags"):
        st.caption("Rule-based checks triggered: " + ", ".join(result["code_flags"]))
    st.subheader("What to do")
    st.markdown("\n".join(f"- {s}" for s in result["what_to_do"]))
    if verdict != "LIKELY SAFE":
        st.subheader("Warning to forward to family")
        st.code(forward_warning(result), language=None)


def run_check(text: str, image, lang: str, use_rules: bool) -> None:
    """Call analyze, update the counter, and render the outcome."""
    image_bytes = image.getvalue() if image else None
    if image_bytes and len(image_bytes) > MAX_IMAGE_BYTES:
        st.error("Screenshot is larger than 5 MB. Please upload a smaller image.")
        return
    try:
        with st.spinner("Checking..."):
            result = analyze(text, image_bytes, image.type if image else None,
                             lang, use_rules)
    except ValueError:
        st.error("API key not configured")
        return
    if result.get("usage", {}).get("input_tokens", 0) > 0:
        st.session_state["checks"] += 1
    render_result(result)


def render_footer() -> None:
    """Show reporting info and the screenshot privacy note."""
    st.info("In India, report cyber fraud at cybercrime.gov.in or call 1930. "
            "Please verify these official contacts yourself.")
    st.caption("Screenshots are sent to Anthropic's API for analysis and are "
               "not stored by this app.")


def main() -> None:
    """Build the page."""
    st.title("\U0001f6e1️ ScamShield")
    st.caption("Check SMS/WhatsApp messages for scams. Not legal or financial advice.")
    passcode_gate()
    st.session_state.setdefault("checks", 0)
    use_rules, slot = render_sidebar()
    lang = st.radio("Answer language", ["English", "Hindi"], horizontal=True)
    text = st.text_area("Paste the message")
    image = st.file_uploader("Or upload a screenshot", type=["png", "jpg", "jpeg"])
    if st.button("Check it"):
        if st.session_state["checks"] >= MAX_CHECKS:
            st.warning("Session limit reached (20 checks). Please come back later.")
        elif text.strip() or image:
            run_check(text, image, lang, use_rules)
        else:
            st.warning("Paste a message or upload a screenshot first.")
    show_counter(slot)
    render_footer()


main()
