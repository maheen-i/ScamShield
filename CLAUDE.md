# ScamShield rules

- Python 3.11+. Only dependencies: streamlit, anthropic, pytest. Ask before adding any other.
- Never hard-code or print API keys. Read ANTHROPIC_API_KEY from st.secrets or the environment.
- Model name comes from env var SCAMSHIELD_MODEL, default "claude-haiku-5-5".
- Never log or store message contents.
- Only touch files named in the prompt. Do not explore or read unrelated files. Do not refactor.
- No network or API calls unless explicitly told. Tests must run offline (mock the Anthropic client).
- Keep each function under 40 lines, with type hints and a one-line docstring.
- When finished, stop and print what you created. No extra features.
