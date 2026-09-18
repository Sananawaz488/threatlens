import json
import os

import streamlit as st

from sources import (
    SOURCE_REGISTRY,
    detect_target_type,
    normalize_target,
    validate_target,
)


VERDICT_PRIORITY = {
    "safe": 1,
    "unknown": 2,
    "suspicious": 3,
    "malicious": 4,
}


def calculate_overall_verdict(results):
    verdicts = [
        result["verdict"]
        for result in results
        if result["status"] == "success"
        and result["verdict"] in VERDICT_PRIORITY
    ]

    if not verdicts:
        return "unknown"

    return max(
        verdicts,
        key=lambda value: VERDICT_PRIORITY[value],
    )


def run_scan(target, target_type):
    results = []

    for source_name, source_function in SOURCE_REGISTRY.items():
        try:
            result = source_function(
                target,
                target_type,
            )
        except Exception as exc:
            result = {
                "source": source_name,
                "status": "error",
                "verdict": "unknown",
                "summary": "",
                "data": {},
                "error": str(exc),
            }

        results.append(result)

    return results


def build_gemini_prompt(
    target,
    target_type,
    knowledge_level,
    results,
    overall_verdict,
):
    return f"""
You are the ThreatLens cybersecurity analysis assistant.

Analyze ONLY the supplied scan results.

Do not invent facts.
Do not assume missing information.
Do not claim a target is guaranteed safe.
WHOIS information is contextual and is not proof that a target is safe.

Target:
{target}

Detected type:
{target_type}

Knowledge level:
{knowledge_level}

Deterministic overall verdict:
{overall_verdict}

Source results:
{json.dumps(results, indent=2, default=str)}

Return exactly these sections:

Verdict
Confidence
Why
Key Findings
Recommended Next Step
"""


def get_ai_insight(
    target,
    target_type,
    knowledge_level,
    results,
    overall_verdict,
):
    api_key = os.getenv("GEMINI_API_KEY")

    if not api_key:
        return (
            "Gemini is unavailable because "
            "GEMINI_API_KEY is not configured."
        )

    try:
        from google import genai

        client = genai.Client(
            api_key=api_key
        )

        prompt = build_gemini_prompt(
            target,
            target_type,
            knowledge_level,
            results,
            overall_verdict,
        )

        response = client.models.generate_content(
            model="openai/gpt-oss-120b",
            contents=prompt,
        )

        return response.text

    except Exception as exc:
        return f"Gemini error: {exc}"


def render_result(result):
    source = result["source"]
    status = result["status"]
    verdict = result["verdict"]

    st.subheader(source.title())

    st.write(f"Status: **{status}**")
    st.write(f"Verdict: **{verdict}**")

    if result.get("summary"):
        st.write(result["summary"])

    if result.get("error"):
        st.warning(result["error"])

    if result.get("data"):
        with st.expander("Source data"):
            st.json(result["data"])


def main():
    st.set_page_config(
        page_title="ThreatLens",
        page_icon="🛡️",
        layout="wide",
    )

    st.title("🛡️ ThreatLens")
    st.caption(
        "IP, domain, and URL safety analysis"
    )

    target = st.text_input(
        "Enter an IP address, domain, or URL",
        placeholder="example.com",
    )

    knowledge_level = st.selectbox(
        "Knowledge level",
        [
            "Beginner",
            "Intermediate",
            "Expert",
        ],
    )

    scan = st.button(
        "🔎 Scan",
        type="primary",
    )

    if not scan:
        return

    normalized = normalize_target(target)
    target_type = detect_target_type(target)

    valid, error = validate_target(
        normalized,
        target_type,
    )

    if not valid:
        st.error(error)
        return

    st.info(
        f"Detected type: **{target_type}**"
    )

    with st.spinner("Running intelligence sources..."):
        results = run_scan(
            target,
            target_type,
        )

    overall = calculate_overall_verdict(
        results
    )

    st.divider()

    st.header(
        f"Overall verdict: {overall.upper()}"
    )

    for result in results:
        render_result(result)

    st.divider()

    st.header("🤖 Gemini Analysis")

    with st.spinner("Preparing analysis..."):
        insight = get_ai_insight(
            target,
            target_type,
            knowledge_level,
            results,
            overall,
        )

    st.write(insight)


if __name__ == "__main__":
    main()
