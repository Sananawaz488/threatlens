import json
import os

import streamlit as st
from groq import Groq

from sources import (
    SOURCE_REGISTRY,
    detect_target_type,
    normalize_target,
    validate_target,
)


# ============================================================
# ThreatLens
# Cybersecurity IP / Domain / URL Analysis
# ============================================================

APP_NAME = "ThreatLens"
AI_MODEL = "openai/gpt-oss-120b"


# ============================================================
# Verdict Configuration
# ============================================================

# Only actual threat verdicts are included here.
# WHOIS returns "unknown" because WHOIS is contextual data,
# so it should NOT override a VirusTotal verdict.

VERDICT_PRIORITY = {
    "safe": 1,
    "suspicious": 2,
    "malicious": 3,
}


# ============================================================
# Secret Helper
# ============================================================

def get_secret(name):
    """
    Read a secret from Streamlit Secrets first.
    Fall back to environment variables if necessary.
    """

    try:
        return st.secrets[name]
    except Exception:
        return os.getenv(name)


# ============================================================
# Overall Verdict
# ============================================================

def calculate_overall_verdict(results):
    """
    Calculate the overall threat verdict.

    Only safe, suspicious, and malicious are considered.
    Source results with unknown/unavailable verdicts do not
    override an actual threat verdict.
    """

    verdicts = [
        result.get("verdict")
        for result in results
        if result.get("status") == "success"
        and result.get("verdict") in VERDICT_PRIORITY
    ]

    if not verdicts:
        return "unknown"

    return max(
        verdicts,
        key=lambda value: VERDICT_PRIORITY[value],
    )


# ============================================================
# Run Intelligence Sources
# ============================================================

def run_scan(target, target_type):
    """
    Run all registered intelligence sources.
    """

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

        # Make sure the source name is always present.
        if not result.get("source"):
            result["source"] = source_name

        results.append(result)

    return results


# ============================================================
# AI Prompt
# ============================================================

def build_ai_prompt(
    target,
    target_type,
    knowledge_level,
    results,
    overall_verdict,
):
    """
    Create a controlled prompt for the AI model.

    The AI is instructed not to invent information.
    """

    scan_data = json.dumps(
        results,
        indent=2,
        default=str,
    )

    return f"""
You are the ThreatLens cybersecurity analysis assistant.

Your job is to explain the supplied cybersecurity scan
results clearly and accurately.

IMPORTANT RULES:

1. Analyze ONLY the supplied scan results.
2. Do NOT invent facts.
3. Do NOT assume missing information.
4. Do NOT claim a target is guaranteed safe.
5. WHOIS information is contextual and is NOT proof
   that a target is safe or malicious.
6. The deterministic overall verdict is:
   {overall_verdict}
7. Do not change the deterministic verdict.
8. If a source is unavailable, clearly mention that.
9. Keep the explanation concise and useful.
10. Do not recommend illegal or unauthorized activity.
11. Do not suggest active scanning unless the user has
    proper authorization.

Target:
{target}

Detected target type:
{target_type}

User knowledge level:
{knowledge_level}

Deterministic overall verdict:
{overall_verdict}

Source results:
{scan_data}

Return exactly these sections:

Verdict
Confidence
Why
Key Findings
Recommended Next Step
"""


# ============================================================
# AI Analysis
# ============================================================

def get_ai_insight(
    target,
    target_type,
    knowledge_level,
    results,
    overall_verdict,
):
    """
    Generate cybersecurity explanation using Groq.
    """

    api_key = get_secret("GROQ_API_KEY")

    if not api_key:

        return (
            "AI analysis is unavailable because "
            "GROQ_API_KEY is not configured."
        )

    try:

        client = Groq(
            api_key=api_key
        )

        prompt = build_ai_prompt(
            target=target,
            target_type=target_type,
            knowledge_level=knowledge_level,
            results=results,
            overall_verdict=overall_verdict,
        )

        response = client.chat.completions.create(
            model=AI_MODEL,
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You are a careful cybersecurity "
                        "analysis assistant. "
                        "Use only the provided scan data."
                    ),
                },
                {
                    "role": "user",
                    "content": prompt,
                },
            ],
            temperature=0.2,
        )

        content = response.choices[0].message.content

        if not content:
            return "AI returned an empty response."

        return content

    except Exception as exc:

        return (
            "AI analysis error: "
            f"{exc}"
        )


# ============================================================
# Verdict Display
# ============================================================

def display_verdict(verdict):
    """
    Display a clear verdict message.
    """

    if verdict == "malicious":

        st.error(
            "🚨 MALICIOUS — Threat indicators were detected."
        )

    elif verdict == "suspicious":

        st.warning(
            "⚠️ SUSPICIOUS — Some threat indicators were detected."
        )

    elif verdict == "safe":

        st.success(
            "✅ SAFE — No malicious or suspicious detections "
            "were reported by the available threat source."
        )

    else:

        st.info(
            "ℹ️ UNKNOWN — There is not enough successful "
            "threat intelligence to determine a verdict."
        )


# ============================================================
# Render Source Result
# ============================================================

def render_result(result):

    source = result.get(
        "source",
        "Unknown Source",
    )

    status = result.get(
        "status",
        "unknown",
    )

    verdict = result.get(
        "verdict",
        "unknown",
    )

    summary = result.get(
        "summary",
        "",
    )

    error = result.get(
        "error",
        "",
    )

    data = result.get(
        "data",
        {},
    )

    st.subheader(
        f"🔹 {source.title()}"
    )

    col1, col2 = st.columns(2)

    with col1:
        st.write(
            f"**Status:** {status}"
        )

    with col2:
        st.write(
            f"**Verdict:** {verdict}"
        )

    if summary:
        st.write(summary)

    if error:
        st.warning(error)

    if data:

        with st.expander(
            "View source data"
        ):
            st.json(data)


# ============================================================
# Main Application
# ============================================================

def main():

    # --------------------------------------------------------
    # Page Configuration
    # --------------------------------------------------------

    st.set_page_config(
        page_title="ThreatLens",
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="expanded",
    )

    # --------------------------------------------------------
    # Header
    # --------------------------------------------------------

    st.title("🛡️ ThreatLens")

    st.caption(
        "Cybersecurity intelligence for IP addresses, "
        "domains, and URLs"
    )

    st.divider()

    # --------------------------------------------------------
    # Sidebar
    # --------------------------------------------------------

    with st.sidebar:

        st.header("⚙️ Scan Settings")

        knowledge_level = st.selectbox(
            "Knowledge level",
            [
                "Beginner",
                "Intermediate",
                "Expert",
            ],
        )

        st.divider()

        st.markdown(
            """
### ThreatLens

ThreatLens combines deterministic threat intelligence
with AI-assisted explanation.

**Sources**
- VirusTotal
- WHOIS

**Supported targets**
- IP addresses
- Domains
- URLs
"""
        )

    # --------------------------------------------------------
    # Target Input
    # --------------------------------------------------------

    target = st.text_input(
        "🎯 Enter an IP address, domain, or URL",
        placeholder="example.com or 8.8.8.8",
    )

    scan = st.button(
        "🔎 Scan Target",
        type="primary",
        use_container_width=True,
    )

    # --------------------------------------------------------
    # Stop if Scan Not Requested
    # --------------------------------------------------------

    if not scan:
        st.info(
            "Enter a target above and click "
            "**Scan Target** to begin."
        )
        return

    # --------------------------------------------------------
    # Normalize Target
    # --------------------------------------------------------

    normalized = normalize_target(
        target
    )

    # Detect type using original target so URLs
    # remain identifiable as URLs.
    target_type = detect_target_type(
        target
    )

    # --------------------------------------------------------
    # Validate
    # --------------------------------------------------------

    valid, error = validate_target(
        normalized,
        target_type,
    )

    if not valid:

        st.error(
            f"❌ {error}"
        )

        return

    # --------------------------------------------------------
    # Target Information
    # --------------------------------------------------------

    st.info(
        f"**Detected type:** `{target_type}`  \n"
        f"**Normalized target:** `{normalized}`"
    )

    # --------------------------------------------------------
    # Run Scan
    # --------------------------------------------------------

    with st.spinner(
        "🔍 Running threat intelligence sources..."
    ):

        results = run_scan(
            normalized,
            target_type,
        )

    # --------------------------------------------------------
    # Overall Verdict
    # --------------------------------------------------------

    overall = calculate_overall_verdict(
        results
    )

    st.divider()

    st.header(
        f"Overall Verdict: {overall.upper()}"
    )

    display_verdict(
        overall
    )

    # --------------------------------------------------------
    # Source Results
    # --------------------------------------------------------

    st.divider()

    st.header(
        "📊 Intelligence Sources"
    )

    for result in results:

        render_result(
            result
        )

    # --------------------------------------------------------
    # AI Analysis
    # --------------------------------------------------------

    st.divider()

    st.header(
        "🤖 AI Security Analysis"
    )

    with st.spinner(
        "Preparing AI analysis..."
    ):

        insight = get_ai_insight(
            target=normalized,
            target_type=target_type,
            knowledge_level=knowledge_level,
            results=results,
            overall_verdict=overall,
        )

    st.markdown(
        insight
    )

    # --------------------------------------------------------
    # Footer
    # --------------------------------------------------------

    st.divider()

    st.caption(
        "ThreatLens provides informational cybersecurity "
        "analysis and does not guarantee that a target is safe."
    )


# ============================================================
# Application Entry Point
# ============================================================

if __name__ == "__main__":
    main()
