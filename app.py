"""
SigmaForge - Streamlit application for LLM-assisted Sigma rule generation.
"""

import logging
from datetime import datetime

import streamlit as st

from sigmaforge.config import (
    DEFAULT_MODEL,
    DEFAULT_TEMPERATURE,
    MIN_TEMPERATURE,
    MAX_TEMPERATURE,
    validate_api_key,
)
from sigmaforge.llm_client import create_client
from sigmaforge.core import (
    parse_threat_to_json,
    generate_sigma_rule,
    review_sigma_rule,
    rough_match_logs,
)
from sigmaforge.validation import validate_sigma_rule
from sigmaforge.conversion import (
    sigma_to_splunk_queries,
    sigma_to_elasticsearch_queries,
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)

# Page configuration
st.set_page_config(
    page_title="SigmaForge - Sigma Rule Generator",
    page_icon="🛡️",
    layout="wide",
)

# Initialize session state
if "threat_json" not in st.session_state:
    st.session_state.threat_json = None
if "sigma_rule" not in st.session_state:
    st.session_state.sigma_rule = None
if "generation_time" not in st.session_state:
    st.session_state.generation_time = None


def main():
    """Main application function."""

    # Header
    st.title("🛡️ SigmaForge")
    st.markdown("### LLM-assisted Sigma Detection Rule Generator")
    st.markdown(
        "A defensive cybersecurity tool for SOC analysts and detection engineers."
    )

    # Check for API key
    if not validate_api_key():
        st.error(
            "⚠️ OpenAI API key not found. Please set the `OPENAI_API_KEY` environment variable."
        )
        st.info(
            "To set the API key, run: `export OPENAI_API_KEY='your-key-here'` before starting Streamlit."
        )
        st.stop()

    # Sidebar configuration
    with st.sidebar:
        st.header("⚙️ Configuration")

        # Input mode selection
        input_mode = st.radio(
            "Input Mode",
            options=["Threat description", "Example logs"],
            help="Choose how you want to describe the threat you want to detect.",
        )

        st.divider()

        # Model configuration
        st.subheader("Model Settings")
        model_name = st.text_input(
            "Model Name",
            value=DEFAULT_MODEL,
            help="OpenAI model to use for generation.",
        )

        temperature = st.slider(
            "Temperature",
            min_value=MIN_TEMPERATURE,
            max_value=MAX_TEMPERATURE,
            value=DEFAULT_TEMPERATURE,
            step=0.1,
            help="Lower values = more deterministic, higher values = more creative.",
        )

        st.divider()

        # Info section
        st.subheader("ℹ️ About")
        st.markdown(
            """
        **SigmaForge** helps you quickly generate Sigma detection rules from:
        - Natural language threat descriptions
        - Example log lines showing suspicious activity

        This is a **defensive tool** designed to accelerate blue team workflows.
        """
        )

    # Main content area
    col1, col2 = st.columns([1, 1])

    with col1:
        st.header("📝 Input")

        # Input text area based on mode
        if input_mode == "Threat description":
            placeholder_text = """Example: Detect repeated failed SSH login attempts from a single IP address followed by a successful login on the same account within a short time window.

Example: Detect suspicious PowerShell execution that downloads a script from pastebin or a URL shortener service."""
            help_text = "Describe the threat or suspicious behavior you want to detect."
        else:
            placeholder_text = """Example log lines (paste 5-20 representative suspicious events):

Feb 10 14:23:45 server sshd[1234]: Failed password for admin from 192.168.1.100 port 51234 ssh2
Feb 10 14:23:48 server sshd[1234]: Failed password for admin from 192.168.1.100 port 51235 ssh2
Feb 10 14:23:51 server sshd[1234]: Accepted password for admin from 192.168.1.100 port 51236 ssh2"""
            help_text = "Paste example log lines that represent suspicious activity you want to detect."

        input_text = st.text_area(
            "Input" if input_mode == "Threat description" else "Example Logs",
            placeholder=placeholder_text,
            height=200,
            help=help_text,
        )

        # Generate button
        generate_button = st.button(
            "🔨 Generate Sigma Rule",
            type="primary",
            use_container_width=True,
            disabled=not input_text.strip(),
        )

        if generate_button and input_text.strip():
            with st.spinner("Analyzing threat and generating Sigma rule..."):
                try:
                    # Create LLM client
                    llm_client = create_client(model=model_name, temperature=temperature)

                    # Parse threat to JSON
                    st.session_state.threat_json = parse_threat_to_json(
                        input_text, llm_client
                    )

                    # Generate Sigma rule
                    st.session_state.sigma_rule = generate_sigma_rule(
                        st.session_state.threat_json, llm_client
                    )

                    st.session_state.generation_time = datetime.now()

                    st.success("✅ Sigma rule generated successfully!")

                except Exception as e:
                    st.error(f"❌ Error generating rule: {str(e)}")
                    logging.error(f"Error during generation: {e}", exc_info=True)

        # Review/Improve button (only show if we have a rule)
        if st.session_state.sigma_rule:
            st.divider()
            review_button = st.button(
                "🔍 Review & Improve Rule",
                use_container_width=True,
            )

            if review_button:
                with st.spinner("Reviewing and improving the rule..."):
                    try:
                        llm_client = create_client(
                            model=model_name, temperature=temperature
                        )

                        st.session_state.sigma_rule = review_sigma_rule(
                            st.session_state.threat_json,
                            st.session_state.sigma_rule,
                            llm_client,
                        )

                        st.success("✅ Rule reviewed and improved!")

                    except Exception as e:
                        st.error(f"❌ Error reviewing rule: {str(e)}")
                        logging.error(f"Error during review: {e}", exc_info=True)

    with col2:
        st.header("📋 Output")

        if st.session_state.threat_json and st.session_state.sigma_rule:
            # Display threat interpretation
            st.subheader("🎯 Threat Interpretation")

            threat_info = st.session_state.threat_json

            # Logsource
            st.markdown("**Log Source:**")
            logsource = threat_info.get("logsource", {})
            st.code(
                f"Product: {logsource.get('product', 'N/A')}\n"
                f"Service: {logsource.get('service', 'N/A')}\n"
                f"Category: {logsource.get('category', 'N/A')}"
            )

            # Attack behavior
            st.markdown("**Attack Behavior:**")
            st.info(threat_info.get("attack_behaviour", "N/A"))

            # Relevant fields
            st.markdown("**Relevant Fields:**")
            fields = threat_info.get("relevant_fields", [])
            st.write(", ".join(f"`{field}`" for field in fields) if fields else "N/A")

            # MITRE techniques
            mitre = threat_info.get("possible_mitre_techniques", [])
            if mitre:
                st.markdown("**MITRE ATT&CK Techniques:**")
                for technique in mitre:
                    st.write(f"- {technique}")

            # Assumptions
            assumptions = threat_info.get("assumptions", [])
            if assumptions:
                with st.expander("⚠️ Assumptions & Limitations"):
                    for assumption in assumptions:
                        st.write(f"- {assumption}")

            st.divider()

            # Display Sigma rule
            st.subheader("📜 Generated Sigma Rule")

            st.code(st.session_state.sigma_rule, language="yaml")

            # Download button
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            st.download_button(
                label="💾 Download Rule (.yml)",
                data=st.session_state.sigma_rule,
                file_name=f"sigma_rule_{timestamp}.yml",
                mime="text/yaml",
            )

            # Validation section
            st.markdown("#### ✅ Rule Validation")
            is_valid, errors, warnings = validate_sigma_rule(st.session_state.sigma_rule)

            if is_valid:
                st.success("✅ Valid Sigma rule (passed pySigma validation)")
                if warnings:
                    with st.expander("⚠️ Quality Suggestions", expanded=False):
                        for warning in warnings:
                            st.warning(warning)
            else:
                st.error("❌ Rule has validation errors:")
                for error in errors:
                    st.error(f"• {error}")
                if warnings:
                    st.markdown("**Warnings:**")
                    for warning in warnings:
                        st.warning(f"• {warning}")

            # SIEM Queries section
            st.markdown("#### 🔍 SIEM Queries")
            st.markdown(
                "*Convert this Sigma rule to production-ready queries for your SIEM*"
            )

            # Splunk queries
            with st.expander("🟠 Splunk SPL", expanded=True):
                success, splunk_queries, error_msg = sigma_to_splunk_queries(
                    st.session_state.sigma_rule
                )
                if success and splunk_queries:
                    for i, query in enumerate(splunk_queries, 1):
                        if len(splunk_queries) > 1:
                            st.markdown(f"**Query {i}:**")
                        st.code(query, language="spl")
                elif error_msg:
                    st.warning(f"Could not convert to Splunk query: {error_msg}")
                else:
                    st.info("No queries generated")

            # Elasticsearch queries
            with st.expander("🔵 Elasticsearch (Lucene)", expanded=False):
                success, es_queries, error_msg = sigma_to_elasticsearch_queries(
                    st.session_state.sigma_rule
                )
                if success and es_queries:
                    for i, query in enumerate(es_queries, 1):
                        if len(es_queries) > 1:
                            st.markdown(f"**Query {i}:**")
                        st.code(query, language="lucene")
                elif error_msg:
                    st.warning(f"Could not convert to Elasticsearch query: {error_msg}")
                else:
                    st.info("No queries generated")

            st.divider()

            # Log matching section
            st.subheader("🔎 Quick Log Sanity Check")
            st.markdown(
                "*Optional: Test the rule against sample logs (rough matching only)*"
            )

            test_logs = st.text_area(
                "Paste sample log lines (one per line)",
                height=150,
                placeholder="Paste log lines here to see which ones might match the rule...",
            )

            if st.button("▶️ Run Rough Match"):
                if test_logs.strip():
                    with st.spinner("Matching logs..."):
                        log_lines = [
                            line.strip()
                            for line in test_logs.split("\n")
                            if line.strip()
                        ]
                        results = rough_match_logs(
                            st.session_state.sigma_rule, log_lines
                        )

                        st.markdown("**Match Results:**")
                        for log_line, matched in results:
                            if matched:
                                st.success(f"✅ `{log_line[:100]}...`" if len(log_line) > 100 else f"✅ `{log_line}`")
                            else:
                                st.info(f"⚪ `{log_line[:100]}...`" if len(log_line) > 100 else f"⚪ `{log_line}`")

                        st.info(
                            "ℹ️ This is a simplified matching algorithm for demonstration. "
                            "For production use, deploy the rule to a proper Sigma engine like "
                            "Sigma CLI, sigmac, or your SIEM's Sigma processor."
                        )
                else:
                    st.warning("Please enter some log lines to test.")

        else:
            st.info(
                "👈 Enter a threat description or example logs on the left, then click **Generate Sigma Rule** to get started."
            )


if __name__ == "__main__":
    main()
