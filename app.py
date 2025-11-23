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
    validate_sigma_rule,
    explain_sigma_rule,
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
if "rule_explanation" not in st.session_state:
    st.session_state.rule_explanation = None


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
            options=["Threat description", "Example logs", "Existing Sigma rule"],
            help="Choose how you want to work with Sigma rules.",
        )

        # Environment selection (not shown for Rule Doctor mode)
        if input_mode != "Existing Sigma rule":
            st.divider()
            st.subheader("🎯 Target Environment")
            target_environment = st.selectbox(
                "SIEM Platform",
                options=["Generic Sigma", "Splunk", "Elastic", "Microsoft Sentinel"],
                help="Select your target SIEM platform. Field names will be adapted to common conventions for your environment.",
            )
        else:
            target_environment = "Generic Sigma"

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
        **SigmaForge** helps you quickly:
        - Generate Sigma rules from threat descriptions
        - Create rules from example logs
        - Understand and improve existing Sigma rules

        **Defensive-Only Tool:**
        - ✅ Detection rule generation
        - ✅ Blue team workflow acceleration
        - ❌ No exploits or offensive capabilities
        - ❌ No network scanning
        """
        )

    # Main content area
    col1, col2 = st.columns([1, 1])

    with col1:
        st.header("📝 Input")

        # Handle different input modes
        if input_mode == "Existing Sigma rule":
            # Rule Doctor mode
            st.markdown("**Rule Doctor: Explain & Improve Existing Sigma Rules**")
            st.markdown("Paste any Sigma rule to get a detailed explanation and tuning suggestions.")

            input_text = st.text_area(
                "Paste Sigma Rule (YAML)",
                placeholder="""title: Suspicious PowerShell Download
description: Detects PowerShell downloading content from the internet
status: experimental
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith: '\\powershell.exe'
    CommandLine|contains:
      - 'DownloadString'
      - 'DownloadFile'
  condition: selection
fields:
  - CommandLine
  - User
  - ParentImage
falsepositives:
  - Legitimate administrative scripts
level: medium
tags:
  - attack.execution
  - attack.t1059.001""",
                height=300,
                help="Paste an existing Sigma rule in YAML format",
            )

            explain_button = st.button(
                "🔍 Explain & Analyze Rule",
                type="primary",
                use_container_width=True,
                disabled=not input_text.strip(),
            )

            if explain_button and input_text.strip():
                with st.spinner("Analyzing Sigma rule..."):
                    try:
                        llm_client = create_client(model=model_name, temperature=temperature)

                        # Store the original rule
                        st.session_state.sigma_rule = input_text

                        # Explain the rule
                        st.session_state.rule_explanation = explain_sigma_rule(
                            input_text, llm_client
                        )

                        # Also store a fake threat_json for compatibility
                        st.session_state.threat_json = {
                            "logsource": {},
                            "relevant_fields": [],
                            "attack_behaviour": st.session_state.rule_explanation["attack_behaviour"],
                            "possible_mitre_techniques": st.session_state.rule_explanation["coverage"],
                            "assumptions": [],
                        }

                        st.success("✅ Rule analyzed successfully!")

                    except Exception as e:
                        st.error(f"❌ Error analyzing rule: {str(e)}")
                        logging.error(f"Error during rule explanation: {e}", exc_info=True)

        else:
            # Threat description or Example logs mode
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

                        # Clear any previous rule explanation
                        st.session_state.rule_explanation = None

                        # Parse threat to JSON (with environment)
                        st.session_state.threat_json = parse_threat_to_json(
                            input_text, llm_client, target_environment
                        )

                        # Generate Sigma rule (with environment)
                        st.session_state.sigma_rule = generate_sigma_rule(
                            st.session_state.threat_json, llm_client, target_environment
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
            # Check if we're in Rule Doctor mode
            if st.session_state.rule_explanation:
                # Display Rule Doctor explanation
                st.subheader("🩺 Rule Analysis")

                explanation = st.session_state.rule_explanation

                # Attack behavior
                st.markdown("**What This Rule Detects:**")
                st.info(explanation["attack_behaviour"])

                # Log source summary
                st.markdown("**Log Sources:**")
                st.write(explanation["logsource_summary"])

                # MITRE Coverage
                st.markdown("**MITRE ATT&CK Coverage:**")
                for technique in explanation["coverage"]:
                    st.write(f"- {technique}")

                # False positives
                with st.expander("⚠️ Likely False Positives"):
                    for fp in explanation["likely_false_positives"]:
                        st.write(f"- {fp}")

                # Tuning suggestions
                with st.expander("💡 Tuning Suggestions"):
                    for suggestion in explanation["tuning_suggestions"]:
                        st.write(f"- {suggestion}")

                st.divider()

            else:
                # Display threat interpretation (normal mode)
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

            # Display Sigma rule (common for all modes)
            st.subheader("📜 " + ("Original Sigma Rule" if st.session_state.rule_explanation else "Generated Sigma Rule"))

            st.code(st.session_state.sigma_rule, language="yaml")

            # pySigma validation
            is_valid, error_msg = validate_sigma_rule(st.session_state.sigma_rule)
            if is_valid:
                st.success("✅ Valid Sigma rule (pySigma validated)")
            else:
                st.error(f"❌ Sigma validation error: {error_msg}")

            # Download button
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            st.download_button(
                label="💾 Download Rule (.yml)",
                data=st.session_state.sigma_rule,
                file_name=f"sigma_rule_{timestamp}.yml",
                mime="text/yaml",
            )

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
