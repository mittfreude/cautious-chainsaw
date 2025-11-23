# Safety, Limitations & Responsible Use

## Defensive-Only Design

**SigmaForge is exclusively a defensive cybersecurity tool** designed to help security teams detect and respond to threats. It is NOT an offensive tool.

### What SigmaForge Does ✅

- **Generates Sigma detection rules** from threat descriptions
- **Analyzes existing detection rules** to help analysts understand them
- **Validates rule syntax** using official Sigma libraries
- **Provides MITRE ATT&CK mappings** for threat intelligence
- **Suggests rule improvements** to reduce false positives
- **Accelerates blue team workflows** by automating tedious rule authoring

### What SigmaForge Does NOT Do ❌

- **No exploit generation or offensive techniques**
- **No network scanning or reconnaissance**
- **No attack execution or payload delivery**
- **No detection evasion assistance**
- **No malware development or reverse engineering**
- **No credential harvesting or lateral movement**

## Intended Use Cases

SigmaForge is designed for:

1. **Security Operations Centers (SOCs)** - Rapidly creating detection rules for emerging threats
2. **Detection Engineers** - Automating the initial rule drafting process
3. **Threat Intelligence Teams** - Converting threat reports into actionable detections
4. **Security Researchers** - Understanding and improving open-source Sigma rules
5. **Cybersecurity Education** - Teaching detection engineering concepts
6. **Incident Response Teams** - Creating rules based on observed attack patterns

## Limitations & Important Caveats

### 1. LLM Outputs Require Human Review

- **LLMs can make mistakes** - Generated rules may be incorrect, incomplete, or overly broad
- **Always review generated rules** before deploying to production
- **Test rules thoroughly** in a development environment first
- **Validate against real telemetry** to ensure rules work in your environment

### 2. Not a Replacement for Human Expertise

- SigmaForge is a **co-pilot, not an autopilot**
- Rules still require **expert review and tuning**
- Understanding detection engineering principles is essential
- Tool accelerates workflows but doesn't eliminate the need for skilled analysts

### 3. False Positives & False Negatives

- **Experimental rules** may have higher false positive rates
- Rules need **environment-specific tuning** based on baselines
- **Attackers may evade** simple detection patterns
- Rules should be **continuously refined** based on SOC feedback

### 4. Synthetic Evaluation Only

- Benchmark scenarios use **synthetic logs, not real production data**
- Effectiveness varies by:
  - Log quality and completeness
  - Environment configuration
  - Attacker sophistication
  - Organizational context

### 5. pySigma Validation Limitations

- Validation checks **syntax only, not detection logic**
- A "valid" rule may still:
  - Miss attacks (false negatives)
  - Alert on benign activity (false positives)
  - Be incompatible with specific SIEM configurations

### 6. Single-Event Detection Only

- Current implementation generates **single-event rules**
- Cannot create:
  - Complex correlation rules across multiple events
  - Statistical threshold rules (e.g., "more than 5 failed logins")
  - Time-window aggregations (e.g., "within 10 minutes")

## Security & Privacy Considerations

### Data Handling

- **API Communication:** Threat descriptions and rules are sent to OpenAI's API for processing
- **No Data Storage:** SigmaForge does not store or log user inputs locally (beyond session state)
- **Sensitive Information:** Avoid pasting real production logs containing PII, credentials, or sensitive data
- **API Key Security:** Store API keys securely using environment variables, never commit them to version control

### Network Connectivity

- **Outbound HTTPS Only:** SigmaForge makes HTTPS requests to OpenAI's API only
- **No Inbound Connections:** The tool does not accept incoming network connections
- **No Scanning:** Does not scan networks, ports, or systems
- **No Command Execution:** Generated rules are detection logic only, not executable code

## Misuse Prevention

### Rules Should Never Be Used For:

1. **Developing Attacks:** Rules describe detection patterns, not attack methodologies
2. **Evading Detection:** Using rule knowledge to bypass security controls is unethical and illegal
3. **Unauthorized Access:** All security testing must be authorized by system owners
4. **Malicious Purposes:** This tool is for defense only; misuse violates intended purpose

### Responsible Disclosure

If you discover security vulnerabilities in SigmaForge:

1. **Do not exploit** the vulnerability
2. **Report it responsibly** to the project maintainers
3. **Allow time** for fixes before public disclosure
4. **Help improve** the tool for the defensive community

## Ethical Guidelines

### Users of SigmaForge Should:

- **Only use on authorized systems** where you have permission to deploy detection rules
- **Follow organizational policies** for security tool usage
- **Respect privacy** and data handling regulations (GDPR, CCPA, etc.)
- **Collaborate openly** with the defensive security community
- **Share knowledge** to improve collective defense capabilities
- **Report issues** to help improve the tool's safety and effectiveness

### Users Should NOT:

- Use rules to understand how to evade detection in unauthorized contexts
- Deploy untested rules to production without review
- Rely solely on automated rule generation without human oversight
- Share sensitive organizational data with the LLM API
- Use the tool for any offensive security purposes

## Deployment Best Practices

### Before Production Deployment:

1. **Review Generated Rules:**
   - Validate logic and field names
   - Check for overly broad patterns
   - Ensure MITRE ATT&CK mappings are accurate

2. **Test in Development:**
   - Run against historical logs
   - Measure false positive rates
   - Verify true positive detection

3. **Tune for Your Environment:**
   - Adjust field names for your SIEM
   - Add environment-specific filters
   - Set appropriate severity levels

4. **Implement Monitoring:**
   - Track rule performance metrics
   - Review alerts regularly
   - Iterate based on analyst feedback

5. **Document Assumptions:**
   - Record what logs the rule requires
   - Note known limitations
   - Document false positive scenarios

## Updates & Maintenance

- **Keep pySigma Updated:** Ensure validation library stays current
- **Review Sigma Specification Changes:** Sigma format may evolve
- **Monitor LLM Quality:** OpenAI models may change behavior
- **Share Feedback:** Report issues and improvements to the community

## Acknowledgment & Agreement

By using SigmaForge, you acknowledge that:

1. This is a **defensive security tool only**
2. You will **not use it for offensive purposes**
3. You have **authorization** to deploy detection rules in your environment
4. You will **review all generated rules** before production use
5. You understand the **limitations and risks** documented here
6. You will use the tool **ethically and responsibly**
7. You accept **full responsibility** for how you deploy and use generated rules

## Support & Contact

- **Issues:** Report bugs and feature requests on GitHub
- **Security Concerns:** Contact maintainers privately for security issues
- **Community:** Join discussions to share knowledge and improvements
- **Documentation:** Refer to README.md and code comments for technical details

---

**Remember: SigmaForge is a tool to accelerate defensive workflows, not replace human expertise. Always prioritize responsible, authorized, and ethical use.**
