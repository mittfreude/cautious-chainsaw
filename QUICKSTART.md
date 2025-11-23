# SigmaForge Quick Start 🚀

Get up and running with SigmaForge in 5 minutes.

---

## Prerequisites

- Python 3.11 or higher
- OpenAI API key ([get one here](https://platform.openai.com/api-keys))
- Basic understanding of security logs

---

## Installation (2 minutes)

```bash
# 1. Navigate to the project directory
cd /home/user/cautious-chainsaw

# 2. Install dependencies
pip install -r requirements.txt

# 3. Set your API key
export OPENAI_API_KEY='sk-your-api-key-here'
```

---

## Launch the App (30 seconds)

```bash
streamlit run app.py
```

The app will automatically open in your browser at `http://localhost:8501`

---

## Your First Detection Rule (2 minutes)

### Option A: Threat Description Mode

1. In the sidebar, select **"Threat description"**
2. In the text area, paste this example:

```
Detect when attackers use PowerShell to download and execute malicious
scripts from the internet, especially when using obfuscation techniques
like base64 encoding or hidden windows.
```

3. Click **"🔨 Generate Sigma Rule"**
4. Wait 10-15 seconds
5. View your results:
   - ✅ Threat analysis with MITRE ATT&CK mapping
   - ✅ Complete Sigma rule in YAML format
   - ✅ Ready to download and deploy

### Option B: Example Logs Mode

1. In the sidebar, select **"Example logs"**
2. Paste these suspicious log examples:

```
2024-01-15 10:23:45 sshd[12345]: Failed password for admin from 192.168.1.100 port 52341 ssh2
2024-01-15 10:23:47 sshd[12346]: Failed password for admin from 192.168.1.100 port 52342 ssh2
2024-01-15 10:23:49 sshd[12347]: Failed password for admin from 192.168.1.100 port 52343 ssh2
2024-01-15 10:23:51 sshd[12348]: Failed password for admin from 192.168.1.100 port 52344 ssh2
2024-01-15 10:23:53 sshd[12349]: Accepted password for admin from 192.168.1.100 port 52345 ssh2
```

3. Click **"🔨 Generate Sigma Rule"**
4. SigmaForge will analyze the pattern and create a brute force detection rule

---

## Try the Review Feature (1 minute)

After generating a rule:

1. Click **"🔍 Review & Improve Rule"**
2. The AI will critique and enhance your rule
3. Compare the before/after versions
4. Download the improved version

---

## Test the Rule (1 minute)

1. Scroll down to **"🔎 Quick Log Sanity Check"**
2. Paste some test logs (both matching and non-matching)
3. Click **"▶️ Run Rough Match"**
4. See which logs would trigger your rule:
   - ✅ = Likely match
   - ⚪ = Probably not matched

---

## Download & Deploy

1. Click **"💾 Download Rule (.yml)"**
2. Deploy to your Sigma engine:

```bash
# Convert to your SIEM format
sigmac -t splunk sigma_rule_*.yml

# Or for Elasticsearch
sigmac -t elasticsearch sigma_rule_*.yml

# Or use modern Sigma CLI
sigma convert -t splunk sigma_rule_*.yml
```

---

## Real-World Examples to Try

### Example 1: Ransomware Detection
```
Detect potential ransomware activity by identifying processes that
rapidly access and modify a large number of files, especially when
the files are being encrypted or renamed with suspicious extensions
like .locked, .encrypted, or random characters.
```

### Example 2: Lateral Movement
```
Detect lateral movement attempts using PsExec or similar remote
execution tools. Look for administrative shares being accessed
(\\C$, \\ADMIN$) combined with service creation or remote process
execution.
```

### Example 3: Data Exfiltration
```
Detect large data transfers to external IPs, especially during
non-business hours or to cloud storage services like Dropbox,
Google Drive, or unknown destinations.
```

### Example 4: Web Shell Detection
```
Detect web shells by identifying web server processes (w3wp.exe,
apache, nginx) spawning command shells (cmd.exe, powershell.exe,
bash) or making unusual network connections.
```

---

## Configuration Tips

### Adjust Temperature (Sidebar)

- **0.0 - 0.2**: More deterministic, consistent rules (recommended for production)
- **0.3 - 0.5**: Balanced creativity and consistency
- **0.6 - 1.0**: More creative, varied outputs (good for brainstorming)

### Model Selection (Sidebar)

- **gpt-4o-mini**: Fast, cost-effective (default)
- **gpt-4o**: More capable, better for complex scenarios
- **gpt-4-turbo**: Balance of speed and quality

---

## Next Steps

📖 Read the full [USAGE_GUIDE.md](USAGE_GUIDE.md) for detailed examples

🧪 Explore the [tests/](tests/) directory to see how the code works

🛠️ Check out [sigmaforge/prompts.py](sigmaforge/prompts.py) to see the expert system prompts

🌐 Visit [SigmaHQ](https://github.com/SigmaHQ/sigma) to learn more about Sigma rules

---

## Troubleshooting

**App won't start?**
```bash
# Check Python version
python3 --version  # Should be 3.11+

# Reinstall dependencies
pip install --upgrade -r requirements.txt
```

**API errors?**
```bash
# Verify API key is set
echo $OPENAI_API_KEY

# Check you have credits at https://platform.openai.com/usage
```

**Rules seem off?**
- Try the "Review & Improve" button
- Lower the temperature to 0.0
- Be more specific in your description
- Provide more example logs

---

## Support

- 📚 Full documentation: [README.md](README.md)
- 🐛 Report issues on GitHub
- 💬 Questions? Check the usage guide

**Happy detecting! 🛡️**
