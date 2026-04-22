# 🛡️ AI Security Log Triage Agent (LangChain)

An AI-powered cybersecurity agent that moves beyond traditional rule-based SIEM triage by using reasoning-driven analysis to detect threats, extract IOCs, and generate actionable security insights.

---

## 🚀 Overview

Security teams are overwhelmed by noisy logs and alert fatigue.

This project introduces a LangChain-based AI agent that:
- Analyzes raw logs
- Detects suspicious patterns
- Extracts Indicators of Compromise (IOCs)
- Assigns severity levels
- Recommends response actions

This is not a chatbot — it's a reasoning security agent.

---

## ⚙️ Core Capabilities

- Log analysis for SSH, HTTP, and system logs
- Threat detection for failed logins, brute force, and suspicious access
- Context-aware reasoning
- Severity classification
- Structured incident summaries
- Actionable remediation recommendations

---

## 🧠 Example Output

```text
Incident: Multiple failed SSH login attempts detected
Severity: High
Confidence: 0.92

Indicators:
- Repeated login failures from IP 192.168.1.100
- Possible brute force attack pattern

Recommended Actions:
- Block offending IP
- Enable rate limiting
- Review authentication logs

🏗️ Architecture
[ Log Input ]
      ↓
[ Preprocessing ]
      ↓
[ AI Agent (LangChain) ]
      ↓
 ├── Threat Detection
 ├── IOC Extraction
 ├── Severity Classification
 └── Response Recommendation
      ↓
[ Structured Security Report ]

🔧 Tech Stack
Python
LangChain
LLMs
Regex and heuristic detection
JSON-based reporting

🧩 Use Cases
SOC log triage automation
Security monitoring enhancement
AI-assisted incident response
Threat intelligence enrichment

🔐 Why This Matters

Traditional systems often rely on static rules, generate high false positives, and lack context.

This approach uses reasoning to adapt to suspicious patterns and produce human-readable security intelligence.

🔄 Future Enhancements
MITRE ATT&CK mapping
Multi-agent orchestration
SIEM integration with Splunk, ELK, or Wazuh
AI red team simulation
Dashboard and visualization

📦 Installation
git clone https://github.com/softvillaGh/langchain-security-log-triage-agent.git
cd langchain-security-log-triage-agent
pip install -r requirements.txt

▶️ Usage
python app/main.py

🤝 Let's Connect
If you're working on AI in cybersecurity, security automation, or red teaming and blue teaming with AI, let’s connect.

Open to opportunities in AI and Cybersecurity.

⭐ Support

If you find this useful:

Star the repo
Share feedback
Suggest improvements
