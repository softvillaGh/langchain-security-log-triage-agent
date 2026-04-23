# 🛡️ AI Security Log Triage Agent

An AI-powered cybersecurity triage layer that enhances traditional SIEM workflows by applying reasoning-driven analysis to detect threats, prioritize alerts, and generate actionable security insights.

---

## 🚀 Overview

Security teams—especially in SMBs and mid-sized organizations—face alert fatigue from noisy logs and limited triage capacity.

This project introduces a **lightweight AI-assisted triage engine** that:

- Ingests logs from multiple sources (file, SIEM simulation)
- Detects suspicious patterns and attack behaviors
- Extracts Indicators of Compromise (IOCs)
- Assigns severity levels dynamically
- Identifies repeated malicious activity
- Generates analyst-ready reports (JSON + HTML)

This is **not a chatbot** — it is a **reasoning-based security analysis engine**.

---

## ⚙️ Core Capabilities

- Multi-source log ingestion (file + simulated SIEM)
- Rule + pattern-based threat detection
- Severity classification (Low / High / Critical)
- Repeated attack detection (for example, brute force)
- Executive summary generation
- Structured reporting (JSON + HTML)
- Actionable recommendations for analysts

---

## 🧠 Example Output

```text
SECURITY TRIAGE REPORT

Headline: Critical malicious activity detected from 10.0.0.5

Total Events: 4
Critical: 2 | High: 1 | Low: 1
Unique IPs: 3

[1] Incident: Failed login
    Time: 2026-04-23T10:00:00Z
    Source: splunk
    IP: 10.0.0.5
    Severity: Critical
    Attack Type: Brute Force / Repeated Malicious Activity
    Recommendation: Block the IP and investigate immediately

🏗️ Architecture
[ Log Sources (File / SIEM) ]
              ↓
     [ Connectors Layer ]
              ↓
     [ Parsing & Normalization ]
              ↓
     [ Triage Engine ]
       ├── Detection
       ├── Classification
       ├── IOC Extraction
       └── Severity Scoring
              ↓
     [ Reporting Layer ]
       ├── Console Output
       ├── JSON Report
       └── HTML Report

🔧 Tech Stack
Python
Modular architecture (connectors, agents, output layers)
JSON-based reporting
Heuristic + rule-based detection
AI-ready design for future extension

▶️ Usage

Run with CLI:

python -m app.main --source splunk

or:

python -m app.main --source file

📦 Output

After execution, reports are generated in:

outputs/

Artifacts generated:

JSON report (machine-readable)
HTML report (human-friendly, shareable)

🧩 Use Cases
SOC triage automation for SMBs
Security monitoring enhancement
AI-assisted incident response
Alert prioritization layer for SIEM tools
Security consulting and reporting

🔐 Why This Matters

Traditional SIEM systems:

rely on static rules
produce high false positives
lack contextual reasoning

This system:

applies structured reasoning
detects patterns across events
prioritizes threats effectively
produces actionable intelligence

🔄 Future Enhancements
MITRE ATT&CK Mapping
Map detections to adversary tactics and techniques.
Multi-Agent Orchestration
Introduce specialized agents for detection, enrichment, and response.
Real SIEM Integration
Connect to Splunk, ELK, and Wazuh APIs.
AI Red Team Simulation
Model attack paths and adversarial behavior.
Dashboard and Visualization
Provide real-time trends, severity distribution, and top attack types.
Workflow Automation
Add ticketing, alerting, and response pipelines with human approval.
Executive and Client Reporting
Export polished HTML and PDF reports for internal and external stakeholders.

🤝 Let's Connect

Open to:

AI Security roles
Cybersecurity Analyst positions
Security automation consulting
⭐ Support

If you find this useful:

Star the repo
Share feedback
Contribute ideas

