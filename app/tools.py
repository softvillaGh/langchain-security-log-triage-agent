from langchain_core.tools import tool
import json


@tool
def detect_iocs(log_text: str) -> str:
    """Detect simple security indicators from log text and return them as JSON."""
    text = log_text.lower()
    findings = []

    if "failed password" in text:
        findings.append({
            "label": "brute_force_attempt",
            "evidence": "failed password"
        })

    if "/admin" in text:
        findings.append({
            "label": "admin_panel_probing",
            "evidence": "/admin"
        })

    if "curl" in text:
        findings.append({
            "label": "suspicious_download_activity",
            "evidence": "curl"
        })

    return json.dumps(findings)


@tool
def map_tactics(indicators_json: str) -> str:
    """Map detected indicators to high-level MITRE-style tactics and return them as JSON."""
    import json

    indicators = json.loads(indicators_json)

    mapping = {
        "brute_force_attempt": "Credential Access",
        "admin_panel_probing": "Initial Access",
        "suspicious_download_activity": "Execution",
        "Brute force attempt": "Credential Access",
        "Admin panel probing": "Initial Access",
        "Suspicious download activity": "Execution",
    }

    tactics = []

    for item in indicators:
        if isinstance(item, dict):
            label = item.get("label", "unknown")
        elif isinstance(item, str):
            label = item
        else:
            label = "unknown"

        tactic = mapping.get(label, "Unknown")
        if tactic not in tactics:
            tactics.append(tactic)

    return json.dumps(tactics)
