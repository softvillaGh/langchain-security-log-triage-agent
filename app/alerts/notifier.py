import json
from pathlib import Path

def build_alert_messages(results):
    alerts = []

    for r in results:
        if r["severity"] in ["Critical", "High"]:
            message = {
                "severity": r["severity"],
                "incident": r["incident"],
                "ip": r["ip"],
                "attack_type": r["attack_type"],
                "mitre_tactic": r.get("mitre_tactic", "Unknown"),
                "mitre_technique": r.get("mitre_technique_id", "Unknown"),
                "recommendation": r["recommendation"]
            }
            alerts.append(message)

    return alerts


def save_alerts(results, output_file="outputs/alerts.json"):
    Path("outputs").mkdir(exist_ok=True)

    alerts = build_alert_messages(results)

    with open(output_file, "w") as f:
        json.dump(alerts, f, indent=4)

    return alerts


def print_alerts(alerts):
    if not alerts:
        print("No High/Critical alerts generated.")
        return

    print("=" * 60)
    print("ALERTS")
    print("=" * 60)

    for i, alert in enumerate(alerts, start=1):
        print(f"[{i}] {alert['severity']} - {alert['incident']}")
        print(f"    IP: {alert['ip']}")
        print(f"    Attack Type: {alert['attack_type']}")
        print(f"    MITRE: {alert['mitre_technique']} ({alert['mitre_tactic']})")
        print(f"    Recommendation: {alert['recommendation']}")
        print()


def format_slack_payload(alert):
    return {
        "text": (
            f"[{alert['severity']}] {alert['incident']} | "
            f"IP: {alert['ip']} | "
            f"Attack: {alert['attack_type']} | "
            f"MITRE: {alert['mitre_technique']} ({alert['mitre_tactic']})"
        )
    }


def format_email_message(alert):
    subject = f"{alert['severity']} Security Alert - {alert['incident']}"
    body = (
        f"Incident: {alert['incident']}\n"
        f"IP: {alert['ip']}\n"
        f"Attack Type: {alert['attack_type']}\n"
        f"MITRE: {alert['mitre_technique']} ({alert['mitre_tactic']})\n"
        f"Recommendation: {alert['recommendation']}\n"
    )
    return {"subject": subject, "body": body}
