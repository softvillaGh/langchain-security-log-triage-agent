
from collections import Counter

def analyze_logs(logs):
    results = []
    ip_counter = Counter()

    # Count suspicious events by IP
    for log in logs:
        event = log.get("event", "").lower()
        ip = log.get("ip", "unknown")

        if (
            "failed login" in event
            or "multiple failed login attempts" in event
            or "suspicious access" in event
            or "/admin" in event
            or "unauthorized" in event
            or "brute force" in event
        ):
            ip_counter[ip] += 1

    # Classify each event
    for log in logs:
        event = log.get("event", "")
        event_lower = event.lower()
        ip = log.get("ip", "unknown")
        source = log.get("source", "unknown")
        timestamp = log.get("timestamp", "unknown")

        severity = "Low"
        recommendation = "No action needed"
        attack_type = "Informational"

        if "failed login" in event_lower or "multiple failed login attempts" in event_lower:
            severity = "High"
            recommendation = "Investigate immediately and consider blocking the source IP"
            attack_type = "Authentication Attack"

        if "suspicious access" in event_lower or "/admin" in event_lower:
            severity = "High"
            recommendation = "Investigate immediately, review web access logs, and restrict unauthorized access"
            attack_type = "Suspicious Web Access"

        if "unauthorized" in event_lower or "privilege escalation" in event_lower:
            severity = "High"
            recommendation = "Review account permissions and investigate for unauthorized privilege changes"
            attack_type = "Privilege Abuse"

        if ip_counter[ip] >= 2 and severity in ["High", "Medium"]:
            severity = "Critical"
            recommendation = (
                "Potential brute force or repeated malicious activity detected. "
                "Block the IP, review related logs, and investigate immediately."
            )
            attack_type = "Brute Force / Repeated Malicious Activity"

        result = {
            "timestamp": timestamp,
            "source": source,
            "incident": event,
            "severity": severity,
            "ip": ip,
            "attack_type": attack_type,
            "event_count_for_ip": ip_counter[ip],
            "recommendation": recommendation
        }

        results.append(result)

    return results
