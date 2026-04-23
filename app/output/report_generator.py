import json
import os
from collections import Counter

def build_summary(results):
    severity_counter = Counter(r["severity"] for r in results)
    attack_counter = Counter(r["attack_type"] for r in results)
    critical_ips = sorted({r["ip"] for r in results if r["severity"] == "Critical"})

    if critical_ips:
        headline = f"Critical malicious activity detected from {', '.join(critical_ips)}."
    elif severity_counter.get("High", 0) > 0:
        headline = "High-severity suspicious activity detected and should be reviewed immediately."
    else:
        headline = "No critical activity detected in this batch."

    return {
        "headline": headline,
        "total_events": len(results),
        "critical_events": severity_counter.get("Critical", 0),
        "high_events": severity_counter.get("High", 0),
        "low_events": severity_counter.get("Low", 0),
        "unique_ips": len(set(r["ip"] for r in results)),
        "top_attack_types": dict(attack_counter.most_common(3))
    }


def save_report(results, output_file="outputs/report.json"):
    os.makedirs(os.path.dirname(output_file), exist_ok=True)

    summary = build_summary(results)

    report = {
        "summary": summary,
        "events": results
    }

    with open(output_file, "w") as f:
        json.dump(report, f, indent=4)

    html_output = output_file.replace(".json", ".html")
    save_html_report(report, html_output)


def save_html_report(report, output_file):
    summary = report["summary"]
    events = report["events"]

    attack_types_html = ""
    for attack_type, count in summary["top_attack_types"].items():
        attack_types_html += f"<li>{attack_type}: {count}</li>"

    html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Triage Report</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            margin: 30px;
            background: #f4f7fb;
            color: #222;
        }}
        h1 {{
            color: #1f4e79;
        }}
        .headline {{
            background: #eaf2fb;
            border-left: 6px solid #1f4e79;
            padding: 15px 18px;
            margin-bottom: 25px;
            border-radius: 8px;
            font-size: 18px;
            font-weight: bold;
        }}
        .summary {{
            display: flex;
            gap: 15px;
            flex-wrap: wrap;
            margin-bottom: 30px;
        }}
        .card {{
            background: white;
            padding: 15px 20px;
            border-radius: 10px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.08);
            min-width: 180px;
        }}
        .card h3 {{
            margin: 0 0 8px 0;
            font-size: 16px;
            color: #1f4e79;
        }}
        .top-attacks {{
            background: white;
            padding: 15px 20px;
            border-radius: 10px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.08);
            margin-bottom: 25px;
        }}
        .event {{
            background: white;
            padding: 18px;
            border-radius: 10px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.08);
            margin-bottom: 18px;
        }}
        .critical {{
            border-left: 6px solid #c0392b;
        }}
        .high {{
            border-left: 6px solid #e67e22;
        }}
        .low {{
            border-left: 6px solid #27ae60;
        }}
        .label {{
            font-weight: bold;
            color: #1f4e79;
        }}
    </style>
</head>
<body>
    <h1>Security Triage Report</h1>

    <div class="headline">{summary['headline']}</div>

    <div class="summary">
        <div class="card">
            <h3>Total Events</h3>
            <p>{summary['total_events']}</p>
        </div>
        <div class="card">
            <h3>Critical Events</h3>
            <p>{summary['critical_events']}</p>
        </div>
        <div class="card">
            <h3>High Events</h3>
            <p>{summary['high_events']}</p>
        </div>
        <div class="card">
            <h3>Low Events</h3>
            <p>{summary['low_events']}</p>
        </div>
        <div class="card">
            <h3>Unique IPs</h3>
            <p>{summary['unique_ips']}</p>
        </div>
    </div>

    <div class="top-attacks">
        <h3>Top Attack Types</h3>
        <ul>
            {attack_types_html}
        </ul>
    </div>
"""

    for event in events:
        severity_class = event["severity"].lower() if event["severity"].lower() in ["critical", "high", "low"] else "low"
        html += f"""
    <div class="event {severity_class}">
        <p><span class="label">Incident:</span> {event['incident']}</p>
        <p><span class="label">Timestamp:</span> {event['timestamp']}</p>
        <p><span class="label">Source:</span> {event['source']}</p>
        <p><span class="label">IP:</span> {event['ip']}</p>
        <p><span class="label">Severity:</span> {event['severity']}</p>
        <p><span class="label">Attack Type:</span> {event['attack_type']}</p>
        <p><span class="label">Events from IP:</span> {event['event_count_for_ip']}</p>
        <p><span class="label">Recommendation:</span> {event['recommendation']}</p>
    </div>
"""

    html += """
</body>
</html>
"""

    with open(output_file, "w") as f:
        f.write(html)
