import argparse
from datetime import datetime

from app.connectors.file_connector import load_logs
from app.connectors.splunk_connector import fetch_splunk_logs
from app.agent.triage_agent import analyze_logs
from app.output.report_generator import save_report, build_summary


def print_report(results):
    summary = build_summary(results)

    print("=" * 60)
    print("SECURITY TRIAGE REPORT")
    print("=" * 60)
    print(f"Headline: {summary['headline']}")
    print(f"Total Events: {summary['total_events']}")
    print(f"Critical: {summary['critical_events']} | High: {summary['high_events']} | Low: {summary['low_events']}")
    print(f"Unique IPs: {summary['unique_ips']}")
    print(f"Top Attack Types: {summary['top_attack_types']}")
    print()

    for i, r in enumerate(results, start=1):
        print(f"[{i}] Incident: {r['incident']}")
        print(f"    Time: {r['timestamp']}")
        print(f"    Source: {r['source']}")
        print(f"    IP: {r['ip']}")
        print(f"    Severity: {r['severity']}")
        print(f"    Attack Type: {r['attack_type']}")
        print(f"    Events from IP: {r['event_count_for_ip']}")
        print(f"    Recommendation: {r['recommendation']}")
        print()


def get_logs(source):
    if source == "file":
        return load_logs("data/sample_logs.json")
    if source == "splunk":
        return fetch_splunk_logs()
    raise ValueError("Invalid log source. Use 'file' or 'splunk'.")


def main():
    parser = argparse.ArgumentParser(description="AI Security Log Triage Agent")
    parser.add_argument(
        "--source",
        choices=["file", "splunk"],
        default="splunk",
        help="Choose the log source"
    )

    args = parser.parse_args()

    logs = get_logs(args.source)
    results = analyze_logs(logs)

    print_report(results)

    timestamp = datetime.now().strftime("%Y-%m-%d_%H%M%S")
    output_file = f"outputs/{args.source}_report_{timestamp}.json"

    save_report(results, output_file=output_file)

    html_file = output_file.replace(".json", ".html")

    print(f"Saved JSON report to {output_file}")
    print(f"Saved HTML report to {html_file}")


if __name__ == "__main__":
    main()
