import json

from app.agent import build_agent
from app.tools import detect_iocs, map_tactics
from app.reporting import save_json_report, save_markdown_report


def main():
    log = input("Enter log: ")

    # Run tools first so facts are deterministic
    indicators_json = detect_iocs.invoke({"log_text": log})
    tactics_json = map_tactics.invoke({"indicators_json": indicators_json})

    indicators = json.loads(indicators_json)
    tactics = json.loads(tactics_json)

    # Normalize indicator labels for the report
    normalized_indicators = []
    for item in indicators:
        if isinstance(item, dict):
            normalized_indicators.append(item.get("label", "unknown"))
        elif isinstance(item, str):
            normalized_indicators.append(item)

    agent = build_agent()

    result = agent.invoke(
        {
            "messages": [
                {
                    "role": "user",
                    "content": (
                        f"Analyze this log: {log}\n\n"
                        f"Detected indicators (use exactly these): {json.dumps(normalized_indicators)}\n"
                        f"Mapped tactics (use exactly these): {json.dumps(tactics)}\n\n"
                        "Return a structured incident report. "
                        "Use the exact indicators and exact tactics provided above. "
                        "Do not change them, do not invent new ones, and do not put verdict values inside tactics."
                    ),
                }
            ]
        }
    )

    structured = result.get("structured_response")
    if structured is None:
        print("No structured response returned.")
        print(result)
        return

    report = structured.model_dump()

    # Final safety override to keep report consistent
    report["indicators"] = normalized_indicators
    report["tactics"] = tactics

    print("\n=== INCIDENT REPORT ===")
    print(json.dumps(report, indent=2))

    json_path = save_json_report(report)
    md_path = save_markdown_report(report)

    print(f"\nSaved JSON report to: {json_path}")
    print(f"Saved Markdown report to: {md_path}")


if __name__ == "__main__":
    main()
