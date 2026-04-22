import json
from datetime import datetime
from pathlib import Path


OUTPUT_DIR = Path("data/outputs")
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)


def _timestamp() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def save_json_report(report: dict) -> Path:
    filename = OUTPUT_DIR / f"incident_{_timestamp()}.json"
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    return filename


def save_markdown_report(report: dict) -> Path:
    filename = OUTPUT_DIR / f"incident_{_timestamp()}.md"

    md = f"""# Incident Report

**Verdict:** {report.get('verdict', 'N/A')}
**Severity:** {report.get('severity', 'N/A')}
**Confidence:** {report.get('confidence', 'N/A')}

## Summary
{report.get('summary', 'N/A')}

## Indicators
"""
    indicators = report.get("indicators", [])
    if indicators:
        for item in indicators:
            md += f"- {item}\n"
    else:
        md += "- None\n"

    md += "\n## Tactics\n"
    tactics = report.get("tactics", [])
    if tactics:
        for item in tactics:
            md += f"- {item}\n"
    else:
        md += "- None\n"

    md += "\n## Recommended Actions\n"
    actions = report.get("recommended_actions", [])
    if actions:
        for item in actions:
            md += f"- {item}\n"
    else:
        md += "- None\n"

    with open(filename, "w", encoding="utf-8") as f:
        f.write(md)

    return filename
