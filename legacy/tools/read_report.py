import json
from pathlib import Path

report_path = Path(__file__).parent / "Report" / "2026-09-17-1-ZAP-Report-.json"

with report_path.open(encoding="utf-8-sig") as report_file:
    report = json.load(report_file)

target_site = "http://127.0.0.1:5001"

report["site"] = [
    site
    for site in report["site"]
    if site["@name"].rstrip("/") == target_site
]

if not report["site"]:
    raise ValueError(f"Target site not found in report: {target_site}")
for site in report["site"]:
    print(f"Site: {site['@name']}")

    for alert in site["alerts"]:
        print(f"\nAlert: {alert['alert']}")
        print(f"Risk and confidence: {alert['riskdesc']}")

        for instance in alert["instances"]:
            print(f"  URL: {instance['uri']}")
            evidence = instance["evidence"] or "No evidence text provided"
            print(f"  Evidence: {evidence}")
alert_types = 0
total_instances = 0

for site in report["site"]:
    alert_types += len(site["alerts"])

    for alert in site["alerts"]:
        total_instances += len(alert["instances"])

print("\n--- Summary ---")
print(f"Alert types across sites: {alert_types}")
print(f"Total instances: {total_instances}")

print("\n--- Scan diagnostics ---")

for insight in report.get("insights", []):
    if insight["key"] in (
        "insight.log.warn",
        "insight.network.failure",
    ):
        print(f"{insight['description']}: {insight['statistic']}")