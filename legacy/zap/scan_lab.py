import json
import time
from datetime import datetime
from getpass import getpass
from pathlib import Path
from urllib.parse import urlsplit

import requests


ZAP_URL = "http://127.0.0.1:8080"
TARGET_URL = "http://127.0.0.1:5001/"


def validate_target(value):
    value = value.strip()

    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError:
        raise ValueError("Invalid target URL.")

    if parsed.scheme not in ("http", "https"):
        raise ValueError("The URL must start with http:// or https://")

    if parsed.hostname not in ("127.0.0.1", "localhost", "::1"):
        raise ValueError("This version accepts local lab URLs only.")

    if parsed.username is not None or parsed.password is not None:
        raise ValueError("Do not include credentials in the URL.")

    if parsed.query or parsed.fragment:
        raise ValueError("Enter the lab root URL without query or fragment.")

    if parsed.path not in ("", "/"):
        raise ValueError("Enter the lab root URL, for example port 5001.")

    effective_port = port if port is not None else (
        443 if parsed.scheme == "https" else 80
    )

    if effective_port == 0:
        raise ValueError("Port 0 is not a valid lab port.")

    if effective_port == urlsplit(ZAP_URL).port:
        raise ValueError("The target must be the lab, not the ZAP API.")

    host = parsed.hostname
    if host == "::1":
        host = "[::1]"

    port_text = f":{port}" if port is not None else ""
    return f"{parsed.scheme}://{host}{port_text}/"


def run_scan(api_key, target_url=TARGET_URL, on_message=print):
    target_url = validate_target(target_url)
    api_key = api_key.strip()

    if not api_key:
        raise ValueError("Enter the ZAP API key.")

    # A separate session is created for each run.
    with requests.Session() as session:
        session.trust_env = False

        def zap_api(component, operation, name, **params):
            response = session.get(
                f"{ZAP_URL}/JSON/{component}/{operation}/{name}/",
                params=params,
                headers={"X-ZAP-API-Key": api_key},
                timeout=30,
            )
            response.raise_for_status()
            data = response.json()

            if "code" in data:
                raise RuntimeError(f"ZAP API error: {data}")

            return data

        def wait_for_scan(component, scan_id, timeout_seconds=600):
            deadline = time.monotonic() + timeout_seconds
            previous = None

            while time.monotonic() < deadline:
                progress = int(
                    zap_api(
                        component, "view", "status", scanId=scan_id
                    )["status"]
                )

                if progress != previous:
                    on_message(f"{component}: {progress}%")
                    previous = progress

                if progress >= 100:
                    return

                time.sleep(2)

            zap_api(component, "action", "stop", scanId=scan_id)
            raise TimeoutError(f"{component} timed out and was stopped.")

        on_message(f"Target: {target_url}")

        # No API key is sent to the lab.
        response = session.get(
            target_url, timeout=10, allow_redirects=False
        )
        response.raise_for_status()

        if 300 <= response.status_code < 400:
            raise ValueError(
                "The lab root redirects. Enter its direct local URL."
            )

        version = zap_api("core", "view", "version")["version"]
        on_message(f"Connected to ZAP {version}")

        spider_id = zap_api(
            "spider",
            "action",
            "scan",
            url=target_url,
            recurse="true",
        )["scan"]

        on_message(f"Spider ID: {spider_id}")
        wait_for_scan("spider", spider_id)

        scan_id = zap_api(
            "ascan",
            "action",
            "scan",
            url=target_url,
            recurse="true",
        )["scan"]

        on_message(f"Active scan ID: {scan_id}")
        wait_for_scan("ascan", scan_id)

        on_message("Waiting for passive analysis...")
        deadline = time.monotonic() + 120

        while True:
            remaining = int(
                zap_api("pscan", "view", "recordsToScan")["recordsToScan"]
            )

            if remaining == 0:
                break

            if time.monotonic() >= deadline:
                raise TimeoutError("Passive analysis did not finish in time.")

            time.sleep(2)

        alerts = []
        start = 0

        while True:
            batch = zap_api(
                "core",
                "view",
                "alerts",
                baseurl=target_url,
                start=start,
                count=100,
            )["alerts"]

            alerts.extend(batch)

            if len(batch) < 100:
                break

            start += len(batch)

        report_dir = Path(__file__).parent / "Report"
        report_dir.mkdir(exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S-%f")
        report_path = report_dir / f"api-lab-{timestamp}.json"

        report = {
            "target": target_url,
            "zap_version": version,
            "spider_id": spider_id,
            "active_scan_id": scan_id,
            "alerts_scope": "target alerts in current ZAP session",
            "alerts": alerts,
        }

        report_path.write_text(
            json.dumps(report, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

        on_message(f"\nAlert records: {len(alerts)}")

        for alert in alerts:
            on_message(f"[{alert['risk']}] {alert['alert']}")
            on_message(f"  URL: {alert['url']}")

        on_message(f"\nReport saved: {report_path}")
        return report, report_path


def main():
    target = input(f"Lab URL [{TARGET_URL}]: ").strip() or TARGET_URL
    api_key = getpass("ZAP API key: ").strip()
    run_scan(api_key, target_url=target)


if __name__ == "__main__":
    main()