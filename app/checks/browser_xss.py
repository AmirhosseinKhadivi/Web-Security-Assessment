import html
import json
import secrets

from urllib.parse import urlsplit

from playwright.sync_api import (
    Error as PlaywrightError,
    sync_playwright,
)
from app.engine.request_planner import replace_parameter

LAB_URL = "http://127.0.0.1:5001"
ALLOWED_PATHS = {"/unsafe", "/safe"}

# Use "chrome" or "msedge" for an installed browser.
# Use None for the Chromium browser installed by Playwright.
BROWSER_CHANNEL = "chrome"


def is_allowed_url(url):
    try:
        parsed = urlsplit(url)

        return (
            parsed.scheme == "http"
            and parsed.hostname == "127.0.0.1"
            and parsed.port == 5001
            and parsed.path in ALLOWED_PATHS
            and parsed.username is None
            and parsed.password is None
        )
    except ValueError:
        return False


def restrict_request(route):
    request = route.request

    if (
        request.method == "GET"
        and request.resource_type == "document"
        and is_allowed_url(request.url)
        and request.redirected_from is None
    ):
        route.continue_()
    else:
        route.abort()


def open_candidate_page(page, candidate, value):
    url = replace_parameter(candidate, value)

    if not is_allowed_url(url):
        raise ValueError("Unsupported lab candidate.")

    response = page.goto(
        url,
        wait_until="domcontentloaded",
        timeout=15000,
    )

    if response is None:
        raise RuntimeError("No document response was received.")

    if response.status != 200:
        raise RuntimeError(
            f"The lab returned HTTP {response.status}."
        )

    if not is_allowed_url(page.url):
        raise RuntimeError("The page left the allowed lab scope.")

    expected_path = urlsplit(candidate["original_url"]).path

    if urlsplit(page.url).path != expected_path:
        raise RuntimeError("The page changed to an unexpected route.")

    content_type = response.headers.get("content-type", "").lower()

    if "text/html" not in content_type:
        raise RuntimeError("The lab did not return HTML.")

    return response


def make_lab_candidate(path):
    if path not in ALLOWED_PATHS:
        raise ValueError("Unsupported lab route.")

    return {
        "candidate_id": f"manual-{path.strip('/')}",
        "source_input_ids": [],
        "method": "GET",
        "original_url": f"{LAB_URL}{path}?name=Alice",
        "endpoint": f"{LAB_URL}{path}",
        "parameter": "name",
        "query_position": 0,
        "query_pairs": [["name", "Alice"]],
    }

def read_marker(page, marker_key, marker_value):
    # Read the property without creating or changing it.
    return page.evaluate(
        """
        ({key, value}) => (
            Object.prototype.hasOwnProperty.call(window, key)
            && window[key] === value
        )
        """,
        {
            "key": marker_key,
            "value": marker_value,
        },
    )


def evidence_excerpt(source, marker):
    position = source.find(marker)

    if position < 0:
        return "The marker was not found in the response source."

    start = max(0, position - 100)
    end = min(len(source), position + len(marker) + 180)

    return source[start:end]


def inspect_candidate(browser, candidate):
    if candidate.get("method") != "GET":
        raise ValueError("Only GET candidates are supported.")

    if candidate.get("parameter") != "name":
        raise ValueError("Unsupported XSS parameter.")

    original_url = candidate.get("original_url", "")

    if not is_allowed_url(original_url):
        raise ValueError("Unsupported lab candidate.")

    path = urlsplit(original_url).path

    marker_key = f"__lab_probe_{secrets.token_hex(12)}"
    marker_value = secrets.token_hex(16)

    payload = (
        "<script>"
        f"window[{json.dumps(marker_key)}]"
        f"={json.dumps(marker_value)};"
        "</script>"
    )

    context = browser.new_context(
        service_workers="block",
        accept_downloads=False,
    )

    try:
        context.route("**/*", restrict_request)

        page = context.new_page()
        page.on("dialog", lambda dialog: dialog.dismiss())

        baseline_response = open_candidate_page(
            page,
            candidate,
            marker_value,
        )

        if marker_value not in baseline_response.text():
            raise RuntimeError(
                "The baseline marker was not reflected."
            )

        if read_marker(page, marker_key, marker_value):
            raise RuntimeError(
                "The execution marker existed before the probe."
            )

        response = open_candidate_page(
            page,
            candidate,
            payload,
        )

        source = response.text()

        executed = read_marker(page, marker_key, marker_value)
        raw_reflected = payload in source

        decoded_source = html.unescape(source)

        encoded_reflected = (
            not raw_reflected
            and payload in decoded_source
        )

        visible_text = page.locator("body").inner_text(timeout=5000)
        probe_as_text = payload in visible_text

        if executed and raw_reflected:
            classification = "REFLECTED_XSS_CONFIRMED"

        elif executed:
            classification = "EXECUTION_OBSERVED_REQUIRES_REVIEW"

        elif encoded_reflected and probe_as_text:
            classification = "ESCAPED_PROBE_NO_EXECUTION"

        elif raw_reflected:
            classification = "RAW_SCRIPT_REFLECTED_NO_EXECUTION"

        else:
            classification = "PROBE_REQUIRES_REVIEW"

        return {
            "candidate_id": candidate.get("candidate_id", ""),
            "source_input_ids": candidate.get("source_input_ids", []),
            "path": path,
            "parameter": candidate["parameter"],
            "classification": classification,
            "marker_executed": executed,
            "raw_payload_reflected": raw_reflected,
            "encoded_payload_reflected": encoded_reflected,
            "probe_visible_as_text": probe_as_text,
            "evidence": evidence_excerpt(source, marker_key),
        }

    finally:
        context.close()


def inspect_route(browser, path):
    candidate = make_lab_candidate(path)
    return inspect_candidate(browser, candidate)

def main():
    expected = {
        "/unsafe": "REFLECTED_XSS_CONFIRMED",
        "/safe": "ESCAPED_PROBE_NO_EXECUTION",
    }

    print("Local browser XSS validation")
    print(f"Target: {LAB_URL}")
    print(f"Browser channel: {BROWSER_CHANNEL or 'bundled Chromium'}")
    print("The probe only sets a temporary window property.")
    print()

    passed = 0

    with sync_playwright() as playwright:
        options = {"headless": True}

        if BROWSER_CHANNEL:
            options["channel"] = BROWSER_CHANNEL

        browser = playwright.chromium.launch(**options)

        try:
            for path, expected_classification in expected.items():
                try:
                    result = inspect_route(browser, path)

                    print(f"Route: {result['path']}")
                    print(f"Observed: {result['classification']}")
                    print(
                        f"Marker executed: {result['marker_executed']}"
                    )
                    print(
                        "Raw payload reflected: "
                        f"{result['raw_payload_reflected']}"
                    )
                    print(
                        "Encoded payload reflected: "
                        f"{result['encoded_payload_reflected']}"
                    )
                    print(
                        "Probe visible as text: "
                        f"{result['probe_visible_as_text']}"
                    )
                    print(f"Evidence: {result['evidence']}")

                    if result["classification"] == expected_classification:
                        passed += 1
                        print("[PASS] Expected lab behavior confirmed.")
                    else:
                        print("[FAIL] The result needs review.")
                        print(f"Expected: {expected_classification}")

                except (PlaywrightError, RuntimeError, ValueError) as exc:
                    print(f"[ERROR] {path}: {exc}")

                print()

        finally:
            browser.close()

    print(f"Result: {passed}/{len(expected)} browser checks passed.")
    print(
        "A negative result applies only to this payload "
        "and the tested browser conditions."
    )

    if passed != len(expected):
        raise SystemExit(1)


if __name__ == "__main__":
    main()