import html
import secrets
import time

import requests

from app.engine.crawler import (
    check_destination,
    get_origin,
    normalize_url,
)
from app.engine.request_planner import replace_parameter


MAX_CANDIDATES = 8
MAX_RESPONSE_BYTES = 1_000_000
MAX_STAGE_SECONDS = 90


def fetch_html(session, url, scope, deadline, metrics):
    url = normalize_url(url)

    if get_origin(url) != scope:
        raise ValueError("The request is outside the scan origin.")

    if time.monotonic() >= deadline:
        raise TimeoutError("The reflection stage time budget was reached.")

    check_destination(url)
    metrics["requests_attempted"] += 1

    with session.get(
        url,
        timeout=(5, 10),
        allow_redirects=False,
        stream=True,
    ) as response:
        status = response.status_code
        content_type = response.headers.get("Content-Type", "").lower()

        if status != 200 or "text/html" not in content_type:
            return {
                "url": response.url,
                "status_code": status,
                "content_type": content_type,
                "body": "",
            }

        body = bytearray()

        for chunk in response.iter_content(chunk_size=16384):
            body.extend(chunk)

            if len(body) > MAX_RESPONSE_BYTES:
                raise ValueError("The response exceeded the size limit.")

            if time.monotonic() >= deadline:
                raise TimeoutError(
                    "The reflection stage time budget was reached."
                )

        encoding = response.encoding or "utf-8"

        try:
            text = bytes(body).decode(encoding, errors="replace")
        except LookupError:
            text = bytes(body).decode("utf-8", errors="replace")

        return {
            "url": response.url,
            "status_code": status,
            "content_type": content_type,
            "body": text,
        }


def is_html_success(response):
    return (
        response["status_code"] == 200
        and "text/html" in response["content_type"]
    )


def excerpt(source, marker):
    position = source.find(marker)

    if position < 0:
        return "The marker was not observed in the response body."

    return source[
        max(0, position - 100):
        position + len(marker) + 160
    ]


def inspect_candidate(session, candidate, scope, deadline, metrics):
    # A numeric marker can also be accepted by numeric input fields.
    marker = str(secrets.randbelow(900_000_000) + 100_000_000)
    payload = f"<strong>{marker}</strong>"

    result = {
        "candidate_id": candidate["candidate_id"],
        "source_input_ids": candidate["source_input_ids"],
        "url": candidate["original_url"],
        "parameter": candidate["parameter"],
        "classification": "REQUIRES_REVIEW",
        "javascript_execution_tested": False,
        "observations": [],
    }

    def fetch(label, url):
        response = fetch_html(
            session, url, scope, deadline, metrics
        )
        result["observations"].append(
            {
                "label": label,
                "url": response["url"],
                "status_code": response["status_code"],
                "content_type": response["content_type"],
            }
        )
        return response

    baseline = fetch("baseline", candidate["original_url"])

    if not is_html_success(baseline):
        result["classification"] = "BASELINE_NOT_ASSESSABLE"
        return result

    if marker in baseline["body"]:
        result["classification"] = "MARKER_COLLISION"
        return result

    marker_response = fetch(
        "text_marker",
        replace_parameter(candidate, marker),
    )

    if not is_html_success(marker_response):
        result["classification"] = "MARKER_RESPONSE_NOT_ASSESSABLE"
        return result

    if marker not in marker_response["body"]:
        result["classification"] = "NO_REFLECTION_OBSERVED"
        result["evidence"] = (
            "The unique marker was absent from the HTML response. "
            "This result applies only to this request."
        )
        return result

    markup_response = fetch(
        "markup_probe",
        replace_parameter(candidate, payload),
    )

    if not is_html_success(markup_response):
        result["classification"] = "MARKUP_RESPONSE_NOT_ASSESSABLE"
        result["evidence"] = (
            "The text marker was reflected, but the markup probe "
            "did not return an HTTP 200 HTML response."
        )
        return result

    source = markup_response["body"]

    if payload in source:
        result["classification"] = "RAW_MARKUP_REFLECTED"
    elif payload in html.unescape(source):
        result["classification"] = "HTML_ENCODED_MARKUP_REFLECTED"
    elif marker in source:
        result["classification"] = "MARKER_REFLECTED_WITH_TRANSFORMATION"
    else:
        result["classification"] = "MARKUP_NOT_REFLECTED"

    result["evidence"] = excerpt(source, marker)
    return result


def run_reflection_checks(report, on_message=print):
    candidates = report.get("request_plan", {}).get("candidates", [])
    scope = get_origin(report["target"])
    deadline = time.monotonic() + MAX_STAGE_SECONDS
    metrics = {"requests_attempted": 0}
    results = []

    completed = {
        "NO_REFLECTION_OBSERVED",
        "RAW_MARKUP_REFLECTED",
        "HTML_ENCODED_MARKUP_REFLECTED",
        "MARKER_REFLECTED_WITH_TRANSFORMATION",
        "MARKUP_NOT_REFLECTED",
        "BASELINE_NOT_ASSESSABLE",
        "MARKER_RESPONSE_NOT_ASSESSABLE",
        "MARKUP_RESPONSE_NOT_ASSESSABLE",
        "MARKER_COLLISION",
    }

    inconclusive = {
        "BASELINE_NOT_ASSESSABLE",
        "MARKER_RESPONSE_NOT_ASSESSABLE",
        "MARKUP_RESPONSE_NOT_ASSESSABLE",
        "MARKER_COLLISION",
    }

    with requests.Session() as session:
        session.trust_env = False
        session.headers["User-Agent"] = "BachelorSecurityScanner/0.2"

        for index, candidate in enumerate(candidates):
            identity = {
                "candidate_id": candidate["candidate_id"],
                "source_input_ids": candidate["source_input_ids"],
                "url": candidate["original_url"],
                "parameter": candidate["parameter"],
                "javascript_execution_tested": False,
            }

            if index >= MAX_CANDIDATES:
                result = {
                    **identity,
                    "classification": "SKIPPED_CANDIDATE_LIMIT",
                }
            elif time.monotonic() >= deadline:
                result = {
                    **identity,
                    "classification": "SKIPPED_TIME_LIMIT",
                }
            else:
                on_message(
                    f"Reflection check: {candidate['candidate_id']} | "
                    f"parameter={candidate['parameter']}"
                )

                try:
                    result = inspect_candidate(
                        session, candidate, scope, deadline, metrics
                    )
                except (
                    requests.RequestException,
                    ValueError,
                    TimeoutError,
                ) as error:
                    result = {
                        **identity,
                        "classification": "CHECK_ERROR",
                        "error": str(error),
                    }

                time.sleep(0.2)

            classification = result["classification"]
            candidate["reflection_status"] = classification
            results.append(result)

            on_message(
                f"Reflection result: {candidate['candidate_id']} "
                f"-> {classification}")

    completed_count = sum(
        result["classification"] in completed for result in results
    )

    inconclusive_count = sum(
        result["classification"] in inconclusive for result in results
    )

    skipped_count = sum(
        result["classification"].startswith("SKIPPED_")
        or result["classification"] == "CHECK_ERROR"
        for result in results
    )
    report["reflection_checks"] = results
    report["coverage"]["reflection"] = {
        "status": (
            "not_applicable"
            if not candidates
            else (
                "completed"
                if completed_count == len(candidates)
                else "incomplete"
            )
        ),
        "candidate_count": len(candidates),
        "completed_candidates": completed_count,
        "inconclusive_or_skipped": inconclusive_count + skipped_count,
        "requests_attempted": metrics["requests_attempted"],
        "candidate_limit": MAX_CANDIDATES,
        "note": (
            "HTTP response reflection analysis only. Raw markup in a "
            "response is not proof of HTML interpretation or JavaScript "
            "execution. Encoded output is not a general safety guarantee."
        ),
    }

    if completed_count != len(candidates):
        report["assessment_status"] = "incomplete"

    check_label = "Query parameter reflection using text and HTML probes"

    if candidates and check_label not in report["coverage"]["checks"]:
        report["coverage"]["checks"].append(check_label)

    on_message(f"Reflection checks completed: {completed_count}/{len(candidates)}")
    on_message(f"Reflection HTTP requests: {metrics['requests_attempted']}")