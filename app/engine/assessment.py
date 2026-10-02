import json
from urllib.parse import parse_qs, urlsplit

from app.checks.reflection import run_reflection_checks
import requests

from app.engine.request_planner import run_scan as run_header_scan
LAB_ORIGIN = ("http", "127.0.0.1", 5001)

XSS_PATHS = {"/unsafe", "/safe"}
SQLI_PATHS = {"/sqli-unsafe", "/sqli-safe"}
CORS_PATHS = {
    "/cors-unsafe",
    "/cors-safe",
}
REDIRECT_PATHS = {
    "/redirect-unsafe",
    "/redirect-safe",
}
CORS_COMPLETED = {
    "CORS_ARBITRARY_ORIGIN_WITH_CREDENTIALS",
    "CORS_EXTERNAL_ORIGIN_BLOCKED",
}
XSS_COMPLETED = {
    "REFLECTED_XSS_CONFIRMED",
    "ESCAPED_PROBE_NO_EXECUTION",
    "RAW_SCRIPT_REFLECTED_NO_EXECUTION",
}

SQLI_COMPLETED = {
    "BOOLEAN_SQLI_BEHAVIOR_OBSERVED",
    "NO_BOOLEAN_SQLI_BEHAVIOR_OBSERVED",
}
REDIRECT_COMPLETED = {
    "OPEN_REDIRECT_CONFIRMED",
    "EXTERNAL_REDIRECT_BLOCKED",
}


def add_open_redirect_finding(report, result):
    report["alerts"].append(
        {
            "rule_id": "OPEN-REDIRECT-LAB",
            "alert": "Open Redirect Confirmed",
            "risk": "Medium",
            "confidence": "High",
            "category": "Open Redirect",
            "url": result["url"],
            "method": "GET",
            "param": result["parameter"],
            "evidence": (
                f"Probe destination: {result['probe_url']}\n"
                f"Location header: {result['location']}"
            ),
            "description": (
                "The application accepted an externally controlled "
                "destination and returned it in the redirect Location "
                "header."
            ),
            "solution": (
                "Allow only trusted internal redirect destinations or "
                "validate destinations against an explicit allowlist."
            ),
            "verification": {
                "classification": result["classification"],
                "status_code": result["status_code"],
                "location": result["location"],
                "resolved_location": result["resolved_location"],
            },
        }
    )


def add_cors_finding(report, result):
    credentials_allowed = (
        result["allow_credentials"] == "true"
    )

    report["alerts"].append(
        {
            "rule_id": "CORS-ARBITRARY-ORIGIN",
            "alert": "Arbitrary CORS Origin Allowed",
            "risk": "Medium",
            "confidence": "High",
            "category": "CORS Misconfiguration",
            "url": result["url"],
            "method": "GET",
            "param": "",
            "evidence": (
                f"Probe Origin: {result['probe_origin']}\n"
                f"Access-Control-Allow-Origin: "
                f"{result['allow_origin']}\n"
                f"Access-Control-Allow-Credentials: "
                f"{result['allow_credentials'] or '(missing)'}"
            ),
            "description": (
                "The application accepted an untrusted Origin in its "
                "CORS response. If sensitive responses are accessible, "
                "this may allow cross-origin access from an attacker-"
                "controlled website."
            ),
            "solution": (
                "Use an explicit allowlist of trusted origins. Do not "
                "reflect arbitrary Origin values, especially when "
                "credentialed cross-origin requests are allowed."
            ),
            "verification": {
                "classification": result["classification"],
                "status_code": result["status_code"],
                "probe_origin": result["probe_origin"],
                "allow_origin": result["allow_origin"],
                "allow_credentials": result[
                    "allow_credentials"
                ],
            },
        }
    )


def is_supported_lab(url):
    try:
        parsed = urlsplit(url)
        return (
            (parsed.scheme, parsed.hostname, parsed.port) == LAB_ORIGIN
            and parsed.username is None
            and parsed.password is None
        )
    except ValueError:
        return False


def find_candidates(report, allowed_paths, parameter):
    candidates = {}

    for page in report.get("pages", []):
        url = page.get("url", "")

        if not is_supported_lab(url):
            continue

        parsed = urlsplit(url)

        if parsed.path not in allowed_paths:
            continue

        if page.get("status_code") != 200:
            continue

        parameters = parse_qs(parsed.query, keep_blank_values=True)

        if parameter not in parameters:
            continue

        candidates.setdefault(parsed.path, url)

    return candidates


def find_route_candidates(report, allowed_paths):
    candidates = {}

    for page in report.get("pages", []):
        url = page.get("url", "")

        if not is_supported_lab(url):
            continue

        try:
            parsed = urlsplit(url)
        except ValueError:
            continue

        if parsed.path not in allowed_paths:
            continue

        if page.get("status_code") != 200:
            continue

        candidates.setdefault(parsed.path, url)

    return candidates


def find_redirect_candidates(
    report,
    allowed_paths,
    parameter,
):
    candidates = []

    for page in report.get("pages", []):
        url = page.get("url", "")

        if not is_supported_lab(url):
            continue

        try:
            parsed = urlsplit(url)
        except ValueError:
            continue

        if parsed.path not in allowed_paths:
            continue

        status_code = page.get("status_code")

        if not isinstance(status_code, int):
            continue

        if not 300 <= status_code < 400:
            continue

        parameters = parse_qs(
            parsed.query,
            keep_blank_values=True,
        )

        if parameter not in parameters:
            continue

        candidates.append(
            {
                "candidate_id": (
                    f"redirect-candidate-{len(candidates) + 1:04d}"
                ),
                "source_input_ids": [],
                "method": "GET",
                "original_url": url,
                "parameter": parameter,
            }
        )

    return candidates


def find_planned_candidates(report, allowed_paths, parameter):
    candidates = []

    for candidate in report.get("request_plan", {}).get("candidates", []):
        if candidate.get("method") != "GET":
            continue

        if candidate.get("parameter") != parameter:
            continue

        original_url = candidate.get("original_url", "")

        if not is_supported_lab(original_url):
            continue

        try:
            path = urlsplit(original_url).path
        except ValueError:
            continue

        if path not in allowed_paths:
            continue

        candidates.append(candidate)

    return candidates


def record_error(report, stage, url, error):
    report.setdefault("errors", []).append(
        {
            "stage": stage,
            "url": url,
            "error": str(error),
        }
    )
    report["assessment_status"] = "incomplete"


def update_test_coverage(report, original_label, check, limitation):
    coverage = report["coverage"]

    checks = coverage.setdefault("checks", [])
    if check not in checks:
        checks.append(check)

    not_tested = coverage.setdefault("not_tested", [])
    coverage["not_tested"] = [
        item for item in not_tested if item != original_label
    ]

    if limitation not in coverage["not_tested"]:
        coverage["not_tested"].append(limitation)


def create_stage_metadata(candidates, parameter):
    return {
        "status": "running",
        "parameter": parameter,
        "candidate_routes": len(candidates),
        "completed_routes": 0,
        "confirmed_findings": 0,
        "scope": "Discovered local lab routes only",
    }


def add_xss_finding(report, result):
    report["alerts"].append(
        {
            "rule_id": "XSS-REFLECTED-BROWSER",
            "alert": "Reflected XSS Confirmed in Chrome",
            "risk": "High",
            "confidence": "High",
            "category": "Cross-Site Scripting",
            "url": result["url"],
            "method": "GET",
            "param": "name",
            "evidence": (
                "A unique JavaScript marker executed after the input "
                "was reflected in the response.\nResponse excerpt: "
                + result["evidence"]
            ),
            "description": (
                "Chrome observed the unique window property created "
                "by the reflected script. The baseline did not contain "
                "that property."
            ),
            "solution": (
                "Apply output encoding appropriate to the output context. "
                "Use template autoescaping and avoid inserting untrusted "
                "input directly into HTML. Add an appropriate CSP as an "
                "additional defense."
            ),
            "verification": {
                "browser": "chrome",
                "classification": result["classification"],
                "marker_executed": result["marker_executed"],
                "raw_payload_reflected": result["raw_payload_reflected"],
            },
        }
    )


def add_sqli_finding(report, result):
    evidence = []

    for label, observation in result["observations"].items():
        evidence.append(
            f"{label}: input={observation['input']!r}, "
            f"count={observation['count']}, "
            f"product_ids={observation['product_ids']}"
        )

    report["alerts"].append(
        {
            "rule_id": "SQLI-BOOLEAN-LAB",
            "alert": "Boolean SQL Injection Behavior Observed",
            "risk": "High",
            "confidence": "Medium",
            "category": "SQL Injection",
            "url": result["url"],
            "method": "GET",
            "param": "id",
            "evidence": "\n".join(evidence),
            "description": (
                "The baseline and repeated baseline returned product 1. "
                "A true SQL condition preserved that result, while a false "
                "condition returned no products. This is consistent with "
                "boolean SQL injection in the known local lab. Detection "
                "uses the lab product-row structure and is not a general "
                "SQL injection assessment of arbitrary websites."
            ),
            "solution": (
                "Use parameterized queries so input values remain separate "
                "from SQL syntax. Validate product IDs against the expected "
                "input format and use a database account with only the "
                "permissions required by the application."
            ),
            "verification": {
                "classification": result["classification"],
                "method": "Boolean response comparison with repeated baseline",
                "response_model": "Local lab product IDs and result count",
                "observations": result["observations"],
            },
        }
    )


def run_browser_checks(report, candidates, on_message):
    metadata = create_stage_metadata(candidates, "name")
    metadata["browser"] = "chrome"
    report["coverage"]["browser_xss"] = metadata
    checks = report["xss_checks"]

    try:
        from playwright.sync_api import sync_playwright

        from app.checks.browser_xss import inspect_candidate

        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(
                channel="chrome",
                headless=True,
            )

            try:
                for candidate in candidates:
                    url = candidate["original_url"]
                    path = urlsplit(url).path

                    on_message(
                        f"Browser XSS check: {candidate['candidate_id']} | "
                        f"{path} | parameter={candidate['parameter']}"
                    )

                    try:
                        result = inspect_candidate(browser, candidate)
                        result["url"] = url

                        candidate["active_test_executed"] = True
                        candidate["xss_status"] = result["classification"]

                        checks.append(result)

                        classification = result["classification"]

                        on_message(
                            f"Browser result: {path} -> {classification}"
                        )

                        if classification in XSS_COMPLETED:
                            metadata["completed_routes"] += 1
                        else:
                            record_error(
                                report,
                                "browser_xss",
                                url,
                                f"Result requires review: {classification}",
                            )

                        if classification == "REFLECTED_XSS_CONFIRMED":
                            add_xss_finding(report, result)
                            metadata["confirmed_findings"] += 1

                    except Exception as error:
                        candidate["active_test_executed"] = True
                        candidate["xss_status"] = "CHECK_ERROR"

                        checks.append(
                            {
                                "candidate_id": candidate.get(
                                    "candidate_id", ""
                                ),
                                "source_input_ids": candidate.get(
                                    "source_input_ids", []
                                ),
                                "path": path,
                                "url": url,
                                "parameter": candidate.get(
                                    "parameter", ""
                                ),
                                "classification": "CHECK_ERROR",
                                "error": str(error),
                            }
                        )

                        record_error(
                            report,
                            "browser_xss",
                            url,
                            error,
                        )

                        on_message(
                            f"Browser check error: {path}: {error}"
                        )

            finally:
                browser.close()

    except Exception as error:
        record_error(
            report,
            "browser_xss",
            report["target"],
            error,
        )

        on_message(f"Browser stage error: {error}")

    metadata["status"] = (
        "completed"
        if metadata["completed_routes"] == len(candidates)
        else "incomplete"
    )

    if metadata["completed_routes"]:
        update_test_coverage(
            report,
            "Active XSS",
            "Chrome verification of one inline script probe per completed "
            "local lab route",
            "Other XSS payloads, contexts, routes, and non-lab targets",
        )

    on_message(
        f"Browser checks completed: "
        f"{metadata['completed_routes']}/{len(candidates)}"
    )

    on_message(
        f"Confirmed browser XSS findings: "
        f"{metadata['confirmed_findings']}"
    )


def run_sqli_checks(report, candidates, on_message):
    metadata = create_stage_metadata(candidates, "id")
    metadata.pop("confirmed_findings")
    metadata["behavior_findings"] = 0
    metadata["planned_requests_per_route"] = 4
    metadata["response_model"] = "Local lab product IDs and result count"

    report["coverage"]["sql_injection"] = metadata
    checks = report["sqli_checks"]

    try:
        from app.checks.boolean_sqli import inspect_route

        with requests.Session() as session:
            session.trust_env = False

            for path, url in candidates.items():
                on_message(f"SQL injection check: {path}")

                try:
                    result = inspect_route(session, path)
                    result["url"] = url
                    checks.append(result)

                    classification = result["classification"]
                    on_message(
                        f"SQL injection result: {path} -> {classification}"
                    )

                    if classification in SQLI_COMPLETED:
                        metadata["completed_routes"] += 1
                    else:
                        record_error(
                            report,
                            "sql_injection",
                            url,
                            f"Result requires review: {classification}",
                        )

                    if classification == "BOOLEAN_SQLI_BEHAVIOR_OBSERVED":
                        add_sqli_finding(report, result)
                        metadata["behavior_findings"] += 1

                except Exception as error:
                    checks.append(
                        {
                            "path": path,
                            "url": url,
                            "classification": "CHECK_ERROR",
                            "error": str(error),
                        }
                    )
                    record_error(report, "sql_injection", url, error)
                    on_message(f"SQL injection check error: {path}: {error}")

    except Exception as error:
        record_error(report, "sql_injection", report["target"], error)
        on_message(f"SQL injection stage error: {error}")

    metadata["status"] = (
        "completed"
        if metadata["completed_routes"] == len(candidates)
        else "incomplete"
    )

    if metadata["completed_routes"]:
        update_test_coverage(
            report,
            "SQL injection",
            "Local lab boolean SQL injection probes with repeated baseline",
            "Other SQL injection techniques, parameters, routes, "
            "and non-lab targets",
        )

    on_message(
        f"SQL injection checks completed: "
        f"{metadata['completed_routes']}/{len(candidates)}"
    )
    on_message(
        f"SQL injection behavior findings: "
        f"{metadata['behavior_findings']}"
    )


def mark_stage_skipped(report, key, reason):
    report["coverage"][key] = {
        "status": "skipped",
        "reason": reason,
        "candidate_routes": 0,
        "completed_routes": 0,
    }


def run_open_redirect_checks(report, candidates, on_message):
    metadata = create_stage_metadata(candidates, "next")
    metadata["confirmed_findings"] = 0
    metadata["planned_requests_per_route"] = 1

    report["coverage"]["open_redirect"] = metadata
    checks = report["open_redirect_checks"]

    try:
        from app.checks.open_redirect import inspect_candidate

        with requests.Session() as session:
            session.trust_env = False

            for candidate in candidates:
                url = candidate["original_url"]
                path = urlsplit(url).path

                on_message(
                    f"Open redirect check: "
                    f"{candidate['candidate_id']} | "
                    f"{path} | parameter={candidate['parameter']}"
                )

                try:
                    result = inspect_candidate(
                        session,
                        candidate,
                    )

                    checks.append(result)

                    classification = result["classification"]

                    on_message(
                        f"Open redirect result: "
                        f"{path} -> {classification}"
                    )

                    if classification in REDIRECT_COMPLETED:
                        metadata["completed_routes"] += 1
                    else:
                        record_error(
                            report,
                            "open_redirect",
                            url,
                            (
                                "Result requires review: "
                                f"{classification}"
                            ),
                        )

                    if classification == "OPEN_REDIRECT_CONFIRMED":
                        add_open_redirect_finding(
                            report,
                            result,
                        )
                        metadata["confirmed_findings"] += 1

                except Exception as error:
                    checks.append(
                        {
                            "candidate_id": candidate.get(
                                "candidate_id",
                                "",
                            ),
                            "url": url,
                            "path": path,
                            "parameter": candidate.get(
                                "parameter",
                                "",
                            ),
                            "classification": "CHECK_ERROR",
                            "error": str(error),
                        }
                    )

                    record_error(
                        report,
                        "open_redirect",
                        url,
                        error,
                    )

                    on_message(
                        f"Open redirect check error: "
                        f"{path}: {error}"
                    )

    except Exception as error:
        record_error(
            report,
            "open_redirect",
            report["target"],
            error,
        )
        on_message(
            f"Open redirect stage error: {error}"
        )

    metadata["status"] = (
        "completed"
        if metadata["completed_routes"] == len(candidates)
        else "incomplete"
    )

    if metadata["completed_routes"]:
        update_test_coverage(
            report,
            "Open redirect",
            "Local lab external redirect verification",
            (
                "Other redirect parameters, routes, schemes, "
                "and non-lab targets"
            ),
        )

    on_message(
        f"Open redirect checks completed: "
        f"{metadata['completed_routes']}/{len(candidates)}"
    )

    on_message(
        f"Confirmed open redirect findings: "
        f"{metadata['confirmed_findings']}"
    )


def run_cors_checks(report, candidates, on_message):
    metadata = create_stage_metadata(
        candidates,
        "Origin header",
    )
    metadata["confirmed_findings"] = 0
    metadata["planned_requests_per_route"] = 1

    report["coverage"]["cors"] = metadata
    checks = report["cors_checks"]

    try:
        from app.checks.cors import inspect_route

        with requests.Session() as session:
            session.trust_env = False

            for path, url in candidates.items():
                on_message(
                    f"CORS check: {path}"
                )

                try:
                    result = inspect_route(
                        session,
                        url,
                    )

                    checks.append(result)

                    classification = result["classification"]

                    on_message(
                        f"CORS result: "
                        f"{path} -> {classification}"
                    )

                    if classification in CORS_COMPLETED:
                        metadata["completed_routes"] += 1
                    else:
                        record_error(
                            report,
                            "cors",
                            url,
                            (
                                "Result requires review: "
                                f"{classification}"
                            ),
                        )

                    if classification == (
                        "CORS_ARBITRARY_ORIGIN_WITH_CREDENTIALS"
                    ):
                        add_cors_finding(
                            report,
                            result,
                        )
                        metadata["confirmed_findings"] += 1

                except Exception as error:
                    checks.append(
                        {
                            "path": path,
                            "url": url,
                            "classification": "CHECK_ERROR",
                            "error": str(error),
                        }
                    )

                    record_error(
                        report,
                        "cors",
                        url,
                        error,
                    )

                    on_message(
                        f"CORS check error: {path}: {error}"
                    )

    except Exception as error:
        record_error(
            report,
            "cors",
            report["target"],
            error,
        )

        on_message(
            f"CORS stage error: {error}"
        )

    metadata["status"] = (
        "completed"
        if metadata["completed_routes"] == len(candidates)
        else "incomplete"
    )

    if metadata["completed_routes"]:
        update_test_coverage(
            report,
            "CORS misconfiguration",
            "Local lab arbitrary-Origin CORS verification",
            (
                "Other CORS policies, preflight behavior, "
                "methods, headers, and non-lab targets"
            ),
        )

    on_message(
        f"CORS checks completed: "
        f"{metadata['completed_routes']}/{len(candidates)}"
    )

    on_message(
        f"Confirmed CORS findings: "
        f"{metadata['confirmed_findings']}"
    )


def run_scan(target_url, on_message=print):
    def header_message(message):
        text = str(message)

        if text.startswith("Report saved:"):
            on_message("Header report prepared. Continuing assessment.")
        elif text.startswith("Active XSS and SQL injection tests"):
            on_message(
                "The HTTP stage checks headers and discovers input points. "
                "Local active checks run in subsequent stages."
            )
        else:
            on_message(text)

    report, report_path = run_header_scan(
        target_url,
        on_message=header_message,
    )

    report["schema_version"] = 3
    report["engine"] = "Independent HTTP and local active assessment"
    report["xss_checks"] = []
    report["sqli_checks"] = []
    report["open_redirect_checks"] = []
    report["cors_checks"] = []


    on_message("The HTTP stage is complete.")

    if is_supported_lab(report["target"]):
        xss_candidates = find_planned_candidates(
            report,
            XSS_PATHS,
            "name",
        )

        sqli_candidates = find_candidates(
            report,
            SQLI_PATHS,
            "id",
        )

        redirect_candidates = find_redirect_candidates(
            report,
            REDIRECT_PATHS,
            "next",
        )

        cors_candidates = find_route_candidates(
            report,
            CORS_PATHS,
        )

        if xss_candidates:
            run_browser_checks(
                report,
                xss_candidates,
                on_message,
            )
        else:
            mark_stage_skipped(
                report,
                "browser_xss",
                "No supported local XSS routes were discovered.",
            )
            on_message("Browser XSS checks skipped: no supported routes.")

        if sqli_candidates:
            run_sqli_checks(
                report,
                sqli_candidates,
                on_message,
            )
        else:
            mark_stage_skipped(
                report,
                "sql_injection",
                "No supported local SQL injection routes were discovered.",
            )
            on_message("SQL injection checks skipped: no supported routes.")

        if redirect_candidates:
            run_open_redirect_checks(
                report,
                redirect_candidates,
                on_message,
            )
        else:
            mark_stage_skipped(
                report,
                "open_redirect",
                "No supported local redirect routes were discovered.",
            )
            on_message("Open redirect checks skipped: no supported routes.")

        if cors_candidates:
            run_cors_checks(
                report,
                cors_candidates,
                on_message,
            )
        else:
            mark_stage_skipped(
                report,
                "cors",
                "No supported local CORS routes were discovered.",
            )
            on_message("CORS checks skipped: no supported routes.")

    else:
        reason = (
            "This version implements active checks only for the "
            "supported lab at http://127.0.0.1:5001."
        )

        mark_stage_skipped(
            report,
            "browser_xss",
            reason,
        )

        mark_stage_skipped(
            report,
            "sql_injection",
            reason,
        )

        mark_stage_skipped(
            report,
            "open_redirect",
            reason,
        )

        mark_stage_skipped(
            report,
            "cors",
            reason,
        )

        on_message("Local active checks skipped for this target.")

    on_message("Starting planned query reflection checks.")
    run_reflection_checks(report, on_message)

    report["coverage"]["request_count_note"] = (
        "requests_attempted counts HTTP crawler requests only. "
        "Browser checks can add two navigations per route. "
        "Local SQL injection checks can add four HTTP requests per route. "
        "Open redirect checks can add one HTTP request per route. "
        "CORS checks can add one HTTP request per route. "
        "Reflection HTTP requests are counted separately in "
        "coverage.reflection.requests_attempted."
    )

    temporary_path = report_path.with_suffix(".json.tmp")
    temporary_path.write_text(
        json.dumps(report, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    temporary_path.replace(report_path)

    on_message(f"Final finding records: {len(report['alerts'])}")
    on_message(f"Final assessment status: {report['assessment_status']}")
    on_message(f"Final report saved: {report_path}")

    return report, report_path
