import json
from collections import Counter
from urllib.parse import parse_qsl, urlsplit, urlunsplit

from app.engine.crawler import get_origin, normalize_url
from app.engine.crawler import run_scan as run_http_scan


MAX_INPUT_RECORDS = 500


def build_input_inventory(report):
    target_origin = get_origin(report["target"])
    records = []
    truncated = False

    def add_record(record):
        nonlocal truncated

        if len(records) >= MAX_INPUT_RECORDS:
            truncated = True
            return

        record["input_id"] = f"input-{len(records) + 1:04d}"

        # Discovery does not establish that an input has been tested.
        record["assessment_status"] = "not_tested"
        records.append(record)

    def resolve_endpoint(url):
        try:
            normalized = normalize_url(url)
            parsed = urlsplit(normalized)

            endpoint = urlunsplit(
                (
                    parsed.scheme,
                    parsed.netloc,
                    parsed.path,
                    "",
                    "",
                )
            )

            return endpoint, get_origin(normalized) == target_origin

        except (TypeError, ValueError, AttributeError):
            return url, False

    for page in report.get("pages", []):
        url = page.get("url", "")
        endpoint, in_scope = resolve_endpoint(url)

        try:
            pairs = parse_qsl(
                urlsplit(url).query,
                keep_blank_values=True,
                max_num_fields=1000,
            )
        except ValueError:
            add_record(
                {
                    "source": "query_parse_error",
                    "page": url,
                    "endpoint": endpoint,
                    "method": "GET",
                    "parameter": "",
                    "in_scope": in_scope,
                    "review_reason": "The query could not be parsed within limits.",
                }
            )
            continue

        counts = Counter(name for name, value in pairs)
        occurrences = Counter()

        for position, (name, value) in enumerate(pairs):
            occurrences[name] += 1

            reasons = []

            if not in_scope:
                reasons.append("The endpoint is outside the scan origin.")

            if not name:
                reasons.append("The parameter name is empty.")

            if counts[name] > 1:
                reasons.append(
                    "The parameter occurs more than once in the query."
                )

            if page.get("status_code") != 200:
                reasons.append("The source response was not HTTP 200.")

            add_record(
                {
                    "source": "url_query",
                    "page": url,
                    "endpoint": endpoint,
                    "method": "GET",
                    "parameter": name,
                    "query_position": position,
                    "parameter_occurrence": occurrences[name],
                    "same_name_count": counts[name],
                    "observed_value_present": bool(value),
                    "in_scope": in_scope,
                    "review_reason": " ".join(reasons),
                }
            )

    for form_index, form in enumerate(report.get("forms", []), start=1):
        page_url = form.get("page", "")
        action = form.get("action") or page_url
        endpoint, in_scope = resolve_endpoint(action)
        method = str(form.get("method", "GET")).upper()
        fields = form.get("fields", [])

        counts = Counter(field.get("name", "") for field in fields)
        occurrences = Counter()

        for field_index, field in enumerate(fields):
            name = field.get("name", "")
            field_type = str(field.get("type", "unknown")).lower()

            # The current parser labels an input without a type as "input".
            if field_type == "input":
                field_type = "text"

            occurrences[name] += 1

            reasons = [
                "Form values and successful-control state are not captured."
            ]

            if not in_scope:
                reasons.append("The form action is outside the scan origin.")

            if method != "GET":
                reasons.append(
                    "This form requires a separate submission strategy."
                )

            if counts[name] > 1:
                reasons.append(
                    "The field name occurs more than once in this form."
                )

            add_record(
                {
                    "source": "form_field",
                    "page": page_url,
                    "action": action,
                    "endpoint": endpoint,
                    "method": method,
                    "parameter": name,
                    "field_type": field_type,
                    "form_index": form_index,
                    "field_index": field_index,
                    "parameter_occurrence": occurrences[name],
                    "same_name_count": counts[name],
                    "in_scope": in_scope,
                    "review_reason": " ".join(reasons),
                }
            )

    source_counts = Counter(record["source"] for record in records)

    summary = {
        "status": "incomplete" if truncated else "completed",
        "input_records": len(records),
        "query_input_records": source_counts["url_query"],
        "form_input_records": source_counts["form_field"],
        "query_parse_errors": source_counts["query_parse_error"],
        "record_limit": MAX_INPUT_RECORDS,
        "limit_reached": truncated,
        "scope": "Inputs observed in the supplied crawl report",
        "additional_requests": 0,
        "note": (
            "URL parameters and form fields are separate observations. "
            "They may refer to the same server-side input. Discovery is "
            "not a vulnerability finding or evidence of active testing. "
            "A completed inventory does not imply full website coverage."
        ),
    }

    if summary["query_parse_errors"]:
        summary["status"] = "incomplete"

    return records, summary


def run_scan(target_url, on_message=print):
    def forward_message(message):
        if not str(message).startswith("Report saved:"):
            on_message(message)

    report, report_path = run_http_scan(
        target_url,
        on_message=forward_message,
    )

    records, summary = build_input_inventory(report)

    report["input_inventory"] = records
    report["coverage"]["input_inventory"] = summary

    if summary["status"] == "incomplete":
        report["assessment_status"] = "incomplete"
        report.setdefault("errors", []).append(
            {
                "stage": "input_inventory",
                "url": report["target"],
                "error": (
                    "Input inventory was incomplete. "
                    "See coverage.input_inventory for details."
                ),
            }
        )

    temporary_path = report_path.with_suffix(".json.tmp")
    temporary_path.write_text(
        json.dumps(report, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    temporary_path.replace(report_path)

    on_message(f"Input inventory records: {summary['input_records']}")
    on_message(f"URL query inputs: {summary['query_input_records']}")
    on_message(f"Form field inputs: {summary['form_input_records']}")

    for record in records:
        on_message(
            f"Input discovered: {record['source']} | "
            f"{record['method']} {record['endpoint']} | "
            f"parameter={record['parameter']}"
        )

    on_message("Input discovery sent no additional requests.")
    on_message(f"Report saved: {report_path}")

    return report, report_path