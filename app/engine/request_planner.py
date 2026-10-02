import json
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from app.engine.input_inventory import run_scan as run_inventory_scan
from app.engine.crawler import get_origin, normalize_url


MAX_PLANNED_REQUESTS = 100


def replace_parameter(candidate, new_value):
    """Replace one query value while preserving all other query pairs."""
    if not isinstance(new_value, str):
        raise ValueError("The replacement value must be text.")

    pairs = [tuple(pair) for pair in candidate["query_pairs"]]
    position = candidate["query_position"]

    if not isinstance(position, int):
        raise ValueError("The query position must be an integer.")

    if position < 0 or position >= len(pairs):
        raise ValueError("The query position is invalid.")

    if pairs[position][0] != candidate["parameter"]:
        raise ValueError("The parameter does not match its query position.")

    pairs[position] = (pairs[position][0], new_value)
    parsed = urlsplit(candidate["original_url"])

    return urlunsplit(
        (
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            urlencode(pairs),
            "",
        )
    )

def build_request_plan(report):
    scope = get_origin(report["target"])
    candidates = []
    skipped = []
    candidate_keys = {}
    limit_reached = False

    def skip(record, reason):
        skipped.append(
            {
                "input_id": record["input_id"],
                "source": record.get("source", ""),
                "parameter": record.get("parameter", ""),
                "page": record.get("page", ""),
                "reason": reason,
            }
        )

    for record in report.get("input_inventory", []):
        source = record.get("source")

        if source == "form_field":
            skip(
                record,
                "Form submission was not planned because field values "
                "and successful-control state have not been captured. "
                "A query parameter observed separately may still be planned.",
            )
            continue

        if source != "url_query":
            skip(record, "This input source is not supported by the planner.")
            continue

        if record.get("review_reason"):
            skip(record, record["review_reason"])
            continue

        try:
            url = normalize_url(record["page"])

            if get_origin(url) != scope:
                raise ValueError("The request is outside the scan origin.")

            parsed = urlsplit(url)
            pairs = parse_qsl(
                parsed.query,
                keep_blank_values=True,
                max_num_fields=1000,
            )
            position = record["query_position"]
            parameter = record["parameter"]

            if not parameter:
                raise ValueError("The parameter name is empty.")

            if not isinstance(position, int):
                raise ValueError("The query position must be an integer.")

            if position < 0 or position >= len(pairs):
                raise ValueError("The query position is invalid.")

            if pairs[position][0] != parameter:
                raise ValueError("The parameter position no longer matches.")

            if sum(name == parameter for name, value in pairs) != 1:
                raise ValueError(
                    "Repeated parameter names require a separate strategy."
                )

        except (KeyError, TypeError, ValueError) as error:
            skip(record, str(error))
            continue

        # Keep different original URLs as separate request variants.
        key = (url, position)

        if key in candidate_keys:
            existing = candidate_keys[key]
            if record["input_id"] not in existing["source_input_ids"]:
                existing["source_input_ids"].append(record["input_id"])
            continue

        if len(candidates) >= MAX_PLANNED_REQUESTS:
            limit_reached = True
            skip(record, "The request-plan limit was reached.")
            continue

        candidate = {
            "candidate_id": f"candidate-{len(candidates) + 1:04d}",
            "source_input_ids": [record["input_id"]],
            "method": "GET",
            "original_url": url,
            "endpoint": urlunsplit(
                (parsed.scheme, parsed.netloc, parsed.path, "", "")
            ),
            "parameter": parameter,
            "query_position": position,
            "query_pairs": [list(pair) for pair in pairs],
            "status": "planned",
            "active_test_executed": False,
        }

        candidates.append(candidate)
        candidate_keys[key] = candidate

    return {
        "status": "limited" if limit_reached else "completed",
        "candidate_count": len(candidates),
        "skipped_input_count": len(skipped),
        "candidate_limit": MAX_PLANNED_REQUESTS,
        "limit_reached": limit_reached,
        "additional_requests": 0,
        "candidates": candidates,
        "skipped_inputs": skipped,
        "note": (
            "Planning sends no requests and does not identify vulnerabilities. "
            "Existing local lab checks are reported separately. "
            "Query values are preserved in this report. Rebuilding a query "
            "may normalize URL encoding, so signed URLs need separate handling."
        ),
    }


def run_scan(target_url, on_message=print):
    def forward_message(message):
        if not str(message).startswith("Report saved:"):
            on_message(message)

    report, report_path = run_inventory_scan(
        target_url,
        on_message=forward_message,
    )

    plan = build_request_plan(report)
    report["request_plan"] = plan

    report["coverage"]["request_planning"] = {
        "status": plan["status"],
        "candidate_count": plan["candidate_count"],
        "skipped_input_count": plan["skipped_input_count"],
        "candidate_limit": plan["candidate_limit"],
        "limit_reached": plan["limit_reached"],
        "additional_requests": 0,
    }

    temporary_path = report_path.with_suffix(".json.tmp")
    temporary_path.write_text(
        json.dumps(report, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    temporary_path.replace(report_path)

    on_message(f"Planned query candidates: {plan['candidate_count']}")
    on_message(f"Inputs not planned: {plan['skipped_input_count']}")

    for candidate in plan["candidates"]:
        on_message(
            f"Planned: {candidate['candidate_id']} | "
            f"{candidate['method']} {candidate['endpoint']} | "
            f"parameter={candidate['parameter']} | "
            f"inputs={','.join(candidate['source_input_ids'])}"
        )

    for skipped in plan["skipped_inputs"]:
        on_message(
            f"Not planned: {skipped['input_id']} | {skipped['reason']}"
        )

    on_message("Request planning sent no additional requests.")
    on_message(f"Report saved: {report_path}")

    return report, report_path