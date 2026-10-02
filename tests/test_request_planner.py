from urllib.parse import parse_qsl, urlsplit

from app.engine.request_planner import build_request_plan, replace_parameter


def main():
    url = (
        "http://127.0.0.1:5001/search"
        "?q=Alice&lang=en&tag=a&tag=b&empty="
    )

    record = {
        "input_id": "input-0001",
        "source": "url_query",
        "page": url,
        "parameter": "q",
        "query_position": 0,
        "review_reason": "",
    }

    duplicate = dict(record, input_id="input-0002")

    form = {
        "input_id": "input-0003",
        "source": "form_field",
        "page": url,
        "parameter": "q",
    }

    report = {
        "target": "http://127.0.0.1:5001/",
        "input_inventory": [record, duplicate, form],
    }

    plan = build_request_plan(report)

    assert plan["candidate_count"] == 1, (
        "Duplicate query observations created duplicate candidates."
    )

    candidate = plan["candidates"][0]

    assert candidate["source_input_ids"] == [
        "input-0001",
        "input-0002",
    ], "Source input references were not preserved."

    changed_url = replace_parameter(candidate, "probe & value")
    changed_pairs = parse_qsl(
        urlsplit(changed_url).query,
        keep_blank_values=True,
    )

    assert changed_pairs == [
        ("q", "probe & value"),
        ("lang", "en"),
        ("tag", "a"),
        ("tag", "b"),
        ("empty", ""),
    ], "Other query values or their order changed."

    assert candidate["query_pairs"][0] == ["q", "Alice"], (
        "The original candidate was modified."
    )

    assert plan["skipped_input_count"] == 1, (
        "The incomplete form should have been skipped."
    )

    print("[PASS] Duplicate observations share one candidate.")
    print("[PASS] Both source input IDs are preserved.")
    print("[PASS] Other query pairs, duplicates, and blank values are preserved.")
    print("[PASS] The original candidate remains unchanged.")
    print("[PASS] The incomplete form is skipped with a reason.")
    print("Result: 5/5 planner checks passed.")
    print("No network requests were sent.")


if __name__ == "__main__":
    main()