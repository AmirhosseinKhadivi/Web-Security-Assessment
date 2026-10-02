import secrets
from urllib.parse import (
    parse_qsl,
    urlencode,
    urljoin,
    urlsplit,
    urlunsplit,
)

LAB_ORIGIN = ("http", "127.0.0.1", 5001)
ALLOWED_PATHS = {"/redirect-unsafe", "/redirect-safe"}


def get_origin(url):
    parsed = urlsplit(url)

    return (
        parsed.scheme.lower(),
        parsed.hostname.lower() if parsed.hostname else "",
        parsed.port or (443 if parsed.scheme == "https" else 80),
    )


def replace_query_parameter(
    url,
    parameter,
    value,
):
    parsed = urlsplit(url)

    query_pairs = parse_qsl(
        parsed.query,
        keep_blank_values=True,
    )

    replaced = False
    updated_pairs = []

    for key, current_value in query_pairs:
        if key == parameter and not replaced:
            updated_pairs.append(
                (key, value)
            )
            replaced = True
        else:
            updated_pairs.append(
                (key, current_value)
            )

    if not replaced:
        raise ValueError(
            "The redirect parameter was not found in the URL."
        )

    updated_query = urlencode(
        updated_pairs,
        doseq=True,
    )

    return urlunsplit(
        (
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            updated_query,
            parsed.fragment,
        )
    )


def inspect_candidate(session, candidate):
    if candidate.get("method") != "GET":
        raise ValueError("Only GET candidates are supported.")

    if candidate.get("parameter") != "next":
        raise ValueError("Unsupported redirect parameter.")

    original_url = candidate.get("original_url", "")
    parsed = urlsplit(original_url)

    if (
        get_origin(original_url) != LAB_ORIGIN
        or parsed.path not in ALLOWED_PATHS
    ):
        raise ValueError("Unsupported local redirect candidate.")

    marker = secrets.token_hex(8)
    probe_url = f"https://example.com/redirect-probe-{marker}"

    test_url = replace_query_parameter(
        original_url,
        candidate["parameter"],
        probe_url,
    )

    response = session.get(
        test_url,
        timeout=(5, 10),
        allow_redirects=False,
    )

    location = response.headers.get("Location", "")
    resolved_location = (
        urljoin(test_url, location)
        if location
        else ""
    )

    status_code = response.status_code

    if 300 <= status_code < 400 and location:
        destination_origin = get_origin(resolved_location)

        if (
            destination_origin != LAB_ORIGIN
            and resolved_location == probe_url
        ):
            classification = "OPEN_REDIRECT_CONFIRMED"
        elif destination_origin == LAB_ORIGIN:
            classification = "EXTERNAL_REDIRECT_BLOCKED"
        else:
            classification = "REDIRECT_RESULT_INCONCLUSIVE"

    elif 300 <= status_code < 400:
        classification = "REDIRECT_WITHOUT_LOCATION"

    else:
        classification = "NO_REDIRECT_OBSERVED"

    return {
        "candidate_id": candidate.get("candidate_id", ""),
        "source_input_ids": candidate.get("source_input_ids", []),
        "url": original_url,
        "path": parsed.path,
        "parameter": candidate["parameter"],
        "probe_url": probe_url,
        "request_url": test_url,
        "status_code": status_code,
        "location": location,
        "resolved_location": resolved_location,
        "classification": classification,
    }