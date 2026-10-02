import html
import secrets

import requests


LAB_URL = "http://127.0.0.1:5001"

MAX_RESPONSE_BYTES = 500_000


def fetch_html(session, path, value):
    url = f"{LAB_URL}{path}"

    with session.get(
        url,
        params={"name": value},
        timeout=(5, 10),
        allow_redirects=False,
        stream=True,
    ) as response:
        if response.status_code != 200:
            raise RuntimeError(
                f"{path} returned HTTP {response.status_code}; "
                "expected HTTP 200."
            )

        content_type = response.headers.get(
            "Content-Type", ""
        ).lower()

        if "text/html" not in content_type:
            raise RuntimeError(
                f"{path} did not return an HTML response."
            )

        body = bytearray()

        for chunk in response.iter_content(chunk_size=16384):
            body.extend(chunk)

            if len(body) > MAX_RESPONSE_BYTES:
                raise RuntimeError(
                    f"{path} exceeded the response size limit."
                )

        encoding = response.encoding or "utf-8"

        try:
            return bytes(body).decode(encoding, errors="replace")
        except LookupError:
            return bytes(body).decode("utf-8", errors="replace")


def inspect_route(session, path):
    token = f"probe_{secrets.token_hex(12)}"

    baseline = fetch_html(session, path, token)

    if token not in baseline:
        return {
            "path": path,
            "classification": "NO_REFLECTION_OBSERVED",
            "evidence": "The plain-text marker was not found.",
        }

    # This probe contains HTML markup but no JavaScript.
    payload = f"<strong>{token}</strong>"
    response_html = fetch_html(session, path, payload)

    if payload in response_html:
        classification = "RAW_MARKUP_REFLECTED"
        evidence = payload

    elif html.escape(payload) in response_html:
        classification = "HTML_ESCAPED_REFLECTION"
        evidence = html.escape(payload)

    elif token in response_html:
        classification = "REFLECTION_REQUIRES_REVIEW"
        evidence = (
            "The marker was reflected, but the markup was transformed."
        )

    else:
        classification = "PROBE_NOT_REFLECTED"
        evidence = "The markup probe was not found in the response."

    return {
        "path": path,
        "classification": classification,
        "evidence": evidence,
    }


def main():
    expected = {
        "/unsafe": "RAW_MARKUP_REFLECTED",
        "/safe": "HTML_ESCAPED_REFLECTION",
    }

    print("Local reflection validation")
    print(f"Target: {LAB_URL}")
    print("No JavaScript payloads will be sent.")
    print()

    passed = 0

    with requests.Session() as session:
        session.trust_env = False

        for path, expected_classification in expected.items():
            try:
                result = inspect_route(session, path)

                print(f"Route: {result['path']}")
                print(f"Observed: {result['classification']}")
                print(f"Evidence: {result['evidence']}")

                if result["classification"] == expected_classification:
                    passed += 1
                    print("[PASS] The route matched the expected lab behavior.")
                else:
                    print("[FAIL] The route needs review.")
                    print(f"Expected: {expected_classification}")

            except (requests.RequestException, RuntimeError) as exc:
                print(f"[ERROR] {path}: {exc}")

            print()

    print(f"Result: {passed}/{len(expected)} route checks passed.")
    print(
        "Raw markup reflection is a candidate for further analysis, "
        "not proof of JavaScript execution."
    )
    print(
        "An escaped result applies only to this probe and output context."
    )

    if passed != len(expected):
        raise SystemExit(1)


if __name__ == "__main__":
    main()