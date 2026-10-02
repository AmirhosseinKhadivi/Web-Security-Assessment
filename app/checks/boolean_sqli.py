from html.parser import HTMLParser

import requests


LAB_URL = "http://127.0.0.1:5001"
ALLOWED_PATHS = {"/sqli-unsafe", "/sqli-safe"}

PROBES = [
    ("baseline", "1"),
    ("true_condition", "1 AND 1=1"),
    ("false_condition", "1 AND 1=2"),
    ("baseline_repeat", "1"),
]


class ProductParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.product_ids = []
        self.count_parts = []
        self.count_elements = 0
        self.reading_count = False
        self.query_error = False

    def handle_starttag(self, tag, attrs):
        attributes = dict(attrs)

        if attributes.get("id") == "query-error":
            self.query_error = True

        if tag == "span" and attributes.get("id") == "result-count":
            self.count_elements += 1
            self.reading_count = True

        if tag == "tr" and "data-product-id" in attributes:
            self.product_ids.append(int(attributes["data-product-id"]))

    def handle_endtag(self, tag):
        if tag == "span":
            self.reading_count = False

    def handle_data(self, data):
        if self.reading_count:
            self.count_parts.append(data)

    def result(self):
        if self.query_error:
            raise ValueError("The lab reported a query error.")

        if self.count_elements != 1:
            raise ValueError("Expected exactly one result-count element.")

        count = int("".join(self.count_parts).strip())

        if count != len(self.product_ids):
            raise ValueError("The result count does not match the product rows.")

        return {
            "count": count,
            "product_ids": sorted(self.product_ids),
        }


def fetch_probe(session, path, value):
    if path not in ALLOWED_PATHS:
        raise ValueError("Unsupported local lab route.")

    with session.get(
        f"{LAB_URL}{path}",
        params={"id": value},
        timeout=(5, 10),
        allow_redirects=False,
    ) as response:
        if response.status_code != 200:
            raise ValueError(
                f"Expected HTTP 200, received {response.status_code}."
            )

        content_type = response.headers.get("Content-Type", "").lower()

        if "text/html" not in content_type:
            raise ValueError("Expected an HTML response.")

        parser = ProductParser()
        parser.feed(response.text)
        parser.close()
        result = parser.result()

        result["url"] = response.url
        result["input"] = value
        return result


def inspect_route(session, path):
    observations = {}

    for label, value in PROBES:
        observations[label] = fetch_probe(session, path, value)

    baseline = observations["baseline"]["product_ids"]
    repeated = observations["baseline_repeat"]["product_ids"]
    true_result = observations["true_condition"]["product_ids"]
    false_result = observations["false_condition"]["product_ids"]

    if baseline != [1] or repeated != baseline:
        classification = "BASELINE_REQUIRES_REVIEW"
    elif true_result == baseline and false_result == []:
        classification = "BOOLEAN_SQLI_BEHAVIOR_OBSERVED"
    elif true_result == [] and false_result == []:
        classification = "NO_BOOLEAN_SQLI_BEHAVIOR_OBSERVED"
    else:
        classification = "PROBE_REQUIRES_REVIEW"

    return {
        "path": path,
        "parameter": "id",
        "classification": classification,
        "observations": observations,
    }


def main():
    print("Local SQL injection validation")
    print(f"Target: {LAB_URL}")
    print("Method: baseline, true condition, false condition, baseline repeat")
    print("Only the two local product lookup routes are tested.")

    expected = {
        "/sqli-unsafe": "BOOLEAN_SQLI_BEHAVIOR_OBSERVED",
        "/sqli-safe": "NO_BOOLEAN_SQLI_BEHAVIOR_OBSERVED",
    }

    passed = 0

    with requests.Session() as session:
        session.trust_env = False

        for path, expected_classification in expected.items():
            print(f"\nRoute: {path}")

            try:
                result = inspect_route(session, path)

                for label, observation in result["observations"].items():
                    print(
                        f"  {label}: "
                        f"input={observation['input']!r}, "
                        f"count={observation['count']}, "
                        f"product_ids={observation['product_ids']}"
                    )

                print(f"Observed: {result['classification']}")

                if result["classification"] == expected_classification:
                    passed += 1
                    print("[PASS] Expected lab behavior confirmed.")
                else:
                    print(f"[FAIL] Expected: {expected_classification}")

            except (requests.RequestException, ValueError) as error:
                print(f"[ERROR] {error}")

    print(f"\nResult: {passed}/{len(expected)} route checks passed.")
    print("This validation uses the known local lab response structure.")
    print("A negative result applies only to these probes and this parameter.")
    print("This is not yet a general-purpose SQL injection detector.")

    return 0 if passed == len(expected) else 1


if __name__ == "__main__":
    raise SystemExit(main())