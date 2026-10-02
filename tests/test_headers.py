from requests.structures import CaseInsensitiveDict

from app.engine.crawler import inspect_headers


HTTP_URL = "http://127.0.0.1:5001/"
HTTPS_URL = "https://example.test/"


def finding_ids(url, headers):
    findings = inspect_headers(
        url,
        CaseInsensitiveDict(headers),
    )

    return {finding["rule_id"] for finding in findings}


def run_case(name, url, headers, expected):
    actual = finding_ids(url, headers)

    if actual == expected:
        print(f"[PASS] {name}")
        return True

    print(f"[FAIL] {name}")
    print(f"  Expected: {sorted(expected)}")
    print(f"  Actual:   {sorted(actual)}")
    print(f"  Missing:  {sorted(expected - actual)}")
    print(f"  Extra:    {sorted(actual - expected)}")

    return False


def main():
    protected_headers = {
        "Content-Security-Policy": (
            "default-src 'none'; frame-ancestors 'none'"
        ),
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "Server": "ExampleServer",
    }

    cases = [
        (
            "Missing headers and disclosed server version",
            HTTP_URL,
            {
                "Server": "ExampleServer/1.2.3",
            },
            {
                "HEADER-CSP",
                "HEADER-FRAMING",
                "HEADER-NOSNIFF",
                "HEADER-SERVER",
            },
        ),
        (
            "HTTP response with the checked protections",
            HTTP_URL,
            protected_headers,
            set(),
        ),
        (
            "HTTPS response without HSTS",
            HTTPS_URL,
            protected_headers,
            {
                "HEADER-HSTS",
            },
        ),
        (
            "HTTPS response with the checked protections and HSTS",
            HTTPS_URL,
            {
                **protected_headers,
                "Strict-Transport-Security": "max-age=31536000",
            },
            set(),
        ),
        (
            "CSP frame-ancestors without X-Frame-Options",
            HTTP_URL,
            {
                "Content-Security-Policy": (
                    "default-src 'none'; frame-ancestors 'none'"
                ),
                "X-Content-Type-Options": "nosniff",
                "Server": "ExampleServer",
            },
            set(),
        ),
        (
            "CSP without a framing directive",
            HTTP_URL,
            {
                "Content-Security-Policy": "default-src 'self'",
                "X-Content-Type-Options": "nosniff",
            },
            {
                "HEADER-FRAMING",
            },
        ),
        (
            "Invalid nosniff value",
            HTTP_URL,
            {
                **protected_headers,
                "X-Content-Type-Options": "invalid-value",
            },
            {
                "HEADER-NOSNIFF",
            },
        ),
        (
            "Case-insensitive HTTP header names",
            HTTP_URL,
            {
                "content-security-policy": (
                    "default-src 'none'; frame-ancestors 'none'"
                ),
                "x-content-type-options": "nosniff",
                "server": "ExampleServer",
            },
            set(),
        ),
    ]

    passed = 0

    for name, url, headers, expected in cases:
        if run_case(name, url, headers, expected):
            passed += 1

    print()
    print(f"Result: {passed}/{len(cases)} checks passed.")
    print("No network requests were made.")
    print(
        "These checks validate selected header rules, "
        "not the overall security of a website."
    )

    if passed != len(cases):
        raise SystemExit(1)


if __name__ == "__main__":
    main()