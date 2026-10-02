import secrets
from urllib.parse import urlsplit


LAB_ORIGIN = ("http", "127.0.0.1", 5001)

ALLOWED_PATHS = {
    "/cors-unsafe",
    "/cors-safe",
}


def is_supported_url(url):
    try:
        parsed = urlsplit(url)

        return (
            (
                parsed.scheme,
                parsed.hostname,
                parsed.port,
            )
            == LAB_ORIGIN
            and parsed.path in ALLOWED_PATHS
            and parsed.username is None
            and parsed.password is None
        )
    except ValueError:
        return False


def inspect_route(session, url):
    if not is_supported_url(url):
        raise ValueError("Unsupported local CORS route.")

    parsed = urlsplit(url)

    probe_origin = (
        "https://attacker-"
        f"{secrets.token_hex(8)}"
        ".example"
    )

    response = session.get(
        url,
        headers={
            "Origin": probe_origin,
        },
        timeout=(5, 10),
        allow_redirects=False,
    )

    allow_origin = response.headers.get(
        "Access-Control-Allow-Origin",
        "",
    ).strip()

    allow_credentials = response.headers.get(
        "Access-Control-Allow-Credentials",
        "",
    ).strip().lower()

    if allow_origin == probe_origin:
        if allow_credentials == "true":
            classification = (
                "CORS_ARBITRARY_ORIGIN_WITH_CREDENTIALS"
            )
        else:
            classification = "CORS_ARBITRARY_ORIGIN_ALLOWED"

    elif not allow_origin:
        classification = "CORS_EXTERNAL_ORIGIN_BLOCKED"

    elif allow_origin == "*":
        classification = "CORS_WILDCARD_ORIGIN_ALLOWED"

    else:
        classification = "CORS_ORIGIN_NOT_REFLECTED"

    return {
        "url": url,
        "path": parsed.path,
        "probe_origin": probe_origin,
        "status_code": response.status_code,
        "allow_origin": allow_origin,
        "allow_credentials": allow_credentials,
        "classification": classification,
    }