import ipaddress
import json
import re
import socket
import time

from collections import deque
from datetime import datetime, timezone
from html.parser import HTMLParser
from http.cookies import CookieError, SimpleCookie
from pathlib import Path
from urllib.parse import (
    parse_qs,
    urldefrag,
    urljoin,
    urlsplit,
    urlunsplit,
)

import requests


MAX_PAGES = 20
MAX_DISCOVERED_URLS = 200
MAX_RESPONSE_BYTES = 1_000_000
MAX_SCAN_SECONDS = 180

LOCAL_HOSTS = {"127.0.0.1", "localhost", "::1"}


def normalize_url(value):
    if not isinstance(value, str):
        raise ValueError("The target URL must be text.")

    value = value.strip()

    if not value or len(value) > 2048:
        raise ValueError("Enter a URL containing at most 2048 characters.")

    if any(character.isspace() for character in value):
        raise ValueError("The URL must not contain whitespace.")

    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise ValueError("Invalid URL or port.") from exc

    if parsed.scheme not in ("http", "https"):
        raise ValueError("The URL must start with http:// or https://.")

    if not parsed.hostname:
        raise ValueError("The URL must contain a hostname.")

    if parsed.username is not None or parsed.password is not None:
        raise ValueError("Do not include credentials in the URL.")

    host = parsed.hostname.lower()
    effective_port = port or (443 if parsed.scheme == "https" else 80)

    if port == 0:
        raise ValueError("Port 0 is not allowed.")

    if host in LOCAL_HOSTS:
        if effective_port != 5001:
            raise ValueError("Local lab scans must use port 5001.")
    elif effective_port not in (80, 443):
        raise ValueError("Public website scans must use port 80 or 443.")

    formatted_host = f"[{host}]" if ":" in host else host
    netloc = formatted_host

    if port is not None:
        netloc += f":{port}"

    return urlunsplit((
        parsed.scheme,
        netloc,
        parsed.path or "/",
        parsed.query,
        "",
    ))


def check_destination(url):
    parsed = urlsplit(url)
    host = parsed.hostname

    if host in LOCAL_HOSTS:
        return

    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    try:
        addresses = socket.getaddrinfo(
            host,
            port,
            type=socket.SOCK_STREAM,
        )
    except socket.gaierror as exc:
        raise ValueError("The target hostname could not be resolved.") from exc

    if not addresses:
        raise ValueError("No address was found for the target.")

    for address in addresses:
        ip = ipaddress.ip_address(address[4][0])

        if not ip.is_global:
            raise ValueError(
                "Private or reserved network destinations are not supported."
            )


def get_origin(url):
    parsed = urlsplit(url)

    return (
        parsed.scheme.lower(),
        parsed.hostname.lower(),
        parsed.port or (443 if parsed.scheme == "https" else 80),
    )


class PageParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)

        self.links = []
        self.forms = []
        self.current_form = None
        self.base_href = None

    def handle_starttag(self, tag, attributes):
        attrs = dict(attributes)

        if tag == "base" and self.base_href is None:
            self.base_href = attrs.get("href")

        if tag == "a" and attrs.get("href"):
            self.links.append(attrs["href"])

        if tag == "form":
            self.current_form = {
                "action": attrs.get("action", ""),
                "method": attrs.get("method", "GET").upper(),
                "fields": [],
            }
            self.forms.append(self.current_form)

        if tag in ("input", "textarea", "select"):
            if self.current_form is not None and attrs.get("name"):
                self.current_form["fields"].append({
                    "name": attrs["name"],
                    "type": attrs.get("type", tag),
                })

    def handle_endtag(self, tag):
        if tag == "form":
            self.current_form = None


def inspect_cookies(url, set_cookie_headers):
    findings = []

    def add(rule_id, title, cookie_name, evidence, description, solution):
        findings.append({
            "rule_id": rule_id,
            "alert": title,
            "risk": "Low",
            "confidence": "High",
            "category": "Security Misconfiguration",
            "url": url,
            "method": "GET",
            "param": cookie_name,
            "evidence": evidence,
            "description": description,
            "solution": solution,
        })

    for header in set_cookie_headers:
        cookie = SimpleCookie()

        try:
            cookie.load(header)
        except CookieError:
            continue

        for name, morsel in cookie.items():
            secure = bool(morsel["secure"])
            httponly = bool(morsel["httponly"])
            samesite = (morsel["samesite"] or "").strip().lower()

            if not secure:
                add(
                    "COOKIE-SECURE",
                    "Cookie Secure Attribute Missing",
                    name,
                    f"Cookie {name!r} does not include the Secure attribute.",
                    (
                        "The cookie may be transmitted over an unencrypted "
                        "connection if the application permits HTTP access."
                    ),
                    (
                        "Use the Secure attribute for security-sensitive "
                        "cookies when they are served over HTTPS."
                    ),
                )

            if not httponly:
                add(
                    "COOKIE-HTTPONLY",
                    "Cookie HttpOnly Attribute Missing",
                    name,
                    f"Cookie {name!r} does not include the HttpOnly attribute.",
                    (
                        "JavaScript may be able to access this cookie. "
                        "Impact depends on the purpose of the cookie."
                    ),
                    (
                        "Use HttpOnly for cookies that do not need to be "
                        "accessed by client-side JavaScript."
                    ),
                )

            if samesite not in ("lax", "strict", "none"):
                observed = samesite or "(missing)"

                add(
                    "COOKIE-SAMESITE",
                    "Cookie SameSite Attribute Missing or Invalid",
                    name,
                    f"Cookie {name!r} SameSite value: {observed}.",
                    (
                        "The cookie does not explicitly use a recognized "
                        "SameSite policy."
                    ),
                    (
                        "Choose an appropriate SameSite value such as "
                        "Lax or Strict based on application requirements."
                    ),
                )

    return findings


def inspect_error_disclosure(url, body):
    findings = []

    indicators = [
        (
            "Python traceback",
            re.compile(
                r"Traceback \(most recent call last\):",
                re.IGNORECASE,
            ),
        ),
        (
            "PHP fatal error",
            re.compile(
                r"\bFatal error:\s",
                re.IGNORECASE,
            ),
        ),
        (
            "Stack trace",
            re.compile(
                r"\bStack trace:",
                re.IGNORECASE,
            ),
        ),
        (
            "ASP.NET server error",
            re.compile(
                r"Server Error in ['\"].*?['\"] Application",
                re.IGNORECASE,
            ),
        ),
    ]

    for label, pattern in indicators:
        match = pattern.search(body)

        if not match:
            continue

        start = max(0, match.start() - 100)
        end = min(len(body), match.end() + 250)

        findings.append({
            "rule_id": "ERROR-DISCLOSURE",
            "alert": "Verbose Error or Stack Trace Disclosure",
            "risk": "Low",
            "confidence": "High",
            "category": "Security Misconfiguration",
            "url": url,
            "method": "GET",
            "param": "",
            "evidence": body[start:end],
            "description": (
                f"A response contained a recognizable {label}. "
                "Verbose error information may reveal internal "
                "application or server details."
            ),
            "solution": (
                "Return generic error responses to users and record "
                "detailed diagnostic information only in protected logs."
            ),
        })

        break

    return findings


def inspect_headers(url, headers):
    findings = []

    def add(rule_id, title, risk, evidence, description, solution):
        findings.append({
            "rule_id": rule_id,
            "alert": title,
            "risk": risk,
            "confidence": "High",
            "category": "Security Misconfiguration",
            "url": url,
            "method": "GET",
            "param": "",
            "evidence": evidence,
            "description": description,
            "solution": solution,
        })

    csp = headers.get("Content-Security-Policy", "")

    if not csp.strip():
        add(
            "HEADER-CSP",
            "Content Security Policy Header Missing",
            "Medium",
            "Content-Security-Policy was not present or was empty.",
            (
                "No enforcing CSP header was observed. "
                "This is a missing defense, not proof of an XSS vulnerability."
            ),
            (
                "Design and test a Content-Security-Policy appropriate "
                "for the application."
            ),
        )

    frame_options = headers.get("X-Frame-Options", "").strip().upper()
    has_frame_ancestors = any(
        directive.strip().lower().startswith("frame-ancestors ")
        for directive in csp.split(";")
    )

    if frame_options not in ("DENY", "SAMEORIGIN") and not has_frame_ancestors:
        add(
            "HEADER-FRAMING",
            "Frame Protection Not Observed",
            "Medium",
            (
                "No recognized X-Frame-Options value or "
                "CSP frame-ancestors directive was observed."
            ),
            (
                "The response may allow framing. Actual clickjacking "
                "impact depends on the page and its available actions."
            ),
            (
                "Configure CSP frame-ancestors and, where appropriate, "
                "X-Frame-Options."
            ),
        )

    content_options = headers.get(
        "X-Content-Type-Options", ""
    ).strip().lower()

    if content_options != "nosniff":
        add(
            "HEADER-NOSNIFF",
            "X-Content-Type-Options Is Not nosniff",
            "Low",
            f"Observed value: {content_options or '(missing)'}",
            "The response does not explicitly enable the nosniff protection.",
            (
                "Return the correct Content-Type and set "
                "X-Content-Type-Options to nosniff."
            ),
        )

    server = headers.get("Server", "")

    if re.search(r"\d+\.\d+", server):
        add(
            "HEADER-SERVER",
            "Server Header Contains Version-Like Information",
            "Low",
            server,
            (
                "The Server header contains a version-like string. "
                "This observation does not establish that the software "
                "has a known vulnerability."
            ),
            "Reduce unnecessary server version disclosure.",
        )

    if urlsplit(url).scheme == "https":
        if not headers.get("Strict-Transport-Security", "").strip():
            add(
                "HEADER-HSTS",
                "Strict-Transport-Security Header Missing",
                "Low",
                "Strict-Transport-Security was not observed.",
                (
                    "The HTTPS response does not advertise an HSTS policy. "
                    "Preload status is not checked."
                ),
                (
                    "Evaluate and configure HSTS after confirming "
                    "the site's HTTPS deployment."
                ),
            )

    return findings


def run_scan(target_url, on_message=print):
    target_url = normalize_url(target_url)
    check_destination(target_url)

    scope = get_origin(target_url)
    deadline = time.monotonic() + MAX_SCAN_SECONDS

    pending = deque([target_url])
    discovered = {target_url}

    pages = []
    forms = []
    alerts = []
    errors = []

    attempted = 0
    html_pages = 0

    on_message(f"Target: {target_url}")
    on_message("Engine: Independent HTTP assessment")
    on_message("Active XSS and SQL injection tests are not enabled.")

    with requests.Session() as session:
        session.trust_env = False
        session.headers["User-Agent"] = "BachelorSecurityScanner/0.1"

        while pending and attempted < MAX_PAGES:
            if time.monotonic() >= deadline:
                errors.append({
                    "url": target_url,
                    "error": "The scan time budget was reached.",
                })
                break

            url = pending.popleft()
            attempted += 1

            on_message(f"Fetching page {attempted}/{MAX_PAGES}: {url}")

            try:
                check_destination(url)

                with session.get(
                    url,
                    timeout=(5, 10),
                    allow_redirects=False,
                    stream=True,
                ) as response:
                    status_code = response.status_code
                    content_type = response.headers.get(
                        "Content-Type", ""
                    ).lower()

                    page = {
                        "url": url,
                        "status_code": status_code,
                        "content_type": content_type,
                        "query_parameters": sorted(
                            parse_qs(
                                urlsplit(url).query,
                                keep_blank_values=True,
                            ).keys()
                        ),
                    }
                    pages.append(page)

                    try:
                        set_cookie_headers = response.raw.headers.getlist("Set-Cookie")
                    except AttributeError:
                        set_cookie = response.headers.get("Set-Cookie", "")
                        set_cookie_headers = [set_cookie] if set_cookie else []

                    alerts.extend(
                        inspect_cookies(url, set_cookie_headers)
                    )

                    if 300 <= status_code < 400:
                        location = response.headers.get("Location", "")
                        page["redirect_location"] = location

                        on_message(
                            f"HTTP {status_code} redirect observed; not followed. "
                            f"Location: {location or '(missing)'}"
                        )
                        continue
                    if status_code >= 400 and "text/html" not in content_type:
                        on_message(f"HTTP {status_code}; non-HTML response skipped.")
                        continue

                    if "text/html" not in content_type:
                        on_message("Skipped non-HTML response.")
                        continue

                    body = bytearray()

                    for chunk in response.iter_content(chunk_size=16384):
                        body.extend(chunk)

                        if len(body) > MAX_RESPONSE_BYTES:
                            raise ValueError(
                                "The response exceeded the size limit."
                            )

                        if time.monotonic() >= deadline:
                            raise TimeoutError(
                                "The scan time budget was reached."
                            )

                    encoding = response.encoding or "utf-8"

                    try:
                        html = bytes(body).decode(
                            encoding,
                            errors="replace",
                        )
                    except LookupError:
                        html = bytes(body).decode(
                            "utf-8",
                            errors="replace",
                        )

                    html_pages += 1
                    alerts.extend(inspect_headers(url, response.headers))
                    alerts.extend(inspect_error_disclosure(url, html))

                    if status_code >= 400:
                        on_message(f"HTTP {status_code}; HTML error response assessed.")
                        continue

                    parser = PageParser()
                    parser.feed(html)

                    base_url = urljoin(
                        url,
                        parser.base_href or url,
                    )

                    for form in parser.forms:
                        forms.append({
                            "page": url,
                            "action": urljoin(
                                base_url,
                                form["action"] or url,
                            ),
                            "method": form["method"],
                            "fields": form["fields"],
                        })

                    for href in parser.links:
                        if len(discovered) >= MAX_DISCOVERED_URLS:
                            break

                        candidate = urldefrag(
                            urljoin(base_url, href)
                        )[0]

                        try:
                            candidate = normalize_url(candidate)
                        except ValueError:
                            continue

                        if get_origin(candidate) != scope:
                            continue

                        if candidate not in discovered:
                            discovered.add(candidate)
                            pending.append(candidate)

            except (requests.RequestException, ValueError, TimeoutError) as exc:
                errors.append({
                    "url": url,
                    "error": str(exc),
                })
                on_message(f"Page error: {exc}")

            time.sleep(0.2)

    if html_pages == 0:
        on_message("No successful HTML page was assessed.")

    report = {
        "schema_version": 1,
        "engine": "Independent HTTP assessment",
        "target": target_url,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "assessment_status": (
            "incomplete"
            if errors or pending or html_pages == 0
            else "completed_within_scope"
        ),
        "coverage": {
            "requests_attempted": attempted,
            "html_pages_assessed": html_pages,
            "urls_discovered": len(discovered),
            "forms_discovered": len(forms),
            "page_limit": MAX_PAGES,
            "remaining_queued_urls": len(pending),
            "discovery_limit_reached": (
                len(discovered) >= MAX_DISCOVERED_URLS
            ),
            "checks": [
                "CSP header presence",
                "Frame protection header presence",
                "X-Content-Type-Options",
                "Server version-like disclosure",
                "HSTS header presence on HTTPS",
                "Cookie Secure, HttpOnly, and SameSite attributes",
                "Verbose error and stack trace disclosure",
            ],
            "not_tested": [
                "Active XSS",
                "SQL injection",
                "Authenticated pages",
                "JavaScript-rendered content",
                "Full OWASP Top 10 coverage",
            ],
        },
        "pages": pages,
        "forms": forms,
        "errors": errors,
        "alerts": alerts,
    }

    report_dir = Path(__file__).resolve().parents[2] / "Report"
    report_dir.mkdir(exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S-%f")
    report_path = report_dir / f"independent-{timestamp}.json"

    report_path.write_text(
        json.dumps(report, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    on_message(f"HTML pages assessed: {html_pages}")
    on_message(f"Forms discovered: {len(forms)}")
    on_message(f"Finding records: {len(alerts)}")
    on_message(f"Assessment status: {report['assessment_status']}")
    on_message(f"Report saved: {report_path}")

    return report, report_path