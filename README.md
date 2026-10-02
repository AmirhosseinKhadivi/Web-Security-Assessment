# Sentinel — Web Security Assessment Engine

![Sentinel Security Dashboard](app/static/hero-security.png)

Sentinel is an independent web security assessment platform developed as a Bachelor of Computer Engineering project.

The system discovers web application attack surfaces, analyzes security configurations, performs controlled vulnerability verification, and generates structured evidence-based reports through a professional local web dashboard.

The primary assessment pipeline is implemented independently and does not depend on OWASP ZAP for its core scanning process.

---

## Features

- Same-origin web crawling
- URL and form input discovery
- Request planning and coverage tracking
- Security header analysis
- Cookie security checks
- Verbose error disclosure detection
- Reflected XSS verification using Chrome
- Boolean-based SQL injection verification
- Open Redirect verification
- CORS misconfiguration verification
- HTTP reflection analysis
- Safe and unsafe laboratory controls
- Structured JSON reports
- Interactive dark cybersecurity dashboard
- Risk-based finding filtering
- Finding and input search
- Detailed technical evidence
- Explicit coverage and limitation reporting
- Separate risk and confidence values

---

## Architecture

```text
Target
  |
  v
Crawler
  |
  v
Input Discovery
  |
  v
Request Planning
  |
  +--> Security Misconfiguration Checks
  |
  +--> Reflected XSS Verification
  |
  +--> Boolean SQL Injection Verification
  |
  +--> Open Redirect Verification
  |
  +--> CORS Verification
  |
  +--> Reflection Analysis
  |
  v
Coverage + Evidence
  |
  v
JSON Report
  |
  v
Web Dashboard
```

Sentinel separates discovery, planning, active verification, findings, and coverage reporting instead of treating every observed condition as a confirmed vulnerability.

---

## Project Structure

```text
ProjectKarshenasi/
│
├── app/
│   ├── checks/
│   │   ├── boolean_sqli.py
│   │   ├── browser_xss.py
│   │   ├── cors.py
│   │   ├── open_redirect.py
│   │   └── reflection.py
│   │
│   ├── engine/
│   │   ├── assessment.py
│   │   ├── crawler.py
│   │   ├── input_inventory.py
│   │   └── request_planner.py
│   │
│   ├── static/
│   │   ├── app.css
│   │   ├── app.js
│   │   └── hero-security.png
│   │
│   ├── templates/
│   │   └── index.html
│   │
│   └── web.py
│
├── lab/
│   └── app.py
│
├── tests/
│   ├── test_headers.py
│   ├── test_reflection.py
│   └── test_request_planner.py
│
├── legacy/
│   ├── desktop/
│   ├── prototypes/
│   ├── tools/
│   └── zap/
│
├── tools/
├── requirements.txt
├── run.py
├── .gitignore
├── .gitattributes
└── README.md
```

---

## Requirements

The project was developed and validated with:

- Python 3.10+
- Google Chrome
- Flask
- Requests
- Selenium-based browser verification
- Windows 11

Python dependencies are listed in:

```text
requirements.txt
```

Chrome is required for browser-backed Reflected XSS verification.

---

## Installation

Clone the repository:

```bash
git clone <YOUR-REPOSITORY-URL>
```

Enter the project directory:

```bash
cd ProjectKarshenasi
```

Create a virtual environment:

```bash
python -m venv .venv
```

Activate it on Windows PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
```

Install the required packages:

```bash
pip install -r requirements.txt
```

---

## Running the Local Security Lab

Sentinel includes a deliberately vulnerable local Flask application for controlled security testing.

Start the laboratory application:

```powershell
python -m lab.app
```

The lab will run at:

```text
http://127.0.0.1:5001/
```

Keep this terminal open while testing Sentinel.

---

## Running the Sentinel Dashboard

Open another terminal in the project directory and activate the virtual environment.

Then run:

```powershell
python -m app.web
```

The Sentinel dashboard will be available at:

```text
http://127.0.0.1:5000/
```

Open the address in a browser.

The default local laboratory target is:

```text
http://127.0.0.1:5001/
```

Enter the target URL and select:

```text
Start Assessment
```

---

## Local Laboratory Routes

The included laboratory contains both vulnerable and safe control routes.

| Route | Purpose |
|---|---|
| `/unsafe?name=Alice` | Vulnerable Reflected XSS route |
| `/safe?name=Alice` | Escaped XSS control |
| `/sqli-unsafe?id=1` | Vulnerable Boolean SQL Injection route |
| `/sqli-safe?id=1` | Parameterized SQL Injection control |
| `/cookie-unsafe` | Insecure cookie attributes |
| `/cookie-safe` | Secure cookie control |
| `/error-unsafe` | Verbose traceback disclosure |
| `/error-safe` | Generic error response control |
| `/redirect-unsafe?next=https://example.com` | Vulnerable Open Redirect route |
| `/redirect-safe?next=https://example.com` | External redirect blocking control |
| `/cors-unsafe` | Arbitrary Origin CORS configuration |
| `/cors-safe` | Restricted CORS control |

The safe routes are used as negative controls to evaluate whether the scanner distinguishes vulnerable behavior from protected behavior.

---

## Assessment Pipeline

A Sentinel assessment is divided into several stages.

### 1. Crawling

The crawler discovers same-origin pages without blindly following external URLs.

It records:

- URLs
- HTTP status codes
- Content types
- Query parameters
- Forms
- Redirect responses

Redirect responses are recorded without automatically following their external destinations.

---

### 2. Input Discovery

The scanner builds an inventory of observed input points.

Currently identified input types include:

- URL query parameters
- HTML form fields

Input discovery itself is not considered a vulnerability finding.

---

### 3. Request Planning

Observed inputs are evaluated before active checks are performed.

The planner determines which inputs can safely participate in supported assessment stages.

Planning does not send additional HTTP requests.

---

## Security Checks

### Security Misconfiguration

Sentinel analyzes response configuration including:

- Content-Security-Policy
- Frame protection
- X-Content-Type-Options
- Server version-like disclosure
- HSTS on HTTPS targets
- Cookie Secure attribute
- Cookie HttpOnly attribute
- Cookie SameSite policy
- Verbose errors and Python traceback disclosure

Missing defensive headers are reported as security configuration findings and are not automatically treated as proof of exploitation.

---

### Reflected XSS

Supported local laboratory XSS routes are verified using Chrome.

Sentinel uses a unique JavaScript marker and confirms whether the marker actually executes in the browser.

Example classifications include:

```text
REFLECTED_XSS_CONFIRMED
ESCAPED_PROBE_NO_EXECUTION
RAW_SCRIPT_REFLECTED_NO_EXECUTION
```

Raw reflection alone is not treated as proof of JavaScript execution.

---

### Boolean SQL Injection

The SQL Injection stage performs controlled Boolean-response comparison against supported local laboratory routes.

The assessment compares:

```text
Baseline
True condition
False condition
Repeated baseline
```

A vulnerability is reported only when the observed result pattern is consistent with the expected Boolean SQL Injection behavior in the laboratory model.

Example:

```text
BOOLEAN_SQLI_BEHAVIOR_OBSERVED
```

The current SQL Injection detector is intentionally scoped to the included laboratory response model and is not presented as a universal SQL Injection scanner.

---

### Open Redirect

The Open Redirect stage tests whether a redirect parameter can send the client to an externally controlled destination.

The scanner sends a unique external destination using `example.com` and does not follow the resulting redirect.

Example classifications:

```text
OPEN_REDIRECT_CONFIRMED
EXTERNAL_REDIRECT_BLOCKED
REDIRECT_RESULT_INCONCLUSIVE
```

---

### CORS Misconfiguration

The CORS stage sends a unique untrusted `Origin` header to supported laboratory routes.

It evaluates:

```text
Access-Control-Allow-Origin
Access-Control-Allow-Credentials
```

Example classifications include:

```text
CORS_ARBITRARY_ORIGIN_WITH_CREDENTIALS
CORS_EXTERNAL_ORIGIN_BLOCKED
CORS_WILDCARD_ORIGIN_ALLOWED
```

A permissive CORS policy is reported based on observed configuration evidence. Sensitive-data exposure is not assumed unless demonstrated separately.

---

### Reflection Analysis

Query parameters may receive controlled text and HTML probes.

Possible results include:

```text
RAW_MARKUP_REFLECTED
HTML_ENCODED_MARKUP_REFLECTED
NO_REFLECTION_OBSERVED
MARKUP_RESPONSE_NOT_ASSESSABLE
```

Reflection analysis is separate from browser-based XSS verification.

A reflected HTML string does not automatically mean that JavaScript execution is possible.

---

## Assessment Results

The dashboard displays:

- Finding records
- Grouped findings
- Risk distribution
- Discovered pages
- Input records
- Form patterns
- Coverage information
- Technical evidence
- Input-check results
- Assessment logs

Findings can be filtered by:

```text
High
Medium
Low
Informational
```

They can also be searched using:

- Finding name
- URL
- Parameter
- Rule identifier
- Category
- Confidence

---

## Finding Details

Each finding may contain:

- Rule ID
- Finding title
- Risk
- Confidence
- Category
- URL
- HTTP method
- Parameter
- Evidence
- Description
- Recommended remediation
- Verification metadata

Example verification data may include:

```json
{
  "classification": "OPEN_REDIRECT_CONFIRMED",
  "status_code": 302,
  "location": "https://example.com/redirect-probe-..."
}
```

---

## Risk and Confidence

Sentinel treats risk and confidence as separate concepts.

**Risk** represents the security significance of the observed condition.

**Confidence** represents how strongly the collected evidence supports the reported finding.

A high-confidence finding does not necessarily require a High risk rating.

---

## Finding Records vs. Vulnerabilities

The number of finding records should not be interpreted as the number of unique vulnerabilities.

For example, a missing security header may be observed on several different URLs and therefore create several records.

The dashboard groups related records by:

```text
Rule identifier
Finding title
Risk level
```

Grouping records does not prove that they share the same root cause.

---

## Coverage Reporting

Sentinel explicitly records what was and was not assessed.

Coverage metadata can include:

- Number of crawler requests
- HTML pages assessed
- URLs discovered
- Forms discovered
- Input inventory status
- Request planning status
- Completed XSS routes
- Completed SQL Injection routes
- Completed Open Redirect routes
- Completed CORS routes
- Reflection-check status
- Discovery limits
- Assessment errors
- Not-tested areas

A successful assessment can use:

```text
completed_within_scope
```

This means that the configured assessment stages completed within their defined scope.

It does **not** mean that the target is completely secure.

---

## JSON Reports

Completed assessments generate structured JSON reports.

Reports include sections such as:

```text
target
assessment_status
coverage
pages
forms
errors
alerts
input_inventory
request_plan
xss_checks
sqli_checks
open_redirect_checks
cors_checks
reflection_checks
```

Reports generated during local use are stored in:

```text
Report/
```

The directory is intentionally excluded from Git version control.

Reports can also be downloaded directly from the Sentinel dashboard.

---

## Loading Existing Reports

The dashboard can open previously generated Sentinel JSON reports without starting a new scan.

Use:

```text
Open JSON Report
```

The selected report is processed locally by the dashboard.

---

## Security of the Dashboard

The local web interface includes additional protections such as:

- Local host restriction
- CSRF protection for POST requests
- Content-Security-Policy
- X-Content-Type-Options
- X-Frame-Options
- No-store cache policy
- Limited in-memory job state

The dashboard is designed as a local single-user application.

---

## Current Scope

The current implementation focuses on:

- Reflected XSS
- Boolean SQL Injection
- Security Misconfiguration
- Open Redirect
- CORS Misconfiguration
- Reflection behavior
- Input discovery
- Coverage reporting

The architecture is designed so that additional checks can be implemented as independent modules.

---

## Limitations

The current version does not claim complete web application security coverage.

Known limitations include:

- No authenticated crawling
- No complete JavaScript-rendered application crawling
- No full OWASP Top 10 coverage
- No automatic general-purpose form submission
- Limited active verification outside supported local laboratory routes
- Reflected XSS verification currently targets designated laboratory routes
- Boolean SQL Injection verification uses the known laboratory response model
- CORS testing does not currently exhaustively test every preflight, method, header, or null-Origin variation
- Open Redirect testing does not cover every possible scheme, parameter name, or bypass technique
- One active dashboard assessment job is maintained in memory at a time
- Absence of a finding must not be interpreted as proof of security

---

## Safe Testing Model

The included active checks are intentionally bounded.

The laboratory uses dedicated vulnerable and protected routes so scanner behavior can be evaluated without targeting third-party systems.

For arbitrary websites, security testing should only be performed with explicit authorization.

---

## Legacy Components

The `legacy/` directory contains earlier prototypes and previous experimental components used during project development.

This includes older desktop interfaces and OWASP ZAP-related experimentation.

These components are preserved for development history and comparison.

The current primary assessment pipeline is located under:

```text
app/
```

and operates independently from ZAP.

---

## Development Environment

The project was developed primarily using:

```text
Windows 11
Python 3.10
PyCharm
Google Chrome
Flask
```

The original development environment also included OWASP ZAP for early experimentation and comparison, but ZAP is not required by the final independent assessment engine.

---

## Testing Philosophy

The included security laboratory contains both positive and negative controls.

For example:

```text
/unsafe       -> vulnerable XSS behavior
/safe         -> protected XSS behavior

/sqli-unsafe  -> vulnerable SQL behavior
/sqli-safe    -> protected SQL behavior

/redirect-unsafe -> external redirect accepted
/redirect-safe   -> external redirect blocked

/cors-unsafe  -> arbitrary Origin accepted
/cors-safe    -> external Origin blocked
```

This approach helps evaluate both detection capability and false-positive behavior.

---

## Example Local Workflow

Terminal 1:

```powershell
cd E:\Projects\ProjectKarshenasi
.\.venv\Scripts\Activate.ps1
python -m lab.app
```

Terminal 2:

```powershell
cd E:\Projects\ProjectKarshenasi
.\.venv\Scripts\Activate.ps1
python -m app.web
```

Then open:

```text
http://127.0.0.1:5000/
```

and assess:

```text
http://127.0.0.1:5001/
```

---

## Git Workflow

After making changes:

```powershell
git status
git add .
git commit -m "Describe the change"
git push
```

Generated reports, virtual environments, IDE files, caches, and local backups are excluded through `.gitignore`.

---

## Ethical Use

This project is intended for:

- Academic research
- Security education
- Controlled laboratory testing
- Authorized security assessment

Only assess applications that you own or have explicit permission to test.

Unauthorized vulnerability testing may violate applicable laws, organizational policies, or service terms.

---

## Disclaimer

Sentinel is an academic security assessment project.

It is not a replacement for:

- Professional penetration testing
- Secure code review
- Threat modeling
- Manual vulnerability research
- Full enterprise security assessment

Scanner results should be interpreted together with their evidence, confidence, scope, and documented limitations.

---

## Academic Project

**Bachelor of Computer Engineering Project**

**Project Title:**  
Design and Implementation of an Intelligent Web Security Assessment System

**Platform Name:**  
Sentinel — Web Security Assessment Engine

The project demonstrates the design and implementation of an independent web security assessment pipeline combining attack-surface discovery, controlled vulnerability verification, evidence-based reporting, and an interactive web dashboard.

---

## Status

```text
Independent assessment engine    ✅
Web crawler                      ✅
Input discovery                  ✅
Request planning                 ✅
Security header checks           ✅
Cookie checks                    ✅
Error disclosure checks          ✅
Reflected XSS verification       ✅
Boolean SQL Injection checks     ✅
Open Redirect checks             ✅
CORS checks                      ✅
Reflection analysis              ✅
Structured JSON reporting        ✅
Professional web dashboard       ✅
Safe/unsafe laboratory controls  ✅
End-to-end validation            ✅
```

**Current status: Complete within the defined academic project scope.**