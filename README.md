# Sentinel — Web Security Assessment Engine

Sentinel is an independent web security assessment platform developed as a Bachelor of Computer Engineering project.

The system discovers web application attack surfaces, analyzes security configurations, performs controlled vulnerability verification, and generates structured evidence-based reports through a professional local web dashboard.

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
- Structured JSON reports
- Interactive dark cybersecurity dashboard
- Risk filtering and finding search
- Detailed technical evidence for findings

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