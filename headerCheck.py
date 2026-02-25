#!/usr/bin/env python3
"""
Security Headers Checker - Pentest Tool
Checks presence AND secure configuration of security headers.
Usage: python3 header_checker.py <url> [--no-verify]
"""

import sys
import re
import argparse
import requests

# ANSI colors
GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

def check_hsts(value):
    """max-age >= 31536000 and includeSubDomains present."""
    match = re.search(r'max-age=(\d+)', value, re.IGNORECASE)
    if not match:
        return False, "max-age directive is missing"
    max_age = int(match.group(1))
    if max_age < 31536000:
        return False, f"max-age is {max_age}, should be >= 31536000"
    if 'includesubdomains' not in value.lower():
        return False, "includeSubDomains directive is missing"
    return True, "max-age >= 31536000 and includeSubDomains present"

def check_csp(value):
    """default-src must be present and not allow unsafe-inline/unsafe-eval/wildcard *."""
    if 'default-src' not in value.lower():
        return False, "default-src directive is missing"
    issues = []
    if "'unsafe-inline'" in value.lower():
        issues.append("'unsafe-inline' is present (risky)")
    if "'unsafe-eval'" in value.lower():
        issues.append("'unsafe-eval' is present (risky)")
    if re.search(r"default-src\s+\*", value, re.IGNORECASE):
        issues.append("wildcard * as default-src (risky)")
    if issues:
        return False, "; ".join(issues)
    return True, "default-src is defined without unsafe directives"

def check_xss(value):
    """Value should be '1' or '1; mode=block'."""
    v = value.strip()
    if v.startswith("1"):
        return True, "XSS filter enabled"
    if v == "0":
        return False, "XSS filter is explicitly disabled"
    return False, f"Unexpected value: {value}"

def check_xfo(value):
    """DENY or SAMEORIGIN are acceptable. ALLOW-FROM is not."""
    v = value.strip().upper()
    if v == "DENY":
        return True, "DENY (most secure)"
    if v == "SAMEORIGIN":
        return True, "SAMEORIGIN (acceptable)"
    if v.startswith("ALLOW-FROM"):
        return False, "ALLOW-FROM is deprecated and not supported by most browsers"
    return False, f"Unknown value: {value}"

def check_xcto(value):
    """Must be exactly 'nosniff'."""
    if value.strip().lower() == "nosniff":
        return True, "nosniff is set"
    return False, f"Expected 'nosniff', got '{value}'"

def check_cache(value):
    """Must contain no-store."""
    if 'no-store' in value.lower():
        return True, "no-store is present"
    return False, "no-store directive is missing (sensitive data may be cached)"

def check_referrer(value):
    """no-referrer or same-origin are the safest options."""
    v = value.strip().lower()
    safe = {"no-referrer", "same-origin", "strict-origin", "strict-origin-when-cross-origin"}
    unsafe = {"unsafe-url", "no-referrer-when-downgrade", "origin-when-cross-origin"}
    if v in safe:
        return True, f"'{v}' is a safe policy"
    if v in unsafe:
        return False, f"'{v}' may leak sensitive URL information"
    return False, f"Unknown or overly permissive value: '{value}'"

def check_permissions(value):
    """
    Check that the policy is not a blanket allow-all.
    A good policy explicitly defines features; wildcards or empty policy are risky.
    """
    v = value.strip().lower()
    if not v:
        return False, "Policy is empty"
    # If every feature uses a wildcard (*) it's essentially allow-all
    directives = [d.strip() for d in v.split(',')]
    wildcard_count = sum(1 for d in directives if '=*' in d or '=(*)' in d)
    if wildcard_count == len(directives):
        return False, "All features use wildcard (*) — effectively allow-all"
    # At least one feature is explicitly restricted
    deny_count = sum(1 for d in directives if d.endswith('=()'))
    if deny_count == 0:
        return False, "No features are explicitly denied — review and restrict unused features"
    return True, f"{deny_count} feature(s) explicitly denied, {len(directives) - deny_count} allowed"

HEADERS_TO_CHECK = {
    "Strict-Transport-Security": {
        "desc": "Enforces HTTPS (HSTS)",
        "rec":  "max-age=31536000; includeSubDomains",
        "check": check_hsts,
    },
    "Content-Security-Policy": {
        "desc": "Prevents XSS / data injection attacks",
        "rec":  "default-src https: 'self'",
        "check": check_csp,
    },
    "X-XSS-Protection": {
        "desc": "Legacy XSS filter (browsers)",
        "rec":  "1; mode=block",
        "check": check_xss,
    },
    "X-Frame-Options": {
        "desc": "Prevents Clickjacking",
        "rec":  "DENY (or SAMEORIGIN)",
        "check": check_xfo,
    },
    "X-Content-Type-Options": {
        "desc": "Blocks MIME-sniffing",
        "rec":  "nosniff",
        "check": check_xcto,
    },
    "Cache-Control": {
        "desc": "Prevents caching of sensitive data",
        "rec":  "no-store",
        "check": check_cache,
    },
    "Referrer-Policy": {
        "desc": "Controls Referrer header leakage",
        "rec":  "no-referrer (or same-origin)",
        "check": check_referrer,
    },
    "Permissions-Policy": {
        "desc": "Restricts browser feature access",
        "rec":  "Define minimum allowed features and deny the rest, e.g. geolocation=(), microphone=(), camera=()",
        "check": check_permissions,
    },
}

STATUS = {
    "present_secure":   f"{GREEN}[✔] PRESENT & SECURE{RESET}",
    "present_insecure": f"{YELLOW}[!] PRESENT BUT INSECURE{RESET}",
    "missing":          f"{RED}[✘] MISSING{RESET}",
}

def normalize_url(url):
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url

def check_headers(url, verify_ssl=True):
    try:
        resp = requests.get(url, timeout=10, verify=verify_ssl,
                            allow_redirects=True,
                            headers={"User-Agent": "SecurityHeadersChecker/1.0"})
    except requests.exceptions.SSLError:
        print(f"{YELLOW}[!] SSL error. Retry with --no-verify to skip certificate validation.{RESET}")
        sys.exit(1)
    except requests.exceptions.ConnectionError:
        print(f"{RED}[!] Could not connect to {url}{RESET}")
        sys.exit(1)
    except requests.exceptions.Timeout:
        print(f"{RED}[!] Connection timed out.{RESET}")
        sys.exit(1)

    resp_headers_lower = {k.lower(): v for k, v in resp.headers.items()}

    print(f"\n{BOLD}{CYAN}{'='*65}{RESET}")
    print(f"{BOLD}{CYAN}  Security Headers Report{RESET}")
    print(f"{BOLD}{CYAN}{'='*65}{RESET}")
    print(f"  {BOLD}URL:{RESET}    {resp.url}")
    print(f"  {BOLD}Status:{RESET} {resp.status_code}")
    print(f"{BOLD}{CYAN}{'='*65}{RESET}\n")

    counts = {"secure": 0, "insecure": 0, "missing": 0}

    for header, info in HEADERS_TO_CHECK.items():
        value = resp_headers_lower.get(header.lower())

        if value is None:
            counts["missing"] += 1
            print(f"  {STATUS['missing']} {BOLD}{header}{RESET}")
            print(f"      {BOLD}Info:{RESET} {info['desc']}")
            print(f"      {BOLD}Fix:{RESET}  {header}: {info['rec']}\n")
        else:
            secure, detail = info["check"](value)
            if secure:
                counts["secure"] += 1
                status_label = STATUS["present_secure"]
            else:
                counts["insecure"] += 1
                status_label = STATUS["present_insecure"]

            print(f"  {status_label} {BOLD}{header}{RESET}")
            print(f"      {BOLD}Value:{RESET}  {value}")
            print(f"      {BOLD}Check:{RESET}  {detail}")
            if not secure:
                print(f"      {BOLD}Fix:{RESET}    {header}: {info['rec']}")
            print()

    # Summary
    total = len(HEADERS_TO_CHECK)
    score = int((counts["secure"] / total) * 100)
    color = GREEN if score >= 75 else YELLOW if score >= 50 else RED

    print(f"{BOLD}{CYAN}{'='*65}{RESET}")
    print(f"  {BOLD}Results:{RESET}  "
          f"{GREEN}{counts['secure']} secure{RESET}  "
          f"{YELLOW}{counts['insecure']} insecure{RESET}  "
          f"{RED}{counts['missing']} missing{RESET}  "
          f"(out of {total})")
    print(f"  {BOLD}Score:{RESET}    {color}{score}%{RESET}")
    print(f"{BOLD}{CYAN}{'='*65}{RESET}\n")

    # All response headers
    print(f"{BOLD}{YELLOW}  All response headers received:{RESET}")
    for k, v in resp.headers.items():
        print(f"    {k}: {v}")
    print()

def main():
    parser = argparse.ArgumentParser(description="Security Headers Checker for pentesting")
    parser.add_argument("url", help="Target URL (e.g. https://example.com)")
    parser.add_argument("--no-verify", action="store_true", help="Skip SSL certificate verification")
    args = parser.parse_args()

    url = normalize_url(args.url)
    check_headers(url, verify_ssl=not args.no_verify)

if __name__ == "__main__":
    main()
