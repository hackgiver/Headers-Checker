# Security Headers Checker

A Python script for pentesting that checks whether key security response headers are present on a given URL. Outputs a color-coded report with current values and recommended fixes for missing headers.

---

## Headers checked

- Strict-Transport-Security (HSTS)
- Content-Security-Policy
- X-XSS-Protection
- X-Frame-Options
- X-Content-Type-Options
- Cache-Control
- Referrer-Policy
- Permissions-Policy

---

## Requirements

Python 3.6 or higher is required. Install the dependency with:

```bash
pip install requests
```

---

## Usage

```bash
python3 header_checker.py <url> [--no-verify]
```

### Arguments

| Argument | Description |
|---|---|
| `url` | Target URL. If no scheme is provided, `https://` is added automatically. |
| `--no-verify` | Optional. Skips SSL certificate verification. Useful in lab environments or when testing self-signed certificates. |

### Examples

```bash
# Basic usage
python3 header_checker.py https://example.com

# Without explicit scheme
python3 header_checker.py example.com

# Skip SSL verification
python3 header_checker.py https://example.com --no-verify
```

---

## Output

For each header the script reports:

- Present: shows the current value returned by the server.
- Missing: shows a recommended secure value to implement.

At the end of the report a summary is displayed with the number of present and missing headers, along with a percentage score color-coded as follows:

- 75% or above: green
- 50% to 74%: yellow
- Below 50%: red

The full list of response headers received from the server is also printed, which can be useful when writing a pentest report.

---

## Disclaimer

This tool is intended for use on systems you own or have explicit permission to test. Unauthorized use against third-party systems may be illegal.
