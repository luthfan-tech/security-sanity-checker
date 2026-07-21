# Security Sanity Checker CLI

A light, practical Python command-line tool for basic security checks: password strength validation, secret detection, URL risk analysis, and log parsing.

## Features
- **Password Evaluator**: Identifies weak length, complexity gaps, and common patterns.
- **Secret Scanner**: Uses regex to flag exposed API keys, secret variables, and private keys.
- **URL Risk Inspector**: Detects IP hostnames, URL shorteners, and high-risk TLDs.
- **Log Anomaly Parser**: Aggregates failed SSH/login events to highlight potential brute-force activity.
- **Reporting**: Exports to clean JSON or CSV formats.

## Usage Examples

### 1. Check Password Strength
```bash
python main.py password -p "admin123" --format json

2. Scan File for Secrets
Bash
python main.py secrets -f sample_data/sample.env -o report.json
3. Analyze URL
Bash
python main.py url -u "[http://bit.ly/3xYz12](http://bit.ly/3xYz12)"
4. Parse Log for Failed Logins
Bash
python main.py logs -f sample_data/auth.log -t 2 --format csv
