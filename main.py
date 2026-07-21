import argparse
import json
import csv
import sys
from checks.passwords import check_password_strength
from checks.secrets import scan_file_for_secrets
from checks.urls import check_url_risk
from checks.logs import parse_failed_logins

def export_results(data: list, fmt: str, output_file: str = None):
    if fmt == "json":
        output = json.dumps(data, indent=2)
    elif fmt == "csv":
        if not data:
            output = ""
        else:
            # Flattens dictionaries for basic CSV export
            keys = data[0].keys()
            import io
            stream = io.StringIO()
            writer = csv.DictWriter(stream, fieldnames=keys)
            writer.writeheader()
            for row in data:
                # Convert list values to string representation for CSV format
                formatted_row = {k: (", ".join(v) if isinstance(v, list) else v) for k, v in row.items()}
                writer.writerow(formatted_row)
            output = stream.getvalue()

    if output_file:
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(output)
        print(f"[+] Report saved to {output_file}")
    else:
        print("\n--- RESULTS ---")
        print(output)

def main():
    parser = argparse.ArgumentParser(description="Security Sanity Checker CLI Tool")
    subparsers = parser.add_parser_subparsers(dest="command", help="Module to run")

    # Password sub-command
    pwd_parser = subparsers.add_parser("password", help="Check password strength")
    pwd_parser.add_argument("-p", "--password", required=True, help="Password string to test")

    # Secrets sub-command
    sec_parser = subparsers.add_parser("secrets", help="Scan text/env file for exposed secrets")
    sec_parser.add_argument("-f", "--file", required=True, help="Path to file")

    # URL sub-command
    url_parser = subparsers.add_parser("url", help="Analyze URL risk indicators")
    url_parser.add_argument("-u", "--url", required=True, help="URL string to check")

    # Log sub-command
    log_parser = subparsers.add_parser("logs", help="Parse log file for failed login anomalies")
    log_parser.add_argument("-f", "--file", required=True, help="Path to auth/syslog file")
    log_parser.add_argument("-t", "--threshold", type=int, default=3, help="Alert threshold count")

    # Common export arguments
    for p in [pwd_parser, sec_parser, url_parser, log_parser]:
        p.add_argument("--format", choices=["json", "csv"], default="json", help="Output format")
        p.add_argument("-o", "--output", help="Output filename")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    results = []
    if args.command == "password":
        results = [check_password_strength(args.password)]
    elif args.command == "secrets":
        results = scan_file_for_secrets(args.file)
    elif args.command == "url":
        results = [check_url_risk(args.url)]
    elif args.command == "logs":
        results = parse_failed_logins(args.file, threshold=args.threshold)

    export_results(results, args.format, args.output)

if __name__ == "__main__":
    main()
