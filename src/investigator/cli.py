"""Command-line interface for the Email & Network Indicator Investigator."""
import argparse, json
from pathlib import Path
from .analyzer import analyze_files

def main():
    parser = argparse.ArgumentParser(description="Offline defensive analysis of supplied .eml headers and DNS records.")
    parser.add_argument("eml", help="Path to an .eml file")
    parser.add_argument("--dns", help="Optional text file containing supplied DNS records")
    parser.add_argument("--json", dest="json_path", help="Write machine-readable JSON report")
    args = parser.parse_args()
    result = analyze_files(args.eml, args.dns)
    rendered = json.dumps(result, indent=2, ensure_ascii=False)
    print(rendered)
    if args.json_path:
        Path(args.json_path).write_text(rendered + "\n", encoding="utf-8")
        print(f"\nJSON report written to {args.json_path}")

if __name__ == "__main__":
    main()
