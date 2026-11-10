# Email & Network Indicator Investigator

A small defensive, offline tool for parsing supplied synthetic email headers (`.eml`) and DNS text records. It summarizes sender-related domains, authentication results, `Received` routing clues, and supplied DNS records. It reports observations, not conclusions.

## Requirements
- Python 3.10 or newer
- No third-party Python packages required

## Setup
```bash
git clone https://github.com/samratashoksonawane-jpg/email-network-indicator-investigator.git
cd email-network-indicator-investigator
python -m unittest discover -s tests -v
```

## Usage
```bash
PYTHONPATH=src python -m investigator samples/synthetic.eml --dns samples/dns-records.txt --json report.json
```
On Windows PowerShell:
```powershell
$env:PYTHONPATH = "src"
python -m investigator samples/synthetic.eml --dns samples/dns-records.txt --json report.json
```

## What it does
- Parses common message headers with Python's standard-library email parser.
- Extracts sender-related domains from From, Reply-To, Return-Path, and Message-ID.
- Displays SPF/DKIM/DMARC outcomes as written in supplied Authentication-Results / Received-SPF headers.
- Lists Received headers in supplied input order and extracts syntactically valid IP addresses.
- Parses supplied A, AAAA, MX, TXT, NS, PTR, and CNAME records.
- Flags limited mismatches and missing evidence; exports JSON.

## What it does not do
No live DNS queries, reputation lookups, mailbox access, packet capture decoding, sender verification, or malware verdicts. Wireshark is a separate offline traffic-analysis demonstration. Do not treat a header anomaly or ATT&CK mapping as proof of an attack.

## Project layout
- `src/investigator/` — analysis library and CLI
- `tests/` — automated unit tests
- `samples/` — synthetic `.eml` and DNS input
- `web/` — browser-based demonstration interface
- `docs/` — report, test matrix, learning journal, demo script

## Safe practice
Only use synthetic data or captures you are authorised to inspect. Use Wireshark sample captures according to their terms and sensitivity. Do not upload secrets, personal data, or unapproved targets.

## References
- Wireshark documentation: https://www.wireshark.org/docs/ (accessed 2026-11-10)
- Wireshark Sample Captures: https://wiki.wireshark.org/SampleCaptures (accessed 2026-11-10)
- Scapy documentation: https://scapy.readthedocs.io/en/latest/ (accessed 2026-11-10)
- MITRE ATT&CK: https://attack.mitre.org/ (accessed 2026-11-10)
- RFC 5322, Internet Message Format: https://www.rfc-editor.org/rfc/rfc5322 (accessed 2026-11-10)
- RFC 7208, Sender Policy Framework: https://www.rfc-editor.org/rfc/rfc7208 (accessed 2026-11-10)
- RFC 7489, Domain-based Message Authentication, Reporting, and Conformance: https://www.rfc-editor.org/rfc/rfc7489 (accessed 2026-11-10)

## License
MIT. See `LICENSE`.
