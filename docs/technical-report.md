# Email & Network Indicator Investigation Helper
## Technical Report

**Project type:** Defensive cybersecurity analysis tool  
**Version:** 1.0.0  
**Data policy:** Synthetic/offline input only  
**Date:** 10 November 2026

## 1. Abstract
This project implements a lightweight offline helper for investigating supplied email headers and DNS indicators. It extracts sender-related domains, records SPF/DKIM/DMARC results as stated in message headers, displays Received routing fields and parses supplied DNS records. The output is an evidence summary with cautious observations and explicit limitations. It does not claim that a message is malicious or benign and does not independently verify DNS or authentication.

## 2. Problem statement and objectives
Email investigations often involve multiple clues spread across message headers, DNS records and network observations. Beginners may over-trust visible sender fields, treat an authentication failure as proof of phishing, or infer an origin IP from an untrusted Received line. The objective is to make supplied evidence easier to inspect while preserving uncertainty.

Objectives:
- Parse a supplied `.eml` message using a standard email parser.
- Extract sender domains from From, Reply-To, Return-Path and Message-ID.
- Summarise authentication results included in Authentication-Results and Received-SPF.
- Preserve Received header order and extract syntactically valid IP addresses.
- Parse supplied A, AAAA, MX, TXT, NS, PTR and CNAME records.
- Flag selected inconsistencies and missing evidence without asserting attribution.
- Provide repeatable tests and a machine-readable JSON report.

## 3. Scope and assumptions
The tool is an offline parser. It assumes the analyst has permission to inspect the input and that supplied DNS text is already collected. It does not perform DNS resolution, SPF evaluation, DKIM signature verification, DMARC policy evaluation, IP reputation checks, packet dissection, malware analysis or mailbox access. The `.test` domain and documentation IP ranges in sample data are synthetic.

## 4. Design
The implementation uses Python 3.10+ standard-library modules:
- `email.parser.BytesParser` and `email.policy` for parsing message structure.
- `email.utils.parseaddr` for extracting mailbox addresses.
- `re` for recognition of authentication tokens and IP candidates.
- `ipaddress` to reject malformed IP addresses.
- `argparse` and `json` for a reproducible command-line interface and JSON output.
The analysis function returns structured data: parsed fields, sender domains, authentication observations, routing entries, DNS records, warnings, analyst notes and limitations. The CLI serialises this object to JSON.

### Data flow
1. Analyst supplies `.eml` and optional DNS text file.
2. Parser reads headers and extracts selected fields.
3. Normalisation extracts domains and validates IP address syntax.
4. Rule checks identify domain mismatches and authentication failures/errors.
5. Results are emitted as terminal JSON and optionally saved to a file.

## 5. Implementation details
Header fields are read using the standard email parser, which supports repeated headers such as Received and Authentication-Results. Authentication tokens are copied as reported; the tool does not trust them as verified results. Received fields are kept in their supplied order rather than claiming to know which relay is trustworthy. DNS records use a simple `name TYPE value` text format. Unrecognised lines are preserved as indicators with a warning instead of being silently discarded.

The initial browser mock-up is included in `web/` as a simple visual demonstration. The Python CLI is the reproducible reference implementation and test target.

## 6. Testing method and results
Eight unit tests cover a normal case, Reply-To mismatch, authentication failure, missing headers, invalid IP, malformed DNS line, absent DNS evidence and multiple Received fields. Run:
```bash
python -m unittest discover -s tests -v
```
Record the actual terminal output at submission time. Passing unit tests demonstrate expected parser behaviour on these fixtures; they do not demonstrate detection accuracy against all phishing campaigns.

## 7. Security interpretation
A different Reply-To domain may be legitimate for support desks, mailing platforms or outsourced services. SPF/DKIM/DMARC results depend on which domain was evaluated and whether the Authentication-Results header was inserted by a trusted receiving system. A Received chain can contain forged entries before a trusted boundary. An IP address in a message header is not automatically the sender's true origin. DNS observations can be time-sensitive and must be timestamped and sourced separately.

MITRE ATT&CK's Phishing technique (T1566) can provide behavioural context when there is independent evidence of phishing behaviour. Mapping an isolated header anomaly to ATT&CK is not proof of an attack.

## 8. Limitations
- No live DNS or reputation lookup.
- No cryptographic DKIM signature verification or SPF/DMARC recomputation.
- No parsing of PCAP files in the Python implementation.
- No determination of trusted Received boundaries.
- Simple DNS text format; not a full zone-file parser.
- Heuristic observations may produce false positives and false negatives.
- No guarantee of complete RFC coverage.

## 9. Ethical and safe-use considerations
Use synthetic samples or data that the analyst is authorised to inspect. Wireshark sample captures must be selected with attention to their licence, terms and sensitivity. Never include credentials, personal data, confidential headers or unapproved targets in public repository examples or demo recordings. Scapy is not required for this version; if used in a future lab, restrict packet generation to a local isolated environment.

## 10. Future work
Potential extensions include `.eml` upload in a graphical interface, a validated PCAP workflow using Wireshark/tshark, timestamped DNS collection, configurable trusted relay boundaries, richer parsing tests, and HTML/PDF report export. Each extension should preserve source provenance and distinguish observed facts from analyst hypotheses.

## 11. References
1. Wireshark, *Wireshark Documentation*, https://www.wireshark.org/docs/ (accessed 2026-11-10).
2. Wireshark Wiki, *Sample Captures*, https://wiki.wireshark.org/SampleCaptures (accessed 2026-11-10).
3. Scapy, *Documentation*, https://scapy.readthedocs.io/en/latest/ (accessed 2026-11-10).
4. MITRE, *MITRE ATT&CK*, https://attack.mitre.org/ (accessed 2026-11-10).
5. IETF, *RFC 5322: Internet Message Format*, https://www.rfc-editor.org/rfc/rfc5322 (accessed 2026-11-10).
6. IETF, *RFC 7208: Sender Policy Framework*, https://www.rfc-editor.org/rfc/rfc7208 (accessed 2026-11-10).
7. IETF, *RFC 7489: Domain-based Message Authentication, Reporting, and Conformance*, https://www.rfc-editor.org/rfc/rfc7489 (accessed 2026-11-10).

## 12. Conclusion
The project provides a small, reproducible way to structure supplied email and DNS evidence. Its value is transparent parsing and careful interpretation, not automated threat verdicts. Further packet-level integration should be added only with a documented sample capture and repeatable offline procedure.

## Wireshark Practical Experiment: mDNS Analysis

### Objective
To inspect DNS-related network traffic using Wireshark and understand how multicast DNS queries and responses work.

### Tools Used
- Wireshark 4.6.9
- Npcap 1.88
- Official Wireshark sample capture: mDNS3.cap

### Display Filters
- `nbns` — to inspect NetBIOS Name Service traffic.
- `mdns` — to inspect multicast DNS traffic.
- `dns` — tested, but no packets were displayed with this filter in the selected capture.

### Experiment Results

**1. NBNS inspection**

Observed UDP traffic using port 137. The capture showed NetBIOS name queries sent to a broadcast destination.

**2. mDNS query — Packet 21**

- Query name: m1.local
- Query type: A
- Query class: IN
- Questions: 1
- Answer records: 0
- Destination: 224.0.0.251
- UDP destination port: 5353

**3. mDNS response — Packet 25**

- Response name: m1.local
- Record type: A
- Returned IPv4 address: 111.111.111.111
- Answer records: 1
- Response status: No error
- Response time: 1.220139 seconds

### Conclusion

The experiment demonstrated how Wireshark can inspect multicast DNS traffic, identify DNS queries, and associate responses with their corresponding requests. It also demonstrated the use of display filters to isolate network protocols.

The sample contains synthetic/documentation-style addresses and should not be treated as evidence of malicious activity or a real-world host.
