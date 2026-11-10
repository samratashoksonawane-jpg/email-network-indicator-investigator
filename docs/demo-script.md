# Demo Video Script (5–8 minutes)

**Before recording:** Run the tests, use only the synthetic sample, close unrelated tabs, and ensure no personal data or secrets are visible.

## 0:00–0:40 — Introduction
“Hello. This project is the Email and Network Indicator Investigation Helper. It parses synthetic email headers and supplied DNS records to organise evidence. It does not decide that a message is malicious.”

## 0:40–1:30 — Problem and design
“Email investigations involve sender identity fields, authentication results and routing headers. These can be incomplete or misleading. The tool uses Python's standard email parser, domain extraction, IP validation and a simple DNS-record parser.”

## 1:30–2:30 — Run the application
Show terminal:
`PYTHONPATH=src python -m investigator samples/synthetic.eml --dns samples/dns-records.txt --json report.json`
Explain the fields in the JSON output.

## 2:30–3:30 — Investigate observations
Show From versus Reply-To, SPF/DKIM/DMARC results and Received entries. Explain that a domain mismatch or DMARC fail is a lead, not proof. Explain why Received trust boundaries matter.

## 3:30–4:45 — Demonstrate tests
Run:
`python -m unittest discover -s tests -v`
Show the eight tests and explain one edge case: invalid IP syntax is rejected by `ipaddress`.

## 4:45–5:45 — Wireshark practice
Open the chosen authorised sample capture offline. Show one display filter from the Wireshark documentation and explain what packet fields it reveals. State the capture source and any terms/sensitivity checks. Do not show unrelated personal traffic.

## 5:45–6:45 — Failure and limitation
Explain the failure case: regex alone could accept an invalid IP, so validation was added. State limitations: no live DNS, no cryptographic verification, no PCAP parser in this version and no attribution.

## 6:45–7:15 — Conclusion
“The project makes supplied evidence easier to review and documents uncertainty. Future work could add a controlled PCAP workflow and a graphical `.eml` upload feature.”
