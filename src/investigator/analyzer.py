"""Defensive, offline parsing of supplied email headers and DNS text records."""
from __future__ import annotations
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from pathlib import Path
import ipaddress
import re

AUTH_RE = re.compile(r'\b(spf|dkim|dmarc)\s*=\s*(pass|fail|softfail|neutral|none|temperror|permerror)\b', re.I)
DNS_TYPES = {"A", "AAAA", "MX", "TXT", "NS", "PTR", "CNAME"}

def _domain(value: str) -> str | None:
    _, address = parseaddr(value or "")
    if "@" not in address:
        return None
    domain = address.rsplit("@", 1)[1].strip().rstrip(".").lower()
    return domain or None

def _domains(value: str) -> list[str]:
    found = re.findall(r'[A-Z0-9._%+-]+@(?:[A-Z0-9-]+\.)+[A-Z]{2,}', value or "", re.I)
    return sorted({x.rsplit("@", 1)[1].rstrip(".").lower() for x in found})

def _ips(value: str) -> list[str]:
    candidates = re.findall(r'(?<![A-Fa-f0-9:.])(?:\d{1,3}\.){3}\d{1,3}(?!\d)|(?<![A-Fa-f0-9:])(?:[A-Fa-f0-9]{0,4}:){2,7}[A-Fa-f0-9]{0,4}(?![A-Fa-f0-9:])', value or "")
    valid = set()
    for candidate in candidates:
        try:
            valid.add(str(ipaddress.ip_address(candidate)))
        except ValueError:
            pass
    return sorted(valid)

def parse_dns_records(text: str) -> tuple[list[dict], list[str]]:
    records, warnings = [], []
    for number, raw in enumerate((text or "").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 2)
        if len(parts) != 3 or parts[1].upper() not in DNS_TYPES:
            warnings.append(f"Line {number}: unrecognised DNS record format; retained as an unparsed indicator.")
            records.append({"line": number, "type": "INDICATOR", "raw": line})
            continue
        records.append({"line": number, "name": parts[0].rstrip(".").lower(),
                        "type": parts[1].upper(), "value": parts[2]})
    return records, warnings

def analyze_message(raw: bytes, dns_text: str = "", analyst_notes: str = "") -> dict:
    msg = BytesParser(policy=policy.default).parsebytes(raw)
    fields = {key: str(msg.get(key, "")) or None for key in
              ("From", "Reply-To", "Return-Path", "Message-ID", "Date", "Subject")}
    sender_domains = {}
    for key in ("From", "Reply-To", "Return-Path", "Message-ID"):
        value = fields.get(key) or ""
        ds = _domains(value)
        if key == "Message-ID" and "@" in value:
            mid_domain = value.rsplit("@", 1)[1].rstrip("> ").lower()
            if re.fullmatch(r"(?:[a-z0-9-]+\.)+[a-z]{2,}", mid_domain):
                ds = [mid_domain]
        sender_domains[key] = ds

    auth_headers = [str(v) for v in msg.get_all("Authentication-Results", [])]
    auth_headers += [str(v) for v in msg.get_all("Received-SPF", [])]
    auth = [{"mechanism": m.group(1).upper(), "result": m.group(2).lower(), "source": h}
            for h in auth_headers for m in AUTH_RE.finditer(h)]
    received = [str(v) for v in msg.get_all("Received", [])]
    routing = [{"input_order": i + 1, "header": h, "ip_addresses": _ips(h)}
               for i, h in enumerate(received)]
    dns_records, dns_warnings = parse_dns_records(dns_text)

    flags = []
    from_domains = sender_domains["From"]
    for key in ("Reply-To", "Return-Path"):
        other = sender_domains[key]
        if other and from_domains and not set(other).intersection(from_domains):
            flags.append(f"{key} domain differs from the From domain. This can be legitimate; verify expected mail-flow arrangements.")
    if any(x["result"] == "fail" for x in auth):
        flags.append("At least one supplied authentication result is fail. Confirm the evaluated domain and whether the Authentication-Results header is from a trusted receiver.")
    if any(x["result"] in {"temperror", "permerror"} for x in auth):
        flags.append("An authentication evaluation error is present; an error is not equivalent to confirmed spoofing.")
    if not received:
        flags.append("No Received headers supplied; routing reconstruction is unavailable.")
    if not auth:
        flags.append("No parseable SPF/DKIM/DMARC results supplied.")
    if not dns_records:
        flags.append("No DNS records supplied; no DNS lookup was attempted.")

    return {
        "fields": fields, "sender_domains": sender_domains, "authentication": auth,
        "received": routing, "dns_records": dns_records, "dns_warnings": dns_warnings,
        "observations": flags, "analyst_notes": analyst_notes,
        "limitations": [
            "Header values are supplied evidence and may be forged, altered, or incomplete.",
            "Authentication results are copied from the message; they are not independently verified.",
            "Received fields are shown in input order. Establish trusted relay boundaries before inferring origin.",
            "DNS data is parsed only from supplied text; absence here does not prove a record is absent.",
            "Reserved/documentation IP addresses are not evidence of attacker infrastructure."
        ],
        "verdict": "No obvious inconsistency identified by these basic checks; this does not establish safety."
                   if not flags else "Review the observations. They are leads for investigation, not proof of maliciousness."
    }

def analyze_files(eml_path: str, dns_path: str | None = None) -> dict:
    raw = Path(eml_path).read_bytes()
    dns_text = Path(dns_path).read_text(encoding="utf-8") if dns_path else ""
    return analyze_message(raw, dns_text)
