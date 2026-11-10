import sys, unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from investigator.analyzer import analyze_message, parse_dns_records

def sample(headers: str, dns: str = ""):
    return analyze_message(headers.replace("\n", "\r\n").encode(), dns)

class AnalyzerTests(unittest.TestCase):
    def test_normal_matching_sender_and_auth_pass(self):
        r = sample("From: Team <a@example.test>\nReply-To: <help@example.test>\nAuthentication-Results: mx; spf=pass; dkim=pass; dmarc=pass\nReceived: from relay [192.0.2.8] by mx")
        self.assertEqual(len(r["authentication"]), 3)
        self.assertFalse(any("Reply-To domain differs" in x for x in r["observations"]))
    def test_reply_to_domain_mismatch_flagged(self):
        r = sample("From: Team <a@example.test>\nReply-To: <help@other.test>")
        self.assertTrue(any("Reply-To domain differs" in x for x in r["observations"]))
    def test_authentication_fail_is_observation_not_verdict(self):
        r = sample("From: <a@example.test>\nAuthentication-Results: mx; dmarc=fail")
        self.assertTrue(any("authentication result is fail" in x for x in r["observations"]))
        self.assertIn("not proof", r["verdict"])
    def test_missing_received_and_auth_headers(self):
        r = sample("From: <a@example.test>")
        self.assertTrue(any("No Received" in x for x in r["observations"]))
        self.assertTrue(any("No parseable" in x for x in r["observations"]))
    def test_invalid_ipv4_not_reported(self):
        r = sample("Received: from bad [999.999.999.999] by mx")
        self.assertEqual(r["received"][0]["ip_addresses"], [])
    def test_dns_records_and_bad_line(self):
        records, warnings = parse_dns_records("example.test A 192.0.2.5\nthis is not a record")
        self.assertEqual(records[0]["type"], "A")
        self.assertEqual(records[1]["type"], "INDICATOR")
        self.assertEqual(len(warnings), 1)
    def test_empty_dns_is_not_claimed_nonexistent(self):
        r = sample("From: <a@example.test>")
        self.assertTrue(any("no DNS lookup was attempted" in x for x in r["observations"]))
    def test_received_multiple_hops_preserve_input_order(self):
        r = sample("Received: from hop1 [192.0.2.1] by hop2\nReceived: from hop0 [198.51.100.2] by hop1")
        self.assertEqual([x["input_order"] for x in r["received"]], [1, 2])

if __name__ == "__main__":
    unittest.main(verbosity=2)
