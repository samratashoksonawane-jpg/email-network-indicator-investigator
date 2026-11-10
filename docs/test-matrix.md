# Test Matrix

Tested using Python's built-in `unittest` framework. Execute with `python -m unittest discover -s tests -v`.

| ID | Case | Expected result | Evidence |
|---|---|---|---|
| T01 | Normal headers with matching sender domains and SPF/DKIM/DMARC pass | Three auth results parsed; no Reply-To mismatch | Automated test `test_normal_matching_sender_and_auth_pass` |
| T02 | Reply-To uses a different domain | Observation raised; no automatic malicious verdict | `test_reply_to_domain_mismatch_flagged` |
| T03 | DMARC fail supplied | Failure reported as an observation | `test_authentication_fail_is_observation_not_verdict` |
| T04 | Received and authentication headers missing | Missing-evidence limitations shown | `test_missing_received_and_auth_headers` |
| T05 | Malformed IPv4 address in Received | Invalid address rejected | `test_invalid_ipv4_not_reported` |
| T06 | Valid DNS record plus malformed line | Valid record parsed; malformed line retained and warning added | `test_dns_records_and_bad_line` |
| T07 | No DNS input | Explicitly says no lookup was attempted | `test_empty_dns_is_not_claimed_nonexistent` |
| T08 | Multiple Received fields | Input order preserved | `test_received_multiple_hops_preserve_input_order` |

## Result recording
Run the command above on the machine used for submission and retain the terminal output or screenshot. The automated tests validate parser behaviour; they do not validate real-world attribution or security outcomes.
