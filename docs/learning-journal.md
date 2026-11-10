# Learning Journal

> Personalise these entries after you run the project and complete the Wireshark exercise. Do not claim experiences you did not actually have.

## Five concepts learned

1. **Email header trust:** From is a display-level identity clue, not cryptographic proof of who sent a message. I learned to compare From, Reply-To and Return-Path while considering legitimate mailing workflows.
2. **SPF, DKIM and DMARC:** These mechanisms answer different questions. A result copied from Authentication-Results is only as trustworthy as the receiving system that added it; this tool does not recompute or verify the result.
3. **Received routing chain:** Receiving servers normally prepend Received fields. I learned not to call the earliest visible IP the origin without identifying trusted relays.
4. **DNS record interpretation:** A, AAAA, MX and TXT records have different purposes. A missing line in a supplied text file does not mean a DNS record does not exist.
5. **Evidence versus inference:** An anomaly can justify further investigation but does not prove maliciousness. ATT&CK is a behaviour knowledge base, not a verdict engine.

## Mistake / failure and diagnosis
A common implementation mistake is accepting any dotted-quad string as an IP address. Regex alone can match impossible values such as `999.999.999.999`. The implementation therefore validates candidates with Python's `ipaddress` module and includes a test that rejects the invalid value.

## What changed
I separated parsing from presentation, preserved raw Received evidence, added explicit limitations to the result, and wrote tests for missing and malformed inputs. This makes the output more reproducible and reduces overconfident conclusions.

## Reflection to complete after practical work
- Wireshark capture selected and licence/sensitivity checked:
- Display filter tested:
- What I observed in the capture:
- One issue encountered and how I diagnosed it:
- Screenshot or terminal evidence saved:
