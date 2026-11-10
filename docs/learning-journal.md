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

# Learning Journal — Wireshark Investigation

## Concepts Learned

### 1. Packet Analysis
I learned how Wireshark captures and displays network packets and how to inspect individual packets.

### 2. Display Filters
I learned to use Wireshark display filters such as `dns`, `mdns`, and `nbns` to isolate specific protocols.

### 3. DNS Queries
I learned that an A record query requests the IPv4 address associated with a hostname.

### 4. Multicast DNS
I learned that mDNS uses UDP port 5353 and the IPv4 multicast address 224.0.0.251 for local network name resolution.

### 5. DNS Responses
I learned how to associate a DNS query with its response and inspect returned resource records.

### 6. Network Protocol Differences
I learned that NBNS and DNS are different protocols. NBNS commonly uses UDP port 137, while standard DNS commonly uses port 53.

## Mistake / Failure and Diagnosis

Initially, I selected an mDNS-related sample capture expecting standard DNS traffic. However, applying the `dns` display filter produced no packets.

I investigated further using the `nbns` and `mdns` filters. This helped me identify the protocols actually present in the capture.

I then located an mDNS query in packet 21 and its corresponding response in packet 25.

## What I Changed

I stopped assuming that every name-resolution packet was standard DNS. I used protocol-specific display filters and inspected packet details before recording conclusions.

## Limitations

The experiment used an offline sample capture. Its results do not establish real-world malicious activity or identify an actual attacker.

## Future Improvements

- Practise with a standard DNS capture containing queries and responses.
- Explore additional DNS record types such as MX, TXT and AAAA.
- Improve understanding of packet routing and authentication.
- Compare packet-level findings with the email header investigation tool.
