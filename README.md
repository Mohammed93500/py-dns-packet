# py-dns-packet

Build DNS wire-format packets from structured record definitions for query and response messages.

```python
from py_dns_packet import DNSBuilder, DNSHeader, RType

packet = (
    DNSBuilder(DNSHeader(id=0x1234))
    .add_question("example.com", RType.A)
    .add_answer("example.com", RType.A, "192.0.2.1", ttl=300)
    .build()
)

wire = packet.to_bytes()
print(wire.hex())
```

## Why this exists

Most DNS libraries combine parsing and building, which makes the encoding path
harder to reason about and pulls in dependencies you may not want. This library
does one thing: turn Python record definitions into bytes. It has no third-party
dependencies and no parser.

The main trade-off is that domain names are never compressed. DNS compression
requires a shared pointer table across the entire message, which would force a
stateful encoder and a more complicated API. For the small messages this library
targets, the extra bytes are not worth the complexity. If you need compression,
you will need a different tool.

## The awkward edge

RDATA types are not uniform. An `A` record takes a string, an `MX` record takes
a `(preference, exchange)` tuple, and `TXT` accepts either a string or a sequence
of strings. The type you pass must match the record type; mismatches raise
`TypeError` (or `ValueError` for out-of-range values). Unknown record types are
passed through as raw `bytes`.

## API

- `DNSBuilder(header=None)` — fluent builder. Methods: `add_question`, `add_answer`, `add_authority`, `add_additional`, `build`.
- `DNSHeader(id=0, qr=0, opcode=Opcode.QUERY, aa=0, tc=0, rd=1, ra=0, z=0, rcode=RCode.NOERROR)`
- `DNSQuestion(name, qtype=RType.A, qclass=RClass.IN)`
- `DNSRecord(name, rtype, rclass=RClass.IN, ttl=0, rdata=b"")`
- `DNSMessage(header=None, questions=None, answers=None, authorities=None, additionals=None)` — `to_bytes()` serializes the message.
- Enums: `RType`, `RClass`, `Opcode`, `RCode`.

## Performance

The window keeps a bounded buffer, so `push` is constant time and memory does not
grow with the length of the stream. `peak` and `trough` are linear in the window
size, which is the trade that keeps `push` cheap.

