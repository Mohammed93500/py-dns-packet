"""Core DNS wire-format encoding.

The module deliberately does not perform domain-name compression. Compression
requires a shared pointer map across the whole message, which complicates the
API and is rarely needed for the small messages this library targets. As a
result every name is encoded in full. This is a documented trade-off.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from enum import IntEnum
from typing import List, Sequence, Tuple, Union


class RType(IntEnum):
    """DNS resource record type codes."""

    A = 1
    NS = 2
    CNAME = 5
    SOA = 6
    PTR = 12
    MX = 15
    TXT = 16
    AAAA = 28
    SRV = 33
    OPT = 41


class RClass(IntEnum):
    """DNS class codes."""

    IN = 1
    CH = 3
    HS = 4


class Opcode(IntEnum):
    """DNS opcodes."""

    QUERY = 0
    IQUERY = 1
    STATUS = 2
    NOTIFY = 4
    UPDATE = 5


class RCode(IntEnum):
    """DNS response codes."""

    NOERROR = 0
    FORMERR = 1
    SERVFAIL = 2
    NXDOMAIN = 3
    NOTIMP = 4
    REFUSED = 5


@dataclass
class DNSHeader:
    """The 12-byte DNS header.

    The header is kept as a plain data object so callers can construct it
    explicitly. The builder computes the counts (QDCOUNT, ANCOUNT, etc.)
    from the provided sections to avoid mismatches.
    """

    id: int = 0
    qr: int = 0  # 0 = query, 1 = response
    opcode: int = Opcode.QUERY
    aa: int = 0  # authoritative answer
    tc: int = 0  # truncated
    rd: int = 1  # recursion desired
    ra: int = 0  # recursion available
    z: int = 0
    rcode: int = RCode.NOERROR


def _encode_name(name: str) -> bytes:
    """Encode a domain name into DNS wire format.

    The name is split on dots; each label is prefixed with its length. An
    empty label (the root) is encoded as a single zero byte. Trailing dots
    are ignored so both ``example.com`` and ``example.com.`` work.
    """
    if name == "":
        return b"\x00"
    labels = name.rstrip(".").split(".")
    out = bytearray()
    for label in labels:
        if not label:
            raise ValueError("empty label in domain name")
        encoded = label.encode("idna")
        if len(encoded) > 63:
            raise ValueError(f"label too long: {label!r}")
        out.append(len(encoded))
        out.extend(encoded)
    out.append(0)
    return bytes(out)


def _encode_character_string(text: str) -> bytes:
    """Encode a single DNS character-string (length byte + bytes)."""
    encoded = text.encode("utf-8")
    if len(encoded) > 255:
        raise ValueError("character-string exceeds 255 bytes")
    return bytes([len(encoded)]) + encoded


def _encode_rdata(rtype: int, rdata: Union[bytes, str, Sequence[str], int, Tuple[int, int]]) -> bytes:
    """Encode RDATA for the supported record types.

    The accepted Python types differ per record type:

    * A / AAAA: a string containing the textual address.
    * NS / CNAME / PTR: a domain name string.
    * MX: a tuple ``(preference, exchange)``.
    * TXT: a string or a sequence of strings.
    * SRV: a tuple ``(priority, weight, port, target)``.
    * Any other type: raw ``bytes`` are passed through unchanged.
    """
    if rtype in (RType.A, RType.AAAA):
        import ipaddress

        if not isinstance(rdata, str):
            raise TypeError("A/AAAA rdata must be a string")
        addr = ipaddress.ip_address(rdata)
        if rtype == RType.A and addr.version != 4:
            raise ValueError("A record requires an IPv4 address")
        if rtype == RType.AAAA and addr.version != 6:
            raise ValueError("AAAA record requires an IPv6 address")
        return addr.packed

    if rtype in (RType.NS, RType.CNAME, RType.PTR):
        if not isinstance(rdata, str):
            raise TypeError("name rdata must be a string")
        return _encode_name(rdata)

    if rtype == RType.MX:
        if not isinstance(rdata, tuple) or len(rdata) != 2:
            raise TypeError("MX rdata must be a (preference, exchange) tuple")
        preference, exchange = rdata
        if not isinstance(preference, int) or not 0 <= preference <= 0xFFFF:
            raise ValueError("MX preference must be a 16-bit integer")
        if not isinstance(exchange, str):
            raise TypeError("MX exchange must be a string")
        return struct.pack("!H", preference) + _encode_name(exchange)

    if rtype == RType.TXT:
        if isinstance(rdata, str):
            return _encode_character_string(rdata)
        if isinstance(rdata, (list, tuple)):
            if not rdata:
                raise ValueError("TXT rdata sequence must not be empty")
            return b"".join(_encode_character_string(s) for s in rdata)
        raise TypeError("TXT rdata must be a string or sequence of strings")

    if rtype == RType.SRV:
        if not isinstance(rdata, tuple) or len(rdata) != 4:
            raise TypeError("SRV rdata must be a (priority, weight, port, target) tuple")
        priority, weight, port, target = rdata
        for value, name in ((priority, "priority"), (weight, "weight"), (port, "port")):
            if not isinstance(value, int) or not 0 <= value <= 0xFFFF:
                raise ValueError(f"SRV {name} must be a 16-bit integer")
        if not isinstance(target, str):
            raise TypeError("SRV target must be a string")
        return struct.pack("!HHH", priority, weight, port) + _encode_name(target)

    if isinstance(rdata, (bytes, bytearray)):
        return bytes(rdata)
    raise TypeError(f"unsupported rdata type for record type {rtype}")


@dataclass
class DNSQuestion:
    """A DNS question entry."""

    name: str
    qtype: int = RType.A
    qclass: int = RClass.IN

    def to_bytes(self) -> bytes:
        return _encode_name(self.name) + struct.pack("!HH", self.qtype, self.qclass)


@dataclass
class DNSRecord:
    """A DNS resource record.

    ``rdata`` accepts different Python types depending on ``rtype``; see
    :func:`_encode_rdata` for the mapping.
    """

    name: str
    rtype: int
    rclass: int = RClass.IN
    ttl: int = 0
    rdata: Union[bytes, str, Sequence[str], int, Tuple] = b""

    def to_bytes(self) -> bytes:
        encoded_rdata = _encode_rdata(self.rtype, self.rdata)
        header = _encode_name(self.name) + struct.pack(
            "!HHIH", self.rtype, self.rclass, self.ttl, len(encoded_rdata)
        )
        return header + encoded_rdata


@dataclass
class DNSMessage:
    """A full DNS message: header plus sections."""

    header: DNSHeader = field(default_factory=DNSHeader)
    questions: List[DNSQuestion] = field(default_factory=list)
    answers: List[DNSRecord] = field(default_factory=list)
    authorities: List[DNSRecord] = field(default_factory=list)
    additionals: List[DNSRecord] = field(default_factory=list)

    def to_bytes(self) -> bytes:
        """Serialize the message to DNS wire format.

        Counts are derived from the section lengths so the caller cannot
        accidentally produce a header that disagrees with the body.
        """
        flags = 0
        flags |= (self.header.qr & 0x1) << 15
        flags |= (self.header.opcode & 0xF) << 11
        flags |= (self.header.aa & 0x1) << 10
        flags |= (self.header.tc & 0x1) << 9
        flags |= (self.header.rd & 0x1) << 8
        flags |= (self.header.ra & 0x1) << 7
        flags |= (self.header.z & 0x7) << 4
        flags |= self.header.rcode & 0xF

        counts = (
            len(self.questions),
            len(self.answers),
            len(self.authorities),
            len(self.additionals),
        )
        out = bytearray(struct.pack("!HHHHHH", self.header.id, flags, *counts))
        for q in self.questions:
            out.extend(q.to_bytes())
        for section in (self.answers, self.authorities, self.additionals):
            for rr in section:
                out.extend(rr.to_bytes())
        return bytes(out)


class DNSBuilder:
    """Fluent builder for DNS messages.

    The builder keeps mutable lists and returns ``self`` from each method so
    calls can be chained. ``build`` produces a :class:`DNSMessage`; call
    ``to_bytes`` on it to obtain the wire encoding.
    """

    def __init__(self, header: DNSHeader | None = None) -> None:
        self.header = header if header is not None else DNSHeader()
        self._questions: List[DNSQuestion] = []
        self._answers: List[DNSRecord] = []
        self._authorities: List[DNSRecord] = []
        self._additionals: List[DNSRecord] = []

    def add_question(self, name: str, qtype: int = RType.A, qclass: int = RClass.IN) -> "DNSBuilder":
        self._questions.append(DNSQuestion(name, qtype, qclass))
        return self

    def add_answer(
        self,
        name: str,
        rtype: int,
        rdata: Union[bytes, str, Sequence[str], int, Tuple],
        ttl: int = 0,
        rclass: int = RClass.IN,
    ) -> "DNSBuilder":
        self._answers.append(DNSRecord(name, rtype, rclass, ttl, rdata))
        return self

    def add_authority(
        self,
        name: str,
        rtype: int,
        rdata: Union[bytes, str, Sequence[str], int, Tuple],
        ttl: int = 0,
        rclass: int = RClass.IN,
    ) -> "DNSBuilder":
        self._authorities.append(DNSRecord(name, rtype, rclass, ttl, rdata))
        return self

    def add_additional(
        self,
        name: str,
        rtype: int,
        rdata: Union[bytes, str, Sequence[str], int, Tuple],
        ttl: int = 0,
        rclass: int = RClass.IN,
    ) -> "DNSBuilder":
        self._additionals.append(DNSRecord(name, rtype, rclass, ttl, rdata))
        return self

    def build(self) -> DNSMessage:
        return DNSMessage(
            header=self.header,
            questions=list(self._questions),
            answers=list(self._answers),
            authorities=list(self._authorities),
            additionals=list(self._additionals),
        )
