"""DNS packet builder for constructing wire-format DNS messages.

This package provides a small, dependency-free way to build DNS query and
response packets from structured record definitions. It focuses on the
encoding side: turning Python objects into bytes that can be sent over UDP
or TCP. Parsing is intentionally out of scope.
"""

from .core import (
    DNSBuilder,
    DNSHeader,
    DNSQuestion,
    DNSRecord,
    DNSMessage,
    RType,
    RClass,
    Opcode,
    RCode,
)

__all__ = [
    "DNSBuilder",
    "DNSHeader",
    "DNSQuestion",
    "DNSRecord",
    "DNSMessage",
    "RType",
    "RClass",
    "Opcode",
    "RCode",
]
