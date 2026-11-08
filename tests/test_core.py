import struct
import unittest

from py_dns_packet import (
    DNSBuilder,
    DNSHeader,
    DNSMessage,
    DNSQuestion,
    DNSRecord,
    Opcode,
    RClass,
    RCode,
    RType,
)
from py_dns_packet.core import _encode_name, _encode_rdata


class EncodeNameTests(unittest.TestCase):
    def test_simple_name(self):
        self.assertEqual(_encode_name("example.com"), b"\x07example\x03com\x00")

    def test_trailing_dot(self):
        self.assertEqual(_encode_name("example.com."), b"\x07example\x03com\x00")

    def test_root(self):
        self.assertEqual(_encode_name(""), b"\x00")

    def test_single_label(self):
        self.assertEqual(_encode_name("localhost"), b"\x09localhost\x00")

    def test_empty_label_rejected(self):
        with self.assertRaises(ValueError):
            _encode_name("example..com")

    def test_label_too_long(self):
        with self.assertRaises(ValueError):
            _encode_name("a" * 64 + ".com")


class EncodeRdataTests(unittest.TestCase):
    def test_a_record(self):
        self.assertEqual(_encode_rdata(RType.A, "192.0.2.1"), b"\xc0\x00\x02\x01")

    def test_aaaa_record(self):
        self.assertEqual(
            _encode_rdata(RType.AAAA, "2001:db8::1"),
            b"\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01",
        )

    def test_a_record_rejects_ipv6(self):
        with self.assertRaises(ValueError):
            _encode_rdata(RType.A, "2001:db8::1")

    def test_ns_record(self):
        self.assertEqual(
            _encode_rdata(RType.NS, "ns1.example.com"),
            b"\x03ns1\x07example\x03com\x00",
        )

    def test_mx_record(self):
        self.assertEqual(
            _encode_rdata(RType.MX, (10, "mail.example.com")),
            struct.pack("!H", 10) + b"\x04mail\x07example\x03com\x00",
        )

    def test_txt_record_single(self):
        self.assertEqual(_encode_rdata(RType.TXT, "hello"), b"\x05hello")

    def test_txt_record_multiple(self):
        self.assertEqual(
            _encode_rdata(RType.TXT, ["ab", "c"]),
            b"\x02ab\x01c",
        )

    def test_txt_empty_sequence_rejected(self):
        with self.assertRaises(ValueError):
            _encode_rdata(RType.TXT, [])

    def test_srv_record(self):
        self.assertEqual(
            _encode_rdata(RType.SRV, (1, 2, 80, "srv.example.com")),
            struct.pack("!HHH", 1, 2, 80) + b"\x03srv\x07example\x03com\x00",
        )

    def test_unknown_type_passthrough(self):
        self.assertEqual(_encode_rdata(999, b"raw"), b"raw")


class HeaderTests(unittest.TestCase):
    def test_default_header(self):
        h = DNSHeader()
        self.assertEqual(h.id, 0)
        self.assertEqual(h.qr, 0)
        self.assertEqual(h.opcode, Opcode.QUERY)
        self.assertEqual(h.rd, 1)

    def test_message_header_flags(self):
        header = DNSHeader(id=0x1234, qr=1, opcode=Opcode.QUERY, aa=1, rd=1, ra=1, rcode=RCode.NOERROR)
        msg = DNSMessage(header=header)
        data = msg.to_bytes()
        self.assertEqual(len(data), 12)
        msg_id, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", data)
        self.assertEqual(msg_id, 0x1234)
        self.assertEqual(qd, 0)
        self.assertEqual(an, 0)
        self.assertEqual(ns, 0)
        self.assertEqual(ar, 0)
        # qr=1 (bit 15), aa=1 (bit 10), rd=1 (bit 8), ra=1 (bit 7)
        expected_flags = (1 << 15) | (1 << 10) | (1 << 8) | (1 << 7)
        self.assertEqual(flags, expected_flags)


class MessageTests(unittest.TestCase):
    def test_query_roundtrip_shape(self):
        msg = (
            DNSBuilder(DNSHeader(id=0xABCD))
            .add_question("example.com", RType.A)
            .build()
        )
        data = msg.to_bytes()
        msg_id, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", data[:12])
        self.assertEqual(msg_id, 0xABCD)
        self.assertEqual(qd, 1)
        self.assertEqual(an, 0)
        self.assertEqual(ns, 0)
        self.assertEqual(ar, 0)
        # rd is set by default
        self.assertEqual(flags & (1 << 8), 1 << 8)
        # question body starts at offset 12
        self.assertEqual(data[12:], b"\x07example\x03com\x00" + struct.pack("!HH", RType.A, RClass.IN))

    def test_response_with_answer(self):
        msg = (
            DNSBuilder(DNSHeader(id=1, qr=1, aa=1))
            .add_question("example.com", RType.A)
            .add_answer("example.com", RType.A, "192.0.2.1", ttl=300)
            .build()
        )
        data = msg.to_bytes()
        _, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", data[:12])
        self.assertEqual(qd, 1)
        self.assertEqual(an, 1)
        self.assertEqual(ns, 0)
        self.assertEqual(ar, 0)
        self.assertEqual(flags & (1 << 15), 1 << 15)  # qr
        self.assertEqual(flags & (1 << 10), 1 << 10)  # aa
        # Find the answer: after question section
        question_end = 12 + len(b"\x07example\x03com\x00") + 4
        answer = data[question_end:]
        self.assertTrue(answer.startswith(b"\x07example\x03com\x00"))
        # rtype, rclass, ttl, rdlength
        offset = len(b"\x07example\x03com\x00")
        rtype, rclass, ttl, rdlength = struct.unpack("!HHIH", answer[offset : offset + 10])
        self.assertEqual(rtype, RType.A)
        self.assertEqual(rclass, RClass.IN)
        self.assertEqual(ttl, 300)
        self.assertEqual(rdlength, 4)
        self.assertEqual(answer[offset + 10 :], b"\xc0\x00\x02\x01")

    def test_authority_and_additional_sections(self):
        msg = (
            DNSBuilder(DNSHeader(id=2))
            .add_question("example.com", RType.NS)
            .add_authority("example.com", RType.NS, "ns1.example.com", ttl=60)
            .add_additional("ns1.example.com", RType.A, "192.0.2.53", ttl=60)
            .build()
        )
        data = msg.to_bytes()
        _, _, qd, an, ns, ar = struct.unpack("!HHHHHH", data[:12])
        self.assertEqual(qd, 1)
        self.assertEqual(an, 0)
        self.assertEqual(ns, 1)
        self.assertEqual(ar, 1)

    def test_counts_derived_from_sections(self):
        # A header with stale counts should be ignored; counts come from lists.
        msg = DNSMessage(
            header=DNSHeader(id=3),
            questions=[DNSQuestion("example.com")],
            answers=[DNSRecord("example.com", RType.A, rdata="192.0.2.1")],
        )
        data = msg.to_bytes()
        _, _, qd, an, _, _ = struct.unpack("!HHHHHH", data[:12])
        self.assertEqual(qd, 1)
        self.assertEqual(an, 1)

    def test_builder_returns_self(self):
        b = DNSBuilder()
        self.assertIs(b.add_question("a.com"), b)
        self.assertIs(b.add_answer("a.com", RType.A, "192.0.2.1"), b)
        self.assertIs(b.add_authority("a.com", RType.NS, "ns.a.com"), b)
        self.assertIs(b.add_additional("ns.a.com", RType.A, "192.0.2.2"), b)


class RecordTests(unittest.TestCase):
    def test_record_to_bytes(self):
        rr = DNSRecord("example.com", RType.A, ttl=60, rdata="192.0.2.1")
        data = rr.to_bytes()
        name = b"\x07example\x03com\x00"
        self.assertTrue(data.startswith(name))
        rtype, rclass, ttl, rdlength = struct.unpack("!HHIH", data[len(name) : len(name) + 10])
        self.assertEqual(rtype, RType.A)
        self.assertEqual(rclass, RClass.IN)
        self.assertEqual(ttl, 60)
        self.assertEqual(rdlength, 4)

    def test_question_to_bytes(self):
        q = DNSQuestion("example.com", RType.MX, RClass.IN)
        self.assertEqual(
            q.to_bytes(),
            b"\x07example\x03com\x00" + struct.pack("!HH", RType.MX, RClass.IN),
        )


if __name__ == "__main__":
    unittest.main()
