#!/usr/bin/env python3
"""A small iterative IPv4 DNS resolver."""

from __future__ import annotations

import argparse
import random
import socket
import struct
import sys
import time
from dataclasses import dataclass
from typing import Optional


HEADER_SIZE = 12
TYPE_A = 1
TYPE_NS = 2
TYPE_CNAME = 5
TYPE_OPT = 41
CLASS_IN = 1
EDNS_UDP_SIZE = 4096
MAX_DNS_PACKET = 65535
UPSTREAM_TIMEOUT = 2.0
MAX_SERVER_ATTEMPTS = 3
MAX_REFERRALS = 32
MAX_NS_LOOKUPS = 8

ROOT_SERVERS = (
    "198.41.0.4",       # a.root-servers.net
    "170.247.170.2",    # b.root-servers.net
    "192.33.4.12",      # c.root-servers.net
    "199.7.91.13",      # d.root-servers.net
    "192.203.230.10",   # e.root-servers.net
    "192.5.5.241",      # f.root-servers.net
    "192.112.36.4",     # g.root-servers.net
    "198.97.190.53",    # h.root-servers.net
    "192.36.148.17",    # i.root-servers.net
    "192.58.128.30",    # j.root-servers.net
    "193.0.14.129",     # k.root-servers.net
    "199.7.83.42",      # l.root-servers.net
    "202.12.27.33",     # m.root-servers.net
)


class DNSFormatError(ValueError):
    """Raised when a DNS message is malformed or unsupported."""


@dataclass(frozen=True)
class Question:
    name: tuple[bytes, ...]
    qtype: int
    qclass: int

    @property
    def key(self) -> tuple[tuple[bytes, ...], int, int]:
        return self.name, self.qtype, self.qclass


@dataclass(frozen=True)
class ResourceRecord:
    name: tuple[bytes, ...]
    rtype: int
    rclass: int
    ttl: int
    rdata_start: int
    rdata_end: int
    start: int
    end: int
    ttl_offset: int
    section: str


@dataclass(frozen=True)
class DNSMessage:
    packet: bytes
    identifier: int
    flags: int
    question: Question
    question_end: int
    answers: tuple[ResourceRecord, ...]
    authorities: tuple[ResourceRecord, ...]
    additionals: tuple[ResourceRecord, ...]

    @property
    def records(self) -> tuple[ResourceRecord, ...]:
        return self.answers + self.authorities + self.additionals


@dataclass
class CacheEntry:
    packet: bytes
    stored_at: float
    ttl_records: tuple[tuple[int, int], ...]
    expires_at: float

    def response(self, now: float) -> Optional[bytes]:
        if now >= self.expires_at:
            return None
        data = bytearray(self.packet)
        elapsed = int(now - self.stored_at)
        for offset, ttl in self.ttl_records:
            struct.pack_into("!I", data, offset, max(0, ttl - elapsed))
        return bytes(data)


def decode_name(packet: bytes, offset: int) -> tuple[tuple[bytes, ...], int]:
    """Decode a possibly compressed wire-format name."""
    if offset < 0 or offset >= len(packet):
        raise DNSFormatError("name starts outside the packet")

    labels: list[bytes] = []
    cursor = offset
    next_offset: Optional[int] = None
    visited: set[int] = set()
    wire_length = 1

    while True:
        if cursor >= len(packet):
            raise DNSFormatError("truncated name")
        length = packet[cursor]

        if length & 0xC0 == 0xC0:
            if cursor + 1 >= len(packet):
                raise DNSFormatError("truncated compression pointer")
            pointer = ((length & 0x3F) << 8) | packet[cursor + 1]
            if pointer >= cursor or pointer in visited:
                raise DNSFormatError("invalid compression pointer")
            visited.add(pointer)
            if next_offset is None:
                next_offset = cursor + 2
            cursor = pointer
            continue
        if length & 0xC0:
            raise DNSFormatError("reserved label encoding")
        cursor += 1
        if length == 0:
            return tuple(labels), next_offset if next_offset is not None else cursor
        if length > 63 or cursor + length > len(packet):
            raise DNSFormatError("invalid or truncated label")

        label = packet[cursor:cursor + length]
        labels.append(label.lower())
        wire_length += length + 1
        if wire_length > 255:
            raise DNSFormatError("name exceeds 255 wire bytes")
        cursor += length


def encode_name(name: tuple[bytes, ...]) -> bytes:
    encoded = bytearray()
    for label in name:
        if not label or len(label) > 63:
            raise DNSFormatError("invalid label length")
        encoded.append(len(label))
        encoded.extend(label)
    encoded.append(0)
    if len(encoded) > 255:
        raise DNSFormatError("name exceeds 255 wire bytes")
    return bytes(encoded)


def _parse_rr(
    packet: bytes, offset: int, section: str
) -> tuple[ResourceRecord, int]:
    start = offset
    name, offset = decode_name(packet, offset)
    if offset + 10 > len(packet):
        raise DNSFormatError("truncated resource record")
    rtype, rclass, ttl = struct.unpack_from("!HHI", packet, offset)
    ttl_offset = offset + 4
    rdlength = struct.unpack_from("!H", packet, offset + 8)[0]
    rdata_start = offset + 10
    rdata_end = rdata_start + rdlength
    if rdata_end > len(packet):
        raise DNSFormatError("truncated resource data")
    rr = ResourceRecord(
        name, rtype, rclass, ttl, rdata_start, rdata_end,
        start, rdata_end, ttl_offset, section
    )
    return rr, rdata_end


def parse_message(packet: bytes) -> DNSMessage:
    if len(packet) < HEADER_SIZE:
        raise DNSFormatError("truncated DNS header")
    identifier, flags, qdcount, ancount, nscount, arcount = struct.unpack_from(
        "!HHHHHH", packet, 0
    )
    if qdcount != 1:
        raise DNSFormatError("expected exactly one question")
    name, offset = decode_name(packet, HEADER_SIZE)
    if offset + 4 > len(packet):
        raise DNSFormatError("truncated question")
    qtype, qclass = struct.unpack_from("!HH", packet, offset)
    offset += 4
    question_end = offset
    question = Question(name, qtype, qclass)

    sections: dict[str, list[ResourceRecord]] = {
        "answer": [],
        "authority": [],
        "additional": [],
    }
    for section, count in (
        ("answer", ancount),
        ("authority", nscount),
        ("additional", arcount),
    ):
        for _ in range(count):
            rr, offset = _parse_rr(packet, offset, section)
            sections[section].append(rr)
    if offset != len(packet):
        raise DNSFormatError("unexpected trailing data")

    return DNSMessage(
        packet, identifier, flags, question, question_end,
        tuple(sections["answer"]),
        tuple(sections["authority"]),
        tuple(sections["additional"]),
    )


def parse_query(packet: bytes) -> tuple[DNSMessage, Optional[int]]:
    message = parse_message(packet)
    if message.flags & 0x8000:
        raise DNSFormatError("query has the response bit set")
    if message.flags & 0x7800:
        raise DNSFormatError("unsupported DNS opcode")
    if message.flags & 0x0040:
        raise DNSFormatError("reserved header bit is set")
    if message.flags & 0x0200:
        raise DNSFormatError("truncated client query")
    if message.flags & (0x0400 | 0x0080 | 0x000F):
        raise DNSFormatError("response-only flags are set in query")
    if message.answers or message.authorities:
        raise DNSFormatError("query contains answer or authority records")

    opt_size: Optional[int] = None
    for rr in message.additionals:
        if rr.rtype != TYPE_OPT or rr.name:
            raise DNSFormatError("unsupported additional query record")
        if opt_size is not None:
            raise DNSFormatError("multiple OPT records")
        if (rr.ttl >> 24) & 0xFF or (rr.ttl >> 16) & 0xFF:
            raise DNSFormatError("unsupported EDNS version")
        cursor = rr.rdata_start
        while cursor < rr.rdata_end:
            if cursor + 4 > rr.rdata_end:
                raise DNSFormatError("truncated EDNS option")
            option_length = struct.unpack_from("!H", packet, cursor + 2)[0]
            cursor += 4 + option_length
            if cursor > rr.rdata_end:
                raise DNSFormatError("truncated EDNS option data")
        opt_size = max(512, min(rr.rclass, 4096, EDNS_UDP_SIZE))
    return message, opt_size


def make_upstream_query(question: Question) -> tuple[int, bytes]:
    identifier = random.randrange(0x10000)
    packet = bytearray(struct.pack(
        "!HHHHHH", identifier, 0, 1, 0, 0, 1
    ))
    packet.extend(encode_name(question.name))
    packet.extend(struct.pack("!HH", question.qtype, question.qclass))
    packet.extend(b"\x00" + struct.pack("!HHIH", TYPE_OPT, EDNS_UDP_SIZE, 0, 0))
    return identifier, bytes(packet)


def _valid_upstream_response(packet: bytes, identifier: int, question: Question) -> DNSMessage:
    message = parse_message(packet)
    if not (message.flags & 0x8000):
        raise DNSFormatError("upstream packet is not a response")
    if message.identifier != identifier or message.question.key != question.key:
        raise DNSFormatError("upstream response does not match the query")
    if message.flags & 0x7800 or message.flags & 0x0040:
        raise DNSFormatError("invalid upstream response flags")
    return message


def _suffix(name: tuple[bytes, ...], zone: tuple[bytes, ...]) -> bool:
    return len(name) >= len(zone) and (
        not zone or name[-len(zone):] == zone
    )


def _name_rdata(packet: bytes, rr: ResourceRecord) -> tuple[bytes, ...]:
    name, end = decode_name(packet, rr.rdata_start)
    if end != rr.rdata_end:
        raise DNSFormatError("invalid domain-name resource data")
    return name


def _referral_servers(
    message: DNSMessage, allow_external_glue: bool = False,
) -> list[str]:
    question_name = message.question.name
    ns_records = [
        rr for rr in message.authorities
        if rr.rtype == TYPE_NS and rr.rclass == CLASS_IN
        and _suffix(question_name, rr.name)
    ]
    if not ns_records:
        return []
    deepest = max(len(rr.name) for rr in ns_records)
    zone = next(rr.name for rr in ns_records if len(rr.name) == deepest)

    nameservers: list[tuple[bytes, ...]] = []
    for rr in ns_records:
        if rr.name == zone:
            target = _name_rdata(message.packet, rr)
            if target not in nameservers:
                nameservers.append(target)

    addresses: list[str] = []
    for target in nameservers:
        if not allow_external_glue and not _suffix(target, zone):
            continue
        for rr in message.additionals:
            if (
                rr.name == target and rr.rtype == TYPE_A and
                rr.rclass == CLASS_IN and rr.rdata_end - rr.rdata_start == 4
            ):
                address = socket.inet_ntoa(
                    message.packet[rr.rdata_start:rr.rdata_end]
                )
                if address not in addresses:
                    addresses.append(address)
    return addresses


def _cacheable_response(message: DNSMessage) -> Optional[CacheEntry]:
    if message.flags & 0x000F or not message.answers:
        return None
    ttl_records = tuple(
        (rr.ttl_offset, rr.ttl)
        for rr in message.answers if rr.rtype != TYPE_OPT
    )
    if not ttl_records:
        return None
    lifetime = min(ttl for _, ttl in ttl_records)
    if lifetime <= 0:
        return None
    now = time.monotonic()
    return CacheEntry(message.packet, now, ttl_records, now + lifetime)


class Resolver:
    def __init__(self) -> None:
        self.cache: dict[tuple[tuple[bytes, ...], int, int], CacheEntry] = {}
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.settimeout(UPSTREAM_TIMEOUT)

    def close(self) -> None:
        self.socket.close()

    def _cached(self, question: Question) -> Optional[bytes]:
        entry = self.cache.get(question.key)
        if entry is None:
            return None
        response = entry.response(time.monotonic())
        if response is None:
            del self.cache[question.key]
        return response

    def _query_server(self, question: Question, server: str) -> Optional[DNSMessage]:
        identifier, query = make_upstream_query(question)
        for _ in range(MAX_SERVER_ATTEMPTS):
            try:
                self.socket.sendto(query, (server, 53))
                packet, _ = self.socket.recvfrom(MAX_DNS_PACKET)
                return _valid_upstream_response(packet, identifier, question)
            except (OSError, DNSFormatError):
                continue
        return None

    def resolve(
        self,
        question: Question,
        ns_stack: Optional[set[tuple[bytes, ...]]] = None,
    ) -> Optional[bytes]:
        cached = self._cached(question)
        if cached is not None:
            return cached
        if ns_stack is None:
            ns_stack = set()
        servers = list(ROOT_SERVERS)
        for _ in range(MAX_REFERRALS):
            referral_servers: list[str] = []
            for server in servers:
                message = self._query_server(question, server)
                if message is None:
                    continue
                rcode = message.flags & 0x000F
                if rcode == 3 or message.answers:
                    answer = _cacheable_response(message)
                    if answer is not None:
                        self.cache[question.key] = answer
                    return message.packet
                if rcode != 0:
                    continue

                try:
                    glue = _referral_servers(
                        message, allow_external_glue=server in ROOT_SERVERS
                    )
                except DNSFormatError:
                    continue
                if glue:
                    referral_servers = glue
                    break

                if any(rr.rtype == 6 for rr in message.authorities):
                    return message.packet

                for rr in message.authorities:
                    if rr.rtype != TYPE_NS or rr.rclass != CLASS_IN:
                        continue
                    if not _suffix(question.name, rr.name):
                        continue
                    try:
                        target = _name_rdata(message.packet, rr)
                    except DNSFormatError:
                        continue
                    if target in ns_stack or len(ns_stack) >= MAX_NS_LOOKUPS:
                        continue
                    ns_stack.add(target)
                    address_question = Question(target, TYPE_A, CLASS_IN)
                    address_response = self.resolve(address_question, ns_stack)
                    ns_stack.remove(target)
                    if address_response is None:
                        continue
                    try:
                        address_message = parse_message(address_response)
                    except DNSFormatError:
                        continue
                    for address_rr in address_message.answers:
                        if (
                            address_rr.name == target and
                            address_rr.rtype == TYPE_A and
                            address_rr.rclass == CLASS_IN and
                            address_rr.rdata_end - address_rr.rdata_start == 4
                        ):
                            address = socket.inet_ntoa(
                                address_message.packet[
                                    address_rr.rdata_start:address_rr.rdata_end
                                ]
                            )
                            if address not in referral_servers:
                                referral_servers.append(address)
                    if len(referral_servers) >= 3:
                        break
                if referral_servers:
                    break
                if message.flags & 0x0400:
                    return message.packet
            if not referral_servers:
                return None
            servers = referral_servers
        return None

    def handle_query(self, packet: bytes) -> Optional[bytes]:
        try:
            request, edns_size = parse_query(packet)
        except DNSFormatError:
            return None
        response = self._cached(request.question)
        if response is None:
            response = self.resolve(request.question)
        if response is None:
            return make_error_response(request, 2)
        return make_client_response(
            response,
            request.identifier,
            request.flags,
            edns_size if edns_size is not None else 512,
        )


def make_error_response(message: DNSMessage, rcode: int) -> bytes:
    flags = 0x8000 | 0x0080 | (message.flags & 0x0100) | (rcode & 0x000F)
    return (
        struct.pack("!HHHHHH", message.identifier, flags, 1, 0, 0, 0)
        + message.packet[HEADER_SIZE:message.question_end]
    )


def make_client_response(
    packet: bytes, identifier: int, request_flags: int, max_size: int
) -> bytes:
    message = parse_message(packet)
    data = bytearray(packet)
    struct.pack_into("!H", data, 0, identifier)
    flags = message.flags | 0x8000 | 0x0080
    flags = (flags & ~0x0100) | (request_flags & 0x0100)
    struct.pack_into("!H", data, 2, flags)
    if len(data) <= max_size:
        return bytes(data)

    counts = [0, 0, 0]
    output = bytearray(packet[:message.question_end])
    truncated = False
    for rr in message.records:
        if len(output) + rr.end - rr.start > max_size:
            truncated = True
            break
        output.extend(packet[rr.start:rr.end])
        section_index = {"answer": 0, "authority": 1, "additional": 2}[rr.section]
        counts[section_index] += 1
    if len(message.records) != sum(counts):
        truncated = True
    output[0:2] = struct.pack("!H", identifier)
    new_flags = flags | (0x0200 if truncated else 0)
    output[2:4] = struct.pack("!H", new_flags)
    output[4:12] = struct.pack("!HHHH", 1, counts[0], counts[1], counts[2])
    return bytes(output)


def serve(port: int) -> None:
    resolver = Resolver()
    listener = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        listener.bind(("0.0.0.0", port))
        print(f"DNS resolver listening on UDP port {port}", flush=True)
        while True:
            packet, client = listener.recvfrom(MAX_DNS_PACKET)
            response = resolver.handle_query(packet)
            if response is not None:
                listener.sendto(response, client)
    finally:
        listener.close()
        resolver.close()


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Iterative IPv4 DNS resolver")
    parser.add_argument("port", nargs="?", type=int, default=53)
    args = parser.parse_args(argv)
    if not 1 <= args.port <= 65535:
        parser.error("port must be between 1 and 65535")
    try:
        serve(args.port)
    except OSError as exc:
        print(f"DNS resolver failed: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
