"""Received-header parsing.

Each ``Received`` header has two halves with completely different trust
properties, and conflating them is the single most common mistake in email
forensics:

``from HELO (rDNS [IP])``
    ``HELO`` is free text supplied by the connecting client. Worthless alone.
    ``(rDNS [IP])`` is the receiving MTA's own record of the TCP peer, and is
    trustworthy exactly to the degree that the receiving MTA is.

``by RECEIVER with PROTO id ID; DATE``
    Written by the receiver about itself.

Headers are prepended, so index 0 is the newest and most trusted hop.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from datetime import datetime
from email.utils import parsedate_to_datetime

from app.models.enums import IpClass

#: Candidate address tokens inside a bracketed or parenthesised clause.
#: Deliberately loose -- ``ipaddress`` decides what is actually an address.
#: A single regex that correctly accepts every IPv6 form (``::`` compression,
#: IPv4-mapped, zone ids) and rejects hostnames is not worth writing when the
#: standard library already has the parser.
_CLAUSE_RE = re.compile(r"[\[(]([^\])]{2,80})[\])]")
_TOKEN_RE = re.compile(r"(?i)(?:IPv6:)?([0-9a-f:.]{3,45})")
_FROM_RE = re.compile(r"(?is)\bfrom\s+(?P<helo>[^\s(;]+)")
_RDNS_RE = re.compile(r"(?is)\bfrom\s+[^\s(;]+\s*\(\s*(?P<rdns>[A-Za-z0-9._-]+)?\s*[\[(]")
_BY_RE = re.compile(r"(?is)\bby\s+(?P<by>[^\s(;]+)")
_WITH_RE = re.compile(r"(?is)\bwith\s+(?P<proto>[A-Za-z0-9/_.-]+)")
_ID_RE = re.compile(r"(?is)\bid\s+(?P<id>[^\s;]+)")
_TLS_RE = re.compile(r"(?is)\((?P<tls>version=TLS[^)]*)\)")


@dataclass(slots=True)
class Hop:
    """One decomposed Received header."""

    seq: int  # 0 = topmost = newest = most trusted
    raw: str
    helo: str | None  # client-asserted; not evidence
    rdns_claim: str | None  # receiver-observed
    observed_ip: str | None  # receiver-observed; the only spoof-resistant field
    by_host: str | None
    protocol: str | None
    queue_id: str | None
    tls_info: str | None
    timestamp: datetime | None
    ip_class: IpClass


#: RFC 5737 (IPv4) and RFC 3849 (IPv6) documentation ranges.
#:
#: These are checked BEFORE the private test on purpose. Python's ``ipaddress``
#: reports them as private -- correctly, since they are reserved -- but they are
#: semantically stand-ins for *public* addresses, not RFC 1918 LAN space. The
#: synthetic corpus uses them so no fixture can ever reference a real host, and
#: without this branch every fixture hop would be discarded as internal and the
#: engine would find no sending infrastructure at all.
_DOCUMENTATION_NETS = tuple(
    ipaddress.ip_network(n)
    for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")
)


def is_documentation_range(addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return any(addr in net for net in _DOCUMENTATION_NETS)


def classify_ip(value: str | None) -> IpClass:
    """Bucket an address. Private and CGNAT hops are real infrastructure but
    carry no attribution value, so they are never geolocated."""
    if not value:
        return IpClass.UNKNOWN
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        return IpClass.UNKNOWN

    # IPv4-mapped IPv6 (::ffff:1.2.3.4) is a very common way to miss a match.
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped

    if addr.is_loopback:
        return IpClass.LOOPBACK
    if addr.is_link_local:
        return IpClass.LINK_LOCAL
    if is_documentation_range(addr):
        return IpClass.PUBLIC
    if isinstance(addr, ipaddress.IPv4Address) and addr in ipaddress.ip_network("100.64.0.0/10"):
        return IpClass.CGNAT
    if addr.is_private:
        return IpClass.PRIVATE
    if addr.is_reserved or addr.is_multicast or addr.is_unspecified:
        return IpClass.RESERVED
    return IpClass.PUBLIC


def normalise_ip(value: str) -> str:
    """Canonical form: IPv6 expanded and lowercased, IPv4-mapped unwrapped."""
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        return value.strip().lower()
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped
    return str(addr)


def parse_received_chain(received_headers: list[str]) -> list[Hop]:
    """Decompose Received headers, preserving prepend order."""
    return [_parse_one(seq, raw) for seq, raw in enumerate(received_headers)]


def _parse_one(seq: int, raw: str) -> Hop:
    collapsed = " ".join(raw.split())

    # The peer address lives in the `from` clause. Searching the whole header
    # would pick up the RECEIVER's own address from the `by` clause instead --
    # which is our own infrastructure, not the sender, and would make every hop
    # appear to originate from the host that received it.
    peer_clause = re.split(r"(?i)\sby\s", collapsed, maxsplit=1)[0]
    observed_ip = _first_address(peer_clause)

    helo_match = _FROM_RE.search(collapsed)
    rdns_match = _RDNS_RE.search(collapsed)
    by_match = _BY_RE.search(collapsed)
    with_match = _WITH_RE.search(collapsed)
    id_match = _ID_RE.search(collapsed)
    tls_match = _TLS_RE.search(collapsed)

    return Hop(
        seq=seq,
        raw=collapsed[:2000],
        helo=helo_match.group("helo").rstrip(".").lower() if helo_match else None,
        rdns_claim=(
            rdns_match.group("rdns").lower() if rdns_match and rdns_match.group("rdns") else None
        ),
        observed_ip=observed_ip,
        by_host=by_match.group("by").rstrip(".").lower() if by_match else None,
        protocol=with_match.group("proto") if with_match else None,
        queue_id=id_match.group("id") if id_match else None,
        tls_info=tls_match.group("tls")[:250] if tls_match else None,
        timestamp=_hop_timestamp(collapsed),
        ip_class=classify_ip(observed_ip),
    )


def _first_address(segment: str) -> str | None:
    """The first syntactically valid IP inside a bracketed/parenthesised clause."""
    for clause in _CLAUSE_RE.finditer(segment):
        for token in _TOKEN_RE.finditer(clause.group(1)):
            candidate = token.group(1).strip().strip(".:")
            if len(candidate) < 3:
                continue
            try:
                ipaddress.ip_address(candidate)
            except ValueError:
                continue
            return normalise_ip(candidate)
    return None


def _hop_timestamp(collapsed: str) -> datetime | None:
    """The date follows the final semicolon."""
    if ";" not in collapsed:
        return None
    try:
        return parsedate_to_datetime(collapsed.rsplit(";", 1)[1].strip())
    except (TypeError, ValueError, IndexError):
        return None
