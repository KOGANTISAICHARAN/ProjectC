"""Network attribution for an IP address.

Answers "which network is this, and where is that network registered" -- never
"where is the person". The distinction is the product's whole posture, so it is
enforced by the return type: there is no field for a city, and country is
optional and always carries its source.

RESOLUTION ORDER
----------------
1. MaxMind GeoLite2 (``GeoLite2-ASN.mmdb`` / ``GeoLite2-Country.mmdb`` in
   ``assets/``) when present.
2. A small bundled table, so the platform still reports network context offline.

Whichever answered is recorded in ``source`` and rendered in the UI. A reader
must always be able to tell a commercial geolocation lookup from a fallback
table -- presenting them identically is how a confident-looking wrong country
ends up in a report.
"""

from __future__ import annotations

import csv
import ipaddress
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from app.core.logging import get_logger

log = get_logger(__name__)

_ASSETS = Path(__file__).resolve().parents[3] / "assets"
_FALLBACK_CSV = _ASSETS / "asn_fallback.csv"
_ASN_MMDB = _ASSETS / "GeoLite2-ASN.mmdb"
_COUNTRY_MMDB = _ASSETS / "GeoLite2-Country.mmdb"


@dataclass(frozen=True, slots=True)
class NetworkInfo:
    ip: str
    asn: int | None = None
    org: str | None = None
    #: ISO-3166-1 alpha-2. Country granularity only: city-level precision is not
    #: defensible for datacentre ranges and is therefore not modelled at all.
    country: str | None = None
    network_type: str | None = None
    source: str = "unavailable"
    note: str | None = None

    @property
    def available(self) -> bool:
        return self.source != "unavailable"


@lru_cache(maxsize=1)
def _fallback_table() -> list[tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, dict[str, str]]]:
    if not _FALLBACK_CSV.exists():
        return []
    rows: list[tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, dict[str, str]]] = []
    with _FALLBACK_CSV.open(encoding="utf-8") as handle:
        for row in csv.DictReader(line for line in handle if not line.startswith("#")):
            try:
                rows.append((ipaddress.ip_network(row["prefix"]), row))
            except ValueError:
                continue
    # Most specific prefix wins, as with a routing table.
    rows.sort(key=lambda item: item[0].prefixlen, reverse=True)
    return rows


@lru_cache(maxsize=2)
def _mmdb_reader(path_str: str) -> object | None:
    path = Path(path_str)
    if not path.exists():
        return None
    try:
        import geoip2.database

        return geoip2.database.Reader(str(path))
    except Exception as exc:
        log.warning("geo.mmdb_unavailable", path=path.name, error=str(exc))
        return None


def datasets_present() -> dict[str, bool]:
    """What the UI reports as provenance."""
    return {
        "geolite2_asn": _ASN_MMDB.exists(),
        "geolite2_country": _COUNTRY_MMDB.exists(),
        "fallback_table": _FALLBACK_CSV.exists(),
    }


def lookup(ip: str | None) -> NetworkInfo:
    """Resolve network context for an address. Never raises."""
    if not ip:
        return NetworkInfo(ip="", source="unavailable", note="no address supplied")

    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return NetworkInfo(ip=ip, source="unavailable", note="not a valid IP address")

    # Documentation ranges are checked BEFORE the private test, for the same
    # reason as in forensics.received: Python reports them private, but they
    # stand in for public addresses. Without this the synthetic corpus resolves
    # to "local" and no network context is ever reported.
    from app.services.forensics.received import is_documentation_range

    if not is_documentation_range(address) and (address.is_private or address.is_loopback):
        return NetworkInfo(
            ip=ip,
            source="local",
            note="private or loopback address; carries no attribution value",
        )

    asn = org = country = None
    used: list[str] = []

    asn_reader = _mmdb_reader(str(_ASN_MMDB))
    if asn_reader is not None:
        try:
            record = asn_reader.asn(ip)  # type: ignore[attr-defined]
            asn, org = record.autonomous_system_number, record.autonomous_system_organization
            used.append("GeoLite2-ASN")
        except Exception as exc:
            # An address absent from the database is normal, not an error.
            log.debug("geo.asn_miss", ip=ip, error=str(exc)[:80])

    country_reader = _mmdb_reader(str(_COUNTRY_MMDB))
    if country_reader is not None:
        try:
            country = country_reader.country(ip).country.iso_code  # type: ignore[attr-defined]
            used.append("GeoLite2-Country")
        except Exception as exc:
            log.debug("geo.country_miss", ip=ip, error=str(exc)[:80])

    if used:
        return NetworkInfo(
            ip=ip,
            asn=asn,
            org=org,
            country=country,
            source=" + ".join(used),
            note="Country-level only. Identifies the network, not a person.",
        )

    for network, row in _fallback_table():
        if address.version == network.version and address in network:
            return NetworkInfo(
                ip=ip,
                asn=int(row["asn"]) or None,
                org=row["org"] or None,
                country=row["country"] or None,
                network_type=row["network_type"] or None,
                source="bundled-table",
                note=(
                    row["note"]
                    or "Hand-curated fallback table, not a geolocation database. "
                    "Install GeoLite2 for authoritative data."
                ),
            )

    return NetworkInfo(
        ip=ip,
        source="unavailable",
        note="No geolocation dataset covers this address. No country is claimed.",
    )
