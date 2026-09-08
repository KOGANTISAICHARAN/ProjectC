"""DNS lookups for authentication verification.

Band B: every function here reaches the network and can fail. Each returns a
result object carrying whether the lookup actually happened, so a caller can
distinguish "checked and found nothing" from "could not check" -- the same
distinction the scoring engine makes between an evaluated and an unevaluated
signal group.
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from typing import Any

from app.core.logging import get_logger

log = get_logger(__name__)

DEFAULT_TIMEOUT = 3.0


@dataclass(frozen=True, slots=True)
class TxtLookup:
    name: str
    records: tuple[str, ...]
    resolved: bool
    error: str | None = None


def _resolver() -> Any:
    import dns.resolver

    resolver = dns.resolver.Resolver()
    resolver.timeout = DEFAULT_TIMEOUT
    resolver.lifetime = DEFAULT_TIMEOUT
    return resolver


def txt(name: str) -> TxtLookup:
    """Fetch TXT records. Never raises: DNS being unavailable is a normal
    operating condition, not an exception."""
    try:
        answers = _resolver().resolve(name, "TXT")
        records = tuple(
            b"".join(part for part in rdata.strings).decode("utf-8", "replace") for rdata in answers
        )
        return TxtLookup(name=name, records=records, resolved=True)
    except Exception as exc:
        name_of = type(exc).__name__
        log.debug("dns.txt_failed", name=name, error=name_of)
        return TxtLookup(name=name, records=(), resolved=False, error=name_of)


@lru_cache(maxsize=512)
def registrable_domain(domain: str) -> str:
    """Organisational domain via the Public Suffix List.

    The last-two-labels heuristic this replaces is wrong for ``co.uk``,
    ``com.au`` and several hundred other suffixes. Since DMARC alignment is
    computed on the organisational domain, that heuristic produced genuinely
    wrong alignment verdicts, not merely imprecise ones.
    """
    try:
        # suffix_list_urls=() pins the extractor to its bundled snapshot: a
        # forensic tool must not silently fetch a different suffix list mid-run,
        # and Band A has to work with no network at all.
        extractor = _extractor()
        parts = extractor(domain)
        if parts.domain and parts.suffix:
            return f"{parts.domain}.{parts.suffix}".lower()
    except Exception as exc:
        log.debug("psl.failed", domain=domain, error=str(exc)[:80])

    labels = domain.strip(".").lower().split(".")
    return ".".join(labels[-2:]) if len(labels) >= 2 else domain.lower()


@lru_cache(maxsize=1)
def _extractor() -> Any:
    import tldextract

    return tldextract.TLDExtract(suffix_list_urls=(), fallback_to_snapshot=True)
