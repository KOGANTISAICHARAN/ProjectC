"""Email DNA: a sectioned campaign fingerprint.

An embedding of the body is a weak fingerprint. Attackers rewrite text
trivially, and all phishing sounds alike. A *sectioned* fingerprint is far
stronger, because it separates the loci an attacker rotates cheaply from the
ones they almost never change.

    I  infrastructure   FEOS prefix, ASN, rDNS suffix, boundary provider
    D  identity         From/Reply-To registrable domains, display-name tokens
    N  naming           lexical shape of the attacker's domains
    M  tooling          header EMISSION ORDER, MIME tree, Message-ID template,
                        X-Mailer, boundary format
    C  content          placeholder-normalised text, SimHash
    P  payload          attachment digests, URL path templates

Locus M is the one that matters. The order a mail library emits headers, the
MIME tree it builds and the shape of its multipart boundaries are a stable
signature of the sending software -- the mail analogue of a JA3 hash. It
survives the three things that actually change between waves: the domain, the
IP address, and the wording.

A match is an OPERATIONAL LINKAGE HYPOTHESIS, never attribution. The same
fingerprint arises from one actor, one purchased phishing kit, or one
phishing-as-a-service platform used by fifty unrelated actors. See
docs/CLAIM_CONTRACT.md.
"""

from __future__ import annotations

import hashlib
import math
import re
from collections import Counter
from dataclasses import dataclass, field
from typing import Any

from app.services.analysis import AnalysisResult

#: Per-locus weights. I and M dominate because they are the expensive things for
#: an attacker to change; C is deliberately small because text is free to rewrite.
LOCUS_WEIGHTS: dict[str, float] = {
    "i": 0.22,  # infrastructure -- rotated between waves, but expensive
    "d": 0.12,  # identity -- rotated cheaply, so weighted low
    "n": 0.13,  # naming habits -- survives a domain change
    "m": 0.28,  # tooling -- the locus attackers do NOT change
    "c": 0.12,  # content -- free to rewrite, so weighted lowest
    "p": 0.13,  # payload structure
}

#: Headers whose ordering is characteristic of the sending software rather than
#: of the message. Trace headers are excluded: they are added by receivers.
_FINGERPRINT_HEADERS = {
    "from",
    "to",
    "cc",
    "bcc",
    "reply-to",
    "return-path",
    "subject",
    "date",
    "message-id",
    "mime-version",
    "content-type",
    "content-transfer-encoding",
    "x-mailer",
    "user-agent",
    "x-priority",
    "importance",
    "list-id",
    "list-unsubscribe",
    "in-reply-to",
    "references",
    "organization",
}

_MSGID_DIGITS = re.compile(r"\d+")
_MSGID_HEX = re.compile(r"\b[0-9a-f]{6,}\b", re.IGNORECASE)
_PLACEHOLDER = [
    (re.compile(r"\b[\d,]+(?:\.\d+)?\b"), "<NUM>"),
    (re.compile(r"https?://\S+"), "<URL>"),
    (re.compile(r"\b[\w.+-]+@[\w.-]+\b"), "<EMAIL>"),
    (re.compile(r"\b\d{1,2}[:.]\d{2}\b"), "<TIME>"),
]


@dataclass(slots=True)
class Dna:
    loci: dict[str, dict[str, Any]] = field(default_factory=dict)
    barcode: str = ""
    version: str = "v1"


def compute_dna(result: AnalysisResult) -> Dna:
    loci = {
        "i": _locus_infrastructure(result),
        "d": _locus_identity(result),
        "n": _locus_naming(result),
        "m": _locus_tooling(result),
        "c": _locus_content(result),
        "p": _locus_payload(result),
    }
    return Dna(loci=loci, barcode=_barcode(loci))


# ------------------------------------------------------------------- loci ---
def _locus_infrastructure(r: AnalysisResult) -> dict[str, Any]:
    prefixes: list[str] = []
    for hop in r.hops:
        if hop.observed_ip and hop.ip_class.value == "public":
            prefix = _prefix(hop.observed_ip)
            if prefix:
                prefixes.append(prefix)
    boundary_host = (
        r.hops[r.origin.boundary_seq].by_host
        if r.origin.boundary_seq is not None and r.origin.boundary_seq < len(r.hops)
        else None
    )
    return {
        "feos_prefix": _prefix(r.origin.feos_ip) if r.origin.feos_ip else None,
        "prefixes": sorted(set(prefixes)),
        "boundary_provider": _suffix(boundary_host, 2),
        "rdns_suffixes": sorted({_suffix(h.rdns_claim, 2) for h in r.hops if h.rdns_claim}),
    }


def _locus_identity(r: AnalysisResult) -> dict[str, Any]:
    return {
        "from_domain": _registrable(r.from_domain),
        "reply_to_domain": _registrable(
            r.reply_to_address.rsplit("@", 1)[-1] if r.reply_to_address else None
        ),
        "return_path_domain": _registrable(
            r.return_path.rsplit("@", 1)[-1] if r.return_path else None
        ),
        "display_tokens": sorted(
            t.lower() for t in re.findall(r"[A-Za-z]{2,}", r.from_display or "")
        ),
        "local_part_shape": _shape(
            r.from_address.split("@", 1)[0] if r.from_address and "@" in r.from_address else ""
        ),
    }


def _locus_naming(r: AnalysisResult) -> dict[str, Any]:
    """Lexical shape of the domains the attacker registered.

    Catches ``secure-hdfc-login.xyz`` next to ``hdfc-secure-verify.xyz``: the
    strings differ, the construction habit does not.
    """
    domains = [d for d in {r.from_domain, _url_host(r)} if d]
    if not domains:
        return {"features": [], "tld": None, "trigrams": []}

    primary = domains[0]
    label = primary.split(".")[0]
    return {
        "tld": primary.rsplit(".", 1)[-1] if "." in primary else None,
        "features": [
            len(label),
            label.count("-"),
            sum(c.isdigit() for c in label),
            round(_entropy(label), 2),
            len(primary.split(".")),
        ],
        "trigrams": sorted({label[i : i + 3] for i in range(max(0, len(label) - 2))}),
    }


def _locus_tooling(r: AnalysisResult) -> dict[str, Any]:
    """The toolchain fingerprint. The locus attackers do not rotate."""
    order = [name.lower() for name, _ in r.parsed.headers if name.lower() in _FINGERPRINT_HEADERS]
    # Deduplicate while preserving first-appearance order: the SEQUENCE is the
    # signal, not the multiset.
    seen: dict[str, None] = {}
    for name in order:
        seen.setdefault(name, None)
    header_order = list(seen)

    content_type = r.parsed.get("Content-Type") or ""
    boundary = re.search(r'boundary="?([^";]+)"?', content_type)

    return {
        "header_order": header_order,
        "header_order_hash": _sha(header_order),
        "x_mailer": (r.parsed.get("X-Mailer") or r.parsed.get("User-Agent") or "").strip()[:120]
        or None,
        "mime_root": content_type.split(";")[0].strip().lower() or None,
        "mime_parts": sorted(a.content_type for a in r.parsed.attachments),
        "boundary_shape": _token_shape(boundary.group(1)) if boundary else None,
        "message_id_template": _msgid_template(r.message_id),
    }


def _locus_content(r: AnalysisResult) -> dict[str, Any]:
    """Placeholder-normalised text: names, sums, times and links replaced, so a
    template survives having its details swapped."""
    text = r.parsed.text_body.lower()
    for pattern, token in _PLACEHOLDER:
        text = pattern.sub(token, text)
    tokens = re.findall(r"[a-z<>]{3,}", text)
    return {
        "simhash": _simhash(tokens),
        "token_count": len(tokens),
        "template_markers": sorted({f.rule_id for f in r.findings if f.group.value == "content"}),
    }


def _locus_payload(r: AnalysisResult) -> dict[str, Any]:
    paths: list[str] = []
    for url in r.parsed.urls[:50]:
        tail = url.split("//", 1)[-1]
        path = "/" + tail.split("/", 1)[1] if "/" in tail else "/"
        paths.append(_shape(path.split("?")[0]))
    return {
        "attachment_hashes": sorted(a.sha256 for a in r.parsed.attachments),
        "url_path_shapes": sorted(set(paths)),
        "url_hosts": sorted(
            {u.split("//", 1)[-1].split("/", 1)[0].lower() for u in r.parsed.urls[:50]}
        ),
    }


# ------------------------------------------------------------- similarity ---
def similarity(a: Dna, b: Dna) -> tuple[float, dict[str, float]]:
    """Weighted per-locus similarity, with the breakdown that justifies it.

    A linkage that cannot explain itself is not intelligence, so the caller
    always receives the per-locus scores alongside the total.
    """
    per: dict[str, float] = {}
    for locus in LOCUS_WEIGHTS:
        left, right = a.loci.get(locus, {}), b.loci.get(locus, {})
        per[locus] = round(_locus_similarity(locus, left, right) if left and right else 0.0, 4)
    total = round(sum(per[k] * w for k, w in LOCUS_WEIGHTS.items()), 4)
    return total, per


def _locus_similarity(locus: str, a: dict[str, Any], b: dict[str, Any]) -> float:
    if locus == "m":
        # Order-aware: a shared header SEQUENCE is far stronger evidence than a
        # shared header set, and an exact match is the strongest signal we have.
        score = 0.0
        if a.get("header_order_hash") and a["header_order_hash"] == b.get("header_order_hash"):
            score += 0.45
        else:
            score += 0.45 * _lcs_ratio(a.get("header_order", []), b.get("header_order", []))
        if a.get("x_mailer") and a["x_mailer"] == b.get("x_mailer"):
            score += 0.20
        if a.get("message_id_template") and a["message_id_template"] == b.get(
            "message_id_template"
        ):
            score += 0.20
        if a.get("boundary_shape") and a["boundary_shape"] == b.get("boundary_shape"):
            score += 0.15
        return min(1.0, score)

    if locus == "c":
        sim = 0.0
        if a.get("simhash") and b.get("simhash"):
            distance = bin(int(a["simhash"], 16) ^ int(b["simhash"], 16)).count("1")
            sim += 0.7 * max(0.0, 1.0 - distance / 64.0)
        sim += 0.3 * _jaccard(a.get("template_markers", []), b.get("template_markers", []))
        return min(1.0, sim)

    if locus == "n":
        left, right = a.get("features") or [], b.get("features") or []
        feature_sim = _cosine(left, right) if left and right else 0.0
        tld_sim = 1.0 if a.get("tld") and a["tld"] == b.get("tld") else 0.0
        gram_sim = _jaccard(a.get("trigrams", []), b.get("trigrams", []))
        return min(1.0, 0.4 * feature_sim + 0.2 * tld_sim + 0.4 * gram_sim)

    # I, D and P are set-shaped: Jaccard over every list/scalar in the locus.
    left_set, right_set = _flatten(a), _flatten(b)
    return _jaccard(left_set, right_set)


# ------------------------------------------------------------------ helpers -
def _flatten(locus: dict[str, Any]) -> list[str]:
    out: list[str] = []
    for key, value in locus.items():
        if value is None:
            continue
        if isinstance(value, list):
            out += [f"{key}={v}" for v in value if v is not None]
        else:
            out.append(f"{key}={value}")
    return out


def _jaccard(a: list[str], b: list[str]) -> float:
    sa, sb = set(a), set(b)
    if not sa and not sb:
        return 0.0
    return len(sa & sb) / len(sa | sb)


def _cosine(a: list[float], b: list[float]) -> float:
    if len(a) != len(b):
        return 0.0
    dot = sum(x * y for x, y in zip(a, b, strict=True))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(y * y for y in b))
    return dot / (na * nb) if na and nb else 0.0


def _lcs_ratio(a: list[str], b: list[str]) -> float:
    """Longest common subsequence ratio: order-sensitive, unlike a set overlap."""
    if not a or not b:
        return 0.0
    prev = [0] * (len(b) + 1)
    for x in a:
        cur = [0] * (len(b) + 1)
        for j, y in enumerate(b, start=1):
            cur[j] = prev[j - 1] + 1 if x == y else max(prev[j], cur[j - 1])
        prev = cur
    return prev[len(b)] / max(len(a), len(b))


def _simhash(tokens: list[str], bits: int = 64) -> str:
    if not tokens:
        return "0" * 16
    vector = [0] * bits
    for token, count in Counter(tokens).items():
        digest = int(hashlib.md5(token.encode(), usedforsecurity=False).hexdigest(), 16)
        for bit in range(bits):
            vector[bit] += count if (digest >> bit) & 1 else -count
    value = sum(1 << bit for bit in range(bits) if vector[bit] > 0)
    return f"{value:016x}"


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    total = len(value)
    return -sum((n / total) * math.log2(n / total) for n in counts.values())


def _shape(value: str) -> str:
    """Character-class skeleton: 'abc-123' -> 'aaa-999'. Matches construction
    habits rather than exact strings."""
    out: list[str] = []
    for ch in value[:80]:
        out.append("9" if ch.isdigit() else "a" if ch.isalpha() else ch)
    # Collapse runs so length noise does not dominate.
    return re.sub(r"(.)\1{2,}", r"\1\1\1", "".join(out))


def _token_shape(value: str) -> str:
    """Structural skeleton: each alphanumeric run becomes ``w<length>``.

    ``b1_9f2a1c88213`` and ``b1_7c33a144172`` are the same construction from the
    same library; a character-class shape separates them only because one run
    happens to begin with a digit.
    """
    return re.sub(r"[A-Za-z0-9]+", lambda m: f"w{len(m.group())}", value[:80])


def _msgid_template(message_id: str | None) -> str | None:
    """Reduce a Message-ID local part to its generator's template.

    Hex substitution runs BEFORE digits: a decimal timestamp such as ``20260902``
    is also a valid hex string, so substituting digits first consumed it and two
    IDs from the same generator normalised to different templates.
    """
    if not message_id:
        return None
    local = message_id.strip("<>").split("@", 1)[0]
    return _MSGID_DIGITS.sub("N", _MSGID_HEX.sub("H", local))[:60]


def _prefix(ip: str | None) -> str | None:
    if not ip:
        return None
    if ":" in ip:
        return ":".join(ip.split(":")[:3]) + "::/48"
    return ".".join(ip.split(".")[:3]) + ".0/24"


def _suffix(host: str | None, labels: int) -> str | None:
    if not host:
        return None
    parts = host.strip(".").split(".")
    return ".".join(parts[-labels:]) if len(parts) >= labels else host


def _registrable(domain: str | None) -> str | None:
    if not domain:
        return None
    parts = domain.strip(".").lower().split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else domain


def _url_host(r: AnalysisResult) -> str | None:
    if not r.parsed.urls:
        return None
    return r.parsed.urls[0].split("//", 1)[-1].split("/", 1)[0].lower() or None


def _sha(value: Any) -> str:
    return hashlib.sha256(str(value).encode()).hexdigest()[:32]


def _barcode(loci: dict[str, dict[str, Any]]) -> str:
    """Six eight-cell bands, one per locus, for the side-by-side UI comparison.

    Each cell is a hex nibble derived from the locus digest, so two related
    fingerprints visibly share cells without anyone reading a number.
    """
    bands: list[str] = []
    for key in ("i", "d", "n", "m", "c", "p"):
        digest = hashlib.sha256(str(sorted(loci.get(key, {}).items())).encode()).hexdigest()
        bands.append(digest[:8])
    return "".join(bands)
