"""MIME parsing.

Every message reaching this module is a live attack that already defeated
somebody's filter. It is parsed defensively: nothing is executed, no URL is
fetched, no archive is expanded, and no HTML is trusted.

DEFERRED (documented, not silently skipped): parsing does not yet run in a
resource-limited subprocess. A pathological MIME tree can therefore still cost
CPU in-process. The size cap and part/depth limits below bound the damage;
``RLIMIT_AS``/``RLIMIT_CPU`` isolation is the remaining hardening step.
"""

from __future__ import annotations

import email
import email.policy
import hashlib
import re
from dataclasses import dataclass, field
from datetime import datetime
from email.message import EmailMessage
from email.utils import getaddresses, parsedate_to_datetime
from typing import Any

from app.core.logging import get_logger

log = get_logger(__name__)

#: Bounds on structural recursion. Real mail never approaches these; malformed
#: mail crafted to exhaust a parser does.
MAX_PARTS = 200
MAX_DEPTH = 20
MAX_BODY_CHARS = 1_000_000

_URL_RE = re.compile(
    r"""(?xi)
    \b(
        (?:https?|ftp)://[^\s<>"'\])}]+       # ordinary URLs
      | hxxps?://[^\s<>"'\])}]+               # defanged, as pasted by analysts
    )
    """
)
_HTML_HREF_RE = re.compile(r"""(?i)href\s*=\s*["']([^"']+)["']""")
_TAG_RE = re.compile(r"(?s)<[^>]+>")
_WS_RE = re.compile(r"[ \t ]+")


@dataclass(slots=True)
class Attachment:
    filename: str | None
    content_type: str
    size_bytes: int
    sha256: str
    is_archive: bool
    #: True when the declared extension disagrees with the declared MIME type --
    #: a cheap, high-signal mismatch (``invoice.pdf`` sent as an executable).
    extension_mismatch: bool


@dataclass(slots=True)
class ParsedEmail:
    """The structured form of one message. Purely derived from bytes."""

    raw_sha256: str
    size_bytes: int
    #: Every header, in emission order. Order is a stable fingerprint of the
    #: sending toolchain (Email DNA locus M), so it is never collapsed to a map.
    headers: list[tuple[str, str]]
    subject: str | None
    date: datetime | None
    text_body: str
    html_present: bool
    urls: list[str]
    attachments: list[Attachment]
    defects: list[str] = field(default_factory=list)

    def get_all(self, name: str) -> list[str]:
        """Every occurrence of a header, in order. Duplicates matter: two From
        headers is both an RFC violation and a real attack."""
        lowered = name.lower()
        return [v for k, v in self.headers if k.lower() == lowered]

    def get(self, name: str) -> str | None:
        values = self.get_all(name)
        return values[0] if values else None


def parse_email(raw: bytes) -> ParsedEmail:
    """Parse RFC 5322 bytes into a structured, safe representation."""
    digest = hashlib.sha256(raw).hexdigest()
    defects: list[str] = []

    # policy.default gives structured header parsing and tolerates real-world
    # violations instead of raising -- which matters, because hostile mail is
    # deliberately non-conforming.
    message = email.message_from_bytes(raw, policy=email.policy.default)
    if not isinstance(message, EmailMessage):  # pragma: no cover - defensive
        raise ValueError("message did not parse as an EmailMessage")

    headers: list[tuple[str, str]] = []
    for key, value in message.items():
        # Header values are attacker-controlled. CR/LF is stripped so a value can
        # never re-open header parsing anywhere downstream (log lines, reports).
        headers.append((str(key), str(value).replace("\r", " ").replace("\n", " ").strip()))

    if message.defects:
        defects.extend(type(d).__name__ for d in message.defects)

    text_parts: list[str] = []
    html_parts: list[str] = []
    attachments: list[Attachment] = []
    _walk(message, text_parts, html_parts, attachments, defects, depth=0, budget=[MAX_PARTS])

    text_body = "\n".join(text_parts)[:MAX_BODY_CHARS]
    html_blob = "\n".join(html_parts)[:MAX_BODY_CHARS]

    # If there is no text/plain alternative, derive readable text from the HTML
    # by stripping tags. Tags are removed, never rendered -- the dashboard shows
    # plain text by default for exactly this reason.
    if not text_body.strip() and html_blob:
        text_body = _WS_RE.sub(" ", _TAG_RE.sub(" ", html_blob)).strip()[:MAX_BODY_CHARS]

    urls = _extract_urls(text_body, html_blob)

    subject = message.get("Subject")
    date = _parse_date(message.get("Date"))

    return ParsedEmail(
        raw_sha256=digest,
        size_bytes=len(raw),
        headers=headers,
        subject=str(subject).strip() if subject else None,
        date=date,
        text_body=text_body,
        html_present=bool(html_blob.strip()),
        urls=urls,
        attachments=attachments,
        defects=sorted(set(defects)),
    )


def _walk(
    part: Any,
    text_parts: list[str],
    html_parts: list[str],
    attachments: list[Attachment],
    defects: list[str],
    *,
    depth: int,
    budget: list[int],
) -> None:
    """Depth- and count-bounded MIME traversal."""
    if depth > MAX_DEPTH:
        defects.append("max_mime_depth_exceeded")
        return
    if budget[0] <= 0:
        defects.append("max_mime_parts_exceeded")
        return
    budget[0] -= 1

    if part.is_multipart():
        for child in part.iter_parts():
            _walk(
                child, text_parts, html_parts, attachments, defects, depth=depth + 1, budget=budget
            )
        return

    content_type = (part.get_content_type() or "application/octet-stream").lower()
    disposition = (part.get_content_disposition() or "").lower()
    filename = part.get_filename()

    try:
        payload = part.get_payload(decode=True)
    except Exception as exc:  # malformed encodings are common in hostile mail
        defects.append(f"undecodable_part:{type(exc).__name__}")
        return

    if payload is None:
        return

    if disposition == "attachment" or filename:
        attachments.append(_describe_attachment(filename, content_type, payload))
        return

    if content_type == "text/plain":
        text_parts.append(_decode(payload, part))
    elif content_type == "text/html":
        html_parts.append(_decode(payload, part))
    else:
        # Inline images and anything else are recorded, never rendered.
        attachments.append(_describe_attachment(filename, content_type, payload))


def _describe_attachment(filename: str | None, content_type: str, payload: bytes) -> Attachment:
    """Record an attachment. It is hashed and described -- never executed,
    never opened, and never written with its original extension."""
    archive_types = {
        "application/zip",
        "application/x-zip-compressed",
        "application/x-rar-compressed",
        "application/x-7z-compressed",
        "application/gzip",
        "application/x-tar",
    }
    archive_exts = (".zip", ".rar", ".7z", ".gz", ".tar", ".iso", ".img")
    name = (filename or "").lower()
    is_archive = content_type in archive_types or name.endswith(archive_exts)

    # Archives are hashed and described only. Expanding attacker-supplied
    # archives in-process is how a decompression bomb takes a service down.
    expected = {
        ".pdf": "application/pdf",
        ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        ".html": "text/html",
        ".htm": "text/html",
    }
    ext = name[name.rfind(".") :] if "." in name else ""
    mismatch = bool(ext and ext in expected and expected[ext] != content_type)

    return Attachment(
        filename=filename,
        content_type=content_type,
        size_bytes=len(payload),
        sha256=hashlib.sha256(payload).hexdigest(),
        is_archive=is_archive,
        extension_mismatch=mismatch,
    )


def _decode(payload: bytes, part: Any) -> str:
    charset = part.get_content_charset() or "utf-8"
    try:
        return payload.decode(charset, errors="replace")
    except LookupError:
        # An unknown or fabricated charset must not stop the analysis.
        return payload.decode("utf-8", errors="replace")


def _extract_urls(text: str, html: str) -> list[str]:
    """Collect URLs from body text and HTML hrefs.

    Refanged for analysis but never fetched: extracting a URL from hostile mail
    and then requesting it is a server-side request forgery hole straight into
    the cloud metadata endpoint.
    """
    found: list[str] = []
    for match in _URL_RE.finditer(text):
        found.append(match.group(1))
    for match in _URL_RE.finditer(html):
        found.append(match.group(1))
    for match in _HTML_HREF_RE.finditer(html):
        href = match.group(1).strip()
        if href.lower().startswith(("http://", "https://", "hxxp://", "hxxps://")):
            found.append(href)

    seen: dict[str, None] = {}
    for url in found:
        refanged = url.replace("hxxp", "http").replace("[.]", ".").rstrip(".,;)>\"'")
        seen.setdefault(refanged, None)
    return list(seen)


def _parse_date(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        return parsedate_to_datetime(str(value))
    except (TypeError, ValueError):
        return None


def addresses_in(header_value: str | None) -> list[tuple[str, str]]:
    """(display_name, addr_spec) pairs. Tolerates malformed address lists."""
    if not header_value:
        return []
    try:
        return [(n.strip(), a.strip().lower()) for n, a in getaddresses([header_value]) if a]
    except Exception:
        return []
