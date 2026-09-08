"""Canonical JSON.

Every hash in the chain of custody is taken over the output of this module.
Without a fixed canonicalisation rule, verification is not reproducible: two
implementations serialising the same dict with different key order or spacing
produce different digests, and the chain becomes unverifiable by anyone who did
not write it. That is the difference between a real chain of custody and a
picture of one.

The rules, stated so a third party can reimplement them:

* keys sorted lexicographically by Unicode code point
* no insignificant whitespace (``,`` and ``:`` separators, no spaces)
* UTF-8, emitted literally rather than ``\\u``-escaped
* datetimes as RFC 3339 in UTC with a ``Z`` suffix
* no floats -- they are formatted as strings, because float repr is not
  portable and a hash must not depend on the language that computed it
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import Any
from uuid import UUID


def _normalise(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")
    if isinstance(value, UUID):
        return str(value)
    if isinstance(value, float):
        # Formatted, never emitted as a JSON number: float repr differs between
        # languages and a digest must not depend on the one that produced it.
        return f"{value:.6f}"
    if isinstance(value, dict):
        return {str(k): _normalise(v) for k, v in value.items()}
    if isinstance(value, list | tuple):
        return [_normalise(v) for v in value]
    return value


def canonical_json(payload: dict[str, Any]) -> str:
    return json.dumps(
        _normalise(payload),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )


def canonical_hash(payload: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()
