"""Ed25519 signing for evidence events.

Integrity says the log was not altered. A signature says *this analyser*
produced it -- non-repudiation, which is what an auditor actually asks for.

The public key is published in every report so a third party can verify without
us. Key rotation never re-signs history: old events stay signed by the old key,
whose public half remains published, or every prior case becomes unverifiable.
"""

from __future__ import annotations

import base64
import hashlib

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from app.core.config import get_settings
from app.core.logging import get_logger

log = get_logger(__name__)

#: Deterministic key used when no key is configured. Derived from a fixed seed so
#: verification still works across restarts in development -- a key regenerated
#: on every boot would make yesterday's chain unverifiable today, which looks
#: exactly like tampering. Never used when EVIDENCE_SIGNING_KEY is set, and the
#: key id makes its provenance obvious in every report.
_DEV_SEED = hashlib.sha256(b"headwaters-development-signing-key-not-for-production").digest()


class Signer:
    """Signs and verifies evidence entries."""

    def __init__(self, private_key: Ed25519PrivateKey, key_id: str) -> None:
        self._private = private_key
        self.key_id = key_id

    @classmethod
    def from_settings(cls) -> Signer:
        configured = get_settings().evidence_signing_key
        if configured:
            raw = base64.b64decode(configured)
            key = Ed25519PrivateKey.from_private_bytes(raw)
            return cls(key, key_id=_key_id(key.public_key()))

        log.warning(
            "evidence.signing.development_key",
            note="EVIDENCE_SIGNING_KEY is unset; using a deterministic development "
            "key. Signatures are reproducible but carry no assurance.",
        )
        key = Ed25519PrivateKey.from_private_bytes(_DEV_SEED)
        return cls(key, key_id=f"dev-{_key_id(key.public_key())}")

    def sign(self, entry_hash: str) -> str:
        return base64.b64encode(self._private.sign(bytes.fromhex(entry_hash))).decode()

    def public_key_b64(self) -> str:
        from cryptography.hazmat.primitives.serialization import (
            Encoding,
            PublicFormat,
        )

        return base64.b64encode(
            self._private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        ).decode()

    def verify(self, entry_hash: str, signature: str | None) -> bool:
        if not signature:
            return False
        try:
            self._private.public_key().verify(
                base64.b64decode(signature), bytes.fromhex(entry_hash)
            )
            return True
        except (InvalidSignature, ValueError):
            return False


def _key_id(public: Ed25519PublicKey) -> str:
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    raw = public.public_bytes(Encoding.Raw, PublicFormat.Raw)
    return hashlib.sha256(raw).hexdigest()[:16]
