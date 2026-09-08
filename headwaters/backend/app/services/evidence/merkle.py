"""Merkle root over the entry hashes of one case.

A single root commits to every event in the chain. Anchoring 32 bytes externally
is what closes the gap a hash chain cannot close on its own: a chain proves the
log is internally consistent, but not that the log was never rewritten wholesale
by whoever controls it.

Duplicate-leaf handling is explicit. The naive construction promotes a lone odd
node by hashing it with itself, which makes two different trees produce the same
root (CVE-2012-2459 in Bitcoin). Odd nodes are carried up unchanged instead.
"""

from __future__ import annotations

import hashlib


def _pair(left: str, right: str) -> str:
    return hashlib.sha256(bytes.fromhex(left) + bytes.fromhex(right)).hexdigest()


def merkle_root(leaves: list[str]) -> str | None:
    """Root over hex-encoded leaf digests, in order. None for an empty list."""
    if not leaves:
        return None

    level = list(leaves)
    while len(level) > 1:
        nxt: list[str] = []
        for i in range(0, len(level) - 1, 2):
            nxt.append(_pair(level[i], level[i + 1]))
        if len(level) % 2 == 1:
            # Carried up unchanged, NOT duplicated: hashing a lone node with
            # itself lets two distinct trees collide on one root.
            nxt.append(level[-1])
        level = nxt
    return level[0]


def merkle_proof(leaves: list[str], index: int) -> list[tuple[str, str]]:
    """Audit path for one leaf: (sibling_hash, 'left'|'right') pairs.

    Lets a third party verify that one event belongs to an anchored root without
    being given the whole chain -- which matters when the chain contains other
    cases' metadata they have no right to see.
    """
    if not leaves or not 0 <= index < len(leaves):
        return []

    path: list[tuple[str, str]] = []
    level = list(leaves)
    position = index

    while len(level) > 1:
        nxt: list[str] = []
        for i in range(0, len(level) - 1, 2):
            if i == position:
                path.append((level[i + 1], "right"))
            elif i + 1 == position:
                path.append((level[i], "left"))
            nxt.append(_pair(level[i], level[i + 1]))
        if len(level) % 2 == 1:
            nxt.append(level[-1])
        position //= 2
        level = nxt
    return path


def verify_proof(leaf: str, path: list[tuple[str, str]], root: str) -> bool:
    current = leaf
    for sibling, side in path:
        current = _pair(sibling, current) if side == "left" else _pair(current, sibling)
    return current == root
