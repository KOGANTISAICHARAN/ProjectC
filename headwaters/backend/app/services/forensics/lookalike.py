"""Impersonation detection: lookalike domains and display-name spoofing.

Two cheap, high-signal checks that catch what authentication cannot. An attacker
who registers ``kaverifs-corp.com`` and configures SPF, DKIM and DMARC correctly
passes every authentication check in existence -- because those checks ask "does
this domain's paperwork match itself", never "is this really the CEO".
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass

#: Characters that are visually confusable with ASCII. A curated subset of the
#: Unicode confusables table, which replaces this in Phase 4.
_CONFUSABLES = {
    "а": "a",
    "е": "e",
    "о": "o",
    "р": "p",
    "с": "c",
    "х": "x",
    "у": "y",  # Cyrillic
    "і": "i",
    "ѕ": "s",
    "ԁ": "d",
    "ɡ": "g",
    "ⅼ": "l",
    "ｍ": "m",
    "α": "a",
    "ο": "o",
    "ρ": "p",
    "ν": "v",
    "τ": "t",  # Greek
    "0": "o",
    "1": "l",
    "5": "s",
}

#: Zero-width and direction-control characters. Presence in a From header is
#: never legitimate: they exist to make one string render as another.
_INVISIBLE = re.compile(r"[​-‏‪-‮⁠-⁤﻿]")


@dataclass(slots=True)
class ImpersonationSignal:
    rule_id: str
    title: str
    detail: str
    evidence: str
    severity: str


def skeleton(value: str) -> str:
    """Reduce a string to its visual skeleton for confusable comparison."""
    normalised = unicodedata.normalize("NFKC", value).lower()
    return "".join(_CONFUSABLES.get(ch, ch) for ch in normalised)


def damerau_levenshtein(a: str, b: str) -> int:
    """Edit distance including transposition -- ``kaveri`` vs ``kavrei`` is one
    slip, not two, and attackers rely on that."""
    if a == b:
        return 0
    previous: list[int] = list(range(len(b) + 1))
    before_previous: list[int] = []
    for i, ca in enumerate(a, start=1):
        current = [i] + [0] * len(b)
        for j, cb in enumerate(b, start=1):
            cost = 0 if ca == cb else 1
            current[j] = min(current[j - 1] + 1, previous[j] + 1, previous[j - 1] + cost)
            if i > 1 and j > 1 and ca == b[j - 2] and a[i - 2] == cb:
                current[j] = min(current[j], before_previous[j - 2] + cost)
        before_previous, previous = previous, current
    return previous[len(b)]


def analyse_identity(
    *,
    from_display: str | None,
    from_domain: str | None,
    reply_to_domain: str | None,
    protected_domains: tuple[str, ...],
    protected_identities: tuple[str, ...],
) -> list[ImpersonationSignal]:
    """Compare the claimed identity against the organisation's own."""
    signals: list[ImpersonationSignal] = []
    display = (from_display or "").strip()
    domain = (from_domain or "").lower()

    if display and _INVISIBLE.search(display):
        signals.append(
            ImpersonationSignal(
                "IDENT_INVISIBLE_CHARS",
                "Invisible characters in sender display name",
                "Zero-width or direction-control characters make a display name render "
                "as text different from what it contains. There is no legitimate use "
                "for this in a sender name.",
                repr(display),
                "high",
            )
        )

    if display and protected_identities:
        folded = display.casefold()
        for identity in protected_identities:
            if identity.casefold() in folded:
                signals.append(
                    ImpersonationSignal(
                        "IDENT_PROTECTED_DISPLAY_NAME",
                        f"Display name claims a protected identity: {identity}",
                        "The sender's display name matches a named executive or "
                        "internal role. Most mail clients show only this name, not the "
                        "address behind it.",
                        display,
                        "high",
                    )
                )
                break

    if domain and protected_domains:
        skeleton_domain = skeleton(domain)
        for protected in protected_domains:
            if domain == protected:
                continue
            distance = damerau_levenshtein(skeleton_domain, skeleton(protected))
            contains = protected.split(".")[0] in domain
            if distance <= 3 or contains:
                signals.append(
                    ImpersonationSignal(
                        "IDENT_LOOKALIKE_DOMAIN",
                        f"Sender domain resembles a protected domain ({protected})",
                        f"'{domain}' is {distance} edit(s) from '{protected}' after "
                        f"normalising visually confusable characters. Authentication "
                        f"cannot detect this: the attacker owns this domain and can "
                        f"configure it perfectly.",
                        f"{domain} ~ {protected}",
                        "critical",
                    )
                )
                break

    if reply_to_domain and domain and reply_to_domain != domain:
        signals.append(
            ImpersonationSignal(
                "IDENT_REPLY_TO_DIVERGENT",
                "Replies leave the sending domain",
                f"Reply-To is '{reply_to_domain}' while From is '{domain}'. Legitimate "
                f"for mailing lists and ticketing systems, so this is scored in "
                f"context rather than on its own.",
                f"From: {domain} / Reply-To: {reply_to_domain}",
                "medium",
            )
        )

    return signals
