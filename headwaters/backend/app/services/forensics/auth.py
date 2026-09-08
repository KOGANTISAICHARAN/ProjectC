"""Authentication-Results evaluation.

THE TRAP THIS MODULE EXISTS TO AVOID
------------------------------------
Attackers inject their own ``Authentication-Results: ... spf=pass; dkim=pass;
dmarc=pass`` header into a message before sending it. A parser that reads the
first one it finds reports a clean bill of health for a hostile email.

The rule: accept only the topmost ``Authentication-Results`` whose *authserv-id*
belongs to infrastructure we recognise. Every other one is discarded -- but not
silently. The mere presence of an extra header below the trust boundary is a
strong indicator of deliberate evasion and becomes a finding of its own.

DEFERRED: live SPF re-evaluation and DKIM signature verification (Phase 4).
Results here are those *reported by our own MTA at delivery time*, which for SPF
is the authoritative answer anyway -- SPF is evaluated against DNS as it existed
then, and a present-day re-check is corroborating context, not the result.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from app.models.enums import AuthMechanism, AuthResult

_AUTHSERV_RE = re.compile(r"^\s*(?P<authserv>[A-Za-z0-9._-]+)\s*(?:;|$)")
_MECH_RE = re.compile(r"(?i)\b(?P<mech>spf|dkim|dmarc|arc)\s*=\s*(?P<result>[a-z]+)")
_DKIM_D_RE = re.compile(r"(?i)header\.d\s*=\s*(?P<d>[A-Za-z0-9._-]+)")
_DKIM_S_RE = re.compile(r"(?i)header\.s\s*=\s*(?P<s>[A-Za-z0-9._-]+)")
_FROM_DOMAIN_RE = re.compile(r"(?i)header\.from\s*=\s*(?P<d>[A-Za-z0-9._-]+)")
_MAILFROM_RE = re.compile(r"(?i)smtp\.mailfrom\s*=\s*(?P<d>[A-Za-z0-9._@-]+)")


@dataclass(slots=True)
class AuthFinding:
    mechanism: AuthMechanism
    result_reported: AuthResult
    authserv_id: str | None
    trusted_source: bool
    d_domain: str | None = None
    selector: str | None = None
    aligned: bool | None = None
    caveat: str | None = None


@dataclass(slots=True)
class AuthEvaluation:
    findings: list[AuthFinding]
    #: Authentication-Results headers we refused to trust.
    discarded: int
    #: True when an untrusted A-R header asserted a pass. Evidence of evasion.
    forged_pass_detected: bool
    trusted_authserv: str | None


def _to_result(value: str) -> AuthResult:
    try:
        return AuthResult(value.lower())
    except ValueError:
        return AuthResult.NONE


def evaluate_authentication(
    ar_headers: list[str],
    *,
    trusted_authserv_suffixes: tuple[str, ...],
    from_domain: str | None,
) -> AuthEvaluation:
    """Evaluate Authentication-Results, trusting only recognised authserv-ids.

    ``ar_headers`` must be in prepend order (index 0 = topmost = added last by
    the most trusted hop).
    """
    trusted_index: int | None = None
    trusted_authserv: str | None = None

    for index, header in enumerate(ar_headers):
        match = _AUTHSERV_RE.match(header)
        authserv = match.group("authserv").lower() if match else None
        if authserv and any(
            authserv == s or authserv.endswith("." + s) for s in trusted_authserv_suffixes
        ):
            trusted_index, trusted_authserv = index, authserv
            break

    findings: list[AuthFinding] = []
    forged_pass = False

    for index, header in enumerate(ar_headers):
        is_trusted = index == trusted_index
        match = _AUTHSERV_RE.match(header)
        authserv = match.group("authserv").lower() if match else None

        for mech_match in _MECH_RE.finditer(header):
            mechanism = AuthMechanism(mech_match.group("mech").lower())
            result = _to_result(mech_match.group("result"))

            if not is_trusted:
                # An untrusted header claiming a pass is the injection attack.
                if result is AuthResult.PASS:
                    forged_pass = True
                continue

            d_match = _DKIM_D_RE.search(header)
            s_match = _DKIM_S_RE.search(header)
            aligned = _alignment(mechanism, header, from_domain, d_match)

            findings.append(
                AuthFinding(
                    mechanism=mechanism,
                    result_reported=result,
                    authserv_id=authserv,
                    trusted_source=True,
                    d_domain=d_match.group("d").lower() if d_match else None,
                    selector=s_match.group("s") if s_match else None,
                    aligned=aligned,
                    caveat=(
                        "Reported by the receiving MTA at delivery time. SPF is "
                        "evaluated against DNS as it then existed; a present-day "
                        "re-check is corroborating context, not the result."
                        if mechanism is AuthMechanism.SPF
                        else None
                    ),
                )
            )

    return AuthEvaluation(
        findings=findings,
        discarded=max(0, len(ar_headers) - (1 if trusted_index is not None else 0)),
        forged_pass_detected=forged_pass,
        trusted_authserv=trusted_authserv,
    )


def _alignment(
    mechanism: AuthMechanism, header: str, from_domain: str | None, d_match: re.Match[str] | None
) -> bool | None:
    """Does the passing identifier match the identity a human actually reads?

    This -- not the pass/fail -- is the question that matters. An attacker who
    registers their own lookalike domain and configures it correctly earns a
    legitimate ``spf=pass``; what they cannot earn is alignment with the domain
    they are impersonating.
    """
    if not from_domain:
        return None

    if mechanism is AuthMechanism.DKIM and d_match:
        return _same_org_domain(d_match.group("d").lower(), from_domain)

    if mechanism is AuthMechanism.SPF:
        mailfrom = _MAILFROM_RE.search(header)
        if mailfrom:
            envelope = mailfrom.group("d").lower().rsplit("@", 1)[-1]
            return _same_org_domain(envelope, from_domain)

    if mechanism is AuthMechanism.DMARC:
        hf = _FROM_DOMAIN_RE.search(header)
        if hf:
            return _same_org_domain(hf.group("d").lower(), from_domain)

    return None


def _same_org_domain(a: str, b: str) -> bool:
    """Registrable-domain comparison.

    DEFERRED: uses a last-two-labels heuristic. The Public Suffix List replaces
    this in Phase 4 -- the heuristic is wrong for multi-part suffixes such as
    ``co.uk`` and ``com.au``, and that is a real limitation, not a rounding
    error.
    """
    return _reg(a) == _reg(b)


def _reg(domain: str) -> str:
    parts = domain.strip(".").lower().split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else domain
