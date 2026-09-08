# Claim contract

This file is normative. Any output — UI string, PDF sentence, API field — that
contradicts it is a bug, not a wording preference.

## What the system may state

- *"The first MTA we trust recorded a TCP connection from `<ip>`."*
  An observation by infrastructure with a reputation to lose. SMTP requires a
  completed TCP handshake, so the source address is not casually spoofable.
- *"`<ip>` is announced by AS`<n>`, registered to `<org>`, and geolocates to
  country `<cc>` at country-level precision per `<dataset> <version>`."*
- *"This is the earliest externally observed sending infrastructure before the
  message entered `<trusted provider>`."*
- *"Network type indicates hosting/VPS infrastructure rather than a consumer
  connection."*
- *"Confidence `<n>`%, computed as follows…"* — always with the arithmetic
  reachable from the UI.

## What the system must never state

- *"The attacker is in `<country>`."* A VPS is rented from anywhere; the
  operator is elsewhere.
- Any **city-level** location for a datacentre range.
- That the message **"travelled through"** the countries shown. Those are
  handling hosts, not a network route. The feature is named *infrastructure
  hops* in the UI, the API (`/hops`, never `/route`) and the code.
- That the sender **is** the attacker. The host may be compromised, an open
  relay, or a legitimate mailbox whose owner is a victim.
- Anything at all when the first externally observed sender is a shared ESP:
  the true origin sits behind that provider and is recoverable only by legal
  process to them.
- An identity, organisation or person as "the attacker". The system produces
  leads, not defendants.

## Campaign linkage

A DNA match is an **operational linkage hypothesis, not attribution.** The same
fingerprint can arise from one actor, one purchased phishing kit, or one
phishing-as-a-service platform used by many unrelated actors. This sentence
appears in the UI, not only in this file.

## Evidence integrity

A hash chain proves *our log is internally consistent*. It does not prove we did
not rewrite the whole log. That gap is why the Merkle root is anchored
externally, and the distinction is stated in the report rather than glossed.
