"""Case ingest: acquire, analyse, persist.

The order is load-bearing. The raw bytes are hashed **before anything parses
them**, and that digest is the anchor the whole chain of custody hangs from.
Everything after it is derived and reproducible; only the acquisition digest is
irreplaceable.

The case row, its artifact, its findings and its first job are written in ONE
transaction. A case without its enrichment job, or a job whose case was rolled
back, are states this design makes unrepresentable -- which is the entire reason
the queue lives in the database.
"""

from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.logging import get_logger
from app.models.enums import (
    ArtifactSource,
    CaseStatus,
    EvidenceAction,
    IndicatorType,
    ParseStatus,
)
from app.services.analysis import AnalysisResult, analyse
from app.services.evidence.chain import append_event
from app.services.scoring.fusion import FusionResult

log = get_logger(__name__)

#: Bounded so a pathological collision loop cannot hang an ingest.
MAX_CASE_REF_ATTEMPTS = 5


@dataclass(slots=True)
class IngestOutcome:
    case_id: uuid.UUID
    case_ref: str
    sha256: str
    analysis: AnalysisResult
    duplicate_of: uuid.UUID | None = None
    campaign: str | None = None


def _canonical(payload: dict[str, object]) -> str:
    """Canonical JSON: sorted keys, no insignificant whitespace, UTF-8.

    Without a fixed canonicalisation rule, hash verification is not reproducible
    across languages -- which is the difference between a real chain of custody
    and a demo of one.
    """
    import json

    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _next_case_ref(db: Session, org_id: uuid.UUID) -> str:
    """Next human-facing case reference for an organisation.

    Derived from the highest existing suffix, NOT from ``count(*)``. Counting
    breaks the moment a case is deleted: with four rows remaining after
    CASE-2026-0003 was removed, the count yields 5 and collides with the
    CASE-2026-0005 that already exists.

    Gaps are fine and expected -- case numbers in any real system have them.
    Re-using a reference is not: analysts quote these aloud and in reports, and
    two cases sharing one is worse than a missing number.

    Still advisory under concurrency, which is why the caller retries on the
    unique constraint rather than trusting this to be atomic.
    """
    year = datetime.now(UTC).year
    prefix = f"CASE-{year}-"
    highest = db.execute(
        text(
            """
            SELECT max(CAST(substring(case_ref FROM char_length(:prefix) + 1) AS integer))
              FROM cases
             WHERE org_id = :org
               AND case_ref LIKE :like
               AND substring(case_ref FROM char_length(:prefix) + 1) ~ '^[0-9]+$'
            """
        ),
        {"org": str(org_id), "prefix": prefix, "like": f"{prefix}%"},
    ).scalar_one()
    return f"{prefix}{int(highest or 0) + 1:04d}"


def _insert_case(
    db: Session, org_id: uuid.UUID, user_id: uuid.UUID, fusion: FusionResult
) -> tuple[uuid.UUID, str]:
    """Insert the case, retrying if its reference was taken concurrently.

    ``_next_case_ref`` reads the current maximum and adds one, which two
    simultaneous ingests can do at the same instant. Rather than serialise every
    ingest behind a lock for a cosmetic identifier, the collision is caught and
    retried: it is rare, cheap to recover from, and the unique constraint is what
    actually guarantees correctness.

    A SAVEPOINT is used because a failed statement poisons the surrounding
    transaction in Postgres -- without it the retry fails too, and so does every
    write after it.
    """
    for attempt in range(MAX_CASE_REF_ATTEMPTS):
        case_ref = _next_case_ref(db, org_id)
        try:
            with db.begin_nested():
                case_id = db.execute(
                    text(
                        """
                        INSERT INTO cases (org_id, case_ref, status, score, band,
                            classification, data_completeness, weights_version, created_by)
                        VALUES (:org, :ref, :status, :score, :band, :classification,
                                :completeness, :weights, :user)
                        RETURNING id
                        """
                    ),
                    {
                        "org": str(org_id),
                        "ref": case_ref,
                        "status": CaseStatus.COMPLETE.value,
                        "score": fusion.score,
                        "band": fusion.band.value,
                        "classification": fusion.classification.value,
                        "completeness": fusion.data_completeness,
                        "weights": fusion.weights_version,
                        "user": str(user_id),
                    },
                ).scalar_one()
            return case_id, case_ref
        except IntegrityError:
            log.info("ingest.case_ref_collision", case_ref=case_ref, attempt=attempt + 1)

    raise RuntimeError(
        f"could not allocate a case reference after {MAX_CASE_REF_ATTEMPTS} attempts"
    )


def ingest_email(
    db: Session,
    raw: bytes,
    *,
    org_id: uuid.UUID,
    user_id: uuid.UUID,
    filename: str | None = None,
    source: ArtifactSource = ArtifactSource.UPLOAD,
) -> IngestOutcome:
    """Analyse and persist one message. Caller owns the transaction."""
    acquired_at = datetime.now(UTC)
    digest = hashlib.sha256(raw).hexdigest()

    # The same bytes submitted twice within an org are the same evidence.
    existing = db.execute(
        text("SELECT case_id FROM email_artifacts WHERE org_id = :org AND sha256 = :sha LIMIT 1"),
        {"org": str(org_id), "sha": digest},
    ).first()

    analysis = analyse(raw)

    if existing is not None:
        log.info("ingest.duplicate", sha256=digest, case_id=str(existing[0]))
        return IngestOutcome(
            case_id=existing[0],
            case_ref="",
            sha256=digest,
            analysis=analysis,
            duplicate_of=existing[0],
        )

    fusion = analysis.fusion
    case_id, case_ref = _insert_case(db, org_id, user_id, fusion)

    # Storage is deferred to Phase 11 (object storage). The digest -- the part
    # that matters for integrity -- is recorded now, and the storage key is
    # marked as pending rather than fabricated.
    db.execute(
        text(
            """
            INSERT INTO email_artifacts (org_id, case_id, storage_key, sha256, size_bytes,
                                         filename, source, acquired_at, acquired_by,
                                         parse_status)
            VALUES (:org, :case, :key, :sha, :size, :name, :src, :at, :by, :status)
            """
        ),
        {
            "org": str(org_id),
            "case": str(case_id),
            "key": f"pending://{digest}",
            "sha": digest,
            "size": len(raw),
            "name": filename,
            "src": source.value,
            "at": acquired_at,
            "by": str(user_id),
            "status": (
                ParseStatus.MALFORMED.value if analysis.parsed.defects else ParseStatus.PARSED.value
            ),
        },
    )

    for ordinal, (name, value) in enumerate(analysis.parsed.headers):
        seen_before = any(n.lower() == name.lower() for n, _ in analysis.parsed.headers[:ordinal])
        db.execute(
            text(
                """
                INSERT INTO email_headers (org_id, case_id, name, value_raw, ordinal,
                                           is_duplicate, above_boundary)
                VALUES (:org, :case, :name, :value, :ordinal, :dup, NULL)
                """
            ),
            {
                "org": str(org_id),
                "case": str(case_id),
                "name": name[:200],
                "value": value[:8000],
                "ordinal": ordinal,
                "dup": seen_before,
            },
        )

    for hop in analysis.hops:
        db.execute(
            text(
                """
                INSERT INTO received_hops (org_id, case_id, seq, helo, rdns_claim,
                    observed_ip, by_host, protocol, tls_info, hop_ts_utc, ip_class,
                    role, trust_state, anomalies)
                VALUES (:org, :case, :seq, :helo, :rdns, CAST(:ip AS inet), :by, :proto,
                        :tls, :ts, :ipclass, :role, :trust, CAST(:anom AS jsonb))
                """
            ),
            {
                "org": str(org_id),
                "case": str(case_id),
                "seq": hop.seq,
                "helo": hop.helo,
                "rdns": hop.rdns_claim,
                "ip": hop.observed_ip,
                "by": hop.by_host,
                "proto": hop.protocol,
                "tls": hop.tls_info,
                "ts": hop.timestamp,
                "ipclass": hop.ip_class.value,
                "role": analysis.origin.hop_roles[hop.seq].value,
                "trust": analysis.origin.hop_trust[hop.seq].value,
                "anom": _canonical({"a": analysis.origin.hop_anomalies.get(hop.seq, [])})
                .replace('{"a":', "")
                .rstrip("}"),
            },
        )

    for finding in analysis.auth.findings:
        db.execute(
            text(
                """
                INSERT INTO auth_results (org_id, case_id, mechanism, result_reported,
                    authserv_id, trusted_source, aligned, selector, d_domain, caveat)
                VALUES (:org, :case, :mech, :res, :authserv, :trusted, :aligned,
                        :sel, :d, :caveat)
                """
            ),
            {
                "org": str(org_id),
                "case": str(case_id),
                "mech": finding.mechanism.value,
                "res": finding.result_reported.value,
                "authserv": finding.authserv_id,
                "trusted": finding.trusted_source,
                "aligned": finding.aligned,
                "sel": finding.selector,
                "d": finding.d_domain,
                "caveat": finding.caveat,
            },
        )

    origin = analysis.origin
    db.execute(
        text(
            """
            INSERT INTO origin_assessment (org_id, case_id, feos_ip, boundary_hop_seq,
                confidence, confidence_breakdown, geo_dataset, evaluated_for_date,
                claim_text)
            VALUES (:org, :case, CAST(:ip AS inet), :boundary, :conf,
                    CAST(:breakdown AS jsonb), :dataset, :for_date, :claim)
            """
        ),
        {
            "org": str(org_id),
            "case": str(case_id),
            "ip": origin.feos_ip,
            "boundary": origin.boundary_seq,
            "conf": origin.confidence,
            "breakdown": _canonical(dict(origin.breakdown)),
            # Honest provenance: no geolocation dataset is installed yet, so the
            # UI reports the field as unavailable rather than inventing a country.
            "dataset": None,
            "for_date": analysis.parsed.date.date() if analysis.parsed.date else None,
            "claim": origin.claim_text,
        },
    )

    for scored in analysis.fusion.scored:
        raw_finding = scored.raw
        db.execute(
            text(
                """
                INSERT INTO findings (org_id, case_id, signal_group, rule_id, severity,
                    title, detail, plain_summary, score_contribution, evidence_ref,
                    evidence_quote, mitre_technique)
                VALUES (:org, :case, :grp, :rule, :sev, :title, :detail, :plain,
                        :contrib, :ref, :quote, :mitre)
                """
            ),
            {
                "org": str(org_id),
                "case": str(case_id),
                "grp": raw_finding.group.value,
                "rule": raw_finding.rule_id,
                "sev": raw_finding.severity.value,
                "title": raw_finding.title[:300],
                "detail": raw_finding.detail,
                "plain": raw_finding.plain,
                "contrib": scored.contribution,
                "ref": (raw_finding.evidence_ref or "")[:300] or None,
                "quote": raw_finding.evidence_quote,
                "mitre": raw_finding.mitre_technique,
            },
        )

    _record_indicators(db, org_id, case_id, analysis)

    # The chain records every stage, in order, each committing to the one before
    # it. A single acquisition event would prove only that the file arrived --
    # not that this analysis produced this verdict.
    _record_acquisition_event(db, org_id, case_id, user_id, digest, acquired_at, analysis)

    append_event(
        db,
        org_id=org_id,
        case_id=case_id,
        actor="service:parser",
        action=EvidenceAction.PARSED,
        payload={
            "headers": len(analysis.parsed.headers),
            "received_hops": len(analysis.hops),
            "urls": len(analysis.parsed.urls),
            "attachments": [a.sha256 for a in analysis.parsed.attachments],
        },
        metadata={"defects": analysis.parsed.defects},
    )
    append_event(
        db,
        org_id=org_id,
        case_id=case_id,
        actor="service:auth",
        action=EvidenceAction.AUTH_EVALUATED,
        payload={
            "trusted_authserv": analysis.auth.trusted_authserv,
            "results": [
                {
                    "mechanism": f.mechanism.value,
                    "result": f.result_reported.value,
                    "aligned": f.aligned,
                }
                for f in analysis.auth.findings
            ],
            "discarded_headers": analysis.auth.discarded,
            "forged_pass_detected": analysis.auth.forged_pass_detected,
        },
    )
    append_event(
        db,
        org_id=org_id,
        case_id=case_id,
        actor="service:origin",
        action=EvidenceAction.ORIGIN_RECONSTRUCTED,
        payload={
            "feos_ip": analysis.origin.feos_ip,
            "boundary_hop_seq": analysis.origin.boundary_seq,
            "confidence": analysis.origin.confidence,
            "flags": analysis.origin.flags,
        },
        metadata={"breakdown": dict(analysis.origin.breakdown)},
    )
    append_event(
        db,
        org_id=org_id,
        case_id=case_id,
        actor="service:scoring",
        action=EvidenceAction.SCORED,
        payload={
            "score": fusion.score,
            "band": fusion.band.value,
            "classification": fusion.classification.value,
            "group_scores": fusion.group_scores,
            "finding_rule_ids": sorted(f.raw.rule_id for f in fusion.scored),
        },
        metadata={
            "weights_version": fusion.weights_version,
            "controls_applied": fusion.controls_applied,
            "data_completeness": fusion.data_completeness,
        },
    )

    # Email DNA and campaign linkage run inline. Both are pure in-process work
    # over data already in hand, with no outbound call, so deferring them to
    # Band B would add a round trip and buy nothing: the Band A/B boundary is
    # about *network dependence*, not about being asynchronous.
    # Band B: reaches the network, so it runs after the deterministic verdict is
    # already recorded and can only ever add to it.
    _enrich_band_b(db, org_id, case_id, analysis, raw)

    _run_ai_layer(db, org_id, case_id, analysis)
    campaign = _link_campaign(db, org_id, case_id, analysis)

    log.info(
        "ingest.complete",
        case_ref=case_ref,
        score=fusion.score,
        band=fusion.band.value,
        sha256=digest,
        campaign=campaign,
    )
    return IngestOutcome(
        case_id=case_id,
        case_ref=case_ref,
        sha256=digest,
        analysis=analysis,
        campaign=campaign,
    )


def _enrich_band_b(
    db: Session,
    org_id: uuid.UUID,
    case_id: uuid.UUID,
    analysis: AnalysisResult,
    raw: bytes,
) -> None:
    """Network-dependent enrichment: DKIM re-verification, DMARC policy, network
    attribution for the observed hops.

    Every step is individually guarded. A DNS timeout enriches less; it never
    invalidates the Band A verdict already written.
    """
    from app.services.forensics.verify import aligned, fetch_dmarc, verify_dkim
    from app.services.intel.geo import lookup as geo_lookup

    # --- DKIM re-verification ------------------------------------------------
    try:
        dkim_result = verify_dkim(raw)
        if dkim_result.result.value != "none":
            db.execute(
                text(
                    """
                    INSERT INTO auth_results (org_id, case_id, mechanism,
                        result_recomputed, selector, d_domain, h_tags,
                        trusted_source, aligned, caveat)
                    VALUES (:o, :c, 'dkim', :res, :sel, :d, :h, false, :al, :cav)
                    """
                ),
                {
                    "o": str(org_id),
                    "c": str(case_id),
                    "res": dkim_result.result.value,
                    "sel": dkim_result.selector,
                    "d": dkim_result.d_domain,
                    "h": ":".join(dkim_result.signed_headers) or None,
                    "al": aligned(dkim_result.d_domain, analysis.from_domain),
                    "cav": dkim_result.caveat,
                },
            )
    except Exception as exc:
        log.warning("enrich.dkim_failed", error=str(exc)[:160])

    # --- DMARC policy of the domain being IMPERSONATED -----------------------
    # The more interesting lookup. "The domain being imitated publishes
    # p=reject, and this message did not come from it" is a far stronger
    # statement than any pass or fail on the sender's own domain.
    try:
        impersonated = next(
            (
                f.evidence_ref.split("~")[-1].strip()
                for f in analysis.findings
                if f.rule_id == "IDENT_LOOKALIKE_DOMAIN" and f.evidence_ref
            ),
            None,
        )
        for domain, label in ((analysis.from_domain, "sender"), (impersonated, "impersonated")):
            if not domain:
                continue
            policy = fetch_dmarc(domain)
            if not policy.resolved:
                continue
            db.execute(
                text(
                    """
                    INSERT INTO auth_results (org_id, case_id, mechanism,
                        result_recomputed, d_domain, policy, trusted_source, caveat)
                    VALUES (:o, :c, 'dmarc', :res, :d, :p, false, :cav)
                    """
                ),
                {
                    "o": str(org_id),
                    "c": str(case_id),
                    "res": "pass" if policy.found else "none",
                    "d": policy.domain,
                    "p": policy.policy,
                    "cav": (
                        f"Policy of the {label} domain, fetched at analysis time. "
                        + (
                            f"{policy.domain} publishes p={policy.policy}; a message "
                            f"purporting to be from it should have originated there."
                            if policy.found and label == "impersonated"
                            else "No DMARC record published."
                            if not policy.found
                            else "Current policy; may differ from the policy at delivery time."
                        )
                    ),
                },
            )
    except Exception as exc:
        log.warning("enrich.dmarc_failed", error=str(exc)[:160])

    # --- network attribution for every observed public hop -------------------
    try:
        enriched = 0
        for hop in analysis.hops:
            if not hop.observed_ip or hop.ip_class.value != "public":
                continue
            info = geo_lookup(hop.observed_ip)
            if not info.available:
                continue
            db.execute(
                text(
                    "UPDATE received_hops SET asn = :asn, asn_org = :org, "
                    "country = :cc, net_type = :nt WHERE case_id = :c AND seq = :s"
                ),
                {
                    "asn": info.asn,
                    "org": info.org,
                    "cc": info.country,
                    "nt": info.network_type,
                    "c": str(case_id),
                    "s": hop.seq,
                },
            )
            enriched += 1

        feos = geo_lookup(analysis.origin.feos_ip) if analysis.origin.feos_ip else None
        if feos and feos.available:
            db.execute(
                text(
                    "UPDATE origin_assessment SET feos_asn = :asn, feos_org = :org, "
                    "feos_country = :cc, net_type = :nt, geo_dataset = :ds "
                    "WHERE case_id = :c"
                ),
                {
                    "asn": feos.asn,
                    "org": feos.org,
                    "cc": feos.country,
                    "nt": feos.network_type,
                    "ds": feos.source,
                    "c": str(case_id),
                },
            )

        append_event(
            db,
            org_id=org_id,
            case_id=case_id,
            actor="service:enrichment",
            action=EvidenceAction.ENRICHED,
            payload={"hops_enriched": enriched, "feos_source": feos.source if feos else None},
            metadata={
                "note": "Network attribution identifies the network an address "
                "belongs to, at country granularity. It never identifies a "
                "person or a physical location.",
                "dataset": feos.source if feos else "unavailable",
            },
        )
    except Exception as exc:
        log.warning("enrich.geo_failed", error=str(exc)[:160])


def _run_ai_layer(
    db: Session, org_id: uuid.UUID, case_id: uuid.UUID, analysis: AnalysisResult
) -> None:
    """Run the intent extraction and record it.

    Band B by nature -- it depends on a provider -- but invoked inline so a
    single-case demo shows the whole picture. Availability is recorded either
    way: an unavailable model lowers data completeness rather than silently
    scoring zero, and never blocks the case.
    """
    from app.services.ai.client import analyse_intent, persist

    indicators = {
        row[0]
        for row in db.execute(
            text("SELECT normalised FROM indicators WHERE case_id = :c"),
            {"c": str(case_id)},
        ).all()
    }

    result = analyse_intent(
        db,
        subject=analysis.parsed.subject,
        body=analysis.parsed.text_body,
        established_facts={
            "from_display": analysis.from_display,
            "reply_to_divergent": bool(
                analysis.reply_to_address
                and analysis.from_address
                and analysis.reply_to_address != analysis.from_address
            ),
            "dmarc_aligned_to_claimed_identity": any(
                f.mechanism.value == "dmarc" and f.aligned for f in analysis.auth.findings
            ),
            "impersonation_rules_fired": sorted(
                f.rule_id for f in analysis.findings if f.rule_id.startswith("IDENT_")
            ),
        },
        known_indicators=indicators,
    )

    if not result.available:
        log.info("ai.unavailable", case_id=str(case_id), reason=result.unavailable_reason)
        return

    persist(db, org_id=org_id, case_id=case_id, result=result)
    append_event(
        db,
        org_id=org_id,
        case_id=case_id,
        actor="service:ai",
        action=EvidenceAction.AI_ANALYSED,
        payload={
            "attack_type": result.extraction.attack_type.value if result.extraction else None,
            "signals": [
                s.type.value for s in (result.extraction.signals if result.extraction else [])
            ],
            "input_sha256": result.input_sha256,
            "output_sha256": result.output_sha256,
        },
        metadata={
            "model_id": result.model_id,
            "prompt_version": result.prompt_version,
            "quotes_validated": result.guard.quotes_validated,
            "quotes_dropped": result.guard.quotes_dropped,
            "cached": result.cached,
            "note": "Model output is capped at 12 of 100 points and cannot alone "
            "raise a case above the High band.",
        },
    )


def _link_campaign(
    db: Session, org_id: uuid.UUID, case_id: uuid.UUID, analysis: AnalysisResult
) -> str | None:
    """Fingerprint the message and link it to a campaign if the evidence allows.

    Imported locally to keep the module import graph shallow: the campaign layer
    imports the analysis layer, and a top-level import here would make that a
    cycle.
    """
    from app.services.campaign.dna import compute_dna
    from app.services.campaign.linking import assign_campaign, find_links, store_dna

    dna = compute_dna(analysis)
    store_dna(db, org_id=org_id, case_id=case_id, dna=dna)
    db.flush()  # the fingerprint must be visible to the linkage query below

    links = find_links(db, org_id=org_id, case_id=case_id, dna=dna)
    if not links:
        return None

    assigned = assign_campaign(db, org_id=org_id, case_id=case_id, links=links)
    if assigned is None:
        return None

    _, name = assigned
    append_event(
        db,
        org_id=org_id,
        case_id=case_id,
        actor="service:campaign",
        action=EvidenceAction.CAMPAIGN_LINKED,
        payload={
            "campaign": name,
            "links": [
                {"case_ref": link.case_ref, "score": link.score, "loci": link.per_locus}
                for link in links[:5]
            ],
        },
        metadata={
            "note": (
                "Operational linkage hypothesis, not attribution. Shared tooling can "
                "indicate one actor, one purchased phishing kit, or one "
                "phishing-as-a-service platform used by many unrelated actors."
            ),
            "dna_version": dna.version,
        },
    )
    return name


def _record_indicators(
    db: Session, org_id: uuid.UUID, case_id: uuid.UUID, analysis: AnalysisResult
) -> None:
    seen: set[tuple[str, str]] = set()

    def add(kind: IndicatorType, value: str | None) -> None:
        if not value:
            return
        normalised = value.strip().lower()
        if (kind.value, normalised) in seen:
            return
        seen.add((kind.value, normalised))
        db.execute(
            text(
                """
                INSERT INTO indicators (org_id, case_id, type, value, normalised)
                VALUES (:org, :case, :type, :value, :norm)
                ON CONFLICT DO NOTHING
                """
            ),
            {
                "org": str(org_id),
                "case": str(case_id),
                "type": kind.value,
                "value": value[:2000],
                "norm": normalised[:2000],
            },
        )

    add(IndicatorType.EMAIL, analysis.from_address)
    add(IndicatorType.EMAIL, analysis.reply_to_address)
    add(IndicatorType.DOMAIN, analysis.from_domain)
    add(IndicatorType.MESSAGE_ID, analysis.message_id)
    for hop in analysis.hops:
        add(IndicatorType.IP, hop.observed_ip)
    for url in analysis.parsed.urls[:100]:
        add(IndicatorType.URL, url)
    for attachment in analysis.parsed.attachments:
        add(IndicatorType.FILE_HASH, attachment.sha256)


def _record_acquisition_event(
    db: Session,
    org_id: uuid.UUID,
    case_id: uuid.UUID,
    user_id: uuid.UUID,
    digest: str,
    acquired_at: datetime,
    analysis: AnalysisResult,
) -> None:
    """Seq 0 of the chain: what arrived, when, and from whom.

    Delegates to the chain service so the hash formula has exactly one
    implementation -- a second copy here would eventually drift and make every
    case written by one path unverifiable by the other.
    """
    append_event(
        db,
        org_id=org_id,
        case_id=case_id,
        actor=str(user_id),
        action=EvidenceAction.ACQUIRED,
        ts_utc=acquired_at,
        payload={
            "sha256": digest,
            "size_bytes": analysis.parsed.size_bytes,
            "filename": None,
        },
        metadata={
            "weights_version": analysis.fusion.weights_version,
            "parser_defects": analysis.parsed.defects,
            "note": "digest computed over the raw bytes before any parsing",
        },
    )


def record_stage_event(
    db: Session,
    *,
    org_id: uuid.UUID,
    case_id: uuid.UUID,
    actor: str,
    action: EvidenceAction,
    payload: dict[str, object],
    metadata: dict[str, object] | None = None,
) -> str:
    """Append a pipeline-stage event. Thin wrapper so callers outside this module
    need not import the chain service directly."""
    return append_event(
        db,
        org_id=org_id,
        case_id=case_id,
        actor=actor,
        action=action,
        payload=payload,
        metadata=metadata,
    )
