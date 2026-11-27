// Copyright 2026 Gian Paolo Franceschini. See LICENSE.
//! Synthetic mail authentication consistency advisory. No parsing, DNS, signature
//! validation, identity assurance, mail access or action authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source { ReviewedFixture, Untrusted, Unavailable }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mechanism { AlignedPass, UnalignedPass, NoPass, Unknown }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dmarc { Pass, Fail, Unavailable }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Authentication {
    UntrustedEvidence, InvalidAuthor, IncompleteEvidence, InconsistentEvidence,
    DomainAlignmentReported, DomainAlignmentFailed,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fixture {
    pub source: Source,
    pub valid_single_author: bool,
    // SPF is MAIL FROM only; DKIM is aggregate over all evaluated signatures.
    // Alignment is supplied by the mock receiver, not calculated by this module.
    pub spf: Mechanism,
    pub dkim: Mechanism,
    pub dmarc: Dmarc,
    pub payment_or_account_change: bool,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Advisory {
    pub authentication: Authentication,
    pub independent_confirmation_required: bool,
}
pub fn assess(f: Fixture) -> Advisory {
    use Authentication::*;
    use Mechanism::*;
    let authentication = if f.source != Source::ReviewedFixture { UntrustedEvidence }
    else if !f.valid_single_author { InvalidAuthor }
    else {
        let aligned = [f.spf, f.dkim].contains(&AlignedPass);
        let incomplete = [f.spf, f.dkim].contains(&Unknown);
        match (f.dmarc, aligned, incomplete) {
            (Dmarc::Fail, true, _) => InconsistentEvidence,
            (Dmarc::Pass, true, _) => DomainAlignmentReported,
            (Dmarc::Pass, false, false) => InconsistentEvidence,
            (Dmarc::Fail, false, false) => DomainAlignmentFailed,
            _ => IncompleteEvidence,
        }
    };
    Advisory {
        authentication,
        // Domain alignment never waives independently verified payment/account changes.
        independent_confirmation_required: f.payment_or_account_change,
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use Authentication::*;
    use Mechanism::*;
    fn good() -> Fixture {
        Fixture { source: Source::ReviewedFixture, valid_single_author: true,
            spf: AlignedPass, dkim: NoPass, dmarc: Dmarc::Pass,
            payment_or_account_change: false }
    }
    #[test] fn either_aligned_mechanism_suffices() {
        assert_eq!(assess(good()).authentication, DomainAlignmentReported);
        assert_eq!(assess(Fixture { spf: NoPass, dkim: AlignedPass, ..good() }).authentication,
            DomainAlignmentReported);
        assert_eq!(assess(Fixture { dkim: Unknown, ..good() }).authentication,
            DomainAlignmentReported);
    }
    #[test] fn unaligned_pass_is_not_dmarc_pass() {
        let f = Fixture { spf: UnalignedPass, dkim: UnalignedPass, ..good() };
        assert_eq!(assess(f).authentication, InconsistentEvidence);
        assert_eq!(assess(Fixture { dmarc: Dmarc::Fail, ..f }).authentication, DomainAlignmentFailed);
    }
    #[test] fn missing_evidence_is_not_a_failure_or_pass() {
        for dmarc in [Dmarc::Pass, Dmarc::Fail, Dmarc::Unavailable] {
            assert_eq!(assess(Fixture { spf: Unknown, dkim: NoPass, dmarc, ..good() }).authentication,
                IncompleteEvidence);
        }
        assert_eq!(assess(Fixture { dmarc: Dmarc::Unavailable, ..good() }).authentication,
            IncompleteEvidence);
    }
    #[test] fn contradictory_failure() {
        assert_eq!(assess(Fixture { dmarc: Dmarc::Fail, ..good() }).authentication,
            InconsistentEvidence);
    }
    #[test] fn trust_and_author_boundary() {
        for source in [Source::Untrusted, Source::Unavailable] {
            assert_eq!(assess(Fixture { source, ..good() }).authentication, UntrustedEvidence);
        }
        assert_eq!(assess(Fixture { valid_single_author: false, ..good() }).authentication,
            InvalidAuthor);
    }
    #[test] fn payment_confirmation_independent_of_every_authentication_state() {
        for source in [Source::ReviewedFixture, Source::Untrusted, Source::Unavailable] {
            for valid_single_author in [true, false] {
                for spf in [AlignedPass, UnalignedPass, NoPass, Unknown] {
                    for dkim in [AlignedPass, UnalignedPass, NoPass, Unknown] {
                        for dmarc in [Dmarc::Pass, Dmarc::Fail, Dmarc::Unavailable] {
                            let f = Fixture { source, valid_single_author, spf, dkim, dmarc,
                                payment_or_account_change: true };
                            assert!(assess(f).independent_confirmation_required);
                            let ordinary = assess(Fixture { payment_or_account_change: false, ..f });
                            assert!(!ordinary.independent_confirmation_required);
                            assert_eq!(ordinary.authentication, assess(f).authentication);
                        }
                    }
                }
            }
        }
    }
}

/** Synthetic transaction metadata. All identifiers are fictional opaque numbers,
 * never account numbers, contact details, credentials or real payment data. */
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Currency { Eur, Usd }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CriticalTerms {
    Payment { amount_minor: u64, currency: Currency },
    DestinationChange,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CriticalRequest {
    pub request_id: u64,
    pub revision: u32,
    pub requester: u64,
    pub beneficiary: u64,
    pub destination: u64,
    pub issued_at: u64,
    pub terms: CriticalTerms,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConfirmationChannel { PreviouslyRegistered, FromRequest, Unknown }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConfirmationFixture {
    pub source: Source,
    pub channel: ConfirmationChannel,
    pub reviewer: u64,
    pub confirmed_at: u64,
    pub bound_request: CriticalRequest,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConfirmationVerdict {
    InvalidRequest, Missing, Untrusted, NonIndependentChannel,
    NonIndependentReviewer, DifferentTransaction, StaleOrInvalidTime,
    FixtureConfirmationReported,
}
pub const CONFIRMATION_MAX_AGE: u64 = 300;
/// Advisory only, never authorizes payments or account changes. The caller's
/// synthetic labels are NOT authenticated; no replay ledger or identity proof.
/// A positive result is not payment approval or proof of a safe recipient.
pub fn assess_confirmation(request: CriticalRequest, now: u64,
    confirmation: Option<ConfirmationFixture>) -> ConfirmationVerdict {
    use ConfirmationVerdict::*;
    if request.request_id == 0 || request.revision == 0 || request.requester == 0 ||
        request.beneficiary == 0 || request.destination == 0 ||
        request.issued_at > now ||
        matches!(request.terms, CriticalTerms::Payment { amount_minor: 0, .. }) {
        return InvalidRequest;
    }
    let Some(c) = confirmation else { return Missing; };
    if c.source != Source::ReviewedFixture { return Untrusted; }
    if c.channel != ConfirmationChannel::PreviouslyRegistered { return NonIndependentChannel; }
    if c.reviewer == 0 || c.reviewer == request.requester { return NonIndependentReviewer; }
    if c.bound_request != request { return DifferentTransaction; }
    if c.confirmed_at < request.issued_at ||
        !now.checked_sub(c.confirmed_at).is_some_and(|age| age < CONFIRMATION_MAX_AGE) {
        return StaleOrInvalidTime;
    }
    FixtureConfirmationReported
}
pub fn confirmation_example() -> (CriticalRequest, ConfirmationFixture) {
    let request = CriticalRequest { request_id: 1, revision: 1, requester: 2,
        beneficiary: 3, destination: 4, issued_at: 100,
        terms: CriticalTerms::Payment { amount_minor: 500, currency: Currency::Eur } };
    let confirmation = ConfirmationFixture { source: Source::ReviewedFixture,
        channel: ConfirmationChannel::PreviouslyRegistered, reviewer: 5,
        confirmed_at: 110, bound_request: request };
    (request, confirmation)
}
#[cfg(test)]
mod confirmation_tests {
    use super::*;
    use ConfirmationVerdict::*;
    #[test] fn valid_fixture_and_missing_confirmation() {
        let (r,c) = confirmation_example();
        assert_eq!(assess_confirmation(r, 120, Some(c)), FixtureConfirmationReported);
        assert_eq!(assess_confirmation(r, 120, None), Missing);
        let r = CriticalRequest { terms: CriticalTerms::DestinationChange, ..r };
        assert_eq!(assess_confirmation(r, 120, Some(ConfirmationFixture { bound_request: r, ..c })),
            FixtureConfirmationReported);
    }
    #[test] fn every_bound_field_matters() {
        let (r,c) = confirmation_example();
        for changed in [
            CriticalRequest { request_id: 9, ..r },
            CriticalRequest { revision: 2, ..r },
            CriticalRequest { requester: 8, ..r },
            CriticalRequest { beneficiary: 8, ..r },
            CriticalRequest { destination: 8, ..r },
            CriticalRequest { issued_at: 101, ..r },
            CriticalRequest { terms: CriticalTerms::Payment { amount_minor: 501, currency: Currency::Eur }, ..r },
            CriticalRequest { terms: CriticalTerms::Payment { amount_minor: 500, currency: Currency::Usd }, ..r },
            CriticalRequest { terms: CriticalTerms::DestinationChange, ..r },
        ] {
            assert_eq!(assess_confirmation(changed, 120, Some(c)), DifferentTransaction);
        }
    }
    #[test] fn untrusted_or_request_supplied_channel_rejected() {
        let (r,c) = confirmation_example();
        for source in [Source::Untrusted, Source::Unavailable] {
            assert_eq!(assess_confirmation(r, 120, Some(ConfirmationFixture { source, ..c })), Untrusted);
        }
        for channel in [ConfirmationChannel::FromRequest, ConfirmationChannel::Unknown] {
            assert_eq!(assess_confirmation(r, 120, Some(ConfirmationFixture { channel, ..c })),
                NonIndependentChannel);
        }
    }
    #[test] fn independent_reviewer_required() {
        let (r,c) = confirmation_example();
        for reviewer in [0, r.requester] {
            assert_eq!(assess_confirmation(r, 120, Some(ConfirmationFixture { reviewer, ..c })),
                NonIndependentReviewer);
        }
    }
    #[test] fn time_boundaries() {
        let (r,c) = confirmation_example();
        for confirmed_at in [99, 121, u64::MAX] {
            assert_eq!(assess_confirmation(r, 120, Some(ConfirmationFixture { confirmed_at, ..c })),
                StaleOrInvalidTime);
        }
        assert_eq!(assess_confirmation(r, 409, Some(c)), FixtureConfirmationReported);
        assert_eq!(assess_confirmation(r, 410, Some(c)), StaleOrInvalidTime);
        assert_eq!(assess_confirmation(r, 109, Some(c)), StaleOrInvalidTime);
    }
    #[test] fn invalid_request_fields() {
        let (r,c) = confirmation_example();
        for invalid in [
            CriticalRequest { request_id: 0, ..r },
            CriticalRequest { revision: 0, ..r },
            CriticalRequest { requester: 0, ..r },
            CriticalRequest { beneficiary: 0, ..r },
            CriticalRequest { destination: 0, ..r },
            CriticalRequest { issued_at: 121, ..r },
            CriticalRequest { terms: CriticalTerms::Payment { amount_minor: 0, currency: Currency::Eur }, ..r },
        ] {
            assert_eq!(assess_confirmation(invalid, 120, Some(c)), InvalidRequest);
        }
    }
}

 
/// Bound a synthetic review batch before inspecting entries. This is not a
/// durable replay ledger, authenticated queue, or payment authorization.
pub const MAX_CONFIRMATION_BATCH: usize = 64;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReviewEntry {
    pub request: CriticalRequest,
    pub confirmation: Option<ConfirmationFixture>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BatchVerdict {
    InvalidBatchSize, DuplicateRequest, NeedsReview, FixtureConfirmationsReported,
}
/// Reject duplicate logical request IDs even across revisions. Do not count a
/// partially valid batch as a success. No state, side effects or real identities.
pub fn assess_confirmation_batch(entries: &[ReviewEntry], now: u64) -> BatchVerdict {
    use BatchVerdict::*;
    if entries.is_empty() || entries.len() > MAX_CONFIRMATION_BATCH {
        return InvalidBatchSize;
    }
    for (i, entry) in entries.iter().enumerate() {
        if entries[..i].iter().any(|earlier| earlier.request.request_id == entry.request.request_id) {
            return DuplicateRequest;
        }
    }
    if entries.iter().any(|entry| assess_confirmation(entry.request, now, entry.confirmation)
        != ConfirmationVerdict::FixtureConfirmationReported) {
        return NeedsReview;
    }
    FixtureConfirmationsReported
}

#[cfg(test)]
mod batch_tests {
    use super::*;
    use BatchVerdict::*;
    fn entry(id: u64) -> ReviewEntry {
        let (r,c) = confirmation_example();
        let request = CriticalRequest { request_id: id, ..r };
        ReviewEntry { request, confirmation: Some(ConfirmationFixture { bound_request: request, ..c }) }
    }
    #[test] fn size_bounds_and_distinct_requests() {
        assert_eq!(assess_confirmation_batch(&[], 120), InvalidBatchSize);
        let mut entries: Vec<_> = (1..=MAX_CONFIRMATION_BATCH as u64).map(entry).collect();
        assert_eq!(assess_confirmation_batch(&entries, 120), FixtureConfirmationsReported);
        entries.push(entry(65));
        assert_eq!(assess_confirmation_batch(&entries, 120), InvalidBatchSize);
    }
    #[test] fn duplicate_ids_across_revisions_and_order() {
        let first = entry(1);
        let revised = CriticalRequest { revision: 2, ..first.request };
        let second = ReviewEntry { request: revised, confirmation: first.confirmation.map(|c|
            ConfirmationFixture { bound_request: revised, ..c }) };
        for entries in [[first, first], [first, second], [second, first]] {
            assert_eq!(assess_confirmation_batch(&entries, 120), DuplicateRequest);
        }
        assert_eq!(assess_confirmation_batch(&[first, entry(2), first], 120), DuplicateRequest);
    }
    #[test] fn one_invalid_entry_blocks_whole_batch() {
        let first = entry(1);
        let second = entry(2);
        for bad in [
            ReviewEntry { confirmation: None, ..second },
            ReviewEntry { confirmation: first.confirmation, ..second },
            ReviewEntry { request: CriticalRequest { request_id: 0, ..second.request }, ..second },
        ] {
            assert_eq!(assess_confirmation_batch(&[first, bad], 120), NeedsReview);
            assert_eq!(assess_confirmation_batch(&[bad, first], 120), NeedsReview);
        }
        assert_eq!(assess_confirmation_batch(&[first, second], 410), NeedsReview);
    }
}


/// In-memory demonstration of logical request reuse across review batches.
/// Not a durable ledger, identity proof, payment authorization or production
/// replay boundary. Never evicts IDs to silently restore acceptance.
pub const MAX_SESSION_REQUESTS: usize = 256;
#[derive(Debug, Default)]
pub struct FixtureReviewSession {
    seen: std::collections::BTreeSet<u64>,
    last_accepted_at: Option<u64>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionVerdict {
    BatchRejected(BatchVerdict), PreviouslyReviewed, ClockRegression,
    SessionCapacityReached, FixtureBatchRecorded,
}
impl FixtureReviewSession {
    pub fn record(&mut self, entries: &[ReviewEntry], now: u64) -> SessionVerdict {
        use SessionVerdict::*;
        let result = assess_confirmation_batch(entries, now);
        if result != BatchVerdict::FixtureConfirmationsReported {
            return BatchRejected(result);
        }
        if self.last_accepted_at.is_some_and(|last| now < last) {
            return ClockRegression;
        }
        if entries.iter().any(|entry| self.seen.contains(&entry.request.request_id)) {
            return PreviouslyReviewed;
        }
        if entries.len() > MAX_SESSION_REQUESTS - self.seen.len() {
            return SessionCapacityReached;
        }
        // Commit only after every check passes; failed batches change nothing.
        self.seen.extend(entries.iter().map(|entry| entry.request.request_id));
        self.last_accepted_at = Some(now);
        FixtureBatchRecorded
    }
    pub fn recorded_count(&self) -> usize { self.seen.len() }
}

#[cfg(test)]
mod session_tests {
    use super::*;
    use SessionVerdict::*;
    fn entry(id: u64) -> ReviewEntry {
        let (r,c) = confirmation_example();
        let request = CriticalRequest { request_id: id, ..r };
        ReviewEntry { request, confirmation: Some(ConfirmationFixture { bound_request: request, ..c }) }
    }
    #[test] fn reuse_across_batches_including_revisions() {
        let mut s = FixtureReviewSession::default();
        let first = entry(1);
        assert_eq!(s.record(&[first], 120), FixtureBatchRecorded);
        let request = CriticalRequest { revision: 2, ..first.request };
        let revised = ReviewEntry { request, confirmation: first.confirmation.map(|c|
            ConfirmationFixture { bound_request: request, ..c }) };
        assert_eq!(s.record(&[entry(2), revised], 121), PreviouslyReviewed);
        assert_eq!(s.recorded_count(), 1);
        assert_eq!(s.record(&[entry(2)], 121), FixtureBatchRecorded);
        assert_eq!(s.recorded_count(), 2);
    }
    #[test] fn failures_do_not_reserve_ids_or_advance_clock() {
        let mut s = FixtureReviewSession::default();
        assert_eq!(s.record(&[entry(1)], 120), FixtureBatchRecorded);
        let bad = ReviewEntry { confirmation: None, ..entry(3) };
        assert_eq!(s.record(&[entry(2), bad], 200), BatchRejected(BatchVerdict::NeedsReview));
        assert_eq!(s.record(&[entry(2)], 119), ClockRegression);
        assert_eq!(s.record(&[entry(2), entry(2)], 121), BatchRejected(BatchVerdict::DuplicateRequest));
        assert_eq!(s.recorded_count(), 1);
        assert_eq!(s.record(&[entry(2), entry(3)], 121), FixtureBatchRecorded);
        assert_eq!(s.recorded_count(), 3);
    }
    #[test] fn capacity_is_atomic_and_never_evicts() {
        let mut s = FixtureReviewSession::default();
        for start in [1, 65, 129] {
            let batch: Vec<_> = (start..start+64).map(entry).collect();
            assert_eq!(s.record(&batch, 120), FixtureBatchRecorded);
        }
        let last: Vec<_> = (193..256).map(entry).collect();
        assert_eq!(s.record(&last, 120), FixtureBatchRecorded);
        assert_eq!(s.recorded_count(), 255);
        assert_eq!(s.record(&[entry(256), entry(257)], 120), SessionCapacityReached);
        assert_eq!(s.recorded_count(), 255);
        assert_eq!(s.record(&[entry(256)], 120), FixtureBatchRecorded);
        assert_eq!(s.record(&[entry(257)], 120), SessionCapacityReached);
        assert_eq!(s.record(&[entry(1)], 120), PreviouslyReviewed);
        assert_eq!(s.recorded_count(), MAX_SESSION_REQUESTS);
    }
}
