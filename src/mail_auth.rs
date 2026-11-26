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
