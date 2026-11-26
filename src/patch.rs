// Copyright 2026 Gian Paolo Franceschini. See LICENSE.
//! Synthetic patch-priority rehearsal only. No authentic catalog, inventory,
//! signature verification, CVE matching, patch installation or system changes.
use std::collections::BTreeSet;

pub const MAX_ROWS: usize = 256;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ProductBuild { pub product: u32, pub build: u32 }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Evidence { ReviewedFixture, Stale, Unavailable }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Applicability { Affected, NotAffected, Remediated, Unknown }

#[derive(Clone, Copy, Debug)]
pub struct Finding {
    pub product: ProductBuild,
    pub vulnerability: u32, // synthetic identifier, never a real CVE
    pub applicability: Applicability,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Advisory {
    ApplicabilityUnknown,
    PriorityReview,
    ReviewNotListedInFixture,
    ReviewCatalogUnavailable,
    NotAffectedByFixture,
    RemediatedByFixture,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error { InvalidInput, Duplicate, LimitExceeded }

fn valid_product(p: ProductBuild) -> bool { p.product != 0 && p.build != 0 }

/// Exact product/build matching, no inference from missing patches or records.
/// Fixture evidence flags do not authenticate data. Unknown/stale evidence
/// never produces a negative or remediated determination. An absent catalog
/// entry is not proof of safety. Outputs are recommendations, not actions.
pub fn triage(
    installed: ProductBuild, inventory: Evidence, mapping: Evidence,
    catalog: Evidence, listed: &[u32], findings: &[Finding],
) -> Result<Vec<Advisory>, Error> {
    if listed.len() > MAX_ROWS || findings.len() > MAX_ROWS {
        return Err(Error::LimitExceeded);
    }
    if !valid_product(installed) { return Err(Error::InvalidInput); }
    let mut catalog_ids = BTreeSet::new();
    for &id in listed {
        if id == 0 { return Err(Error::InvalidInput); }
        if !catalog_ids.insert(id) { return Err(Error::Duplicate); }
    }
    let mut keys = BTreeSet::new();
    for f in findings {
        if f.vulnerability == 0 || !valid_product(f.product) {
            return Err(Error::InvalidInput);
        }
        if !keys.insert((f.product, f.vulnerability)) {
            return Err(Error::Duplicate);
        }
    }
    Ok(findings.iter().map(|f| {
        if inventory != Evidence::ReviewedFixture ||
            mapping != Evidence::ReviewedFixture || f.product != installed {
            return Advisory::ApplicabilityUnknown;
        }
        match f.applicability {
            Applicability::Unknown => Advisory::ApplicabilityUnknown,
            Applicability::NotAffected => Advisory::NotAffectedByFixture,
            Applicability::Remediated => Advisory::RemediatedByFixture,
            Applicability::Affected if catalog != Evidence::ReviewedFixture =>
                Advisory::ReviewCatalogUnavailable,
            Applicability::Affected if catalog_ids.contains(&f.vulnerability) =>
                Advisory::PriorityReview,
            Applicability::Affected => Advisory::ReviewNotListedInFixture,
        }
    }).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    const P: ProductBuild = ProductBuild { product: 1, build: 1 };
    const OTHER: ProductBuild = ProductBuild { product: 1, build: 2 };
    const R: Evidence = Evidence::ReviewedFixture;
    fn f(product: ProductBuild, vulnerability: u32, applicability: Applicability) -> Finding {
        Finding { product, vulnerability, applicability }
    }
    #[test]
    fn exact_applicability_and_catalog_priority() {
        use Applicability::*;
        assert_eq!(triage(P,R,R,R,&[1],&[
            f(P,1,Affected),f(P,2,Affected),f(P,3,Unknown),
            f(P,4,NotAffected),f(P,5,Remediated),f(OTHER,1,Affected),
        ]),Ok(vec![Advisory::PriorityReview,Advisory::ReviewNotListedInFixture,
            Advisory::ApplicabilityUnknown,Advisory::NotAffectedByFixture,
            Advisory::RemediatedByFixture,Advisory::ApplicabilityUnknown]));
    }
    #[test]
    fn stale_or_missing_inventory_or_mapping_cannot_clear() {
        for bad in [Evidence::Stale,Evidence::Unavailable] {
            for (i,m) in [(bad,R),(R,bad),(bad,bad)] {
                assert_eq!(triage(P,i,m,R,&[1],&[f(P,1,Applicability::Remediated),
                    f(P,2,Applicability::NotAffected),f(P,3,Applicability::Affected)]),
                    Ok(vec![Advisory::ApplicabilityUnknown;3]));
            }
        }
    }
    #[test]
    fn catalog_unavailable_is_not_a_negative() {
        for bad in [Evidence::Stale,Evidence::Unavailable] {
            assert_eq!(triage(P,R,R,bad,&[1],&[f(P,1,Applicability::Affected),
                f(P,2,Applicability::Affected)]),
                Ok(vec![Advisory::ReviewCatalogUnavailable;2]));
        }
    }
    #[test]
    fn duplicates_reject_whole_batch_even_if_conflicting() {
        assert_eq!(triage(P,R,R,R,&[1,1],&[]),Err(Error::Duplicate));
        assert_eq!(triage(P,R,R,R,&[],&[f(P,1,Applicability::Affected),
            f(P,1,Applicability::Remediated)]),Err(Error::Duplicate));
    }
    #[test]
    fn invalid_and_oversize_rejected() {
        assert_eq!(triage(P,R,R,R,&[0],&[]),Err(Error::InvalidInput));
        assert_eq!(triage(P,R,R,R,&[],&[f(P,0,Applicability::Unknown)]),Err(Error::InvalidInput));
        assert_eq!(triage(ProductBuild {product:0,build:1},R,R,R,&[],&[]),Err(Error::InvalidInput));
        assert_eq!(triage(P,R,R,R,&vec![1;MAX_ROWS+1],&[]),Err(Error::LimitExceeded));
        assert_eq!(triage(P,R,R,R,&[],&vec![f(P,1,Applicability::Unknown);MAX_ROWS+1]),
            Err(Error::LimitExceeded));
    }
    #[test]
    fn empty_or_absent_never_implies_safe() {
        assert_eq!(triage(P,R,R,R,&[],&[]),Ok(vec![]));
        assert_eq!(triage(P,R,R,R,&[],&[f(P,1,Applicability::Affected)]),
            Ok(vec![Advisory::ReviewNotListedInFixture]));
    }
}

/// Synthetic rollout identity; artifact is an opaque fixture label, NOT a hash
/// or verified signature. Build numbers are synthetic monotonic integers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rollout {
    pub from: ProductBuild,
    pub to: ProductBuild,
    pub artifact: u32,
    pub policy_version: u64,
    pub canary_count: u16,
}
#[derive(Clone, Copy, Debug)]
pub struct RolloutEvidence {
    pub rollout: Rollout,
    pub observed_at: u64,
    pub source: Evidence,
    pub rollback_rehearsal: Evidence,
    pub checked: u16,
    pub healthy: u16,
    pub failed: u16,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RolloutAdvisory {
    InvalidPlan, EvidenceUnavailable, EvidenceMismatch, InvalidCounts,
    RollbackReviewRequired, CanaryIncomplete, ExpansionReviewOnly,
}
/// No deployment or approval. Even a fully healthy synthetic canary only
/// suggests human review. A failed canary takes precedence over incomplete
/// coverage. Neither an expiry nor a reported rehearsal proves real rollback.
pub fn review_rollout(plan: Rollout, now: u64, evidence: RolloutEvidence) -> RolloutAdvisory {
    use RolloutAdvisory::*;
    if !valid_product(plan.from) || !valid_product(plan.to) ||
        plan.from.product != plan.to.product || plan.to.build <= plan.from.build ||
        plan.artifact == 0 || plan.policy_version == 0 ||
        plan.canary_count == 0 || usize::from(plan.canary_count) > MAX_ROWS {
        return InvalidPlan;
    }
    if evidence.rollout != plan { return EvidenceMismatch; }
    if evidence.source != Evidence::ReviewedFixture ||
        !now.checked_sub(evidence.observed_at).is_some_and(|age| age <= 300) {
        return EvidenceUnavailable;
    }
    if evidence.checked > plan.canary_count ||
        evidence.healthy.checked_add(evidence.failed) != Some(evidence.checked) {
        return InvalidCounts;
    }
    if evidence.failed != 0 || evidence.rollback_rehearsal != Evidence::ReviewedFixture {
        return RollbackReviewRequired;
    }
    if evidence.checked != plan.canary_count { return CanaryIncomplete; }
    ExpansionReviewOnly
}

#[cfg(test)]
mod rollout_tests {
    use super::*;
    const PLAN: Rollout = Rollout {
        from: ProductBuild { product: 1, build: 1 },
        to: ProductBuild { product: 1, build: 2 },
        artifact: 7, policy_version: 1, canary_count: 3,
    };
    fn evidence() -> RolloutEvidence {
        RolloutEvidence { rollout: PLAN, observed_at: 100,
            source: Evidence::ReviewedFixture, rollback_rehearsal: Evidence::ReviewedFixture,
            checked: 3, healthy: 3, failed: 0 }
    }
    #[test]
    fn full_canary_only_suggests_review() {
        assert_eq!(review_rollout(PLAN,400,evidence()),RolloutAdvisory::ExpansionReviewOnly);
        assert_eq!(review_rollout(PLAN,100,RolloutEvidence { checked: 2, healthy: 2, ..evidence() }),
            RolloutAdvisory::CanaryIncomplete);
    }
    #[test]
    fn failure_even_in_partial_canary_requires_rollback_review() {
        assert_eq!(review_rollout(PLAN,100,RolloutEvidence { checked: 1, healthy: 0, failed: 1, ..evidence() }),
            RolloutAdvisory::RollbackReviewRequired);
        for state in [Evidence::Stale,Evidence::Unavailable] {
            assert_eq!(review_rollout(PLAN,100,RolloutEvidence { rollback_rehearsal: state, ..evidence() }),
                RolloutAdvisory::RollbackReviewRequired);
        }
    }
    #[test]
    fn evidence_bound_to_entire_plan() {
        for rollout in [Rollout { artifact: 8, ..PLAN }, Rollout { policy_version: 2, ..PLAN },
            Rollout { canary_count: 4, ..PLAN }, Rollout { to: ProductBuild { product: 1, build: 3 }, ..PLAN },
            Rollout { from: ProductBuild { product: 1, build: 2 }, ..PLAN }] {
            assert_eq!(review_rollout(PLAN,100,RolloutEvidence { rollout, ..evidence() }),
                RolloutAdvisory::EvidenceMismatch);
        }
    }
    #[test]
    fn missing_future_or_stale_evidence() {
        for now in [99,401] {
            assert_eq!(review_rollout(PLAN,now,evidence()),RolloutAdvisory::EvidenceUnavailable);
        }
        for source in [Evidence::Stale,Evidence::Unavailable] {
            assert_eq!(review_rollout(PLAN,100,RolloutEvidence { source, ..evidence() }),
                RolloutAdvisory::EvidenceUnavailable);
        }
    }
    #[test]
    fn invalid_and_overflow_counts_rejected() {
        for e in [RolloutEvidence { checked: 4, healthy: 4, ..evidence() },
            RolloutEvidence { healthy: 2, ..evidence() },
            RolloutEvidence { healthy: u16::MAX, failed: 1, ..evidence() }] {
            assert_eq!(review_rollout(PLAN,100,e),RolloutAdvisory::InvalidCounts);
        }
    }
    #[test]
    fn invalid_plan_rejected() {
        for plan in [Rollout { artifact: 0, ..PLAN }, Rollout { policy_version: 0, ..PLAN },
            Rollout { canary_count: 0, ..PLAN }, Rollout { canary_count: 257, ..PLAN },
            Rollout { to: PLAN.from, ..PLAN },
            Rollout { to: ProductBuild { product: 2, build: 2 }, ..PLAN }] {
            assert_eq!(review_rollout(plan,100,evidence()),RolloutAdvisory::InvalidPlan);
        }
    }
}
