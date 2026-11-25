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
