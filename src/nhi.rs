// Copyright 2026 Gian Paolo Franceschini. See LICENSE.
//! Bounded workload identity inventory rehearsal. Metadata only; no credentials,
//! real identity discovery, cryptography, authorization, rotation or revocation.
use std::collections::BTreeSet;

pub const MAX_IDENTITIES: usize = 256;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reported { Yes, No, Unknown }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Revocation { NotRevoked, Revoked, Unknown }
#[derive(Clone, Copy, Debug)]
pub struct Identity {
    pub id: u32,
    pub owner_assigned: Reported,
    pub scoped: Reported,
    pub reviewed_fixture: bool,
    pub observed_at: u64,
    pub issued_at: Option<u64>,
    pub expires_at: Option<u64>,
    pub revocation: Revocation,
}
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub max_observation_age: u64,
    pub max_lifetime: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Advisory {
    UnverifiedEvidence, StaleEvidence, OwnerReview, ScopeReview,
    Revoked, RevocationUnknown, TimeUnknown, InvalidTime, Expired,
    LifetimeReview, FixtureCriteriaReported,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error { InvalidConfiguration, InvalidIdentifier, Duplicate, LimitExceeded }

/// Each row returns all applicable advisory reasons. Positive fixture criteria
/// never establish real identity, validity, permission, or non-compromise.
/// No external inputs are fetched and no action is executed.
pub fn assess(rows: &[Identity], now: u64, limits: Limits)
    -> Result<Vec<Vec<Advisory>>, Error>
{
    if limits.max_observation_age == 0 || limits.max_lifetime == 0 {
        return Err(Error::InvalidConfiguration);
    }
    if rows.len() > MAX_IDENTITIES { return Err(Error::LimitExceeded); }
    let mut ids = BTreeSet::new();
    for row in rows {
        if row.id == 0 { return Err(Error::InvalidIdentifier); }
        if !ids.insert(row.id) { return Err(Error::Duplicate); }
    }
    Ok(rows.iter().map(|row| {
        use Advisory::*;
        let mut a = Vec::new();
        if !row.reviewed_fixture { a.push(UnverifiedEvidence); }
        match now.checked_sub(row.observed_at) {
            None => a.push(InvalidTime),
            Some(age) if age > limits.max_observation_age => a.push(StaleEvidence),
            _ => (),
        }
        if row.owner_assigned != Reported::Yes { a.push(OwnerReview); }
        if row.scoped != Reported::Yes { a.push(ScopeReview); }
        match row.revocation {
            Revocation::Revoked => a.push(Revoked),
            Revocation::Unknown => a.push(RevocationUnknown),
            Revocation::NotRevoked => (),
        }
        match (row.issued_at, row.expires_at) {
            (Some(start), Some(end)) if start <= row.observed_at && end > start => {
                if end <= now { a.push(Expired); }
                if end - start > limits.max_lifetime { a.push(LifetimeReview); }
            }
            (Some(_), Some(_)) => {
                if !a.contains(&InvalidTime) { a.push(InvalidTime); }
            }
            _ => a.push(TimeUnknown),
        }
        if a.is_empty() { a.push(FixtureCriteriaReported); }
        a
    }).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    const LIMITS: Limits = Limits { max_observation_age: 10, max_lifetime: 30 };
    const ROW: Identity = Identity { id: 1, owner_assigned: Reported::Yes,
        scoped: Reported::Yes, reviewed_fixture: true, observed_at: 95,
        issued_at: Some(90), expires_at: Some(120), revocation: Revocation::NotRevoked };
    fn single(row: Identity) -> Vec<Advisory> {
        assess(&[row], 100, LIMITS).unwrap().remove(0)
    }
    #[test] fn positive_fixture_only() {
        assert_eq!(single(ROW), vec![Advisory::FixtureCriteriaReported]);
        assert_eq!(assess(&[], 100, LIMITS), Ok(vec![]));
    }
    #[test] fn unknown_and_untrusted_never_positive() {
        for value in [Reported::No, Reported::Unknown] {
            assert_eq!(single(Identity { owner_assigned: value, scoped: value,
                reviewed_fixture: false, revocation: Revocation::Unknown,
                issued_at: None, ..ROW }), vec![Advisory::UnverifiedEvidence,
                Advisory::OwnerReview, Advisory::ScopeReview, Advisory::RevocationUnknown,
                Advisory::TimeUnknown]);
        }
    }
    #[test] fn revoked_expired_and_long_lived() {
        assert_eq!(single(Identity { issued_at: Some(10), expires_at: Some(100),
            revocation: Revocation::Revoked, ..ROW }), vec![Advisory::Revoked,
            Advisory::Expired, Advisory::LifetimeReview]);
    }
    #[test] fn observation_time_boundaries() {
        assert_eq!(single(Identity { observed_at: 90, ..ROW }), vec![Advisory::FixtureCriteriaReported]);
        assert!(single(Identity { observed_at: 89, ..ROW }).contains(&Advisory::StaleEvidence));
        assert_eq!(single(Identity { observed_at: 101, ..ROW }), vec![Advisory::InvalidTime]);
    }
    #[test] fn invalid_credential_time_no_underflow() {
        for (start,end) in [(96,120),(90,90),(90,0),(u64::MAX,1)] {
            assert_eq!(single(Identity { issued_at: Some(start), expires_at: Some(end),
                ..ROW }), vec![Advisory::InvalidTime]);
        }
    }
    #[test] fn rejects_invalid_batch() {
        assert_eq!(assess(&[ROW,ROW],100,LIMITS), Err(Error::Duplicate));
        assert_eq!(assess(&[Identity { id:0,..ROW }],100,LIMITS), Err(Error::InvalidIdentifier));
        assert_eq!(assess(&vec![ROW;MAX_IDENTITIES+1],100,LIMITS), Err(Error::LimitExceeded));
        assert_eq!(assess(&[],100,Limits {max_lifetime:0,..LIMITS}), Err(Error::InvalidConfiguration));
    }
}


/// Offline rotation evidence: fixture identifiers only, no credentials or actions.
/// The timestamps describe a synthetic handoff, not verified authentication.
#[derive(Clone, Copy, Debug)]
pub struct Rotation {
    pub workload: u32,
    pub previous: u32,
    pub successor: u32,
    pub issued: u64,
    pub successor_check: Option<u64>,
    pub previous_revocation: Option<u64>,
    pub observed: u64,
    pub reviewed_fixture: bool,
    pub successor_scoped: Reported,
    pub previous_revoked: Revocation,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RotationReview {
    InvalidPlan, Unverified, Stale, InvalidTimeline, ScopeReview,
    ContinuityUnknown, RevocationReview, OverlapExceeded, FixtureReviewOnly,
}

/// Never recommends automatic revocation. A successful synthetic handoff is
/// review evidence only. All time arithmetic follows explicit ordering checks.
pub fn assess_rotation(r: Rotation, now: u64, max_age: u64, max_overlap: u64)
    -> RotationReview
{
    use RotationReview::*;
    if r.workload == 0 || r.previous == 0 || r.successor == 0 ||
        r.previous == r.successor || max_age == 0 || max_overlap == 0 {
        return InvalidPlan;
    }
    if !r.reviewed_fixture { return Unverified; }
    if r.issued > r.observed || r.observed > now { return InvalidTimeline; }
    if now - r.observed > max_age { return Stale; }
    if r.successor_scoped != Reported::Yes { return ScopeReview; }
    let Some(check) = r.successor_check else { return ContinuityUnknown; };
    if check < r.issued || check > r.observed { return InvalidTimeline; }
    if let Some(revoked) = r.previous_revocation {
        if revoked < check || revoked > r.observed { return InvalidTimeline; }
        if revoked - r.issued > max_overlap { return OverlapExceeded; }
        if r.previous_revoked != Revocation::Revoked { return RevocationReview; }
    } else {
        if now - r.issued > max_overlap { return OverlapExceeded; }
        return RevocationReview;
    }
    FixtureReviewOnly
}

#[cfg(test)]
mod rotation_tests {
    use super::*;
    const R: Rotation = Rotation { workload: 1, previous: 2, successor: 3,
        issued: 80, successor_check: Some(85), previous_revocation: Some(90),
        observed: 95, reviewed_fixture: true, successor_scoped: Reported::Yes,
        previous_revoked: Revocation::Revoked };
    fn check(r: Rotation) -> RotationReview { assess_rotation(r, 100, 10, 10) }
    #[test] fn exact_overlap_boundary_is_review_only() {
        assert_eq!(check(R), RotationReview::FixtureReviewOnly);
        assert_eq!(check(Rotation { previous_revocation: Some(91), ..R }), RotationReview::OverlapExceeded);
    }
    #[test] fn missing_continuity_or_revocation_never_passes() {
        assert_eq!(check(Rotation { successor_check: None, ..R }), RotationReview::ContinuityUnknown);
        assert_eq!(check(Rotation { previous_revoked: Revocation::Unknown, ..R }), RotationReview::RevocationReview);
        assert_eq!(check(Rotation { previous_revocation: None, ..R }), RotationReview::OverlapExceeded);
        assert_eq!(assess_rotation(Rotation { previous_revocation: None, ..R }, 100, 10, 20), RotationReview::RevocationReview);
    }
    #[test] fn invalid_time_order_is_rejected() {
        for r in [Rotation { issued: 96, ..R }, Rotation { observed: 101, ..R },
            Rotation { successor_check: Some(79), ..R },
            Rotation { previous_revocation: Some(84), ..R },
            Rotation { previous_revocation: Some(96), ..R }] {
            assert_eq!(check(r), RotationReview::InvalidTimeline);
        }
        assert_eq!(check(Rotation { observed: 89, ..R }), RotationReview::Stale);
    }
    #[test] fn scope_identity_and_provenance_required() {
        assert_eq!(check(Rotation { successor: 2, ..R }), RotationReview::InvalidPlan);
        assert_eq!(check(Rotation { workload: 0, ..R }), RotationReview::InvalidPlan);
        assert_eq!(check(Rotation { reviewed_fixture: false, ..R }), RotationReview::Unverified);
        assert_eq!(check(Rotation { successor_scoped: Reported::Unknown, ..R }), RotationReview::ScopeReview);
        assert_eq!(assess_rotation(R, 100, 0, 10), RotationReview::InvalidPlan);
    }
}


/// Explicit coverage against an independently supplied required fixture set.
/// A complete report is not proof that all real identities were inventoried.
/// No discovery, authorization, credentials, persistence or system actions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CoverageStatus {
    MissingObservation,
    Observed(Vec<Advisory>),
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoverageRow {
    pub id: u32,
    pub status: CoverageStatus,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoverageReport {
    pub rows: Vec<CoverageRow>,
    pub all_fixture_criteria_reported: bool,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CoverageError {
    EmptyRequired,
    UnexpectedIdentity,
    Inventory(Error),
}
/// Validate the entire snapshot before returning a report. Expected identities
/// cannot be inferred from observations; missing rows are not healthy rows.
pub fn assess_coverage(required: &[u32], observed: &[Identity], now: u64, limits: Limits)
    -> Result<CoverageReport, CoverageError>
{
    use CoverageError::*;
    if required.is_empty() { return Err(EmptyRequired); }
    if required.len() > MAX_IDENTITIES || observed.len() > MAX_IDENTITIES {
        return Err(Inventory(Error::LimitExceeded));
    }
    let mut expected = BTreeSet::new();
    for &id in required {
        if id == 0 { return Err(Inventory(Error::InvalidIdentifier)); }
        if !expected.insert(id) { return Err(Inventory(Error::Duplicate)); }
    }
    let assessments = assess(observed, now, limits).map_err(Inventory)?;
    let mut by_id = std::collections::BTreeMap::new();
    for (row, advisory) in observed.iter().zip(assessments) {
        if !expected.contains(&row.id) { return Err(UnexpectedIdentity); }
        by_id.insert(row.id, advisory);
    }
    let rows: Vec<_> = expected.into_iter().map(|id| CoverageRow {
        id,
        status: match by_id.remove(&id) {
            Some(a) => CoverageStatus::Observed(a),
            None => CoverageStatus::MissingObservation,
        },
    }).collect();
    let all_fixture_criteria_reported = rows.iter().all(|row| match &row.status {
        CoverageStatus::Observed(a) => a.as_slice() == [Advisory::FixtureCriteriaReported],
        CoverageStatus::MissingObservation => false,
    });
    Ok(CoverageReport { rows, all_fixture_criteria_reported })
}

#[cfg(test)]
mod coverage_tests {
    use super::*;
    const LIMITS: Limits = Limits { max_observation_age: 10, max_lifetime: 30 };
    const ROW: Identity = Identity { id: 1, owner_assigned: Reported::Yes,
        scoped: Reported::Yes, reviewed_fixture: true, observed_at: 95,
        issued_at: Some(90), expires_at: Some(120), revocation: Revocation::NotRevoked };
    #[test]
    fn coverage_is_complete_only_for_all_required_healthy_fixtures() {
        let second = Identity { id: 2, ..ROW };
        let report = assess_coverage(&[2,1], &[second,ROW], 100, LIMITS).unwrap();
        assert!(report.all_fixture_criteria_reported);
        assert_eq!(report, assess_coverage(&[1,2], &[ROW,second], 100, LIMITS).unwrap());
        assert_eq!(report.rows.iter().map(|r| r.id).collect::<Vec<_>>(), vec![1,2]);
    }
    #[test]
    fn missing_and_untrusted_rows_do_not_clear_inventory() {
        let report = assess_coverage(&[1,2,3], &[ROW,
            Identity { id: 2, reviewed_fixture: false, ..ROW }], 100, LIMITS).unwrap();
        assert!(!report.all_fixture_criteria_reported);
        assert_eq!(report.rows[1].status, CoverageStatus::Observed(vec![Advisory::UnverifiedEvidence]));
        assert_eq!(report.rows[2].status, CoverageStatus::MissingObservation);
        let empty = assess_coverage(&[1], &[], 100, LIMITS).unwrap();
        assert!(!empty.all_fixture_criteria_reported);
        assert_eq!(empty.rows[0].status, CoverageStatus::MissingObservation);
    }
    #[test]
    fn rejects_invalid_required_and_observed_snapshots() {
        use CoverageError::*;
        assert_eq!(assess_coverage(&[], &[], 100, LIMITS), Err(EmptyRequired));
        assert_eq!(assess_coverage(&[0], &[], 100, LIMITS), Err(Inventory(Error::InvalidIdentifier)));
        assert_eq!(assess_coverage(&[1,1], &[], 100, LIMITS), Err(Inventory(Error::Duplicate)));
        assert_eq!(assess_coverage(&[1], &[ROW,ROW], 100, LIMITS), Err(Inventory(Error::Duplicate)));
        assert_eq!(assess_coverage(&[2], &[ROW], 100, LIMITS), Err(UnexpectedIdentity));
        assert_eq!(assess_coverage(&[1], &[Identity { id: 0, ..ROW }], 100, LIMITS),
            Err(Inventory(Error::InvalidIdentifier)));
        assert_eq!(assess_coverage(&[1], &[], 100, Limits { max_lifetime: 0, ..LIMITS }),
            Err(Inventory(Error::InvalidConfiguration)));
    }
    #[test]
    fn bounds_and_nonpositive_reasons_are_preserved() {
        let required: Vec<u32> = (1..=MAX_IDENTITIES as u32).collect();
        let observed: Vec<_> = required.iter().map(|&id| Identity { id, ..ROW }).collect();
        assert!(assess_coverage(&required, &observed, 100, LIMITS).unwrap().all_fixture_criteria_reported);
        assert_eq!(assess_coverage(&vec![1; MAX_IDENTITIES+1], &[], 100, LIMITS),
            Err(CoverageError::Inventory(Error::LimitExceeded)));
        assert_eq!(assess_coverage(&[1], &vec![ROW; MAX_IDENTITIES+1], 100, LIMITS),
            Err(CoverageError::Inventory(Error::LimitExceeded)));
        for bad in [Identity { revocation: Revocation::Revoked, ..ROW },
            Identity { observed_at: 101, ..ROW }, Identity { observed_at: 89, ..ROW },
            Identity { expires_at: Some(100), ..ROW }, Identity { scoped: Reported::Unknown, ..ROW }] {
            let r = assess_coverage(&[1], &[bad], 100, LIMITS).unwrap();
            assert!(!r.all_fixture_criteria_reported);
            assert_eq!(r.rows[0].status, CoverageStatus::Observed(assess(&[bad],100,LIMITS).unwrap().remove(0)));
        }
    }
}
