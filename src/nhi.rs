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
