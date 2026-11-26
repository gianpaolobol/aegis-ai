// Copyright 2026 Gian Paolo Franceschini. See LICENSE.
//! Synthetic recovery-readiness advisory. No filesystem, backup or restore operations.
use std::collections::BTreeSet;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Medium { Disk, Tape, ObjectStorage, Unknown }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Evidence { ReportedYes, ReportedNo, Unknown }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind { Original, Backup }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CopyFixture {
    pub id: u16,
    pub failure_domain: u16,
    pub medium: Medium,
    pub kind: Kind,
    pub offsite: Evidence,
    pub offline_or_immutable: Evidence,
    pub encrypted: Evidence,
    pub separate_credentials: Evidence,
    // Synthetic observed restore time; not a signed restore receipt.
    pub restore_verified_at: Option<u64>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error { InvalidScope, InvalidInventory, FutureRestore }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict { ReviewRequired, FixtureCriteriaReported }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Report {
    pub copies: usize,
    pub failure_domains: usize,
    pub known_media: usize,
    pub offsite_backup: bool,
    pub isolated_backup: bool,
    pub all_backups_encrypted: bool,
    pub all_backups_separate_credentials: bool,
    pub recent_isolated_restore: bool,
    pub verdict: Verdict,
}
/// Require a bounded explicit inventory with one original and unique copy IDs.
/// The isolated restore must refer to an actual backup with isolation reported,
/// not to the original or a different copy. No unknown is positive evidence.
pub fn assess(copies: &[CopyFixture], now: u64, max_restore_age: u64) -> Result<Report, Error> {
    if now == 0 || max_restore_age == 0 || max_restore_age > now {
        return Err(Error::InvalidScope);
    }
    if copies.is_empty() || copies.len() > 64 { return Err(Error::InvalidInventory); }
    let mut ids = BTreeSet::new();
    let mut domains = BTreeSet::new();
    let mut media = BTreeSet::new();
    let mut originals = 0;
    let mut offsite = false;
    let mut isolated = false;
    let mut recent = false;
    let mut encrypted = true;
    let mut separate = true;
    let mut backups = 0;
    for c in copies {
        if c.id == 0 || c.failure_domain == 0 || !ids.insert(c.id) {
            return Err(Error::InvalidInventory);
        }
        if matches!(c.restore_verified_at, Some(t) if t == 0 || t > now) {
            return Err(Error::FutureRestore);
        }
        domains.insert(c.failure_domain);
        if c.medium != Medium::Unknown { media.insert(c.medium); }
        if c.kind == Kind::Original {
            originals += 1;
            // Restore evidence is only meaningful on the backup tested.
            if c.restore_verified_at.is_some() { return Err(Error::InvalidInventory); }
            continue;
        }
        backups += 1;
        offsite |= c.offsite == Evidence::ReportedYes;
        encrypted &= c.encrypted == Evidence::ReportedYes;
        separate &= c.separate_credentials == Evidence::ReportedYes;
        if c.offline_or_immutable == Evidence::ReportedYes {
            isolated = true;
            recent |= matches!(c.restore_verified_at, Some(t) if now - t <= max_restore_age);
        }
    }
    if originals != 1 { return Err(Error::InvalidInventory); }
    encrypted &= backups > 0;
    separate &= backups > 0;
    let verdict = if copies.len() >= 3 && domains.len() >= 3 && media.len() >= 2 &&
        offsite && isolated && encrypted && separate && recent {
        Verdict::FixtureCriteriaReported
    } else { Verdict::ReviewRequired };
    Ok(Report { copies: copies.len(), failure_domains: domains.len(), known_media: media.len(),
        offsite_backup: offsite, isolated_backup: isolated, all_backups_encrypted: encrypted,
        all_backups_separate_credentials: separate, recent_isolated_restore: recent, verdict })
}
/// Fixed harmless scenario for CLI and regression tests.
pub fn example() -> [CopyFixture; 3] {
    use Evidence::{ReportedYes as Yes, ReportedNo as No, Unknown};
    [
        CopyFixture { id: 1, failure_domain: 1, medium: Medium::Disk, kind: Kind::Original,
            offsite: No, offline_or_immutable: No, encrypted: Unknown,
            separate_credentials: Unknown, restore_verified_at: None },
        CopyFixture { id: 2, failure_domain: 2, medium: Medium::Disk, kind: Kind::Backup,
            offsite: No, offline_or_immutable: No, encrypted: Yes,
            separate_credentials: Yes, restore_verified_at: None },
        CopyFixture { id: 3, failure_domain: 3, medium: Medium::Tape, kind: Kind::Backup,
            offsite: Yes, offline_or_immutable: Yes, encrypted: Yes,
            separate_credentials: Yes, restore_verified_at: Some(90) },
    ]
}
#[cfg(test)]
mod tests {
    use super::*;
    fn run(c: &[CopyFixture]) -> Result<Report, Error> { assess(c,100,20) }
    #[test] fn complete_fixture_is_not_proof() {
        let r = run(&example()).unwrap();
        assert_eq!(r.verdict,Verdict::FixtureCriteriaReported);
        assert_eq!((r.copies,r.failure_domains,r.known_media),(3,3,2));
    }
    #[test] fn duplicate_ids_and_invalid_inventory_rejected() {
        let mut c = example(); c[2].id = c[1].id;
        assert_eq!(run(&c),Err(Error::InvalidInventory));
        assert_eq!(run(&[]),Err(Error::InvalidInventory));
        assert_eq!(run(&[example()[0];65]),Err(Error::InvalidInventory));
        let mut c = example(); c[1].kind = Kind::Original;
        assert_eq!(run(&c),Err(Error::InvalidInventory));
    }
    #[test] fn shared_failure_domain_or_medium_requires_review() {
        let mut c = example(); c[2].failure_domain = 2;
        assert_eq!(run(&c).unwrap().verdict,Verdict::ReviewRequired);
        c = example(); c[2].medium = Medium::Unknown;
        assert_eq!(run(&c).unwrap().verdict,Verdict::ReviewRequired);
    }
    #[test] fn no_backup_is_not_vacuous_success() {
        let c = example(); let r = run(&c[..1]).unwrap();
        assert!(!r.all_backups_encrypted && !r.all_backups_separate_credentials);
        assert_eq!(r.verdict,Verdict::ReviewRequired);
    }
    #[test] fn unknown_security_evidence_requires_review() {
        for n in 0..4 {
            let mut c = example();
            match n {
                0 => c[2].offsite = Evidence::Unknown,
                1 => c[2].offline_or_immutable = Evidence::Unknown,
                2 => c[2].encrypted = Evidence::Unknown,
                _ => c[1].separate_credentials = Evidence::Unknown,
            }
            assert_eq!(run(&c).unwrap().verdict,Verdict::ReviewRequired);
        }
    }
    #[test] fn restore_must_be_recent_and_on_isolated_backup() {
        let mut c = example(); c[2].restore_verified_at = Some(79);
        c[1].restore_verified_at = Some(99);
        assert!(!run(&c).unwrap().recent_isolated_restore);
        assert_eq!(run(&c).unwrap().verdict,Verdict::ReviewRequired);
        c[2].restore_verified_at = Some(80);
        assert_eq!(run(&c).unwrap().verdict,Verdict::FixtureCriteriaReported);
        c[2].restore_verified_at = None;
        assert!(!run(&c).unwrap().recent_isolated_restore);
    }
    #[test] fn future_and_original_restore_rejected() {
        let mut c = example(); c[2].restore_verified_at = Some(101);
        assert_eq!(run(&c),Err(Error::FutureRestore));
        c = example(); c[0].restore_verified_at = Some(99);
        assert_eq!(run(&c),Err(Error::InvalidInventory));
        assert_eq!(assess(&example(),100,0),Err(Error::InvalidScope));
    }
}
