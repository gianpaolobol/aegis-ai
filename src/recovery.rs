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
    assess_inner(copies, now, max_restore_age, None)
}
fn assess_inner(copies: &[CopyFixture], now: u64, max_restore_age: u64,
    required_restore: Option<u16>) -> Result<Report, Error> {
    if now == 0 || max_restore_age == 0 || max_restore_age > now {
        return Err(Error::InvalidScope);
    }
    if copies.is_empty() || copies.len() > 64 { return Err(Error::InvalidInventory); }
    let mut ids = BTreeSet::new();
    let mut domains = BTreeSet::new();
    let mut media = BTreeSet::new();
    let mut originals = 0;
    let mut original = None;
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
            original = Some(c);
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
    // A single coherent 3-2-1 witness, not unrelated aggregate counters.
    // The original and two known-medium backups must have distinct failure
    // domains, and the offsite and recently restored isolated copy must be
    // part of that same witness. Extra backups still need security evidence.
    let original = original.ok_or(Error::InvalidInventory)?;
    let witness = original.medium != Medium::Unknown && copies.iter().any(|a|
        a.kind == Kind::Backup && a.medium != Medium::Unknown &&
        a.failure_domain != original.failure_domain && copies.iter().any(|b|
            b.kind == Kind::Backup && b.medium != Medium::Unknown &&
            b.failure_domain != original.failure_domain &&
            b.failure_domain != a.failure_domain &&
            (a.medium != original.medium || b.medium != original.medium) &&
            (a.offsite == Evidence::ReportedYes || b.offsite == Evidence::ReportedYes) &&
            [a,b].iter().any(|c| required_restore.is_none_or(|id| c.id == id) &&
                c.offline_or_immutable == Evidence::ReportedYes &&
                c.restore_verified_at.is_some_and(|at| now - at <= max_restore_age))));
    let verdict = if witness && encrypted && separate {
        Verdict::FixtureCriteriaReported
    } else { Verdict::ReviewRequired };
    Ok(Report { copies: copies.len(), failure_domains: domains.len(), known_media: media.len(),
        offsite_backup: offsite, isolated_backup: isolated, all_backups_encrypted: encrypted,
        all_backups_separate_credentials: separate, recent_isolated_restore: recent, verdict })
}
/// Synthetic restore objectives are expressed in seconds and bound to one
/// planned dataset, backup copy and exercise. The caller supplies fixture
/// evidence; nothing here authenticates it or performs a restoration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RestorePlan {
    pub dataset: u16,
    pub copy: u16,
    pub exercise: u64,
    pub incident_at: u64,
    pub max_data_loss: u64,
    pub max_downtime: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RestoreReceipt {
    pub dataset: u16,
    pub copy: u16,
    pub exercise: u64,
    pub recovery_point: u64,
    pub completed_at: u64,
    pub integrity: Evidence,
    pub functional_check: Evidence,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObjectiveVerdict { InvalidPlan, MissingOrMismatchedEvidence, InvalidTimeline,
    VerificationRequired, ObjectivesMissed, FixtureObjectivesReported }
pub fn assess_objectives(plan: RestorePlan, receipt: Option<RestoreReceipt>,
    now: u64) -> ObjectiveVerdict {
    use ObjectiveVerdict::*;
    if plan.dataset == 0 || plan.copy == 0 || plan.exercise == 0 ||
        plan.incident_at == 0 || plan.incident_at > now ||
        plan.max_downtime == 0 {
        return InvalidPlan;
    }
    let Some(r) = receipt else { return MissingOrMismatchedEvidence; };
    if (r.dataset, r.copy, r.exercise) != (plan.dataset, plan.copy, plan.exercise) {
        return MissingOrMismatchedEvidence;
    }
    if r.recovery_point == 0 || r.recovery_point > plan.incident_at ||
        r.completed_at < plan.incident_at || r.completed_at > now {
        return InvalidTimeline;
    }
    if r.integrity != Evidence::ReportedYes || r.functional_check != Evidence::ReportedYes {
        return VerificationRequired;
    }
    if plan.incident_at - r.recovery_point > plan.max_data_loss ||
        r.completed_at - plan.incident_at > plan.max_downtime {
        return ObjectivesMissed;
    }
    FixtureObjectivesReported
}
/// Combined advisory only: callers supply one synthetic dataset inventory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LinkedVerdict {
    Objectives(ObjectiveVerdict),
    ReceiptNotLinked,
    InventoryReviewRequired,
    LinkedFixtureReported,
}
/// The exercise receipt must match the actual isolated backup in the same
/// 3-2-1 witness, including its reported restore completion time. Neither
/// the inventory nor the clock or receipt is authenticated here.
pub fn assess_linked_objectives(copies: &[CopyFixture], plan: RestorePlan,
    receipt: Option<RestoreReceipt>, now: u64, max_restore_age: u64)
    -> Result<LinkedVerdict, Error> {
    // Validate every inventory entry even when the receipt is missing.
    let report = assess_inner(copies, now, max_restore_age, Some(plan.copy))?;
    let objectives = assess_objectives(plan, receipt, now);
    if objectives != ObjectiveVerdict::FixtureObjectivesReported {
        return Ok(LinkedVerdict::Objectives(objectives));
    }
    let Some(r) = receipt else { return Ok(LinkedVerdict::ReceiptNotLinked); };
    if !copies.iter().any(|c| c.kind == Kind::Backup && c.id == r.copy &&
        c.offline_or_immutable == Evidence::ReportedYes &&
        c.restore_verified_at == Some(r.completed_at)) {
        return Ok(LinkedVerdict::ReceiptNotLinked);
    }
    if report.verdict != Verdict::FixtureCriteriaReported {
        return Ok(LinkedVerdict::InventoryReviewRequired);
    }
    Ok(LinkedVerdict::LinkedFixtureReported)
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
    #[test] fn unrelated_offsite_or_isolated_copy_cannot_complete_witness() {
        let mut c = example().to_vec();
        // The sole offsite / isolated restore shares the original failure domain.
        c[2].failure_domain = 1;
        c.push(CopyFixture { id: 4, failure_domain: 3, medium: Medium::Tape,
            ..c[1] });
        let r = run(&c).unwrap();
        assert_eq!((r.failure_domains, r.known_media), (3, 2));
        assert!(r.offsite_backup && r.recent_isolated_restore);
        assert_eq!(r.verdict, Verdict::ReviewRequired);
        c[2].failure_domain = 3;
        assert_eq!(run(&c).unwrap().verdict, Verdict::FixtureCriteriaReported);
    }
    #[test] fn unrelated_medium_cannot_complete_witness() {
        let mut c = example().to_vec();
        c[2].medium = Medium::Disk;
        c.push(CopyFixture { id: 4, failure_domain: 1, medium: Medium::Tape,
            ..c[1] });
        assert_eq!(run(&c).unwrap().known_media, 2);
        assert_eq!(run(&c).unwrap().verdict, Verdict::ReviewRequired);
    }
    fn objective_fixture() -> (RestorePlan, RestoreReceipt) {
        (RestorePlan { dataset: 1, copy: 3, exercise: 7, incident_at: 100,
            max_data_loss: 10, max_downtime: 20 },
         RestoreReceipt { dataset: 1, copy: 3, exercise: 7, recovery_point: 90,
            completed_at: 120, integrity: Evidence::ReportedYes,
            functional_check: Evidence::ReportedYes })
    }
    #[test] fn objective_boundaries_and_missed_objectives() {
        use ObjectiveVerdict::*;
        let (p,r) = objective_fixture();
        assert_eq!(assess_objectives(p,Some(r),120),FixtureObjectivesReported);
        assert_eq!(assess_objectives(p,Some(RestoreReceipt { recovery_point: 89, ..r }),120),ObjectivesMissed);
        assert_eq!(assess_objectives(p,Some(RestoreReceipt { completed_at: 121, ..r }),121),ObjectivesMissed);
        assert_eq!(assess_objectives(RestorePlan { max_data_loss: 0, ..p },
            Some(RestoreReceipt { recovery_point: 100, ..r }),120),FixtureObjectivesReported);
    }
    #[test] fn objectives_require_exact_scope_and_verification() {
        use ObjectiveVerdict::*;
        let (p,r) = objective_fixture();
        assert_eq!(assess_objectives(p,None,120),MissingOrMismatchedEvidence);
        for wrong in [RestoreReceipt { dataset: 2, ..r }, RestoreReceipt { copy: 4, ..r },
            RestoreReceipt { exercise: 8, ..r }] {
            assert_eq!(assess_objectives(p,Some(wrong),120),MissingOrMismatchedEvidence);
        }
        for wrong in [RestoreReceipt { integrity: Evidence::Unknown, ..r },
            RestoreReceipt { functional_check: Evidence::ReportedNo, ..r }] {
            assert_eq!(assess_objectives(p,Some(wrong),120),VerificationRequired);
        }
    }
    #[test] fn objectives_reject_invalid_timeline_and_plan() {
        use ObjectiveVerdict::*;
        let (p,r) = objective_fixture();
        for wrong in [RestoreReceipt { recovery_point: 0, ..r },
            RestoreReceipt { recovery_point: 101, ..r },
            RestoreReceipt { completed_at: 99, ..r },
            RestoreReceipt { completed_at: 121, ..r }] {
            assert_eq!(assess_objectives(p,Some(wrong),120),InvalidTimeline);
        }
        assert_eq!(assess_objectives(RestorePlan { exercise: 0, ..p },Some(r),120),InvalidPlan);
        assert_eq!(assess_objectives(p,Some(r),99),InvalidPlan);
    }
    #[test] fn linked_restore_requires_exact_receipt_and_copy() {
        use LinkedVerdict::*;
        let (p,r) = objective_fixture();
        let mut c = example();
        c[2].restore_verified_at = Some(120);
        assert_eq!(assess_linked_objectives(&c,p,Some(r),120,20),Ok(LinkedFixtureReported));
        c[2].restore_verified_at = Some(119);
        assert_eq!(assess_linked_objectives(&c,p,Some(r),120,20),Ok(ReceiptNotLinked));
        c[2].restore_verified_at = Some(120);
        let p = RestorePlan { copy: 1, ..p };
        let r = RestoreReceipt { copy: 1, ..r };
        assert_eq!(assess_linked_objectives(&c,p,Some(r),120,20),Ok(ReceiptNotLinked));
    }
    #[test] fn linked_restore_cannot_borrow_unrelated_witness() {
        use LinkedVerdict::*;
        let (p,r) = objective_fixture();
        let mut c = example().to_vec();
        c[2].restore_verified_at = Some(120);
        let extra = CopyFixture { id: 4, failure_domain: 1, ..c[2] };
        c.push(extra);
        assert_eq!(assess(&c,120,20).unwrap().verdict,Verdict::FixtureCriteriaReported);
        let p = RestorePlan { copy: 4, ..p };
        let r = RestoreReceipt { copy: 4, ..r };
        assert_eq!(assess_linked_objectives(&c,p,Some(r),120,20),Ok(InventoryReviewRequired));
    }
    #[test] fn linked_restore_preserves_negative_checks() {
        use LinkedVerdict::*;
        let (p,r) = objective_fixture();
        let mut c = example();
        c[2].restore_verified_at = Some(120);
        assert_eq!(assess_linked_objectives(&c,p,None,120,20),
            Ok(Objectives(ObjectiveVerdict::MissingOrMismatchedEvidence)));
        assert_eq!(assess_linked_objectives(&c,p,Some(RestoreReceipt {
            recovery_point: 89, ..r }),120,20),Ok(Objectives(ObjectiveVerdict::ObjectivesMissed)));
        assert_eq!(assess_linked_objectives(&c,p,Some(r),141,20),Ok(InventoryReviewRequired));
        c[1].encrypted = Evidence::Unknown;
        assert_eq!(assess_linked_objectives(&c,p,Some(r),120,20),Ok(InventoryReviewRequired));
        c[1].id = c[0].id;
        assert_eq!(assess_linked_objectives(&c,p,None,120,20),Err(Error::InvalidInventory));
    }
    #[test] fn future_and_original_restore_rejected() {
        let mut c = example(); c[2].restore_verified_at = Some(101);
        assert_eq!(run(&c),Err(Error::FutureRestore));
        c = example(); c[0].restore_verified_at = Some(99);
        assert_eq!(run(&c),Err(Error::InvalidInventory));
        assert_eq!(assess(&example(),100,0),Err(Error::InvalidScope));
    }
}
