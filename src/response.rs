// Copyright 2026 Gian Paolo Franceschini. See LICENSE.
//! Anti-Self-DoS dry-run planning over bounded synthetic service metadata.
//! No system access, execution, authorization, persistence or rollback.

use std::collections::{BTreeMap, BTreeSet};

pub const MAX_SERVICES: usize = 128;
pub const MAX_TTL: u64 = 300;
pub const MAX_IMPACT: u32 = 1000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role { Ordinary, Administration, Recovery, Critical }

#[derive(Clone, Copy, Debug)]
pub struct Service { pub id: u16, pub role: Role, pub impact: u32 }

#[derive(Clone, Copy, Debug)]
pub struct Reservation { pub service: u16, pub expires: u64 }

#[derive(Clone, Copy, Debug)]
pub struct Snapshot {
    pub policy_version: u64,
    pub observed_at: u64,
    pub now: u64,
    pub reviewed_fixture: bool,
    pub recovery_available: bool,
    pub administration_available: bool,
    pub stopped: bool,
}

#[derive(Clone, Copy, Debug)]
pub struct Proposal {
    pub service: u16,
    pub policy_version: u64,
    pub expires: u64,
    pub reversible_in_fixture: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    InvalidPolicy, InvalidSnapshot, Stopped, RecoveryUnavailable, AdministrationUnavailable, StalePolicy,
    InvalidProposal, ProtectedService, UnknownService, AlreadyReserved,
    ImpactBudgetExceeded, RecoveryVerificationRequired, DryRunCandidateOnly,
}

/// The registry and budget are separate from the proposal. Impact units are
/// synthetic configured costs, not measurements of actual service availability.
/// The snapshot lists all unresolved reservations, including expired ones.
/// Expiry is not proof of recovery. An expired unresolved reservation blocks
/// new candidates until an independently reconciled snapshot is available.
/// This pure fixture cannot authenticate reconciliation or prove rollback.
pub fn plan(registry: &[Service], budget: u32, snapshot: Snapshot,
    active: &[Reservation], proposal: Proposal) -> Verdict {
    use Verdict::*;
    if registry.is_empty() || registry.len() > MAX_SERVICES ||
        budget == 0 || budget > MAX_IMPACT || snapshot.policy_version == 0 {
        return InvalidPolicy;
    }
    let mut services = BTreeMap::new();
    for &s in registry {
        if s.id == 0 || s.impact == 0 || s.impact > MAX_IMPACT ||
            services.insert(s.id, s).is_some() { return InvalidPolicy; }
    }
    if !registry.iter().any(|s| s.role == Role::Administration) ||
        !registry.iter().any(|s| s.role == Role::Recovery) {
        return InvalidPolicy;
    }
    if snapshot.stopped { return Stopped; }
    if !snapshot.reviewed_fixture ||
        !snapshot.now.checked_sub(snapshot.observed_at).is_some_and(|age| age <= 30) ||
        active.len() > MAX_SERVICES {
        return InvalidSnapshot;
    }
    if !snapshot.recovery_available { return RecoveryUnavailable; }
    if !snapshot.administration_available { return AdministrationUnavailable; }
    if proposal.policy_version != snapshot.policy_version { return StalePolicy; }
    if !proposal.reversible_in_fixture ||
        !proposal.expires.checked_sub(snapshot.now).is_some_and(|ttl| ttl > 0 && ttl <= MAX_TTL) {
        return InvalidProposal;
    }
    let Some(target) = services.get(&proposal.service) else { return UnknownService; };
    if target.role != Role::Ordinary { return ProtectedService; }

    let mut seen = BTreeSet::new();
    let mut used = 0u32;
    let mut unresolved_expiry = false;
    for reservation in active {
        let Some(s) = services.get(&reservation.service) else { return InvalidSnapshot; };
        if s.role != Role::Ordinary || !seen.insert(s.id) ||
            reservation.expires == 0 ||
            reservation.expires.saturating_sub(snapshot.now) > MAX_TTL {
            return InvalidSnapshot;
        }
        // Never release the impact reservation merely because its TTL elapsed.
        // At most 128 * 1000, bounded well below u32::MAX.
        used += s.impact;
        unresolved_expiry |= reservation.expires <= snapshot.now;
    }
    if unresolved_expiry { return RecoveryVerificationRequired; }
    if active.iter().any(|r| r.service == target.id) {
        return AlreadyReserved;
    }
    if used + target.impact > budget { return ImpactBudgetExceeded; }
    DryRunCandidateOnly
}

#[cfg(test)]
mod tests {
    use super::*;
    const SERVICES: [Service; 5] = [
        Service { id: 1, role: Role::Ordinary, impact: 2 },
        Service { id: 2, role: Role::Ordinary, impact: 3 },
        Service { id: 3, role: Role::Administration, impact: 1 },
        Service { id: 4, role: Role::Recovery, impact: 1 },
        Service { id: 5, role: Role::Critical, impact: 1 },
    ];
    fn snapshot() -> Snapshot {
        Snapshot { policy_version: 1, observed_at: 90, now: 100,
            reviewed_fixture: true, recovery_available: true, administration_available: true, stopped: false }
    }
    fn proposal(service: u16) -> Proposal {
        Proposal { service, policy_version: 1, expires: 120, reversible_in_fixture: true }
    }
    #[test]
    fn candidate_is_dry_run_and_budget_boundary() {
        assert_eq!(plan(&SERVICES, 2, snapshot(), &[], proposal(1)), Verdict::DryRunCandidateOnly);
        assert_eq!(plan(&SERVICES, 1, snapshot(), &[], proposal(1)), Verdict::ImpactBudgetExceeded);
    }
    #[test]
    fn protected_and_unknown_targets() {
        for id in [3, 4, 5] {
            assert_eq!(plan(&SERVICES, 10, snapshot(), &[], proposal(id)), Verdict::ProtectedService);
        }
        assert_eq!(plan(&SERVICES, 10, snapshot(), &[], proposal(99)), Verdict::UnknownService);
    }
    #[test]
    fn aggregate_budget_and_duplicate_target() {
        let active = [Reservation { service: 2, expires: 101 }];
        assert_eq!(plan(&SERVICES, 4, snapshot(), &active, proposal(1)), Verdict::ImpactBudgetExceeded);
        assert_eq!(plan(&SERVICES, 5, snapshot(), &active, proposal(1)), Verdict::DryRunCandidateOnly);
        assert_eq!(plan(&SERVICES, 5, snapshot(), &active, proposal(2)), Verdict::AlreadyReserved);
    }
    #[test]
    fn unresolved_expiry_blocks_new_and_repeat_candidates() {
        for expires in [99, 100] {
            let active = [Reservation { service: 2, expires }];
            for target in [1, 2] {
                assert_eq!(plan(&SERVICES, 10, snapshot(), &active, proposal(target)),
                    Verdict::RecoveryVerificationRequired);
            }
        }
        // A later, independently reconciled fixture can be evaluated again.
        // An empty list itself is not evidence of real-world rollback.
        assert_eq!(plan(&SERVICES, 10, snapshot(), &[], proposal(1)), Verdict::DryRunCandidateOnly);
    }
    #[test]
    fn expired_records_do_not_hide_malformed_snapshot() {
        let expired = Reservation { service: 2, expires: 99 };
        let unknown = Reservation { service: 99, expires: 110 };
        for active in [[expired, unknown], [unknown, expired]] {
            assert_eq!(plan(&SERVICES, 10, snapshot(), &active, proposal(1)), Verdict::InvalidSnapshot);
        }
        assert_eq!(plan(&SERVICES, 10, snapshot(), &[expired, expired], proposal(1)), Verdict::InvalidSnapshot);
    }
    #[test]
    fn kill_switch_and_recovery() {
        assert_eq!(plan(&SERVICES, 5, Snapshot { stopped: true, ..snapshot() }, &[], proposal(1)), Verdict::Stopped);
        assert_eq!(plan(&SERVICES, 5, Snapshot { recovery_available: false, ..snapshot() }, &[], proposal(1)), Verdict::RecoveryUnavailable);
    }
    #[test]
    fn administration_channel_is_independent() {
        assert_eq!(plan(&SERVICES, 5, Snapshot { administration_available: false, ..snapshot() }, &[], proposal(1)),
            Verdict::AdministrationUnavailable);
        assert_eq!(plan(&SERVICES, 5, Snapshot { stopped: true, administration_available: false, ..snapshot() }, &[], proposal(1)),
            Verdict::Stopped);
    }
    #[test]
    fn stale_missing_or_future_snapshot_and_policy() {
        for s in [Snapshot { reviewed_fixture: false, ..snapshot() },
            Snapshot { observed_at: 69, ..snapshot() },
            Snapshot { observed_at: 101, ..snapshot() }] {
            assert_eq!(plan(&SERVICES, 5, s, &[], proposal(1)), Verdict::InvalidSnapshot);
        }
        assert_eq!(plan(&SERVICES, 5, snapshot(), &[], Proposal { policy_version: 2, ..proposal(1) }), Verdict::StalePolicy);
    }
    #[test]
    fn invalid_expiry_or_irreversible() {
        for p in [Proposal { expires: 100, ..proposal(1) },
            Proposal { expires: 401, ..proposal(1) },
            Proposal { reversible_in_fixture: false, ..proposal(1) }] {
            assert_eq!(plan(&SERVICES, 5, snapshot(), &[], p), Verdict::InvalidProposal);
        }
    }
    #[test]
    fn malformed_registry_or_active_snapshot() {
        assert_eq!(plan(&SERVICES[..3], 5, snapshot(), &[], proposal(1)), Verdict::InvalidPolicy);
        let mut registry = SERVICES.to_vec();
        registry.push(SERVICES[0]);
        assert_eq!(plan(&registry, 5, snapshot(), &[], proposal(1)), Verdict::InvalidPolicy);
        for active in [vec![Reservation { service: 99, expires: 120 }],
            vec![Reservation { service: 4, expires: 120 }],
            vec![Reservation { service: 2, expires: 120 }; 2],
            vec![Reservation { service: 2, expires: 401 }],
            vec![Reservation { service: 2, expires: 0 }],
            vec![Reservation { service: 2, expires: 120 }; MAX_SERVICES + 1]] {
            assert_eq!(plan(&SERVICES, 5, snapshot(), &active, proposal(1)), Verdict::InvalidSnapshot);
        }
    }
}
