// Copyright 2026 Gian Paolo Franceschini. See LICENSE.
//! Synthetic multi-grant session accounting. No authentication, durable state,
//! credential access, tool execution, or production authorization.
use crate::gateway_fixture::{Approval, Binding, Control, Grant, Id, Ledger, Verdict, MAX_BUDGET};
use std::collections::{BTreeMap, BTreeSet};

pub const MAX_GRANTS: usize = 16;

/// One trusted fixture session, one principal and one immutable policy version.
/// The control channel is harness-owned. Revocation and stop are session-wide.
/// A process restart loses state; this is not a persistent replay boundary.
#[derive(Debug)]
pub struct Session {
    principal: Id,
    session: Id,
    policy_version: u64,
    grants: BTreeMap<Id, Ledger>,
    seen: BTreeSet<Id>,
    remaining: u16,
    last_time: u64,
    stopped: bool,
    revoked: bool,
    invalidated: bool,
}
impl Session {
    pub fn new(grants: &[(Grant, u16)], budget: u16) -> Result<Self, Verdict> {
        if grants.is_empty() || grants.len() > MAX_GRANTS || budget == 0 || budget > MAX_BUDGET {
            return Err(Verdict::Invalid);
        }
        let first = grants[0].0;
        let mut ledgers = BTreeMap::new();
        for &(g, local_budget) in grants {
            if (g.principal, g.session, g.policy_version) !=
                (first.principal, first.session, first.policy_version) || ledgers.contains_key(&g.id) {
                return Err(Verdict::Invalid);
            }
            ledgers.insert(g.id, Ledger::new(g, local_budget)?);
        }
        Ok(Self { principal: first.principal, session: first.session,
            policy_version: first.policy_version, grants: ledgers, seen: BTreeSet::new(),
            remaining: budget, last_time: 0, stopped: false, revoked: false, invalidated: false })
    }
    pub fn remaining(&self) -> u16 { self.remaining }
    /// All control observations latch before request validation, including those
    /// arriving alongside an unknown grant. Only a positive fixture decision
    /// spends either budget and reserves a session-wide transaction ID.
    pub fn evaluate(&mut self, grant: Id, req: Binding, ctl: Control, approval: Option<Approval>) -> Verdict {
        use Verdict::*;
        self.stopped |= ctl.stopped;
        self.revoked |= ctl.revoked;
        self.invalidated |= ctl.policy_version != self.policy_version;
        let regressed = ctl.now < self.last_time;
        self.last_time = self.last_time.max(ctl.now);
        if self.stopped { return Stopped; }
        if self.revoked { return Revoked; }
        if self.invalidated { return StalePolicy; }
        if regressed { return ClockRegression; }
        if (req.principal, req.session) != (self.principal, self.session) { return ScopeMismatch; }
        if req.policy_version != self.policy_version { return StalePolicy; }
        let Some(ledger) = self.grants.get_mut(&grant) else { return ScopeMismatch; };
        if self.seen.contains(&req.transaction) { return Replay; }
        if self.remaining == 0 { return BudgetExhausted; }
        let result = ledger.evaluate(req, ctl, approval);
        if result == AcceptedFixtureOnly {
            self.seen.insert(req.transaction);
            self.remaining -= 1;
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Action;
    fn id(n: u8) -> Id { [n; 32] }
    fn grant(n: u8, action: Action) -> Grant {
        Grant { id: id(n), principal: id(1), session: id(2), resource: id(n+20),
            action, policy_version: 1, issued_at: 10, expires_at: 100 }
    }
    fn binding(g: Grant, tx: u8) -> Binding {
        Binding { principal: g.principal, session: g.session, resource: g.resource,
            action: g.action, payload_digest: id(90), transaction: id(tx), policy_version: g.policy_version }
    }
    fn ctl(now: u64) -> Control { Control { policy_version: 1, stopped: false, revoked: false, now } }
    #[test]
    fn cross_grant_replay_and_shared_budget() {
        let a = grant(3, Action::Read);
        let b = grant(4, Action::Read);
        let mut s = Session::new(&[(a, 3), (b, 3)], 2).unwrap();
        assert_eq!(s.evaluate(a.id, binding(a, 5), ctl(20), None), Verdict::AcceptedFixtureOnly);
        assert_eq!(s.evaluate(b.id, binding(b, 5), ctl(21), None), Verdict::Replay);
        assert_eq!(s.remaining(), 1);
        assert_eq!(s.evaluate(b.id, binding(b, 6), ctl(21), None), Verdict::AcceptedFixtureOnly);
        assert_eq!(s.evaluate(a.id, binding(a, 7), ctl(22), None), Verdict::BudgetExhausted);
        assert_eq!(s.remaining(), 0);
    }
    #[test]
    fn local_budget_and_sensitive_binding_are_preserved() {
        let a = grant(3, Action::Read);
        let b = grant(4, Action::Export);
        let mut s = Session::new(&[(a, 1), (b, 2)], 3).unwrap();
        let req = binding(b, 5);
        let approval = Approval { binding: req, grant_id: b.id, reviewer: id(8), issued_at: 11, expires_at: 40 };
        assert_eq!(s.evaluate(b.id, req, ctl(20), None), Verdict::ApprovalRequired);
        assert_eq!(s.evaluate(b.id, req, ctl(20), Some(Approval { grant_id: a.id, ..approval })), Verdict::ApprovalMismatch);
        assert_eq!(s.remaining(), 3);
        assert_eq!(s.evaluate(b.id, req, ctl(20), Some(approval)), Verdict::AcceptedFixtureOnly);
        assert_eq!(s.evaluate(a.id, binding(a, 6), ctl(20), None), Verdict::AcceptedFixtureOnly);
        assert_eq!(s.evaluate(a.id, binding(a, 7), ctl(20), None), Verdict::BudgetExhausted);
        assert_eq!(s.remaining(), 1);
        let next = binding(b, 7);
        assert_eq!(s.evaluate(b.id, next, ctl(20), Some(Approval { binding: next, ..approval })), Verdict::AcceptedFixtureOnly);
    }
    #[test]
    fn control_latches_across_grants_and_unknown_grant() {
        let a = grant(3, Action::Read);
        let b = grant(4, Action::Read);
        for (control, expected) in [
            (Control { stopped: true, ..ctl(19) }, Verdict::Stopped),
            (Control { revoked: true, ..ctl(19) }, Verdict::Revoked),
            (Control { policy_version: 2, ..ctl(19) }, Verdict::StalePolicy),
        ] {
            let mut s = Session::new(&[(a, 2), (b, 2)], 3).unwrap();
            assert_eq!(s.evaluate(a.id, binding(a, 5), ctl(20), None), Verdict::AcceptedFixtureOnly);
            assert_eq!(s.evaluate(id(99), binding(a, 6), control, None), expected);
            assert_eq!(s.evaluate(b.id, binding(b, 6), ctl(21), None), expected);
            assert_eq!(s.remaining(), 2);
        }
    }
    #[test]
    fn rejected_attempt_advances_shared_clock_without_spending() {
        let a = grant(3, Action::Read);
        let b = grant(4, Action::Read);
        let mut s = Session::new(&[(a, 2), (b, 2)], 3).unwrap();
        assert_eq!(s.evaluate(id(99), binding(a, 5), ctl(30), None), Verdict::ScopeMismatch);
        assert_eq!(s.evaluate(b.id, binding(b, 5), ctl(29), None), Verdict::ClockRegression);
        assert_eq!(s.remaining(), 3);
        assert_eq!(s.evaluate(b.id, binding(b, 5), ctl(30), None), Verdict::AcceptedFixtureOnly);
    }
    #[test]
    fn constructor_and_scope_fail_closed() {
        let a = grant(3, Action::Read);
        for invalid in [
            a, Grant { id: id(4), principal: id(9), ..a },
            Grant { id: id(4), session: id(9), ..a },
            Grant { id: id(4), policy_version: 2, ..a },
        ] { assert_eq!(Session::new(&[(a, 1), (invalid, 1)], 2).unwrap_err(), Verdict::Invalid); }
        assert_eq!(Session::new(&[], 1).unwrap_err(), Verdict::Invalid);
        assert_eq!(Session::new(&[(a, 1); MAX_GRANTS+1], 1).unwrap_err(), Verdict::Invalid);
        assert_eq!(Session::new(&[(a, 1)], 0).unwrap_err(), Verdict::Invalid);
        assert_eq!(Session::new(&[(a, 1)], MAX_BUDGET+1).unwrap_err(), Verdict::Invalid);
        assert_eq!(Session::new(&[(a, 0)], 1).unwrap_err(), Verdict::Invalid);
        assert_eq!(Session::new(&[(grant(4, Action::Execute), 1)], 1).unwrap_err(), Verdict::Forbidden);
        let mut s = Session::new(&[(a, 1)], 1).unwrap();
        for req in [Binding { session: id(9), ..binding(a, 5) }, Binding { principal: id(9), ..binding(a, 5) }] {
            assert_eq!(s.evaluate(a.id, req, ctl(20), None), Verdict::ScopeMismatch);
        }
        assert_eq!(s.remaining(), 1);
    }
}
