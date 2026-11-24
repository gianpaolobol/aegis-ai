#![forbid(unsafe_code)]
// Copyright 2026 Gian Paolo Franceschini. See LICENSE.
//! Pure policy classifier; not an authorization boundary.

pub mod wifi;
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Action { Read, Write, Export, Execute, ChangePolicy, Unknown }
#[derive(Debug, PartialEq, Eq)]
pub enum Decision { Deny, RequireApproval, Allow }
pub fn classify(action: Action, integrated: bool, scoped: bool) -> Decision {
    if !integrated || !scoped { return Decision::Deny; }
    match action {
        Action::Read => Decision::Allow,
        Action::Write | Action::Export => Decision::RequireApproval,
        Action::Execute | Action::ChangePolicy | Action::Unknown => Decision::Deny,
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    const ACTIONS: [Action;6] = [Action::Read, Action::Write, Action::Export, Action::Execute, Action::ChangePolicy, Action::Unknown];
    #[test] fn fail_closed() {
        for action in ACTIONS {
            for (integrated, scoped) in [(false,true),(true,false),(false,false)] {
                assert_eq!(classify(action, integrated, scoped), Decision::Deny);
            }
        }
    }
    #[test] fn sensitive_requires_approval() {
        for action in [Action::Write, Action::Export] {
            assert_eq!(classify(action, true, true), Decision::RequireApproval);
        }
    }
    #[test] fn read_only() { assert_eq!(classify(Action::Read,true,true), Decision::Allow); }
    #[test] fn privileged_and_unknown_denied() {
        for action in [Action::Execute,Action::ChangePolicy,Action::Unknown] {
            assert_eq!(classify(action,true,true),Decision::Deny);
        }
    }
}
