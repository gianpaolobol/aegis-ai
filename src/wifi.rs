// Copyright 2026 Gian Paolo Franceschini. See LICENSE.
//! Pure advisory classification of caller-supplied metadata.
//! No radio, credential, network, persistence or router access.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityMode {
    Open, Wep, Wpa, Wpa2Personal, Wpa2Enterprise, Wpa3Personal,
    Wpa3Enterprise, Wpa2Wpa3Transition, EnhancedOpen, Unknown,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reported { Yes, No, Unknown }
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pmf { Required, Optional, Disabled, Unknown }
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Metadata {
    pub security: SecurityMode,
    pub wps: Reported,
    pub pmf: Pmf,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Advisory {
    Unencrypted, LegacyProtocol, PreferWpa3IfSupported,
    TransitionMode, UnauthenticatedEncryptedNetwork,
    SecurityUnknown, DisableWps, WpsUnknown,
    PmfNotRequired, PmfUnknown, InconsistentWpa3Metadata,
}
/// Advisories are configuration observations, not password assessments.
/// An empty result does not establish that a network is safe.
pub fn assess(m: Metadata) -> Vec<Advisory> {
    use Advisory::*;
    use SecurityMode::*;
    let mut out = Vec::new();
    match m.security {
        Open => out.push(Unencrypted),
        Wep | Wpa => out.push(LegacyProtocol),
        Wpa2Personal => out.push(PreferWpa3IfSupported),
        Wpa2Wpa3Transition => out.push(TransitionMode),
        EnhancedOpen => out.push(UnauthenticatedEncryptedNetwork),
        Unknown => out.push(SecurityUnknown),
        Wpa2Enterprise | Wpa3Personal | Wpa3Enterprise => {}
    }
    match m.wps {
        Reported::Yes => out.push(DisableWps),
        Reported::Unknown => out.push(WpsUnknown),
        Reported::No => {}
    }
    match m.pmf {
        Pmf::Unknown => out.push(PmfUnknown),
        Pmf::Optional | Pmf::Disabled => {
            if matches!(m.security, Wpa3Personal | Wpa3Enterprise) {
                out.push(InconsistentWpa3Metadata);
            } else if matches!(m.security, Wpa2Personal | Wpa2Enterprise | Wpa2Wpa3Transition) {
                out.push(PmfNotRequired);
            }
        }
        Pmf::Required => {}
    }
    out
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Observation {
    PermissionDenied, Unavailable, Observed(Metadata),
}
#[derive(Debug, PartialEq, Eq)]
pub enum Audit {
    PermissionDenied, Unavailable, Advisory(Vec<Advisory>),
}
pub fn audit(observation: Observation) -> Audit {
    match observation {
        Observation::PermissionDenied => Audit::PermissionDenied,
        Observation::Unavailable => Audit::Unavailable,
        Observation::Observed(m) => Audit::Advisory(assess(m)),
    }
}
/// Compare a user-approved baseline with current reported metadata only.
/// Callers must separately establish scope; changes are not proof of an evil twin.
pub fn security_mode_changed(baseline: SecurityMode, current: SecurityMode) -> Option<bool> {
    if baseline == SecurityMode::Unknown || current == SecurityMode::Unknown {
        None
    } else {
        Some(baseline != current)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn meta(security: SecurityMode) -> Metadata {
        Metadata { security, wps: Reported::No, pmf: Pmf::Required }
    }
    #[test]
    fn legacy_and_open() {
        assert_eq!(assess(meta(SecurityMode::Open)), vec![Advisory::Unencrypted]);
        for mode in [SecurityMode::Wep, SecurityMode::Wpa] {
            assert_eq!(assess(meta(mode)), vec![Advisory::LegacyProtocol]);
        }
    }
    #[test]
    fn transition_is_not_pure_wpa3() {
        assert_eq!(assess(meta(SecurityMode::Wpa2Wpa3Transition)), vec![Advisory::TransitionMode]);
    }
    #[test]
    fn enhanced_open_is_not_authenticated() {
        assert_eq!(assess(meta(SecurityMode::EnhancedOpen)), vec![Advisory::UnauthenticatedEncryptedNetwork]);
    }
    #[test]
    fn wpa2_personal_and_enterprise_distinct() {
        assert_eq!(assess(meta(SecurityMode::Wpa2Personal)), vec![Advisory::PreferWpa3IfSupported]);
        assert!(assess(meta(SecurityMode::Wpa2Enterprise)).is_empty());
    }
    #[test]
    fn unknown_never_becomes_safe() {
        let m = Metadata { security: SecurityMode::Unknown, wps: Reported::Unknown, pmf: Pmf::Unknown };
        assert_eq!(assess(m), vec![Advisory::SecurityUnknown, Advisory::WpsUnknown, Advisory::PmfUnknown]);
    }
    #[test]
    fn inconsistent_wpa3_and_wps() {
        for security in [SecurityMode::Wpa3Personal, SecurityMode::Wpa3Enterprise] {
            for pmf in [Pmf::Optional, Pmf::Disabled] {
                let m = Metadata { security, wps: Reported::Yes, pmf };
                assert_eq!(assess(m), vec![Advisory::DisableWps, Advisory::InconsistentWpa3Metadata]);
            }
        }
    }
    #[test]
    fn pmf_optional_wpa2() {
        let m = Metadata { pmf: Pmf::Optional, ..meta(SecurityMode::Wpa2Personal) };
        assert!(assess(m).contains(&Advisory::PmfNotRequired));
    }
    #[test]
    fn permission_denial_is_not_a_pass() {
        assert_eq!(audit(Observation::PermissionDenied), Audit::PermissionDenied);
        assert_eq!(audit(Observation::Unavailable), Audit::Unavailable);
        assert_eq!(audit(Observation::Observed(meta(SecurityMode::Open))), Audit::Advisory(vec![Advisory::Unencrypted]));
    }
    #[test]
    fn change_is_only_an_observation() {
        use SecurityMode::*;
        assert_eq!(security_mode_changed(Wpa3Personal, Wpa2Personal), Some(true));
        assert_eq!(security_mode_changed(Wpa3Personal, Wpa3Personal), Some(false));
        assert_eq!(security_mode_changed(Unknown, Wpa3Personal), None);
        assert_eq!(security_mode_changed(Wpa3Personal, Unknown), None);
    }
}

// Baseline comparison uses fictional opaque scope IDs and synthetic clock ticks.
// No inference about SSID identity, authentication or actual network safety.
pub const BASELINE_MAX_AGE: u64 = 86_400;
pub const OBSERVATION_MAX_AGE: u64 = 30;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScopedObservation {
    pub scope: u64,
    pub at: u64,
    pub observation: Observation,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BaselineFixture {
    pub scope: u64,
    pub approved_at: u64,
    pub reviewed: bool,
    pub metadata: Metadata,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldChange { Same, Changed, Unknown }
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Comparison {
    InvalidBaseline, ScopeMismatch, StaleObservation, Unavailable,
    PermissionDenied,
    Compared { security: FieldChange, wps: FieldChange, pmf: FieldChange },
}
fn compare_field<T: PartialEq>(a: T, b: T, unknown: T) -> FieldChange {
    if a == unknown || b == unknown { FieldChange::Unknown }
    else if a == b { FieldChange::Same }
    else { FieldChange::Changed }
}
/// Pure advisory. The caller-supplied scope and approval labels are not
/// authenticated; production adapters require separately verified scope.
pub fn compare_baseline(b: BaselineFixture, o: ScopedObservation, now: u64) -> Comparison {
    if !b.reviewed || b.scope == 0 ||
        !now.checked_sub(b.approved_at).is_some_and(|age| age <= BASELINE_MAX_AGE) {
        return Comparison::InvalidBaseline;
    }
    if o.scope != b.scope { return Comparison::ScopeMismatch; }
    if o.at < b.approved_at ||
        !now.checked_sub(o.at).is_some_and(|age| age <= OBSERVATION_MAX_AGE) {
        return Comparison::StaleObservation;
    }
    match o.observation {
        Observation::Unavailable => Comparison::Unavailable,
        Observation::PermissionDenied => Comparison::PermissionDenied,
        Observation::Observed(m) => Comparison::Compared {
            security: compare_field(b.metadata.security, m.security, SecurityMode::Unknown),
            wps: compare_field(b.metadata.wps, m.wps, Reported::Unknown),
            pmf: compare_field(b.metadata.pmf, m.pmf, Pmf::Unknown),
        },
    }
}
#[cfg(test)]
mod baseline_tests {
    use super::*;
    fn baseline() -> BaselineFixture {
        BaselineFixture { scope: 1, approved_at: 100, reviewed: true,
            metadata: Metadata { security: SecurityMode::Wpa3Personal, wps: Reported::No, pmf: Pmf::Required } }
    }
    fn current() -> ScopedObservation {
        ScopedObservation { scope: 1, at: 120, observation: Observation::Observed(baseline().metadata) }
    }
    #[test]
    fn per_field_changes_and_unknowns() {
        use FieldChange::*;
        let b = baseline();
        assert_eq!(compare_baseline(b, current(), 125), Comparison::Compared { security: Same, wps: Same, pmf: Same });
        let m = Metadata { security: SecurityMode::Wpa2Personal, wps: Reported::Unknown, pmf: Pmf::Disabled };
        assert_eq!(compare_baseline(b, ScopedObservation { observation: Observation::Observed(m), ..current() }, 125),
            Comparison::Compared { security: Changed, wps: Unknown, pmf: Changed });
        let unknown = Metadata { security: SecurityMode::Unknown, wps: Reported::Unknown, pmf: Pmf::Unknown };
        assert_eq!(compare_baseline(BaselineFixture { metadata: unknown, ..b }, current(), 125),
            Comparison::Compared { security: Unknown, wps: Unknown, pmf: Unknown });
    }
    #[test]
    fn approval_scope_and_clock_boundaries() {
        let b = baseline();
        for invalid in [BaselineFixture { reviewed: false, ..b }, BaselineFixture { scope: 0, ..b },
            BaselineFixture { approved_at: 126, ..b }] {
            assert_eq!(compare_baseline(invalid, current(), 125), Comparison::InvalidBaseline);
        }
        for scope in [0, 2] {
            assert_eq!(compare_baseline(b, ScopedObservation { scope, ..current() }, 125), Comparison::ScopeMismatch);
        }
        for at in [94, 99, 126, u64::MAX] {
            assert_eq!(compare_baseline(b, ScopedObservation { at, ..current() }, 125), Comparison::StaleObservation);
        }
        assert_eq!(compare_baseline(b, current(), 151), Comparison::StaleObservation);
        assert!(matches!(compare_baseline(b, current(), 150), Comparison::Compared { .. }));
        let now = b.approved_at + BASELINE_MAX_AGE;
        assert!(matches!(compare_baseline(b, ScopedObservation { at: now, ..current() }, now), Comparison::Compared { .. }));
        assert_eq!(compare_baseline(b, ScopedObservation { at: now + 1, ..current() }, now + 1), Comparison::InvalidBaseline);
    }
    #[test]
    fn unavailable_and_permission_denial_remain_distinct() {
        for (observation, expected) in [(Observation::Unavailable, Comparison::Unavailable),
            (Observation::PermissionDenied, Comparison::PermissionDenied)] {
            assert_eq!(compare_baseline(baseline(), ScopedObservation { observation, ..current() }, 125), expected);
        }
    }
}
