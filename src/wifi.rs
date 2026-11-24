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
