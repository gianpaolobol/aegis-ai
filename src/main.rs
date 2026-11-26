#![forbid(unsafe_code)]
// Copyright 2026 Gian Paolo Franceschini. See LICENSE.
//! Read-only alpha demonstrator. No device access, enforcement or networking.
use aegis_policy::{classify, Action, Decision};
use aegis_policy::wifi::{audit, Audit, Metadata, Observation, Pmf, Reported, SecurityMode};
use std::ffi::{OsStr, OsString};

const HELP: &str = "AEGIS AI — alpha demonstrator (not validated)\nUsage: aegis-policy [status|demo-policy|demo-wifi|demo-incidents|demo-patches|demo-mail-auth|--help|--version]\nNo device access, network operations, antivirus or active protection.\n";
const STATUS: &str = "AEGIS AI — development alpha\nActive protection: unavailable\nPolicy: pure classifier, not enforcement\nWi-Fi: synthetic metadata only, no radio access\nNo system settings changed. Keep native protections enabled.\n";
fn run(args: &[OsString]) -> (i32, String) {
    if args.is_empty() { return (0, HELP.into()); }
    if args.len() != 1 { return (2, "Invalid arguments. Use --help.\n".into()); }
    let arg = args[0].as_os_str();
    if arg == OsStr::new("--help") { return (0, HELP.into()); }
    if arg == OsStr::new("--version") {
        return (0, format!("aegis-policy {} (development alpha)\n", env!("CARGO_PKG_VERSION")));
    }
    if arg == OsStr::new("status") { return (0, STATUS.into()); }
    if arg == OsStr::new("demo-policy") {
        let mut report = String::from("Synthetic policy examples; not enforcement.\n");
        for (label, action, integrated, scoped, expected) in [
            ("unscoped read", Action::Read, true, false, Decision::Deny),
            ("scoped read", Action::Read, true, true, Decision::Allow),
            ("scoped export", Action::Export, true, true, Decision::RequireApproval),
            ("policy change", Action::ChangePolicy, true, true, Decision::Deny),
        ] {
            let observed = classify(action, integrated, scoped);
            report.push_str(&format!("{label}: {observed:?}\n"));
            if observed != expected {
                report.push_str("Unexpected classifier result.\n");
                return (1, report);
            }
        }
        use aegis_policy::response::{plan, Proposal, Reservation, Role, Service, Snapshot, Verdict};
        let registry = [
            Service { id: 1, role: Role::Ordinary, impact: 2 },
            Service { id: 2, role: Role::Ordinary, impact: 3 },
            Service { id: 3, role: Role::Administration, impact: 1 },
            Service { id: 4, role: Role::Recovery, impact: 1 },
        ];
        let snapshot = Snapshot { policy_version: 1, observed_at: 90, now: 100,
            reviewed_fixture: true, recovery_available: true, administration_available: true, stopped: false };
        let proposal = Proposal { service: 1, policy_version: 1, expires: 120,
            reversible_in_fixture: true };
        let reservation = [Reservation { service: 2, expires: 110 }];
        report.push_str("Synthetic response dry-run; no containment or rollback performed.\n");
        for (label, observed, expected) in [
            ("bounded proposal", plan(&registry, 5, snapshot, &[], proposal), Verdict::DryRunCandidateOnly),
            ("aggregate impact", plan(&registry, 4, snapshot, &reservation, proposal), Verdict::ImpactBudgetExceeded),
            ("recovery channel", plan(&registry, 5, snapshot, &[], Proposal { service: 4, ..proposal }), Verdict::ProtectedService),
            ("expired unresolved reservation", plan(&registry, 5, snapshot, &[Reservation { service: 2, expires: 100 }], proposal), Verdict::RecoveryVerificationRequired),
            ("administration channel unavailable", plan(&registry, 5, Snapshot { administration_available: false, ..snapshot }, &[], proposal), Verdict::AdministrationUnavailable),
            ("kill switch", plan(&registry, 5, Snapshot { stopped: true, ..snapshot }, &[], proposal), Verdict::Stopped),
        ] {
            report.push_str(&format!("{label}: {observed:?}\n"));
            if observed != expected { return (1, report); }
        }
        return (0, report);
    }
    if arg == OsStr::new("demo-wifi") {
        let mut report = String::from("Synthetic Wi-Fi metadata; no scan or password assessment.\n");
        for (label, obs) in [
            ("fixture-open", Observation::Observed(Metadata { security: SecurityMode::Open, wps: Reported::Unknown, pmf: Pmf::Unknown })),
            ("fixture-wpa3", Observation::Observed(Metadata { security: SecurityMode::Wpa3Personal, wps: Reported::No, pmf: Pmf::Required })),
            ("fixture-permission", Observation::PermissionDenied),
        ] {
            match audit(obs) {
                Audit::Advisory(items) if items.is_empty() =>
                    report.push_str(&format!("{label}: no advisory from supplied metadata; safety not established\n")),
                other => report.push_str(&format!("{label}: {other:?}\n")),
            }
        }
        return (0, report);
    }
    if arg == OsStr::new("demo-incidents") {
        use aegis_policy::incident::{correlate, Event, Signal};
        let events = [
            Event { id: 1, asset: 1, seconds: 0, signal: Signal::IntegrityMismatch },
            Event { id: 2, asset: 1, seconds: 60, signal: Signal::PolicyDenied },
            Event { id: 3, asset: 2, seconds: 60, signal: Signal::NativeProtectionDisabled },
            Event { id: 4, asset: 3, seconds: 60, signal: Signal::Normal },
        ];
        match correlate(&events) {
            Ok(s) => return (0, format!("Synthetic incident correlation; not live telemetry or enforcement.\nEvents: {}\nAssets observed: {}\nAssets with advisories: {}\nAssets for review: {}\nNo attack probability or safety established.\n",
                s.event_count, s.assets_observed, s.assets_with_advisories, s.assets_for_review)),
            Err(_) => return (1, "Synthetic correlation unavailable.\n".into()),
        }
    }
    if arg == OsStr::new("demo-patches") {
        use aegis_policy::patch::{triage, Advisory, Applicability, Evidence, Finding, ProductBuild};
        let p = ProductBuild { product: 1, build: 1 };
        let other = ProductBuild { product: 1, build: 2 };
        let findings = [
            Finding { product: p, vulnerability: 1, applicability: Applicability::Affected },
            Finding { product: p, vulnerability: 2, applicability: Applicability::Affected },
            Finding { product: other, vulnerability: 1, applicability: Applicability::Affected },
        ];
        let reviewed = Evidence::ReviewedFixture;
        match triage(p, reviewed, reviewed, reviewed, &[1], &findings) {
            Ok(v) => {
                let priority = v.iter().filter(|a| **a == Advisory::PriorityReview).count();
                let unknown = v.iter().filter(|a| **a == Advisory::ApplicabilityUnknown).count();
                let review = v.iter().filter(|a| **a == Advisory::ReviewNotListedInFixture).count();
                return (0, format!("Synthetic patch priority; no real KEV catalog or CVE mapping.\nPriority review: {priority}\nOther review: {review}\nApplicability unknown: {unknown}\nNo patch installation or safety established.\n"));
            }
            Err(_) => return (1, "Synthetic patch priority unavailable.\n".into()),
        }
    }
    if arg == OsStr::new("demo-mail-auth") {
        use aegis_policy::mail_auth::{assess, Authentication, Dmarc, Fixture, Mechanism, Source};
        let f = Fixture { source: Source::ReviewedFixture, valid_single_author: true,
            spf: Mechanism::AlignedPass, dkim: Mechanism::NoPass, dmarc: Dmarc::Pass,
            payment_or_account_change: true };
        let mut report = String::from("Synthetic mail authentication advisory; no mail access, DNS or signature validation.\n");
        for (label, input, expected) in [
            ("aligned payment fixture", f, Authentication::DomainAlignmentReported),
            ("unaligned fixture", Fixture { spf: Mechanism::UnalignedPass, ..f }, Authentication::InconsistentEvidence),
            ("missing fixture", Fixture { spf: Mechanism::Unknown, ..f }, Authentication::IncompleteEvidence),
            ("untrusted fixture", Fixture { source: Source::Untrusted, ..f }, Authentication::UntrustedEvidence),
        ] {
            let result = assess(input);
            report.push_str(&format!("{label}: {:?}\n", result.authentication));
            if result.authentication != expected || !result.independent_confirmation_required {
                return (1, report);
            }
        }
        report.push_str("Payment/account changes require independent confirmation even with domain alignment. No sender identity or message safety established.\n");
        return (0, report);
    }
    (2, "Unknown command. Use --help.\n".into())
}
fn main() -> std::process::ExitCode {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let (code, report) = run(&args);
    if code == 0 { print!("{report}"); } else { eprint!("{report}"); }
    std::process::ExitCode::from(code as u8)
}
#[cfg(test)]
mod tests {
    use super::*;
    fn cmd(args: &[&str]) -> (i32, String) {
        run(&args.iter().map(|s| OsString::from(*s)).collect::<Vec<_>>())
    }
    #[test] fn default_help() { assert_eq!(cmd(&[]), (0, HELP.into())); }
    #[test] fn status_is_not_protection_claim() {
        let (code, output) = cmd(&["status"]);
        assert_eq!(code, 0);
        assert!(output.contains("Active protection: unavailable"));
    }
    #[test] fn unknown_command_rejected_without_echo() {
        let (code, output) = cmd(&["synthetic-secret"]);
        assert_eq!(code, 2);
        assert!(!output.contains("synthetic-secret"));
    }
    #[test] fn extra_arguments_rejected() { assert_eq!(cmd(&["status", "extra"]).0, 2); }
    #[test] fn policy_demo() {
        let (code, output) = cmd(&["demo-policy"]);
        assert_eq!(code, 0);
        assert!(output.contains("unscoped read: Deny"));
        assert!(output.contains("scoped export: RequireApproval"));
    }
    #[test] fn wifi_demo_never_claims_safe() {
        let (code, output) = cmd(&["demo-wifi"]);
        assert_eq!(code, 0);
        assert!(output.contains("PermissionDenied"));
        assert!(output.contains("safety not established"));
        assert!(output.contains("no scan"));
    }
    #[test] fn version_reports_alpha() {
        let (code, output) = cmd(&["--version"]);
        assert_eq!(code, 0);
        assert!(output.contains("development alpha"));
    }
}
