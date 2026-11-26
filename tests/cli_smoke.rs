#![forbid(unsafe_code)]
// Copyright 2026 Gian Paolo Franceschini. See LICENSE.
//! Process-level smoke tests for the read-only alpha; synthetic arguments only.
use std::process::{Command, Output};

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_aegis-policy"))
        .args(args)
        .output()
        .expect("launch alpha executable")
}
fn stdout(output: &Output) -> &str {
    std::str::from_utf8(&output.stdout).expect("UTF-8 stdout")
}
fn stderr(output: &Output) -> &str {
    std::str::from_utf8(&output.stderr).expect("UTF-8 stderr")
}
#[test]
fn help_and_default_exit_successfully() {
    for args in [&[][..], &["--help"][..]] {
        let output = run(args);
        assert_eq!(output.status.code(), Some(0));
        assert!(stdout(&output).contains("not validated"));
        assert!(stdout(&output).contains("No device access"));
        assert!(output.stderr.is_empty());
    }
}
#[test]
fn status_and_version_disclose_limitations() {
    let status = run(&["status"]);
    assert_eq!(status.status.code(), Some(0));
    assert!(stdout(&status).contains("Active protection: unavailable"));
    assert!(stdout(&status).contains("not enforcement"));
    assert!(status.stderr.is_empty());
    let version = run(&["--version"]);
    assert_eq!(version.status.code(), Some(0));
    assert!(stdout(&version).contains(env!("CARGO_PKG_VERSION")));
    assert!(stdout(&version).contains("development alpha"));
    assert!(version.stderr.is_empty());
}
#[test]
fn synthetic_demos_have_expected_results() {
    let policy = run(&["demo-policy"]);
    assert_eq!(policy.status.code(), Some(0));
    for expected in ["unscoped read: Deny", "scoped read: Allow",
                     "scoped export: RequireApproval", "policy change: Deny",
                     "no containment or rollback performed", "bounded proposal: DryRunCandidateOnly",
                     "aggregate impact: ImpactBudgetExceeded", "recovery channel: ProtectedService",
                     "expired unresolved reservation: RecoveryVerificationRequired",
                     "administration channel unavailable: AdministrationUnavailable",
                     "kill switch: Stopped", "no credential access or authentication",
                     "no tool action or actual authorization", "missing approval: ApprovalRequired",
                     "bound approval: AcceptedFixtureOnly", "duplicate transaction: Replay",
                     "revocation: Revoked", "revocation remains latched: Revoked",
                     "Workload fixture: criteria reported, not verified",
                     "Revoked fixture: Revoked, Expired",
                     "Unknown scope: ScopeReview, RevocationUnknown"] {
        assert!(stdout(&policy).contains(expected));
    }
    assert!(policy.stderr.is_empty());
    let wifi = run(&["demo-wifi"]);
    assert_eq!(wifi.status.code(), Some(0));
    assert!(stdout(&wifi).contains("PermissionDenied"));
    assert!(stdout(&wifi).contains("safety not established"));
    assert!(stdout(&wifi).contains("no scan"));
    assert!(wifi.stderr.is_empty());
}
#[test]
fn invalid_invocations_fail_without_echoing_input() {
    for args in [&["fixture-secret"][..], &["status", "fixture-secret"][..],
                 &["--help", "fixture-secret"][..], &[""][..]] {
        let output = run(args);
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
        assert!(stderr(&output).contains("Use --help."));
        assert!(!stderr(&output).contains("fixture-secret"));
    }
}

#[test]
fn incident_demo_reports_counts_and_limitations() {
    let output = run(&["demo-incidents"]);
    assert_eq!(output.status.code(), Some(0));
    for expected in ["Events: 4", "Assets observed: 3", "Assets with advisories: 2",
                     "Assets for review: 1", "not live telemetry or enforcement",
                     "No attack probability or safety established",
                     "Fixture asset 1: event 1 (IntegrityMismatch) + event 2 (PolicyDenied), 60 seconds apart.",
                     "Correlation explanation only; no causal attribution."] {
        assert!(stdout(&output).contains(expected));
    }
    assert!(output.stderr.is_empty());
    let invalid = run(&["demo-incidents", "synthetic-secret"]);
    assert_eq!(invalid.status.code(), Some(2));
    assert!(invalid.stdout.is_empty());
    assert!(!stderr(&invalid).contains("synthetic-secret"));
}

#[test]
fn patch_demo_is_advisory_and_denies_extra_arguments() {
    let output = run(&["demo-patches"]);
    assert_eq!(output.status.code(), Some(0));
    for expected in ["no real KEV catalog or CVE mapping", "Priority review: 1",
        "Other review: 1", "Applicability unknown: 1", "No patch installation or safety established"] {
        assert!(stdout(&output).contains(expected));
    }
    assert!(output.stderr.is_empty());
    let invalid = run(&["demo-patches", "synthetic-secret"]);
    assert_eq!(invalid.status.code(), Some(2));
    assert!(invalid.stdout.is_empty());
    assert!(!stderr(&invalid).contains("synthetic-secret"));
}

#[test]
fn mail_auth_demo_is_advisory_and_rejects_extra_arguments() {
    let output = run(&["demo-mail-auth"]);
    assert_eq!(output.status.code(), Some(0));
    for expected in ["no mail access, DNS or signature validation",
        "aligned payment fixture: DomainAlignmentReported",
        "unaligned fixture: InconsistentEvidence", "missing fixture: IncompleteEvidence",
        "untrusted fixture: UntrustedEvidence", "require independent confirmation",
        "No sender identity or message safety established",
        "independent confirmation fixture: FixtureConfirmationReported",
        "missing confirmation fixture: Missing",
        "request-supplied channel fixture: NonIndependentChannel",
        "changed destination fixture: DifferentTransaction",
        "expired confirmation fixture: StaleOrInvalidTime",
        "no payment authorization or contact verification"] {
        assert!(stdout(&output).contains(expected));
    }
    assert!(output.stderr.is_empty());
    let invalid = run(&["demo-mail-auth", "synthetic-secret"]);
    assert_eq!(invalid.status.code(), Some(2));
    assert!(invalid.stdout.is_empty());
    assert!(!stderr(&invalid).contains("synthetic-secret"));
}

#[test]
fn recovery_demo_is_advisory_and_rejects_extra_arguments() {
    let output = run(&["demo-recovery"]);
    assert_eq!(output.status.code(), Some(0));
    for expected in ["Copies: 3", "Failure domains: 3", "Known media: 2",
        "Complete fixture: FixtureCriteriaReported", "Missing isolated restore: ReviewRequired",
        "no backup inspection or restore performed", "Recovery capability not established"] {
        assert!(stdout(&output).contains(expected));
    }
    assert!(output.stderr.is_empty());
    let invalid = run(&["demo-recovery", "synthetic-secret"]);
    assert_eq!(invalid.status.code(), Some(2));
    assert!(invalid.stdout.is_empty());
    assert!(!stderr(&invalid).contains("synthetic-secret"));
}
