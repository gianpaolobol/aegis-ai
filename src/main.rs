#![forbid(unsafe_code)]
// Copyright 2026 Gian Paolo Franceschini. See LICENSE.
//! Read-only alpha demonstrator. No device access, enforcement or networking.
use aegis_policy::{classify, Action, Decision};
use aegis_policy::wifi::{audit, Audit, Metadata, Observation, Pmf, Reported, SecurityMode};
use std::ffi::{OsStr, OsString};

const HELP: &str = "AEGIS AI — alpha demonstrator (not validated)\nUsage: aegis-policy [status|demo-policy|demo-wifi|demo-incidents|demo-patches|demo-mail-auth|demo-recovery|--help|--version]\nNo device access, network operations, antivirus or active protection.\n";
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
        // Expose the existing bounded transaction fixture, not an enforcement interface.
        {
            use aegis_policy::gateway_fixture::{Approval, Binding, Control, Grant, Ledger, Verdict};
            let g = Grant { id: [1;32], principal: [2;32], session: [3;32], resource: [4;32],
                action: Action::Export, policy_version: 1, issued_at: 10, expires_at: 100 };
            let b = Binding { principal: g.principal, session: g.session, resource: g.resource,
                action: g.action, payload_digest: [5;32], transaction: [6;32], policy_version: 1 };
            let a = Approval { binding: b, grant_id: g.id, reviewer: [7;32], issued_at: 11, expires_at: 50 };
            let c = Control { policy_version: 1, stopped: false, revoked: false, now: 20 };
            let Ok(mut ledger) = Ledger::new(g, 2) else { return (1, report); };
            report.push_str("Synthetic transaction ledger; no tool action or actual authorization.\n");
            for (label, observed, expected) in [
                ("missing approval", ledger.evaluate(b,c,None), Verdict::ApprovalRequired),
                ("bound approval", ledger.evaluate(b,c,Some(a)), Verdict::AcceptedFixtureOnly),
                ("duplicate transaction", ledger.evaluate(b,c,Some(a)), Verdict::Replay),
                ("revocation", ledger.evaluate(b,Control { revoked: true, ..c },None), Verdict::Revoked),
                ("revocation remains latched", ledger.evaluate(b,Control { now: 21, ..c },Some(a)), Verdict::Revoked),
            ] {
                report.push_str(&format!("{label}: {observed:?}\n"));
                if observed != expected { return (1, report); }
            }
            if ledger.remaining() != 1 { return (1, report); }
        }
        {
            use aegis_policy::gateway_fixture::{Binding, Control, Grant, Verdict};
            use aegis_policy::gateway_session::Session;
            let a = Grant { id: [1;32], principal: [2;32], session: [3;32], resource: [4;32],
                action: Action::Read, policy_version: 1, issued_at: 10, expires_at: 100 };
            let b = Grant { id: [8;32], resource: [9;32], ..a };
            let x = Binding { principal: a.principal, session: a.session, resource: a.resource,
                action: a.action, payload_digest: [5;32], transaction: [6;32], policy_version: 1 };
            let y = Binding { resource: b.resource, ..x };
            let c = Control { policy_version: 1, stopped: false, revoked: false, now: 20 };
            let Ok(mut s) = Session::new(&[(a, 2), (b, 2)], 2) else { return (1, report); };
            report.push_str("Synthetic shared session budget; no real authorization.\n");
            for (label, observed, expected) in [
                ("session first grant", s.evaluate(a.id,x,c,None), Verdict::AcceptedFixtureOnly),
                ("session cross-grant replay", s.evaluate(b.id,y,c,None), Verdict::Replay),
                ("session second grant", s.evaluate(b.id,Binding { transaction: [7;32], ..y },c,None), Verdict::AcceptedFixtureOnly),
                ("session shared budget", s.evaluate(a.id,Binding { transaction: [10;32], ..x },c,None), Verdict::BudgetExhausted),
                ("session stop", s.evaluate(a.id,x,Control { stopped: true, ..c },None), Verdict::Stopped),
                ("session stop across grants", s.evaluate(b.id,y,c,None), Verdict::Stopped),
            ] {
                report.push_str(&format!("{label}: {observed:?}\n"));
                if observed != expected { return (1, report); }
            }
            if s.remaining() != 0 { return (1, report); }
        }
        use aegis_policy::response::{plan, plan_batch, BatchVerdict, Proposal, Reservation, Role, Service, Snapshot, Verdict};
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
        let batch = [proposal, Proposal { service: 2, ..proposal }];
        for (label, observed, expected) in [
            ("response batch within budget", plan_batch(&registry, 5, snapshot, &[], &batch),
                BatchVerdict::DryRunBatchCandidateOnly),
            ("response batch over budget", plan_batch(&registry, 4, snapshot, &[], &batch),
                BatchVerdict::Rejected { service: 2, reason: Verdict::ImpactBudgetExceeded }),
        ] {
            report.push_str(&format!("{label}: {observed:?}\n"));
            if observed != expected { return (1, report); }
        }
        use aegis_policy::nhi::{assess, Advisory, Identity, Limits, Reported, Revocation};
        let identity = Identity { id: 1, owner_assigned: Reported::Yes, scoped: Reported::Yes,
            reviewed_fixture: true, observed_at: 95, issued_at: Some(90), expires_at: Some(120),
            revocation: Revocation::NotRevoked };
        let identities = [identity, Identity { id: 2, expires_at: Some(100),
            revocation: Revocation::Revoked, ..identity }, Identity { id: 3,
            scoped: Reported::Unknown, revocation: Revocation::Unknown, ..identity }];
        report.push_str("Synthetic workload identity inventory; no credential access or authentication.\n");
        match assess(&identities, 100, Limits { max_observation_age: 10, max_lifetime: 30 }) {
            Ok(v) if v == vec![vec![Advisory::FixtureCriteriaReported],
                vec![Advisory::Revoked, Advisory::Expired],
                vec![Advisory::ScopeReview, Advisory::RevocationUnknown]] => {
                report.push_str("Workload fixture: criteria reported, not verified.\nRevoked fixture: Revoked, Expired\nUnknown scope: ScopeReview, RevocationUnknown\n");
            }
            _ => return (1, "Synthetic workload identity assessment unavailable.\n".into()),
        }
        use aegis_policy::nhi::{assess_coverage, CoverageStatus};
        let limits = Limits { max_observation_age: 10, max_lifetime: 30 };
        match assess_coverage(&[1, 2], &[identity], 100, limits) {
            Ok(r) if !r.all_fixture_criteria_reported &&
                r.rows.len() == 2 && r.rows[1].id == 2 &&
                r.rows[1].status == CoverageStatus::MissingObservation =>
                report.push_str("Required identity coverage: fixture 2 missing; criteria incomplete.\n"),
            _ => return (1, report),
        }
        match assess_coverage(&[1], &[identity], 100, limits) {
            Ok(r) if r.all_fixture_criteria_reported =>
                report.push_str("Required identity coverage: all fixture criteria reported, not verified.\n"),
            _ => return (1, report),
        }
        use aegis_policy::nhi::{assess_rotation, Rotation, RotationReview};
        let rotation = Rotation { workload: 1, previous: 2, successor: 3, issued: 80,
            successor_check: Some(85), previous_revocation: Some(90), observed: 95,
            reviewed_fixture: true, successor_scoped: Reported::Yes, previous_revoked: Revocation::Revoked };
        report.push_str("Synthetic rotation evidence; no credential rotation or revocation performed.\n");
        for (label, observed, expected) in [
            ("rotation handoff", assess_rotation(rotation,100,10,10), RotationReview::FixtureReviewOnly),
            ("rotation without continuity", assess_rotation(Rotation { successor_check: None, ..rotation },100,10,10), RotationReview::ContinuityUnknown),
            ("rotation overlap", assess_rotation(Rotation { previous_revocation: None, ..rotation },100,10,10), RotationReview::OverlapExceeded),
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
        use aegis_policy::wifi::{compare_baseline, BaselineFixture, ScopedObservation};
        let baseline = BaselineFixture { scope: 1, approved_at: 100, reviewed: true,
            metadata: Metadata { security: SecurityMode::Wpa3Personal, wps: Reported::No, pmf: Pmf::Required } };
        let current = ScopedObservation { scope: 1, at: 120, observation: Observation::Observed(
            Metadata { security: SecurityMode::Wpa2Personal, wps: Reported::Unknown, pmf: Pmf::Disabled }) };
        report.push_str(&format!("fixture-baseline: {:?}; change is not proof of an evil twin\n",
            compare_baseline(baseline, current, 125)));
        report.push_str(&format!("fixture-other-scope: {:?}\n",
            compare_baseline(baseline, ScopedObservation { scope: 2, ..current }, 125)));
        return (0, report);
    }
    if arg == OsStr::new("demo-incidents") {
        use aegis_policy::incident::{correlate, current_timeline, current_graph, current_clusters, search_current, SearchQuery, Event, Signal, TimelineError, GraphError};
        let events = [
            Event { id: 1, asset: 1, seconds: 0, signal: Signal::IntegrityMismatch },
            Event { id: 2, asset: 1, seconds: 60, signal: Signal::PolicyDenied },
            Event { id: 3, asset: 2, seconds: 60, signal: Signal::NativeProtectionDisabled },
            Event { id: 4, asset: 3, seconds: 60, signal: Signal::Normal },
        ];
        match correlate(&events) {
            Ok(s) => {
                let mut report = format!("Synthetic incident correlation; not live telemetry or enforcement.\nEvents: {}\nAssets observed: {}\nAssets with advisories: {}\nAssets for review: {}\nNo attack probability or safety established.\n",
                    s.event_count, s.assets_observed, s.assets_with_advisories, s.assets_for_review);
                for p in s.review_evidence {
                    report.push_str(&format!("Fixture asset {}: event {} ({:?}) + event {} ({:?}), {} seconds apart.\n",
                        p.asset, p.first_event, p.first_signal, p.second_event, p.second_signal, p.elapsed_seconds));
                }
                report.push_str("Correlation explanation only; no causal attribution.\n");
                match current_timeline(&events, 1, 60) {
                    Ok(Some(t)) => report.push_str(&format!("Current fixture timeline (asset 1): {} events; review evidence: {}.\n", t.events.len(), if t.review_evidence.is_some() { "present" } else { "none" })),
                    _ => return (1, "Synthetic timeline unavailable.\n".into()),
                }
                if current_timeline(&events, 4, 60) != Ok(None) ||
                    current_timeline(&events, 1, 601) != Err(TimelineError::StaleSnapshot) ||
                    current_timeline(&events, 1, 59) != Err(TimelineError::FutureEvent) {
                    return (1, "Synthetic timeline checks failed.\n".into());
                }
                report.push_str("Unobserved asset: no evidence, not healthy.\nStale or future snapshot: rejected.\n");
                match current_graph(&events,1,60) {
                    Ok(Some(g)) if g.nodes.len() == 2 && g.edges.len() == 1 =>
                        report.push_str("Synthetic evidence graph: 2 nodes, 1 co-occurrence edge; no causal inference.\n"),
                    _ => return (1, "Synthetic evidence graph unavailable.\n".into()),
                }
                let crowded: Vec<_> = (1..=49).map(|id| Event { id, asset: 1, seconds: 0,
                    signal: if id <= 16 { Signal::IntegrityMismatch } else { Signal::PolicyDenied } }).collect();
                if current_graph(&crowded,1,0) != Err(GraphError::EdgeLimit) {
                    return (1, "Synthetic evidence graph capacity check failed.\n".into());
                }
                report.push_str("Graph capacity exceeded: rejected, no partial graph.\n");
                match (current_clusters(&events,1,60), current_clusters(&events,2,60),
                    current_clusters(&events,3,60)) {
                    (Ok(Some(a)),Ok(Some(b)),Ok(Some(c))) if a.clusters.len() == 1
                        && a.clusters[0].event_ids == vec![1,2]
                        && b.clusters.is_empty() && b.isolated_advisories == 1
                        && c.normal_observations == 1 =>
                        report.push_str("Synthetic review clusters: 1 connected group, 1 isolated advisory, 1 normal observation across fixture assets. Groups are not incidents or causal chains.\n"),
                    _ => return (1, "Synthetic review cluster checks failed.\n".into()),
                }
                if current_clusters(&crowded,1,0) != Err(GraphError::EdgeLimit) {
                    return (1, "Synthetic review cluster capacity check failed.\n".into());
                }
                let q = SearchQuery { asset: 1, from: 0, through: 60,
                    signal: Some(Signal::PolicyDenied) };
                match search_current(&events,q,60) {
                    Ok(Some(result)) if result.scoped_observations == 2 &&
                        result.matches.len() == 1 && result.matches[0].id == 2 =>
                        report.push_str("Synthetic event search: 1 of 2 scoped observations matches the filter.\n"),
                    _ => return (1, "Synthetic event search failed.\n".into()),
                }
                match (search_current(&events,SearchQuery { signal: Some(Signal::Normal), ..q },60),
                    search_current(&events,SearchQuery { asset: 4, ..q },60)) {
                    (Ok(Some(result)),Ok(None)) if result.matches.is_empty() =>
                        report.push_str("No matching event differs from an unobserved asset; neither establishes safety.\n"),
                    _ => return (1, "Synthetic empty search checks failed.\n".into()),
                }
                return (0, report);
            }
            Err(_) => return (1, "Synthetic correlation unavailable.\n".into()),
        }
    }
    if arg == OsStr::new("demo-patches") {
        use aegis_policy::patch::{triage, review_rollout, review_cohort, CanaryObservation, CanaryOutcome, Advisory, Applicability, Evidence, Finding, ProductBuild, Rollout, RolloutAdvisory, RolloutEvidence};
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
                let plan = Rollout { from: p, to: other, artifact: 7, policy_version: 1, canary_count: 3 };
                let evidence = RolloutEvidence { rollout: plan, observed_at: 100, source: reviewed,
                    rollback_rehearsal: reviewed, checked: 3, healthy: 3, failed: 0 };
                let healthy = review_rollout(plan, 100, evidence) == RolloutAdvisory::ExpansionReviewOnly;
                let failure = review_rollout(plan, 100, RolloutEvidence { healthy: 2, failed: 1, ..evidence })
                    == RolloutAdvisory::RollbackReviewRequired;
                let partial = review_rollout(plan, 100, RolloutEvidence { checked: 2, healthy: 2, ..evidence })
                    == RolloutAdvisory::CanaryIncomplete;
                let row = |id| CanaryObservation { id, rollout: plan, observed_at: 100,
                    source: reviewed, outcome: CanaryOutcome::Healthy };
                let cohort = review_cohort(plan, &[1,2,3], &[row(1),row(2),row(3)], 100, reviewed)
                    == RolloutAdvisory::ExpansionReviewOnly;
                let duplicate = review_cohort(plan, &[1,2,3], &[row(1),row(1),row(2)], 100, reviewed)
                    == RolloutAdvisory::InvalidCounts;
                return (0, format!("Synthetic patch priority; no real KEV catalog or CVE mapping.\nPriority review: {priority}\nOther review: {review}\nApplicability unknown: {unknown}\nSynthetic healthy canary prompts human review: {healthy}\nSynthetic failed canary prompts rollback review: {failure}\nSynthetic incomplete canary blocks expansion review: {partial}\nSynthetic distinct cohort prompts human review: {cohort}\nSynthetic duplicate canary blocks expansion review: {duplicate}\nNo patch installation or safety established.\n"));
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
        use aegis_policy::mail_auth::{assess_confirmation, confirmation_example,
            ConfirmationChannel, ConfirmationFixture, ConfirmationVerdict, CriticalRequest};
        let (request, confirmation) = confirmation_example();
        for (label, r, c, now, expected) in [
            ("independent confirmation fixture", request, Some(confirmation), 120,
                ConfirmationVerdict::FixtureConfirmationReported),
            ("missing confirmation fixture", request, None, 120, ConfirmationVerdict::Missing),
            ("request-supplied channel fixture", request,
                Some(ConfirmationFixture { channel: ConfirmationChannel::FromRequest, ..confirmation }),
                120, ConfirmationVerdict::NonIndependentChannel),
            ("changed destination fixture", CriticalRequest { destination: 9, ..request },
                Some(confirmation), 120, ConfirmationVerdict::DifferentTransaction),
            ("expired confirmation fixture", request, Some(confirmation), 410,
                ConfirmationVerdict::StaleOrInvalidTime),
        ] {
            let observed = assess_confirmation(r, now, c);
            report.push_str(&format!("{label}: {observed:?}\n"));
            if observed != expected { return (1, report); }
        }
        report.push_str("Confirmation metadata is synthetic; no payment authorization or contact verification.\n");
        use aegis_policy::mail_auth::{assess_confirmation_batch, BatchVerdict, ReviewEntry};
        let first = ReviewEntry { request, confirmation: Some(confirmation) };
        let other = CriticalRequest { request_id: 2, ..request };
        let second = ReviewEntry { request: other,
            confirmation: Some(ConfirmationFixture { bound_request: other, ..confirmation }) };
        for (label, batch, expected) in [
            ("distinct review batch fixture", [first, second], BatchVerdict::FixtureConfirmationsReported),
            ("duplicate review batch fixture", [first, first], BatchVerdict::DuplicateRequest),
            ("incomplete review batch fixture", [first, ReviewEntry { confirmation: None, ..second }], BatchVerdict::NeedsReview),
        ] {
            let observed = assess_confirmation_batch(&batch, 120);
            report.push_str(&format!("{label}: {observed:?}\n"));
            if observed != expected { return (1, report); }
        }
        report.push_str("Batch checks are synthetic; no persistent replay protection.\n");
        use aegis_policy::mail_auth::{FixtureReviewSession, SessionVerdict};
        let mut session = FixtureReviewSession::default();
        for (label, batch, expected) in [
            ("first session batch fixture", [first, second], SessionVerdict::FixtureBatchRecorded),
            ("repeated session batch fixture", [first, second], SessionVerdict::PreviouslyReviewed),
        ] {
            let observed = session.record(&batch, 120);
            report.push_str(&format!("{label}: {observed:?}\n"));
            if observed != expected || session.recorded_count() != 2 { return (1, report); }
        }
        report.push_str("Session history is volatile and synthetic; no persistent replay protection or payment authority.\n");
        return (0, report);
    }
    if arg == OsStr::new("demo-recovery") {
        use aegis_policy::recovery::{assess, example, Verdict, assess_objectives,
            RestorePlan, RestoreReceipt, Evidence, ObjectiveVerdict, assess_linked_objectives, LinkedVerdict,
            assess_portfolio, DatasetExercise};
        let mut c = example();
        let complete = assess(&c, 100, 20);
        c[2].restore_verified_at = None;
        let missing = assess(&c, 100, 20);
        let plan = RestorePlan { dataset: 1, copy: 3, exercise: 7, incident_at: 100,
            max_data_loss: 10, max_downtime: 20 };
        let receipt = RestoreReceipt { dataset: 1, copy: 3, exercise: 7, recovery_point: 90,
            completed_at: 120, integrity: Evidence::ReportedYes,
            functional_check: Evidence::ReportedYes };
        let objectives = assess_objectives(plan, Some(receipt), 120);
        let missed = assess_objectives(plan, Some(RestoreReceipt { completed_at: 121, ..receipt }), 121);
        c[2].restore_verified_at = Some(120);
        let linked = assess_linked_objectives(&c, plan, Some(receipt), 120, 20);
        c[2].restore_verified_at = Some(119);
        let unlinked = assess_linked_objectives(&c, plan, Some(receipt), 120, 20);
        c[2].restore_verified_at = Some(120);
        let plan2 = RestorePlan { dataset: 2, ..plan };
        let e1 = DatasetExercise { dataset: 1, copies: &c, receipt: Some(receipt) };
        let e2 = DatasetExercise { dataset: 2, copies: &c,
            receipt: Some(RestoreReceipt { dataset: 2, ..receipt }) };
        let portfolio = assess_portfolio(&[plan,plan2], &[e1,e2],120,20);
        let incomplete = assess_portfolio(&[plan,plan2], &[e1],120,20);
        let (Ok(portfolio), Ok(incomplete)) = (portfolio,incomplete) else {
            return (1, "Synthetic recovery portfolio unavailable.\n".into());
        };
        if !portfolio.all_fixture_criteria_reported || incomplete.all_fixture_criteria_reported {
            return (1, "Unexpected synthetic recovery portfolio result.\n".into());
        }
        if objectives != ObjectiveVerdict::FixtureObjectivesReported ||
            missed != ObjectiveVerdict::ObjectivesMissed ||
            linked != Ok(LinkedVerdict::LinkedFixtureReported) ||
            unlinked != Ok(LinkedVerdict::ReceiptNotLinked) {
            return (1, "Synthetic recovery objectives unavailable.\n".into());
        }
        match (complete, missing) {
            (Ok(a), Ok(b)) if a.verdict == Verdict::FixtureCriteriaReported &&
                b.verdict == Verdict::ReviewRequired => return (0, format!(
                    "Synthetic recovery readiness; no backup inspection or restore performed.\nCopies: {}\nFailure domains: {}\nKnown media: {}\nComplete fixture: {:?}\nMissing isolated restore: {:?}\nRestore objectives: {:?}\nLate restore: {:?}\nLinked inventory exercise: {:?}\nUnlinked receipt: {:?}\nAll required dataset fixtures reported: {}\nMissing dataset coverage reported complete: {}\nRecovery capability not established.\n",
                    a.copies, a.failure_domains, a.known_media, a.verdict, b.verdict, objectives, missed,
                    linked.unwrap(), unlinked.unwrap(), portfolio.all_fixture_criteria_reported,
                    incomplete.all_fixture_criteria_reported)),
            _ => return (1, "Synthetic recovery assessment unavailable.\n".into()),
        }
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
