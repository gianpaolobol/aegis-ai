# Release readiness — Windows alpha first
Status: development; no installable artifact or production protection validated.
| Gate | Evidence required | State |
|---|---|---|
| Read-only CLI | help/status/fixture commands; reject unknown and extra args | prior head 360f26b: unit CI green on all 3 desktop OS; new process tests pending |
| Windows executable | exact-head cargo release build, clean VM smoke test | release-mode CI steps added; execution pending |
| macOS/Linux | exact-head release build and smoke test | release-mode CI steps added; execution pending |
| Install/uninstall | unprivileged installer, clean removal, no services/settings changes | open |
| Supply chain | locked toolchain/dependencies, SBOM, provenance, checksum, signing verification | open |
| Independent review | review of exact release candidate | open |
| Mobile | real device API entitlement and signing tests; no claim of endpoint-wide AV on iOS | open |
No production release, no automatic changes to personal devices. Keep native protections enabled. The alpha is a demonstrator, not antivirus, VPN, EDR or a policy enforcement boundary. A signed artifact, installation and uninstall evidence are required before calling it installable and validated. No external network access or credentials in fixture tests.
Next: exact-head CI; add process-level CLI smoke checks and package build in CI; select maintained installer tooling with verified license. UI follows validated core. Eight planning workstreams remain backlog, not independently running teams.

## ADE-005 evidence (2026-11-24)
Prior head `360f26b62bc9770e3144fd43e51120ed60dc25a0`: [run 45438601792](https://github.com/gianpaolobol/aegis-ai/actions/runs/45438601792), three OS jobs passed; Windows log confirms 13 library + 7 CLI unit tests, zero failures, Rust 1.100.0. Four new process test functions check successful invocations, output limitations, synthetic decisions and invalid arguments without echo; release-mode build and process tests added to CI, not yet verified. No installer, artifact publication or independent review. Next after CI: lock Rust version and dependency graph, packaging with license notice and checksums, signed artifact, clean install/uninstall and independent review. No claim of reproducibility or device validation.
