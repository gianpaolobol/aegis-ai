# Release readiness — Windows alpha first
Status: development; no installable artifact or production protection validated.
| Gate | Evidence required | State |
|---|---|---|
| Read-only CLI | help/status/fixture commands; reject unknown and extra args | code authored, CI pending |
| Windows executable | exact-head cargo release build, clean VM smoke test | open |
| macOS/Linux | exact-head release build and smoke test | open |
| Install/uninstall | unprivileged installer, clean removal, no services/settings changes | open |
| Supply chain | locked toolchain/dependencies, SBOM, provenance, checksum, signing verification | open |
| Independent review | review of exact release candidate | open |
| Mobile | real device API entitlement and signing tests; no claim of endpoint-wide AV on iOS | open |
No production release, no automatic changes to personal devices. Keep native protections enabled. The alpha is a demonstrator, not antivirus, VPN, EDR or a policy enforcement boundary. A signed artifact, installation and uninstall evidence are required before calling it installable and validated. No external network access or credentials in fixture tests.
Next: exact-head CI; add process-level CLI smoke checks and package build in CI; select maintained installer tooling with verified license. UI follows validated core. Eight planning workstreams remain backlog, not independently running teams.
