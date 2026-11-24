# AEGIS AI V1.0 master plan
Status: development, not validated. Shared Rust core, OS adapters and optional self-hosted control plane. Personal, Professional, Enterprise profiles; optional Forgia integration.
| Phase | Deliverable | Acceptance |
|---|---|---|
| 0 | Governance, licenses, threat model | documented scope and review gates |
| 1 | Deterministic AI authorization | deny unknown actions; authenticated identity, scoped grants, expiry, transaction-bound approval, replay protection, budgets, revocation, kill switch; concurrency and persistence tests |
| 2 | Endpoint antivirus and EDR | benign fixtures, real OS integration, reversible quarantine, measured false positives |
| 3 | VPN, firewall, DNS, network and XDR | WireGuard integration, isolation, event correlation, recovery channel |
| 4 | Identity and vault | FIDO2/WebAuthn, secure recovery, short-lived tokens; no custom cryptography |
| 5 | AI gateway and MCP | guardrails, untrusted document separation, DLP, sandbox default no network, least privilege, human approval |
| 6 | Email/browser security | BEC, QR/URL, SPF/DKIM/DMARC, phishing, out-of-band identity checks; deepfake scores not proofs |
| 7 | Patch and supply chain | inventory, KEV priority, signed update, rollback, SBOM, provenance |
| 8 | Recovery | encrypted 3-2-1 backups, offline/immutable copy, restore exercises |
| 9 | Platform adapters | Windows, macOS, Linux, Android/AOSP without Google, GrapheneOS, LineageOS, /e/OS, CalyxOS, iodéOS, Volla OS, Fire OS, other forks, iOS/iPadOS, ChromeOS, BSD, mobile Linux, HarmonyOS subject to API and device validation |
| 10 | Release gates | platform capability matrix, independent review, benchmark p95 latency/CPU/RAM/battery/precision/recall, signed builds and no unresolved high/critical known findings |
Threat coverage: hostile agents, adaptive malware, ransomware, phishing, deepfake, automated vulnerability exploitation, prompt injection, data poisoning, token theft, exfiltration, MCP compromise, supply chain. Deterministic boundaries independent of AI; no automatic privilege escalation or counterattack. No forced root, Google services, invasive TLS interception or mandatory telemetry. Zero Trust, microsegmentation, reversible isolation and safe admin channel. Assess free components and license compatibility before distribution. Benchmark all competitors in COMPETITIVE_MATRIX.md; no unverified superiority claims.