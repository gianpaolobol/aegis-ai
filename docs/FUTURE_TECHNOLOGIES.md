# ARFT — Future technologies
2026-11-24 | Design requirements and research backlog; not implemented or validated.
## V1.0 architecture gates
- PQC: inventory crypto algorithms, protocols, certificates and key lifetimes; versioned provider interfaces, migration/rollback and downgrade protection. Evaluate FIPS 203 ML-KEM, FIPS 204 ML-DSA, FIPS 205 SLH-DSA and standardized hybrid protocols using established audited libraries. No custom primitives or blanket quantum-safe claims; WireGuard is not automatically PQC.
- NHI: distinct authenticated identities for agents and workloads, scoped short-lived credentials, rotation, revocation, dynamic Zero Trust. Evaluate SPIFFE/SPIRE; verify issuer/audience, expiry, replay and trust-domain boundaries.
- Predictive defense: inventory exposed assets, prioritize documented vulnerabilities, synthetic regression tests and explicitly authorized isolated labs only. Self-healing changes via reviewed branch, test, signature, reversible rollout and approval for sensitive deployment; no autonomous production patching.
- Confidential AI: minimize data, prefer local inference, define trust boundaries and hardware capability discovery. Evaluate remote attestation, TEE, MPC, differential privacy, FHE and federated learning. Explicitly model side channels, metadata and leakage; benchmark accuracy, latency, memory and cost. Advanced features remain research until validated.
## Permanent research process
Review primary sources weekly within existing scheduled development and reassess roadmap monthly or on relevant security advisories. Record source/date/version, license, platform support, maturity, risk, benchmark, adoption decision and regression criteria. Never equate a research prototype with production support. Preserve all existing release gates and proprietary/third-party license obligations.
## Baseline sources
- NIST PQC: https://csrc.nist.gov/projects/post-quantum-cryptography
- NIST crypto agility CSWP 39upd1: https://csrc.nist.gov/pubs/cswp/39/upd1/considerations-for-achieving-crypto-agility/final
- EU coordinated roadmap: https://digital-strategy.ec.europa.eu/en/library/coordinated-implementation-roadmap-transition-post-quantum-cryptography
- SPIFFE Workload API: https://spiffe.io/docs/latest/spiffe-specs/spiffe_workload_api/
EU roadmap targets start of Member State transition by end 2026 and high-risk use cases by end 2030; not a universal product certification deadline.
