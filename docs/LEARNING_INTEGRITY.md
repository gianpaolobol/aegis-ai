# ALIS — Learning Integrity Shield
Status: design; no detector integrated or benchmark validated.
## Pipeline
Authenticated source metadata → bounded quarantine → schema and provenance validation → deduplication and per-source contribution caps → statistical review → offline training → independent held-out evaluation → signed model registry → approved deployment and rollback. Never learn directly from production traffic.
## Candidate tools (version, license, compatibility and maintenance checks required)
- [IBM ART](https://github.com/trusted-ai/adversarial-robustness-toolbox): evaluate activation clustering, spectral signatures and provenance defenses for compatible classifiers; results are advisory. STRIP is a separate runtime detection candidate, not proof of a backdoor.
- [Cleanlab](https://github.com/cleanlab/cleanlab): label quality review with out-of-sample predictions.
- [Evidently](https://github.com/evidentlyai/evidently): distribution drift against frozen baselines; drift is not proof of poisoning.
- [BackdoorBox](https://github.com/THUYimingLi/BackdoorBox): literature review only; do not enable attack generation.
- [LLM Guard](https://github.com/protectai/llm-guard): candidate content screening; never treat screening as an authorization boundary.
- [Fickling](https://github.com/trailofbits/fickling): static inspection of pickle artifacts without deserialization; cannot certify safety.
- SafeTensors: prefer non-executable tensor serialization where compatible; verify provenance and resource bounds.
- DVC, MLflow, Sigstore: evaluate versioned manifests, restricted registry and signed releases.
## RAG integrity
Allowlisted authenticated sources, document-level ACL enforcement at retrieval and output, immutable version identifiers and hashes, quarantine unexpected changes, separate untrusted content from instructions, no tool authority from retrieved text. Revoke and reindex affected documents and derived embeddings. Never trust a document solely because a classifier accepts it.
## Acceptance
Synthetic fixtures only: duplicate handling, contribution caps, invalid provenance, drift vs legitimate change, unauthorized retrieval denial, unsigned artifact rejection, rollback and lineage completeness. Suspicious records quarantined, not auto-deleted. A 2% alert threshold is experimental only; calibrate with held-out data, confidence intervals and measured false positives. Critical deterministic invariants require zero failures; statistical non-inferiority gates predefined. No claim of immunity.
## Isolation
Python research workers offline with no production credentials; Rust runtime enforces deterministic permissions. No real secrets, live malware, executable untrusted artifacts or offensive generation. Review dependency licenses before distribution. Keep Windows alpha priority.
