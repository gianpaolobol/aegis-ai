# AAIS — Adaptive Immune System
Design only. Start with deterministic, non-executable synthetic event fixtures; no offensive autonomous capabilities.
| Stage | Requirement | Acceptance |
|---|---|---|
| Sentinel | passive authorized metadata; optional isolated decoy without real data or egress | no external connectivity; scope and retention verified |
| Forensics | normalize metadata, provenance, quarantine, curated labels, deduplicate | untrusted inputs cannot authorize actions or execute content |
| Arena | Red abstract fixture events, Blue bounded defensive actions, Green legitimate workloads, White fixed invariants, Gold held-out fixtures | deterministic seeds; no real attack generation; holdout separated |
| Validator | offline candidate compared with static baseline and held-out cases | fail closed on invariant failure; no regression beyond predeclared budgets |
| Distributor | signed artifact, human approval bound to exact version, shadow mode, canary, rollback | no unsigned or unapproved structural changes; recovery exercised |
Short/long-term behavioral summaries and an independently approved reference baseline; quarantine suspicious observations, test drift and slow poisoning, never change production model weights online. Anomaly scores are not attack probabilities absent calibration. Measure precision/recall, false positives, legitimate availability, latency and resource use; report dataset limits. No cross-device raw secrets. No AI can expand privileges or rewrite constitutional policy. Evaluate candidate frameworks and licenses before integration: Firecracker, Kubernetes, RLlib, PettingZoo, NeMo, MLflow, eBPF/Falco/Tetragon, ETW, Apple Endpoint Security; none validated yet. Compare documented capabilities of Darktrace, Vectra, SentinelOne, Promptfoo, PyRIT, garak, Ethiack, XBOW and research preprints only for defensive validation and behavioral analytics. No claim of parity. Regulatory and response requirements in RESPONSE_GOVERNANCE.md.
