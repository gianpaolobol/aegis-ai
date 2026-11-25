# Competitive matrix — initial backlog
All entries level 1 (preliminary analysis based on project requirements, vendor documentation and edition/OS verification pending). Levels 0 absent, 1 analyzed, 2 designed, 3 implemented, 4 internally tested, 5 demonstrated parity, 6 measured improvement, 7 independently validated.
| Reference | Capability to verify | Candidate | Acceptance target |
|---|---|---|---|
| CrowdStrike Falcon/AIDR | endpoint and agent monitoring | osquery, OPA | unauthorized action denied |
| SentinelOne Singularity | isolation and recovery | Wazuh, Restic | reversible containment and restore |
| Microsoft Defender XDR | identity/email/endpoint correlation | OCSF, OpenSearch | synthetic cross-source incident |
| Cortex XDR | network/endpoint analytics | Zeek, Suricata | correlated alerts |
| Bitdefender | behavioral malware defense | ClamAV, YARA-X | benign fixture coverage |
| Norton 360/Genie | scam detection | local classifier | labeled synthetic messages |
| 1Password | passkeys and vault | WebAuthn | origin-bound login |
| Bitwarden | credential management | compatible integration | no secret disclosure |
| Malwarebytes | browser and malware protection | browser adapter | benign URL fixture |
| Proofpoint | BEC and attachment analysis | Rspamd | synthetic mail corpus |
| Mimecast | impersonation | Rspamd | out-of-band verification |
| Material Security | cloud account controls | authorized APIs | least-privilege access |
| Azure Prompt Shields | indirect/direct injection | policy gateway | untrusted instructions cannot authorize actions |
| Netskope One | DLP and AI gateway | Presidio, OPA | scoped egress policy |
| NVIDIA NeMo Guardrails | programmable guards | NeMo evaluation | input/output and tool policy tests |
For each row add official source/date, SKU, platform, prerequisites, exact version/license of candidate, measured results and limitations before raising maturity.

## ADE-021 — official evidence slice (2026-11-25)
Vendor-documented features only; no independent equivalence benchmark. All rows below remain level 1 (researched); the AEGIS fixture ledger is not a detector or production enforcement.
| Reference / feature | Edition, platform and prerequisite | AEGIS gap and candidate | Priority / acceptance |
|---|---|---|---|
| Azure Prompt Shields: user prompt manipulation detection | Azure AI Content Safety API, or Foundry configuration; service/API access and supported region/model configuration, not a native endpoint OS feature; exact SKU/region to verify | No calibrated prompt classifier; local screening candidate plus independent deterministic gateway; OPA (Apache-2.0) as policy engine candidate only | P1; fixed benign synthetic labeled text and no unauthorized action regardless of detector verdict; precision/recall/FPR and p95 |
| Azure Prompt Shields: document injection detection | Content Safety API analyzes supplied document text; supported Foundry agent tool-response intervention is documented as Preview | No integrated email/RAG/tool ingestion or classifier; isolate untrusted text and keep provenance/authority separate | P1; fixed synthetic document/tool-response fixtures, session/ACL separation and no fake secret disclosure |
| Azure Prompt Shields: enforcement integration | API reports classifications; application decides routing/blocking; Foundry can filter when configured | AEGIS gateway fixture checks exact transaction, but no authenticated dispatcher; external policy engine not adopted | P0; deterministic denial of unknown and out-of-scope action, replay, revoked grant, expired approval; test even if model/detector says allow |

Sources consulted 2026-11-25: Microsoft concepts https://learn.microsoft.com/en-us/azure/ai-services/content-safety/concepts/jailbreak-detection and API quickstart https://learn.microsoft.com/en-us/azure/ai-services/content-safety/quickstart-jailbreak ; OPA upstream https://github.com/open-policy-agent/opa and https://github.com/open-policy-agent/opa/blob/main/LICENSE (Apache-2.0). OPA is a policy engine, not a substitute for prompt-injection detection or verified execution mediation. Pin exact version, inspect dependencies/advisories, benchmark local evaluation, failure behavior and resource use before adopting. No external service calls, no vendor code copied, no production integration. Remaining vendors and exact edition/platform prerequisites still require itemized source review.

## ADE-025 — endpoint protection evidence slice (2026-11-25)
Source: Bitdefender Total Security official US product page https://www.bitdefender.com/en-us/consumer/total-security (accessed 2026-11-25). Vendor-described capabilities, not independently benchmarked. Total Security Individual/Family paid plans cover desktop/mobile; feature-specific OS/version and entitlement requirements beyond Windows PC must be confirmed, never assume parity across OS.
| Capability | Edition / platform / prerequisite | AEGIS gap / candidate | Priority / test | Level |
|---|---|---|---|---|
| Real-time malware protection | Total Security, Windows endpoint client; current subscription and installed protection | No real-time sensor or malware corpus; YARA-X BSD-3-Clause candidate only for pattern matching, native protection remains enabled | P0; harmless marker tests, bounded scans, then authorized synthetic event coverage and FP/latency/RAM | 1 |
| Behavioral app monitoring | Total Security Advanced Threat Defense, Windows client; feature enabled | No runtime behavior monitor; read-only OS telemetry and deterministic bounded event correlation planned; YARA-X does not replace this | P1; synthetic legitimate workload and abstract anomaly fixtures, availability and p95 | 1 |
| Vulnerability assessment | Total Security Windows client, installed software/settings visibility | No software inventory or KEV correlation; signed advisory sources and inventory adapter planned | P1; fixed package/version and patch metadata fixtures, unknown preserved | 1 |
| Ransomware file protection | Total Security Windows client; configured protection | No real-time containment or restore gate; bounded reversible policy plus separate offline backups planned | P1; synthetic event/restore fixtures, no encryption of real user data | 1 |
| Wi-Fi configuration advice | Total Security Wi-Fi Security Advisor; Windows endpoint, network metadata access | Synthetic metadata advisor only; native passive metadata adapter still open | P1; unknown/permission denied and configured fixture outcomes; no password-strength inference | 1 |
YARA-X optional Python API candidate 1.24.0 (published 2026-11-20, Python >=3.9, Linux/macOS/Windows), official API https://virustotal.github.io/yara-x/docs/api/python/ and https://pypi.org/project/yara-x/ checked 2026-11-25. Upstream repo reports BSD-3-Clause; exact tag license retrieval via public web unavailable, transitive/embedded notices, advisories, wheel hash and provenance not verified. No engine installed or distributed. Mock adapter regression level 4 only for the local adapter logic, not these competitive features or actual engine performance. No parity claimed.
