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