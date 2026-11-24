# AEGIS Wi-Fi Security Auditor
Status: planned; no live scanning or device tests claimed.
## Scope and acceptance
- WIFI-01: read OS-exposed Wi-Fi metadata with user permission; no active probing or association; unavailable fields remain unknown.
- WIFI-02: classify open, WEP, WPA, WPA2, WPA3, transition and unknown configurations; distinguish observed security mode from password strength; surface WPS and PMF only when reliably reported.
- WIFI-03: local assessment of a password voluntarily supplied for an authorized network; never read saved credentials or log, persist or transmit the secret. Do not estimate exact cracking time.
- WIFI-04: generate a strong unique password using the OS cryptographically secure RNG; recommend WPA3-SAE where supported, disabling WPS, firmware updates and guest isolation; user applies router changes.
- WIFI-05: alert on suspicious changes to a user-approved network profile; same SSID or changed BSSID alone is not proof of an evil twin.
- WIFI-06: synthetic educational demonstrations and periodic opt-in checks of authorized network configurations.
## Boundaries
No cracking, handshake capture, credential extraction, deauthentication, active probing, unauthorized connections or automated router changes. No telemetry by default. Respect native platform permissions and sandboxing.
## Platform plan
Windows/macOS/Linux: native metadata adapters; Android/AOSP/GrapheneOS and forks: permission-aware Android adapter; iOS/iPadOS: only sanctioned APIs and entitlements, no promise of nearby-network enumeration. Unsupported fields remain unknown.
## Test gates
Synthetic security-mode fixtures, unknown metadata, denied permissions, transition mode, false-positive cases, no secret in logs, RNG failure, and platform-specific integration tests. Review privacy, licensing and CI before merge. No production readiness claim before physical-device validation.
