# Istruzioni per gli agenti AI — aegis-ai

<!-- inizio-protocollo-comune -->
## [Gian] Protocollo comune — gestito dalla sincronizzazione, non modificare

Questo repository fa parte della piattaforma di Gian Paolo Franceschini.

1. **Leggi prima `LINEE_GUIDA.md`** (nella radice): struttura, regole e protocollo validi per tutti i progetti. Poi questo file, comprese le deroghe `[Gian]`, poi `STATO.md`.
   Poi il **giro di controllo** (cap. 8 delle linee guida): leggi l'ultimo diario del registro e la mappa dei collegamenti, e riusa ciò che esiste già in altri repository.
2. **Firma tutto ciò che aggiungi:** `[Codex]`, `[Claude]`, `[Gemini]`, `[Copilot]`, `[Gian]`.
3. **Questo file si aggiunge, non si riscrive:** nuova sezione `## [Firma] Titolo — AAAA-MM-GG`; per superarne una scrivi una `Rettifica`.
4. **Aggiorna `STATO.md`** nella stessa pull request del lavoro.
5. **Deroghe** alle linee guida: solo Gian, in una sezione `## [Gian] Deroghe alle linee guida` di questo file.
<!-- fine-protocollo-comune -->

## [Codex] Protocollo di sviluppo difensivo AEGIS — 2026-11-28

# Development protocol
Copyright 2026 Gian Paolo Franceschini. See LICENSE.
For each iteration: inspect main, open PRs and CI; define scope, acceptance and threat model; review plan; implement on branch; run negative and regression tests; review independently when possible; record actual evidence and limitations; merge only after verified checks and review. Never report simulated agents as independent reviewers. No production deployment, personal-device changes, offensive activity or real malware. Use synthetic fixtures and isolated authorized environments. No secrets in this public repository. Preserve third-party licenses and original proprietary rights. Track docs/MASTER_PLAN.md, docs/DEVELOPMENT_PROGRESS.md and docs/COMPETITIVE_MATRIX.md. Stop release if a critical/high known issue remains or platform claims lack evidence.
