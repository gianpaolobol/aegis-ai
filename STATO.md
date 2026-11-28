# Stato — aegis-ai

> Formato fisso: `gianpaolobol/registro-delle-idee` → `PROTOCOLLO_AI.md`, sezione 4. Massimo una pagina: i dettagli restano in `README.md`.

## Cos'è
Sistema di sicurezza difensiva multipiattaforma con core Rust e dimostratore Windows non privilegiato. Il codice è nella PR #1 in bozza; main contiene documenti legali e di governance.

## Fase
in sviluppo

## Dove è pubblicata
non pubblicata

## Prossimi passi
1. V0.1 Alpha approvata provvisoriamente dal titolare; sviluppare V0.2 AV/EDR/XDR e lotti successivi senza blocchi indipendenti. Congelare i candidati solo dopo test e review.
2. Completare provenienza, licenze, linkage e laboratorio del motore AV.
3. Collaudare installazione e rimozione su VM Windows client isolata.
4. Ottenere firma attendibile e revisione indipendente prima di ogni distribuzione.
5. Proseguire V0.3–V1.0 secondo MASTER_PLAN, senza dichiarare capacità non validate.

## Blocchi
- Revisione indipendente, firma di distribuzione, laboratorio Windows client e motore AV nativo non ancora validati.
- Nessuna pubblicazione; eventuali autorizzazioni specifiche di laboratorio restano da verificare.

## Componenti condivisi
- Usa da altri repository: —
- Offre agli altri: —

## Linee guida
Segue la versione **1.1.0** (`LINEE_GUIDA.md`).

## Registro aggiornamenti
- 2026-11-26 [Claude] Prima compilazione dai contenuti del repository; le voci "da confermare" vanno verificate.
- 2026-11-28 [Codex] Aggiornamento su evidenza CI ADE-096: tre OS e controlli UI superati; riconciliazione della governance su ramo di sviluppo, non rilascio.

- 2026-11-28 [Codex] ADE-098: CI ADE-097 verde; validatore offline di coerenza dei verbali Windows client, installazione reale ancora non verificata.

- 2026-11-28 [Codex] ADE-099: CI ADE-098 verde; confronto offline SHA-256 dei byte del pacchetto e delle sette evidenze, senza attestare installazione o autenticità.

- 2026-11-28 [Codex] ADE-100: CI ADE-099 verde; diagnostica in lettura configurazione cloud e invio campioni Defender, nuovi test in attesa di CI.

- 2026-11-28 [Codex] ADE-101: CI ADE-100 verde; diagnostica SmartScreen Explorer/Edge in sola lettura, nuova CI da verificare.

- 2026-11-28 [Codex] ADE-102: CI ADE-101 verde; riepilogo eventi Defender locali su richiesta, soli conteggi, nuovo collaudo CI in attesa.

- 2026-11-28 [Codex] ADE-103: CI ADE-102 verde; riferimento offline di triage dei soli conteggi Defender, 6 test locali superati; integrazione UI e collaudo finale ancora aperti. Build differite secondo direttiva del titolare.

- 2026-11-28 [Codex] ADE-104: avvio V0.2, correlazione offline di segnali AV/EDR sintetici e 12 test locali (6 nuovi, 6 regressioni); integrazione nativa e gate di distribuzione ancora aperti.

- 2026-11-28 [Codex] ADE-105: collegamento della correlazione AV/EDR ai dati nativi in sola lettura nell'interfaccia Windows; fixture di regressione aggiunte, esecuzione PowerShell ancora da verificare; V0.2 in sviluppo.
