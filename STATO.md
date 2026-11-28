# Stato — aegis-ai

> Formato fisso: `gianpaolobol/registro-delle-idee` → `PROTOCOLLO_AI.md`, sezione 4. Massimo una pagina: i dettagli restano in `README.md`.

## Cos'è
Sistema di sicurezza difensiva multipiattaforma con core Rust e dimostratore Windows non privilegiato. Il codice è nella PR #1 in bozza; main contiene documenti legali e di governance.

## Fase
in sviluppo

## Dove è pubblicata
non pubblicata

## Prossimi passi
1. Verificare le nuove CI e completare il candidato Windows alpha.
2. Completare provenienza, licenze, linkage e laboratorio del motore AV.
3. Collaudare installazione e rimozione su VM Windows client isolata.
4. Ottenere firma attendibile e revisione indipendente prima di ogni distribuzione.
5. Proseguire il piano V1.0 senza dichiarare capacità non validate.

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
