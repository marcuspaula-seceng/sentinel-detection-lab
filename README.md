# sentinel-detection-lab

Microsoft Sentinel detection engineering without a workspace: four analytics rules in the
community template format, a local evaluator for the KQL subset they use, 45 declared
fixtures, a cross-table correlation case, an automation rule modelled against the published
ARM schema, and a read-only triage playbook — plus the Python hardening that made all of it
testable (unit tests, linter, single CLI, CI written but never run).

```text
python topicos/03-sentinel/tools/lab.py all     unit 34 · lint 4/4 · fixtures 45/45 · cases 4/4
```

## What this is not

No Sentinel workspace, no tenant, no Kusto engine. Every query was written against the
official table schemas and real community templates, and executed only by the local
evaluator — which raises on anything outside its subset instead of pretending.

## Layout

`topicos/03-sentinel/` — `DAY-01..06`, `CASE-04`, `rules/`, `tools/`, `automation/`. Lab notes are
in Portuguese, as written. See `topicos/03-sentinel/README.md` for the file map.

**Private.** Extracted from a personal study repository on 2026-09-24. Synthetic data only;
one real public-domain EVTX event used as a positive fixture, with provenance in the notes.
No licence chosen yet.
