# sentinel-detection-lab

Microsoft Sentinel detection engineering **without a workspace**: four analytics rules in the
community template format, a local evaluator for the KQL subset they use, 45 declared
fixtures, a cross-table correlation case, an automation rule modelled against the published
ARM schema, a read-only triage playbook — and the Python hardening that made it testable.

[![sentinel-lab](https://github.com/marcuspaula-seceng/sentinel-detection-lab/actions/workflows/sentinel-lab.yml/badge.svg)](https://github.com/marcuspaula-seceng/sentinel-detection-lab/actions/workflows/sentinel-lab.yml)

---

## What this is not — read this first

```text
No Sentinel workspace.   No tenant.   No Kusto engine.   No production telemetry.
```

Every query was written against the **official table schemas** (`SecurityEvent`,
`SigninLogs`, `DeviceProcessEvents`) and **real community templates** from
`Azure/Azure-Sentinel`, and executed only by the local evaluator in `tools/kql_eval.py` —
which raises on anything outside its subset instead of pretending to be Kusto. One positive
fixture is a real Event 4698 taken from a public-domain (CC0) EVTX sample; its provenance is in
the notes. Everything else is synthetic (`example.com`, RFC 5737 addresses).

This is a laboratory. It does not claim production experience with Sentinel.

## What is here

```text
topicos/03-sentinel/
  rules/        4 scheduled analytics rules (community YAML template format) + a correlation query
  tools/        kql_eval.py (evaluator) · run_tests.py · run_case.py · lint_rules.py · lab.py (single entry point)
                fixtures-*.json (45 fixtures + 4 multi-table cases) · test_kql_eval.py · test_triage.py
  automation/   automation rule (ARM, Microsoft.SecurityInsights/automationRules) · triage.py playbook
  DAY-01..06    lab notes (Portuguese, as written) · CASE-04 correlation case
```

## How to verify

```text
python topicos/03-sentinel/tools/lab.py all
   unit      34 tests   (evaluator + playbook)
   lint      4/4 rules  (template structure checked against documented limits)
   fixtures  45/45      (every rule behaves exactly as each fixture declares)
   cases     4/4        (cross-table correlation, including one deliberate false positive)
```

Standard library plus PyYAML. Runs in CI on Ubuntu (badge above). Last local run:
2026-09-24, all green.

## Three results worth reading

- **`contains` vs `has`** are not interchangeable in KQL; the inherited fixtures could not tell
  them apart, and two purpose-built ones can (`DAY-02`).
- `SecurityEvent` has no `TaskName` column: the task XML lives **HTML-escaped inside
  `EventData`**, and a rule that searches `<UserId>` never fires — with every test green
  (`DAY-03`).
- With the real fixtures, the three telemetry families **do not correlate** — not because of
  the SIEM but because the entities differ; correlation is a property of identifier
  conventions (`CASE-04`).

## Licence

No licence has been chosen yet; all rights reserved by default.
