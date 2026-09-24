# 03 — Microsoft Sentinel

**Posição na prioridade:** P0.3 (ordem de execução: depois de Entra, por delta de 08/09/2026)
**Estado:** em curso
**Ciclo:** 5 — aberto em 22/09/2026

> **Histórico do stub.** Este README existia desde 06/09/2026 com o texto
> *"Ciclo previsto: 4 · Estado: nao iniciado"*. O número mudou pelo `DELTA DE PRIORIDADE`
> de 08/09/2026 (Entra antes de Sentinel). O stub não foi apagado — foi absorvido aqui.

---

## Sem workspace — o que isso permite e o que proíbe

Marcus **não tem** workspace do Sentinel nem Log Analytics. Igual ao Ciclo 2 (sem tenant MDE)
e ao Ciclo 4 (sem tenant Entra).

```text
PERMITIDO   schema oficial das tabelas (referência Azure Monitor Logs), propriedades
            oficiais da regra agendada, template YAML da comunidade, telemetria
            sintética marcada, KQL escrito e raciocinado, modelação de analytics rule
PROIBIDO    afirmar uso real de Sentinel, workspace, incidente tratado, regra em
            produção; criar recurso Azure; pedir credenciais; instalar ferramenta
```

**Formulação permitida:** *Analytics rule modelling lab using official Microsoft Sentinel
schemas and synthetic telemetry.*

**Nunca:** *real Sentinel investigation · production workspace · SOC incident handled ·
Sentinel tenant lab.*

## O que este ciclo reaproveita

As três telemetrias já construídas caem em tabelas do Sentinel com nome oficial:

| Ciclo | Telemetria construída | Tabela no Sentinel | Verificado em |
|---|---|---|---|
| 2 | Advanced Hunting `Device*` (sintético) | `DeviceProcessEvents` e irmãs | `DAY-01` |
| 3 | EVTX real 4688/4698 (CC0) | `SecurityEvent` | `DAY-01` |
| 4 | Graph `signIn` / `directoryAudit` (sintético) | `SigninLogs` / `AuditLogs` | `DAY-01` (`SigninLogs`) |

Fecha com `CASE-04-SENTINEL-CORRELATION.md`.

## Ficheiros

| Ficheiro | O que é |
|---|---|
| `DAY-01-SENTINEL-DATA-MODEL-AND-RULE-ANATOMY.md` | modelo de dados, anatomia da regra agendada, entidades, primeira regra traduzida |
| `DAY-02-FIXTURES-AND-LOCAL-EVALUATOR.md` | 10 fixtures, avaliador local, `contains` vs `has`, `connectorId` confirmado |
| `DAY-03-EVENT-4698-VIA-EVENTDATA.md` | a coluna que não existe: `parse EventData`, escape HTML, evento real como positivo |
| `DAY-04-SIGNINLOGS-IDENTITY-RULE.md` | CASE-03 vira regra; `dynamic`; **delta ao Ciclo 4**: `ResultType` é string |
| `DAY-05-DEVICEPROCESSEVENTS-ENDPOINT-RULE.md` | CASE-01 vira regra sem tradução; decisão sobre ASIM, com razão |
| `DAY-06-INCIDENT-MODEL-AND-AUTOMATION.md` | alertas → incidentes: agrupamento por regra, entidades fortes/fracas, automação modelada |
| **`CASE-04-SENTINEL-CORRELATION.md`** | **artefacto principal** — com as fixtures reais, as 3 famílias NÃO se correlacionam; o que decide é a convenção de identificadores, não o SIEM |
| `rules/CASE-04-correlation.kql` | quinta regra (`join` por conta e janela) — **4/4 casos** em `run_case.py`; o caso D é o falso positivo por desenho |
| `tools/run_case.py` · `tools/fixtures-case04.json` | runner multi-tabela (`let`/`join`/`between`) e os 4 casos do CASE-04 |
| `automation/triage-system-persistence-on-servers.automationrule.json` | regra de automação em ARM (`@2025-10-01-preview`), enums do schema; **não implantada** |
| `rules/marcus_schtasks_system_persistence.sentinel.yaml` | regra 1 (4688 + schtasks.exe) — 10/10 fixtures |
| `rules/marcus_schtasks_4698_system_persistent.sentinel.yaml` | regra 2 (4698 via `EventData`) — 10/10 fixtures |
| `rules/marcus_signin_noncompliant_device_outside_allowed_countries.sentinel.yaml` | regra 3 (`SigninLogs`, identidade) — 12/12 fixtures |
| `rules/marcus_powershell_script_from_temp_path.sentinel.yaml` | regra 4 (`DeviceProcessEvents`, endpoint) — 13/13 fixtures |
| `tools/kql_eval.py` | avaliador de um **subconjunto** de KQL (`where`, `project`, `parse`, `extend/tostring`, `=~`, `has_any`); biblioteca padrão; não é motor Kusto |
| `tools/fixtures-securityevent.json` | regra 1: 8 fixtures do Ciclo 3 como linhas `SecurityEvent` + 2 de divergência |
| `tools/fixtures-securityevent-4698.json` | regra 2: evento real + 9 sintéticas, `EventData` no formato do Sentinel |
| `tools/fixtures-signinlogs.json` | regra 3: 6 linhas do dataset do Ciclo 4 + 6 de fronteira (null, tipo, país, dispositivo) |
| `tools/fixtures-deviceprocessevents.json` | regra 4: dataset + timeline do Ciclo 2 + 7 de fronteira (`-Command`, filtro, null, maiúsculas) |
| `tools/run_tests.py` | `python tools/run_tests.py` — casa fixture↔regra por `_rule`; exit 1 se alguma regra falhar |

## Regras desta série

- Coluna só entra depois de lida na página oficial da tabela. Nada de memória.
- Toda query leva o rótulo: *escrita e raciocinada; NÃO executada contra motor KQL*.
- Segredo sintético; nenhum dado real de nenhuma natureza.
- Limitação declarada em todo artefacto.
