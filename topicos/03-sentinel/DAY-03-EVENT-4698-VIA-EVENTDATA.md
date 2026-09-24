# Ciclo 5 · Dia 3 — Event 4698 via `EventData`: a coluna que não existe

**22/09/2026** · a segunda regra do Ciclo 3.1 chega ao Sentinel — e o caminho não é o que o Sigma sugeria.

---

## Rótulo de claim

```text
SYNTHETIC LAB (com um evento REAL como positivo de referência)

Motor:        nenhum motor Kusto; avaliador local, agora com `parse` (modo simples)
Workspace:    nenhum
Host:         nada instalado; Get-WinEvent nativo, só leitura, sobre o sample CC0 do Ciclo 3
Dados:        10 fixtures; o positivo 1 é o 4698 real do sample (campos extraídos hoje),
              com EventData RECONSTRUÍDO no formato que o Sentinel usa
Execução:     python tools/run_tests.py  ->  20/20 nas duas regras, exit 0
```

## 1. O problema herdado do Dia 1

`SecurityEvent` **não tem** `TaskName` nem `TaskContent`. A regra 2 do Ciclo 3.1 vivia desses
dois campos. No Sentinel eles só existem **dentro de `EventData`** (string), como
`<Data Name="TaskName">…</Data>`.

## 2. Como a Microsoft resolve — lido, não inventado

`Solutions/Endpoint Threat Protection Essentials/Hunting Queries/ScheduledTaskCreationUpdateFromUserWritableDrectory.yaml` (v1.0.3), via `gh api`:

```kusto
| where EventID in (4698,4702) and EventData has_any (WritableUserPaths)
| parse EventData with * 'Command&gt;' Command "&lt" *
| parse EventData with * 'SubjectUserName">' SubjectUserName "<" * ... 'TaskName">' TaskName "<" *
```

Duas coisas que esta query ensina e que eu não teria adivinhado:

1. **`parse … with * 'lit' Col "lit" *`** é o padrão para extrair `Data Name="X"`.
2. **O XML de `TaskContent` está HTML-escapado dentro de `EventData`** — `'Command&gt;'`,
   `"&lt"`. O `<UserId>S-1-5-18</UserId>` que o Ciclo 3.1 viu em bruto aparece no Sentinel
   como `&lt;UserId&gt;S-1-5-18&lt;/UserId&gt;`. Uma regra escrita com `<UserId>` seria
   **muda em produção com 100% de testes verdes** se as fixtures fossem em bruto.

O parser ASIM `ASimAuditEventMicrosoftSecurityEvents.yaml` confirma que 4698–4702 são a
família "Scheduled Task" e que o próprio ASIM os lê de `EventData`.

## 3. O evento real — extraído hoje

```powershell
Get-WinEvent -Path <T1053.005-scheduled-task-creation.evtx> -Oldest | ? Id -eq 4698
```

| Campo | Valor real |
|---|---|
| `Computer` | `srvdefender01.offsec.lan` |
| `TimeCreated` | `2021-04-21T13:30:00.5894609Z` |
| `SubjectUserSid` | `S-1-5-21-4230534742-2542757381-3142984815-1111` |
| `SubjectUserName` / `SubjectDomainName` | `admmig` / `OFFSEC` |
| `SubjectLogonId` | `0x6fc89e` |
| `TaskName` | `\eviltask` |
| `TaskContent` | XML de **1.640** caracteres: `<Interval>PT1M</Interval>`, `<Command>C:\tools\shell.cmd</Command>`, `<UserId>S-1-5-18</UserId>`, `<RunLevel>LeastPrivilege</RunLevel>` |

Bate com o Ciclo 3.1 campo a campo. O `EventData` da fixture positiva foi **reconstruído**
com estes valores no formato `<Data Name=…>` + escape HTML — não foi copiado de um Sentinel,
porque não há Sentinel. Isto está dito na própria fixture.

## 4. IMPLEMENTAR — regra 2

`rules/marcus_schtasks_4698_system_persistent.sentinel.yaml`:

```kusto
SecurityEvent
| where EventID == 4698
| parse EventData with * 'TaskName">' TaskName "<" *
| parse EventData with * 'TaskContent">' TaskContent "</Data>" *
| where TaskContent contains "&lt;UserId&gt;S-1-5-18&lt;/UserId&gt;"
| where TaskContent contains "&lt;Interval&gt;PT1M&lt;/Interval&gt;" or … PT5M
    or TaskContent contains "&lt;BootTrigger&gt;"
    or TaskContent contains "&lt;LogonTrigger&gt;"
| where not(TaskName startswith @"\Microsoft\")
| project TimeGenerated, Computer, SubjectDomainName, SubjectUserName, TaskName, EventID
```

Decisões:

| Sigma (Ciclo 3.1) | KQL | Porquê |
|---|---|---|
| `TaskContent contains <UserId>S-1-5-18</UserId>` | o mesmo, **escapado** | é assim que está em `EventData` |
| `PT1M..PT5M` | 5 `contains` explícitos | fica no subconjunto; `matches regex` seria mais curto e fica anotado |
| `TaskName startswith \Microsoft\` | `parse` + `startswith` | não há coluna |
| entidade `Account` | `SubjectUserName`/`SubjectDomainName` — **quem registou**, não o principal SYSTEM | o principal seria descartado (built-in) |

## 5. O avaliador cresceu — só o necessário

`tools/kql_eval.py` ganhou **um** operador de pipeline: `parse <col> with * 'a' Col "b" *`.
Semântica: procura `a`, captura até `b`; se um não existir, `Col` fica vazia e a linha
continua (o Kusto também não a descarta). Fora disso, continua a levantar erro.

O runner passou a casar fixture ↔ regra pelo campo `_rule` (as 10 do Dia 2 receberam-no,
aditivamente). Sem isso, as fixtures 4688 corriam contra a regra 4698 e vice-versa.

## 6. TESTAR / QUEBRAR — as 10 fixtures

```text
=> 4 TP / 6 TN / 0 FAIL      variante `has`: 0 divergências (nada de pontuação aqui)
```

| # | Fixture | Veredito | O que prova |
|---|---|---|---|
| 1 | **evento real** (`\eviltask`, PT1M, S-1-5-18) | MATCH | a regra apanha o sample que a originou |
| 2 | PT5M | MATCH | limite superior da janela |
| 3 | `BootTrigger` | MATCH | equivalente de `/sc onstart` — **não observado**, declarado |
| 4 | `LogonTrigger`, criada por `Register-ScheduledTask` | MATCH | **a regra 4688 não vê isto; esta vê** — é a razão de existir |
| 5 | SYSTEM + semanal | NO MATCH | gatilho manda |
| 6 | PT1M + SID de utilizador | NO MATCH | principal manda |
| 7 | `\Microsoft\Windows\…` + SYSTEM + boot | NO MATCH | ramo do filtro |
| 8 | **evasão**: tarefa registada debaixo de `\Microsoft\` | NO MATCH | o filtro é uma porta — limitação declarada |
| 9 | **4702** (tarefa *actualizada* para SYSTEM+PT1M) | NO MATCH | fora de escopo — editar tarefa benigna passa |
| 10 | **`TaskContent` em bruto**, sem escape | NO MATCH | a regra **depende** do escape; sem esta fixture o risco do §2 seria invisível |

As fixtures 8, 9 e 10 não são "falhas": são a fronteira da regra, escrita em código.

## 7. O que a evidência sustenta

- No formato `<Data Name=…>` com escape HTML, a regra devolve o veredito declarado em 10/10.
- O padrão de `parse` e o escape vêm de uma query publicada pela Microsoft, não de suposição.
- Os valores do positivo 1 são os do evento real, extraídos hoje com ferramenta nativa.

## O que a evidência NÃO sustenta

- Que o `EventData` reconstruído é **byte a byte** o que um Sentinel real guarda — a
  ordem dos `Data`, espaços e o escape de `"` são a minha reconstrução do padrão da query MS.
- Que `SubjectUserName` (coluna) vem populada para 4698 — a query da Microsoft **faz parse**
  dela de `EventData`, o que sugere que a coluna pode não vir. Fica registado como risco;
  a correcção seria trocar a coluna por `parse`, como a MS faz.
- Que `parse` do avaliador é a semântica completa do Kusto (`kind=simple` só).

## 8. Limitações

- 4702 fora de escopo; `\Microsoft\` é filtro contornável; sem "Audit Other Object Access
  Events" a regra é surda — os três vêm do Ciclo 3.1 e continuam.
- `TaskContent` de 1.640 caracteres: o exportador do Ciclo 3 truncava a 400. No Sentinel a
  coluna `EventData` não tem esse limite, mas o **agente** pode ter — não verificado.

## Próximo passo

**Dia 4:** regra de identidade sobre `SigninLogs` a partir do CASE-03 — a primeira com
colunas `dynamic` (`ConditionalAccessPolicies`, `Status`), que o avaliador não conhece.
Decidir de novo se cresce ou se declara.

---

## MARCUS REFLECTION

```text
MARCUS REFLECTION: PENDING
```

Pergunta de entrevista deste dia — só para `ENTREVISTA.md` quando sair em voz alta, sem ler:

> *"A sua regra procura `<UserId>S-1-5-18</UserId>`. Por que é que ela não dispara em produção?"*
